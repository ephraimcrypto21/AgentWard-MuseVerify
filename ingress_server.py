#!/usr/bin/env python3
"""
AgentWard + MuseVerify Remote Node Server (Stages 1 & 2).

Exposes:
  - GET  /                  -> HTTP 200 health check
  - GET  /health            -> HTTP 200 health check
  - POST /scan-ingress      -> Meta Prompt-Guard-86M classifier
  - POST /run-sandbox-test  -> Zero-network Docker verification sandbox
  - POST /run-poc-sandbox   -> Alias for /run-sandbox-test

Binds explicitly to 127.0.0.1:8000 by default for SSH tunnel forwarding.
"""
import argparse
import json
import os
import urllib.error
import urllib.request

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Lock PyTorch to 2 threads for 2-vCPU instance
torch.set_num_threads(2)

app = FastAPI(title="AgentWard + MuseVerify Node (Stage 1 & 2)")

MODEL_ID = "Niansuh/Prompt-Guard-86M"
LEGACY_SANDBOX_URL = os.environ.get(
    "AGENTWARD_SANDBOX_PROXY_URL", "http://127.0.0.1:8001/run-sandbox-test"
)
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)


class ScanRequest(BaseModel):
    file_path: str = "unknown"
    content: str = ""
    text: str = ""


class SandboxTestRequest(BaseModel):
    vuln_id: str
    target_filename: str
    sanitized_target_code: str
    test_script: str = ""
    poc_script: str = ""


@app.get("/")
@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "AgentWard + MuseVerify Node (Stage 1 & 2)",
        "model": MODEL_ID,
        "legacy_sandbox_proxy": LEGACY_SANDBOX_URL,
        "bind": "127.0.0.1:8000",
    }


@app.post("/scan-ingress")
@app.post("/classify")
@app.post("/predict")
def scan_ingress(req: ScanRequest):
    raw_text = req.content or req.text
    inputs = tokenizer(raw_text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        logits = model(**inputs).logits
    probs = torch.softmax(logits, dim=-1).squeeze().tolist()
    labels = ["BENIGN", "INJECTION", "JAILBREAK"]
    top_idx = int(torch.argmax(logits, dim=-1))
    return {
        "file_path": req.file_path,
        "verdict": labels[top_idx],
        "label": labels[top_idx].lower(),
        "scores": {
            "benign": round(probs[0], 4),
            "injection": round(probs[1], 4),
            "jailbreak": round(probs[2], 4),
        },
        "blocked": top_idx != 0 or probs[1] > 0.40 or probs[2] > 0.40,
    }


@app.post("/run-sandbox-test")
@app.post("/run-poc-sandbox")
def run_sandbox_test(req: SandboxTestRequest):
    payload = json.dumps({
        "vuln_id": req.vuln_id,
        "target_filename": req.target_filename,
        "sanitized_target_code": req.sanitized_target_code,
        "test_script": req.test_script,
        "poc_script": req.poc_script,
    }).encode("utf-8")
    request = urllib.request.Request(
        LEGACY_SANDBOX_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return {
            "vuln_id": req.vuln_id,
            "verified": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Sandbox proxy HTTP {exc.code}: {detail[:200]}",
            "engine": "proxy_error",
            "trace_backend": "none",
            "syscall_events": [],
        }
    except (urllib.error.URLError, TimeoutError) as exc:
        return {
            "vuln_id": req.vuln_id,
            "verified": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Sandbox proxy unavailable: {exc}",
            "engine": "proxy_error",
            "trace_backend": "none",
            "syscall_events": [],
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentWard + MuseVerify Ingress & Sandbox Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, workers=1)
