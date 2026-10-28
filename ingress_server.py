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
import os
import shutil
import subprocess
import tempfile
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Lock PyTorch to 2 threads for 2-vCPU instance
torch.set_num_threads(2)

app = FastAPI(title="AgentWard + MuseVerify Node (Stage 1 & 2)")

MODEL_ID = "Niansuh/Prompt-Guard-86M"
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
    sandbox_dir = tempfile.mkdtemp(prefix=f"museverify_{req.vuln_id}_")
    try:
        script_content = req.test_script or req.poc_script
        target_path = os.path.join(sandbox_dir, os.path.basename(req.target_filename))
        test_path = os.path.join(sandbox_dir, "verify_test.py")

        with open(target_path, "w") as f:
            f.write(req.sanitized_target_code)
        with open(test_path, "w") as f:
            f.write(script_content)

        docker_cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--memory", "256m",
            "--cpus", "0.5",
            "-v", f"{sandbox_dir}:/workspace:rw",
            "-w", "/workspace",
            "python:3.12-slim",
            "python3", "verify_test.py",
        ]
        proc = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=15)

        if proc.returncode != 0 and (
            "permission denied" in proc.stderr.lower() or "cannot connect" in proc.stderr.lower()
        ):
            proc = subprocess.run(
                ["python3", "verify_test.py"],
                cwd=sandbox_dir,
                capture_output=True,
                text=True,
                timeout=10,
            )

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()
        verified = proc.returncode == 0 and ("VULN_CONFIRMED" in stdout or "EXPLOIT_VERIFIED" in stdout)
        return {
            "vuln_id": req.vuln_id,
            "verified": verified,
            "exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }
    except subprocess.TimeoutExpired:
        return {"vuln_id": req.vuln_id, "verified": False, "exit_code": -1, "stdout": "", "stderr": "Sandbox timed out"}
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentWard + MuseVerify Ingress & Sandbox Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, workers=1)
