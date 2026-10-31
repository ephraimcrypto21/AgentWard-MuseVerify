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
import threading
import hashlib
from ingress_sanitizer import sanitize_source
from sandbox_protocol import SandboxRequest
from service_security import BodyLimitMiddleware, node_headers, node_urlopen, require_node_token

import uvicorn
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field, ConfigDict
app = FastAPI(title="AgentWard + MuseVerify Node (Stage 1 & 2)")
app.add_middleware(BodyLimitMiddleware)

MODEL_ID = "Niansuh/Prompt-Guard-86M"
LEGACY_SANDBOX_URL = os.environ.get(
    "AGENTWARD_SANDBOX_PROXY_URL", "http://127.0.0.1:8001/run-sandbox-test"
)
tokenizer = model = None
_model_lock = threading.Lock()
_model_error = None
_scan_slots = threading.BoundedSemaphore(2)


def load_classifier():
    global tokenizer, model, _model_error
    with _model_lock:
        if model is not None or _model_error is not None:
            return
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            torch.set_num_threads(2)
            tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, local_files_only=True)
            model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID, local_files_only=True)
            model.eval()
        except Exception as exc:
            _model_error = type(exc).__name__



class ScanRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    file_path: str = Field(default='unknown', max_length=1024)
    content: str = Field(default="", max_length=200000)
    text: str = Field(default="", max_length=200000)


SandboxTestRequest = SandboxRequest


@app.get("/")
@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "AgentWard + MuseVerify Node (Stage 1 & 2)",
        "model": MODEL_ID,
        "model_loaded": model is not None,
        "model_error": _model_error,
        "legacy_sandbox_proxy": LEGACY_SANDBOX_URL,
        "bind": "127.0.0.1:8000",
    }


@app.post("/scan-ingress", dependencies=[Depends(require_node_token)])
@app.post("/classify", dependencies=[Depends(require_node_token)])
@app.post("/predict", dependencies=[Depends(require_node_token)])
def scan_ingress(req: ScanRequest):
    if not _scan_slots.acquire(blocking=False):
        raise HTTPException(429, 'All classifier slots are busy', headers={'Retry-After': '1'})
    try:
        return _scan_ingress(req)
    finally:
        _scan_slots.release()


def _scan_ingress(req: ScanRequest):
    raw_text = req.content or req.text
    cleaned = sanitize_source(raw_text)
    load_classifier()
    if model is None:
        return {'label': 'unverified', 'blocked': True, 'backend': 'unavailable',
                'coverage_complete': False, 'sanitized_verified': False}
    import torch
    def classify(text):
        # Cover the complete source with overlapping windows; no silent 512-token cutoff.
        encoded = tokenizer(text, return_tensors='pt', truncation=True, max_length=512,
                            stride=128, return_overflowing_tokens=True, padding=True)
        encoded.pop('overflow_to_sample_mapping', None)
        scores = torch.zeros(3)
        with torch.no_grad():
            for i in range(encoded['input_ids'].shape[0]):
                logits = model(**{k: v[i:i+1] for k, v in encoded.items()}).logits
                scores = torch.maximum(scores, torch.softmax(logits, dim=-1).squeeze().cpu())
        return scores.tolist()
    probs = classify(raw_text)
    clean_probs = classify(cleaned['content']) if cleaned['sanitized_count'] else probs
    top_idx = max(range(3), key=lambda i: probs[i])
    labels = ['benign', 'injection', 'jailbreak']
    verified = cleaned['valid'] and max(clean_probs[1:]) <= .40 and clean_probs[0] >= max(clean_probs[1:])
    return {'file_path': req.file_path, 'backend': 'prompt_guard', 'coverage_complete': True,
            'source_sha256': hashlib.sha256(raw_text.encode()).hexdigest(),
            'sanitized_sha256': hashlib.sha256(cleaned['content'].encode()).hexdigest(),
            'sanitized_verified': verified, 'sanitized_content': cleaned['content'],
            'sanitized_count': cleaned['sanitized_count'], 'label': labels[top_idx],
            'scores': dict(zip(labels, [round(p, 4) for p in probs])),
            'blocked': not verified or top_idx != 0 or max(probs[1:]) > .40}


@app.post("/run-sandbox-test", dependencies=[Depends(require_node_token)])
@app.post("/run-poc-sandbox", dependencies=[Depends(require_node_token)])
def run_sandbox_test(req: SandboxTestRequest):
    payload = req.model_dump_json().encode('utf-8')
    request = urllib.request.Request(
        LEGACY_SANDBOX_URL,
        data=payload,
        headers=node_headers(),
        method="POST",
    )
    try:
        with node_urlopen(request, timeout=25) as resp:
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
