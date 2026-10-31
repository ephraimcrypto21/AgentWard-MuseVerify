#!/usr/bin/env python3
"""
AgentWard + MuseVerify Remote Node Server (Stages 1 & 2).

Exposes:
  - GET  /                  -> HTTP 200 health check
  - GET  /health            -> HTTP 200 health check
  - POST /scan-ingress      -> Pinned local prompt-injection classifier
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
from language_adapters import adapter_for
from sandbox_protocol import SandboxRequest
from service_security import BodyLimitMiddleware, node_headers, node_urlopen, require_node_token

import uvicorn
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field, ConfigDict, model_validator
from typing import Literal
from ingress_guard import BACKEND, MODEL_LOCK, RISK_THRESHOLD, contract, load_classifier as load_pinned_classifier
app = FastAPI(title="AgentWard + MuseVerify Node (Stage 1 & 2)")
app.add_middleware(BodyLimitMiddleware)

MODEL_ID = MODEL_LOCK['model_id']
LEGACY_SANDBOX_URL = os.environ.get(
    "AGENTWARD_SANDBOX_PROXY_URL", "http://127.0.0.1:8001/run-sandbox-test"
)
model = None
_model_lock = threading.Lock()
_model_error = None
_scan_slots = threading.BoundedSemaphore(2)


def load_classifier():
    global model, _model_error
    with _model_lock:
        if model is not None or _model_error is not None:
            return
        try:
            model = load_pinned_classifier()
        except Exception as exc:
            _model_error = type(exc).__name__



class ScanRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    file_path: str = Field(default='unknown.py', max_length=1024)
    language: Literal['python', 'javascript', 'typescript'] | None = None
    content: str = Field(default="", max_length=200000)
    text: str = Field(default="", max_length=200000)

    @model_validator(mode='after')
    def check_language(self):
        adapter = adapter_for(self.file_path)
        if self.language is not None and self.language != adapter.name:
            raise ValueError('Language does not match file extension')
        if self.content and self.text and self.content != self.text:
            raise ValueError('Conflicting source aliases')
        self.language = adapter.name
        return self


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
        "classifier_contract": contract(),
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
    cleaned = adapter_for(req.file_path).sanitize(raw_text)
    load_classifier()
    if model is None:
        return {'label': 'unverified', 'blocked': True, 'backend': 'unavailable',
                'coverage_complete': False, 'sanitized_verified': False}
    try:
        probs = model.classify(raw_text, language=req.language)
        clean_probs = model.classify(cleaned['content'], language=req.language) if cleaned['sanitized_count'] else probs
    except Exception:
        return {'label': 'unverified', 'blocked': True, 'backend': 'unavailable',
                'coverage_complete': False, 'sanitized_verified': False}
    verified = cleaned['valid'] and clean_probs['injection'] <= RISK_THRESHOLD
    flagged = probs['injection'] > RISK_THRESHOLD
    return {'file_path': req.file_path, 'backend': BACKEND, 'coverage_complete': True,
            'classifier_contract': contract(),
            'language': req.language,
            'source_sha256': hashlib.sha256(raw_text.encode()).hexdigest(),
            'sanitized_sha256': hashlib.sha256(cleaned['content'].encode()).hexdigest(),
            'sanitized_verified': verified, 'sanitized_content': cleaned['content'],
            'sanitized_count': cleaned['sanitized_count'], 'label': 'injection' if flagged else 'benign',
            'scores': {k: round(probs[k], 6) for k in ('benign', 'injection')},
            'sanitized_scores': {k: round(clean_probs[k], 6) for k in ('benign', 'injection')},
            'windows_scanned': probs['windows'], 'sanitized_windows_scanned': clean_probs['windows'],
            'blocked': not verified or flagged}


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
