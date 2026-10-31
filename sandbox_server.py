#!/usr/bin/env python3
"""
MuseVerify Remote Sandbox Node (Stages 2 & 5).

Runs an untrusted verification harness inside a zero-network Docker container and
returns BOTH the process output and a structured syscall audit trail, so the
AI auditor can reason about *behaviour* (execve/openat/connect) instead of
trusting an exit code that a polymorphic payload can trivially forge.

A root tracer writes protected evidence outside the payload's bounded workspace.
The immutable bootstrap drops to nobody before loading any submitted source.
Missing, truncated, or unprotected kernel evidence fails closed.

Exposed endpoints:
  GET  /                -> health
  POST /execute         -> run harness + syscall trace
  POST /run-sandbox-test-> alias kept for older clients
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import tempfile
import uuid
import threading
import selectors
import time
import stat
import struct
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Depends, HTTPException
from sandbox_protocol import SandboxRequest, EVIDENCE_VERSION
from service_security import BodyLimitMiddleware, require_node_token

app = FastAPI(title="MuseVerify Sandbox Node (Stage 2/5)")
app.add_middleware(BodyLimitMiddleware)
_sandbox_slots = threading.BoundedSemaphore(3)

def _default_image() -> str:
    """Prefer the trace-capable derived image when it has been built locally."""
    if shutil.which("docker"):
        probe = subprocess.run(
            ["docker", "image", "inspect", "agentward-sandbox:latest"],
            capture_output=True, text=True, timeout=10,
        )
        if probe.returncode == 0:
            return "agentward-sandbox:latest"
    return "python:3.12-slim"


SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE") or _default_image()
SANDBOX_TIMEOUT_S = int(os.environ.get("SANDBOX_TIMEOUT_S", "15"))
MAX_EVENTS = 500
TRACE_SYSCALLS = "execve,execveat,openat,open,connect,unlinkat"

# Paths that produce noise on every single Python start.
_NOISE_FRAGMENTS = (
    "site-packages",
    "__pycache__",
    "/usr/lib/python",
    "/usr/local/lib/python",
    ".so",
    ".pyc",
)

MAX_OUTPUT_BYTES = 1_000_000
MAX_TRACE_BYTES = 8_000_000

# strace owns /evidence/kernel.strace as root. The payload runs as nobody,
# with no capabilities, after this immutable bootstrap drops every group/UID.
# -I keeps source-controlled Python startup hooks away from the privileged step.
BOOTSTRAP = r'''
import os, runpy, shutil, sys
os.setgroups([])
os.setgid(65534)
os.setuid(65534)
for name in os.listdir('/inputs'):
    shutil.copyfile('/inputs/' + name, '/workspace/' + name)
sys.path.insert(0, '/workspace')
os.chdir('/workspace')
sys.argv = ['/workspace/verify_test.py']
runpy.run_path(sys.argv[0], run_name='__main__')
'''


def _split_args(raw: str) -> list:
    """Split an strace argument list on top-level commas, respecting quotes."""
    args, buf, quote, depth = [], [], None, 0
    for char in raw:
        if quote:
            if char == quote:
                quote = None
            buf.append(char)
        elif char in ('"', "'"):
            quote = char
            buf.append(char)
        elif char in "([{":
            depth += 1
            buf.append(char)
        elif char in ")]}":
            depth = max(0, depth - 1)
            buf.append(char)
        elif char == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
        else:
            buf.append(char)
    if buf:
        args.append("".join(buf).strip())
    return args


def _unquote(token: str) -> str:
    return token.strip().strip('"').strip("'")


def normalize_strace(text: str) -> list:
    """Convert raw strace lines into the same schema the audit shim emits.

    `openat`/`execveat`/`connect` carry a leading dirfd or fd, so the payload
    lives in the second argument — parsing positionally keeps paths and remote
    addresses intact.
    """
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("+++", "---", "exit", "strace:")):
            continue
        name, _, rest = line.partition("(")
        name = name.split()[-1] if name else ""
        rest = rest.split(" = ")[0]
        if rest.endswith(")"):
            rest = rest[:-1]
        args = _split_args(rest)
        if name in ("execve", "execveat"):
            argv = _unquote(args[1] if name == "execveat" and len(args) > 1 else (args[0] if args else ""))
            if not argv or _is_noisy(argv):
                continue
            events.append({"syscall": "sys_enter_execve", "argv": argv[:400],
                           "args": rest[:400],
                           "shell": os.path.basename(argv) in ("sh", "bash", "dash"),
                           "source": "strace"})
        elif name in ("openat", "open"):
            path = _unquote(args[1]) if name == "openat" and len(args) > 1 else (
                _unquote(args[0]) if args else "")
            if not path or _is_noisy(path):
                continue
            flag = args[2] if name == "openat" and len(args) > 2 else (
                args[1] if len(args) > 1 else "?")
            events.append({"syscall": "sys_enter_openat", "path": path[:300],
                           "flag": flag[:60], "source": "strace"})
        elif name == "connect":
            addr = args[1] if len(args) > 1 else (args[0] if args else "")
            events.append({"syscall": "sys_enter_connect", "addr": addr[:200], "source": "strace"})
        elif name in ("unlink", "unlinkat"):
            path = _unquote(args[1]) if name == "unlinkat" and len(args) > 1 else (
                _unquote(args[0]) if args else "")
            events.append({"syscall": "sys_enter_unlinkat", "path": path[:300], "source": "strace"})
        if len(events) > MAX_EVENTS:
            break
    return events


def _is_noisy(path: str) -> bool:
    return any(frag in path for frag in _NOISE_FRAGMENTS)


def _write_harness_files(sandbox_dir: str, req: SandboxRequest) -> str:
    target_name = req.target_file or req.target_filename or 'target.py'
    root = Path(sandbox_dir)
    root.chmod(0o755)
    inputs = root / 'inputs'
    inputs.mkdir(mode=0o755)
    (inputs / target_name).write_text(req.code_content or req.sanitized_target_code)
    (inputs / 'verify_test.py').write_text(req.test_code or req.test_script or req.poc_script)
    for path in inputs.iterdir():
        path.chmod(0o644)
    (root / 'bootstrap.py').write_text(BOOTSTRAP)
    (root / 'bootstrap.py').chmod(0o644)
    evidence = root / 'evidence'
    evidence.mkdir()
    # POSIX ACL grants only the service owner and container root access. The
    # payload cannot create files here (which would bypass its tmpfs quota).
    # Root creates a 0644 trace; the service can read and remove it afterwards.
    entries = [(0x01, 7, 0xffffffff), (0x02, 7, 0), (0x04, 0, 0xffffffff),
               (0x10, 7, 0xffffffff), (0x20, 0, 0xffffffff)]
    acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in entries)
    os.setxattr(evidence, 'system.posix_acl_access', acl)
    return target_name


def _run_container(sandbox_dir: str):
    name = 'agentward-' + uuid.uuid4().hex
    root = Path(sandbox_dir)
    command = [
        'docker', 'run', '--rm', '--name', name, '--pull', 'never',
        '--network', 'none', '--read-only', '--memory', '256m', '--memory-swap', '256m',
        '--pids-limit', '64', '--user', '0:0', '--cap-drop', 'ALL',
        '--cap-add', 'SYS_PTRACE', '--cap-add', 'SETUID', '--cap-add', 'SETGID',
        '--security-opt', 'no-new-privileges', '--cpus', '0.5',
        '--ulimit', 'fsize=8000000:8000000', '--ulimit', 'nofile=256:256',
        '--log-driver', 'none',
        '--tmpfs', '/workspace:rw,nosuid,nodev,noexec,size=64m,mode=1777',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777',
        '--mount', f'type=bind,src={root / "inputs"},dst=/inputs,readonly',
        '--mount', f'type=bind,src={root / "bootstrap.py"},dst=/opt/bootstrap.py,readonly',
        '--mount', f'type=bind,src={root / "evidence"},dst=/evidence',
        '-w', '/', '--env', 'PYTHONUNBUFFERED=1', '--env', 'PYTHONDONTWRITEBYTECODE=1',
        '--entrypoint', '/bin/sh', SANDBOX_IMAGE, '-c',
        'umask 022; exec strace -f -qq -e trace=' + TRACE_SYSCALLS
        + ' -o /evidence/kernel.strace python3 -I /opt/bootstrap.py',
    ]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    captured = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic() + SANDBOX_TIMEOUT_S
    try:
        with selectors.DefaultSelector() as selector:
            for stream, key in [(proc.stdout, 'stdout'), (proc.stderr, 'stderr')]:
                selector.register(stream, selectors.EVENT_READ, key)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, SANDBOX_TIMEOUT_S)
                for key, _ in selector.select(min(remaining, .2)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(captured[key.data]) + len(chunk) > MAX_OUTPUT_BYTES:
                        raise RuntimeError('Sandbox output limit exceeded')
                    captured[key.data].extend(chunk)
        proc.wait(timeout=max(.01, deadline - time.monotonic()))
        return subprocess.CompletedProcess(command, proc.returncode,
            captured['stdout'].decode('utf-8', errors='replace'),
            captured['stderr'].decode('utf-8', errors='replace'))
    finally:
        # Always reap the container, including output overflow, timeout and errors.
        try:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            proc.stdout.close()
            proc.stderr.close()


def _read_trace(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise RuntimeError('Trace is not a protected regular file')
        if info.st_uid != 0:
            raise RuntimeError('Trace must be owned by the rootful Docker tracer')
        raw = handle.read(MAX_TRACE_BYTES + 1)
    if len(raw) >= MAX_TRACE_BYTES:
        raise RuntimeError('Kernel trace limit reached')
    return raw.decode('utf-8', errors='replace')



_TRACE_CAPABLE_CACHE = {}


def _image_has_strace() -> bool:
    """Cached probe: does the configured sandbox image ship strace?"""
    if SANDBOX_IMAGE not in _TRACE_CAPABLE_CACHE:
        try:
            probe = subprocess.run(
                ["docker", "run", "--rm", "--network", "none", SANDBOX_IMAGE,
                 "/bin/sh", "-c", "command -v strace"],
                capture_output=True, text=True, timeout=30,
            )
            _TRACE_CAPABLE_CACHE[SANDBOX_IMAGE] = probe.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            _TRACE_CAPABLE_CACHE[SANDBOX_IMAGE] = False
    return _TRACE_CAPABLE_CACHE[SANDBOX_IMAGE]


@app.get("/")
@app.get("/health")
def health():
    have_docker = shutil.which("docker") is not None
    trace_capable = have_docker and _image_has_strace()
    return {
        "status": "ok",
        "service": "MuseVerify Sandbox Node",
        "docker": have_docker,
        "sandbox_image": SANDBOX_IMAGE,
        "trace_capable": trace_capable,
        "syscall_telemetry": "protected-strace-v2" if trace_capable else "unavailable (image lacks strace)",
        "evidence_version": EVIDENCE_VERSION,
    }


@app.post('/execute', dependencies=[Depends(require_node_token)])
@app.post('/run-sandbox-test', dependencies=[Depends(require_node_token)])
@app.post('/run-poc-sandbox', dependencies=[Depends(require_node_token)])
def execute(req: SandboxRequest):
    if not _sandbox_slots.acquire(blocking=False):
        raise HTTPException(429, 'All sandbox slots are busy', headers={'Retry-After': '1'})
    try:
        return _execute(req)
    finally:
        _sandbox_slots.release()


def _execute(req: SandboxRequest):
    sandbox_dir = tempfile.mkdtemp(prefix='museverify_')
    failure = {'vuln_id': req.vuln_id, 'verified': False, 'exit_code': -1,
               'stdout': '', 'engine': 'docker', 'trace_backend': 'none',
               'trace_complete': False, 'trace_protected': False,
               'evidence_version': EVIDENCE_VERSION, 'syscall_events': []}
    try:
        _write_harness_files(sandbox_dir, req)
        proc = _run_container(sandbox_dir)
        trace = _read_trace(Path(sandbox_dir) / 'evidence' / 'kernel.strace')
        events = normalize_strace(trace)
        complete = bool(events) and len(events) <= MAX_EVENTS and proc.returncode == 0
        return {
            **failure, 'verified': complete and ('VULN_CONFIRMED' in proc.stdout or 'EXPLOIT_VERIFIED' in proc.stdout),
            'exit_code': proc.returncode, 'stdout': proc.stdout.strip(), 'stderr': proc.stderr.strip(),
            'trace_backend': 'strace', 'syscall_events': events[:MAX_EVENTS],
            'trace_complete': complete, 'trace_protected': True,
            'source_sha256': hashlib.sha256((req.code_content or req.sanitized_target_code).encode()).hexdigest(),
            'harness_sha256': hashlib.sha256((req.test_code or req.test_script or req.poc_script).encode()).hexdigest(),
            'execution_contract': {'engine': 'docker', 'network': 'none', 'memory': '256m',
                'pids_limit': 64, 'read_only_root': True, 'payload_uid': 65534,
                'payload_capabilities': [], 'tracer_capabilities': ['SYS_PTRACE', 'SETUID', 'SETGID'],
                'no_new_privileges': True, 'credentials_mounted': False,
                'workdir': '/workspace', 'workspace_limit_bytes': 64 * 1024 * 1024,
                'output_limit_bytes': MAX_OUTPUT_BYTES, 'trace_limit_bytes': MAX_TRACE_BYTES},
        }
    except subprocess.TimeoutExpired:
        return {**failure, 'stderr': 'Sandbox timed out'}
    except (OSError, RuntimeError) as exc:
        return {**failure, 'stderr': 'Sandbox evidence unavailable: ' + type(exc).__name__}
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, workers=1)
