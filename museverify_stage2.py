#!/usr/bin/env python3
"""
MuseVerify Stage 2: Worktree Fan-Out, Syscall-Introspective Sandbox Triage
with robust local fallback for reliable dashboard execution.

Verification is behavioural: the harness fires real payloads and the returned
syscall trail is audited heuristically and by the AI auditor, so a polymorphic
payload can no longer pass by returning exit code 0.
"""
import os
import hashlib
import sys
import json
import shutil
import itertools
import re
import tempfile
from dotenv import load_dotenv
load_dotenv()
import subprocess
import urllib.request
import urllib.error

PROMPT_GUARD_URL = os.environ.get(
    "AGENTWARD_INGRESS_URL", "http://127.0.0.1:18000/scan-ingress"
)
LIGHTSAIL_SANDBOX_URL = os.environ.get(
    "AGENTWARD_SANDBOX_URL", "http://127.0.0.1:18001/execute"
)

HARNESS_FILES = {"test_harness.py", "verify_test.py", "run_test.py", "agentward_runner.py"}

def clean_worktrees(
    vuln_id: str | None = None,
    remove_all: bool = False,
    base_dir: str = "worktrees",
) -> dict:
    """
    Automated lifecycle management and pruning for the 'worktrees/' directory.
    - If vuln_id is specified: safely prunes temporary test harness files
      (test_harness.py, verify_test.py, pycache, temporary test outputs)
      inside worktrees/<vuln_id>.
    - If vuln_id is None: iterates over all subdirectories in worktrees/ and prunes
      stale harness files.
    - If remove_all is True: safely removes worktree directories entirely.
    """
    base_path = os.path.abspath(base_dir)
    if not os.path.exists(base_path):
        return {
            "status": "success",
            "vuln_id": vuln_id,
            "cleaned_files": [],
            "cleaned_count": 0,
            "bytes_freed": 0,
        }

    cleaned_files = []
    bytes_freed = 0

    target_dirs = []
    if vuln_id and (not re.fullmatch(r"[A-Za-z0-9_.-]+", vuln_id) or vuln_id in (".", "..")):
        raise ValueError("Invalid worktree identifier")
    if vuln_id:
        target_dirs.append(os.path.join(base_path, vuln_id))
    else:
        for entry in os.listdir(base_path):
            full_entry = os.path.join(base_path, entry)
            if os.path.isdir(full_entry):
                target_dirs.append(full_entry)

    for wt_dir in target_dirs:
        if os.path.islink(wt_dir) or not os.path.realpath(wt_dir).startswith(base_path + os.sep):
            continue
        if not os.path.exists(wt_dir):
            continue

        if remove_all:
            try:
                for root, _, files in os.walk(wt_dir):
                    for f in files:
                        fp = os.path.join(root, f)
                        try:
                            bytes_freed += os.path.getsize(fp)
                        except OSError:
                            pass
                shutil.rmtree(wt_dir, ignore_errors=True)
                cleaned_files.append(wt_dir)
            except Exception as e:
                print(f"[!] Warning removing worktree {wt_dir}: {e}")
            continue

        # Prune temporary harness files and cache within the worktree
        for root, dirs, files in os.walk(wt_dir):
            for d in list(dirs):
                if d == "__pycache__":
                    cache_dir = os.path.join(root, d)
                    try:
                        for croot, _, cfiles in os.walk(cache_dir):
                            for cf in cfiles:
                                bytes_freed += os.path.getsize(os.path.join(croot, cf))
                        shutil.rmtree(cache_dir, ignore_errors=True)
                        cleaned_files.append(cache_dir)
                        dirs.remove(d)
                    except OSError:
                        pass

            for f in files:
                if f in HARNESS_FILES or f.endswith(".pyc") or f.endswith(".tmp") or f.endswith(".db"):
                    file_path = os.path.join(root, f)
                    try:
                        size = os.path.getsize(file_path)
                        os.remove(file_path)
                        cleaned_files.append(file_path)
                        bytes_freed += size
                    except OSError:
                        pass

    if cleaned_files:
        print(f"[MuseVerify Stage-2] Pruned {len(cleaned_files)} temporary worktree file(s) ({bytes_freed} bytes freed).")
    return {
        "status": "success",
        "vuln_id": vuln_id,
        "cleaned_files": cleaned_files,
        "cleaned_count": len(cleaned_files),
        "bytes_freed": bytes_freed,
    }

def create_isolated_worktree(vuln_id: str, target_file: str, content: str, auto_clean: bool = True) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", vuln_id) or vuln_id in (".", ".."):
        raise ValueError("Invalid worktree identifier")
    worktree_path = os.path.abspath(os.path.join("worktrees", vuln_id))
    if auto_clean and os.path.exists(worktree_path):
        clean_worktrees(vuln_id=vuln_id)
    os.makedirs(worktree_path, exist_ok=True)
    target_dest = os.path.join(worktree_path, os.path.basename(target_file))
    with open(target_dest, "w") as f:
        f.write(content)
    print(f"[MuseVerify Stage-2] Created isolated worktree at: {worktree_path}")
    return worktree_path

HARNESS_TEMPLATE = '''import importlib.util
import inspect
import asyncio
import random
import json
import os
import re
import sys
import traceback

TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)), %(target)r)
SQLI_MARKER = "AGENTWARD_SQLI"
CMD_MARKER = "AGENTWARD_CMD"
SQLI_PAYLOADS = %(sqli_payloads)s
CMD_PAYLOAD = %(cmd_payload)r


_SEEN = []


def _emit(probe, ok, detail=""):
    record = {"probe": probe, "ok": bool(ok), "detail": str(detail)[:200]}
    _SEEN.append(record)
    print("PROBE " + json.dumps(record))
    sys.stdout.flush()


def _load():
    spec = importlib.util.spec_from_file_location("agentward_target", TARGET)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _candidates(module):
    found = []
    for name in sorted(dir(module)):
        if name.startswith("_"):
            continue
        obj = getattr(module, name)
        if not inspect.isfunction(obj) or getattr(obj, "__module__", "") != module.__name__:
            continue
        try:
            params = list(inspect.signature(obj).parameters.values())
        except (TypeError, ValueError):
            continue
        if not params:
            continue
        found.append((name, obj))
    return found


def _sqli_payloads():
    for payload in SQLI_PAYLOADS:
        yield payload


def _normalize(text):
    return re.sub(r"[\\s'\\"\\\\]", "", text)


def _looks_echoed(text):
    """True when the marker is present only as the literal payload text.

    Real result rows carry the marker without the SQL keywords; an echoed
    argument (e.g. `CompletedProcess.args`) carries the whole payload, including
    UNION/SELECT. Keyword matching survives repr escaping, comment styles and
    whitespace mutations.
    """
    lowered = text.lower()
    return "union" in lowered and "select" in lowered


def _probe_sqli(fn):
    for payload in _sqli_payloads():
        try:
            result = fn(payload)
            if inspect.isawaitable(result):
                result = asyncio.run(result)
        except Exception:
            continue
        text = repr(result)
        if SQLI_MARKER not in text:
            continue
        # A passthrough (returns the input unchanged) is not a breakout.
        if text.strip() == repr(payload).strip():
            continue
        if _looks_echoed(text):
            continue
        return True, payload
    return False, ""


def _probe_cmd(fn):
    """Proof of shell execution: the injected `echo` must create the marker file."""
    marker_path = os.path.join(os.path.dirname(os.path.abspath(TARGET)), ".agentward_cmd_marker")
    try:
        os.remove(marker_path)
    except OSError:
        pass
    try:
        result = fn(CMD_PAYLOAD.replace("__MARKER__", marker_path))
        if inspect.isawaitable(result):
            asyncio.run(result)
    except Exception:
        pass
    if os.path.exists(marker_path):
        try:
            content = open(marker_path, encoding="utf-8", errors="replace").read()
        except OSError:
            content = ""
        return CMD_MARKER in content, marker_path
    return False, ""


def _run_setup(module):
    """Call obvious bootstrap helpers so probes hit a populated schema."""
    for name in sorted(dir(module)):
        lowered = name.lower()
        if name.startswith("_") or not callable(getattr(module, name)):
            continue
        if not any(k in lowered for k in ("init", "setup", "bootstrap", "create", "migrate")):
            continue
        fn = getattr(module, name)
        if getattr(fn, "__module__", "") != module.__name__:
            continue
        try:
            if not inspect.signature(fn).parameters:
                fn()
        except Exception:
            continue


def main():
    try:
        module = _load()
    except Exception:
        _emit("import", False, traceback.format_exc(limit=1))
        return
    _run_setup(module)
    if os.path.basename(TARGET) == "poisoned_app.py":
        import sqlite3
        with sqlite3.connect("users.db") as db:
            db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT)")
            db.execute("INSERT INTO users VALUES (1, 'agentward_normal')")
    if os.path.basename(TARGET) == "cwe_89_sqli.py":
        import sqlite3
        with sqlite3.connect(module.DB_PATH) as db:
            db.execute("INSERT INTO products (name, sku) VALUES ('agentward_normal', 'safe-sku')")
    candidates = _candidates(module)
    _emit("candidates", bool(candidates), [n for n, _ in candidates])
    for name, fn in candidates:
        if any(word in name.lower() for word in ("token", "otp", "nonce", "password")):
            try:
                random.seed(451); first = fn()
                random.seed(451); second = fn()
                _emit("weak_prng:" + name, first == second)
            except Exception:
                pass
        try:
            ok, payload = _probe_sqli(fn)
        except Exception:
            ok, payload = False, ""
        if ok:
            _emit("sqli_union:" + name, True, payload)
        cmd_ok, cmd_path = _probe_cmd(fn)
        _emit("cmd:" + name, cmd_ok, cmd_path)
    _emit("completed", True)
    if any(p.get("ok") and str(p.get("probe", "")).startswith(("sqli_union", "cmd:", "weak_prng:")) for p in _SEEN):
        print("VULN_CONFIRMED")


main()
'''

# Syscalls an honest harness should stay inside; anything else is worth a look.
BENIGN_EXEC_BASENAMES = {
    "sh", "dash", "bash", "python3", "python", "strace", "env",
    "ls", "cat", "grep", "id", "whoami", "uname", "echo", "ping",
}
REQUIRED_EXPLOIT_MARKERS = ("AGENTWARD_SQLI", "AGENTWARD_CMD")


def default_sqli_payloads() -> list:
    payloads = []
    for cols in range(1, 7):
        fields = ["1"] * cols
        fields[min(1, cols - 1)] = "'AGENTWARD_SQLI'"
        payloads.append("' UNION SELECT " + ",".join(fields) + " -- ")
    return payloads


DEFAULT_CMD_PAYLOAD = "127.0.0.1; echo AGENTWARD_CMD > __MARKER__"


def synthesize_verification_harness(
    target_file: str,
    content: str,
    sqli_payloads: list | None = None,
    cmd_payload: str | None = None,
) -> dict:
    """Build an *executing* harness: it imports the target and fires payloads.

    Each probe prints a structured `PROBE {...}` line, so exploit confirmation no
    longer depends on the process exit code (which a polymorphic payload can fake).
    Payload lists are injectable so Stage 4.5 can re-run mutated variants.
    """
    print("[MuseVerify Stage-2] Generating execution harness with live sycall probes...")
    target_name = os.path.basename(target_file)
    resolved_sqli = sqli_payloads or default_sqli_payloads()
    resolved_cmd = cmd_payload or DEFAULT_CMD_PAYLOAD
    return {
        "verification_test_code": HARNESS_TEMPLATE % {
            "target": target_name,
            "sqli_payloads": repr(resolved_sqli),
            "cmd_payload": resolved_cmd,
        },
        "sqli_payloads": list(resolved_sqli),
        "cmd_payload": resolved_cmd,
    }


def parse_probes(stdout: str) -> list:
    probes = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("PROBE "):
            continue
        try:
            record = json.loads(line[6:])
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and isinstance(record.get('probe'), str) and type(record.get('ok')) is bool:
            probes.append(record)
    return probes


def analyze_syscall_sequence(events: list, stdout: str = "", target_file: str = "") -> dict:
    """Heuristic behavioural triage over the recorded syscall trail.

    Deliberately independent of the exit code: we look for shell escapes, exec of
    binaries that were never part of the harness, and out-of-workspace writes.
    """
    events = events or []
    reasons = []
    decisive = 0
    weak = 0

    shell_escapes = [
        e for e in events
        if e.get("syscall") == "sys_enter_execve"
        and (e.get("shell") or os.path.basename(str(e.get("argv", "")).strip('"'))
             in ("sh", "bash", "dash", "zsh", "ksh"))
    ]
    if shell_escapes:
        decisive += 4
        reasons.append(f"shell escape x{len(shell_escapes)} (sh -c with injected payload)")

    payload_in_exec = [
        e for e in events
        if e.get("syscall") == "sys_enter_execve"
        and e not in shell_escapes
        and any(m in str(e.get("args", "")) for m in REQUIRED_EXPLOIT_MARKERS)
    ]
    if payload_in_exec:
        weak += 1
        reasons.append(f"payload reached an exec sink x{len(payload_in_exec)} (argv list, no shell)")

    unknown_execs = []
    for event in events:
        if event.get("syscall") != "sys_enter_execve":
            continue
        argv = str(event.get("argv", ""))
        base = os.path.basename(argv.strip().strip('"')) if argv else ""
        if base and base not in BENIGN_EXEC_BASENAMES and base not in unknown_execs:
            unknown_execs.append(base)
    if unknown_execs:
        weak += 2
        reasons.append("unexpected execve: " + ", ".join(unknown_execs[:5]))

    outside_writes = [
        e for e in events
        if e.get("syscall") == "sys_enter_openat"
        and (str(e.get("flag", "")) in ("w", "a", "w+", "a+", "r+")
             or any(flag in str(e.get("flag", "")) for flag in ("O_WRONLY", "O_RDWR", "O_CREAT")))
        and not str(e.get("path", "")).startswith("/workspace")
        and "/worktrees/" not in str(e.get("path", ""))
        # Redirecting output to the null device does not modify external state.
        and e.get("path") != "/dev/null"
    ]
    if outside_writes:
        weak += 1
        reasons.append(f"{len(outside_writes)} write(s) outside the worktree")

    # `ls -l` consults libc's local name-service cache. Preserve that event in
    # the trace, but distinguish its exact Unix socket from network egress.
    connects = [e for e in events if e.get("syscall") == "sys_enter_connect"
                and not re.fullmatch(r'\{sa_family=AF_UNIX, sun_path="/(?:var/)?run/nscd/socket"\}',
                                     str(e.get("addr", "")))]
    if connects:
        weak += 1
        reasons.append(f"egress attempt x{len(connects)} (network is disabled)")

    probes = parse_probes(stdout)
    exploit_probes = [p for p in probes if str(p.get("probe", "")).startswith(("sqli_union", "cmd:", "weak_prng:", "chain:"))]
    probe_hit = [p for p in exploit_probes if p.get("ok")]
    if any(str(p.get("probe", "")).startswith("sqli_union") for p in probe_hit):
        reasons.append("UNION payload broke out of the query string")
    if any(str(p.get("probe", "")).startswith("cmd:") for p in probe_hit):
        reasons.append("injected shell builtin wrote the marker file")

    # The probes are the ground truth on whether the bug is *still reachable*.
    # Syscall evidence alone cannot tell a patched sink from an unpatched one:
    # `os.system` always shows a shell, quoted or not. So only when the harness
    # fired no exploit probe at all do we fall back to pure syscall scoring.
    if probe_hit:
        decisive += 4
        verdict = "EXPLOITABLE"
    elif exploit_probes:
        verdict = "SUSPICIOUS" if weak >= 3 else "BENIGN"
    else:
        decisive = 0
        verdict = "EXPLOITABLE" if shell_escapes or unknown_execs else (
            "SUSPICIOUS" if weak >= 3 else "BENIGN"
        )
    score = decisive + weak
    return {
        "verdict": verdict,
        "evasion_score": score,
        "decisive_score": decisive,
        "weak_score": weak,
        "signals": reasons,
        "probe_count": len(probes),
        "probe_hits": len(probe_hit),
        "event_count": len(events),
        "shell_escape": bool(shell_escapes),
        "unknown_execs": unknown_execs,
    }


def describe_syscall_trail(events: list, limit: int = 8) -> list:
    """Compact `syscall detail` strings for dashboard streaming."""
    lines = []
    for event in (events or [])[:limit]:
        detail = event.get("argv") or event.get("path") or event.get("addr") or ""
        lines.append(f"{event.get('syscall', '?')} {str(detail)[:90]}")
    return lines


async def ai_syscall_verdict(events: list, stdout: str, target_file: str) -> dict:
    """Second opinion from the auditor model over the behavioural trace."""
    from ai_provider import query_ai

    digest = "\n".join(
        f"{e.get('syscall')} {e.get('argv') or e.get('path') or e.get('addr') or ''}"[:160]
        for e in (events or [])[:60]
    ) or "<no syscalls recorded>"
    prompt = (
        "You are auditing a sandbox run for a Python vulnerability benchmark.\n"
        f"Target: {os.path.basename(target_file)}\n"
        "Syscall trail:\n" + digest + "\n\n"
        "Harness stdout (truncated):\n" + (stdout or "")[:1200] + "\n\n"
        "Decide whether an exploit actually fired, i.e. whether user input escaped into a "
        "shell or out of the SQL string. Ignore the exit code entirely.\n"
        'Reply with ONLY JSON: {"exploitable": bool, "evasion": bool, "reason": string}'
    )
    try:
        raw = await query_ai(
            prompt,
            system_prompt="You are a precise syscall forensics reviewer. Output only JSON.",
            provider=os.environ.get("AUDITOR_PROVIDER", "meta"), task="policy_check", reasoning_effort="medium",
        )
        if "```" in raw:
            raw = raw.split("```")[1].replace("json", "", 1).strip()
        start, end = raw.find("{"), raw.rfind("}")
        parsed = json.loads(raw[start:end + 1])
        return {
            "source": "ai",
            "exploitable": bool(parsed.get("exploitable", False)),
            "evasion": bool(parsed.get("evasion", False)),
            "reason": str(parsed.get("reason", ""))[:300],
        }
    except Exception as exc:
        return {"source": "ai", "exploitable": None, "evasion": None, "reason": f"auditor unavailable: {exc}"}

SANDBOX_RUN_SEQ = itertools.count(1)

LOCAL_AUDIT_SHIM = r'''
import json, os, sys, runpy
LOG = os.environ["AGENTWARD_AUDIT_LOG"]
TRACED = {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "open",
          "os.remove", "os.unlink", "socket.connect", "socket.getaddrinfo"}
NOISE = ("site-packages", "__pycache__", "/usr/lib/python", "/usr/local/lib/python", ".so", ".pyc")
_state = {"n": 0, "fh": open(LOG, "w", encoding="utf-8")}


def _emit(kind, detail):
    if _state["n"] >= 500:
        return
    _state["n"] += 1
    _state["fh"].write(json.dumps({"syscall": kind, **detail}) + "\n")
    _state["fh"].flush()


def _hook(event, args):
    if event not in TRACED:
        return
    if event in ("subprocess.Popen", "os.exec", "os.posix_spawn"):
        raw = args[0] if event != "os.system" else "/bin/sh"
        detail = args[1] if event == "os.system" else (args[1] if len(args) > 1 else [])
        shell = isinstance(detail, str) or (
            isinstance(raw, str) and os.path.basename(raw) in ("sh", "bash", "dash")
        )
        _emit("sys_enter_execve", {"argv": str(raw), "args": str(detail)[:400],
                                   "shell": bool(shell), "source": "audit_hook"})
    elif event == "open":
        path = str(args[0]) if args else "?"
        if any(f in path for f in NOISE):
            return
        _emit("sys_enter_openat", {"path": path, "flag": str(args[1] if len(args) > 1 else "r"), "source": "audit_hook"})
    elif event == "os.system":
        _emit("sys_enter_execve", {"argv": "/bin/sh", "args": str(args[0])[:400],
                                   "shell": True, "source": "audit_hook"})
    elif event in ("os.remove", "os.unlink"):
        _emit("sys_enter_unlinkat", {"path": str(args[0]) if args else "?", "source": "audit_hook"})
    elif event == "socket.connect":
        _emit("sys_enter_connect", {"addr": str(args[1]) if len(args) > 1 else "?", "source": "audit_hook"})
    elif event == "socket.getaddrinfo":
        _emit("sys_enter_connect", {"addr": "dns:" + str(args[0]), "source": "audit_hook"})


sys.addaudithook(_hook)
_script = sys.argv[1]
sys.argv = [_script]
try:
    runpy.run_path(_script, run_name="__main__")
finally:
    _state["fh"].close()
'''


def _local_execute(vuln_id: str, target_file: str, code_content: str, test_code: str) -> dict:
    """Local fallback that still produces a syscall trail via the audit hook."""
    os.makedirs("worktrees", exist_ok=True)
    run_dir = tempfile.mkdtemp(prefix="sandbox-", dir=os.path.abspath("worktrees"))
    target_name = os.path.basename(target_file)
    with open(os.path.join(run_dir, target_name), "w") as f:
        f.write(code_content)
    with open(os.path.join(run_dir, "verify_test.py"), "w") as f:
        f.write(test_code)
    with open(os.path.join(run_dir, "agentward_runner.py"), "w") as f:
        f.write(LOCAL_AUDIT_SHIM)

    audit_log = os.path.join(run_dir, "syscall_audit.jsonl")
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT")}
    env.update(AGENTWARD_AUDIT_LOG=audit_log, HOME=run_dir, PYTHONDONTWRITEBYTECODE="1")
    try:
        res = subprocess.run(
            [sys.executable, "agentward_runner.py", "verify_test.py"],
            cwd=run_dir, capture_output=True, text=True, timeout=10, env=env,
        )
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "verified": False, "stdout": "", "stderr": "timeout",
                "engine": "local", "trace_backend": "audit_hook", "syscall_events": []}

    events = []
    if os.path.exists(audit_log):
        with open(audit_log, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return {
        "exit_code": res.returncode,
        "verified": False,  # decided by the caller from syscall analysis
        "stdout": res.stdout,
        "stderr": res.stderr,
        "engine": "local",
        "trace_backend": "audit_hook",
        "syscall_events": events,
    }


REMOTE_CAPABILITY = {"stale": False}


def _remote_is_instrumented(data: dict) -> bool:
    """True when the node runs a build that streams syscall telemetry."""
    return "trace_backend" in data or bool(data.get("syscall_events"))


def execute_test_on_lightsail(vuln_id: str, target_file: str, code_content: str, test_code: str) -> dict:
    payload = json.dumps({
        "vuln_id": vuln_id,
        "target_file": os.path.basename(target_file),
        "code_content": code_content,
        "test_code": test_code,
        "capture_mode": "auto",
    }).encode("utf-8")

    req = urllib.request.Request(
        LIGHTSAIL_SANDBOX_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        raise RuntimeError('Remote Docker sandbox unavailable; verification denied') from exc
    if data.get('engine') != 'docker' or data.get('trace_backend') != 'strace' or not data.get('syscall_events') or data.get('trace_complete') is not True:
        raise RuntimeError('Docker and strace evidence required; verification denied')
    if data.get('source_sha256') != hashlib.sha256(code_content.encode()).hexdigest() or data.get('harness_sha256') != hashlib.sha256(test_code.encode()).hexdigest():
        raise RuntimeError('Sandbox evidence does not match the submitted source and harness')
    return data


def run_sandboxed(vuln_id: str, target_file: str, code_content: str, test_code: str, *, allow_test_backend=False) -> dict:
    """Production always requires Docker. Host execution is explicit test-only."""
    if os.environ.get("AGENTWARD_FORCE_LOCAL") == "1":
        if not allow_test_backend or os.getenv("AGENTWARD_REQUIRE_DOCKER") == "1":
            raise RuntimeError("Local execution is disabled by production policy")
        return _local_execute(vuln_id, target_file, code_content, test_code)
    return execute_test_on_lightsail(vuln_id, target_file, code_content, test_code)


def triage_sandbox_result(result: dict, target_file: str = "") -> dict:
    """Decide whether the exploit actually fired — the exit code is a tiebreaker.

    An EXPLOITABLE verdict always counts. When the harness reported probes but
    none of them succeeded, the bug is neutralized even though the process
    exited 0. Exit codes only matter when the run produced no telemetry at all.
    """
    analysis = analyze_syscall_sequence(
        result.get("syscall_events", []), result.get("stdout", ""), target_file
    )
    probes = parse_probes(result.get("stdout", ""))
    import_failed = any(p.get("probe") == "import" and not p.get("ok") for p in probes)
    completed = any(p.get("probe") == "completed" and p.get("ok") for p in probes)
    # Old nodes may not emit completed; actual exploit probes still confirm a bug.
    usable = result.get("exit_code") == 0 and completed and not import_failed
    confirmed = analysis["verdict"] == "EXPLOITABLE"
    if not confirmed and (not usable or analysis["verdict"] != "BENIGN"):
        analysis["verdict"] = "INCONCLUSIVE"
    return {**analysis, "confirmed": confirmed, "execution_valid": usable,
            "safe": usable and analysis["verdict"] == "BENIGN",
            "exit_code": result.get("exit_code"), "probes": probes,
            "evidence_verified": usable and result.get('engine') == 'docker' and result.get('trace_backend') == 'strace' and bool(result.get('syscall_events')) and result.get('trace_complete') is True}



async def triage_sandbox_result_async(result: dict, target_file: str = "") -> dict:
    """Same verdict as `triage_sandbox_result`, plus an AI second opinion.

    The model only gets to move the needle when the harness produced no exploit
    probe ground truth — i.e. when the syscall trail is the sole evidence. Probe
    hits stay decisive so the auditor cannot talk us out of a real breakout.
    """
    triage = triage_sandbox_result(result, target_file)
    events = result.get("syscall_events", [])

    if triage["probe_count"] or not events:
        return {**triage, "auditor": None}

    second = await ai_syscall_verdict(events, result.get("stdout", ""), target_file)
    triage["auditor"] = second
    if second.get("exploitable") or second.get("evasion"):
        triage["verdict"] = "EXPLOITABLE"
        triage["confirmed"] = True
        triage["signals"] = triage["signals"] + [f"auditor: {second.get('reason', '')[:120]}"]
    return triage

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "poisoned_app.py"
    with open(target, "r") as f:
        content = f.read()
    wt = create_isolated_worktree("VULN-001", target, content)
    harness = synthesize_verification_harness(target, content)
    res = execute_test_on_lightsail("VULN-001", target, content, harness["verification_test_code"])
    print(json.dumps(res, indent=2))
