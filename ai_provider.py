#!/usr/bin/env python3
"""Backwards-compatible model router with task-scoped, provider-reported telemetry.

Prompt caching is provider prefix caching, never a cache of security decisions.
Prices are estimates in USD; unconfigured tariffs/absent usage remain unknown.
"""
import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import os
import re
import shutil
import tempfile
import time

import httpx
from dotenv import load_dotenv

load_dotenv()
ACTIVE_PROVIDER = os.getenv("ACTIVE_AI_PROVIDER", "meta").lower()
META_API_KEY = os.getenv("META_API_KEY")
META_BASE_URL = os.getenv("META_API_BASE_URL", "https://api.meta.ai/v1")
AGY_MODEL = os.getenv("AGY_SELECTED_MODEL", "gemini-4-argon")
CUSTOM_URL = os.getenv("CUSTOM_API_URL")
CUSTOM_KEY = os.getenv("CUSTOM_API_KEY")
CUSTOM_MODEL = os.getenv("CUSTOM_MODEL_NAME") or "openai/gpt-6.1-sol"
REASONING_EFFORTS = {"low", "medium", "high", "xhigh", "max"}
DEEP_TASKS = {"patch_synthesis", "patch_verification", "semantic_hunt", "root_cause"}
_SCOPE = ContextVar("ai_telemetry", default=None)
_SECRET_NAME = re.compile(r"API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL", re.I)


@contextmanager
def telemetry_scope(run_id, on_event=None):
    state = {"run_id": run_id, "calls": [], "on_event": on_event}
    token = _SCOPE.set(state)
    try:
        yield state
    finally:
        _SCOPE.reset(token)


def telemetry_summary(calls):
    known = [c["estimated_cost_usd"] for c in calls if c.get("estimated_cost_usd") is not None]
    return {
        "calls": list(calls), "request_count": len(calls),
        "input_tokens": sum(c.get("input_tokens") or 0 for c in calls),
        "output_tokens": sum(c.get("output_tokens") or 0 for c in calls),
        "cached_input_tokens": sum(c.get("cached_input_tokens") or 0 for c in calls),
        "latency_ms": round(sum(c["latency_ms"] for c in calls), 2),
        "estimated_cost_usd": round(sum(known), 8) if known else None,
        "cost_complete": bool(calls) and len(known) == len(calls),
        "usage_complete": bool(calls) and all(c.get("usage_reported") for c in calls),
    }


def _usage(data):
    usage = data.get("usage") or {}
    # AGY versions may expose Gemini usageMetadata or per-model stats.
    if not usage and isinstance(data.get("usageMetadata"), dict):
        u = data["usageMetadata"]
        usage = {"prompt_tokens": u.get("promptTokenCount"),
                 "completion_tokens": u.get("candidatesTokenCount"),
                 "cached_tokens": u.get("cachedContentTokenCount", 0)}
    stats = (data.get("stats") or {}).get("models", {})
    if not usage and stats:
        counters = [m.get("tokens", {}) for m in stats.values()]
        usage = {"prompt_tokens": sum(t.get("prompt", t.get("input", 0)) for t in counters),
                 "completion_tokens": sum(t.get("candidates", 0) + t.get("thoughts", 0) for t in counters),
                 "cached_tokens": sum(t.get("cached", 0) for t in counters)}
    def count(value):
        return value if type(value) is int and value >= 0 else None
    inp = count(usage.get("prompt_tokens", usage.get("input_tokens")))
    out = count(usage.get("completion_tokens", usage.get("output_tokens")))
    details = usage.get("prompt_tokens_details") or usage.get("input_tokens_details") or {}
    return {"input_tokens": inp, "output_tokens": out,
            "cached_input_tokens": count(details.get("cached_tokens", usage.get("cached_tokens"))),
            "cache_write_tokens": count(details.get("cache_write_tokens")),
            "reasoning_tokens": count((usage.get("completion_tokens_details") or usage.get("output_tokens_details") or {}).get("reasoning_tokens")),
            "usage_reported": inp is not None and out is not None}


def _cost(provider, model, usage):
    if not usage["usage_reported"]:
        return None
    tariffs = json.loads(os.getenv("AI_PRICING_JSON", "{}"))
    rates = tariffs.get(f"{provider}:{model}") or tariffs.get(model)
    if rates is None and model.removeprefix("openai/") == "gpt-6.1-sol":
        rates = {"input": 2.0, "output": 10.0, "cached_input": 0.10, "cache_write": 2.50}
    if rates is None:
        return None
    inp, out = usage["input_tokens"], usage["output_tokens"]
    cached = min(usage["cached_input_tokens"] or 0, inp)
    writes = min(usage["cache_write_tokens"] or 0, inp - cached)
    long = model.removeprefix("openai/") == "gpt-6.1-sol" and inp > 272000
    return ((inp-cached-writes)*rates["input"] + cached*rates.get("cached_input", rates["input"])
            + writes*rates.get("cache_write", rates["input"])) * (2 if long else 1) / 1e6 + out*rates["output"]*(1.5 if long else 1)/1e6


async def _cli_data(cmd, env):
    # Never run the reasoning CLI from the directory containing hostile sources.
    with tempfile.TemporaryDirectory(prefix="agentward-review-") as scratch:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=scratch, env=env, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), float(os.getenv("AGY_TIMEOUT_S", "180")))
        except (asyncio.TimeoutError, asyncio.CancelledError):
            if proc.returncode is None:
                proc.kill()
            await proc.communicate()
            raise
        if proc.returncode:
            raise RuntimeError(f"Anti-Gravity exited with status {proc.returncode}")
    raw = stdout.decode("utf-8").strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"response": raw}
    if not isinstance(data, dict) or data.get("status") in ("ERROR", "FAILED"):
        raise ValueError("Anti-Gravity returned an unsuccessful response")
    return data


async def asyncio_subprocess_exec_helper(cmd, env):
    data = await _cli_data(cmd, env)
    return _content(data)


def _content(data):
    if isinstance(data.get("structured_output"), dict):
        return json.dumps(data["structured_output"])
    if "choices" in data:
        content = data["choices"][0]["message"]["content"]
    else:
        content = data.get("response", data.get("output_text"))
        if content is None and "output" in data:
            content = "".join(part.get("text", "") for item in data["output"]
                              for part in item.get("content", []) if part.get("type") == "output_text")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Provider returned no text")
    return content


async def query_ai(prompt: str, system_prompt: str = "", provider: str | None = None,
                   model: str | None = None, *, reasoning_effort: str | None = None,
                   task: str = "policy_check", prompt_cache: bool = True) -> str:
    target = (provider or ACTIVE_PROVIDER).lower()
    target = {"gemini": "antigravity", "claude": "antigravity", "agy": "antigravity",
              "byok": "custom", "openai": "custom"}.get(target, target)
    if target not in {"meta", "antigravity", "custom"}:
        raise ValueError(f"Unknown AI provider: {target}")
    chosen = model or ({"meta": "muse-wonder-1.0" if task in DEEP_TASKS else "muse-spark-1.3",
                       "antigravity": AGY_MODEL, "custom": CUSTOM_MODEL}[target])
    effort = reasoning_effort or ("xhigh" if task in DEEP_TASKS else "medium")
    if effort not in REASONING_EFFORTS:
        raise ValueError(f"Unsupported reasoning_effort: {effort}")
    is_sol = chosen.removeprefix("openai/") == "gpt-6.1-sol"
    start, data, error = time.perf_counter(), {}, None
    try:
        if target == "antigravity":
            binary = os.getenv("AGY_BIN") or shutil.which("agy") or os.path.expanduser("~/.local/bin/agy")
            combined = f"{system_prompt}\n\n{prompt}"
            if len(combined.encode()) > 120000:
                raise ValueError("Review context exceeds CLI argument limit")
            cmd = [binary, "-p", combined, "--model", chosen, "--output-format", "json",
                   "--sandbox", "--disable-slash-commands"]
            env = {k: v for k, v in os.environ.items()
                   if not _SECRET_NAME.search(k) or k.startswith(("AGY_", "GEMINI_", "GOOGLE_"))}
            data = await _cli_data(cmd, env)
        else:
            key = META_API_KEY if target == "meta" else CUSTOM_KEY
            url = META_BASE_URL.rstrip("/") + "/chat/completions" if target == "meta" else CUSTOM_URL
            if not key or not url:
                raise ValueError(f"{target} endpoint and API key must be configured")
            messages = ([{"role": "system", "content": system_prompt}] if system_prompt else [])
            messages.append({"role": "user", "content": prompt})
            responses_api = url.rstrip("/").endswith("/responses")
            payload = {"model": chosen, "input" if responses_api else "messages": messages}
            if is_sol:
                payload.update({"reasoning": {"effort": effort}} if responses_api else {"reasoning_effort": effort})
                if prompt_cache and os.getenv("CUSTOM_PROMPT_CACHE", "1") == "1":
                    prefix = f"agentward-v2:{chosen}:{task}:{system_prompt}"
                    payload["prompt_cache_key"] = hashlib.sha256(prefix.encode()).hexdigest()
            async with httpx.AsyncClient(timeout=float(os.getenv("AI_TIMEOUT_S", "120"))) as client:
                resp = await client.post(url, json=payload, headers={"Authorization": f"Bearer {key}"})
                if resp.is_error:
                    raise RuntimeError(f"{target} HTTP {resp.status_code}")
                data = resp.json()
            if data.get("status") == "incomplete":
                raise ValueError("Provider response incomplete")
        return _content(data)
    except BaseException as exc:
        error = type(exc).__name__
        raise
    finally:
        usage = _usage(data)
        try:
            cost = _cost(target, chosen, usage)
        except (ValueError, TypeError, KeyError):
            cost = None
        record = {"task": task, "provider": target, "model": chosen,
                  "reasoning_effort": effort if is_sol else None, **usage,
                  "estimated_cost_usd": cost, "latency_ms": round((time.perf_counter()-start)*1000, 2),
                  "error": error}
        state = _SCOPE.get()
        if state is not None:
            record["run_id"] = state["run_id"]
            state["calls"].append(record)
            if state["on_event"]:
                state["on_event"]("provider_usage", record)


async def query_meta_muse(prompt: str, system_prompt: str = "", model: str = "muse-spark-1.3", **kwargs) -> str:
    return await query_ai(prompt, system_prompt, "meta", model, **kwargs)


async def query_secondary_provider(prompt: str, system_prompt: str = "", model: str | None = None, **kwargs) -> str:
    return await query_ai(prompt, system_prompt, "antigravity", model or AGY_MODEL, **kwargs)
