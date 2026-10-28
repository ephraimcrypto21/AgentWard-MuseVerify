#!/usr/bin/env python3
"""
Multi-Provider AI Router for AgentWard & MuseVerify.
Supports Meta Muse, Anti-Gravity model selection, and Universal Custom BYOK endpoints (Mistral, OpenAI, etc.).
"""
import os
import json
import asyncio
import httpx
from dotenv import load_dotenv

load_dotenv()

ACTIVE_PROVIDER = os.getenv("ACTIVE_AI_PROVIDER", "meta").lower()
META_API_KEY = os.getenv("META_API_KEY")
META_BASE_URL = os.getenv("META_API_BASE_URL", "https://api.meta.ai/v1")
AGY_MODEL = os.getenv("AGY_SELECTED_MODEL", "gemini-4-argon")

CUSTOM_URL = os.getenv("CUSTOM_API_URL")
CUSTOM_KEY = os.getenv("CUSTOM_API_KEY")
CUSTOM_MODEL = os.getenv("CUSTOM_MODEL_NAME", "mistral-large-latest")


async def query_meta_muse(prompt: str, system_prompt: str = "", model: str = "muse-spark-1.3") -> str:
    """
    Sends a real HTTP/REST request to the Meta Model API for muse-spark-1.3,
    authenticating with META_API_KEY.
    """
    if not META_API_KEY:
        raise ValueError("META_API_KEY is missing in .env")

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    headers = {
        "Authorization": f"Bearer {META_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {"model": model, "messages": messages}

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(f"{META_BASE_URL}/chat/completions", json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


async def query_secondary_provider(prompt: str, system_prompt: str = "", model: str | None = None) -> str:
    """
    Invokes a secondary independent auditor (e.g. gemini-4-argon or claude-opus-5-5)
    via Anti-Gravity CLI or configured fallback.
    """
    agy_model = model or AGY_MODEL
    agy_bin = os.environ.get("AGY_BIN") or os.path.expanduser("~/.local/bin/agy")
    if not os.path.isfile(agy_bin):
        import shutil
        agy_bin = shutil.which("agy") or agy_bin

    combined_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
    cmd = [
        agy_bin, "-p", combined_prompt,
        "--model", agy_model,
        "--output-format", "json",
        "--sandbox",
        "--disable-slash-commands",
    ]
    child_env = {k: v for k, v in os.environ.items() if k != "META_API_KEY"}
    return await asyncio_subprocess_exec_helper(cmd, child_env)


async def query_ai(
    prompt: str,
    system_prompt: str = "",
    provider: str | None = None,
    model: str | None = None
) -> str:
    """Unified asynchronous router for all configured AI providers."""
    target_provider = (provider or ACTIVE_PROVIDER).lower()

    # ---------------------------------------------------------
    # Provider 1: Meta Muse (muse-spark-1.3)
    # ---------------------------------------------------------
    if target_provider == "meta":
        return await query_meta_muse(prompt, system_prompt, model=model or "muse-spark-1.3")

    # ---------------------------------------------------------
    # Provider 2: Anti-Gravity CLI (Gemini / Claude Secondary Auditors)
    # ---------------------------------------------------------
    elif target_provider in ("antigravity", "gemini", "claude"):
        return await query_secondary_provider(prompt, system_prompt, model=model or AGY_MODEL)

    # ---------------------------------------------------------
    # Provider 3: Universal Custom BYOK Endpoint (Mistral, OpenAI, etc.)
    # ---------------------------------------------------------
    elif target_provider == "custom":
        if not CUSTOM_URL or not CUSTOM_KEY:
            raise ValueError("CUSTOM_API_URL and CUSTOM_API_KEY must be configured in .env")

        headers = {"Authorization": f"Bearer {CUSTOM_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": model or CUSTOM_MODEL,
            "messages": [
                *([{"role": "system", "content": system_prompt}] if system_prompt else []),
                {"role": "user", "content": prompt}
            ]
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(CUSTOM_URL, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    else:
        raise ValueError(f"Unknown AI provider: {target_provider}")


async def asyncio_subprocess_exec_helper(cmd, env):
    proc = await asyncio.create_subprocess_exec(
        *cmd, env=env,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"AGY execution failed: {stderr.decode(errors='replace')}")
    
    output = stdout.decode("utf-8").strip()
    try:
        parsed = json.loads(output)
        return parsed.get("response", output)
    except json.JSONDecodeError:
        return output
