"""
Velocitee Prism — Sovereign Local & Sanitized Cloud Model Router (PR-08)

Routes sanitized prompts (`[PII_<TYPE>_<N>]` surrogates) to:
1. Local sovereign Ollama / vLLM endpoints (`OLLAMA_URL`, `LOCAL_LLM_URL`)
2. Cloud API-billed frontier models (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`)
   ONLY after mandatory PII redaction, followed by local surrogate re-hydration
3. Deterministic Sovereign Edge Analyzer (`execution_mode: "deterministic_edge_analyzer"`)
   when no external LLM server is reachable, performing genuine content analysis over the
   sanitized text and transparently reporting `execution_mode` in the response (PR-08).
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional


def _call_ollama(prompt: str, model_name: str, timeout: float = 8.0) -> Optional[str]:
    ollama_url = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
    payload = json.dumps(
        {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        ollama_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            text = body.get("response")
            if isinstance(text, str) and text.strip():
                return text.strip()
    except (OSError, ValueError, urllib.error.URLError):
        return None
    return None


def _call_openai_compatible(
    url: str,
    api_key: str,
    model_name: str,
    sanitized_prompt: str,
    timeout: float = 12.0,
) -> Optional[str]:
    if not api_key:
        return None
    payload = json.dumps(
        {
            "model": model_name,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are operating behind Velocitee Prism Sovereign Privacy Proxy. "
                        "Preserve all [PII_*] surrogate tokens verbatim in your response."
                    ),
                },
                {"role": "user", "content": sanitized_prompt},
            ],
            "temperature": 0.2,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            choices = data.get("choices", [])
            if choices and isinstance(choices[0], dict):
                msg = choices[0].get("message", {})
                content = msg.get("content")
                if isinstance(content, str) and content.strip():
                    return content.strip()
    except (OSError, ValueError, urllib.error.URLError):
        return None
    return None


def _call_anthropic(
    api_key: str,
    model_name: str,
    sanitized_prompt: str,
    timeout: float = 12.0,
) -> Optional[str]:
    if not api_key:
        return None
    payload = json.dumps(
        {
            "model": model_name,
            "max_tokens": 512,
            "system": (
                "You are operating behind Velocitee Prism Sovereign Privacy Proxy. "
                "Preserve all [PII_*] surrogate tokens verbatim in your response."
            ),
            "messages": [{"role": "user", "content": sanitized_prompt}],
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content_list = data.get("content", [])
            if content_list and isinstance(content_list[0], dict):
                text = content_list[0].get("text")
                if isinstance(text, str) and text.strip():
                    return text.strip()
    except (OSError, ValueError, urllib.error.URLError):
        return None
    return None


def _deterministic_edge_analysis(
    sanitized_prompt: str,
    entities: List[Dict[str, object]],
    profile_id: str,
) -> str:
    """
    Performs deterministic structural analysis of `sanitized_prompt` on-device when no
    external LLM server is configured or reachable (PR-08).
    """
    sentences = [
        s.strip()
        for s in re.split(r"(?<=[.!?])\s+|\n+", sanitized_prompt)
        if s.strip()
    ]
    word_count = len(sanitized_prompt.split())
    tokens = [str(e.get("token", "")) for e in entities]
    by_type: Dict[str, int] = {}
    for e in entities:
        etype = str(e.get("type", "UNKNOWN"))
        by_type[etype] = by_type.get(etype, 0) + 1

    type_summary = (
        ", ".join(f"{k}: {v}" for k, v in sorted(by_type.items()))
        if by_type
        else "none"
    )
    lead_preview = sentences[0] if sentences else sanitized_prompt[:160]

    return (
        f"[Sovereign Edge Analysis | Profile: {profile_id}]\n"
        f"- Document Structure: {len(sentences)} statement(s), {word_count} token(s).\n"
        f"- Redacted Entities ({len(tokens)} total): {type_summary}.\n"
        f"- Sanitized Content Summary: {lead_preview}\n"
        f"- Surrogates Preserved: {', '.join(tokens) if tokens else 'No PII detected'}."
    )


def execute_model_inference(
    sanitized_prompt: str,
    entities: List[Dict[str, object]],
    profile: Dict[str, object],
    requested_model: Optional[str] = None,
) -> Dict[str, object]:
    """
    Executes inference against the profile-configured model backend and returns:
    `{output_text, model_id, upstream_model, provider, execution_mode, latency_ms, billing_mode}`
    """
    t0 = time.monotonic()
    profile_id = str(profile.get("profile_id", "default"))
    routing_table = profile.get("model_routing", {})
    if not isinstance(routing_table, dict):
        routing_table = {}

    default_model_id = str(profile.get("default_model", "prism-sovereign-local"))
    model_id = requested_model if (requested_model and requested_model in routing_table) else (
        requested_model or default_model_id
    )
    route_cfg = routing_table.get(model_id, {})
    if not isinstance(route_cfg, dict):
        route_cfg = {}

    provider = str(route_cfg.get("provider", "local_ollama"))
    upstream_model = str(route_cfg.get("upstream_model", model_id))
    billing_mode = str(route_cfg.get("billing_mode", "sovereign_zero_marginal_cost"))
    rehydrate_response = bool(route_cfg.get("rehydrate_response", False))

    output_text: Optional[str] = None
    execution_mode = "deterministic_edge_analyzer"

    if provider == "local_ollama":
        output_text = _call_ollama(sanitized_prompt, upstream_model)
        if output_text is not None:
            execution_mode = "local_ollama"
    elif provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        output_text = _call_anthropic(api_key, upstream_model, sanitized_prompt)
        if output_text is not None:
            execution_mode = "cloud_sanitized_anthropic"
    elif provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY", "")
        output_text = _call_openai_compatible(
            "https://api.openai.com/v1/chat/completions",
            api_key,
            upstream_model,
            sanitized_prompt,
        )
        if output_text is not None:
            execution_mode = "cloud_sanitized_openai"
    elif provider == "openrouter":
        api_key = os.environ.get("OPENROUTER_API_KEY", "")
        output_text = _call_openai_compatible(
            "https://openrouter.ai/api/v1/chat/completions",
            api_key,
            upstream_model,
            sanitized_prompt,
        )
        if output_text is not None:
            execution_mode = "cloud_sanitized_openrouter"

    if output_text is None:
        output_text = _deterministic_edge_analysis(sanitized_prompt, entities, profile_id)
        execution_mode = "deterministic_edge_analyzer"

    latency_ms = round((time.monotonic() - t0) * 1000.0, 2)
    return {
        "output_text": output_text,
        "model_id": model_id,
        "upstream_model": upstream_model,
        "provider": provider,
        "billing_mode": billing_mode,
        "execution_mode": execution_mode,
        "rehydrate_response": rehydrate_response,
        "latency_ms": latency_ms,
    }
