"""
Velocitee Prism — Hermes Agent (NousResearch/hermes-agent) Sovereign Bridge

Provides:
1. OpenAI-compatible Privacy Proxy (`POST /v1/chat/completions`, `GET /v1/models`):
   Intercepts agent messages, redacts PII into `[PII_<TYPE>_<N>]` surrogates in a
   request-scoped `EphemeralVault`, routes sanitized messages to local Ollama or
   API-billed frontier models (Claude, GPT-4o, Hermes-3-70B), and re-hydrates
   surrogates locally before returning the completion to Hermes Agent.
2. Model Context Protocol (MCP) JSON-RPC 2.0 Server (`POST /api/v1/mcp`):
   Exposes `prism_redact_text`, `prism_sovereign_infer`, `prism_list_profiles`,
   and `prism_upsert_profile` so Hermes Agent can chain privacy-preserving tools
   and subagents across enterprise workflows.
"""

from __future__ import annotations

import time
import uuid
from typing import Dict, List, Optional, Tuple

from .model_client import execute_model_inference
from .profiles import ProfileRegistry
from .receipt import ComplianceLedger
from .redaction import EphemeralVault


MCP_TOOLS_SPEC: List[Dict[str, object]] = [
    {
        "name": "prism_redact_text",
        "description": "Redacts European/Nordic PII (names, IBANs, Isikukood/HETU/Personnummer, cards, emails, phones, currency) under a customizable company profile.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Raw text to sanitize"},
                "profile_id": {"type": "string", "description": "Company profile ID (e.g., default, telia-nordic-core, eu-finserv-strict, hermes-hybrid-agent)"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "prism_sovereign_infer",
        "description": "Runs privacy-preserving inference with automatic pre-egress PII redaction, hybrid model routing (local Ollama or sanitized Claude/GPT/Hermes), and HMAC-SHA256 compliance receipt.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string", "description": "Input prompt or document"},
                "profile_id": {"type": "string", "description": "Company profile ID"},
                "model": {"type": "string", "description": "Target routed model ID"},
            },
            "required": ["prompt"],
        },
    },
    {
        "name": "prism_list_profiles",
        "description": "Lists all available company privacy & model-routing profiles registered in Velocitee Prism.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "prism_upsert_profile",
        "description": "Creates or updates a customizable company profile with custom regexes, allowlists, and hybrid model routing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "profile_id": {"type": "string"},
                "name": {"type": "string"},
                "description": {"type": "string"},
                "enabled_entities": {"type": "array", "items": {"type": "string"}},
                "custom_patterns": {"type": "array", "items": {"type": "object"}},
                "allowlist": {"type": "array", "items": {"type": "string"}},
                "default_model": {"type": "string"},
                "set_active": {"type": "boolean"},
            },
            "required": ["profile_id"],
        },
    },
]


def build_hermes_manifest(host_url: str, registry: ProfileRegistry) -> Dict[str, object]:
    """Returns the Hermes Agent integration manifest and ready-to-use config snippet."""
    active_prof = registry.get_profile()
    routing = active_prof.get("model_routing", {})
    models = list(routing.keys()) if isinstance(routing, dict) else ["prism-sovereign-local"]

    return {
        "integration": "NousResearch/hermes-agent",
        "prism_version": "2.0.0-bilberry",
        "prism_codename": "Bilberry",
        "protocol_versions": {
            "openai_proxy": "v1",
            "mcp_jsonrpc": "2024-11-05",
        },
        "active_profile_id": registry.get_active_profile_id(),
        "available_models": models,
        "endpoints": {
            "openai_base_url": f"{host_url}/v1",
            "chat_completions": f"{host_url}/v1/chat/completions",
            "models": f"{host_url}/v1/models",
            "mcp_http": f"{host_url}/api/v1/mcp",
            "profiles": f"{host_url}/api/v1/profiles",
        },
        "hermes_agent_config_yaml": (
            "# Hermes Agent (NousResearch/hermes-agent) Sovereign Configuration\n"
            "model:\n"
            f"  provider: custom_openai\n"
            f"  base_url: \"{host_url}/v1\"\n"
            f"  name: \"{active_prof.get('default_model', 'hermes-3-llama-70b')}\"\n"
            "mcpServers:\n"
            "  velocitee_prism:\n"
            f"    url: \"{host_url}/api/v1/mcp\"\n"
            "    transport: http\n"
        ),
        "tools": MCP_TOOLS_SPEC,
    }


def handle_openai_chat_completions(
    body: Dict[str, object],
    registry: ProfileRegistry,
    ledger: ComplianceLedger,
) -> Tuple[int, Dict[str, object]]:
    """
    Handles `POST /v1/chat/completions` for Hermes Agent and OpenAI SDK clients.
    Redacts PII across all input messages using a request-scoped `EphemeralVault`,
    executes the routed model, optionally re-hydrates surrogates locally, and destroys the vault.
    """
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        return 400, {"error": {"message": "'messages' must be a non-empty list", "type": "invalid_request_error"}}

    profile_id = str(body.get("profile_id") or registry.get_active_profile_id())
    profile = registry.get_profile(profile_id)
    engine = registry.build_engine(profile_id)
    requested_model = str(body.get("model") or profile.get("default_model", "prism-sovereign-local"))
    rehydrate_flag = bool(body.get("rehydrate", profile.get("rehydrate_cloud_responses", True)))

    vault = EphemeralVault()
    try:
        sanitized_messages: List[str] = []
        for msg in messages:
            if isinstance(msg, dict):
                role = str(msg.get("role", "user"))
                content = str(msg.get("content", ""))
                sanitized_content, _ = engine.redact(content, vault=vault)
                sanitized_messages.append(f"[{role.upper()}]: {sanitized_content}")

        combined_sanitized = "\n".join(sanitized_messages)
        public_entities = vault.public_entities

        infer_res = execute_model_inference(
            sanitized_prompt=combined_sanitized,
            entities=public_entities,
            profile=profile,
            requested_model=requested_model,
        )
        sanitized_output = str(infer_res["output_text"])
        final_output = vault.rehydrate(sanitized_output) if rehydrate_flag else sanitized_output

        audit_entry = ledger.record_operation(
            operation="HERMES_CHAT_COMPLETION",
            profile_id=profile_id,
            model_id=str(infer_res["model_id"]),
            execution_mode=str(infer_res["execution_mode"]),
            redaction_count=vault.redaction_count,
            entity_types=[str(e["type"]) for e in public_entities],
            sanitized_text=combined_sanitized,
        )

        completion_id = f"chatcmpl-prism-{uuid.uuid4().hex[:12]}"
        return 200, {
            "id": completion_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": infer_res["model_id"],
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": final_output,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": len(combined_sanitized.split()),
                "completion_tokens": len(final_output.split()),
                "total_tokens": len(combined_sanitized.split()) + len(final_output.split()),
            },
            "prism_sovereignty": {
                "profile_id": profile_id,
                "execution_mode": infer_res["execution_mode"],
                "billing_mode": infer_res["billing_mode"],
                "redaction_count": vault.redaction_count,
                "entities_redacted": public_entities,
                "sanitized_prompt": combined_sanitized,
                "rehydrated_locally": rehydrate_flag,
                "compliance_receipt": audit_entry["compliance_receipt"],
            },
        }
    finally:
        vault.clear()


def handle_mcp_jsonrpc(
    body: Dict[str, object],
    registry: ProfileRegistry,
    ledger: ComplianceLedger,
) -> Tuple[int, Dict[str, object]]:
    """Handles Model Context Protocol (MCP) JSON-RPC 2.0 requests (`POST /api/v1/mcp`)."""
    rpc_id = body.get("id", 1)
    method = str(body.get("method", ""))
    params = body.get("params", {})
    if not isinstance(params, dict):
        params = {}

    if method == "initialize":
        return 200, {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "velocitee-prism-mcp", "version": "2.0.0-bilberry", "codename": "Bilberry"},
                "capabilities": {"tools": {"listChanged": True}},
            },
        }

    if method == "tools/list":
        return 200, {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"tools": MCP_TOOLS_SPEC},
        }

    if method == "tools/call":
        tool_name = str(params.get("name", ""))
        args = params.get("arguments", {})
        if not isinstance(args, dict):
            args = {}

        if tool_name == "prism_redact_text":
            raw_text = str(args.get("text", ""))
            profile_id = str(args.get("profile_id") or registry.get_active_profile_id())
            engine = registry.build_engine(profile_id)
            vault = EphemeralVault()
            try:
                sanitized, _ = engine.redact(raw_text, vault=vault)
                entities = vault.public_entities
                audit_entry = ledger.record_operation(
                    operation="MCP_REDACT_TEXT",
                    profile_id=profile_id,
                    model_id="redaction-only",
                    execution_mode="deterministic_redactor",
                    redaction_count=vault.redaction_count,
                    entity_types=[str(e["type"]) for e in entities],
                    sanitized_text=sanitized,
                )
                return 200, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "content": [{"type": "text", "text": sanitized}],
                        "structuredContent": {
                            "sanitized_text": sanitized,
                            "redaction_count": vault.redaction_count,
                            "entities_redacted": entities,
                            "profile_id": profile_id,
                            "compliance_receipt": audit_entry["compliance_receipt"],
                        },
                        "isError": False,
                    },
                }
            finally:
                vault.clear()

        if tool_name == "prism_sovereign_infer":
            prompt = str(args.get("prompt", ""))
            profile_id = str(args.get("profile_id") or registry.get_active_profile_id())
            profile = registry.get_profile(profile_id)
            engine = registry.build_engine(profile_id)
            vault = EphemeralVault()
            try:
                sanitized, _ = engine.redact(prompt, vault=vault)
                entities = vault.public_entities
                infer_res = execute_model_inference(
                    sanitized_prompt=sanitized,
                    entities=entities,
                    profile=profile,
                    requested_model=str(args["model"]) if "model" in args else None,
                )
                audit_entry = ledger.record_operation(
                    operation="MCP_SOVEREIGN_INFER",
                    profile_id=profile_id,
                    model_id=str(infer_res["model_id"]),
                    execution_mode=str(infer_res["execution_mode"]),
                    redaction_count=vault.redaction_count,
                    entity_types=[str(e["type"]) for e in entities],
                    sanitized_text=sanitized,
                )
                return 200, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "content": [{"type": "text", "text": str(infer_res["output_text"])}],
                        "structuredContent": {
                            "sanitized_prompt": sanitized,
                            "output": infer_res["output_text"],
                            "execution_mode": infer_res["execution_mode"],
                            "model_id": infer_res["model_id"],
                            "redaction_count": vault.redaction_count,
                            "entities_redacted": entities,
                            "compliance_receipt": audit_entry["compliance_receipt"],
                        },
                        "isError": False,
                    },
                }
            finally:
                vault.clear()

        if tool_name == "prism_list_profiles":
            profiles = registry.list_profiles()
            return 200, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [{"type": "text", "text": f"Found {len(profiles)} profiles"}],
                    "structuredContent": {
                        "active_profile_id": registry.get_active_profile_id(),
                        "profiles": profiles,
                    },
                    "isError": False,
                },
            }

        if tool_name == "prism_upsert_profile":
            try:
                updated = registry.upsert_profile(args, set_active=bool(args.get("set_active", False)))
                return 200, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Updated profile {updated['profile_id']}"}],
                        "structuredContent": {"profile": updated},
                        "isError": False,
                    },
                }
            except ValueError as exc:
                return 400, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32602, "message": str(exc)},
                }

        return 404, {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {"code": -32601, "message": f"Unknown tool '{tool_name}'"},
        }

    return 400, {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {"code": -32601, "message": f"Unsupported MCP method '{method}'"},
    }
