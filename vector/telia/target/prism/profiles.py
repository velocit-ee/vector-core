"""
Velocitee Prism — Customizable Company Profiles & Hybrid Model Routing Registry

Allows each enterprise tenant to tune:
1. Active PII/entity detectors (`enabled_entities`)
2. Custom regex patterns (`custom_patterns`, e.g., internal ticket IDs, IMSI, subscriber numbers)
3. Phrase allowlists (`allowlist`, e.g., product names, offices, standard greetings)
4. Hybrid model routing (`model_routing`) across sovereign local models (Ollama/vLLM) and
   API-billed cloud frontier models (Claude, GPT-4o, OpenRouter, Nous Hermes 3) with
   mandatory pre-egress sanitization and local surrogate re-hydration.
"""

from __future__ import annotations

import copy
import json
import os
import threading
from pathlib import Path
from typing import Dict, List, Optional

from .redaction import RedactionEngine


BUILTIN_PROFILES: Dict[str, Dict[str, object]] = {
    "default": {
        "profile_id": "default",
        "name": "European Enterprise Sovereign Default",
        "description": "Balanced GDPR & EU AI Act privacy profile with full Nordic/Baltic PII redaction and hybrid local/cloud routing.",
        "compliance_frameworks": ["GDPR", "EU-AI-Act", "NIS2"],
        "enabled_entities": list(RedactionEngine.DEFAULT_ENABLED_ENTITIES),
        "custom_patterns": [],
        "allowlist": [],
        "sanitize_before_cloud_egress": True,
        "rehydrate_cloud_responses": True,
        "default_model": "prism-sovereign-local",
        "model_routing": {
            "prism-sovereign-local": {
                "provider": "local_ollama",
                "upstream_model": "llama3.2:3b",
                "billing_mode": "sovereign_zero_marginal_cost",
                "sanitize_before_egress": True,
                "rehydrate_response": False,
            },
            "claude-3-7-sonnet-sovereign": {
                "provider": "anthropic",
                "upstream_model": "claude-3-7-sonnet-20250219",
                "billing_mode": "api_metered",
                "sanitize_before_egress": True,
                "rehydrate_response": True,
            },
            "gpt-4o-sovereign": {
                "provider": "openai",
                "upstream_model": "gpt-4o",
                "billing_mode": "api_metered",
                "sanitize_before_egress": True,
                "rehydrate_response": True,
            },
            "hermes-3-llama-70b": {
                "provider": "openrouter",
                "upstream_model": "nousresearch/hermes-3-llama-3.1-70b",
                "billing_mode": "api_metered",
                "sanitize_before_egress": True,
                "rehydrate_response": True,
            },
        },
    },
    "telia-nordic-core": {
        "profile_id": "telia-nordic-core",
        "name": "Telia Nordic & Baltic Telecom Core",
        "description": "Telecom-grade profile detecting IMSI/ICCID/MSISDN, Estonian Isikukood, Finnish HETU, Swedish Personnummer, and subscriber billing records.",
        "compliance_frameworks": ["GDPR", "NIS2", "ETSI-EN-303-645"],
        "enabled_entities": list(RedactionEngine.DEFAULT_ENABLED_ENTITIES),
        "custom_patterns": [
            {"type": "TELECOM_IMSI", "pattern": r"\b(?:24801|24491|24001)\d{10}\b"},
            {"type": "SUBSCRIBER_ACC", "pattern": r"\bSUB-\d{6,10}\b"},
        ],
        "allowlist": [
            "telia eesti",
            "telia finland",
            "telia sverige",
            "telia company",
            "core network",
        ],
        "sanitize_before_cloud_egress": True,
        "rehydrate_cloud_responses": True,
        "default_model": "prism-sovereign-local",
        "model_routing": {
            "prism-sovereign-local": {
                "provider": "local_ollama",
                "upstream_model": "llama3.2:3b",
                "billing_mode": "sovereign_zero_marginal_cost",
                "sanitize_before_egress": True,
                "rehydrate_response": False,
            },
            "claude-3-7-sonnet-sovereign": {
                "provider": "anthropic",
                "upstream_model": "claude-3-7-sonnet-20250219",
                "billing_mode": "api_metered",
                "sanitize_before_egress": True,
                "rehydrate_response": True,
            },
        },
    },
    "eu-finserv-strict": {
        "profile_id": "eu-finserv-strict",
        "name": "EU Financial Services DORA Strict",
        "description": "Strict banking & DORA compliance profile redacting IBANs, payment cards, SWIFT/BIC references, and currency exposures before any model invocation.",
        "compliance_frameworks": ["DORA", "GDPR", "PCI-DSS-v4"],
        "enabled_entities": list(RedactionEngine.DEFAULT_ENABLED_ENTITIES),
        "custom_patterns": [
            {"type": "TRADE_REF", "pattern": r"\bTRD-[A-Z0-9]{8,12}\b"},
        ],
        "allowlist": ["european central bank", "sepa instant"],
        "sanitize_before_cloud_egress": True,
        "rehydrate_cloud_responses": True,
        "default_model": "claude-3-7-sonnet-sovereign",
        "model_routing": {
            "claude-3-7-sonnet-sovereign": {
                "provider": "anthropic",
                "upstream_model": "claude-3-7-sonnet-20250219",
                "billing_mode": "api_metered",
                "sanitize_before_egress": True,
                "rehydrate_response": True,
            },
            "gpt-4o-sovereign": {
                "provider": "openai",
                "upstream_model": "gpt-4o",
                "billing_mode": "api_metered",
                "sanitize_before_egress": True,
                "rehydrate_response": True,
            },
        },
    },
    "hermes-hybrid-agent": {
        "profile_id": "hermes-hybrid-agent",
        "name": "Nous Hermes Agent Multi-Tool Profile",
        "description": "Optimized for Hermes Agent (NousResearch/hermes-agent) tool-calling workflows: preserves JSON/code identifiers while redacting human PII and credentials across subagent delegations.",
        "compliance_frameworks": ["GDPR", "EU-AI-Act", "MCP-Sovereign-1.0"],
        "enabled_entities": [
            "API_KEY_SECRET",
            "EMAIL",
            "IBAN",
            "NATIONAL_ID",
            "CREDIT_CARD",
            "PHONE_INTL",
            "PERSON_NAME",
        ],
        "custom_patterns": [],
        "allowlist": ["hermes agent", "nous research", "model context protocol"],
        "sanitize_before_cloud_egress": True,
        "rehydrate_cloud_responses": True,
        "default_model": "hermes-3-llama-70b",
        "model_routing": {
            "hermes-3-llama-70b": {
                "provider": "openrouter",
                "upstream_model": "nousresearch/hermes-3-llama-3.1-70b",
                "billing_mode": "api_metered",
                "sanitize_before_egress": True,
                "rehydrate_response": True,
            },
            "claude-3-7-sonnet-sovereign": {
                "provider": "anthropic",
                "upstream_model": "claude-3-7-sonnet-20250219",
                "billing_mode": "api_metered",
                "sanitize_before_egress": True,
                "rehydrate_response": True,
            },
            "gpt-4o-sovereign": {
                "provider": "openai",
                "upstream_model": "gpt-4o",
                "billing_mode": "api_metered",
                "sanitize_before_egress": True,
                "rehydrate_response": True,
            },
            "prism-sovereign-local": {
                "provider": "local_ollama",
                "upstream_model": "llama3.2:3b",
                "billing_mode": "sovereign_zero_marginal_cost",
                "sanitize_before_egress": True,
                "rehydrate_response": False,
            },
        },
    },
}


class ProfileRegistry:
    """Thread-safe registry of built-in and tenant-customized Prism profiles."""

    def __init__(self, storage_path: Optional[Path] = None) -> None:
        self._lock = threading.Lock()
        default_path = Path(
            os.environ.get(
                "PRISM_PROFILES_PATH",
                "/tmp/velocitee-prism-profiles.json",
            )
        )
        self._storage_path = storage_path or default_path
        self._profiles: Dict[str, Dict[str, object]] = copy.deepcopy(BUILTIN_PROFILES)
        self._active_profile_id: str = "default"
        self._load_persisted()

    def _load_persisted(self) -> None:
        if not self._storage_path.exists():
            return
        try:
            data = json.loads(self._storage_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                custom = data.get("profiles", {})
                if isinstance(custom, dict):
                    for pid, pcfg in custom.items():
                        if isinstance(pcfg, dict):
                            self._profiles[str(pid)] = pcfg
                active = data.get("active_profile_id")
                if isinstance(active, str) and active in self._profiles:
                    self._active_profile_id = active
        except (OSError, ValueError):
            pass

    def _save_persisted(self) -> None:
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "active_profile_id": self._active_profile_id,
                "profiles": self._profiles,
            }
            self._storage_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError:
            pass

    def list_profiles(self) -> List[Dict[str, object]]:
        with self._lock:
            return [copy.deepcopy(p) for p in self._profiles.values()]

    def get_active_profile_id(self) -> str:
        with self._lock:
            return self._active_profile_id

    def get_profile(self, profile_id: Optional[str] = None) -> Dict[str, object]:
        with self._lock:
            pid = profile_id or self._active_profile_id
            if pid not in self._profiles:
                pid = "default"
            return copy.deepcopy(self._profiles[pid])

    def upsert_profile(
        self,
        profile_data: Dict[str, object],
        set_active: bool = False,
    ) -> Dict[str, object]:
        pid = str(profile_data.get("profile_id", "")).strip()
        if not pid or not all(c.isalnum() or c in "-_" for c in pid):
            raise ValueError("Invalid profile_id (use alphanumeric, '-', or '_')")

        base = copy.deepcopy(BUILTIN_PROFILES["default"])
        base["profile_id"] = pid
        base["name"] = str(profile_data.get("name", pid))
        base["description"] = str(profile_data.get("description", "Custom company profile"))

        if isinstance(profile_data.get("compliance_frameworks"), list):
            base["compliance_frameworks"] = [
                str(x) for x in profile_data["compliance_frameworks"]  # type: ignore[index]
            ]
        if isinstance(profile_data.get("enabled_entities"), list):
            base["enabled_entities"] = [
                str(x).upper() for x in profile_data["enabled_entities"]  # type: ignore[index]
            ]
        if isinstance(profile_data.get("custom_patterns"), list):
            validated_patterns = []
            for item in profile_data["custom_patterns"]:  # type: ignore[index]
                if isinstance(item, dict) and "type" in item and "pattern" in item:
                    validated_patterns.append(
                        {"type": str(item["type"]).upper(), "pattern": str(item["pattern"])}
                    )
            base["custom_patterns"] = validated_patterns
        if isinstance(profile_data.get("allowlist"), list):
            base["allowlist"] = [
                str(x).strip().lower() for x in profile_data["allowlist"]  # type: ignore[index]
            ]
        if isinstance(profile_data.get("default_model"), str):
            base["default_model"] = str(profile_data["default_model"])
        if isinstance(profile_data.get("model_routing"), dict):
            merged_routing = copy.deepcopy(base["model_routing"])
            assert isinstance(merged_routing, dict)
            for mkey, mval in profile_data["model_routing"].items():  # type: ignore[union-attr]
                if isinstance(mval, dict):
                    merged_routing[str(mkey)] = mval
            base["model_routing"] = merged_routing

        with self._lock:
            self._profiles[pid] = base
            if set_active:
                self._active_profile_id = pid
            self._save_persisted()
            return copy.deepcopy(base)

    def build_engine(self, profile_id: Optional[str] = None) -> RedactionEngine:
        prof = self.get_profile(profile_id)
        enabled = prof.get("enabled_entities")
        custom = prof.get("custom_patterns")
        allowlist = prof.get("allowlist")
        return RedactionEngine(
            enabled_entities=enabled if isinstance(enabled, list) else None,
            custom_patterns=custom if isinstance(custom, list) else None,
            allowlist=allowlist if isinstance(allowlist, list) else None,
        )
