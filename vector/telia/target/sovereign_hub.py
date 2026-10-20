#!/usr/bin/env python3
"""
Velocitee Prism v2.0 — Sovereign AI & Hermes Agent Privacy Hub Entrypoint
Decomposed into modular `prism/` package (PR-09).
"""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

TARGET_DIR = Path(__file__).resolve().parent
if str(TARGET_DIR) not in sys.path:
    sys.path.insert(0, str(TARGET_DIR))

from prism.profiles import BUILTIN_PROFILES, ProfileRegistry
from prism.receipt import ComplianceLedger, load_or_create_node_key
from prism.redaction import (
    EphemeralVault,
    RedactionEngine,
    verify_estonian_isikukood,
    verify_finnish_hetu,
    verify_iban_mod97,
    verify_luhn,
    verify_swedish_personnummer,
)
from prism.server import (
    DEFAULT_GATEWAY_URL,
    DEFAULT_NODE_MAC,
    DEFAULT_PORT,
    MAX_BODY_BYTES,
    GatewayStateCache,
    PrismRuntimeState,
    create_server,
    make_prism_handler,
)
from prism.system_status import collect_system_status, probe_luks2_status, probe_tpm2_status

__all__ = [
    "BUILTIN_PROFILES",
    "ComplianceLedger",
    "DEFAULT_GATEWAY_URL",
    "DEFAULT_NODE_MAC",
    "DEFAULT_PORT",
    "EphemeralVault",
    "GatewayStateCache",
    "MAX_BODY_BYTES",
    "PrismRuntimeState",
    "ProfileRegistry",
    "RedactionEngine",
    "collect_system_status",
    "create_server",
    "load_or_create_node_key",
    "make_prism_handler",
    "probe_luks2_status",
    "probe_tpm2_status",
    "verify_estonian_isikukood",
    "verify_finnish_hetu",
    "verify_iban_mod97",
    "verify_luhn",
    "verify_swedish_personnummer",
]


def main() -> None:
    host = os.environ.get("PRISM_HOST", "0.0.0.0")
    port = int(os.environ.get("PRISM_PORT", str(DEFAULT_PORT)))
    httpd, _, edge_agent = create_server(host=host, port=port, start_edge_agent=True)

    def handle_sig(signum: int, _frame: object) -> None:
        print(f"\n[PRISM] Received signal {signum}; shutting down cleanly.")
        if edge_agent is not None:
            edge_agent.stop()
        httpd.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGINT, handle_sig)

    print("================================================================")
    print("  Velocitee Prism v2.0 — Sovereign AI & Hermes Agent Hub")
    print(f"  Listening on:   http://{host}:{port}")
    print(f"  Gateway Check:  {DEFAULT_GATEWAY_URL} (MAC: {DEFAULT_NODE_MAC})")
    print("  OpenAI Proxy:   POST /v1/chat/completions")
    print("  MCP Server:     POST /api/v1/mcp")
    print("================================================================")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
