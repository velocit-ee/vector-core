"""
Integration and API unit tests for Velocitee Vector Edge Orchestrator.
Tests state transitions, REST endpoints, path traversal defense, and error responses.
Uses ephemeral ports to guarantee zero port collisions.
"""

import http.server
import json
import os
import threading
import urllib.request
import urllib.error
import pytest

from vector.telia.daemon.agent import (
    EdgeOrchestrator,
    safe_asset_path,
    EnterpriseEdgeHandler,
    ASSETS_DIR,
)


def test_orchestrator_state_and_lifecycle():
    """Verify state initialization, node lookup, and claim transitions."""
    orch = EdgeOrchestrator()
    gw = orch.get_gateway()
    assert gw["lan_ip"] == "192.168.100.1"
    assert gw["hardware_model"] == "Technicolor DGA4330 (Vantiva)"

    nodes = orch.get_nodes()
    assert len(nodes) == 1
    node = nodes[0]
    assert node["current_ip"] == "192.168.100.50"
    assert node["gateway_ip"] == "192.168.100.1"
    assert node["status"] == "quarantined"

    # Claim the node
    token, _ = orch.start_claim("52:54:00:12:34:56", "plain-ubuntu-server", "admin@velocit.ee")
    assert token is not None
    assert orch.find_node("52:54:00:12:34:56")["status"] == "provisioning"

    # Reset the node
    orch.reset("52:54:00:12:34:56")
    assert orch.find_node("52:54:00:12:34:56")["status"] == "quarantined"


def test_path_traversal_defense():
    """Verify that safe_asset_path strictly blocks directory traversal attempts."""
    boot_dir = os.path.join(ASSETS_DIR, "boot")
    
    # Path traversal attempts
    assert safe_asset_path(boot_dir, "../../../etc/passwd") is None
    assert safe_asset_path(boot_dir, "../../daemon/agent.py") is None
    assert safe_asset_path(boot_dir, "/etc/shadow") is None

    # Legitimate file check
    vmlinuz_path = safe_asset_path(boot_dir, "vmlinuz")
    if os.path.exists(os.path.join(boot_dir, "vmlinuz")):
        assert vmlinuz_path is not None


@pytest.fixture(scope="module")
def ephemeral_server():
    """Spawns an ephemeral instance of EnterpriseEdgeHandler for clean API testing."""
    os.environ["TELIA_VECTOR_FAST_SIMULATION"] = "1"
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), EnterpriseEdgeHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://{host}:{port}"
    yield base_url
    server.shutdown()


def test_api_telemetry(ephemeral_server):
    req = urllib.request.Request(f"{ephemeral_server}/api/v1/telemetry")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert data["lan_ip"] == "192.168.100.1"


def test_api_nodes(ephemeral_server):
    req = urllib.request.Request(f"{ephemeral_server}/api/v1/nodes")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        nodes = json.loads(resp.read().decode())
        assert len(nodes) == 1
        assert nodes[0]["current_ip"] == "192.168.100.50"


def test_api_claim_validation_and_flow(ephemeral_server):
    # Invalid MAC
    body = json.dumps({"mac": "not-a-mac", "profile": "plain-ubuntu-server"}).encode()
    req = urllib.request.Request(f"{ephemeral_server}/api/v1/claim", data=body, headers={"Content-Type": "application/json"}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 400

    # Invalid profile
    body = json.dumps({"mac": "52:54:00:12:34:56", "profile": "unauthorized"}).encode()
    req = urllib.request.Request(f"{ephemeral_server}/api/v1/claim", data=body, headers={"Content-Type": "application/json"}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 400

    # Valid claim
    body = json.dumps({"mac": "52:54:00:12:34:56", "profile": "plain-ubuntu-server", "operator": "tester@velocit.ee"}).encode()
    req = urllib.request.Request(f"{ephemeral_server}/api/v1/claim", data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode())
        assert res["status"] == "claiming"
        assert "claim_token" in res


def test_api_reset(ephemeral_server):
    req = urllib.request.Request(f"{ephemeral_server}/api/v1/reset", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        res = json.loads(resp.read().decode())
        assert res["status"] == "reset"


def _claim(base_url, mac="52:54:00:12:34:56", profile="plain-ubuntu-server"):
    body = json.dumps({"mac": mac, "profile": profile, "operator": "tester@velocit.ee"}).encode()
    req = urllib.request.Request(f"{base_url}/api/v1/claim", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    return urllib.request.urlopen(req)


def test_api_double_claim_returns_409(ephemeral_server):
    """Fix 2.9: a second claim on an in-flight node is a 409 Conflict, not a
    silent second pipeline."""
    # Start from a known-unclaimed state.
    reset = urllib.request.Request(f"{ephemeral_server}/api/v1/reset", data=b"{}",
                                   headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(reset)

    with _claim(ephemeral_server) as first:
        assert first.status == 200

    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _claim(ephemeral_server)
    assert exc_info.value.code == 409
    payload = json.loads(exc_info.value.read().decode())
    assert payload["code"] == "CLAIM_CONFLICT"


def test_boot_assets_require_a_valid_token(ephemeral_server):
    """Fix 2.7: kernel/initrd are not served to an unauthenticated caller."""
    req = urllib.request.Request(f"{ephemeral_server}/boot/vmlinuz")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 403

    req = urllib.request.Request(f"{ephemeral_server}/cloud-init/user-data")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 403
