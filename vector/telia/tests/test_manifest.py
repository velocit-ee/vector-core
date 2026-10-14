"""
Unit tests for Velocitee VME Manifest Generation.
Validates canonical schema 1.0, network addressing, and compliance attributes.
"""

from vector.telia.daemon.manifest_generator import build_velocitee_manifest


def test_manifest_schema_and_addressing():
    """Verify manifest fields, dedicated IP space, and gateway declaration."""
    manifest = build_velocitee_manifest(
        hostname="edge-node-01",
        ip="192.168.100.50",
        gateway="192.168.100.1",
        dns="192.168.100.1",
        mac="52:54:00:12:34:56"
    )

    assert manifest["schema_version"] == "1.0"
    target = manifest["target"]
    assert target["hostname"] == "edge-node-01"
    assert target["ip"] == "192.168.100.50"
    assert target["gateway"] == "192.168.100.1"
    assert target["dns"] == "192.168.100.1"
    assert target["mac"] == "52:54:00:12:34:56"

    engine = manifest["engines"]["vme"]
    assert engine["status"] == "success"
    assert engine["gateway_hardware"] == "Technicolor DGA4330 (Telia X2)"
    assert engine["compliance_verified"]["gdpr_article_32"] is True
    assert engine["compliance_verified"]["nis2_supply_chain"] is True
    assert engine["compliance_verified"]["local_data_boundary"] == "EE-Tallinn"
