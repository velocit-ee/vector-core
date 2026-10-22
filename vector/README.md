# Velocitee Vector

> **Zero-touch bare-metal server provisioning at the network edge.**  
> Part of the [Velocitee](https://velocit.ee) infrastructure automation ecosystem.

---

## Overview

**Vector** is Velocitee's flagship commercial edge appliance product. It bridges the gap between raw bare-metal hardware and production-ready sovereign cloud infrastructure for small- and medium-sized enterprises (SMEs).

While public cloud hyperscalers offer ease-of-use at the expense of data sovereignty, latency, and unpredictable egress costs, traditional on-premises servers require specialized systems engineering that SMEs cannot afford.

**Vector solves this:**
1. **Zero-Touch Provisioning:** Unbox a certified node, connect it to the designated edge port, and the node self-configures over cryptographically authenticated iPXE.
2. **Sovereignty & Compliance:** 100% of primary client data remains legally anchored on local NVMe storage with automated LUKS2 disk encryption (GDPR Art. 32 & NIS2 compliant).
3. **Carrier & Partner Editions:** Deploys as an ultra-lightweight micro-service (< 40 MB RAM) directly on ISP customer-premises equipment (CPE) or managed branch gateways.

---

## Product Architecture & Separation of Concerns

The Velocitee Vector platform is organized into three distinct tiers:

1. **Carrier Infrastructure Rails (Vector Gateway — Rust):**
   * Statically compiled sub-1MB native binary (`musl`) running directly on OpenWrt / CPE routers (GL-AXT1800, Telia X2, MediaTek Filogic).
   * Enforces kernel-level zero-trust port isolation (VLAN 999), constant-time HMAC-SHA256 claim token validation, and single-use iPXE netboot staging.
   * Codenames: **v1.0.0 Alder** (Current), **v2.0.0 Birch** (Future).
   * Located in repository [`vector-gateway`](https://github.com/velocit-ee/vector-gateway).

2. **Sovereign Edge Intelligence (Velocitee Prism — Python):**
   * Multi-lingual European PII redaction cleanroom (EN/ET/FI/SV), enterprise company profiles, and Nous Hermes Agent proxy (OpenAI & MCP protocols).
   * Runs natively on provisioned edge servers / hypervisors under systemd (`192.168.8.200:8081`).
   * Codenames: **v1.0.0 Aronia** (Prototype), **v2.0.0 Bilberry** (Current production).
   * Located in [`core/vector/telia/target/prism`](./telia/target/prism).

3. **Modular Vector Engine Pipeline (Core — Python):**
   * Composable, independent automation engines:
     * **VME (Vector Metal Engine):** Bare-metal PXE provisioning & OS install.
     * **VNE (Vector Network Engine):** OPNsense VM deployment or read-only network join.
     * **VSE (Vector Services Engine):** Deploys containerized payloads and sovereign cleanrooms.
     * **VLE (Vector Lifecycle Engine):** Telemetry, tamper-evident SHA-256 audit ledger, and drift detection.
   * Invoked via the unified `vector` CLI or standalone engine commands.

---

## Repository Structure

```
vector/
├── README.md               # Product overview & architectural separation
└── telia/                  # Telia Carrier Edition
    ├── target/             # Target node payloads & cleanrooms
    │   ├── prism/          # Velocitee Prism v2.0 (Bilberry) sovereign AI package
    │   ├── sovereign_hub.py# Live legal workspace web service (Port 8081)
    │   └── edge_node_ssh.py# Secure SSH bridge to edge hardware
    ├── assets/             # Static bootloaders (iPXE) & checksum manifests
    └── scripts/            # Hardware demo & verification runners
```

---

## Quick Start

Run modules independently using the unified `vector` CLI:

```bash
# Check overall status and detected manifests
vector status

# Run individual modules independently
vector metal deploy --config vme-config.yml   # Bare-metal provisioning
vector network join                           # Join existing network (read-only)
vector services deploy --profile prism        # Deploy Prism AI cleanroom
vector lifecycle audit                        # Verify SHA-256 audit chain
```
