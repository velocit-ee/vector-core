# Changelog

All notable changes to Velocitee Vector are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- **VSE (Vector Services Engine) Standalone Package:** Standalone orchestration for containerized service stacks and sovereign AI cleanrooms.
- **VLE (Vector Lifecycle Engine) Daemon:** Continuous telemetry streaming, automated drift repair, and remote syslog collector.

### Engines
<!-- ENGINE-STATUS:BEGIN region=engine-table-unreleased -->
| Engine  | Phase | Status  |
|---------|:-----:|---------|
| **VME** | 1     | Alpha   |
| **VNE** | 2     | Alpha   |
| VSE     | 3     | Planned |
| VLE     | 4     | Planned |
<!-- ENGINE-STATUS:END region=engine-table-unreleased -->

---

## [0.6.0] — 2026-10-22

### Added
- **Unified Modular `vector` CLI:** Installed as `vector` (aliased as `velocitee`) via `shared.vector_cli`. Provides universal status overview, topology discovery, and independent modular engine invocation.
- **Independent Engine Execution:** Operators can enter at any stage of infrastructure maturity (`vector metal`, `vector network`, `vector services`, `vector lifecycle`, `vector discover`, or `vector run <module>`) without being forced through the bare-metal VME flow.
- **Engine Nomenclature Standard:** Formally updated all engine names so the "V" represents **Vector**:
  - **VME:** Vector Metal Engine
  - **VNE:** Vector Network Engine
  - **VSE:** Vector Services Engine
  - **VLE:** Vector Lifecycle Engine
- **Test Suite Expansion:** Added unit test coverage for the modular CLI (`shared/tests/test_vector_cli.py`), bringing total passing test suite to **397 tests**.
- **Physical Hardware Gate:** 10/10 end-to-end acceptance tests verified on live edge appliances (`./harness/run.sh full-cycle`).

---

## [0.5.0] — 2026-10-15

### Added
- **Velocitee Prism v2.0 ("Bilberry"):** Decomposed sovereign AI appliance into a modular Python package (`vector/telia/target/prism`) running as a systemd service.
- **Multilingual European PII Scrubbing:** High-precision entity detection across English, Estonian, Finnish, and Swedish (Luhn Mod-10 credit card, ISO 7064 IBAN, Estonian isikukood, Finnish HETU, Swedish personnummer, and currency amounts).
- **Enterprise Company Profiles:** Runtime CRUD support for configurable compliance profiles (`default`, `telia-nordic-core`, `eu-finserv-strict`, `hermes-hybrid-agent`).
- **Nous Hermes Agent Integration:** OpenAI-compatible proxy (`/v1/chat/completions`) with automatic prompt redaction/re-hydration, and native Model Context Protocol (MCP) HTTP JSON-RPC 2.0 tool server (`/api/v1/mcp`).
- **Cryptographic Receipts:** HMAC-SHA256 audit receipts proving client data was scrubbed before external LLM transmission.
- **Vector Gateway Separation:** Cleanly severed legacy Python router code, designating `vector-gateway` as a pure native Rust daemon (**v1.0.0 "Alder"**).

---

## [0.4.0] — 2026-08-31

### Fixed — Phase 1 Correctness & Security Pass
- **Proxmox Password Security:** Proxmox targets no longer ship a default `changeme` root password; answer files require `target.password_hash` with preflight verification.
- **Secure Image Downloads:** ISO checksums are always verified over HTTPS before caching; unverified images abort immediately.
- **State File Permissions:** Renderer state files containing OPNsense API credentials are restricted to `0600` permissions.
- **Single Installable Distribution:** Root `pyproject.toml` packages `shared` + `vme` + `vne` as a unified distribution (`pip install -e .`), eliminating legacy PYTHONPATH wrappers.

### Added
- **Canonical MAAS Backend for VME:** Support for delegating bare-metal provisioning to existing Canonical MAAS controllers (`backend: maas`).
- **Nmap Service Enrichment:** Subprocess nmap probe (`shared/discovery/nmap_probe.py`) for OS fingerprinting and service detection.
- **Resilience & Retries:** `shared._retry` module using tenacity for exponential backoff on transient 5xx API errors across Proxmox, OPNsense, and MAAS.
- **Engine Status SSOT:** Introduced `engines.json` as the single source of truth with automated Markdown region rendering (`tools/render_engine_status.py`).

---

## [0.3.0] — 2026-07-19

### Added
- **VNE Path B (`vne join`):** Non-invasive network topology discovery and router identification for existing infrastructure.
- **Router Adapters:** Pluggable router adapters for OPNsense and unmanaged gateways.
- **Vendor-Agnostic Scan Toolkit:** `velocitee-discover` CLI for local subnet ARP/mDNS/SSDP and TCP connect scanning.

### Changed
- **Relicense to Apache 2.0:** All engines relicensed from AGPL v3 to the permissive [Apache License, Version 2.0](LICENSE).
- **Contributor License Agreement (CLA):** Updated to v2.0 with explicit patent grants.

---

## [0.2.0] — 2026-06-15

### Added
- **Vector Network Engine (VNE) Initial Implementation:** Declarative network intent parsing (`velocitee.yml`) to provision OPNsense VMs, VLANs, DHCP, DNS, and firewall rules on Proxmox VE.
- **Dual Provisioner Backends:** `velocitee-native` (direct REST driver with resumable state) and `opentofu+ansible` (HCL generation with Ansible playbooks).
- **Verification Gate:** Automated post-deployment checks verifying API reachability, DNS resolution, and egress connectivity before emitting handoff manifests.
- **Manifest Pipeline:** Inter-engine handoff manifest contracts validated via JSON Schema.

---

## [0.1.0] — 2026-04-24

### Added
- **Vector Metal Engine (VME) Initial Public Release:** Containerized seed stack (dnsmasq, nginx, iPXE) for unattended PXE network booting of bare-metal hardware.
- **Unattended OS Installers:** Support for Proxmox VE and Ubuntu Server autoinstall via cloud-init.
- **Guided Setup Wizard:** Interactive `vme setup` detecting network interfaces and generating configuration.
- **Shared CLI Framework:** Typer-based CLI utilities with clean error handling and suggested command correction.
