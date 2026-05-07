---
name: tdisp-spec
description: "Navigate the PCI-SIG TDISP (TEE Device Interface Security Protocol) v2022-07-27 specification. Load when answering questions about TDISP messages, state machine, IDE/SPDM relationships, security model, message formats, error codes, or device/host requirements.
---

# TDISP Specification — Navigation Skill

## Source files

- PDF: [docs/spec/TEE Device Interface Security Protocol - TDISP - v2022-07-27 (3).pdf](../../../docs/spec/TEE%20Device%20Interface%20Security%20Protocol%20-%20TDISP%20-%20v2022-07-27%20%283%29.pdf)
- Extracted text (3,101 lines, ~183 KB): [docs/spec/TEE Device Interface Security Protocol - TDISP - v2022-07-27 (3).txt](../../../docs/spec/TEE%20Device%20Interface%20Security%20Protocol%20-%20TDISP%20-%20v2022-07-27%20%283%29.txt)
- Re-extract with: [scripts/extract_tdisp_pdf.sh](../../../docs/spec/extract_tdisp_pdf.sh) (uses `pdftotext -layout`).

When citing the spec to a user, prefer section numbers (e.g. "§11.3.8 LOCK_INTERFACE_REQUEST"). Use the line ranges below to `read_file` directly into the relevant region instead of scanning the whole document.

## What this document is

A PCI-SIG ECN against the **PCIe Base Spec rev 5.0 + IDE ECN / 6.0** that adds **Chapter 11 — TEE Device Interface Security Protocol (TDISP)**. TDISP defines:

1. How a **TVM** (TEE-protected VM) establishes trust with a **TDI** (TEE Device Interface — the unit of direct assignment, e.g. an SR-IOV VF).
2. How the host↔device interconnect is secured (built on **SPDM ≥1.2** for authentication/secure session and **IDE** for link encryption/integrity, with the IDE **T-bit** marking TEE traffic).
3. The message protocol and state machine the **TSM** (host-side TEE Security Manager) uses to lock a TDI's configuration, get a signed measurement/configuration report, hand it to the TVM, and start/stop the TDI.

Key actors:
- **TSM** — TEE Security Manager (host, requester role).
- **DSM** — Device Security Manager (device, responder role).
- **TVM** — Trusted-VM owner of the TDI.
- **VMM** — *not trusted* by the TVM; only configures the TDI in `CONFIG_UNLOCKED`.

The four TDI security states (Figure 11-5): `CONFIG_UNLOCKED → CONFIG_LOCKED → RUN`, with `ERROR` as the failure sink. "Locked" = `CONFIG_LOCKED` ∪ `RUN`.

## Document layout

The first ~10 pages are PCI-SIG ECN front-matter and edits to existing PCIe sections (terms, IDE TLP fields, Device Capabilities Register additions). All TDISP-specific content lives in **Chapter 11**, which starts around line 425 of the extracted text.

## Section map (line numbers refer to the .txt extract)

### Front matter & PCIe edits (lines 1–423)
| Lines | Topic |
|---|---|
| 1–48 | ECN cover page, summary, hardware/software/C&I impact |
| 49–110 | New terms: TDI, TEE-I/O, TCB, TVM, DSM, TSM (added to PCIe glossary) |
| 110–250 | Edits to §2.2.1.2 (Flit-mode header), §6.33 (IDE threat model), §6.33.4 (T-bit semantics, Sub-Stream encoding) |
| 250–400 | Edits to Device Capabilities Register (TEE-IO Supported bit), TLP rules around T-bit, IDE rules for TEE traffic |

### Chapter 11 — TDISP (lines 425–3101)

#### 11.1 Overview of the TEE-I/O Security Model (lines 425–655)
- Lines 425–540: TEE-assignable vs Non-TEE-assignable resources; confidentiality/integrity guarantees; explicit *non-goals* (DoS, side channels in general).
- Lines 540–655: **Figure 11-2** reference architecture (TSM/DSM/IDE/SPDM stack), Figure 11-3 request identification, Figure 11-4 + **Table 1 INTERFACE_ID** (Function/Segment/Bus/Device encoding of a TDI ID).

#### 11.2 TDISP Rules (lines 656–1227)
| Sub | Lines | Topic |
|---|---|---|
| 11.2 intro + Figure 11-5 | 656–800 | **State machine diagram and per-state rules**. Definitive source for what each transition requires and which TLPs are legal in each state. |
| 11.2.1 TLP Rules | 899–962 | Per-state legality of Memory/Config/Msg/IDE TLPs; T-bit handling rules. |
| 11.2.2 TDISP Message Transport | 963–1028 | TDISP runs as **SPDM Vendor-Defined Messages (VDM)** inside an SPDM 1.2 secure session; Figure 11-6 encapsulation. |
| 11.2.3 Requirements for Requesters (TSM) | 1029–1039 | TSM-side normative requirements. |
| 11.2.4 Requirements for Responders (DSM) | 1040–1053 | DSM-side normative requirements. |
| 11.2.5 Timing Requirements | 1054–1056 | Response timeouts. |
| 11.2.6 DSM Tracking & Handling of Locked TDI | 1057–1206 | **Per-PCIe-event matrix** (FLR, Conventional Reset, Hot Reset, ATS Invalidate, PRG, Config writes, VPD, …) and required DSM behavior in each state. Includes Table 3 (ECN-internal — operations vs result/state-transition). |
| 11.2.7 TVM Acceptance of a TDI | 1207–1227 | **The four questions** a TVM must answer before accepting a TDI into its TCB (identity, SPDM session, IDE keys, mapping). Critical for any TVM-side acceptance logic. |

#### 11.3 TDISP Message Formats and Processing (lines 1228–2436)
This is the **wire-format reference**. Each subsection has a Table N defining the byte layout and an Error-Response-Codes table where applicable.

| Sub | Lines | Message / Table |
|---|---|---|
| 11.3.1 | 1230–1288 | **Table 3 — TDISP Request Codes** (with required/optional + legal states per code) |
| 11.3.2 | 1289–1336 | **Table 4 — TDISP Response Codes** |
| 11.3.3 | 1337–1414 | **Table 5 — Common TDISP Message Header**, Table 6 generic error codes, version negotiation |
| 11.3.4 / 11.3.5 | 1415–1453 | `GET_TDISP_VERSION` / `TDISP_VERSION` (Table 7) |
| 11.3.6 / 11.3.7 | 1454–1519 | `GET_TDISP_CAPABILITIES` (Table 8) / `TDISP_CAPABILITIES` (Table 9) |
| 11.3.8 / 11.3.9 | 1520–1705 | **`LOCK_INTERFACE_REQUEST` (Table 10)** / `LOCK_INTERFACE_RESPONSE` (Tables 11–12). Includes **lock flags** (no_fw_update, system_cache_line_size, lock_msix, bind_p2p, all_request_redirect) and **start_interface_nonce** mechanics. |
| 11.3.10 / 11.3.11 | 1706–1960 | `GET_DEVICE_INTERFACE_REPORT` (Tables 13, 16) / `DEVICE_INTERFACE_REPORT` (Table 14) including **Table 15 — TDI Report Structure** (MMIO ranges, attribute flags, `IS_NON_TEE_MEM`, `IS_MEM_ATTR_UPDATABLE`, MSI-X table location, vendor-specific blob). Figure 11-7 multi-fragment report flow. |
| 11.3.12 / 11.3.13 | 1961–1985 | `GET_DEVICE_INTERFACE_STATE` / `DEVICE_INTERFACE_STATE` (Table 17 — returns current TDI state) |
| 11.3.14 / 11.3.15 | 1986–2029 | `START_INTERFACE_REQUEST` (Tables 18–19, **carries the nonce**) / `START_INTERFACE_RESPONSE` |
| 11.3.16 / 11.3.17 | 2030–2059 | `STOP_INTERFACE_REQUEST` / `STOP_INTERFACE_RESPONSE` |
| 11.3.18 / 11.3.19 | 2060–2139 | `BIND_P2P_STREAM_REQUEST` (Tables 20–21) / `RESPONSE` |
| 11.3.20 / 11.3.21 | 2140–2192 | `UNBIND_P2P_STREAM_REQUEST` (Tables 22–23) / `RESPONSE` |
| 11.3.22 / 11.3.23 | 2193–2274 | `SET_MMIO_ATTRIBUTE_REQUEST` (Tables 24–25) / `RESPONSE` |
| 11.3.24 | 2275–2382 | **`TDISP_ERROR` (Tables 26–28)** — generic error envelope, `ERROR_CODE`/`ERROR_DATA`, `EXTENDED_ERROR_DATA` |
| 11.3.25 / 11.3.26 | 2383–2436 | `VDM_REQUEST` / `VDM_RESPONSE` (Tables 29–30) — passthrough for vendor-defined extensions |

#### 11.4 Device Security Requirements (lines 2437–2702)
Normative requirements **on the device/DSM**.

| Sub | Lines | Topic |
|---|---|---|
| 11.4.1 | 2438–2447 | Device identity & SPDM authentication |
| 11.4.2 | 2448–2478 | Firmware & configuration measurements |
| 11.4.3 | 2479–2503 | Securing interconnects (IDE binding) |
| 11.4.4 | 2504–2529 | Device-attached memory protections |
| 11.4.5 | 2530–2582 | TDI security: per-state device behavior, MSI-X protection, MMIO attributes |
| 11.4.6 | 2583–2592 | Data integrity errors |
| 11.4.7 | 2593–2618 | Debug modes (must be disabled or measured) |
| 11.4.8 | 2619–2640 | Conventional Reset — clear TVM/IDE/SPDM secrets |
| 11.4.9 | 2641–2648 | Function-Level Reset → ERROR |
| 11.4.10 | 2649–2702 | **ATS & Access Control** — required ATS behavior for TEE-marked translations |

#### 11.5 Requirements Placed on Host Security due to TDI (lines 2703–2957)
Normative requirements **on the host/TSM/Root Complex**.

| Sub | Lines | Topic |
|---|---|---|
| 11.5.1 | 2706–2727 | Address translation integrity (TSM gates IOMMU programming) |
| 11.5.2 | 2728–2738 | MMIO access control (T-bit gating per page) |
| 11.5.3 | 2739–2749 | DMA access control |
| 11.5.4 | 2750–2758 | Device binding |
| 11.5.5 | 2759–2774 | IDE stream setup, key management |
| 11.5.6 | 2775–2783 | Data integrity errors |
| 11.5.7 | 2784–2945 | **TSM tracking and handling of Locked Root Port** — Table 31 per-event matrix mirroring 11.2.6 but for the host side |
| 11.5.8 | 2946–2957 | IDE Extended Capability registers (host view) |

#### 11.6 Threat Model and Mitigations (lines 2958–3101)
| Sub | Lines | Topic |
|---|---|---|
| 11.6.1 | 2962–3003 | Interconnect security threats and IDE/SPDM mitigations |
| 11.6.2 | 3004–3033 | Identity & measurement-reporting threats |
| 11.6.3 | 3034–3101 | TDI assignment/detach threats; how `LOCK→REPORT→START` chain (with the per-session nonce) defeats reconfiguration / reset / overlapping-MMIO / impersonation attacks |

## How to use this skill

- **"What does message X look like?"** → jump to `11.3.<n>` table for X (use the table above to find the line range).
- **"Is operation Y legal in state Z?"** → §11.2 (state machine + 11.2.1 TLP rules) and the per-message Error-Response-Codes table in §11.3.
- **"What must the TVM check before trusting a TDI?"** → §11.2.7 (the four questions).
- **"What is the lock→nonce→start chain?"** → §11.3.8 + §11.3.14 + §11.6.3.
- **"What happens on reset / FLR / config write while locked?"** → §11.2.6 (device side) and §11.5.7 (host side) — *both* matrices.
- **"What measurements/IDE keys must the device provide?"** → §11.4.1, §11.4.2, §11.4.3.
- **"What MMIO attribute bits exist (`IS_NON_TEE_MEM`, etc.)?"** → §11.3.11 Table 15 + §11.3.22 (`SET_MMIO_ATTRIBUTE_REQUEST`).

## Caveats about the extracted text

- `pdftotext -layout` preserves columns but occasionally splits long words across lines (e.g. "TDI\nSP" near line 540) and inlines table cells with extra whitespace. When a quote looks garbled, open the PDF for that page.
- Page numbers in the extract are **PCIe spec page numbers** (e.g. "11", "25", "62"), not text-file line numbers — use the line numbers in the tables above for navigation.
- The extracted text is generated; do not edit by hand. Re-run `scripts/extract_tdisp_pdf.sh` if the PDF is updated.
