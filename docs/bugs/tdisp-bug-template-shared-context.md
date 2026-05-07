# Shared context for OpenHCL TDISP bug reports

This document is referenced by all `tdisp-bug-*.md` reports in this
folder. It establishes the threat model, the role mapping, and the
trusted-component axioms used by every report.

## Threat model

OpenHCL on AMD SNP/SEV-TIO. The host VMM, host OS, and host TSM are
adversarial. The host can fabricate, drop, reorder, or replay any
TDISP-protocol message it relays between the paravisor and the device
DSM. See `docs/tdisp-formal-verification-reference.md` §2.

## Role mapping

| Reference role | Entity in OpenHCL |
|---|---|
| Trusted firmware oracle (TDX Module / SEV equivalent) | **AMD SEV PSP** |
| TPA / TDISP-protocol agent (owns SPDM, IDE keys, LOCK/START, fetches and caches the report) | **OpenHCL paravisor in VTL2** |
| Guest TD workload | **VTL0 guest payload** (no SPDM session for this TDI; can perform its own SNP attestation but not CHECK-1 for the device) |
| TSM | **Host VPCI relay / host VMM** (adversary) |
| DSM | Device firmware |

By this mapping every `CHECK-1..9`, `SAFE-1..10`, and `INV-1..11`
obligation in the reference that the formal model assigns to "the
guest TD" lands on the **paravisor**. The PSP is the *trusted oracle*
(holds the ground-truth `device_info_hash`, validates `TIO_MSG_*_REQ`)
but does not perform per-call protocol verification on the paravisor's
behalf.

## Implementation entry points

| Subsystem | File |
|---|---|
| TDISP state machine | [vm/devices/pci/vpci_client/src/tdisp.rs](../../vm/devices/pci/vpci_client/src/tdisp.rs) |
| SEV-TIO validator (PSP plumbing) | [openhcl/openhcl_tdisp/src/sevtio.rs](../../openhcl/openhcl_tdisp/src/sevtio.rs) |
| TDISP trait definitions | [openhcl/openhcl_tdisp/src/lib.rs](../../openhcl/openhcl_tdisp/src/lib.rs) |
| Kani harnesses | [vm/devices/pci/vpci_client/src/kani_proofs.rs](../../vm/devices/pci/vpci_client/src/kani_proofs.rs) |
| Guest-facing VPCI dispatcher | [vm/devices/pci/vpci/src/device.rs](../../vm/devices/pci/vpci/src/device.rs) |
| Findings & analysis | [docs/tdisp-kani-verification-findings.md](../tdisp-kani-verification-findings.md) |
| Formal reference | [docs/tdisp-formal-verification-reference.md](../tdisp-formal-verification-reference.md) |

## Severity language used in these reports

- **Critical**: load-bearing protocol property is absent; combined
  with adversarial host yields a path that the architecture cannot
  catch except by an axiomatic backstop (e.g. SEV PSP enforcement).
- **High**: real exploitable gap or direct API-contract violation;
  fix is required for the paravisor to meet its share of the TDISP
  obligations.
- **Medium**: incomplete check; combined with another gap may become
  load-bearing.
