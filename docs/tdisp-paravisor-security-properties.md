# Paravisor TDISP Security Properties

This document records the security properties that the OpenHCL paravisor
must enforce when acting as a **TDISP guest CVM** (TPA-TD / TVM in the
TDISP specification's vocabulary) for a TDISP-capable assigned device.

The list is derived **top-down from the TDISP reference**
([../docs/tdisp-formal-verification-reference.md](tdisp-formal-verification-reference.md)) — not from the current
implementation. It was reached by spec-first drafting followed by
adversarial review with a TDISP subject-matter agent.

## Trust model recap

- **PSP / TDX-module** — trusted firmware oracle
  (axioms `SEV_PSP_CORRECT` / `TDX_MODULE_CORRECT`, §2). Holds
  `stored_device_info_hash`, validates IDE / MMIO / DMA mappings.
- **Device** — trusted by axiom `DEVICE_CORRECT` (§2), reachable only
  via SPDM through the host VMBus path.
- **Host VMM** — fully untrusted. Mediates every TDISP request /
  response over plain VMBus; can return any value for `result`,
  `tdi_state_after`, and the typed payload.
- **Paravisor (OpenHCL VTL2)** — the TDISP guest CVM. Owns the SPDM
  session, the lock-epoch nonce, the cached `tdi_state`, the cached
  TDI report, IDE keys, and the guest-facing
  `VPCI_QUERY_ISOLATED_RESOURCES` surface.
- **VTL0 workload** — the paravisor's own guest. Has no SPDM session
  for the TDI; consumes the paravisor's isolation classification.

In this mapping, **the paravisor inherits every §3.2 / §6 / §7 / §8 /
§10 obligation that the spec assigns to the "guest TVM"**. CHECK-1..9
land on the paravisor, not on VTL0.

## Final property list

Each property is a single, falsifiable statement intended to be
discharged by a Kani harness or by code review. The "Provable" column
records whether the property can be discharged in `vpci_client`-scoped
code with the SPDM/PSP/IDE layer modelled as an axiom (`Yes`), whether
it requires modelling deeper protocol layers (`Partial`), or whether it
lives in a different crate entirely (`Out-of-scope`).

| ID | Property | Spec basis | Provable in `vpci_client`? |
|---|---|---|---|
| **F-1** | After every public TDI operation, cached `tdi_state ∈ {state_before, decode(host_claimed_state_after)}`; `decode = None ⇒ state_before`; on `Err` return the cached state equals `state_before`. | §6 post, §3.2, §11 | Yes |
| **F-2** | The paravisor never sends a TDISP command whose §6 precondition on `tdi_state` is unsatisfied by the locally cached state. | ORD-1..6, §6 Pre | Yes |
| **F-3** | A cached report is treated as `verified` only if (a) all chunks were reassembled with monotonically increasing, contiguous, non-overlapping offsets ending with `remainder_length=0`, and (b) the report's `device_info_hash` matched the trusted oracle (CHECK-1 / V1). The oracle is modelled as a fixed `kani::any()` value held constant across the harness. | CHECK-1, CONC-3, ORD-13, §6.2 | Yes (with oracle axiom) |
| **F-4** | A cached report marked `verified` is bound to the lock-epoch nonce of the immediately preceding successful `LOCK_INTERFACE_RESPONSE` for this TDI. The nonce is consumed by at most one `START_INTERFACE_REQUEST` and never reused. | CHECK-6, SAFE-3, INV-8, V6 | Yes |
| **F-5** | A new `LOCK_INTERFACE_RESPONSE` invalidates any prior cached report and prior `EPOCH_ACTIVE` for that TDI before any further operation observes them. | §3.5, SAFE-3 | Yes |
| **F-6** | The paravisor never invokes `tdisp_unblock_mmio(gpa, len, range_id)` unless `[gpa, gpa+len)` is fully contained in the verified report's range for `range_id`, and the resulting accepted set is injective in GPA (no aliasing). | CHECK-4, CHECK-5, INV-5, INV-6 | Yes |
| **F-7** | The paravisor never invokes `tdisp_unblock_mmio` or `tdisp_unblock_dma` unless: cached `tdi_state == Run` ∧ verified report cached ∧ `classify(bar) == PRIVATE` ∧ ¬already-validated for that BAR/range. (Stated separately for the MMIO and DMA gates.) | SAFE-1, SAFE-7, PSI-25..32 | Yes |
| **F-8** | The paravisor never sends `LOCK_INTERFACE_REQUEST` unless its cached IDE-stream model is `SECURE` and the SPDM session it will use for IDE keying is the same session it records as `lock_session`. | §6.1 Pre, ORD-1, ORD-11, INV-7, CHECK-7, SAFE-4 | Yes (axioms: SPDM_SESSION_AUTHENTIC + IDE_KM correctness) |
| **F-9** | On any observed IDE-insecure, SPDM-session-lost, FLR, conventional-reset, or config-change event in any cached state in `{LOCKED_UNVERIFIED..TRUSTED_RUN}`, the cached state transitions to `Untrusted` before any subsequent operation can observe the prior cached "verified report" or "Run" state. | SAFE-6, §3.3, PSI-34 | Partial (async event delivery; local response is in scope) |
| **F-10** | The verified report's `default_stream_id` equals the IDE stream the paravisor records as bound for this TDI. | CHECK-8 | Yes (same axioms as F-8) |
| **F-11** | `isolation_snapshot()` returns `Ready` only if cached `tdi_state == Run` ∧ verified report cached ∧ resource-acceptance step has completed for the BARs the VTL0 guest can address as trusted. (`Locked` is **never** a safe `Ready` state.) | SAFE-1, SAFE-7, PSI-6, PSI-10, PSI-25, §6.4 | Yes |
| **F-12** | On `tdisp_unbind`, all previously-unblocked MMIO ranges are re-blocked and all in-flight DMA is aborted **before** `STOP_INTERFACE_REQUEST` is sent; IDE/SPDM/device key scrub is recorded only after `STOP_INTERFACE_RESPONSE`. | INV-9, ORD-10, ORD-14, §6.6 | Partial (re-block ordering Yes; key-scrub semantics need IDE/SPDM model) |
| **F-13** | After `tdisp_unbind` returns `Ok`: `tdi_state == Unassigned`, no cached report is treated as verified, `lock_epoch == NO_EPOCH`, `validated_mmio_bars == ∅`, `dma_unblocked == false`. | PSI-2, PSI-3, PSI-37..38, §6.6 Post | Yes |
| **F-14** | `tdisp_unbind_preserve_report` preserves only the report bytes; it MUST clear the `verified` flag, `accepted_mmio`, `accepted_dma`, `lock_epoch`, and any cached "Run" indicator. A preserved report is downgraded to *unverified*; it is never accepted in a new epoch without re-running F-3 + F-4 against a fresh nonce. | SAFE-3, INV-8, V6, §6.6 | Yes |
| **F-15** | Any internal recovery / abort path leaves `(tdi_state, validated_mmio_bars, dma_unblocked, verified-report flag)` in either the pre-operation tuple or the `Untrusted` tuple — never in a partially-validated tuple. | PSI-34..38, INV-9 | Yes |
| **F-16** | The verifier rejects any report whose `device_identity` does not match the paravisor's pinned/expected identity and whose `measurements` are not in the policy allow-list. | CHECK-2, CHECK-3, V2, V3 | Out-of-scope (lives in `underhill_attestation` / SPDM policy layer) |
| **F-17** | TDI-ID binding across LOCK → REPORT → START: every cached field (`tdi_report`, `tdi_state`, `validated_mmio_bars`, `dma_unblocked`, `default_stream_id`) is keyed by the `tdi_id` (function_id) named in the `LOCK_INTERFACE_REQUEST`. The paravisor rejects any response whose `tdi_id` field disagrees with the in-flight request's `tdi_id`. | §10 CHECK-class | Yes |
| **F-17a** | The paravisor never accepts a `LOCK_INTERFACE_RESPONSE` over an SPDM session whose peer identity (cert chain leaf) has changed since session establishment. | CHECK-7, V2, V3, §6.1 | Partial (needs SPDM peer-identity model) |

## Provability summary

- **Provable in `vpci_client` today (with axiomatised PSP/SPDM/IDE):** F-1, F-2, F-3, F-4, F-5, F-6, F-7, F-8, F-10, F-11, F-13, F-14, F-15, F-17. (14 properties)
- **Partially provable (response-side local, async / deeper layer external):** F-9, F-12, F-17a.
- **Out-of-scope for `vpci_client` (different crate):** F-16.

## Notes on consumer surface

- The properties are stated against the paravisor's responsibilities,
  not against any specific public API. F-1, F-2, F-4, F-5 constrain
  `tdisp_bind_interface`, `tdisp_start_device`, `tdisp_get_device_report`,
  `tdisp_unbind`. F-6, F-7 constrain `tdisp_on_mmio_reconfigured`. F-11
  constrains `isolation_snapshot()` /
  `tdisp_isolation_snapshot()` / `tdisp_get_tdi_state()`. F-12, F-13,
  F-14 constrain the unbind family. F-17 constrains `send_tdisp_command`
  and every per-method handler.
- Every property is intended to hold **regardless of the host's
  response**. The host adversary may return any combination of
  `result`, `tdi_state_after`, and typed payload (including undecodable
  values, mismatched payloads, and protocol-violating sequences).

## Out-of-scope (intentional)

- Confidentiality of guest-private memory pages once a BAR is
  classified `PRIVATE` and accepted — this is a downstream platform
  obligation backed by `SEV_PSP_CORRECT`, not a paravisor obligation.
- VTL0 driver behaviour after the paravisor returns a `Ready` snapshot
  — the paravisor's contract ends at faithful classification.
- Performance properties (timing, throughput).
- Liveness / progress (the paravisor is allowed to refuse / `Err` any
  operation; safety properties only constrain what `Ok` returns may
  imply).

## Review log

- **Drafted from first principles** (no production-source reading) by
  the maintainer.
- **Round 1 critique** by TDISP/SEV-TIO/SPDM expert subagent: 12 → 16
  properties. Merges (P-4/P-5/P-6/P-12 → F-1), additions (F-5, F-6
  aliasing, F-9, F-12 ordering, F-14, F-15), tightening of F-11 to
  `{Run}` only.
- **Round 2 push-back** on provability classification: F-3, F-8, F-10
  upgraded from `Partial` to `Yes` with explicit axioms. F-17 added
  (TDI-ID binding) per subagent's "must-add". F-17a added as a deferred
  SPDM-layer companion.
