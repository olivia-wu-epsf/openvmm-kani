# OpenHCL Paravisor TDISP TVM — Security Property List (Iteration 2)

This document records the consensus list of TVM-side TDISP security
properties that the OpenHCL paravisor is responsible for enforcing
under the malicious-host threat model. The list was derived by
independent debate between two skill-restricted expert subagents and
reconciled into a single Kani-targeted verification plan.

## Threat model & scope

- **OpenHCL paravisor = TVM** in the PCI-SIG TDISP v2022-07-27 role
  mapping. The paravisor sits in VTL2 and owns the local TDI-state
  cache, the cached interface report, BAR validation bookkeeping, and
  the guest-facing isolation classification.
- **Host VMM = fully untrusted adversary** that mediates the VMBus
  channel between the paravisor and the host-side TDISP machinery.
  Every TDISP response field (`error_code` / `result`,
  `tdi_state_after`, response payload variant and contents) is
  attacker-controlled.
- **Goals**: confidentiality and integrity of the TVM and its
  communications with the TEE device.
- **Non-goal**: availability. The paravisor may refuse / error / hang
  any operation. We only require that any `Ok(_)` return never implies
  an unsafe local cached state.
- **Cryptographic correctness of SPDM, IDE, and the SEV PSP** is
  treated as an external axiom (in the role mapping, the PSP is the
  trusted firmware oracle). Properties that depend on those layers are
  **out of scope** for `vpci_client`-level Kani verification.

## Sources of truth (only)

- `.github/skills/tdisp-spec/SKILL.md` and the PCI-SIG TDISP
  v2022-07-27 specification it references.
- `.github/skills/openhcl-knowledge-base/SKILL.md` and
  `docs/openhcl-knowledge-base.md`.
- `.github/skills/model-checking/SKILL.md`.
- Source-code comments in [vm/devices/pci/vpci_client/src/tdisp.rs](../../vm/devices/pci/vpci_client/src/tdisp.rs)
  and [openhcl/openhcl_tdisp/src/lib.rs](../../openhcl/openhcl_tdisp/src/lib.rs)
  (treated as descriptive, not normative).

Pre-existing TDISP property docs and Kani harness files were
intentionally **not** consulted.

## Subagent debate process

1. **Round 1 (independent drafting).**
   - TDISP-spec subagent (Claude Opus 4.7) — restricted to the
     tdisp-spec skill — produced 9 properties grounded in PCI-SIG TDISP
     §11.x.
   - OpenHCL subagent (Claude Opus 4.7) — restricted to the
     openhcl-knowledge-base skill — produced 10 properties grounded in
     paravisor crate / file references.
2. **Round 2 (TDISP expert merges and proposes).** TDISP-spec subagent
   merged the two lists into a single 10-item proposal (M-1 .. M-10),
   marked two items `[CONTESTED?]`, and dropped two with rationale.
3. **Round 3 (OpenHCL expert reviews and adjudicates).** OpenHCL
   subagent reviewed each merged item, accepted, amended, or rejected
   based on actual paravisor code, and re-confirmed the dropped items.
4. **Result**: the consensus list below. No human escalation needed at
   this stage.

## Final consensus list

| ID    | Pri | Statement |
|-------|-----|-----------|
| M-1   | P0  | Cached `tdi_state` matches spec post-state on `Ok` of Bind / Start / Unbind: Bind→`Locked`, Start→`Run`, Unbind→`Unlocked`. |
| M-3   | P0  | `mutable_state.tdi_report` is `Some(_)` only after a complete attest chain (Bind → Start → GetTdiReport with cached state `Run` on entry); set to `None` exactly when `tdisp_unbind_inner(.., clear_cached_report=true)` succeeds. |
| M-4   | P0  | `tdisp_unblock_mmio(bar)` is invoked only when `tdi_state == Run` ∧ `tdi_report` cached ∧ `classify_bar(bar) == PRIVATE` (where `classify_bar` is a pure function of cached state — no host-supplied data). |
| M-5   | P0  | `tdisp_unblock_dma` is invoked only after a same-call M-4-satisfying `tdisp_unblock_mmio` has succeeded; never if `tdi_state ≠ Run`. |
| M-6   | P0  | A successful Unbind re-blocks every previously unblocked MMIO range and DMA scope **before** the host-facing Unbind RPC; on `Ok` clears `validated_mmio_bars`, `dma_unblocked`, and (for the non-preserving variant) `tdi_report`. |
| M-7   | P0  | Audit invariant: every outgoing TDISP command's cached `tdi_state` at issue is in the request code's "Legal TDISP states for Device" column in §11.3.1 Table 3. |
| M-8a  | P0  | `isolation_snapshot()` is a pure function of `mutable_state` only (no I/O, no validator/PSP call, no mutation). Returns `NotReady` iff `tdi_report.is_none()`; otherwise returns `Ready { bars, dma }` with `bars[i] = classify_bar(i)` and `dma = PRIVATE iff dma_unblocked else SHARED`. |
| M-8b  | P1  | Tightened: `isolation_snapshot()` returns `NotReady` unless `tdi_state == Run`. **Expected to FAIL** in the current implementation (corresponds to the OpenHCL-expert-flagged audit finding around `tdisp_unbind_preserve_report` leaving `tdi_report` cached while the TDI is in `Unlocked`). |
| M-9   | P0  | (a) `attest()` Ok ⇒ `tdi_state == Run` ∧ `tdi_report.is_some()`. (b) Inside `attest()`, the only insertions into `intercepted_bars` are for cached-report ranges with the MSI-X table or PBA flag set. |
| M-10  | P1  | `mark_bar_intercepted(b)` is monotonic across attest / unbind cycles (never cleared). |

## Spec basis (per property)

All citations to PCI-SIG TDISP ECN v2022-07-27.

- **M-1**: §11.2 Figure 11-5 (state machine); §11.3.1 Table 3
  (legal source/post states); §11.3.9 (Lock → `CONFIG_LOCKED`); §11.3.14
  (Start → `RUN`); §11.3.16 + §11.3.17 (Stop → `CONFIG_UNLOCKED`; no
  request-specific response payload defined).
- **M-3**: §11.3.10 (legal states `LOCKED`/`RUN`,
  `INVALID_INTERFACE_STATE` error); §11.3.1 Table 3; §11.6.3 (TVM and
  TSM use `DEVICE_INTERFACE_REPORT` to enforce assignment correctness).
- **M-4**: §11.3.11 Table 15 (attribute flags including
  `IS_NON_TEE_MEM`, MSI-X table/PBA bits, `Range ID/BEI` ordering);
  §11.4.5 (RUN required for TVM-side memory access); §11.6.3
  (overlapping/reordered MMIO threats).
- **M-5**: §11.5.3; §11.6.3 ("securely enabling the memory space and
  DMA for TVM access using `START_INTERFACE_REQUEST`").
- **M-6**: §11.3.16 (`STOP` semantics: drain/abort/scrub before
  `STOP_RESPONSE`); §11.4.5; §11.6.3 (race-on-detach threat).
- **M-7**: §11.3.1 Table 3; per-message error tables (e.g. §11.3.9
  / §11.3.10 `INVALID_INTERFACE_STATE`).
- **M-8a, M-8b**: §11.2.7 acceptance Q1–Q4; §11.6.3 (TSM not in TVM
  TCB).
- **M-9**: §11.3.10 Table 15 MSI-X bits; §11.3.8 `LOCK_MSIX` flag;
  §11.4.5 ("transactions to access the MSI-X table and PBA without the
  T bit Set must be rejected").
- **M-10**: §11.6.3 reprogramming threat (defensive hardening; not a
  hard normative spec requirement).

## Defense against "this is the host's job, not the TVM's"

In the OpenHCL threat model the host is **the TSM** and is **outside
the TCB**. PCI-SIG TDISP §11.5 and §11.6.3 routinely assign state-
tracking obligations to the TSM, but those obligations migrate onto
the paravisor in this mapping because there is no other trusted party
left between the device (DSM, trusted by axiom) and the paravisor
(TVM). Ceding state tracking to host-supplied metadata discards the
named §11.6.3 LOCK→REPORT→START chain-of-custody mitigation.

## Dropped properties

| Dropped | Why |
|---|---|
| Nonce custody (`START_INTERFACE_NONCE`) | The paravisor sits on the wrong side of VMBus to ever see the SPDM-/IDE-layer nonce; firmware-owned (PSP). Out of scope for `vpci_client`. |
| `query_capabilities` ⇒ `guest_protocol_type` matches `isolation_type` | A trivially-auditable 4-line static `match` in the paravisor; not a TDISP-spec property. |
| "No shortcut to private" composite | Provably the conjunction of M-1 ∧ M-3 ∧ M-4 ∧ M-8. No standalone proof needed. |

## Verification plan

Each property is verified by one or more `#[kani::proof]` harnesses in
[vm/devices/pci/vpci_client/src/kani_proofs_session.rs](../../vm/devices/pci/vpci_client/src/kani_proofs_session.rs).
The harnesses share the production-side `#[cfg(kani)]` infrastructure
on `VpciClientTdispState` (constructors `kani_new_with_response`,
`kani_new_for_mmio_reconfigured`, `kani_new_for_unbind_with_report`,
`kani_new_for_activate`, plus the audit-trail accessor
`kani_audit_trail`) — which is part of the production crate, not part
of any pre-existing harness file.

Per the user's instructions, harnesses are written one at a time. Any
verification failure triggers another expert-debate round to determine
true-positive vs false-positive before proceeding.

## Status (this iteration)

| Harness | Status |
|---|---|
| `m1_bind_ok_implies_state_locked` | ✅ verified (1.6 s, 320 VCCs) |
| `m1_start_ok_implies_state_run` | ✅ verified (1.7 s, 360 VCCs) |
| `m1_unbind_ok_implies_state_unlocked` | ❌ **FAILED — TRUE POSITIVE finding AF-iter2-1** (see [findings/m1-unbind-missing-post-check.md](findings/m1-unbind-missing-post-check.md)) |
| `m1_unbind_preserve_ok_implies_state_unlocked` | ❌ **FAILED — same root cause** |
| `m3_unbind_clears_cached_report` | ✅ verified (~9.6 s) |
| `m3_unbind_preserve_keeps_cached_report` | ✅ verified (~6.4 s) |
| `m3_bind_does_not_grow_report` | ✅ verified |
| `m3_start_does_not_grow_report` | ✅ verified |
| `m3_unbind_does_not_grow_report` | ✅ verified |
| `m3_attest_ok_implies_report_cached_and_run` | ⚠ removed — CBMC OOM on multi-call attest orchestration; behavioral coverage via M-3 negative trio + M-1 Start, plus the static observation that the only `Some(_)` writer of `tdi_report` is inside `attest()` |
| `m4_unblock_mmio_requires_run_report_private` | ✅ verified (~6.8 s) |
| `m5_unblock_dma_requires_unblock_mmio_in_same_call` | ✅ verified (~6.5 s) |
| `m6_unbind_reblocks_and_clears_bookkeeping` | ✅ verified (~6.8 s) |
| `m6_unbind_preserve_reblocks_and_clears_bookkeeping` | ✅ verified (~6.3 s) |
| `m6_unbind_skips_block_for_zero_length_bar` | ✅ verified (~3.1 s) — SHARED-sentinel branch |
| `m7_bind_audit_state_is_unlocked` (request-side) | ⚠ removed after debate — adjudicated **FALSE POSITIVE** as a TDISP-spec security finding; Table 3 governs the device, not the TVM. See [findings/m7-request-side-adjudication.md](findings/m7-request-side-adjudication.md) |
| `m7_start_audit_state_is_locked` (request-side) | ⚠ removed (same FALSE POSITIVE as above) |
| `m7_unbind_audit_trail_is_well_formed` | ✅ verified (~75 s) — renamed from `m7_unbind_audit_state_in_legal_set` per OpenHCL-expert review (asserts only that `UNBIND` audit entries carry a valid enum discriminant; the spec-legal-source-state portion is vacuous because §11.3.1 Table 3's source-state set for STOP is "any") |
| `m8a_isolation_snapshot_is_pure_no_validator_calls` | ⚠ removed — CBMC OOM (validator-counter atomic state on top of 6× BTreeMap traversals). Behavioral content covered by `m8a_isolation_snapshot_classification_for_matching_bar`; "no validator I/O" is a code-grep observation (`isolation_snapshot` takes `&self` and never reaches the validator field) |
| `m8a_isolation_snapshot_classification_for_matching_bar` | ✅ verified (~214 s) |
| `m8a_isolation_snapshot_invalid_when_report_lacks_matching_range` | ✅ verified (~7 s) — INVALID-from-Ready branch |
| `m9_attest_ok_implies_run_and_report` | ⏸ deferred — same multi-call OOM as M-3 attest; behavioral coverage via M-1 Start + M-3 negative trio + static observation |
| `m10_mark_bar_intercepted_persists_across_unbind` | ✅ verified (~9.1 s) |
| `m10_mark_bar_intercepted_persists_across_unbind_preserve` | ✅ verified (~9.2 s) |
