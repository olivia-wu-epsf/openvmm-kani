# `vpci_relay` TDISP verification opportunities (M-relay-N)

This document catalogs additional Kani verification opportunities
identified in `vm/devices/pci/vpci_relay/src/lib.rs` during the
focused review of AF-iter2-1's exploit path. The properties below
are **state-machine, ordering, and cache invariants enforced or
claimed by the relay itself** — not delegations to `vpci_client`'s
per-method invariants already covered by M-1..M-10.

These are **not yet implemented as Kani harnesses**. They are
exploration outputs from the OpenHCL expert; concrete harness
authoring is deferred.

## Source-of-truth restriction

This list was derived under the same skill-only restriction as the
rest of iteration 2: only the openhcl-knowledge-base skill, the
per-crate KB, and source-code comments in `.rs` files. No
`docs/tdisp-*.md` references were consulted.

## Surface

The OpenHCL expert's call-site inventory of TDISP entry points hit
from `vpci_relay`:

| API on `VpciClientTdispState` / `VpciDevice` | vpci_relay caller | Site |
|---|---|---|
| `tdisp_query_capabilities()` | `relay_vpci_bus`, per arrived device | [lib.rs#L389](../../vm/devices/pci/vpci_relay/src/lib.rs#L389) |
| `tdisp_attest_device(...)` | `relay_vpci_bus`, after capabilities OK | [lib.rs#L394](../../vm/devices/pci/vpci_relay/src/lib.rs#L394) |
| `tdisp_unbind_preserve_report(Graceful)` | `relay_vpci_bus`, after attest_device OK | [lib.rs#L411](../../vm/devices/pci/vpci_relay/src/lib.rs#L411) |
| `tdisp_attest_device(...)` (mock) | `tdisp_test_mock_attest_flow` | [lib.rs#L560](../../vm/devices/pci/vpci_relay/src/lib.rs#L560) |
| `tdisp_unbind(DeviceTeardown)` | `RelayedDevice::remove` (gated) | [lib.rs#L146](../../vm/devices/pci/vpci_relay/src/lib.rs#L146) |
| `tdisp_tdi_state()` | `RelayedDevice::remove` (gating) | [lib.rs#L143](../../vm/devices/pci/vpci_relay/src/lib.rs#L143) |
| `tdisp_on_device_activate()` | `pci_cfg_write` MMIO-enable edge | [lib.rs#L705](../../vm/devices/pci/vpci_relay/src/lib.rs#L705) |
| `tdisp_on_device_deactivate()` | `pci_cfg_write` MMIO-disable edge (gated `tdi_state ∉ {Uninitialized, Unlocked}`) | [lib.rs#L735](../../vm/devices/pci/vpci_relay/src/lib.rs#L735) |
| `tdisp_try_isolation_snapshot()` | `tdisp_isolation_report` (sync, from `vpci` server's `QueryIsolatedResources` handler) | [lib.rs#L633](../../vm/devices/pci/vpci_relay/src/lib.rs#L633) |
| `mark_bar_intercepted` / `is_bar_intercepted` / `tdisp_on_mmio_reconfigured` | **Not called from vpci_relay** — driven internally from `tdisp_on_device_activate` ([vpci_client/src/lib.rs#L900-L935](../../vm/devices/pci/vpci_client/src/lib.rs#L900)) | — |

## Verification opportunities

| # | Property (one-sentence falsifiable) | Symbolize | Drives entry-point | Severity |
|---|---|---|---|---|
| **M-relay-1** | After `tdisp_on_device_deactivate` returns successfully, the cached `tdi_state` must be in `{Unlocked, Uninitialized}`; never `Run` or `Locked`. | A symbolic `Run`-state device whose host channel returns a wire-valid `Unbind` response with `result=Success` and a host-chosen `tdi_state_after`. | `RelayedVpciDevice::pci_cfg_write` MMIO-disable edge (or `tdisp_on_device_deactivate` directly). | **High** — the missing post-check that AF-iter2-1 exploits; falsification gives the relay-driven exploit. |
| **M-relay-2** | The MMIO-enable activate path must NEVER call `tdisp_on_mmio_reconfigured` without first having issued (within the same activate call) at least one of `query_capabilities` followed by `bind/start/get_tdi_report` — i.e. it must not consult a cached report it inherited from a prior cycle that the relay itself terminated with an unbind. | Symbolic `Run`-or-`Unlocked`-cached device with a non-`None` `tdi_report` from a previous cycle; symbolic guest BAR shadows. | `RelayedVpciDevice::pci_cfg_write` MMIO-enable edge (drives `tdisp_on_device_activate`). | **High** — cycle-(N+1) MMIO admitted into TCB without fresh attestation. |
| **M-relay-3** | The deferred cfg-write on the MMIO-disable edge must always observe `tdisp_on_device_deactivate` having completed before the cfg write reaches the host (no reordering window where guest sees MMIO-disabled while pages are still PRIVATE/RMP-flipped). | Two interleaved cfg writes: disable then enable, with a symbolic poll-order on the deferred futures. | `RelayedVpciDevice::pci_cfg_write` + `PollDevice::poll_device`. | **Medium** — KB calls this informational; a Kani harness would convert it to a witness or a proof. |
| **M-relay-4** | At any time, `RelayedVpciDevice::pending` holds at most ONE in-flight TDISP future (no stacking by rapid back-to-back cfg writes); that is, `pci_cfg_write` returning `IoResult::Defer` must not be possible while `pending.is_some()`. | Symbolic prior `pending` state (`None` or `Some`); symbolic `STATUS_COMMAND` value sequence. | `RelayedVpciDevice::pci_cfg_write`. | **Medium** — currently relies on the *external* "bus serializes cfg writes" comment ([lib.rs#L685-L687](../../vm/devices/pci/vpci_relay/src/lib.rs#L685)); a stacking bug would corrupt deferred-write completion. |
| **M-relay-5** | `RelayedVpciDevice::tdisp_isolation_report` must NEVER block (only `try_lock`) and must NEVER return `Ready` when `tdi_report` is absent — i.e. the snapshot path must be non-blocking and must not synthesize `PRIVATE` classification from partial state. | Symbolic mutex-contended state and symbolic `tdi_report ∈ {None, Some}`. | `RelayedVpciDevice::tdisp_isolation_report`. | **Medium** — guest-controlled `QueryIsolatedResources` path; blocking under contention is a DoS, synthesizing `Ready` is a confidentiality lie. |
| **M-relay-6** | `RelayedDevice::remove`'s teardown unbind (`tdisp_unbind(DeviceTeardown)`) must be issued *exactly* when `tdi_state != Uninitialized` at entry; the channel/device-unit teardown must precede the unbind so no further guest packets can race the unbind. | Symbolic `tdi_state` at entry; ordering of `bus_unit.remove`, `device_unit.remove`, and `tdisp_unbind` calls observed via instrumented mocks. | `RelayedDevice::remove`. | **Medium** — wrong order leaves a window for guest-initiated TDISP commands to hit a half-torn-down device. |
| **M-relay-7** | If `tdisp_unbind_preserve_report` after the proactive `tdisp_attest_device` *fails* in `relay_vpci_bus` ([lib.rs#L411-L420](../../vm/devices/pci/vpci_relay/src/lib.rs#L411)), the relay must NOT proceed to insert the device into `self.devices` while leaving cached `tdi_state == Run` and `tdi_report` populated — otherwise the very first guest MMIO-enable will hit the M-relay-2 "skip attest" path. | Symbolic post-`attest` state (`Run`) and symbolic `tdisp_unbind_preserve_report` outcome (`Ok` / `Err`). | `VpciRelay::relay_vpci_bus`. | **High** — today the `Err` arm only logs and continues. Same-class exploit as AF-iter2-1's relay path without needing AF-iter2-1 itself. |
| **M-relay-8** | `RelayedVpciDevice::pci_cfg_write` must invoke a TDISP edge handler exactly once per *true* `mmio_enabled` transition, and never on enable→enable / disable→disable writes (or other `STATUS_COMMAND` bit-only writes). | Symbolic prior `STATUS_COMMAND` value (read via `read_cfg`) and symbolic incoming `value`; verify the `mmio_edge: Option<bool>` discriminant. | `RelayedVpciDevice::pci_cfg_write` with `offset == STATUS_COMMAND`. | **Low–Medium** — spurious activate calls flood the host with bind/attest churn; spurious deactivates poison the cache via AF-iter2-1's window. |
| **M-relay-9** | The relay's `tdisp_isolation_report` reply must ONLY classify a BAR as `PRIVATE` when, at the same observation point, `vpci_client` would actually call `tdisp_unblock_mmio` for that BAR on the next MMIO-enable edge. (Cross-check the relay's reported `bars[i]` against `classify_bar(i)` AND against the gating logic at [vpci_client/src/tdisp.rs#L1325-L1385](../../vm/devices/pci/vpci_client/src/tdisp.rs#L1325).) | Symbolic cached `tdi_report`, `intercepted_bars`, and `tdi_state`. | `RelayedVpciDevice::tdisp_isolation_report` paired with `tdisp_on_mmio_reconfigured`. | **High** — directly characterizes the Stage-1 confidentiality lie in AF-iter2-1's exploit: today the snapshot reports `PRIVATE` based on the cached report regardless of whether the activate path will actually re-attest. |
| **M-relay-10** | The `(false, true)` MMIO-enable arm at [lib.rs#L702-L719](../../vm/devices/pci/vpci_relay/src/lib.rs#L702) writes the cfg *before* spawning the activate future; the relay must therefore guarantee that the host cannot observe the BAR pages as `PRIVATE` (i.e. cannot have `tdisp_unblock_mmio` already been called) at the moment of that cfg write. (The current code relies on `validated_mmio_bars` having been cleared by the matching disable-edge unbind; if AF-iter2-1 leaves it cleared but state == Run, the next activate skips attest and re-arms unblock — verify the temporal ordering.) | Composition of M-relay-1 and M-relay-2 with the deferred-write order. | `RelayedVpciDevice::pci_cfg_write` enable arm. | **Medium** — TOCTOU window between guest-visible cfg state and TDISP-visible RMP state. |

## Open questions

These should be referred to the TDISP-spec expert in a future
iteration to decide whether the corresponding properties are
TVM-mandatory or only defense-in-depth:

1. Does the spec require the TVM to perform a full
   `bind→start→get_report` chain on every transition out of
   `Unlocked` into the TCB (M-relay-2 / M-relay-9), or is a TVM
   allowed to cache attestation evidence across an `Unlocked`
   interval if it can prove the firmware-side TDI was not torn
   down?
2. Does the spec impose any TVM-side post-check on the
   `tdi_state_after` field of an `Unbind` response (M-relay-1)?
   AF-iter2-1's TDISP-spec adjudication already established that
   `STOP_INTERFACE_RESPONSE` carries no such field per §11.3.17,
   strongly implying yes.

## Priority recommendations for next iteration

If iteration 3 picks up M-relay-N:

- **First**: M-relay-1 (the missing post-check; same finding as
  AF-iter2-1 viewed through the relay surface).
- **Second**: M-relay-7 (relay's `relay_vpci_bus` error-path
  swallowing is a same-class exploit independent of AF-iter2-1).
- **Third**: M-relay-2 + M-relay-9 (the chain-of-custody +
  isolation-snapshot honesty pair).

The remaining (M-relay-3..6, 8, 10) are useful defense-in-depth
hygiene targets but are not on the critical path of any current
finding.
