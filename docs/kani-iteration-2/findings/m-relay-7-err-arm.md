# AF-iter2-2 — `vpci_relay` admits device when post-attest unbind fails

**Property violated:** M-relay-7 Err-arm — when
`vpci_device.tdisp_unbind_preserve_report(Graceful)` returns `Err(_)`
in the relay's proactive arrival cycle, the relay still admits the
device with the cached `tdi_state` poisoned to `Run` (and a stale
`tdi_report`).

**Code site:**
[vm/devices/pci/vpci_relay/src/lib.rs#L411-L429](../../../vm/devices/pci/vpci_relay/src/lib.rs#L411-L429)
(arrival cycle's `Err` arm — only logs, falls through to admit) +
[vm/devices/pci/vpci_client/src/tdisp.rs#L527-L548](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L527-L548)
(`update_tdi_state` runs unconditionally **before** the
`error_code != Success` check that returns `Err`).

**Harnesses:** [vm/devices/pci/vpci_client/src/kani_proofs_session.rs](../../../vm/devices/pci/vpci_client/src/kani_proofs_session.rs)
- `m_relay_7_err_arm_relay_inserts_with_poisoned_cache` — failed
  in 8.0 s. Asserts `kani::assume(r.is_err())` to isolate the
  Err-arm failure mode.
- `m_relay_7_ok_arm_corroborates_af_iter2_1` — failed in 8.0 s.
  Asserts `kani::assume(r.is_ok())` to isolate the AF-iter2-1
  failure mode (Ok-arm with poisoned `tdi_state_after`).
- `m_relay_7_arrival_cycle_failed_unbind_must_not_leave_run_state`
  — failed in 8.7 s. Union harness covering both arms.

**Severity:** high — same downstream consequence as AF-iter2-1
(chain-of-custody bypass on next guest MMIO unblock), distinct
upstream lever.

**Verdict:** TRUE POSITIVE. Both expert subagents (TDISP-spec and
OpenHCL) reached this verdict independently with skill-only sources.
**Distinct from AF-iter2-1.** Fixing AF-iter2-1 does not fix
AF-iter2-2 and vice versa.

## Counterexample (Kani)

Malicious host returns:

```
GuestToHostResponse {
    result:           any non-Success (e.g. NotReady, BUSY, Other),
    tdi_state_before: <any>,
    tdi_state_after:  Run,                         // wire-attacker-controlled
    response:         Some(Resp::Unbind(...)),
}
```

Inside [`send_tdisp_command`](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L527-L548):

```rust
match res.tdi_state_after_enum() {
    Some(state) => self.mutable_state.update_tdi_state(state),  // line 530 — UNCONDITIONAL
    None => tracing::warn!(...),
}
match res.error_code() {
    Some(Success) => Ok(res),
    other => Err(crate::err!(...)),  // line 545 — Err only when error_code != Success
}
```

So the cache is poisoned to `Run` **before** the function returns
`Err`. `tdisp_unbind_preserve_report` propagates the `Err`, and
the cached `tdi_report` is left untouched (the `Err` arm of
`tdisp_unbind_inner` at [tdisp.rs#L890](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L890)
neither preserves nor clears it by intent — it just returns).

The relay's arrival cycle at
[vpci_relay/src/lib.rs#L416-L420](../../../vm/devices/pci/vpci_relay/src/lib.rs#L416-L420):

```rust
Err(e) => tracing::error!(
    %instance_id,
    error = &*e as &dyn std::error::Error,
    "TDISP post-attestation unbind failed; continuing to relay device"
),
```

falls through to `chipset.add_dyn_device(...)` /
`vpci::bus::VpciBus::new(...)` ([lib.rs#L451-L488](../../../vm/devices/pci/vpci_relay/src/lib.rs#L451-L488)).
The device is now visible to VTL0 with cache `tdi_state = Run`,
`tdi_report = Some(stale)`, and downstream `tdisp_on_mmio_reconfigured`
will skip attestation and fire `tdisp_unblock_mmio` against
attacker-chosen BAR coordinates.

## Distinction from AF-iter2-1

| | AF-iter2-1 (Ok-arm) | AF-iter2-2 / M-relay-7 (Err-arm) |
|---|---|---|
| Wire payload | `error_code = Success`, `tdi_state_after = Run` | `error_code = NotReady` (or any non-Success), `tdi_state_after = Run` |
| TDISP §11.3.24 framing | A "successful" unbind whose state field is internally inconsistent with the requested transition | An explicit "request not performed" — TDI's true on-device state was not touched by the request |
| Defective layer | `tdisp_unbind_inner` (no post-state check after `Ok`) | `vpci_relay::relay_vpci_bus` arrival cycle (no fail-closed on `Err`) + `send_tdisp_command` (cache update precedes error check) |
| Spec obligations breached | §11.6.3 chain-of-custody; §11.2.7 Q1/Q4 | §11.3.24 (error = not-performed); §11.6.3 chain-of-custody; §11.2.7 Q1/Q4 |
| Fix locality | `vpci_client::tdisp_unbind_inner` — verify `tdi_state == Unlocked` before returning `Ok` | `vpci_relay` Err arm + `vpci_client::send_tdisp_command` (gate cache update on `Success`) + `vpci_client::tdisp_unbind_inner` Err arm (evict cached report) |

**Critically**: fixing AF-iter2-1 does not fix AF-iter2-2 (the
Err-arm bypasses the post-check entirely), and fixing AF-iter2-2
does not fix AF-iter2-1 (a fail-closed relay still admits the
Ok-with-poisoned-state case).

## TDISP-spec basis (TDISP-expert subagent)

PCI-SIG TDISP v2022-07-27:

- **§11.3.24 TDISP_ERROR + Table 27** — *"The TDISP_ERROR is
  permitted to be used by the device to complete any of the
  requests issued to the device."* The semantics are explicit: a
  `TDISP_ERROR` is the completion form the responder uses when the
  requested operation **was not performed**. (`BUSY` even spells
  this out: "the Responder may be able to process the request
  message if the request message is sent again in the future.")
  Implication: when a request that *would have* effected a state
  transition (e.g. `STOP_INTERFACE_REQUEST`, the wire-level
  primitive underlying `tdisp_unbind_preserve_report`) returns
  `TDISP_ERROR`, the **TDI's true on-device state is whatever it
  was before the request** — it was not touched.

- **§11.6.3 LOCK→REPORT→START chain-of-custody** — re-admission
  must rest on a fresh, verified LOCK→REPORT→START in the same
  SPDM session, anchored by the per-LOCK nonce. A failed/incomplete
  detach cannot be silently treated as a clean detach.

- **§11.2.7 Q1/Q4** — TVM acceptance gate. Q1/Q4 must be answered
  before admitting the TDI into the TVM TCB. There is no
  spec-permitted "log the error and continue admitting the device"
  branch.

## OpenHCL paravisor basis (OpenHCL-expert subagent)

- **No post-relay invalidation hook**. `tdisp_query_firmware_tdi_state`
  is implemented but has zero production callers (KB lines
  1364-1369). `RelayedDevice::remove`'s teardown unbind is gated
  on the (poisoned) cached `tdi_state`. No watchdog evicts on
  arrival-time TDISP failure.

- **`update_tdi_state` is a latent defect**. No production caller
  benefits from observing a host-claimed Err-arm `tdi_state_after`.
  Local fix in [`send_tdisp_command`](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L527-L548):
  gate the cache update on `error_code == Success`.

- **The relay's `Err` arm violates its own design intent**. The
  comment at [vpci_relay/src/lib.rs#L405-L410](../../../vm/devices/pci/vpci_relay/src/lib.rs#L405-L410)
  says the unbind's purpose is to leave the device "Unlocked with
  cached report so that VPCI_QUERY_ISOLATED_RESOURCES can still
  answer with real MMIO/DMA isolation classification." If the
  unbind fails, neither half of that postcondition is established
  by the host. Safe options for the Err arm: eject the device,
  force a hard reset (non-preserving unbind), or cross-check with
  firmware via `tdisp_query_firmware_tdi_state`.

- **`tdi_report` should be evicted on Err**. `tdisp_unbind_inner`
  ([tdisp.rs#L880-L894](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L880-L894))
  leaves `tdi_report` untouched on the Err arm. Per §11.3.10 the
  report is bound to the LOCK→START→UNLOCK envelope it was produced
  in; if the unbind RPC errored, the report's chain-of-custody
  guarantee is lost. Recommended fix: on the Err arm, evict
  `tdi_report` always (regardless of `clear_cached_report`) and
  reset the per-bind bookkeeping.

## Recommended fix (three-part)

1. **`send_tdisp_command`** at [vpci_client/src/tdisp.rs#L527-L548](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L527-L548):
   gate the `update_tdi_state(...)` call on `error_code == Success`.
2. **`tdisp_unbind_inner`** at [vpci_client/src/tdisp.rs#L880-L894](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L880-L894):
   on the Err arm, evict `tdi_report = None`, set
   `dma_unblocked = false`, clear `validated_mmio_bars`.
3. **`vpci_relay::relay_vpci_bus`** at
   [vpci_relay/src/lib.rs#L416-L420](../../../vm/devices/pci/vpci_relay/src/lib.rs#L416-L420):
   replace the `tracing::error!`-only Err arm with one of:
   - eject the device and skip the `add_dyn_device` insert;
   - issue a hard `tdisp_unbind(Graceful)` (non-preserving) and
     only relay if that succeeds;
   - cross-check with `vpci_device.tdisp_query_firmware_tdi_state()`
     and act on the firmware-reported state.

All three fixes should land together — fixing only one leaves the
chain-of-custody bypass reachable.
