# Bug TDISP-003 — No lock-epoch nonce tracking (CHECK-6 / SAFE-3)

**Severity:** High
**Obligation violated:** O-4 (CHECK-6, SAFE-3, §3.5)
**Status:** Open. No nonce field exists in `VpciClientTdispMutableState`.

See [shared context](tdisp-bug-template-shared-context.md).

## Summary

The TDISP protocol uses a per-lock nonce returned in
`LOCK_INTERFACE_RESPONSE` to bind a subsequent
`START_INTERFACE_REQUEST` to that specific lock epoch. The reference
encodes this as `CHECK-6` (nonce freshness), `SAFE-3` (single-use),
and the lock-epoch sub-machine in §3.5. The paravisor does not
implement nonce tracking: there is no nonce field in
`VpciClientTdispMutableState`, the production
`new_start_tdi_command(vpci_device_id)` builder takes no nonce
argument, and `tdisp_start_device_inner` does not pass one.

## Technical details

The mutable TDISP state in
[vm/devices/pci/vpci_client/src/tdisp.rs](../../vm/devices/pci/vpci_client/src/tdisp.rs)
tracks `tdi_state`, `guest_device_id`, `validated_mmio_bars`,
`dma_unblocked`, `tdi_report`, `intercepted_bars`,
`cached_capabilities` — but **no `lock_nonce` / `lock_epoch` /
`lock_session_id` field**.

The bind path (`tdisp_bind_interface`) does not extract a nonce from
`TdispCommandResponseBind`. The start path
(`tdisp_start_device_inner`) builds the StartTdi command without a
nonce. The `openhcl_tdisp::new_start_tdi_command` constructor takes
only `vpci_device_id`.

## Why this lands on the paravisor

The SPDM session id authenticates that LOCK and START come from the
same authenticated party; it does **not** prevent replay across lock
epochs within the same session. The reference is explicit:

> `INV-8 (Nonce Freshness): ∀ tdi: nonce_used_in_START(tdi) was
> produced by the immediately preceding LOCK_INTERFACE_RESPONSE for
> that tdi (no replay across epochs)`

The device DSM is responsible for enforcing nonce single-use, **but
only on the nonce the paravisor actually sends**. If the paravisor
sends nothing (or always sends `0`), the DSM has no nonce to check.
The PSP does not synthesize the nonce on the paravisor's behalf.

## Attack scenario

A malicious host can mount a cross-epoch replay:

1. **Earlier in the VM lifetime**, the paravisor performs a legitimate
   attestation cycle: LOCK → REPORT → V1 → START. The DSM accepts the
   START and transitions the device to `Run`.
2. **Now** the device is unbound, reset, or simply put through a
   normal `tdisp_unbind_preserve_report` cycle. Cached `tdi_state`
   may go to `Unlocked`. The lock epoch is invalidated on the device.
3. The guest re-triggers attestation. Paravisor sends `LOCK`.
4. **Malicious host** does not actually relay `LOCK_INTERFACE_REQUEST`
   to the device. Instead it returns the **stored** `LOCK_INTERFACE_RESPONSE`
   from step 1 (Success, with the previous epoch's nonce, the previous
   epoch's `tdi_state_after = Locked`).
5. Paravisor caches `Locked`. Sends `START_INTERFACE_REQUEST`.
6. The device DSM sees no current `EPOCH_ACTIVE`. With nonce tracking
   on the paravisor side, the START would carry a nonce that no
   epoch on the device has issued, and the DSM rejects. **Without**
   nonce tracking, the START carries no nonce or a sentinel value,
   and the host can again fabricate the response (Success,
   `tdi_state_after = Run`). Paravisor caches `Run`.

The attack consumes no real device-side resource and produces a
paravisor that believes a `Run` device exists for an attestation
that never actually happened. Combined with TDISP-001 (V1 missing),
the entire chain runs without ever contacting the real device.

A weaker but still material variant: even with V1 present, an
adversary that can replay an old `LOCK_INTERFACE_RESPONSE` from a
prior bind cycle (where V1 *did* succeed once) can repeatedly
re-arm START against a now-stale device state, because the paravisor
has no way to distinguish "this is the nonce from the LOCK I just
issued" from "this is some nonce".

## Impact

- **`SAFE-3`:** directly violated. The paravisor cannot enforce
  single-use of the START nonce because it does not track the value.
- **`CHECK-6`:** unenforced.
- **`INV-8`:** unenforced.
- **Composes with TDISP-001 / TDISP-005:** without V1 and without
  nonce tracking, the paravisor has no per-call protocol-level
  evidence that the device it is talking to is in the state the host
  claims it is.

## Suggested remediation

1. Extend `VpciClientTdispMutableState` with:
   ```rust
   /// Nonce returned by the most recent LOCK_INTERFACE_RESPONSE.
   /// Cleared on STOP/Unbind and on any failed verification.
   lock_nonce: Option<u64>,
   /// SPDM session id observed during LOCK; START must use the same.
   lock_session_id: Option<u32>,
   ```
2. Populate `lock_nonce` from
   `TdispCommandResponseBind::start_interface_nonce` (add the field to
   the proto if not present) inside `tdisp_bind_interface`.
3. Modify `openhcl_tdisp::new_start_tdi_command` to take a nonce
   argument; thread the cached `lock_nonce` through
   `tdisp_start_device_inner`. Refuse to issue START if
   `lock_nonce.is_none()`.
4. Clear `lock_nonce` on:
   - successful START (consumed),
   - unbind / preserve-report-unbind / STOP,
   - any rejected/error response,
   - any per-method post-check failure once TDISP-005/006/007 land.
5. Add Kani harness `verify_start_uses_fresh_nonce`:
   - precondition: pre-populate `lock_nonce = Some(N)`; symbolic host;
   - assertion: every reachable call to the host's `StartTdi` carries
     the same `N`; on `Ok` return, cached `lock_nonce` becomes `None`.
6. Add Kani harness `verify_start_refuses_without_nonce`:
   - precondition: `lock_nonce = None`; symbolic state;
   - assertion: `tdisp_start_device` returns `Err` without sending
     any host command.

## Acceptance criteria

- `tdisp_start_device` returns `Err` if no current lock-epoch nonce
  is cached.
- The Kani harnesses above verify under `cargo kani`.
- A unit test confirms the nonce is cleared after START success and
  after any unbind / error path.
