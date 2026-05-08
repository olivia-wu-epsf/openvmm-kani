# TDISP-TVM-18 — `send_tdisp_command` advances cached `tdi_state` on a non-Success host response

**Status:** open
**Discovered by (low-level harness):** Kani harness
`verify_tvm18_err_response_does_not_advance_cache_on_bind` in
[vm/devices/pci/vpci_client/src/kani_proofs.rs](../vm/devices/pci/vpci_client/src/kani_proofs.rs)
(VERIFICATION FAILED in 10.2 s) — drives the internal
`VpciClientTdispState::tdisp_bind_interface` primitive directly.
**Reconfirmed at the public-API layer (high-level harness):** Kani
harness `verify_tvm18_deactivate_err_response_does_not_advance_cache_via_lib` in
[vm/devices/pci/vpci_client/src/kani_proofs_highlevel.rs](../vm/devices/pci/vpci_client/src/kani_proofs_highlevel.rs)
(VERIFICATION FAILED in 141.6 s, 9773 VCCs) — drives the public
`VpciDevice::tdisp_on_device_deactivate` entry point that the chipset
MMIO disable edge actually calls. The same root cause is observable
through the host-facing surface, so no orchestration-layer wrapper
masks the bug.
**Spec basis:** PCI-SIG TDISP v2022-07-27 §11.3.13 Table 17, §11.3.24,
§11.6.3.

## Property (TVM-18)

When a TDISP request is rejected by the device (`TDISP_ERROR` /
non-`Success` operation result), the TVM-side cached TDI state must
not be advanced beyond `state_before`. Per §11.3.13 + §11.3.24, an
error response signals the device did **not** transition to the
requested target state; per §11.6.3, the host VMM is on the wire and
may forge any `tdi_state_after` value it likes alongside an error
code — the TVM cannot use those bytes as authority for a state
update.

## Counter-examples

### Low-level harness (Bind branch)

The low-level harness drives `tdisp_bind_interface()` with
`state_before` symbolic over all four `TdispTdiState` variants and a
fully-symbolic `GuestToHostResponse`. CBMC produces:

- `state_before = Unlocked`.
- Malicious host returns
  `result = InvalidDeviceState` (non-Success error)
  + `tdi_state_after = Locked` (decodable).
- `send_tdisp_command` runs `update_tdi_state(Locked)` **before**
  inspecting `error_code()`, so the cache flips to `Locked`.
- `error_code()` then returns `Some(InvalidDeviceState)` and the
  function returns `Err(...)`.
- Post-state: `result.is_err()` ∧ `cached_after = Locked ≠ state_before`.

### Public-API harness (Unbind branch via `tdisp_on_device_deactivate`)

The high-level harness pre-caches `tdi_state = Run` plus a non-empty
`validated_mmio_bars` / `dma_unblocked = true` / cached `tdi_report`,
then calls `VpciDevice::tdisp_on_device_deactivate`. The mock host
returns a fully-symbolic `GuestToHostResponse` whose `response` oneof
is pinned to a matching `Unbind` payload but whose `result` and
`tdi_state_after` are symbolic. CBMC produces:

- Mock host returns `result = InvalidDeviceState` +
  `tdi_state_after = Unlocked` (or any other decodable state).
- `tdisp_on_device_deactivate` invokes `tdisp_unbind_preserve_report`,
  which routes through the same `send_tdisp_command` body.
- Cache flips to the host-claimed `tdi_state_after` **before** the
  error-code branch is taken, then the function returns `Err`
  internally. `tdisp_on_device_deactivate` discards the `Err` (its
  signature is `() -> ()`).
- Post-state: cached `tdi_state ≠ Run` (the entry state), even though
  the host explicitly signalled the unbind failed.

The assertion `host_result != Success ⇒ cached_after == Run` fails.
This confirms that the cache-poisoning primitive is reachable from
the public surface that the guest's MMIO disable edge actually
traverses, not just from the internal `tdisp_bind_interface` API.

## Code basis

[vm/devices/pci/vpci_client/src/tdisp.rs](../vm/devices/pci/vpci_client/src/tdisp.rs#L308-L334)

```rust
// Record state transitions based on the TDI state returned by the host
// in the response, if available.
match res.tdi_state_after_enum() {
    Some(state) => self.mutable_state.update_tdi_state(state),  // ← runs unconditionally
    None => tracing::warn!("host did not return valid TDI state in response"),
}

match res.error_code() {
    Some(TdispGuestOperationErrorCode::Success) => Ok(res),
    other => {
        ...
        Err(crate::err!(
            "send_tdisp_command {:?} failed because host responded with an error: {:?}",
            payload.type_name(), other
        ))
    }
}
```

The `update_tdi_state` write is unconditional on `error_code`. There
is no rollback after the Err branch is taken.

## Impact (concrete attack)

This finding is **load-bearing for any precondition-gate fix**
(TDISP-TVM-1, TDISP-TVM-2, TDISP-TVM-3). Without it, a malicious host
can use an explicitly-failed exchange to *poison* the cached state,
which then satisfies a future precondition gate falsely:

1. Initial: cached `Unlocked`. Attacker triggers a
   `tdisp_bind_interface` call (assume TDISP-TVM-1 has been fixed: the
   bind precondition passes because state is `Unlocked`).
2. Host returns `result = InvalidDeviceState` + `tdi_state_after = Locked`.
3. `send_tdisp_command` flips cache → `Locked` then returns `Err`.
   `tdisp_bind_interface` propagates the `Err` to its caller.
4. Cache is now `Locked` even though no successful LOCK happened
   on the device.
5. Attacker now triggers `tdisp_start_device`. With the TDISP-TVM-3
   fix in place, the precondition `state_before == Locked` passes
   (cache is dirty `Locked`).
6. Host returns `Success + tdi_state_after = Run` + matching
   `StartTdi` payload. Cache → `Run`. Function returns `Ok`.
7. Paravisor now believes the TDI is in `Run` and an authentic
   epoch is active. F-7 gate
   ([`tdisp_on_mmio_reconfigured_inner`](../vm/devices/pci/vpci_client/src/tdisp.rs#L944-L987))
   will unblock PRIVATE pages on the next BAR reconfigure;
   [`isolation_snapshot()`](../vm/devices/pci/vpci_client/src/tdisp.rs#L883-L901)
   returns `Ready`.

So the same attack class as TDISP-TVM-1 / TDISP-TVM-3 is reachable
even *with* their precondition gates added, unless TVM-18 is also
fixed. Severity: **load-bearing**.

## Recommended fix

Re-order `send_tdisp_command` so the cache update only happens on
`Success`:

```rust
// Validate the host's operation result FIRST.
match res.error_code() {
    Some(TdispGuestOperationErrorCode::Success) => {}
    other => {
        tracing::error!(error_code = ?other, ...);
        return Err(crate::err!(...));
    }
}

// Only on Success do we trust the host's claimed tdi_state_after
// far enough to advance the cache. (Authority for the state value
// itself still requires the §11.6.3 lock-epoch nonce binding —
// see TVM-8 — but at least an Err response cannot mutate the cache.)
match res.tdi_state_after_enum() {
    Some(state) => self.mutable_state.update_tdi_state(state),
    None => tracing::warn!("host did not return valid TDI state in response"),
}

Ok(res)
```

## Attribution

- Property derived top-down by the **TdispExpert** subagent (Claude
  Opus 4.7) from PCI-SIG TDISP v2022-07-27 §11.3.13 Table 17,
  §11.3.24, §11.6.3.
- Code-path confirmed by reading
  [vm/devices/pci/vpci_client/src/tdisp.rs](../vm/devices/pci/vpci_client/src/tdisp.rs#L308-L334).
- Composes with TDISP-TVM-1 / TDISP-TVM-2 / TDISP-TVM-3: any fix to
  those preconditions is bypassable until this is also fixed.
