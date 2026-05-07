# Bug TDISP-005 — `tdisp_unbind` returns `Ok` without checking `tdi_state_after`

**Severity:** High
**Obligation violated:** O-11 (per-method state-after enforcement),
contributes to O-14 (`isolation_snapshot` API contract).
**Status:** Open. Documented as **AF-2** in
[tdisp-kani-verification-findings.md](../tdisp-kani-verification-findings.md);
specified by failing Kani harness `verify_unbind_post_check`.

See [shared context](tdisp-bug-template-shared-context.md).

## Summary

`tdisp_bind_interface` and `tdisp_start_device_inner` both perform a
post-state match against the cached `tdi_state` after the host
responds. `tdisp_unbind_inner` does not. A malicious host can return
`Success` plus an `Unbind` payload while claiming `tdi_state_after =
Run` (or any other non-`Unlocked` state); the paravisor returns `Ok`,
caches `Run`, and reports `Run` to its own callers via
`tdisp_get_tdi_state()`. The `tdisp_unbind_preserve_report` variant
additionally leaves the cached `tdi_report`, so a subsequent
`isolation_snapshot()` returns a `Ready` classification for an
unbound device.

## Technical details

[`tdisp_unbind_inner`](../../vm/devices/pci/vpci_client/src/tdisp.rs)
runs the re-block loop, sends `Unbind`, then matches only on the
typed payload — never on the wire-level `tdi_state_after`:

```rust
let res = self.send_tdisp_command(openhcl_tdisp::new_unbind_command(...)).await?;
match res.response::<TdispCommandResponseUnbind>() {
    Ok(_) => {
        self.mutable_state.validated_mmio_bars.clear();
        self.mutable_state.dma_unblocked = false;
        if clear_cached_report { self.mutable_state.tdi_report = None; }
        Ok(())
    }
    Err(err) => Err(crate::err!("error response in tdisp_unbind: {err}")),
}
```

`send_tdisp_command` separately did `update_tdi_state(Run)` if the
host claimed it, leaving the cache at `Run` even though the typed
payload is `Unbind`.

The bookkeeping clears (`validated_mmio_bars`, `dma_unblocked`,
optionally `tdi_report`) are correct, and Kani harness 7
(`verify_unbind_reblocks_previously_unblocked_resources`) proves the
re-block step happens for every previously-unblocked BAR before the
host is contacted. The bug is purely the missing post-check on
`tdi_state_after`.

## Why this lands on the paravisor

Same as TDISP-004: only the paravisor sees the wire response, and
the per-method post-check is the only protocol-level check the
paravisor performs after `send_tdisp_command`'s state-update step.

## Attack scenario

1. Guest issues `tdisp_unbind(Graceful)`.
2. Paravisor's `tdisp_unbind_inner` runs the re-block loop (correct,
   verified by harness 7).
3. Paravisor sends `Unbind` to the host.
4. **Malicious host** returns:
   ```text
   GuestToHostResponse {
       result: Success,
       tdi_state_after: Run as i32,        // or Locked, or anything not-Unlocked
       response: Some(Unbind(TdispCommandResponseUnbind {})),
   }
   ```
5. `send_tdisp_command` calls `update_tdi_state(Run)` → cache is now
   `Run`. The typed payload is `Unbind`.
6. `tdisp_unbind_inner` matches `Ok(_)` → clears `validated_mmio_bars`
   and `dma_unblocked`, optionally clears `tdi_report` — and **returns
   `Ok(())` while the cached `tdi_state` is `Run`**.

After this:
- `tdisp_get_tdi_state()` returns `Run`.
- If the unbind was `tdisp_unbind_preserve_report`, `tdi_report` is
  still `Some(...)`, so `isolation_snapshot()` returns
  `IsolationSnapshot::Ready { bars, dma }` derived from the stale
  report — i.e. it tells the guest the device is in a Ready
  TEE-isolation state while the device is in fact `Unlocked`.

## Impact

- **`O-11`:** unenforced for unbind.
- **`O-14` (API contract):** directly violated. `tdisp_get_tdi_state()`
  reports `Run` against an unbound device.
  `VPCI_QUERY_ISOLATED_RESOURCES` returns `Ready { bars, dma }` against
  an unbound device when combined with `tdisp_unbind_preserve_report`.
- **Composes with TDISP-004 / TDISP-006:** the surviving cached `Run`
  becomes the precondition that TDISP-004 then exploits to bypass
  the start-device post-check on a subsequent re-attestation.

## Suggested remediation

Add a wire-level post-check at the end of `tdisp_unbind_inner` (or
inside the `Ok(_)` arm before clearing bookkeeping), mirroring
`tdisp_start_device_inner`'s pattern:

```rust
let claimed = res.tdi_state_after_enum()
    .ok_or_else(|| crate::err!(
        "host returned undecodable tdi_state_after for Unbind"
    ))?;
if claimed != TdispTdiState::Unlocked {
    return Err(crate::err!(
        "host claimed wrong state for Unbind: {claimed:?}, expected Unlocked"
    ));
}
```

If the typed `Err(_)` arm is taken or the post-check fails, the
bookkeeping clears must still happen (the paravisor must not leave
its own caches in an unsafe state just because the host responded
adversarially). Move the `validated_mmio_bars.clear()`,
`dma_unblocked = false`, and conditional `tdi_report = None` lines
above the success/failure decision.

## Acceptance criteria

- `verify_unbind_post_check` verifies under `cargo kani`.
- A unit test with a mock host returning `Success` + `Run` causes
  `tdisp_unbind` to return `Err` *and* the paravisor's bookkeeping
  is cleared (validated_mmio_bars / dma_unblocked).
- After the fix, `tdisp_get_tdi_state()` never reports `Run` after
  a `tdisp_unbind` call returns regardless of host behaviour.
