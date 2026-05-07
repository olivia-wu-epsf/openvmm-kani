# Bug TDISP-004 — `tdisp_start_device` accepts undecodable host `tdi_state_after`

**Severity:** High
**Obligation violated:** O-11 (per-method state-after enforcement)
**Status:** Open. Documented as **AF-1** in
[tdisp-kani-verification-findings.md](../tdisp-kani-verification-findings.md);
specified by failing Kani harness `verify_start_device_post_check`.

See [shared context](tdisp-bug-template-shared-context.md).

## Summary

`tdisp_start_device_inner` reads `self.tdi_state()` (the cached
state) to decide whether the StartTdi succeeded, instead of reading
the wire-level `tdi_state_after` field directly. When the host
returns `Success` with an undecodable `tdi_state_after` byte,
`send_tdisp_command` skips its `update_tdi_state` call (logging a
warning), the cache stays at whatever it was before, and the
post-check observes the prior cached state. If the prior cached state
was already `Run` (e.g. from a successful earlier attestation, or
from a prior cache poisoning under
[TDISP-005](tdisp-bug-005-unbind-no-state-after-check.md) /
[TDISP-006](tdisp-bug-006-get-report-no-precondition.md)), the
post-check accepts.

## Technical details

[`tdisp_start_device_inner`](../../vm/devices/pci/vpci_client/src/tdisp.rs)
matches on `self.tdi_state()`, not on `res.tdi_state_after_enum()`:

```rust
let res = self.send_tdisp_command(openhcl_tdisp::new_start_tdi_command(...)).await?;

match self.tdi_state() {        // ← reads cached, not wire field
    TdispTdiState::Run => …,
    state_after => return Err(...),
}
```

`send_tdisp_command` updates the cache only when
`res.tdi_state_after_enum()` decodes:

```rust
match res.tdi_state_after_enum() {
    Some(state) => self.mutable_state.update_tdi_state(state),
    None => tracing::warn!("host did not return valid TDI state in response"),
}
```

The Kani counter-example produced by `verify_start_device_post_check`
fixes `state_before == Run` and varies `tdi_state_after` over all
byte values. For the undecodable-byte cases the post-check passes
without the host ever having to claim `Run`.

## Why this lands on the paravisor

The paravisor is the only entity that sees the wire-level response.
The host is adversarial; the device cannot speak directly to the
paravisor. The post-check is the only paravisor-side enforcement
that the host's per-method response is consistent with the operation
that was requested.

## Attack scenario

Pre-condition: cached `tdi_state == Run` for the device. This is
reachable via a legitimate prior successful attestation, or
fabricated via TDISP-005 / TDISP-006 cache poisoning.

1. Guest re-issues `StartTdi` (e.g. an idempotent recovery path).
2. Paravisor sends `StartTdi` over the host channel.
3. **Malicious host** returns:
   ```text
   GuestToHostResponse {
       result: Success,
       tdi_state_after: <undecodable byte, e.g. 0xFF>,
       response: Some(StartTdi(TdispCommandResponseStartTdi {})),
   }
   ```
4. `send_tdisp_command` calls `res.tdi_state_after_enum()` → `None`,
   logs a warning, leaves the cache at the prior `Run`.
5. `tdisp_start_device_inner` matches `self.tdi_state()` →
   `TdispTdiState::Run` ✓. Returns `Ok(())`.

The paravisor returns `Ok` for a `StartTdi` for which the host never
explicitly acknowledged the requested transition. Combined with
TDISP-001 / TDISP-002 / TDISP-003, the entire chain `Bind → StartTdi
→ GetTdiReport` of `tdisp_attest_device` can succeed without the
host ever having to commit to a per-call state claim.

## Impact

- **`SAFE-2`:** the temporal "report verified before START" guarantee
  cannot be reconstructed by any consumer that gates on `tdisp_start_device(Ok)`.
- **`O-11`:** unenforced.
- **`O-14`:** the paravisor's own `tdisp_get_tdi_state()` continues
  to report `Run` on the back of an unverified per-call response.

## Suggested remediation

Inside `tdisp_start_device_inner`, branch on
`res.tdi_state_after_enum()` directly and reject undecodable values:

```rust
let claimed = res.tdi_state_after_enum()
    .ok_or_else(|| crate::err!(
        "host returned undecodable tdi_state_after for StartTdi"
    ))?;
if claimed != TdispTdiState::Run {
    return Err(crate::err!(
        "host claimed wrong state for StartTdi: {claimed:?}, expected Run"
    ));
}
```

This makes `verify_start_device_post_check` (already in tree) verify
under Kani.

## Acceptance criteria

- `verify_start_device_post_check` verifies under `cargo kani`.
- A unit test with a mock host returning `Success` + an undecodable
  `tdi_state_after` causes `tdisp_start_device` to return `Err`.
- A unit test with a mock host returning `Success` + `Locked`
  causes `tdisp_start_device` to return `Err`.
