# Bug TDISP-006 — `tdisp_get_device_report` accepts a host-supplied report without precondition

**Severity:** High
**Obligation violated:** O-12 (ORD-2: `LOCK_RESPONSE < GET_REPORT`),
contributes to O-14.
**Status:** Open. Documented as **AF-3** in
[tdisp-kani-verification-findings.md](../tdisp-kani-verification-findings.md);
specified by failing Kani harness `verify_get_device_report_post_check`.

See [shared context](tdisp-bug-template-shared-context.md).

## Summary

`tdisp_get_device_report_inner` issues `GetTdiReport` to the host and
returns the `report_buffer` whenever the typed payload deserializes,
without checking the cached `tdi_state` precondition. The reference
requires `GET_DEVICE_INTERFACE_REPORT` to be issued only when the
device is in `LOCKED_UNVERIFIED` (`ORD-2`, §6.2 precondition). In
paravisor terms: cached `tdi_state ∈ {Locked, Run}`. The current
implementation accepts a "device report" for a device the paravisor
has not bound. Combined with the absence of V1 (TDISP-001), the
report can be entirely attacker-chosen, and it is then cached as
`self.mutable_state.tdi_report` for use by `classify_bar()` and
`isolation_snapshot()`.

## Technical details

[`tdisp_get_device_report_inner`](../../vm/devices/pci/vpci_client/src/tdisp.rs):

```rust
async fn tdisp_get_device_report_inner(
    &mut self,
    report_type: &TdispReportType,
) -> crate::Result<Vec<u8>> {
    let res = self.send_tdisp_command(
        openhcl_tdisp::new_get_tdi_report_command(self.vpci_device_id, *report_type),
    ).await?;

    match res.response::<TdispCommandResponseGetTdiReport>() {
        Ok(r) => Ok(r.report_buffer),
        Err(err) => Err(crate::err!("error response in tdisp_get_device_report: {err}")),
    }
}
```

No precondition on `self.tdi_state()`. No verification of the
returned buffer.

## Why this lands on the paravisor

`ORD-2` is a paravisor obligation: it is the only entity that
issues `GET_DEVICE_INTERFACE_REPORT` and therefore the only one that
can refuse to issue it before `LOCK` has succeeded. The PSP does not
mediate this command.

## Attack scenario

Pre-condition: cached `tdi_state ∉ {Locked, Run}` — e.g.
`Uninitialized` (post-boot), `ConfigUnlocked`, `Unlocked` (post-
`tdisp_unbind`), or `Error`. This is the natural state at boot and
after any teardown.

1. Guest (or a paravisor-internal recovery path) calls
   `tdisp_get_tdi_report` (which calls
   `tdisp_get_device_report(InterfaceReport)`).
2. Paravisor sends `GetTdiReport` to the host.
3. **Malicious host** returns:
   ```text
   GuestToHostResponse {
       result: Success,
       tdi_state_after: Run as i32,       // optional cache poisoning
       response: Some(GetTdiReport(TdispCommandResponseGetTdiReport {
           report_type: InterfaceReport as i32,
           report_buffer: <attacker-chosen well-formed bytes>,
       })),
   }
   ```
4. `send_tdisp_command` calls `update_tdi_state(Run)` (cache
   poisoned). Returns `Ok(res)`.
5. `tdisp_get_device_report_inner` extracts `r.report_buffer` and
   returns `Ok(<attacker-chosen>)`.
6. The caller (`tdisp_get_tdi_report`) calls
   `tdisp::devicereport::deserialize_tdi_report(&buffer)`. Attacker
   chooses the bytes to deserialize cleanly.
7. In `tdisp_attest_device`, the result is stored as
   `self.mutable_state.tdi_report = Some(<attacker-chosen>)`.

The cached report is now an attacker-chosen `TdiReportStruct`. Per
TDISP-001 the paravisor never V1-checks it. Subsequent calls into
`classify_bar()` and `isolation_snapshot()` produce attacker-chosen
classifications.

## Impact

- **`ORD-2` / `O-12`:** directly violated.
- **Combined with TDISP-001:** the fabricated report is consumed as
  authoritative.
- **Combined with TDISP-005:** the cached report can outlive a
  subsequent unbind via `tdisp_unbind_preserve_report` *or* via the
  AF-2 cache-staying-`Run` path, indefinitely persisting the attack.
- **`O-14` (API contract):** `isolation_snapshot()` returns `Ready`
  with attacker-chosen bars/dma classifications.

## Suggested remediation

Gate the call at the top of `tdisp_get_device_report_inner` on the
cached state, *without contacting the host*:

```rust
async fn tdisp_get_device_report_inner(
    &mut self,
    report_type: &TdispReportType,
) -> crate::Result<Vec<u8>> {
    match self.tdi_state() {
        TdispTdiState::Locked | TdispTdiState::Run => {}
        other => return Err(crate::err!(
            "tdisp_get_device_report refused: device is in state {other:?}, \
             expected Locked or Run"
        )),
    }
    // … existing body …
}
```

Note that this fix is necessary but not sufficient: it prevents AF-3
on its own, but the cached `tdi_state` is itself adversary-influenced
under TDISP-004 / TDISP-005. This bug should be fixed together with
those, and ultimately backed by V1 (TDISP-001) so that the
"cached state is `Locked` or `Run`" precondition has independent
meaning.

Independently, V1 (TDISP-001) should be applied to every report
return-buffer before it is cached or returned to a higher layer.
This bug fixes the *protocol-ordering* gate; TDISP-001 fixes the
*content-trust* gate.

## Acceptance criteria

- `verify_get_device_report_post_check` verifies under `cargo kani`.
- A unit test with cached `tdi_state == Uninitialized` and any
  host response causes `tdisp_get_device_report` to return `Err`
  without contacting the host.
- A unit test with cached `tdi_state == Locked` and a malformed
  host response returns `Err` (existing behavior, regression check).
