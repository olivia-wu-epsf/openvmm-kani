# TDISP-TVM-2 — `tdisp_get_device_report` is missing the `state ∈ {Locked, Run}` precondition gate

**Status:** open
**Discovered by:** Kani harness `verify_tvm2_get_report_only_from_locked_or_run` in
[vm/devices/pci/vpci_client/src/kani_proofs.rs](../vm/devices/pci/vpci_client/src/kani_proofs.rs)
(VERIFICATION FAILED in 13.2 s).
**Spec basis:** PCI-SIG TDISP v2022-07-27 §11.3.1 Table 3, §11.3.10,
§11.3.11, §11.6.3.

## Property (TVM-2)

`GET_DEVICE_INTERFACE_REPORT` may be issued only when the TVM's
locally tracked TDI state is `CONFIG_LOCKED` or `RUN` (§11.3.1
Table 3). The device must reject the request from any other state
(§11.3.10). The report itself is meaningful only as the §11.6.3
LOCK→REPORT→START chain anchor — outside that chain, the response
buffer is arbitrary host-controlled bytes.

## Counter-example

The harness drives `tdisp_get_device_report(&InterfaceReport)` with
`state_before` symbolic over all four `TdispTdiState` variants and a
fully-symbolic `GuestToHostResponse`. CBMC produces:

- `state_before = Unlocked` (or `Uninitialized`).
- `tdisp_get_device_report` is called and emits GET_REPORT with
  **no** precondition check.
- Malicious host returns `Success` + `tdi_state_after = <anything>` +
  matching `GetTdiReport` payload.
- Function returns `Ok(buf)`. Caller (e.g.
  [`tdisp_get_tdi_report`](../vm/devices/pci/vpci_client/src/tdisp.rs#L468))
  proceeds to deserialize host-supplied bytes as a trusted device report
  for an unbound TDI.

## Code basis

[vm/devices/pci/vpci_client/src/tdisp.rs](../vm/devices/pci/vpci_client/src/tdisp.rs#L448-L466)

```rust
async fn tdisp_get_device_report_inner(
    &mut self,
    report_type: &TdispReportType,
) -> crate::Result<Vec<u8>> {
    let res = self
        .send_tdisp_command(openhcl_tdisp::new_get_tdi_report_command(
            self.vpci_device_id,
            *report_type,
        ))
        .await?;
    match res.response::<TdispCommandResponseGetTdiReport>() {
        Ok(r) => Ok(r.report_buffer),
        Err(err) => Err(crate::err!(
            "error response in tdisp_get_device_report: {err}"
        )),
    }
}
```

No `self.tdi_state()` inspection appears anywhere in the function body
or its forwarders.

## Impact (concrete attack)

Two distinct impacts:

1. **Trust laundering of host-controlled bytes.** The downstream
   [`tdisp_get_tdi_report`](../vm/devices/pci/vpci_client/src/tdisp.rs#L468)
   deserializes `report_buffer` as a `TdiReportStruct` and the
   resulting structure is used by
   [`tdisp_on_mmio_reconfigured_inner`](../vm/devices/pci/vpci_client/src/tdisp.rs#L944-L987)
   to classify BARs as PRIVATE (and unblock pages). Issuing the
   request from `Unlocked` lets a malicious host inject a report that
   was never tied to any `LOCK_INTERFACE_RESPONSE` — the §11.6.3
   chain-of-custody anchor is missing.
2. **Cache poisoning via `tdi_state_after`.** Because
   [`send_tdisp_command`](../vm/devices/pci/vpci_client/src/tdisp.rs#L262-L335)
   writes `mutable_state.tdi_state` from the host's
   `tdi_state_after_enum()` for every response that decodes, a
   malicious host can use a GET_REPORT exchange from cached `Unlocked`
   to flip the cache to `Run` (or any decodable state) without ever
   running LOCK or START. Composes with TDISP-TVM-1 / TDISP-TVM-3 to
   give the host a third Unlocked → Run path.

## Recommended fix

Insert at the top of `tdisp_get_device_report_inner`
([tdisp.rs#L448](../vm/devices/pci/vpci_client/src/tdisp.rs#L448)):

```rust
async fn tdisp_get_device_report_inner(
    &mut self,
    report_type: &TdispReportType,
) -> crate::Result<Vec<u8>> {
    match self.tdi_state() {
        TdispTdiState::Locked | TdispTdiState::Run => {}
        other => {
            return Err(crate::err!(
                "TVM-2: get-report requires cached state Locked|Run, got {:?}",
                other
            ));
        }
    }
    // ... rest of body ...
}
```

Independently, the §11.6.3 anchor requires the report be bound to the
current lock-epoch nonce (no implementation today; see TVM-8).

## Attribution

- Property derived top-down by the **TdispExpert** subagent (Claude
  Opus 4.7) from PCI-SIG TDISP v2022-07-27 §11.3.1 Table 3, §11.3.10,
  §11.3.11, §11.6.3.
- Code-path confirmed by reading
  [vm/devices/pci/vpci_client/src/tdisp.rs](../vm/devices/pci/vpci_client/src/tdisp.rs#L448-L466).
