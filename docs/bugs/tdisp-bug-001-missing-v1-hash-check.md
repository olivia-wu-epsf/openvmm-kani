# Bug TDISP-001 — Paravisor never performs CHECK-1 (`device_info` hash verification)

**Severity:** Critical
**Obligation violated:** O-1 (CHECK-1, §6.3 V1, INV-7)
**Status:** Open. No production code performs the check.

See [shared context](tdisp-bug-template-shared-context.md) for threat
model, role mapping, and entry points.

## Summary

The paravisor never compares the `device_info_hash` carried in the
TDI interface report against the ground-truth hash that the SEV PSP
stores for the bound TDI. This is the foundational TDISP integrity
check (`CHECK-1` / `V1` in
[docs/tdisp-formal-verification-reference.md](../tdisp-formal-verification-reference.md)).
Its absence means a malicious host can deliver an arbitrary,
attacker-chosen TDI report payload to the paravisor and the paravisor
will treat it as authoritative.

## Technical details

`tdisp_attest_device` in
[vm/devices/pci/vpci_client/src/tdisp.rs](../../vm/devices/pci/vpci_client/src/tdisp.rs)
fetches the report via `tdisp_get_tdi_report` and stores it directly
in `self.mutable_state.tdi_report` without any verification step:

```rust
let tdi_report = self.tdisp_get_tdi_report().await
    .context("…")?;
…
self.mutable_state.tdi_report = Some(tdi_report);
```

There is no call into `sev_guest::*` to fetch
`stored_device_info_hash` for the device, no hash computation over
the report contents, and no comparison.

The paravisor *does* expose a single PSP-state query via
`tdisp_query_firmware_tdi_state`, but that returns only the device's
`TdispTdiState` (an enum), not the device-info hash. No production
code path queries the PSP for the stored hash.

## Why this lands on the paravisor (not on the PSP, not on the guest)

- The PSP holds `stored_device_info_hash` but does not see the
  host-relayed TDI report. The PSP cannot perform the comparison on
  its own.
- The VTL0 guest receives only the classified
  `VpciIsolatedResourcesReply` from `VPCI_QUERY_ISOLATED_RESOURCES`;
  it has no SPDM session for this TDI and never sees the raw report.
  The guest cannot perform the comparison.
- The paravisor is the only entity that holds both the report (from
  the host TSM via SPDM) and the channel to the PSP. The paravisor is
  the obligated enforcer.

## Attack scenario

1. Guest driver triggers `tdisp_attest_device` for a TDISP-capable
   PCI device.
2. Paravisor sends `Bind`, `StartTdi`, `GetTdiDeviceId`, `GetTdiReport`
   over the host channel.
3. **Malicious host** returns `Success` for each command and supplies
   a fully attacker-chosen `TdispCommandResponseGetTdiReport` payload:
   crafted `device_info_hash`, crafted `mmio_interface_info` (with
   attacker-chosen `range_id`, `is_non_tee_mem` flags per BAR),
   crafted measurements.
4. Paravisor caches the report. `self.mutable_state.tdi_report =
   Some(<attacker-chosen>)`.
5. Subsequent paravisor decisions consult the cached report:
   - `classify_bar()` returns `PRIVATE` / `SHARED` based on
     attacker-chosen flags;
   - `tdisp_on_mmio_reconfigured_inner` opens the unblock gate using
     the attacker-chosen classification;
   - `isolation_snapshot()` reports attacker-chosen BAR/DMA states to
     the guest over `VPCI_QUERY_ISOLATED_RESOURCES`.

The attack is bounded only by `Axiom SEV_PSP_CORRECT`: the PSP's
own validation of `TIO_MSG_MMIO_VALIDATE_REQ` may reject the unblock
if the device is not actually bound. That backstop is load-bearing
*because* O-1 is missing; it is not a substitute for O-1.

## Impact

- **Integrity (`GOAL_INTEGRITY`):** direct breach at the paravisor's
  guest-facing API surface. `VPCI_QUERY_ISOLATED_RESOURCES` returns
  attacker-chosen classifications.
- **Confidentiality (`GOAL_CONFIDENTIALITY`):** not directly leaked
  by the immediate paravisor action (`tdisp_unblock_mmio` flips
  pages PRIVATE, not SHARED), but the paravisor's gate to that
  action is satisfied on adversary input alone — defence is then
  entirely on the PSP firmware.
- **State-machine faithfulness (§3.2):** the paravisor's local mirror
  diverges arbitrarily from the real device state.

## Suggested remediation

1. Add a paravisor-side V1 check in `tdisp_attest_device`, after
   `tdisp_get_tdi_report` and before caching the report or returning
   `Ok`:
   ```rust
   let stored_hash = self.resource_validator
       .as_ref()
       .ok_or_else(|| anyhow::anyhow!("no resource validator; cannot perform V1"))?
       .tdisp_query_firmware_device_info_hash(self.mutable_state.guest_device_id)?;
   let report_hash = compute_device_info_hash(&tdi_report)?;
   if !ct_eq(&stored_hash, &report_hash) {
       anyhow::bail!("V1 failed: device_info hash mismatch");
   }
   ```
2. Extend `TdispResourceValidationInterface` (in
   [openhcl/openhcl_tdisp/src/lib.rs](../../openhcl/openhcl_tdisp/src/lib.rs))
   with a new method `tdisp_query_firmware_device_info_hash(device_id)`
   that calls into `sev_guest` to retrieve the PSP-stored hash.
3. Add a Kani harness `verify_attest_device_calls_v1`:
   - precondition: cached state is fresh; symbolic host response;
     symbolic stored-hash mock recording one call;
   - assertion: a successful return implies (a) `tdisp_query_firmware_device_info_hash`
     was called with `self.mutable_state.guest_device_id` and (b) the
     returned hash equals the report's `device_info_hash` field.
4. Document the V1 step in `tdisp_attest_device`'s doc-comment
   referencing CHECK-1 / V1 / O-1.

## Acceptance criteria

- The new `verify_attest_device_calls_v1` harness verifies under
  Kani.
- Manual: a unit test with a mock `sev_guest` that returns a
  mismatched hash causes `tdisp_attest_device` to return `Err`.
