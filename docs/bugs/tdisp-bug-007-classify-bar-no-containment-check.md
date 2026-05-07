# Bug TDISP-007 — `classify_bar` does not check `(base_address, length)` containment within reported range

**Severity:** Medium
**Obligation violated:** O-6 (CHECK-4, INV-6: page-level resource set
containment).
**Status:** Open. The check is only on `range_id` and the
`is_non_tee_mem` flag.

See [shared context](tdisp-bug-template-shared-context.md).

## Summary

`classify_bar` in
[vm/devices/pci/vpci_client/src/tdisp.rs](../../vm/devices/pci/vpci_client/src/tdisp.rs)
classifies a BAR as `PRIVATE` whenever the cached TDI report contains
*any* `mmio_interface_info` entry whose `range_id == bar_id` and
whose `is_non_tee_mem` flag is clear. It does **not** verify that the
configured `(base_address, length)` of the reconfigured BAR lies
within the report's claimed range. A host that supplies a valid
`range_id` but lies about the BAR base/length can pass the gate
even though the `(base_address, length)` the paravisor is about to
unblock is outside the range the device actually claims.

This is a paravisor-side instance of `CHECK-4` ("MMIO range
consistency: ∀ page offered by VMM: page.physical_addr ∈
report.mmio_ranges").

## Technical details

[`classify_bar`](../../vm/devices/pci/vpci_client/src/tdisp.rs):

```rust
fn classify_bar(&self, bar_id: u16) -> ResourceIsolation {
    if self.mutable_state.intercepted_bars.contains(&bar_id) {
        return ResourceIsolation::SHARED;
    }
    let Some(report) = self.mutable_state.tdi_report.as_ref() else {
        return ResourceIsolation::INVALID;
    };
    let Some(range) = report.mmio_interface_info
        .iter()
        .find(|r| r.range_id == bar_id)        // ← only checks range_id
    else {
        return ResourceIsolation::INVALID;
    };
    if range.flags.is_non_tee_mem() {
        ResourceIsolation::SHARED
    } else {
        ResourceIsolation::PRIVATE
    }
}
```

The caller `tdisp_on_mmio_reconfigured_inner` then unblocks the
configured `(base_address, length)` without re-checking against
`range.{base, length}`.

## Why this lands on the paravisor

The PSP separately validates the MMIO range when
`TIO_MSG_MMIO_VALIDATE_REQ` is sent (firmware-level check), but the
paravisor's local enforcement also has a duty to refuse to even
issue the call for a `(base_address, length)` it has no report
support for. That defence-in-depth at the paravisor layer is what
the obligation table calls O-6 / CHECK-4 / INV-6.

## Attack scenario

Pre-condition: the paravisor has cached a TDI report (legitimate or
attacker-chosen via TDISP-006). The report contains a legitimate
`mmio_interface_info` entry `{ range_id: 0, base: 0xF000_0000, length:
0x1000, is_non_tee_mem: false }` for BAR 0.

1. The host's VPCI BAR-mapping path proposes a *different*
   `(base_address, length)` for BAR 0 — for example
   `(base_address = 0xDEAD_0000, length = 0x10_0000)` — that has not
   been reported.
2. Guest enables BAR 0; paravisor invokes
   `tdisp_on_mmio_reconfigured(bar_id=0, base_address=0xDEAD_0000,
   length=0x10_0000)`.
3. `classify_bar(0)` returns `PRIVATE` because the report has an
   entry with `range_id == 0` and `is_non_tee_mem == false`.
4. Paravisor calls
   `validator.tdisp_unblock_mmio(target_vtl, device_id, 0xDEAD_0000,
   0, 0x10_0000, /*range_id=*/ 0)`.
5. The PSP firmware (under
   `TIO_MSG_MMIO_VALIDATE_REQ` / `Axiom SEV_PSP_CORRECT`) is the
   only remaining defence. If the PSP rejects, the unblock fails
   safely. If the PSP accepts (e.g. because it indexes only by
   `range_id` and `device_id` and trusts the caller's
   `(base, length)`), the paravisor commits a fabricated mapping.

## Impact

- **CHECK-4 / INV-6:** unenforced at the paravisor layer.
- **Worst case (PSP also lax):** a confused-deputy mapping of TEE
  memory at an attacker-chosen GPA range.
- **Best case (PSP rejects):** the bug surfaces as a denial-of-service
  on legitimate BAR enables, but no security breach. Either way the
  paravisor's local gate should refuse first.

## Suggested remediation

Either tighten `classify_bar` itself or push the containment check
into `tdisp_on_mmio_reconfigured_inner` after the `PRIVATE`
classification:

```rust
let range = report.mmio_interface_info.iter()
    .find(|r| r.range_id == bar_id)
    .ok_or(...)?;

// CHECK-4: configured (base, length) MUST lie within the reported range.
let cfg_end = base_address.checked_add(length as u64)
    .ok_or_else(|| crate::err!("bar end overflows"))?;
let report_end = range.base.checked_add(range.length as u64)
    .ok_or_else(|| crate::err!("report range end overflows"))?;
if base_address < range.base || cfg_end > report_end {
    return Err(crate::err!(
        "BAR {bar_id} configured ({base_address:#x}, {length:#x}) lies outside \
         reported range ({:#x}, {:#x})", range.base, range.length
    ));
}
```

Then call `tdisp_unblock_mmio` with the verified `(base_address,
length)`. Equivalent ranges over multiple report entries (if the
device fragments a BAR into sub-ranges) need a small generalization
of the containment loop — left as part of the implementation.

Add a Kani harness `verify_unblock_within_reported_range`:

- precondition: a single report-range with symbolic `(report_base,
  report_length)`; symbolic `(cfg_base, cfg_length)`;
- assertion: `tdisp_on_mmio_reconfigured(Ok)` ⇒ `cfg_base ≥
  report_base ∧ cfg_base + cfg_length ≤ report_base + report_length`.

## Acceptance criteria

- The new `verify_unblock_within_reported_range` Kani harness
  verifies.
- A unit test with a `(base, length)` that does not match the
  reported range causes `tdisp_on_mmio_reconfigured` to return `Err`
  without calling `tdisp_unblock_mmio`.
