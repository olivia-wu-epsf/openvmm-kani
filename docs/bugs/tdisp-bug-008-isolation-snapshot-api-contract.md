# Bug TDISP-008 — `isolation_snapshot()` API contract: `Ready` returned for unbound device

**Severity:** High
**Obligation violated:** O-14 (paravisor's guest-facing API contract).
**Status:** Open. Two paths produce the violation:
1. **By design** via `tdisp_unbind_preserve_report`.
2. **As a downstream effect** of TDISP-005 (AF-2) and TDISP-006 (AF-3)
   plus TDISP-001 (no V1).

See [shared context](tdisp-bug-template-shared-context.md).

## Summary

The paravisor's
[`isolation_snapshot()`](../../vm/devices/pci/vpci_client/src/tdisp.rs)
returns `IsolationSnapshot::Ready { bars, dma }` whenever
`self.mutable_state.tdi_report.is_some()`, deriving the BAR/DMA
classifications from the cached report and the cached `dma_unblocked`
flag. There is no freshness check, no PSP cross-check, and no
verification that the cached state was honestly produced. The
function is reached by the guest over VMBus via
`VPCI_QUERY_ISOLATED_RESOURCES` and is the guest's only authoritative
view of TDISP isolation state.

## Technical details

[`isolation_snapshot()`](../../vm/devices/pci/vpci_client/src/tdisp.rs):

```rust
pub fn isolation_snapshot(&self) -> IsolationSnapshot {
    if self.mutable_state.tdi_report.is_none() {
        return IsolationSnapshot::NotReady;
    }
    let mut bars = [ResourceIsolation::INVALID; 6];
    for bar_id in 0..6u16 {
        bars[bar_id as usize] = self.classify_bar(bar_id);
    }
    let dma = if self.mutable_state.dma_unblocked {
        ResourceIsolation::PRIVATE
    } else {
        ResourceIsolation::SHARED
    };
    IsolationSnapshot::Ready { bars, dma }
}
```

The function never consults `self.mutable_state.tdi_state`, never
calls `tdisp_query_firmware_tdi_state`, and never invalidates the
result based on time, sessions, or events.

The dispatch path is:

```
guest TD
   │  VMBus
   ▼
protocol::MessageType::VPCI_QUERY_ISOLATED_RESOURCES   (vm/devices/pci/vpci/src/device.rs:512)
   │
   ▼
TdispVpciAttestationInterface::tdisp_isolation_snapshot
   │
   ▼
VpciClientTdispState::isolation_snapshot()
```

## Why this lands on the paravisor

The guest has no other source of truth for the device's TDISP
isolation. There is no separate guest API to query the PSP for the
device's state, no out-of-band cert chain the guest can validate.
The paravisor's reply is authoritative or it is nothing. When the
paravisor's reply does not correspond to the device's real state,
the contract is broken.

## Three observable desync scenarios

### Scenario A — by-design (`tdisp_unbind_preserve_report`)

`tdisp_unbind_preserve_report(reason)` deliberately does not clear
`tdi_report`. After it returns, the device is in `Unlocked` (assuming
TDISP-005 fixed) or whatever the host claims (today). Subsequent
`isolation_snapshot()` returns `Ready { bars, dma }` derived from the
preserved report.

This is documented in the function's doc-comment as enabling
"isolation_snapshot to continue to classify BAR/DMA isolation while
the TDI sits in the Unlocked state awaiting a guest-initiated
re-attestation". The guest is told `Ready` for an `Unlocked` device.

### Scenario B — TDISP-005-induced

After a normal `tdisp_unbind` against a malicious host (TDISP-005),
cached `tdi_state` may stay `Run` while `tdi_report` is cleared on
the `Ok` path. `isolation_snapshot()` returns `NotReady` in this
specific case (because `tdi_report` is `None`), but
`tdisp_get_tdi_state()` returns `Run` — same class of API-contract
violation, different surface.

### Scenario C — TDISP-006-induced (cache poisoning)

A malicious host walks the paravisor through `tdisp_attest_device`
without ever putting the device into TDISP. The fabricated report
lands in `tdi_report`. `isolation_snapshot()` returns `Ready` with
attacker-chosen BAR classifications and attacker-chosen DMA state.

## Attack scenario (composed)

The guest driver issues `VPCI_QUERY_ISOLATED_RESOURCES` after device
enumeration to decide which BARs to treat as TEE memory:

1. Paravisor → guest:
   `VpciIsolatedResourcesReply { Ready { bars: [PRIVATE, ...], dma: PRIVATE } }`.
2. Guest assumes BAR 0 is TEE memory, configures higher-trust IOMMU
   policy / device driver behaviour accordingly.
3. Real device state: `Unlocked` (Scenario A or C). The "TEE memory"
   the guest is treating as private is actually un-attested.

Whether this is exploitable end-to-end depends on what the guest
does with the classification, but the paravisor is supplying false
isolation information.

## Impact

- **`O-14`:** directly violated.
- **Architectural:** the only authoritative isolation-state surface
  the guest sees is unreliable.

## Suggested remediation

Two complementary changes, the first being load-bearing:

1. **Tighten the function to refuse `Ready` against an unsafe cached
   `tdi_state`:**

   ```rust
   pub fn isolation_snapshot(&self) -> IsolationSnapshot {
       if self.mutable_state.tdi_report.is_none() {
           return IsolationSnapshot::NotReady;
       }
       // O-14: do not claim Ready unless the cached state shows the
       // device is currently TDISP-active.
       match self.tdi_state() {
           TdispTdiState::Locked | TdispTdiState::Run => {}
           _ => return IsolationSnapshot::NotReady,
       }
       // … existing classification …
   }
   ```

   This makes the by-design Scenario A return `NotReady` for an
   `Unlocked` device. Callers that needed the previous behaviour
   (`tdisp_unbind_preserve_report` consumers) must instead query the
   stale report explicitly via a separate API documented as advisory.

2. **Optional: query the PSP for ground truth** on platforms that
   support it. `tdisp_query_firmware_tdi_state` already exists and is
   plumbed through `TdispResourceValidationInterface` for SEV. Where
   `Some(state)` is returned, gate `Ready` on the firmware state
   matching the cached `tdi_state`. Disagreement should return
   `IsolationSnapshot::Error` (or a new `Stale` variant) and emit a
   ratelimited warning. This makes the API contract robust against
   any combination of TDISP-004 / TDISP-005 / TDISP-006 cache
   poisoning even before those individual bugs are fixed.

3. **Drop or rewrite `tdisp_unbind_preserve_report`.** Its single
   purpose is to keep `isolation_snapshot()` returning `Ready` after
   a logical unbind. Once the API contract is tightened, that
   purpose evaporates. If consumers still need to inspect the
   *last-known* report, expose an explicit
   `last_seen_report() -> Option<&TdiReportStruct>` accessor with
   a doc-comment that says "advisory, may not match the device".

## Acceptance criteria

- `isolation_snapshot()` returns `NotReady` whenever cached
  `tdi_state ∉ {Locked, Run}`, regardless of whether `tdi_report` is
  cached.
- A new Kani harness `verify_isolation_snapshot_only_ready_in_attested_state`:
  - precondition: symbolic cached `tdi_state`, symbolic
    `tdi_report.is_some()`, symbolic `dma_unblocked`;
  - assertion: `Ready` is returned ⇒ `tdi_state ∈ {Locked, Run}` ∧
    `tdi_report.is_some()`.
- A unit test where `tdisp_unbind` (post-TDISP-005 fix) is followed
  by a `VPCI_QUERY_ISOLATED_RESOURCES` returns `NotReady`, regardless
  of whether the unbind variant preserved the report.
