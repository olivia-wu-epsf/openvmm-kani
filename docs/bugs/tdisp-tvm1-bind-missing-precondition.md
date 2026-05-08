# TDISP-TVM-1 — `tdisp_bind_interface` is missing the `state == Unlocked` precondition gate

**Status:** open
**Discovered by:** Kani harness `verify_tvm1_bind_only_from_unlocked` in
[vm/devices/pci/vpci_client/src/kani_proofs.rs](../vm/devices/pci/vpci_client/src/kani_proofs.rs)
(VERIFICATION FAILED in 3.4 s — 1 of 592 checks).
**Public-API coverage:** A counterpart harness driving the chipset
MMIO enable edge (`VpciDevice::tdisp_on_device_activate`) is **not
yet present**. The activate path runs a multi-step orchestration
(unbind-if-not-Unlocked → query_capabilities → bind → get_report →
start) and verifying the spec property at that layer requires a
multi-shot symbolic `KaniMock` plus cfg(kani) shims for the
`dev_snp_ohcl_tio_support` feature gate and the Vec-parsing report
deserializer. Until that scaffolding lands, the precondition-gate
property is verified only at the
`VpciClientTdispState::tdisp_bind_interface` primitive layer. See
[vm/devices/pci/vpci_client/src/kani_proofs_highlevel.rs](../vm/devices/pci/vpci_client/src/kani_proofs_highlevel.rs)
for the public-API harness module that already covers TVM-18 /
TVM-19 via `tdisp_on_device_deactivate`.
**Spec basis:** PCI-SIG TDISP v2022-07-27 §11.3.1 Table 3, §11.3.8,
§11.3.9 Table 12, §11.6.3, §11.2.7 Q4, §11.2 Figure 11-5.

## Property (TVM-1)

A `LOCK_INTERFACE_REQUEST` may be transmitted for a TDI **iff** the
TVM's locally tracked TDI state is `CONFIG_UNLOCKED`. The spec
restricts entry into `CONFIG_LOCKED` to a successful
`LOCK_INTERFACE_REQUEST` and explicitly enumerates LOCK as legal only
when the device is in `CONFIG_UNLOCKED` (§11.3.1 Table 3, §11.3.8).
The §11.6.3 LOCK→REPORT→START chain — including the per-lock
device-generated nonce — is the spec-blessed mitigation for a hostile
VMM, and depends on the TVM treating each LOCK as the start of a
fresh epoch.

## Counter-example

The Kani harness drives `tdisp_bind_interface()` with
`state_before` symbolic over all four `TdispTdiState` variants and a
fully-symbolic `GuestToHostResponse`. CBMC produces:

- `state_before = Run` (from a prior legitimate bind+start epoch).
- `tdisp_bind_interface()` is called and emits LOCK with **no**
  precondition check.
- Malicious host returns `Success` + `tdi_state_after = Locked` +
  matching `Bind` payload.
- Function returns `Ok(())`. Cached state is now `Locked`.

## Code basis

[vm/devices/pci/vpci_client/src/tdisp.rs](../vm/devices/pci/vpci_client/src/tdisp.rs#L359-L386)

```rust
pub async fn tdisp_bind_interface(&mut self) -> crate::Result<()> {
    let state_before = self.tdi_state();   // captured for tracing only
    let res = self
        .send_tdisp_command(openhcl_tdisp::new_bind_command(self.vpci_device_id))
        .await?;
    match self.tdi_state() {
        TdispTdiState::Locked => { tracing::info!(...) }
        state_after => { ...; return Err(...); }
    }
    match res.response::<TdispCommandResponseBind>() { ... }
}
```

`state_before` is referenced only by the failure-arm `tracing::error!`
call. It is never compared against `Unlocked`. The function will
happily emit a LOCK from cached `Run` / `Locked` / `Uninitialized`.

## Impact (concrete attack)

The cached fields `validated_mmio_bars`, `dma_unblocked`, and
`tdi_report` are scrubbed **only** by `tdisp_unbind_inner`
([tdisp.rs#L596-L603](../vm/devices/pci/vpci_client/src/tdisp.rs#L596-L603)),
which is also the only path that re-blocks pages via
`tdisp_block_mmio` / `tdisp_block_dma`. They survive a Run → Locked
transition driven by a forged host LOCK reply.

A malicious host can therefore, given a future caller of
`tdisp_bind_interface` that bypasses `attest()`'s upstream
`unbind-if-not-Unlocked` convergence step:

1. Catch the paravisor in cached `Run` (legitimate prior epoch) with
   non-empty `validated_mmio_bars` and `dma_unblocked = true`.
2. When the paravisor sends LOCK, fabricate
   `LOCK_INTERFACE_RESPONSE` (`Success`, `tdi_state_after = Locked`,
   arbitrary 32-byte `START_INTERFACE_NONCE`). Paravisor's cache
   flips to `Locked`. Prior-epoch trust caches survive.
3. Similarly fabricate `START_INTERFACE_RESPONSE`. Paravisor's cache
   flips to `Run`. Paravisor believes it has a fresh, legitimate
   epoch.
4. The F-7 gate inside
   [`tdisp_on_mmio_reconfigured_inner`](../vm/devices/pci/vpci_client/src/tdisp.rs#L944-L987)
   skips re-validation because `validated_mmio_bars.contains_key(bar_id)`
   is true from the prior epoch.
   [`isolation_snapshot()`](../vm/devices/pci/vpci_client/src/tdisp.rs#L883-L901)
   classifies DMA as `PRIVATE` purely from the un-scrubbed
   `dma_unblocked` flag.

This is the precise threat class §11.6.3 names ("reprogram a TDI that
is being used by a TVM", "map the MMIO resources … in an incorrect
order", "overlapping MMIO resources"). The mitigation §11.6.3
prescribes — re-deriving MMIO trust from a fresh
`DEVICE_INTERFACE_REPORT` per epoch — is bypassed because the
prior-epoch trust state is reused under the legitimacy of the (forged)
fresh lock.

## Latency / mitigating factor today

The only in-tree caller of `tdisp_bind_interface` reachable through
the public API is
[`attest()`](../vm/devices/pci/vpci_client/src/tdisp.rs#L711), which
calls `tdisp_unbind` first when cached state is not `Unlocked`. The
trait bridge
[`<VpciDevice as TdispVirtualDeviceInterface>::tdisp_bind_interface`](../vm/devices/pci/vpci_client/src/tdisp.rs#L1374-L1377)
re-exposes the un-gated method but currently has no in-tree caller.
The attack surface is therefore **latent**: any new caller that
forgets `attest()`'s convergence step re-opens the hole. The defence
must live in `tdisp_bind_interface` itself, not in one orchestrator.

## Recommended fix

Insert a precondition at the top of `tdisp_bind_interface` and scrub
per-bind cache fields as part of the gate:

```rust
pub async fn tdisp_bind_interface(&mut self) -> crate::Result<()> {
    let state_before = self.tdi_state();
    if state_before != TdispTdiState::Unlocked {
        return Err(crate::err!(
            "TVM-1: bind requires cached state Unlocked, got {:?}",
            state_before
        ));
    }
    // ... rest of the existing body ...
}
```

Independently, every successful bind should clear `validated_mmio_bars`,
`dma_unblocked`, and `tdi_report` (those are per-epoch trust state and
must not survive into a new lock epoch even if the precondition gate
were ever bypassed).

## Attribution

- Property derived top-down by the **TdispExpert** subagent (Claude
  Opus 4.7) from PCI-SIG TDISP v2022-07-27 §11.3.1 Table 3 etc.
- Code-path confirmed by the **OpenHclExpert** subagent (Claude Opus
  4.7) against
  [vm/devices/pci/vpci_client/src/tdisp.rs](../vm/devices/pci/vpci_client/src/tdisp.rs).
- Both subagents independently reached consensus: true-positive,
  exploitable, recommended fix is local.
