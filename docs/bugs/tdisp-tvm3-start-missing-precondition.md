# TDISP-TVM-3 — `tdisp_start_device` is missing the `state == Locked` precondition gate

**Status:** open
**Discovered by:** Kani harness `verify_tvm3_start_only_from_locked` in
[vm/devices/pci/vpci_client/src/kani_proofs.rs](../vm/devices/pci/vpci_client/src/kani_proofs.rs)
(VERIFICATION FAILED in 16.9 s).
**Spec basis:** PCI-SIG TDISP v2022-07-27 §11.3.1 Table 3, §11.3.14,
§11.3.9, §11.6.3.

## Property (TVM-3)

A `START_INTERFACE_REQUEST` may be transmitted for a TDI **iff** the
TVM's locally tracked TDI state is `CONFIG_LOCKED` (§11.3.1 Table 3).
§11.3.14 further requires the device to reject START unless the TDI is
`CONFIG_LOCKED` and the request's `START_INTERFACE_NONCE` matches the
nonce minted in the prior successful `LOCK_INTERFACE_RESPONSE` (§11.3.9).
The §11.6.3 LOCK→REPORT→START chain-of-custody guarantee is conditional
on the TVM-side emitter only sending START when it holds the matching
cached nonce.

## Counter-example

The harness drives `tdisp_start_device()` with `state_before` symbolic
over all four `TdispTdiState` variants and a fully-symbolic
`GuestToHostResponse`. CBMC produces:

- `state_before = Unlocked` (e.g., after a legitimate guest-driven
  Stop, or for a never-locked TDI).
- `tdisp_start_device()` is called and emits START with **no**
  precondition check.
- Malicious host returns `Success` + `tdi_state_after = Run` +
  matching `StartTdi` payload.
- Function returns `Ok(())`. Cached state is now `Run`.

## Code basis

[vm/devices/pci/vpci_client/src/tdisp.rs](../vm/devices/pci/vpci_client/src/tdisp.rs#L402-L429)

```rust
async fn tdisp_start_device_inner(&mut self) -> crate::Result<()> {
    let state_before = self.tdi_state();   // captured for tracing only
    let res = self
        .send_tdisp_command(openhcl_tdisp::new_start_tdi_command(self.vpci_device_id))
        .await?;
    match self.tdi_state() {
        TdispTdiState::Run => { tracing::info!(...) }
        state_after => { ...; return Err(...); }
    }
    match res.response::<TdispCommandResponseStartTdi>() { ... }
}
```

`state_before` is referenced only by the failure-arm `tracing::error!`
call. It is never compared against `Locked`, and the production state
holds no `start_interface_nonce` field at all — so even the §11.3.14
nonce-match check has no analogue on the TVM side.

## Independence from TDISP-TVM-1

Confirmed by the **TdispExpert** subagent: TVM-3 is independently
exploitable even if TVM-1 is fixed. STOP_INTERFACE_REQUEST legitimately
returns a TDI to `CONFIG_UNLOCKED` (§11.3.1 Table 3), so cached
`Unlocked` is reachable in normal operation. From there, calling
`tdisp_start_device` with no LOCK in between gives a malicious host a
direct Unlocked → Run cached transition without ever exercising the
LOCK path.

The §11.6.3 nonce-binding is a **device-side** check. It does not
protect the TVM-side emitter from believing in a transition that never
happened on-device, because a forged `Success + tdi_state_after = Run`
host response never has to reach the device at all.

## Impact (concrete attack)

Same downstream amplification chain as TDISP-TVM-1 once cached state
reaches `Run`:

- The F-7 gate inside
  [`tdisp_on_mmio_reconfigured_inner`](../vm/devices/pci/vpci_client/src/tdisp.rs#L944-L987)
  unblocks PRIVATE pages on the basis of cached `tdi_state == Run` +
  cached `tdi_report`. A forged Unlocked → Run transition therefore
  enables guest-private MMIO/DMA without any real device-side
  attestation having occurred in this epoch.
-
  [`isolation_snapshot()`](../vm/devices/pci/vpci_client/src/tdisp.rs#L883-L901)
  classifies BAR/DMA isolation off the cached state, so VTL0 is told
  the device is `Ready` for trusted access.

Severity: **load-bearing**. The §11.6.3 chain-of-custody mitigation
fails open without this gate.

## Recommended fix

Insert at the top of `tdisp_start_device_inner`
([tdisp.rs#L402](../vm/devices/pci/vpci_client/src/tdisp.rs#L402)):

```rust
async fn tdisp_start_device_inner(&mut self) -> crate::Result<()> {
    let state_before = self.tdi_state();
    if state_before != TdispTdiState::Locked {
        return Err(crate::err!(
            "TVM-3: start requires cached state Locked, got {:?}",
            state_before
        ));
    }
    // ... rest of body ...
}
```

Independently — and required for full §11.6.3 coverage — the cached
state must include a `start_interface_nonce: Option<[u8; 32]>` field,
populated from `LOCK_INTERFACE_RESPONSE` and consumed exactly once by
`tdisp_start_device`. The latter is currently unimplemented (no nonce
field anywhere in `VpciClientTdispMutableState`). See TVM-8 in the
broader property list.

## Attribution

- Property derived top-down by the **TdispExpert** subagent (Claude
  Opus 4.7) from PCI-SIG TDISP v2022-07-27 §11.3.1 Table 3, §11.3.14,
  §11.3.9, §11.6.3.
- Independence-from-TVM-1 confirmed by the same subagent.
- Code-path confirmed by reading
  [vm/devices/pci/vpci_client/src/tdisp.rs](../vm/devices/pci/vpci_client/src/tdisp.rs#L402-L429).
