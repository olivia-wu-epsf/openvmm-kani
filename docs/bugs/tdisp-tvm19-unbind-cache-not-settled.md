# TDISP-TVM-19 — `tdisp_unbind` does not enforce `cached tdi_state == Unlocked` on success

**Status:** open
**Discovered by:** Kani harness `verify_tvm19_unbind_settles_cache_to_unlocked` in
[vm/devices/pci/vpci_client/src/kani_proofs.rs](../vm/devices/pci/vpci_client/src/kani_proofs.rs)
(VERIFICATION FAILED in 55.4 s).
**Companion harness:** `verify_tvm19_unbind_scrubs_per_bind_state`
PASSES in 46.0 s — the bookkeeping-clear half of TVM-19 is already
honored.
**Spec basis:** PCI-SIG TDISP v2022-07-27 §11.2 Figure 11-5,
§11.3.16, §11.3.9, §11.6.3.

## Property (TVM-19, two parts)

On a successful `STOP_INTERFACE_REQUEST` exchange the TVM must:

- **(a)** Scrub per-bind trust state — equivalent to clearing
  `validated_mmio_bars`, `dma_unblocked`, and `tdi_report` on the
  Ok path. (Spec: §11.3.16 device-side scrub list, §11.3.9 nonce
  destruction on `CONFIG_LOCKED → CONFIG_UNLOCKED`, §11.6.3 chain
  guarantee.)
- **(b)** Reflect the device-side terminal state in the cache:
  cached `tdi_state == Unlocked` (per §11.2 Figure 11-5: STOP
  returns the TDI to `CONFIG_UNLOCKED`).

Part (a) verifies. Part (b) does not.

## Counter-example (part b)

The harness drives `tdisp_unbind(Graceful)` with `state_before`
symbolic over all four `TdispTdiState` variants and a fully-symbolic
`GuestToHostResponse`. CBMC produces:

- `state_before = Run`.
- Malicious host returns `Success` + `tdi_state_after = Run` (or any
  decodable value other than `Unlocked`) + matching `Unbind` payload.
- `send_tdisp_command` writes `update_tdi_state(Run)` from the
  forged `tdi_state_after`.
- `tdisp_unbind_inner` clears `validated_mmio_bars` / `dma_unblocked`
  / `tdi_report` on the Ok arm, then returns `Ok(())`.
- Post-state: cached `tdi_state == Run`, even though the TVM just
  acknowledged a successful unbind.

## Code basis

[vm/devices/pci/vpci_client/src/tdisp.rs](../vm/devices/pci/vpci_client/src/tdisp.rs#L540-L613)

`tdisp_unbind_inner` performs no per-method post-check on
`self.tdi_state()` after `send_tdisp_command` returns. The Ok arm of
the response match clears bookkeeping fields but does not validate
that the host's claimed `tdi_state_after` matches the protocol-mandated
terminal state `Unlocked`.

## Impact (concrete attack)

Composes with TDISP-TVM-1 / TDISP-TVM-3 (and any future precondition
fix to those): a malicious host can land the cached state at `Run`
*after* an unbind. Downstream:

-
  [`isolation_snapshot()`](../vm/devices/pci/vpci_client/src/tdisp.rs#L883-L901)
  may return `Ready` for an unbound TDI if any cached classification
  bits remain that satisfy its predicate. Even with bookkeeping
  cleared, the function reads cached `tdi_state` to decide
  `Ready` vs `NotReady` — leaving cached state at `Run` after unbind
  is a precondition for false-Ready replies.
- The cached `Run` state subsequently satisfies the TVM-2 GET_REPORT
  precondition gate (if added per TDISP-TVM-2), letting the host
  re-introduce a forged report into a freshly cleared cache without
  ever running LOCK in between.

Severity: **load-bearing**. Without this fix, the precondition gates
proposed for TVM-1/2/3 fail to anchor the TVM back at `Unlocked` after
a teardown.

## Recommended fix

Add a per-method post-check at the top of `tdisp_unbind_inner`'s Ok
arm
([tdisp.rs#L596-L603](../vm/devices/pci/vpci_client/src/tdisp.rs#L596-L603)):

```rust
match res.response::<TdispCommandResponseUnbind>() {
    Ok(_) => {
        if self.tdi_state() != TdispTdiState::Unlocked {
            // Force cache back to Unlocked regardless of host claim:
            // STOP_INTERFACE_REQUEST is defined to land the TDI at
            // CONFIG_UNLOCKED (TDISP §11.2 Figure 11-5). A
            // host-claimed `tdi_state_after` ≠ Unlocked indicates a
            // protocol-violating reply.
            return Err(crate::err!(
                "TVM-19: unbind did not settle cache at Unlocked, got {:?}",
                self.tdi_state()
            ));
            // (The bookkeeping clear below is intentionally NOT
            // executed in this Err path — leaving stale entries that
            // an audit log can use is preferable to silently masking
            // the protocol violation.)
        }
        self.mutable_state.validated_mmio_bars.clear();
        self.mutable_state.dma_unblocked = false;
        if clear_cached_report { self.mutable_state.tdi_report = None; }
        Ok(())
    }
    Err(err) => Err(crate::err!("error response in tdisp_unbind: {err}")),
}
```

Combined with TDISP-TVM-18 (don't advance cache on Err response), this
guarantees that after `tdisp_unbind` returns `Ok` the cached state is
exactly `Unlocked`.

## Attribution

- Property derived top-down by the **TdispExpert** subagent (Claude
  Opus 4.7) from PCI-SIG TDISP v2022-07-27 §11.2 Figure 11-5,
  §11.3.16, §11.3.9, §11.6.3.
- Code-path confirmed by reading
  [vm/devices/pci/vpci_client/src/tdisp.rs](../vm/devices/pci/vpci_client/src/tdisp.rs#L540-L613).
- TVM-19 part (a) bookkeeping clear PASSES verification (production
  code already honors it); only the cached-state-settle clause fails.
