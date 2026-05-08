# AF-iter2-2 — concrete attacker scenario

All citations are from the source as it lives at the cited paths; the line numbers below match the current revision and are within ±5 of the ones the bug report uses.

---

## 1. Initial system state and prerequisites

- **Hardware:** AMD SEV-SNP with SEV-TIO firmware (per AMD spec 0.91), PCIe device with TDISP support behind an IDE stream the host has provisioned, IOMMU configured.
- **Software:** OpenHCL paravisor built on branch `tdisp_tio_vpci` with the `dev_snp_ohcl_tio_support` Cargo feature **enabled** (otherwise `TdispSevTioResourceValidator` and `vpci_client::query_capabilities` aren't compiled in — see knowledge base lines 1153–1248). `test_tdisp_flow` MUST be `false` so the relay takes the "real attestation" branch at [vpci_relay/src/lib.rs#L387](vm/devices/pci/vpci_relay/src/lib.rs#L387).
- **Guest:** any CVM that loads a stock PCI driver for the offered device class (NVMe, NIC, GPU). The guest does **not** need to be attacker-aware.
- **Device offered by the host:** a real, attestable TDISP device, chosen so the relay-driven proactive attest will *succeed*. The attacker must give the relay a real attestation pass; the bug fires on the *unbind* that follows.
- **Paravisor at t=0:** `VpciRelay::relay_vpci_bus` ([vpci_relay/src/lib.rs#L340–L490](vm/devices/pci/vpci_relay/src/lib.rs#L340-L490)) is processing the offer: `VpciClient::connect` has returned, `init` has produced `vpci_device`, `tdisp_query_capabilities()` is about to run.
- **Attacker knowledge:** the host VMM knows the VMBus channel for VPCI, can synthesize any wire-valid `VpciTdispResponse`, knows the `VPCI_TDISP_COMMAND` (`0x4249001D`) format from `vpci_protocol` (knowledge base lines 1249–1325), and knows the prost wire format of `GuestToHostResponse` from `tdisp_proto`. No guest-memory introspection needed for the cache-poisoning step itself.

---

## 2. The trigger event

The trigger is **the relay's own proactive attestation flow** in [vpci_relay/src/lib.rs#L386–L429](vm/devices/pci/vpci_relay/src/lib.rs#L386-L429), which fires **before the device is inserted into the chipset**. Sequence the relay drives, end-to-end:

1. `tdisp_query_capabilities` → host returns real `TdispDeviceInterfaceInfo`.
2. `tdisp_attest_device(interface_info)` → calls `VpciClientTdispState::attest()` at [vpci_client/src/tdisp.rs#L1015](vm/devices/pci/vpci_client/src/tdisp.rs#L1015): bind → start → `get_tdi_device_id` → `get_tdi_report`. **Host plays this leg honestly**, so the AMD PSP issues real `TIO_TDI_BIND` / `TIO_TDI_START` and the cached state lands at `tdi_state = Run`, `tdi_report = Some(real_report)`, `intercepted_bars = {MSI-X table BAR, PBA BAR}`, `cached_capabilities = Some(...)`, `guest_device_id = real_id`, `validated_mmio_bars = {}` (empty — `attest()` does not unblock MMIO), `dma_unblocked = false`.
3. Relay then calls `tdisp_unbind_preserve_report(TdispGuestUnbindReason::Graceful)` at [vpci_relay/src/lib.rs#L411](vm/devices/pci/vpci_relay/src/lib.rs#L411). **This is the call the host weaponizes.**

The host's role: it is the wire endpoint receiving the `VpciTdispCommand` carrying the prost-encoded `TdispCommandUnbind`. It controls every byte of the matching `VpciTdispResponse`.

---

## 3. The malicious-host action — wire-level details

When the host receives the `TdispCommandUnbind` for slot `S`, it crafts the response below and *also* skips the corresponding firmware step (i.e. it does **not** issue `TIO_TDI_UNBIND` to the PSP — the on-firmware TDI stays in its post-`TIO_TDI_START` state).

`GuestToHostResponse` (per `tdisp_proto`):

| Field | Value | Why |
|---|---|---|
| `result` (oneof tag) | `TdispCommandResponseUnbind { ... }` | Must be the matching variant or `validate_response` in `tdisp::serialize_proto` rejects it (knowledge base lines 1066–1136). The body fields can be defaults; nothing inside is read on the Err path. |
| `error_code` | `TdispGuestOperationErrorCode::Unspecified` (or any non-`Success` known variant — `InsufficientResources`, `Failed`, `OperationNotSupported` are equally good) | Forces the `other =>` arm at [vpci_client/src/tdisp.rs#L540](vm/devices/pci/vpci_client/src/tdisp.rs#L540) so `send_tdisp_command` returns `Err` to the relay. Choosing a *known* enum (not `Unknown(0xFFFF)`) means `tracing::error!` produces a benign-looking line that blends in with normal transient errors and is unlikely to trigger an operator alert. |
| `tdi_state_after` | `TdispTdiState::Run` (encoded as the protobuf int for `Run`) | This is the cache-poisoning lever. `res.tdi_state_after_enum()` at [vpci_client/src/tdisp.rs#L529](vm/devices/pci/vpci_client/src/tdisp.rs#L529) returns `Some(Run)` and `update_tdi_state` writes it unconditionally. Choosing `Run` (not `Unlocked`) is what unlocks Stage 2 of the exploit by causing `tdisp_on_device_activate` to **skip the re-attest branch** entirely. (`Unlocked` is a viable alternative for a DoS-only variant; see §9.) |

Wire packing: `serialize_proto::serialize_response` plus the `VpciTdispResponseHeader` with `message_type = VPCI_TDISP_COMMAND` (`0x4249001D`) and `slot = S`. Total payload < `MAX_VPCI_TDISP_COMMAND_SIZE`.

---

## 4. Paravisor processing — code path trace

State of `mutable_state` immediately before step (a): `{tdi_state: Run, tdi_report: Some(real), intercepted_bars: {...}, cached_capabilities: Some(...), guest_device_id: real, validated_mmio_bars: {}, dma_unblocked: false}`.

(a) Relay calls `vpci_device.tdisp_unbind_preserve_report(Graceful)` — [vpci_relay/src/lib.rs#L411](vm/devices/pci/vpci_relay/src/lib.rs#L411).

(b) `VpciClientTdispState::tdisp_unbind_preserve_report` at [vpci_client/src/tdisp.rs#L800](vm/devices/pci/vpci_client/src/tdisp.rs#L800) forwards to `tdisp_unbind_inner(reason, clear_cached_report=false)`.

(c) `tdisp_unbind_inner` at [vpci_client/src/tdisp.rs#L821](vm/devices/pci/vpci_client/src/tdisp.rs#L821):
   - The MMIO re-block `for` loop at [#L832–L857](vm/devices/pci/vpci_client/src/tdisp.rs#L832-L857) iterates `validated_mmio_bars` — **empty**, no calls.
   - The DMA re-block at [#L859–L867](vm/devices/pci/vpci_client/src/tdisp.rs#L859-L867) is gated by `if self.mutable_state.dma_unblocked` — **false**, no call.
   - Calls `send_tdisp_command(new_unbind_command(...))` at [#L869](vm/devices/pci/vpci_client/src/tdisp.rs#L869).

(d) `send_tdisp_command` at [vpci_client/src/tdisp.rs#L470–L551](vm/devices/pci/vpci_client/src/tdisp.rs#L470-L551):
   - Sends `VpciTdispCommand` over the host channel at [#L494](vm/devices/pci/vpci_client/src/tdisp.rs#L494).
   - Receives the malicious response.
   - **[#L528–L532] Cache-poisoning happens here:**
     ```rust
     match res.tdi_state_after_enum() {
         Some(state) => self.mutable_state.update_tdi_state(state),
         None => tracing::warn!(...),
     }
     ```
     `update_tdi_state` at [vpci_client/src/tdisp.rs#L385](vm/devices/pci/vpci_client/src/tdisp.rs#L385) blindly assigns `self.tdi_state = Run`. **No comparison to `error_code`, no sanity-check against the requested transition (e.g. "an Unbind command should land in `Unlocked`, not `Run`"), no consult of `tdisp_query_firmware_tdi_state` (knowledge base lines 1252–1325 note that plumbing exists but no caller uses it).**
   - **[#L534–L548] Error-code check — happens AFTER cache write:** `error_code()` returns `Unspecified`, the `other` arm fires, `tracing::error!` is emitted, returns `Err(crate::err!(…))`.

(e) Back in `tdisp_unbind_inner`, the `?` after the `await` ([#L872](vm/devices/pci/vpci_client/src/tdisp.rs#L872)) propagates the Err. The `Ok` arm at [#L874–L893](vm/devices/pci/vpci_client/src/tdisp.rs#L874-L893) — the only place that calls `validated_mmio_bars.clear()`, `dma_unblocked = false`, and the `if clear_cached_report { tdi_report = None }` branch — **never executes**. State after return:
   - `tdi_state = Run` ✗ POISONED
   - `tdi_report = Some(real_report)` (preserved)
   - `intercepted_bars = {...}` (preserved)
   - `cached_capabilities = Some(...)` (preserved)
   - `guest_device_id = real_id` (preserved)
   - `validated_mmio_bars = {}` / `dma_unblocked = false` (unchanged)

(f) Relay receives the `Err` at [vpci_relay/src/lib.rs#L420–L427](vm/devices/pci/vpci_relay/src/lib.rs#L420-L427). Match arm:
   ```rust
   Err(e) => tracing::error!(
       %instance_id, error = &*e as &dyn std::error::Error,
       "TDISP post-attestation unbind failed; continuing to relay device"
   ),
   ```
   Falls through. Relay-decision-to-admit happens here: control reaches [#L453+](vm/devices/pci/vpci_relay/src/lib.rs#L453) and `chipset.add_dyn_device(...)` inserts the device unit; then `vpci::bus::VpciBus::new(...)` exposes it on the guest-visible VPCI bus. The device is now reachable from VTL0.

---

## 5. Device-visible state at insertion time

Cached `VpciClientTdispMutableState` (the paravisor's view of the TDI):

| Field | Value | Source of truth? |
|---|---|---|
| `tdi_state` | `Run` | **Lie** — host injected it. |
| `tdi_report` | `Some(real attested report)` | Real, from step §2.2. |
| `intercepted_bars` | `{MSI-X table BAR, PBA BAR}` | Real. |
| `cached_capabilities` | `Some(real interface info)` | Real. |
| `guest_device_id` | real `u16` device ID | Real. |
| `validated_mmio_bars` | `{}` | Real (empty — never unblocked). |
| `dma_unblocked` | `false` | Real. |

Firmware-side TDI state, per the AMD PSP: still in `CONFIG_LOCKED` + `RUN` for the real device, because the host **declined** to issue `TIO_TDI_UNBIND`. Per knowledge base §"End-to-end paravisor TDISP flow" line 1369, `tdisp_query_firmware_tdi_state` exists but has no production caller, so this drift is invisible to the paravisor.

VTL0's view: PCI cfg space exposes the device's vendor/device IDs (real, copied from host VPCI), BARs are in the disabled state (cmd register memory-space-enable bit = 0), MSI-X table is at the host-reported offset, and `VPCI_QUERY_ISOLATED_RESOURCES` returns `Ready { bars: [PRIVATE for non-MSIX BARs, SHARED for MSI-X BAR/PBA], dma: SHARED }` — built by `isolation_snapshot()` at [vpci_client/src/tdisp.rs#L1252](vm/devices/pci/vpci_client/src/tdisp.rs#L1252) from the real cached report. The guest is shown a **fully attested-looking device**.

---

## 6. The guest action that triggers exploitation

VTL0 runs an ordinary stock PCI driver (no TDISP awareness needed). The driver:

1. Reads `STATUS_COMMAND` in cfg space, sees memory-space-enable = 0.
2. Sizes the BARs (writes `0xFFFFFFFF`, reads back, computes size).
3. Programs each BAR with a chosen GPA (e.g. `0xF0000000` for BAR0). The GPA comes from the guest's MMIO allocator; the attacker does not control it directly.
4. Writes `STATUS_COMMAND` with the memory-space-enable bit set.

This is what **any** PCI driver does on probe. The guest is **oblivious** — no cooperation required.

Step 4 hits `RelayedVpciDevice::pci_cfg_write` in [vpci_relay/src/lib.rs](vm/devices/pci/vpci_relay/src/lib.rs), which detects the disabled→enabled MMIO edge and runs `VpciDevice::tdisp_on_device_activate` ([vpci_client/src/lib.rs#L799](vm/devices/pci/vpci_client/src/lib.rs#L799)).

---

## 7. Exploitation — what the attacker achieves

Inside `tdisp_on_device_activate` ([vpci_client/src/lib.rs#L851–L860](vm/devices/pci/vpci_client/src/lib.rs#L851-L860)):

```rust
let state = self.tdisp_tdi_state().await;
if state != TdispTdiState::Run {
    /* … attest path … */
}
```

Cache says `Run` → **the entire `if`-block is skipped**. No `query_capabilities`, no `attest()`, no `bind`, no `start`, no `get_tdi_report`. **The intended guest-driven attestation cycle is bypassed.**

Control flows directly to the BAR-iteration loop at [#L893–L949](vm/devices/pci/vpci_client/src/lib.rs#L893-L949). For each BAR with non-zero mask the loop calls `tdisp_on_mmio_reconfigured(bar_id, base_address, length)` at [#L941](vm/devices/pci/vpci_client/src/lib.rs#L941).

`tdisp_on_mmio_reconfigured_inner` at [vpci_client/src/tdisp.rs#L1321](vm/devices/pci/vpci_client/src/tdisp.rs#L1321):
- `self.tdi_state() != Run` → false (cache says Run), **does not bail**.
- `validated_mmio_bars.contains_key(&bar_id)` → false (empty), **does not skip**.
- `classify_bar(bar_id)` at [#L1200](vm/devices/pci/vpci_client/src/tdisp.rs#L1200) consults `intercepted_bars` (real) and `tdi_report` (real) → returns `PRIVATE` for the non-MSI-X BARs.
- Calls `validator.tdisp_unblock_mmio(target_vtl=Vtl0, device_id=real_id, base_gpa=guest-chosen, base_offset=0, length, bar_id)` at [#L1402](vm/devices/pci/vpci_client/src/tdisp.rs#L1402).

`TdispSevTioResourceValidator::tdisp_unblock_mmio` (knowledge base lines 1198–1212, source [openhcl/openhcl_tdisp/src/sevtio.rs](openhcl/openhcl_tdisp/src/sevtio.rs)):
1. Flips PFNs at `[base_gpa, base_gpa+length)` to PRIVATE via mshv.
2. Issues `TIO_MSG_MMIO_VALIDATE_REQ(device_id=real_id, gpa=base_gpa, len)` to the PSP via `/dev/sev-guest`.
3. RMPADJUSTs the pages so the guest VMPL has R/W.

Then on the first successful BAR ([#L1419+](vm/devices/pci/vpci_client/src/tdisp.rs#L1419)), `dma_unblocked` is set and `tdisp_unblock_dma` issues `TIO_MSG_SDTE_WRITE_REQ` to the PSP.

**What the PSP sees** at `TIO_MSG_MMIO_VALIDATE_REQ` time: TDI is in `RUN` (host kept it there), device_id matches, BAR mapping matches what the host's IDE/IOMMU layer programmed for the real device. **PSP accepts.** Pages are now PRIVATE-for-VTL0, mapped to the real device's MMIO.

### Concrete impact

- **DoS (the most reachable concrete consequence).** Three sub-variants depending on how the host plays the firmware side:
  - **D1 (chosen variant above):** host *did* keep PSP TDI in RUN. Then MMIO_VALIDATE_REQ succeeds, SDTE write succeeds, **the device works**. From the attacker's standpoint, this variant has *no direct DoS or confidentiality payload* on its own — it merely demonstrates that the relay's intended "force a fresh guest-driven re-attest at MMIO-enable" invariant is broken. The downstream consequence is that a *second* malicious step (e.g. coupling with a separate slot-substitution attack — see knowledge base finding #3 line 1378) can land without ever forcing a fresh attestation.
  - **D2 (likely DoS variant):** host issued `TIO_TDI_UNBIND` to PSP at the same time it lied to the paravisor. PSP TDI is in `CONFIG_UNLOCKED`. `MMIO_VALIDATE_REQ` is rejected by the PSP with a TIO error. `tdisp_unblock_mmio` returns `Err`, `tdisp_on_mmio_reconfigured_inner` propagates it, the activate loop logs `tracing::error!` ([vpci_client/src/lib.rs#L953–L957](vm/devices/pci/vpci_client/src/lib.rs#L953-L957)) and moves on. Result: **device is on the bus, BARs appear enabled to the guest's cfg-space read, but every guest MMIO access falls through to a SHARED page the host owns.** The guest's PCI driver hangs on driver init.
  - **D3:** in addition to D2, the host opens `/dev/sev-guest` ioctls at exactly the moment that triggers one of the `.context("…").unwrap()` sites in [openhcl/openhcl_tdisp/src/sevtio.rs](openhcl/openhcl_tdisp/src/sevtio.rs) at ~lines 43 / 215 / 342 (knowledge base finding #1 line 1374). Result: **paravisor panic = full guest crash.**

- **Confidentiality breach.** Direct read-out of guest secrets via the cache-poisoning step alone is **blocked by the PSP** in §7's flow above: `TIO_MSG_MMIO_VALIDATE_REQ` and `TIO_MSG_SDTE_WRITE_REQ` are signed by the PSP against its own view of the TDI/device, so the host cannot make the paravisor unblock pages mapping host-controlled memory at a real device_id without the PSP refusing. The actual confidentiality payload requires composing this bug with an independent "device substitution under the same VPCI slot" lever (knowledge base finding #3 line 1378), in which case the cached `tdi_report` from the original attest is reused to classify a *different* physical device's BARs — and the PSP acceptance check is satisfied because the host can present a different real TDI under the same slot. AF-iter2-2 is the **enabler** that strips the second-attest defense; the confidentiality breach itself rides on the slot-substitution lever.

**TL;DR on which is more reachable: DoS (D2/D3). Confidentiality is reachable only when AF-iter2-2 is composed with an unrelated lever; on its own it's a defense-in-depth failure that removes the activate-time re-attest checkpoint.**

---

## 8. Realistic attacker model

- **Patience:** zero. The exploit fires on the very first device offer. No need to wait for a particular guest workload — the relay's proactive attest+unbind sequence happens at device arrival, before the device is exposed to VTL0.
- **Round-trips on the wire:** for the cache-poisoning step, exactly **one** malicious response (the rigged Unbind reply at §3). The host must also have honored the preceding bind/start/get_report/get_device_id (4 round-trips) so the attest leg succeeds.
- **Repeatability:** the attack is **idempotent and stateless on the host's side**. Every device offer can be poisoned the same way; the bug is in the paravisor's response handling and is not rate-limited (`tracing::error!` at [vpci_client/src/tdisp.rs#L542](vm/devices/pci/vpci_client/src/tdisp.rs#L542) is **not** `tracelimit::error_ratelimited!`, but the host gates how often a device-arrival can be triggered, so flooding isn't a concern).
- **Detection surface:**
  - `tracing::error!` at [vpci_client/src/tdisp.rs#L538–L548](vm/devices/pci/vpci_client/src/tdisp.rs#L538-L548): `"send_tdisp_command failed because host responded with an error"` with fields `error_code = Unspecified, command = "TdispCommandUnbind"`.
  - `tracing::error!` at [vpci_relay/src/lib.rs#L420–L426](vm/devices/pci/vpci_relay/src/lib.rs#L420-L426): `"TDISP post-attestation unbind failed; continuing to relay device"`.
  - Crucially, **no warning is emitted** when `update_tdi_state` writes `Run` after an error response — `update_tdi_state` only logs at `info!` ([vpci_client/src/tdisp.rs#L386–L391](vm/devices/pci/vpci_client/src/tdisp.rs#L386-L391)) with no annotation that the transition is suspicious. An operator scanning for high-severity events sees only "transient unbind failure, device still relayed", which looks like a benign retry-able condition.
  - No telemetry compares cached `tdi_state` to `tdisp_query_firmware_tdi_state` (no caller exists, knowledge base line 1369).

---

## 9. Comparison to AF-iter2-1's exploit

| Axis | AF-iter2-1 | AF-iter2-2 |
|---|---|---|
| Cache-poisoning entry point | Disable-edge unbind in `tdisp_on_device_deactivate` ([vpci_client/src/lib.rs#L1000+](vm/devices/pci/vpci_client/src/lib.rs#L1000)). Host returns Unbind response with `result=Success` and an attacker-chosen `tdi_state_after`. Cache lands at attacker value via the *Ok* arm, no error code involved. | Post-attest unbind in `relay_vpci_bus` ([vpci_relay/src/lib.rs#L411](vm/devices/pci/vpci_relay/src/lib.rs#L411)). Host returns Unbind with `error_code=non-Success` and `tdi_state_after=Run`. Cache lands at attacker value via the *Err* arm at [vpci_client/src/tdisp.rs#L528–L532](vm/devices/pci/vpci_client/src/tdisp.rs#L528-L532). |
| Trigger | Guest must have first enabled MMIO and then disabled it. | Fires unconditionally at device arrival — **no guest action required to trigger the cache poison**. Only Stage 2 (BAR unblock) needs the guest to enable MMIO. |
| Persistence of `tdi_report` | Already preserved by the `_preserve_report` Ok arm — bug is *only* in the state field. | Preserved because the Ok arm never runs at all. Same end-state for `tdi_report`. |
| `validated_mmio_bars` going in | Populated (guest had unblocked MMIO before disabling). | Empty (attest never unblocked). The defective preservation of stale-bar entries is irrelevant here. |
| Patience | Has to wait for a guest disable→re-enable cycle. | Zero patience — fires on first device offer. |
| Stealth | The success-code response looks ordinary; activate→deactivate→activate cycles are common. | Slightly noisier (one extra `error!` log), but still a benign-looking transient. |
| Reliability | Depends on hitting the disable edge cleanly; the relay's deferred-cfg-write logic adds asynchronous serialisation. | One-shot, deterministic, synchronous within `relay_vpci_bus`. |
| Easier? | AF-iter2-2: strictly fewer prerequisites, no guest-side timing. |
| Stealthier? | AF-iter2-1: success-code response, no `error!` log on the unbind. |
| **Combined attack ("use both in tandem")** | Yes, valuable. Use **AF-iter2-2 at device arrival** to insert the device with poisoned `Run` cache and skip the first guest-driven re-attest. Then, if the guest ever issues a disable→re-enable cycle (e.g. driver suspend/resume), use **AF-iter2-1 at the disable edge** to keep the cache in `Run` *and* keep `validated_mmio_bars` populated, so the next enable's `tdisp_on_mmio_reconfigured` short-circuits at the `validated_mmio_bars.contains_key(&bar_id)` check ([vpci_client/src/tdisp.rs#L1369](vm/devices/pci/vpci_client/src/tdisp.rs#L1369)) and **the validator is never re-invoked at all** — no PSP backstop on the second activate, while the per-bar pages were re-blocked to SHARED by the disable-edge `tdisp_block_mmio` calls at [vpci_client/src/tdisp.rs#L832–L857](vm/devices/pci/vpci_client/src/tdisp.rs#L832-L857). That is the cleanest path to a guest-MMIO-falls-through-to-host-RAM confidentiality breach **without needing PSP cooperation**. AF-iter2-2 alone gets the device installed; AF-iter2-1 alone needs the device already installed and a disable edge; together they cover the full lifecycle. |