# AF-iter2-1 — `tdisp_unbind` accepts host-poisoned `tdi_state_after`

**Property violated:** M-1 (cached `tdi_state` matches spec post-state
on `Ok` of `tdisp_unbind`).
**Code site:** [vm/devices/pci/vpci_client/src/tdisp.rs#L821-L894](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L821-L894)
(`tdisp_unbind_inner`).
**Harnesses:** [vm/devices/pci/vpci_client/src/kani_proofs_session.rs](../../../vm/devices/pci/vpci_client/src/kani_proofs_session.rs)
- `m1_unbind_ok_implies_state_unlocked` — failed in 6.2 s, 1/971 checks.
- `m1_unbind_preserve_ok_implies_state_unlocked` — failed in 7.3 s, 1/395 checks.
- `m_relay_1_deactivate_post_state_is_unlocked_or_uninitialized` — failed in 31 s. **Relay-side corroboration**: drives the same bug through `VpciDevice::tdisp_on_device_deactivate` (the public entrypoint the relay's MMIO-disable edge calls).
- `m_relay_2_focused_unblock_mmio_against_poisoned_run_cache` — failed in 2.6 s. **Chain-of-custody-bypass corroboration**: with a poisoned-`Run` cache and a stale cached report, `tdisp_on_mmio_reconfigured` calls `validator.tdisp_unblock_mmio` against attacker-controlled `(base, length)` without any fresh attestation. This is the precise downstream consequence of the missing post-check that AF-iter2-1's exploit relies on.

All four failures share root cause: `tdisp_unbind_inner` is the shared
implementation behind both `tdisp_unbind` and
`tdisp_unbind_preserve_report`. The two `m_relay_*` harnesses
demonstrate that the bug is reachable through the same public
entrypoints that `vpci_relay`'s MMIO-disable / MMIO-enable edges
drive in production. A local-only fix to one wrapper would not
catch the bug at the relay surface.

**Severity:** high (confidentiality breach on non-SEV-TIO platforms;
DoS-only on SEV-TIO via external PSP backstop).
**Verdict:** TRUE POSITIVE. Both expert subagents (TDISP-spec and
OpenHCL) reached this verdict independently with skill-only sources.

## Spec-grounded restatement (consensus, round 3)

Initial expert framings cited §11.2.7 Q4 in isolation. Round 2
tightened the citation to a composite. Round 3 of the debate
corrected the role mapping: the **TSM is in the TVM's TCB**
(Figure 11-2 legend, lines 716–722; §11.1 lines 762–768) and is
**not** the host VMM. In the OpenHCL paravisor architecture the
TSM is the AMD SEV-PSP; the SPDM session terminates between the
PSP (TSM) and the device (DSM), and the host VMM is the mediator
of the **TVM↔TSM** interface (§11.2.7 line 1224). Full debate
transcript at
[../../security-properties-2/af-iter2-1-debate-transcript.md](../../security-properties-2/af-iter2-1-debate-transcript.md).

The canonical claim, with corrected role mapping:

> The TVM acceptance procedure of §11.2.7 (lines 1207–1227) places
> four normative trust questions on the TVM — which in the OpenHCL
> architecture is the paravisor in VTL2. Even though the spec
> declares the TSM (here the AMD SEV-PSP) to be in the TVM's TCB,
> §11.2.7 does not authorize the TVM to omit per-message
> validation of the answers it gets back: the TVM must form an
> independent judgment from the TDI report (§11.3.10–§11.3.11,
> lines 1706–1960) and the TDI's reported state
> (§11.3.12–§11.3.13, lines 1961–1985), and it must enforce the
> LOCK→REPORT→START chain whose binding to a single SPDM secure
> session is the central mitigation in §11.6.3 (lines 3034–3101)
> carried by the per-session `start_interface_nonce` (§11.3.8 /
> §11.3.14, lines 1520–1705 and 1986–2029). The DSM event matrix
> in §11.2.6 (lines 1057–1206) makes clear that the TDI's TDISP
> state can transition to ERROR at any time as the result of
> asynchronous host-side events (FLR, conventional reset, IDE
> de-keying, config writes to locked registers, etc.), so the TVM
> cannot treat any single TSM response as a durable witness of
> state. In the OpenHCL paravisor the host VMM is the **mediator**
> of the TVM↔TSM interface (§11.2.2 line 978 explicitly
> anticipates the VMM being on this kind of path, and §11.6.3
> names the VMM as the canonical adversary), so the TVM-side
> post-condition checks AF-iter2-1 calls out — verifying the
> post-state implied by `LOCK_INTERFACE_RESPONSE` /
> `STOP_INTERFACE_RESPONSE` and re-querying / cross-checking
> before treating the TDI as trustworthy on subsequent operations
> — are the only things standing between the paravisor and a
> host-substituted reply.

Concrete code-level statement of the defect:

> [`attest()` (vpci_client/src/tdisp.rs#L1011-L1099)](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L1011-L1099)
> reissues `Bind → Start → GetTdiReport` but the paravisor never
> generates or verifies a nonce of its own, and
> [`tdisp_unbind_preserve_report` (#L823-L836)](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L823-L836)
> keeps the prior cycle's `tdi_report` cached across the UNLOCK
> transition that §11.3.9 says destroys the binding nonce and
> §11.2.6 says ends the DSM's obligation to track config changes.
> The paravisor-internal `IsolationSnapshot::Ready` answer to
> `QueryIsolatedResources`
> ([#L1254-L1270](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L1254-L1270))
> returning stale `PRIVATE` is a downstream symptom of the missing
> per-cycle re-acceptance check, not an independent spec violation.

### Important distinctions established by the debate

- **The TSM is in the TVM's TCB** (Figure 11-2 legend, lines
  716–722; §11.1, line 762–768). The TSM is **not** the host VMM.
  In the OpenHCL paravisor architecture the TSM is the AMD SEV-PSP
  (a host-hardware-resident trusted module); the host VMM is a
  separate untrusted entity.
- **The SPDM session is between the TSM (PSP) and the DSM
  (device)**, NOT between the TVM and anyone (§11.2.2 lines 977–979;
  §11.2.7 line 1217 Q2). The TVM is a *consumer* of the result via
  a "TSM-provided interface" (§11.2.7 line 1224).
- **The host VMM mediates the TVM↔TSM interface in the OpenHCL
  architecture.** The spec is silent on a wire protocol or
  transport for the TVM↔TSM interface (Q3 of the round-3
  adjudication); §11.2.2 line 978 explicitly anticipates the VMM
  being a transport carrier ("The TSM is permitted to use an
  untrusted channel (e.g., proxy through the VMM) to access the
  transport mechanism.").
- **The wire-level `tdi_state_after` framing is paravisor-internal,
  not a TDISP wire-protocol violation.** §11.3.17 defines no
  `tdi_state_after` field for `STOP_INTERFACE_RESPONSE`; the field
  is on OpenHCL's `GuestToHostResponse` envelope only. The defect
  is that the paravisor's cache update should derive
  "post-Unbind state == `CONFIG_UNLOCKED`" from §11.2 Figure 11-5
  rather than sourcing it from a host-asserted byte.
- **`QueryIsolatedResources` and `IsolationSnapshot` are
  OpenHCL-internal APIs**, not TDISP-spec terms. They cannot
  violate the TDISP spec; they violate only the OpenHCL-internal
  contract that `PRIVATE`-classified resources should match what
  would currently pass §11.2.7 Q1–Q4.

### Note on §11.2.2 SPDM-encapsulation (corrected after round 3)

**Earlier rounds incorrectly framed §11.2.2 as constraining the
OpenHCL VMBus command envelope.** Round 3 of the expert debate
corrected this:

§11.2.2 (lines 963–1028) governs only the **TSM↔DSM** wire — the
SPDM secure session terminates between the AMD SEV-PSP (acting as
TSM) and the device (DSM). That wire is out of OpenHCL's
implementation scope; it lives inside the PSP firmware and the
device.

The host-mediated VMBus `TIO_MSG_*` / TDISP-shaped command channel
between the paravisor (TVM) and the PSP (TSM) is a different
interface — the **TVM↔TSM interface** of §11.2.7 (line 1224),
described in the spec only as "a TSM-provided interface". The spec
imposes **no normative confidentiality/integrity requirements** on
the TVM↔TSM wire; the trust model addresses it structurally by
declaring the TSM in the TVM's TCB (Figure 11-2 legend, lines
716–722).

However, two spec facts make AF-iter2-1 still load-bearing:

1. **§11.2.2 line 978** explicitly anticipates the VMM being on
   the SPDM transport path: *"The TSM is permitted to use an
   untrusted channel (e.g., proxy through the VMM) to access the
   transport mechanism."* The spec contemplates the VMM as a
   carrier of opaque ciphertext.
2. **§11.6.3 names the VMM as the canonical adversary** for
   TDI-assignment attacks (lines 3041–3050).

Combined with the TVM's normative obligations under §11.2.7 and
the LOCK→REPORT→START chain of §11.6.3, the paravisor cannot omit
per-response validation of TSM replies received over a
VMM-mediated channel, because a hostile VMM is permitted to be on
that path and the spec does not give the TVM any cryptographic
recourse on it.

**Resource-layer mitigation actually in place:** every
`tdisp_unblock_mmio` / `tdisp_unblock_dma` issues a real
`TIO_MSG_*` request to the PSP via `/dev/sev-guest`
([sevtio.rs#L150-L222](../../../openhcl/openhcl_tdisp/src/sevtio.rs#L150-L222)),
so the PSP — not the host — is authoritative for whether an
unblock succeeds. **TDI state machine and TDI report are NOT
PSP-validated**: both flow from host-supplied
`GuestToHostResponse` fields with no PSP cross-check, even though
`tdisp_query_firmware_tdi_state`
([sevtio.rs#L334-L369](../../../openhcl/openhcl_tdisp/src/sevtio.rs#L334-L369))
is plumbed and ready to be called. The KB notes "no production
caller yet" (lines 1364–1369). AF-iter2-1 is therefore the
OpenHCL-internal manifestation of the TVM's §11.2.7 / §11.6.3
obligation when the TVM↔TSM interface is host-mediated.

## Counterexample (Kani)

```
GuestToHostResponse {
    result:           TdispGuestOperationErrorCode::Success,
    tdi_state_before: <any>,
    tdi_state_after:  <any value other than Unlocked, e.g. Run>,
    response:         Some(Resp::Unbind(TdispCommandResponseUnbind {})),
}
```

Failing assertion:

```
assertion failed: matches!(s.kani_tdi_state(), TdispTdiState::Unlocked)
  vm/devices/pci/vpci_client/src/kani_proofs_session.rs:165
  in m1_unbind_ok_implies_state_unlocked
```

`tdisp_unbind_inner` returns `Ok(())`. Cached `tdi_state` is now `Run`
(or any other host-chosen value), while the device has actually been
unbound (or was never unbound at all).

## Root cause

`tdisp_unbind_inner` does **not** post-check the cached `tdi_state`
after the host reply. The only `Ok` gate is the response-variant
match (`TdispCommandResponseUnbind {}`) — which the malicious host
trivially supplies.

`send_tdisp_command` ([line 529-532](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L529-L532))
unconditionally writes whatever `tdi_state_after_enum()` decodes into
the cache **before** `tdisp_unbind_inner` runs its match arm. So a
host reply with `tdi_state_after = Run` poisons the cache regardless
of any local check.

This is the **odd one out** in the file:

- `tdisp_bind_interface` ([L597-L625](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L597-L625)) post-checks `tdi_state == Locked`.
- `tdisp_start_device_inner` ([L645-L685](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L645-L685)) post-checks `tdi_state == Run`.
- `tdisp_unbind_inner` ([L821-L894](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L821-L894)) — **no equivalent check**.

The code-comment context at [L821-L829](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L821-L829)
explicitly frames the pre-RPC re-block as "best-effort" and notes
"the host-side TDI state is our only source of truth for what
remains bound" — the inverse of how Bind/Start treat the cache. There
is no comment justifying the asymmetric design choice.

## TDISP-spec basis (TDISP-expert subagent)

PCI-SIG TDISP v2022-07-27, the only spec-grounded post-state for a
successful `STOP_INTERFACE_REQUEST` is `CONFIG_UNLOCKED`:

- **§11.3.1, Table 3** ([lines 1268-1276](../../../docs/spec/TEE%20Device%20Interface%20Security%20Protocol%20-%20TDISP%20-%20v2022-07-27%20%283%29.txt#L1268-L1276)):
  `STOP_INTERFACE_REQUEST` is legal in
  `{CONFIG_UNLOCKED, CONFIG_LOCKED, RUN, ERROR}`; description: *"Stop
  and move TDI to CONFIG_UNLOCKED (if not already in CONFIG_UNLOCKED)"*.
- **§11.2** RUN/ERROR/intro ([lines 808-823](../../../docs/spec/TEE%20Device%20Interface%20Security%20Protocol%20-%20TDISP%20-%20v2022-07-27%20%283%29.txt#L808-L823)):
  *"This state [`CONFIG_UNLOCKED`] must be entered from any other state
  in response to the `STOP_INTERFACE_REQUEST` message."*
- **§11.3.16** ([lines 2030-2056](../../../docs/spec/TEE%20Device%20Interface%20Security%20Protocol%20-%20TDISP%20-%20v2022-07-27%20%283%29.txt#L2030-L2056)):
  enumerates the actions the device must perform in response to
  `STOP_INTERFACE_REQUEST` (abort in-flight, scrub internal state,
  reclaim and scrub private resources) before generating the
  response.
- **§11.3.17** ([lines 2057-2059](../../../docs/spec/TEE%20Device%20Interface%20Security%20Protocol%20-%20TDISP%20-%20v2022-07-27%20%283%29.txt#L2057-L2059)):
  *"No request-specific responses are defined."* — the wire
  `STOP_INTERFACE_RESPONSE` carries **zero** post-state metadata.
  There is no `tdi_state_after` field defined in the spec at all.
- **§11.3.13 Table 17** ([lines 1969-1985](../../../docs/spec/TEE%20Device%20Interface%20Security%20Protocol%20-%20TDISP%20-%20v2022-07-27%20%283%29.txt#L1969-L1985)):
  the only spec-defined message that returns a `TDI_STATE` byte is
  `DEVICE_INTERFACE_STATE` in response to an explicit
  `GET_DEVICE_INTERFACE_STATE` (§11.3.12).
- **§11.6.3** ([lines 3034-3101](../../../docs/spec/TEE%20Device%20Interface%20Security%20Protocol%20-%20TDISP%20-%20v2022-07-27%20%283%29.txt#L3034-L3101)):
  the entire detach-attack mitigation rests on TSM/TVM correctly
  tracking state across the lifecycle. Names *"untrusted VMM"* as the
  adversary in the assignment/detach threat model and lists
  *"asynchronously change the device state"* and *"reprogram a TDI"*
  as in-scope attacks.

**Mapping to the paravisor.** Under the OpenHCL role mapping:

- TVM = paravisor; TSM = host (adversary); DSM = device.
- The wire `STOP_INTERFACE_RESPONSE` carries **no** authoritative
  `tdi_state_after` (§11.3.17). The OpenHCL-internal field of that
  name is **purely host-fabricated metadata** when populated for the
  Unbind reply.
- §11.5 *"Requirements Placed on Host Security due to TDI"* assumes
  the host is the TSM (in the TCB). In the OpenHCL model the host is
  outside the TCB, so §11.5's "TSM tracks state" obligations migrate
  onto the paravisor — there is no other trusted party left.

The paravisor's only spec-consistent options after an `Ok` unbind are:

1. Cache `Unlocked` unconditionally, ignoring the host-supplied
   `tdi_state_after`, **or**
2. Cross-validate via an explicit `GET_DEVICE_INTERFACE_STATE`
   round-trip and reject any post-state ≠ `CONFIG_UNLOCKED`.

Caching whatever the host claimed (`Run`, `Locked`, …) is consistent
with **neither**.

## Concrete exploit (OpenHCL-expert subagent)

The hot path uses `tdisp_unbind_preserve_report`, called by
`vpci_relay::tdisp_on_device_deactivate` on the MMIO-disable edge and
on attestation failure. The `preserve` variant intentionally keeps
`tdi_report = Some(_)` across the unbind (per the design comment at
[L800+](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L800)). Per
the audit finding, the **non-preserve** path is *self-healing* — it
clears `tdi_report = None`, which makes `classify_bar` return
`INVALID` and downstream `tdisp_on_mmio_reconfigured` reject. The
**preserve** path has no such latch.

### End-to-end exploit through `vpci_relay`

This expansion was produced by the OpenHCL expert in a focused
review of `vm/devices/pci/vpci_relay/src/lib.rs`. The earlier
exploit description (below) abstracts over the relay; this section
gives the literal `vpci_relay`-driven call sequence.

#### Initial conditions

- `dev_snp_ohcl_tio_support` enabled; SNP isolation; PSP-backed
  `TdispResourceValidationInterface` is wired.
- A device has been relayed; the proactive arrival cycle in
  `relay_vpci_bus` ([lib.rs#L385-L429](../../../vm/devices/pci/vpci_relay/src/lib.rs#L385))
  succeeded:
  - `tdi_state = Unlocked` (after the proactive
    `tdisp_unbind_preserve_report(Graceful)` at
    [lib.rs#L411](../../../vm/devices/pci/vpci_relay/src/lib.rs#L411))
  - `tdi_report = Some(...)` (firmware-validated, persisted across
    the preserve-report unbind)
  - `intercepted_bars = {MSI-X BAR}`
  - `validated_mmio_bars = {}`, `dma_unblocked = false`
- Guest then enables MMIO once and operates normally:
  - Cfg write hits the MMIO-enable edge ([lib.rs#L702-L719](../../../vm/devices/pci/vpci_relay/src/lib.rs#L702)).
  - `tdisp_on_device_activate` re-attests (state was `Unlocked`),
    drives `bind→start→get_report`, ends in `Run`. BAR loop calls
    `tdisp_on_mmio_reconfigured` for each PRIVATE BAR → PSP
    `MMIO_VALIDATE_REQ` succeeds, `validated_mmio_bars` populated,
    `dma_unblocked = true`. Guest does private I/O.

#### Trigger: guest disables MMIO

Guest writes `STATUS_COMMAND` with the memory-space-enable bit
cleared. Relay's `pci_cfg_write` detects the disable edge
([lib.rs#L687-L704](../../../vm/devices/pci/vpci_relay/src/lib.rs#L687))
and dispatches a deferred future ([lib.rs#L729-L745](../../../vm/devices/pci/vpci_relay/src/lib.rs#L729)).

State at entry to the deferred future: `tdi_state = Run` ⇒ the
future calls `device.tdisp_on_device_deactivate().await`
([lib.rs#L735](../../../vm/devices/pci/vpci_relay/src/lib.rs#L735)).
`tdisp_on_device_deactivate` ([vpci_client/src/lib.rs#L996-L1035](../../../vm/devices/pci/vpci_client/src/lib.rs#L996))
sees `state == Run` and calls
`self.tdisp_unbind_preserve_report(Graceful)`.

#### Malicious-host action (AF-iter2-1)

The unbind reaches the host via `send_tdisp_command`
([vpci_client/src/tdisp.rs#L443-L546](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L443)).
The malicious host:

1. **Does NOT issue the corresponding `TIO_MSG_TDI_UNBIND_REQ` to
   the PSP.** The firmware-side TDI stays in `Run`.
2. **Replies on the VMBus channel with a wire-valid `Unbind`
   response carrying `result = Success` and `tdi_state_after = Run`**
   (or `Locked`).

Both fields pass `validate_response` ([tdisp/src/serialize_proto.rs#L94-L116](../../../vm/devices/tdisp/src/serialize_proto.rs#L94));
that function only enforces `require_enum!(response.tdi_state_after,
TdispTdiState)` and has no awareness of which command the response
answers, so any of `Uninitialized | Unlocked | Locked | Run` is
structurally accepted.

#### What the paravisor does next

Inside `send_tdisp_command` ([vpci_client/src/tdisp.rs#L528-L531](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L528)):

```rust
match res.tdi_state_after_enum() {
    Some(state) => self.mutable_state.update_tdi_state(state),  // ← stores Run unconditionally
    None => tracing::warn!("host did not return valid TDI state in response"),
}
```

Then control returns to `tdisp_unbind_inner`
([vpci_client/src/tdisp.rs#L869-L890](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L869)).
The `match res.response::<TdispCommandResponseUnbind>()` arm matches
`Ok(_)`, runs:

- `validated_mmio_bars.clear()` (production)
- `dma_unblocked = false`
- `tdi_report` **NOT cleared** (preserve-report path:
  `clear_cached_report = false`)
- returns `Ok(())`

**There is no post-check that
`mutable_state.tdi_state == Unlocked`** — the AF-iter2-1 defect.
Cached state is now `Run`, the cached report is still the original
firmware-validated one, but `validated_mmio_bars` is empty and the
firmware-side TDI is still `Run` (because the host never told it
otherwise).

Back in the relay's deferred future, `tdisp_on_device_deactivate`
returns. The relay completes the deferred cfg write
([lib.rs#L739-L741](../../../vm/devices/pci/vpci_relay/src/lib.rs#L739))
— `STATUS_COMMAND` now has MMIO-disabled visible to both the guest's
shadow and the host's cfg space.

#### Stage 1 — confidentiality lie via `QueryIsolatedResources`

Guest issues `VPCI_QUERY_ISOLATED_RESOURCES` (`0x4249001E`).
Server-side, the `vpci` device dispatches to
`dev.supports_tdisp_isolation()` →
`RelayedVpciDevice::tdisp_isolation_report` ([lib.rs#L621-L666](../../../vm/devices/pci/vpci_relay/src/lib.rs#L621))
→ `tdisp_try_isolation_snapshot` → `isolation_snapshot()`
([vpci_client/src/tdisp.rs#L1253-L1289](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L1253)):

- `tdi_report` is `Some` ⇒ returns
  `IsolationSnapshot::Ready { bars: [...PRIVATE/SHARED per cached report...], dma: SHARED }`.

The reply is built with no host involvement and tells the guest
"BAR n is PRIVATE." The guest's reasonable interpretation per the
spec contract: "the paravisor will arrange for BAR n to be host-
inaccessible memory once I bring MMIO back up." That's not actually
what is queued for the next activate — see Stage 2.

#### Stage 2 — bypass of re-attestation on the next MMIO-enable

Guest re-enables MMIO. The MMIO-enable edge in `pci_cfg_write`
([lib.rs#L693-L719](../../../vm/devices/pci/vpci_relay/src/lib.rs#L693))
runs the cfg write then dispatches `tdisp_on_device_activate`.

In `tdisp_on_device_activate` ([vpci_client/src/lib.rs#L843-L876](../../../vm/devices/pci/vpci_client/src/lib.rs#L843)):

```rust
let state = self.tdisp_tdi_state().await;
if state != TdispTdiState::Run {           // ← cached state is Run (poisoned)
    /* attest path: query_capabilities, tdisp_attest_device, rollback ... */
}
// Falls straight through to the BAR loop without ever calling
// query_capabilities, tdisp_bind_interface, tdisp_start_device,
// tdisp_get_tdi_device_id, or tdisp_get_tdi_report.
```

The relay therefore **skips the entire fresh chain-of-custody
cycle**:

- No re-fetch of device interface info — bypasses any chance to
  detect that the host has substituted a different device.
- No `bind/start` — no fresh handshake at the firmware identifying
  *this* TDI.
- No fresh `get_tdi_report` — `intercepted_bars` and
  `mmio_interface_info` from the **previous** cycle are reused for
  `classify_bar`.
- `guest_device_id` retains its value from the previous cycle
  ([vpci_client/src/tdisp.rs#L1390](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L1390)).

The BAR loop then calls
`tdisp_on_mmio_reconfigured(bar_id, new_base, new_length)` for
whatever the guest's new BAR-shadow values are
([vpci_client/src/lib.rs#L878-L935](../../../vm/devices/pci/vpci_client/src/lib.rs#L878)).
Inside `tdisp_on_mmio_reconfigured_inner`
([vpci_client/src/tdisp.rs#L1318-L1450](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L1318)):

- `tdi_state() != Run` check: passes (state poisoned to `Run`).
- `validated_mmio_bars.contains_key(bar_id)`: false (was cleared on
  the unbind).
- `classify_bar(bar_id)`: PRIVATE, from the **stale cached report**.
- Falls into the PRIVATE arm; calls
  `validator.tdisp_unblock_mmio(self.target_vtl,
  guest_device_id_OLD, base_address_NEW, 0, length_NEW, bar_id)`.
- On the first BAR with `dma_unblocked == false`, also fires
  `tdisp_unblock_dma(target_vtl, guest_device_id_OLD)`.

#### Concrete observable break

- The PSP receives `MMIO_VALIDATE_REQ` and `DMA_UNBLOCK_REQ` for a
  TDI that — from the firmware's point of view — never left `Run`.
  The host never issued `TDI_UNBIND_REQ`, so the firmware's TDI
  context is intact. Whether the PSP accepts the new
  `MMIO_VALIDATE_REQ` for the new GPA depends on its own admission
  rules, but the **paravisor has stopped enforcing its TVM-side
  obligation** to refuse unblocks for a TDI whose attestation chain
  has been cycled.
- The guest is told (via Stage 1's `QueryIsolatedResources`) that
  BAR n is PRIVATE based on the previous cycle's report; whether
  that is honored depends on whether the PSP accepts the unblock on
  the new GPA, but the guest has no signal that no fresh
  attestation took place.
- Even in the conservative case where the PSP rejects, the host has
  gained an oracle: it can bait the paravisor into emitting
  paravisor-authoritative `tdisp_unblock_mmio` calls for arbitrary
  GPAs of the host's choosing, against a stale `guest_device_id`,
  without going through `query_capabilities`/`bind`/`start`.

#### Why the precautionary-unbind branch in `attest()` does NOT save us

The hot path bypasses `attest()` entirely.
`tdisp_on_device_activate`'s precondition `state != Run` gates the
call into `tdisp_attest_device`, and that precondition is exactly
what AF-iter2-1 lets the host falsify. The self-healing in
`attest()`'s unbind-then-rebind branch
([vpci_client/src/tdisp.rs#L1027-L1037](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L1027))
is only reachable on the **cold** path where state is observed
`!= Run` — which the exploit avoids.

### Earlier (relay-agnostic) version of the exploit

### Exploit sequence

1. Honest attestation completes. Cache: `tdi_state = Run`,
   `tdi_report = Some(R)` for some report `R` whose MMIO range `i`
   has `is_non_tee_mem = false`. Guest enables MMIO;
   `validated_mmio_bars` populated.

2. Guest disables MMIO. `vpci_relay::tdisp_on_device_deactivate` →
   `tdisp_unbind_preserve_report(Graceful)`.

3. `tdisp_unbind_inner`: pre-flips MMIO/DMA back to SHARED via
   `tdisp_block_*` (good — M-6 is satisfied). Sends Unbind RPC.

4. **Malicious host** replies:
   ```
   { result: Success,
     tdi_state_after: Run,
     response: Some(Resp::Unbind(_)) }
   ```
   `send_tdisp_command` writes `Run` into the cache. The Ok arm of
   `tdisp_unbind_inner` clears `validated_mmio_bars` and
   `dma_unblocked` but **leaves `tdi_report = Some(R)` and
   `tdi_state = Run`**. Returns `Ok(())`. **M-1 violated.**

5. Guest re-enables MMIO at attacker-coordinated BAR base address
   `B` and length `L` (the guest controls BAR programming).
   `vpci_relay` calls `tdisp_on_device_activate`.

6. `tdisp_on_device_activate` ([lib.rs#L843-L879](../../../vm/devices/pci/vpci_client/src/lib.rs#L843-L879))
   reads `state == Run` → **skips attestation entirely**. Walks
   `bars[]` and calls `tdisp_on_mmio_reconfigured(i, B, L)`.

7. `tdisp_on_mmio_reconfigured_inner`:
   - `tdi_state() != Run` → false (cache is poisoned). Pass.
   - `validated_mmio_bars.contains_key(i)` → false (cleared at
     step 4). Pass.
   - `classify_bar(i)` → `PRIVATE` (cached report still present;
     range `i` is TEE memory). Pass.
   - Calls `validator.tdisp_unblock_mmio(target_vtl, device_id, B, 0,
     L, i)` with **guest-controlled `B`/`L` against a TDI the
     firmware believes is Unlocked**.

8. **Branch on validator implementation:**

   - **SEV-TIO path** ([sevtio.rs](../../../openhcl/openhcl_tdisp/src/sevtio.rs)):
     mshv flips the page range at `B..B+L` to PRIVATE (host loses
     access to those HPAs); PSP receives `MMIO_VALIDATE_REQ` for an
     Unlocked TDI; expected to reject; `?` propagates `Err`;
     `validated_mmio_bars` not inserted; `dma_unblocked` not set.
     Net effect: **DoS** (host pages stranded as PRIVATE without a
     guest VMPL grant; the next bona-fide bind would re-validate).
     Confidentiality preserved **only by the firmware reject**, which
     the paravisor never verifies.

   - **`TdispNoopResourceValidator` path** ([mocks.rs](../../../openhcl/openhcl_tdisp/src/mocks.rs)):
     unblock returns `Ok(())`. `validated_mmio_bars.insert(i, {B, L})`,
     `dma_unblocked = true`. `isolation_snapshot()` now reports BAR
     `i` as `PRIVATE` and DMA as `PRIVATE` to the guest's
     `QueryIsolatedResources`. Guest treats BAR `i` as a
     confidentiality-protected MMIO region and writes secrets.
     **Confidentiality breach.** This path matters for any non-SEV-
     TIO build (tests, future TDX validator that doesn't replicate
     the PSP's firmware-state check, etc.).

9. Bonus: even on the SEV-TIO path, the cached `tdi_state = Run`
   makes a subsequent `tdisp_on_device_deactivate` ([lib.rs#L956-L962](../../../vm/devices/pci/vpci_client/src/lib.rs#L956-L962))
   re-fire `tdisp_unbind_preserve_report` — the host can repeat the
   lie and keep the cache pinned indefinitely, blocking the relay
   from realizing the device is actually unbound.

### Why mitigations elsewhere don't close this

- **`tdisp_query_firmware_tdi_state`** trait ([openhcl_tdisp/src/lib.rs](../../../openhcl/openhcl_tdisp/src/lib.rs))
  has **no production caller** in the current code (per
  [docs/openhcl-knowledge-base.md#L1359-L1369](../../openhcl-knowledge-base.md#L1359-L1369),
  step 7). The PSP-state cross-check is wired but never invoked.
- The SEV-TIO PSP rejecting `MMIO_VALIDATE_REQ` on an Unlocked TDI
  is the *only* realistic backstop for the SEV-TIO branch, and it is
  not Rust code in this repository — it is firmware behaviour the
  paravisor relies on without verifying from the static call graph.
- The `attest()` precautionary-unbind branch ([L1015-L1100](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L1015-L1100))
  IS self-healing (it calls the **non-preserve** unbind, which
  clears `tdi_report` and latches subsequent `classify_bar` to
  `INVALID`). But this branch is reached only via `attest()`, not via
  the post-unbind MMIO-reconfiguration path described in steps 5-8
  above.

## Defense against "this is the host's job, not the TVM's"

PCI-SIG TDISP §11.5 assumes the host is the TSM and is *part of the
TCB*. In the OpenHCL threat model the host is *outside* the TCB, so
§11.5's "TSM tracks state" obligations migrate onto the paravisor.
§11.6.3 explicitly names *"an untrusted VMM"* as the adversary and
lists *"asynchronously change the device state"* and *"reprogram a
TDI"* as in-scope attacks; the spec mitigation is the **TSM/TVM-side
state tracking plus the LOCK/REPORT/START chain**. Ceding state
tracking to host-supplied metadata discards the mitigation while
remaining inside the threat model.

The wire spec also leaves no room to argue "I trusted the host's
`tdi_state_after`": §11.3.17 simply does not define any such field
for `STOP_INTERFACE_RESPONSE`. There is nothing on the wire to
trust.

## Recommended fix

Local one-paragraph patch in [tdisp_unbind_inner](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L874-L894),
after the `match res.response::<TdispCommandResponseUnbind>()` Ok arm,
mirroring the existing Bind/Start patterns:

```rust
match self.tdi_state() {
    TdispTdiState::Unlocked => { /* good */ }
    state_after => {
        tracing::error!(
            %state_after,
            "device in unexpected TDI state after unbind, expected Unlocked"
        );
        return Err(crate::err!(
            "device in unexpected TDI state after unbind, expected Unlocked"
        ));
    }
}
```

### Defense-in-depth (recommended)

- On the new `Err` path, **force** `tdi_state = Unlocked` and clear
  `tdi_report = None` so a lying host cannot keep the cache pinned
  across repeated calls.
- Consider centralizing the gate at `send_tdisp_command`: maintain a
  per-opcode expected-post-state table and refuse to write
  `tdi_state_after` into the cache when the response disagrees.
- Wire a production caller of `tdisp_query_firmware_tdi_state` at
  attestation boundaries on the SEV-TIO path so the PSP backstop is
  observed by Rust code rather than implicit.

## Open questions

1. (TDISP/SEV-TIO expert) Does AMD SEV-TIO firmware actually reject
   `TIO_MSG_MMIO_VALIDATE_REQ` when the targeted TDI is in
   `TIO_TDI_STATE_UNLOCKED`? If not, the SEV-TIO path is also a
   confidentiality breach, not DoS-only.
2. (TDISP expert) Same question for `TIO_MSG_SDTE_WRITE_REQ` against
   an Unlocked TDI — reject, allow, or silent no-op?
3. (Maintainer) Is `tdisp_query_firmware_tdi_state` intended to be
   invoked at every cache write, or only at attestation boundaries?
   Affects whether the fix should be the local post-check above or a
   broader refactor.
