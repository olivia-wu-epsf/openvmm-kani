# AF-iter2-1 — Round-2 expert debate transcript

A second adjudication round between the TDISP-spec expert and the
OpenHCL paravisor expert tightened the spec grounding of AF-iter2-1.
Both experts were skill-restricted (TDISP-spec expert: PCI-SIG TDISP
v2022-07-27 only; OpenHCL expert: openhcl-knowledge-base only). No
`docs/tdisp-*.md` was consulted by either expert.

This document captures the debate verbatim. The canonical AF-iter2-1
finding statement that resulted from this debate lives in
[../kani-iteration-2/findings/m1-unbind-missing-post-check.md](../kani-iteration-2/findings/m1-unbind-missing-post-check.md).

---

## Round 2 Step 1 — OpenHCL expert explains the exploit

The OpenHCL expert produced a 7-section rigorous walkthrough of the
relay-driven AF-iter2-1 exploit:

1. **Threat model recap** — host VMM is fully adversarial; controls
   the wire on the host-side VPCI channel; TVM is OpenHCL paravisor
   in VTL2 of an SNP CVM; PSP authoritatively tracks firmware-side
   TDI state; cached TVM state can diverge.
2. **Code surface** — `VpciClientTdispMutableState`'s seven cached
   fields; relay-side proactive attestation; activate/deactivate
   edges; `TdispResourceValidationInterface` validator;
   `validate_response` wire-format gate.
3. **The defect** — `tdisp_unbind_inner` lacks the post-state check
   that Bind/Start have; the doc comment at [tdisp.rs#L821-L829](../../vm/devices/pci/vpci_client/src/tdisp.rs#L821-L829)
   ("the host-side TDI state is our only source of truth") is wrong
   under the malicious-host model.
4. **Initial cycle (N)** — proactive `relay_vpci_bus` attest →
   preserve-report unbind leaves cache with `tdi_state=Unlocked`,
   `tdi_report=Some(cycle-N report)`, `intercepted_bars=cycle-N`,
   `cached_capabilities=cycle-N`, `guest_device_id=cycle-N`.
5. **Trigger** — guest disables MMIO; relay defers cfg write; runs
   `tdisp_on_device_deactivate` which calls
   `tdisp_unbind_preserve_report(Graceful)`.
6. **The exploit** — host returns wire-valid Unbind with
   `tdi_state_after = Run`; `validate_response` accepts;
   `send_tdisp_command` calls `update_tdi_state(Run)`;
   `tdisp_unbind_inner`'s Ok arm clears `validated_mmio_bars` and
   `dma_unblocked` but never re-checks `tdi_state` and never clears
   `tdi_report`. End-state: cache shows `Run` while firmware-side
   TDI is truly `CONFIG_UNLOCKED`.
7. **The break** —
   - **(a)** Re-enable bypasses re-attestation:
     `tdisp_on_device_activate` reads `state == Run` and skips
     bind/attest; falls through to `tdisp_on_mmio_reconfigured`
     against stale `guest_device_id` and stale report; calls
     `tdisp_unblock_mmio`/`tdisp_unblock_dma` which reach
     `TdispSevTioResourceValidator` and flip PFNs to PRIVATE,
     send `TIO_MSG_MMIO_VALIDATE_REQ`/`TIO_MSG_SDTE_WRITE_REQ`
     against a stale device id, `RMPADJUST` for guest VMPL — all
     without fresh attestation.
   - **(b)** `QueryIsolatedResources` lies — `isolation_snapshot()`
     returns `Ready { ... PRIVATE ... }` from the stale cached
     report.

   **Initial precise security claim**: "TVM admits MMIO and DMA
   into its TCB after a TDI lifecycle event the spec requires to
   leave the TDI in `CONFIG_UNLOCKED`. Violates TVM-role
   obligation derived from TDISP §11.2.7 acceptance Q4."

---

## Round 2 Step 2 — TDISP expert challenges, per-section

### §1 — Threat model framing — **REFINE**

> The spec does not contemplate a "host VMM controls the wire on
> the host-side VPCI channel that carries the TDISP guest-to-host
> command/response stream", because in the spec there is no such
> channel. Per **§11.2.2 (lines 963–1028)**, TDISP messages are
> TSM↔DSM only, encapsulated as SPDM Vendor-Defined Messages
> inside a Secured SPDM session with AES-256-GCM AEAD; lines
> 1026–1028 are explicit: *"If a TDISP message is received that
> has not been transferred securely per [Secured SPDM], the
> received TDISP message must not be used, and must not result in
> a response."* The TVM does not exchange TDISP wire messages
> with anyone — per **§11.2.7 line 1224**, the TVM *"queries the
> TSM using a TSM-provided interface."* So the threat model the
> OpenHCL expert describes ("host lies on the TDISP wire to the
> TVM") is not a threat model the spec enumerates; the spec
> assumes the TVM↔TSM interface is trusted and the TSM↔DSM wire
> is SPDM-protected. Restate the threat: *the OpenHCL paravisor
> exposes a host-VMBus-tunneled, non-SPDM, non-spec command
> envelope, and treats host-asserted fields in that envelope as
> authoritative for TDI state.*

### §2 — Code surface — **ACCEPT**

Descriptive; no spec claim.

### §3 — The defect — **REFINE**

> The description of the cache update is correct as code, but the
> framing "the Ok arm of `tdisp_unbind_inner` does not verify
> post-state is `Unlocked`" cannot be grounded in the TDISP wire
> protocol because **§11.3.17 (lines 2056–2059)** is explicit:
> *"No request-specific responses are defined."* There is no
> `tdi_state_after` field in `STOP_INTERFACE_RESPONSE` for the TVM
> (or anyone) to verify. The proper spec-grounded statement is:
> per the state diagram **§11.2 Figure 11-5 (lines 770–795)**,
> STOP_INTERFACE_REQUEST unconditionally transitions the TDI from
> any state → CONFIG_UNLOCKED, and per §11.3.16 (lines 2030–2050)
> the device must drain DMA/ATS/PRI and scrub TDI secrets before
> responding. Hence after an UNBIND/STOP the TVM's spec-mandated
> belief is `CONFIG_UNLOCKED`; sourcing post-state from a
> host-controlled non-spec field (instead of either deriving it
> from Figure 11-5 or querying the trusted TSM oracle) is the
> OpenHCL-internal defect.

### §4 — Initial cycle (N) — **ACCEPT**

Note: the proactive Bind→Start→GetReport→Unbind dance is itself
outside the spec — the spec models LOCK→START as the TVM's
acceptance moment, not as a pre-attestation pass. Orthogonal to
AF-iter2-1.

### §5 — Trigger — **REFINE**

> Worth flagging that per **§11.2.6 Command-register row (lines
> ~1090)**, *"Clearing any of the following bits causes the TDI
> hosted by the Function to transition to ERROR: Memory Space
> Enable, Bus Master Enable."* The spec's expected behavior on a
> guest CMD-register clear is **DSM-driven transition to ERROR**,
> not a TSM-driven graceful Unbind preserving the report. So the
> OpenHCL "deactivate via Unbind/preserve-report and
> re-activate-bypassing-attest" lifecycle is *itself* a divergence
> from the spec's intent. Re-entering use of the TDI from ERROR
> requires re-LOCK from CONFIG_UNLOCKED via the
> ERROR→CONFIG_UNLOCKED edge in Figure 11-5, which mints a new
> nonce (§11.3.9 lines 1670–1675).

### §6 — The exploit — **REFINE**

> The mechanical claim is correct as a paravisor-internal-cache
> exploit: the host can return whatever it likes in OpenHCL's
> home-grown `tdi_state_after` envelope field, and OpenHCL's
> `send_tdisp_command` will unconditionally cache it. But this is
> **not** a TDISP wire-protocol violation, because the field
> doesn't exist in the spec (§11.3.17). The exploit is a
> violation of an OpenHCL-internal cache invariant that *should*
> be: "TDI state after STOP is CONFIG_UNLOCKED per Figure 11-5,
> regardless of any wire field." The downstream consequence
> (cycle-(N+1) admission into TCB without re-attestation) does
> still hold under this corrected framing.

### §7(a) — Re-enable bypasses re-attestation — **REFINE then ACCEPT**

> The OpenHCL expert paraphrases §11.2.7 Q4 as *"verify the new
> mapping against a fresh interface report"*. The literal Q4
> (§11.2.7 line 1218) reads: *"Has the VMM configured the TDI and
> mapped the TDI into the TVM address space as expected?"* —
> answered "with support from the TSM" using the
> GET_DEVICE_INTERFACE_REPORT (§11.2.7 lines 1222–1224). Q4 by
> itself does not flatly say "fresh report on every Unlocked→
> Locked transition." However, the obligation IS spec-grounded by
> composition:
>
> - **§11.2.7 (lines 1207–1227)** — Q1–Q4 must be answered
>   *"before [the TVM] accepts a TDI into its TCB."* A re-entry
>   into the TCB after CONFIG_UNLOCKED is a fresh acceptance
>   event.
> - **§11.3.10 (lines 1712–1715)** — `GET_DEVICE_INTERFACE_REPORT`
>   MUST fail when *"TDI is not in CONFIG_LOCKED or RUN."* A
>   report obtained in cycle N is therefore bound to that LOCK
>   lifetime.
> - **§11.3.9 (lines 1670–1675)** — *"This nonce must be destroyed
>   when the TDI moves to CONFIG_UNLOCKED or ERROR from
>   CONFIG_LOCKED."* The cycle-N START credential is gone after
>   UNBIND/STOP.
> - **§11.2.6 (lines 1057–1066)** — DSM tracks configuration
>   changes only *"affecting any … Function hosting a TDI in
>   CONFIG_LOCKED or RUN."* A CONFIG_UNLOCKED interval breaks the
>   change-tracking guarantee that gives the prior report its
>   meaning.
> - **§11.6.3 (lines 3057–3061)** — *"A nonce generated by the
>   device when the TDI is transitioned to CONFIG_LOCKED and
>   verified on request to transition to RUN provide the property
>   that all transitions through the TDISP state machine occur due
>   to TDISP requests generated in the same SPDM secure session."*
>
> So: a cached report from cycle N is bound to (i) a destroyed
> nonce, (ii) a closed LOCK lifetime, and (iii) a configuration-
> tracking interval the device is no longer guaranteed to have
> maintained. Reusing it to admit cycle-(N+1) MMIO is incompatible
> with §11.6.3 chain-of-custody.

### §7(b) — `QueryIsolatedResources` lies — **CHALLENGE as worded**

> `QueryIsolatedResources` and `IsolationSnapshot` are not TDISP
> terms; they appear nowhere in §11.3 message tables. They cannot
> violate the TDISP spec — only the OpenHCL-internal contract
> that the paravisor's TCB-membership view tracks reality. The
> spec does not regulate the TVM's internal APIs.

---

## Round 2 Step 3 — OpenHCL expert responds

### Per-point disposition

1. **Threat model**: ACCEPT. KB does not contradict; TDISP path is
   over VMBus (`VPCI_TDISP_COMMAND` `0x4249001D`), not SPDM. No
   SPDM machinery anywhere in the relevant crates.
2. **`tdi_state_after` framing**: ACCEPT (with code-side note).
   `tdi_state_after` is on OpenHCL's `GuestToHostResponse`
   envelope at [vpci_client/src/tdisp.rs#L488-L491](../../vm/devices/pci/vpci_client/src/tdisp.rs#L488-L491),
   consumed for *every* response not just StopInterface. Restate:
   after STOP/Unbind the paravisor should derive
   "CONFIG_UNLOCKED" from §11.2 Figure 11-5, not from a
   host-asserted byte. KB audit finding #2 already flags the
   related desync (lines 1370–1388).
3. **§11.2.6 Command-register**: DEFER. Spec-level claim about DSM
   behavior, outside OpenHCL-expert scope. Agree it's orthogonal
   to AF-iter2-1.
4. **§11.2.7 Q4 vs. composite citation**: ACCEPT. Composite
   citation matches what the code actually fails to do. Cached
   `tdi_report` survives `tdisp_unbind_preserve_report`
   ([#L823-L836](../../vm/devices/pci/vpci_client/src/tdisp.rs#L823-L836)),
   and `attest()` at [#L1011-L1099](../../vm/devices/pci/vpci_client/src/tdisp.rs#L1011-L1099)
   re-issues `Bind→Start→GetTdiReport` but never binds the new
   report to a fresh nonce that the paravisor itself generated.
   KB audit finding #3 acknowledges this directly.
5. **`QueryIsolatedResources` is OpenHCL-internal**: ACCEPT.
   `IsolationSnapshot::Ready` is gated only on
   `tdi_report.is_some()` ([#L1254-L1270](../../vm/devices/pci/vpci_client/src/tdisp.rs#L1254-L1270))
   — does not consult `TdispTdiState`, so a TDI currently
   `Unlocked` (after preserve-report unbind) still answers
   `Ready { ... PRIVATE ... }`. The downstream symptom; the
   spec violation is upstream in the missing acceptance check.

### Final restated security claim — **ACCEPT verbatim**

> The OpenHCL paravisor (acting as TVM) admits MMIO mappings and
> DMA permissions into its TCB on a re-LOCK cycle without
> re-evaluating §11.2.7 Q1–Q4 — in particular without obtaining a
> fresh `DEVICE_INTERFACE_REPORT` (§11.3.10) bound to the cycle's
> new `START_INTERFACE_NONCE` (§11.3.9, §11.3.14). This breaks
> the per-LOCK chain-of-custody §11.6.3 relies on, and realizes
> the §11.6.3-enumerated MMIO-remapping / TDI-reprogramming
> threats. The paravisor-internal `QueryIsolatedResources`
> returning stale `PRIVATE` is a downstream symptom of the broken
> acceptance check, not a separate spec violation.

### §11.2.2 SPDM-encapsulation — partial **COUNTER**, partial **ACCEPT**

After reading [openhcl/openhcl_tdisp/src/sevtio.rs](../../openhcl/openhcl_tdisp/src/sevtio.rs)
and [vpci_client/src/tdisp.rs](../../vm/devices/pci/vpci_client/src/tdisp.rs):

- **Resource gating IS PSP-backed.** Every `tdisp_unblock_mmio`
  issues `TIO_MSG_MMIO_VALIDATE_REQ` ([sevtio.rs#L150-L177](../../openhcl/openhcl_tdisp/src/sevtio.rs#L150-L177))
  and bails on non-zero PSP status. Every `tdisp_unblock_dma` /
  `tdisp_block_dma` issues `TIO_MSG_SDTE_WRITE_REQ`
  ([sevtio.rs#L208-L222](../../openhcl/openhcl_tdisp/src/sevtio.rs#L208-L222),
  [#L321-L349](../../openhcl/openhcl_tdisp/src/sevtio.rs#L321-L349)).
  KB lines 1361–1369 confirm: *"The PSP — not the host — is the
  authority on whether the unblock succeeds."*
- **TDI state-machine cache and TDI report are NOT PSP-backed.**
  Cached `tdi_state` is updated unconditionally from the host's
  `res.tdi_state_after_enum()` at [#L488-L491](../../vm/devices/pci/vpci_client/src/tdisp.rs#L488-L491).
  TDI interface report fed to `attest()` is whatever the host
  returns to `GetTdiReport` at [#L992-L1006](../../vm/devices/pci/vpci_client/src/tdisp.rs#L992-L1006)
  — paravisor does not verify a measurement signature, does not
  bind it to a paravisor-generated nonce, does not cross-check
  against a fresh `tio_msg_tdi_info_req` PSP query.
- **`tdisp_unbind` is NOT an exception.**
  `tdisp_unbind_inner` ([#L823-L890](../../vm/devices/pci/vpci_client/src/tdisp.rs#L823-L890))
  does call `validator.tdisp_block_mmio` / `tdisp_block_dma`
  (which DO consult the PSP for the *resource* op), but the cached
  `tdi_state` is then updated from the **host's** Unbind response
  via the same `send_tdisp_command` path, and
  `tdisp_query_firmware_tdi_state` is not called.
- **Architectural choice or oversight?** The PSP-backed *resource*
  design IS documented (KB lines 1361–1369). The PSP-backed
  *state/report* design is plumbed but not wired:
  `tdisp_query_firmware_tdi_state` was added in commit `936d0471`
  and the SEV-TIO impl returns a real `TioMsgTdiStatus` translation
  at [sevtio.rs#L334-L369](../../openhcl/openhcl_tdisp/src/sevtio.rs#L334-L369)
  — but **the KB explicitly notes "no production caller yet"**
  (lines 1364–1369). So the state/report side is best
  characterized as a **known gap with plumbing in place, not a
  documented architectural choice**.

### Final note on §11.2.2

> The TDISP wire path in OpenHCL traverses VMBus directly via
> `send_tdisp_command` at [vpci_client/src/tdisp.rs#L463-L524](../../vm/devices/pci/vpci_client/src/tdisp.rs#L463-L524),
> with no TSM↔DSM SPDM session anywhere in the paravisor — strict
> reading of §11.2.2 lines 1026–1028 ("TDISP messages shall not be
> transferred unless transferred securely") puts the OpenHCL
> design at odds with the wire-protocol normative. The design *can*
> be defended only if every security-bearing field is sourced from
> the SEV-PSP via `TIO_MSG_*` and the VMBus envelope is treated as
> a pure untrusted control-plane proxy. Today, that defense holds
> for the **resource layer** but **does not hold for the TDI state
> machine and TDI report** — both flow from host-supplied
> `GuestToHostResponse` fields with no PSP cross-check, even
> though `tdisp_query_firmware_tdi_state` ([sevtio.rs#L334-L369](../../openhcl/openhcl_tdisp/src/sevtio.rs#L334-L369))
> is plumbed and ready to be called. AF-iter2-1 is therefore the
> OpenHCL-internal manifestation of the §11.2.2 trust-boundary
> rule.

---

## Convergence (round 2)

Both experts agreed on:
- TRUE POSITIVE finding (unchanged from round 1).
- Spec-grounding tightened from "§11.2.7 Q4" to a composite citation
  (§11.2.7 + §11.3.9 + §11.3.10 + §11.2.6 + §11.6.3).
- The "host lies via `tdi_state_after`" framing is paravisor-
  internal, not a TDISP wire-protocol violation; the
  spec-correct framing is "paravisor must derive
  post-Unbind state == `CONFIG_UNLOCKED` from §11.2 Figure 11-5".
- `QueryIsolatedResources` returning stale `PRIVATE` is a
  downstream symptom, not an independent spec violation.
- A deeper systemic question (§11.2.2 SPDM encapsulation) was
  surfaced — but **see round 3 correction below: the round-2
  framing of §11.2.2 was incorrect**.

---

## Round 3 — TSM/host distinction correction

The user flagged a misconception in the round-2 framing:

> *"The TSM is in the TCB and it is NOT the untrusted host or VMM.
> It is a hardware module on the TVM host hardware (e.g. AMD PSP
> for SEV-TIO). The host/VMM is a separate untrusted entity that
> mediates the TDISP state transition messages between the TVM
> and the TSM."*
>
> *"Is the SPDM session established between the TSM and the DSM,
> or is it owned by the TVM? The user thinks it is between the
> TSM and the DSM, but the host/VMM has to mediate the TDISP
> state transition messages between the TVM and the TSM."*

The TDISP-spec expert re-read §11.1, §11.2.1, §11.2.2, §11.2.4,
§11.2.7, Figure 11-2, and §11.6, and produced these
spec-grounded answers:

### Q1. Is the TSM in the TCB or is it the untrusted host/VMM?

**The TSM is in the TCB. The VMM is explicitly NOT in the TCB.**
The two are distinct host-side entities.

- **Figure 11-2 legend** (lines 716–722) classifies host-side
  entities into three colors:
  - "In TCB of TVMs accepting the device" — **TSM**, IDE/TA on
    the host side
  - "Not in TVM TCB" — **VMM**, Legacy VM, PF Driver, PF
- **§11.1, line 444:** *"The TEE-I/O security model does not
  require the VMM to be trusted by TVMs."*
- **§11.1, lines 730–733** (just below Figure 11-2): *"Typically,
  a PF is the resource management entity for a TDI and is managed
  by the PF driver in the VMM. The VMM and the PF driver are not
  required to be in the TCB of the TVMs."*
- **§11.1, lines 762–768** (TSM functions): the TSM "Provides
  interfaces to the VMM to assign memory, CPU, and TDI resources
  to TVMs", "Implements the security mechanisms and access
  controls (e.g., IOMMU translation tables, etc.) to protect
  confidentiality and integrity of the TVM data and execution
  state in the host", and "Use[s] TDISP protocol to manage the
  security state of the TDIs". These are **trusted** host-side
  functions performed by an entity that is *not* the VMM.

The spec does not name the physical realization of the TSM (e.g.,
SEV-PSP, TDX-module), but Figure 11-2 places it inside the "TEE
I/O Capable Host" box as a peer of the VMM and TVMs.

> **Verdict:** The user is correct. The TSM ≠ VMM. The TSM is in
> the TVM's TCB.

### Q2. SPDM session endpoints

**The SPDM secure session terminates at TSM ↔ DSM, not at the
TVM.** The VMM is permitted to act as an *untrusted transport
carrier* for the SPDM bytes (it sees only ciphertext).

- **§11.1, lines 779–783:** *"Secured messages as specified in
  Section [6.31] are used by TSM and DSM to communicate TDISP
  messages securely. The secure session establishment is used by
  the TSM to authenticate the DSM…"*
- **§11.2.2, lines 963–966:** *"All TDISP messages must be
  transported between TSM and DSM using secured messages…"*
- **§11.2.2, lines 977–979:** *"The [SPDM] Requester role is
  assumed by the TSM in the host and the Responder role is
  assumed by the DSM. The TSM is permitted to use an untrusted
  channel (e.g., proxy through the VMM) to access the transport
  mechanism."* — The VMM may ferry the encrypted SPDM bytes; the
  cryptographic endpoints are TSM and DSM.
- **§11.2.7, line 1217 (Question 2):** *"Is there a SPDM secure
  session established between the TSM and the DSM…"* — The TVM
  does not own the SPDM session; it asks whether one exists
  between TSM and DSM.

> **Verdict:** The user's first claim is correct. SPDM is TSM ↔
> DSM. The TVM is a *consumer* of the result via a separate
> TSM-provided interface (Q3 below).

### Q3. Who mediates TDISP state-transition messages between the TVM and the TSM?

**The spec does not specify a wire protocol or transport for the
TVM ↔ TSM interface.** It only says the TVM uses a "TSM-provided
interface" to query the TSM.

- **§11.2.7, line 1224:** *"The TVM queries the TSM using a
  TSM-provided interface to determine the answers to questions 1,
  2 and 3."*
- **No section** defines a wire protocol for the TVM↔TSM
  interface, names a transport for it, or describes what the
  VMM's role is in carrying it. The spec scope ends at
  "TSM-provided interface."

> **Verdict (with caveat):** Underdetermined by spec alone. The
> OpenHCL architectural choice to ferry TVM→TSM commands over a
> host-mediated VMBus channel is permitted by the spec (the spec
> is silent on this transport), but it is *not required* by the
> spec, and it is also *not blessed* by the spec.

### Q4. Spec-defined trust relationship between TVM and TSM

**The TVM↔TSM interface is trusted by definition** — the TSM is
declared in the TVM's TCB whenever the TVM accepts a TDI. The
spec does not require cryptographic protection on the TVM↔TSM
interface and does not specify what makes it trustworthy.

- The spec **does not** define attestation of the TSM to the TVM,
  key exchange between TVM and TSM, or replay/integrity protection
  on the TVM↔TSM interface. The trust is structural (TCB
  membership), not protocol-level.

> **Verdict:** The TVM↔TSM relationship is **structurally trusted
> by spec**, with the trust mechanism left entirely to the
> platform.

### Q5. Where the VMM appears in the spec

The VMM is mentioned in three normatively meaningful capacities,
all of which assume it is **untrusted by the TVM**:

1. **CONFIG_UNLOCKED-time configurer of the TDI** (§11.2 first
   CONFIG_UNLOCKED bullet near line 793).
2. **Optional untrusted transport carrier for SPDM secured
   messages** (§11.2.2 lines 978–979).
3. **The named adversary in the TDI-assignment threat model**
   (§11.6.3 lines 3041–3050).

The VMM is **not** mentioned in §11.2.7 as a mediator of the
TVM↔TSM interface. Its role in carrying TVM-originated
TDISP-shaped commands to the TSM is neither required nor
prohibited; it is simply not addressed.

### Re-evaluation of AF-iter2-1 in light of the corrected mapping

The TDISP expert's earlier framing was **wrong on one point**:

> *"I conflated the TVM↔TSM-mediator wire (which is what the
> OpenHCL VMBus `TIO_MSG_*` channel is) with the TSM↔DSM wire
> (which is the SPDM-protected channel that §11.2.2 governs). The
> TSM in the OpenHCL paravisor architecture is the SEV-PSP, a
> host-hardware-resident trusted module, and the SPDM session
> lives between the PSP and the device. The VMBus channel ferries
> TVM-originated TDISP-shaped commands to the PSP-as-TSM; the PSP
> then issues the TDISP wire requests over the SPDM session it
> owns with the DSM."*

Implications for AF-iter2-1:

- **§11.2.2 does NOT directly constrain the OpenHCL VMBus command
  envelope.** §11.2.2 governs only the TSM↔DSM wire — i.e., the
  PSP↔device SPDM session, which is out of OpenHCL's
  implementation scope (it lives inside the PSP firmware). The
  earlier "non-spec, non-SPDM, host-VMBus-tunneled command
  envelope is at odds with §11.2.2" claim is incorrect. The VMBus
  envelope is the TVM↔TSM interface, not the TSM↔DSM interface.
- **The spec imposes NO normative confidentiality/integrity
  requirement on the TVM↔TSM wire** (Q4 above). The trust model
  declares the TSM in the TVM's TCB and leaves the wire's
  protection to the platform. So the OpenHCL VMBus channel is not
  violating a §11.2.2 obligation; it simply operates in
  spec-silent territory.
- **However, the AF-iter2-1 finding's core argument is
  unaffected.** The composition §11.2.7 (TVM acceptance) +
  §11.3.9 (LOCK_INTERFACE_RESPONSE post-state semantics) +
  §11.3.10 (GET_DEVICE_INTERFACE_REPORT post-state semantics) +
  §11.2.6 (DSM event matrix) + §11.6.3 (LOCK→REPORT→START chain
  bound to a single SPDM session via the start_interface_nonce)
  all impose obligations on the **TVM** (i.e., the OpenHCL
  paravisor) regardless of how the TVM↔TSM interface is
  implemented. The paravisor must verify post-conditions on
  whatever data the TSM hands back, because the host/VMM that is
  allowed to mediate the TVM↔TSM channel is the same untrusted
  entity §11.6.3 names as the adversary, and a hostile VMM can
  substitute, drop, reorder, or fabricate the TSM's replies on
  that channel.

### Round 3 corrected AF-iter2-1 framing

> The TVM acceptance procedure of §11.2.7 (lines 1207–1227) places
> four normative trust questions on the TVM — which in the
> OpenHCL architecture is the paravisor in VTL2. Even though the
> spec declares the TSM (here the AMD SEV-PSP) to be in the TVM's
> TCB, §11.2.7 does not authorize the TVM to omit per-message
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

### Round 3 corrected §11.2.2 systemic note

> ~~"The OpenHCL VMBus command envelope is a non-spec, non-SPDM
> channel that is at odds with §11.2.2's normative-secure-transport
> requirement."~~
>
> **Replace with:** §11.2.2 (lines 963–1028) governs only the
> **TSM↔DSM** wire, which carries TDISP wire messages over a
> Secured CMA/SPDM session with AES-256-GCM. In the OpenHCL
> paravisor architecture this wire lives inside the AMD SEV-PSP
> and the device — it is out of OpenHCL's implementation scope.
> The host-mediated VMBus `TIO_MSG_*` channel between the
> paravisor (TVM) and the PSP (TSM) is a different interface, the
> **TVM↔TSM interface** of §11.2.7 (line 1224), which the spec
> describes only as a "TSM-provided interface" and on which the
> spec imposes no normative confidentiality/integrity
> requirements. The trust model addresses this interface
> structurally: the TSM is declared in the TVM's TCB (Figure 11-2
> legend, lines 716–722). However, §11.2.2 line 978 explicitly
> acknowledges that even the SPDM transport may be proxied through
> the untrusted VMM, and §11.6.3 names the VMM as the canonical
> adversary for TDI-assignment attacks; combined with the TVM's
> normative obligations under §11.2.7 and the LOCK→REPORT→START
> chain of §11.6.3, the paravisor cannot omit per-response
> validation of TSM replies received over a VMM-mediated channel,
> because a hostile VMM is permitted to be on that path and the
> spec does not give the TVM any cryptographic recourse on it.

---

## Final convergence (after round 3)

Both experts agree on:

- TRUE POSITIVE finding (unchanged from round 1).
- Composite spec citation (§11.2.7 + §11.3.9 + §11.3.10 + §11.2.6 +
  §11.6.3) is unchanged from round 2.
- The wire-level `tdi_state_after` framing is paravisor-internal,
  not a TDISP wire-protocol violation.
- `QueryIsolatedResources` returning stale `PRIVATE` is a
  downstream symptom, not an independent spec violation.
- **Corrected role mapping**: TSM is in the TVM's TCB (= AMD PSP);
  SPDM session is TSM↔DSM, not TVM↔anything; host VMM is the
  mediator of the TVM↔TSM interface (which the spec leaves
  silent); §11.2.2 governs only the TSM↔DSM wire and does NOT
  directly constrain the OpenHCL VMBus envelope.
- **The §11.6.3 / §11.2.7 obligations on the TVM still hold** —
  even though the TVM↔TSM interface is structurally trusted by
  spec, in the OpenHCL implementation the host VMM mediates that
  interface, so the TVM must verify per-response post-conditions
  (which is precisely what AF-iter2-1's missing post-check fails
  to do).

The canonical AF-iter2-1 finding statement, spec-grounding note,
and round-3 corrected §11.2.2 systemic note now live in
[../kani-iteration-2/findings/m1-unbind-missing-post-check.md](../kani-iteration-2/findings/m1-unbind-missing-post-check.md).
