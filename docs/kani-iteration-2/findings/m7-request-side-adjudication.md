# M-7 (request-side variant) — adjudicated FALSE POSITIVE

**Property attempted:** "Every outgoing TDISP command's cached
`tdi_state` at issue is in §11.3.1 Table 3 'Legal TDISP states for
Device' for that command." Specifically:
- `LOCK_INTERFACE_REQUEST` (Bind) issued only when cache says
  `Unlocked`.
- `START_INTERFACE_REQUEST` (Start) issued only when cache says
  `Locked`.

**Kani harnesses:**
- `m7_bind_audit_state_is_unlocked` — FAILED in 1.7 s.
- `m7_start_audit_state_is_locked` — FAILED in 2.2 s.

Both failures share the same counterexample: the paravisor's
`tdisp_bind_interface` ([tdisp.rs#L599-L626](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L599-L626))
and `tdisp_start_device_inner` ([tdisp.rs#L642-L668](../../../vm/devices/pci/vpci_client/src/tdisp.rs#L642-L668))
read the cached `tdi_state` for tracing purposes only and do **not**
gate the outgoing `send_tdisp_command` call on it. The post-state
checks (M-1) exist and pass for both — the cache is required to be
the spec post-state on `Ok`.

**Verdict (consensus, both expert subagents):** **FALSE POSITIVE** as
a TDISP-spec security finding.

## TDISP-spec expert (skill-restricted to PCI-SIG TDISP v2022-07-27)

> The "Legal TDISP states for Device" column in §11.3.1 Table 3 is
> normative on the **DSM (device)**, not on the requester (TVM/TSM).
> The spec contains no obligation — explicit or implicit — that the
> requester verify its cached source state before transmitting.

Key citations:

- **§11.3.1 Table 3** is literally titled *"Legal TDISP states for
  **Device**"*. Section preamble (lines 1232–1235) frames enforcement
  as a response-side behaviour ("Unsupported request codes must
  return a TDISP_ERROR response message").
- **§11.3.8 LOCK_INTERFACE_REQUEST** (lines 1521–1544): *"**The
  device must fail the request** if … TDI is not in
  CONFIG_UNLOCKED."* Returned via `INVALID_INTERFACE_STATE`
  (Table 12).
- **§11.3.14 START_INTERFACE_REQUEST** (lines 1986–1993): *"**The
  device must fail the request** if … TDI is not in CONFIG_LOCKED."*
- **§11.3.24 Table 27** defines `INVALID_INTERFACE_STATE = 0x0004`:
  *"The Responder received the request **while in the wrong state**,
  or received an unexpected request."* The very existence of this
  response code is the spec acknowledgment that the wire protocol
  handles requesters sending out-of-state requests.
- **§11.2.3 Requirements for Requesters (TSM)** — the *only* section
  imposing normative requester obligations — covers `NUM_REQ_ALL` /
  `NUM_REQ_THIS` outstanding-request limits and serialization.
  **Nothing** about pre-send state validation.
- **§11.2.7 TVM Acceptance** — the four normative TVM questions
  (device identity/measurements, SPDM session identity match, IDE key
  provenance, mapping correctness) are all evaluated **after**
  receiving REPORT and before transitioning to RUN. Cached source
  state at request-issue time is not on this list.
- **§11.6.3** — the load-bearing chain is *"SPDM session ⇒ device-
  side state-machine enforcement ⇒ START_INTERFACE_NONCE binding
  LOCK→START"*. None of the listed mitigations rely on the requester
  pre-checking its own cache.

The spec's defenses against the hypothesised attack ("malicious host
witnesses paravisor sending LOCK while the device is in RUN") are:

1. **Wire confidentiality/integrity (§11.2.2, §11.6.1):** all TDISP
   messages traverse an SPDM 1.2 secure session as VDMs. The
   "malicious host" cannot read or modify the request opcode in
   transit; it sees only ciphertext.
2. **Device-side rejection (§11.3.8 / §11.3.14):** out-of-state
   requests are rejected with `INVALID_INTERFACE_STATE`. The cache
   stays unchanged.
3. **Post-response cache update (M-1, already proven for
   Bind/Start):** the paravisor only advances its cached state on a
   successful, nonce-validated response.

## OpenHCL expert (skill-restricted to OpenHCL KB)

> Valid but mitigated.
>
> The primitives genuinely lack a `state == Unlocked` /
> `state == Locked` precondition gate. Treating M-7 as "every
> emitted command must have legal pre-state at issue", the property
> literally fails on the function in isolation.
>
> In the **current call graph** there is no observable security
> break: the orchestrator `attest()` is the only path that reaches
> bind/start, and it forces the pre-state via a prior unbind whose
> own M-1 post-check rejects host lies. Honest host returns
> `INVALID_INTERFACE_STATE` on illegal pre-state → `Err`, cache
> unchanged. Confidentiality / integrity: no break, because the
> resource-isolation gating (MMIO unblock / DMA unblock) is keyed on
> the SEV-TIO firmware-validated unblock map, not on whether the
> bind audit log was clean.

The OpenHCL expert classified this as **defense-in-depth /
internal-correctness gap, not a TDISP-spec security finding**.

## Spec-aligned reformulation (for future work)

The TDISP expert proposed a stronger, spec-aligned variant of M-7
worth pursuing as a future tightening of M-1:

> "the paravisor must reject any **incoming** `*_RESPONSE` whose
> post-state implied by the response is not consistent with §11.3.1
> Table 3 *and* the cached pre-state" — i.e. tighten M-1 to also
> reject responses whose claimed transition was not legal from the
> cached source state.

This is a TVM-side property the spec arguably supports via §11.2.7
question 4 plus §11.6.3's "all transitions … in the same SPDM secure
session". M-1 as currently proven only checks the post-state, not
the (pre-state → post-state) transition legality. Filed as a
follow-on for a future iteration.

## Action

The two failing harnesses (`m7_bind_audit_state_is_unlocked`,
`m7_start_audit_state_is_locked`) are removed from
[kani_proofs_session.rs](../../../vm/devices/pci/vpci_client/src/kani_proofs_session.rs).
The `m7_unbind_audit_state_in_legal_set` harness is retained because
its property — STOP_INTERFACE_REQUEST is legal in any TDI state —
*is* satisfied by the implementation and verifiable cheaply. The
removed-harness rationale is documented in the file's M-7 comment
block.
