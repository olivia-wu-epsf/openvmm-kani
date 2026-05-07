# TDISP Formal Verification Reference

## For Model-Checking a Guest-Side Implementation

> Distilled from: Intel TDX Connect Architecture Specification and
> TEE Device Interface Security Protocol (TDISP) v1.0 (2022-07-27).
>
> Target audience: Formal verification engineers who may not have a
> confidential computing background.

---

## 1. Glossary

| Term | Definition |
|------|-----------|
| **TD** | Trust Domain — a hardware-isolated VM whose memory is encrypted. The "guest" in this document. |
| **TDI** | TEE Device Interface — a logical device function (e.g., a PCIe VF) that can be exclusively assigned to a TD. |
| **TDX Module** | Trusted firmware running in CPU SEAM root mode; acts as a trusted oracle for the TD. |
| **TPA TD** | TEE-IO Provisioning Agent TD — performs SPDM key exchange on behalf of the TDX Module; its measurement is verified by the TDX Module. |
| **TSM** | TEE Security Manager — the host-side entity that sends TDISP messages (adversary-controlled from the TD's perspective). |
| **DSM** | Device Security Manager — device-side firmware enforcing TDISP state machine. |
| **VMM** | Virtual Machine Monitor / hypervisor — adversary-controlled. |
| **IDE** | Integrity and Data Encryption — PCIe link-layer encryption (AES-256-GCM, 96-bit MAC). |
| **Selective IDE Stream** | An IDE stream bound to specific address/RID ranges (not the whole link). |
| **T-bit** | A bit in a PCIe TLP indicating "trusted" (TD-owned) traffic. T=1 means encrypted on the bound IDE stream. |
| **SPDM** | Security Protocol and Data Model — the authentication/key-exchange protocol underlying TDISP. |
| **MMIO** | Memory-Mapped I/O — device registers mapped into the TD's address space. |
| **DMA** | Direct Memory Access — device-initiated reads/writes to TD memory. |
| **Nonce** | Single-use value returned in `LOCK_INTERFACE_RESPONSE`; binds a START to a specific lock epoch. |
| **FLR** | Function-Level Reset — a PCIe reset affecting one function. |

---

## 2. Threat Model (Formalized)

### 2.1 Adversary Capabilities

```
Adversary = VMM ∪ Host_OS ∪ BIOS_runtime ∪ Switches ∪ Bridges ∪ Non_TEE_Devices

∀ msg ∈ Messages_from_host:
    msg is adversary-controlled (may be forged, replayed, reordered, dropped)

∀ mmio_mapping ∈ Host_proposed_MMIO:
    mapping parameters are adversary-chosen (may be wrong, overlapping, stale)

∀ dma_mapping ∈ Host_proposed_DMA:
    mapping parameters are adversary-chosen

Adversary can trigger at any time:
    - IDE_stream_insecure events (physical attack or config change)
    - FLR / conventional reset
    - Configuration register modifications
    - Withdrawal of scheduling (denial of service)
    - Reordering or dropping of protocol messages
```

### 2.2 Trusted Components (Axioms)

```
Axiom TDX_MODULE_CORRECT:
    The TDX Module faithfully:
    - enforces memory isolation (Secure-EPT)
    - controls IOMMU trusted DMA tables
    - verifies TPA TD measurement
    - compares device_info hashes on TD request
    - prevents MMIO removal while TDI is assigned

Axiom TPA_TD_CORRECT:
    The TPA TD (whose measurement is verified by TDX Module):
    - correctly performs SPDM authentication
    - correctly delivers device identity/measurements to TDX Module
    - does not leak session keys

Axiom DEVICE_CORRECT (conditional):
    After successful attestation AND report verification:
    - the device DSM correctly enforces TDISP state transitions
    - IDE encryption/decryption is correct
    - device does not leak TD private data while in RUN
    (Trust is revoked on ERROR transition)

Axiom CPU_HARDWARE_CORRECT:
    Root complex, root ports, IOMMU, memory controllers:
    - correctly enforce T-bit semantics
    - correctly route IDE-encrypted traffic
    - correctly tag trusted vs untrusted IOTLB entries
```

### 2.3 Security Goals (Properties to Verify)

```
GOAL_CONFIDENTIALITY:
    TD private memory and trusted MMIO content are never observable
    by the adversary in plaintext.

GOAL_INTEGRITY:
    TD private memory and trusted MMIO cannot be modified by the
    adversary without detection.

GOAL_REPLAY_PROTECTION:
    Replayed PCIe TLPs are detected and rejected (via IDE AES-GCM
    IV/sequence numbers).

NON_GOAL_AVAILABILITY:
    The adversary may deny service at any time. No liveness property
    is guaranteed unconditionally.
```

---

## 3. State Machines

### 3.1 Device TDI State Machine (Protocol-Level)

This is the TDISP-specified state machine for the device interface.
The guest does not control this directly but must track it.

```
States = { CONFIG_UNLOCKED, CONFIG_LOCKED, RUN, ERROR }

Initial state: CONFIG_UNLOCKED

Transitions:
┌─────────────────────┬──────────────────┬────────────────────┬─────────────────────────────┐
│ From                │ To               │ Trigger            │ Guard                       │
├─────────────────────┼──────────────────┼────────────────────┼─────────────────────────────┤
│ CONFIG_UNLOCKED     │ CONFIG_LOCKED    │ LOCK_INTERFACE_REQ │ IDE stream configured,      │
│                     │                  │                    │ SPDM session active         │
├─────────────────────┼──────────────────┼────────────────────┼─────────────────────────────┤
│ CONFIG_LOCKED       │ RUN              │ START_INTERFACE_REQ│ valid nonce from LOCK resp, │
│                     │                  │                    │ same SPDM session           │
├─────────────────────┼──────────────────┼────────────────────┼─────────────────────────────┤
│ CONFIG_LOCKED       │ ERROR            │ (async event)      │ see §3.3                    │
├─────────────────────┼──────────────────┼────────────────────┼─────────────────────────────┤
│ RUN                 │ ERROR            │ (async event)      │ see §3.3                    │
├─────────────────────┼──────────────────┼────────────────────┼─────────────────────────────┤
│ CONFIG_LOCKED       │ CONFIG_UNLOCKED  │ STOP_INTERFACE_REQ │ always allowed              │
├─────────────────────┼──────────────────┼────────────────────┼─────────────────────────────┤
│ RUN                 │ CONFIG_UNLOCKED  │ STOP_INTERFACE_REQ │ always allowed              │
├─────────────────────┼──────────────────┼────────────────────┼─────────────────────────────┤
│ ERROR               │ CONFIG_UNLOCKED  │ STOP_INTERFACE_REQ │ scrub completed             │
├─────────────────────┼──────────────────┼────────────────────┼─────────────────────────────┤
│ ANY                 │ CONFIG_UNLOCKED  │ Conventional Reset │ forced; secrets scrubbed    │
├─────────────────────┼──────────────────┼────────────────────┼─────────────────────────────┤
│ CONFIG_LOCKED/RUN   │ ERROR            │ FLR                │ forced; STOP still needed   │
└─────────────────────┴──────────────────┴────────────────────┴─────────────────────────────┘
```

### 3.2 Guest-Local Acceptance State Machine

This is the **key machine to verify**. It models what the TD itself
tracks and enforces, independent of the device-side TDI state.

```
States = {
    UNASSIGNED,
    ASSIGNED_PENDING,       -- TDI assigned, not yet locked
    LOCKED_UNVERIFIED,      -- device locked, TD has not verified report
    REPORT_ACQUIRED,        -- report received (possibly chunked reassembly complete)
    REPORT_VERIFIED,        -- report matches expectations + TDX module hash check
    RESOURCES_ACCEPTED,     -- MMIO and DMA mappings accepted per report
    TRUSTED_RUN,            -- START issued, device operational
    UNTRUSTED               -- trust revoked (ERROR detected or stop initiated)
}

Initial state: UNASSIGNED

Transitions:
┌─────────────────────────┬───────────────────────┬────────────────────────────────────────────┐
│ From                    │ To                    │ Guard / Action                             │
├─────────────────────────┼───────────────────────┼────────────────────────────────────────────┤
│ UNASSIGNED              │ ASSIGNED_PENDING      │ VMM assigns TDI; TD creates local context  │
├─────────────────────────┼───────────────────────┼────────────────────────────────────────────┤
│ ASSIGNED_PENDING        │ LOCKED_UNVERIFIED     │ LOCK_INTERFACE_RESPONSE received with      │
│                         │                       │ nonce; store nonce as lock_epoch           │
├─────────────────────────┼───────────────────────┼────────────────────────────────────────────┤
│ LOCKED_UNVERIFIED       │ REPORT_ACQUIRED       │ GET_DEVICE_INTERFACE_REPORT complete       │
│                         │                       │ (all chunks reassembled)                   │
├─────────────────────────┼───────────────────────┼────────────────────────────────────────────┤
│ REPORT_ACQUIRED         │ REPORT_VERIFIED       │ TD verifies:                               │
│                         │                       │   - device_info_hash matches TDX module    │
│                         │                       │   - measurements match policy              │
│                         │                       │   - SPDM identity matches expected device  │
│                         │                       │   - report content matches expected config │
├─────────────────────────┼───────────────────────┼────────────────────────────────────────────┤
│ REPORT_VERIFIED         │ RESOURCES_ACCEPTED    │ TD accepts each MMIO page and DMA mapping: │
│                         │                       │   - MMIO pages ∈ reported_mmio             │
│                         │                       │   - DMA mappings ∈ reported_dma            │
│                         │                       │   - no aliasing (one page → one GPA)       │
├─────────────────────────┼───────────────────────┼────────────────────────────────────────────┤
│ RESOURCES_ACCEPTED      │ TRUSTED_RUN           │ TD issues START_INTERFACE_REQUEST with     │
│                         │                       │ lock_epoch nonce; nonce consumed            │
├─────────────────────────┼───────────────────────┼────────────────────────────────────────────┤
│ TRUSTED_RUN             │ UNTRUSTED             │ Any of: ERROR detected, STOP issued,       │
│                         │                       │ IDE insecure, reset, timeout               │
├─────────────────────────┼───────────────────────┼────────────────────────────────────────────┤
│ LOCKED_UNVERIFIED       │ UNTRUSTED             │ ERROR/reset detected before verification   │
│ REPORT_ACQUIRED         │ UNTRUSTED             │ ERROR/reset detected before verification   │
│ REPORT_VERIFIED         │ UNTRUSTED             │ ERROR/reset detected before acceptance     │
│ RESOURCES_ACCEPTED      │ UNTRUSTED             │ ERROR/reset detected before START          │
├─────────────────────────┼───────────────────────┼────────────────────────────────────────────┤
│ UNTRUSTED               │ UNASSIGNED            │ Cleanup complete: STOP ack, resources      │
│                         │                       │ released, secrets scrubbed                 │
├─────────────────────────┼───────────────────────┼────────────────────────────────────────────┤
│ ASSIGNED_PENDING        │ UNASSIGNED            │ Assignment aborted / VMM revokes           │
└─────────────────────────┴───────────────────────┴────────────────────────────────────────────┘
```

### 3.3 Asynchronous Adversary Events (Environment Transitions)

These can fire at **any time** regardless of guest state, forcing
transitions to UNTRUSTED / ERROR:

```
Event IDE_STREAM_INSECURE:
    Precondition: guest_state ∈ {LOCKED_UNVERIFIED, REPORT_ACQUIRED,
                                  REPORT_VERIFIED, RESOURCES_ACCEPTED, TRUSTED_RUN}
    Effect: guest_state := UNTRUSTED
    Meaning: physical link compromise or adversary reconfigured IDE

Event FUNCTION_LEVEL_RESET:
    Precondition: guest_state ∉ {UNASSIGNED}
    Effect: guest_state := UNTRUSTED
    Note: device goes to ERROR; STOP still required for cleanup

Event CONVENTIONAL_RESET:
    Precondition: true
    Effect: guest_state := UNASSIGNED (immediate; all state wiped)

Event CONFIG_CHANGE_DETECTED:
    Precondition: guest_state ∈ {LOCKED_UNVERIFIED .. TRUSTED_RUN}
    Effect: guest_state := UNTRUSTED
    Meaning: DSM detected unauthorized register modification

Event SPDM_SESSION_LOST:
    Precondition: guest_state ∈ {LOCKED_UNVERIFIED .. TRUSTED_RUN}
    Effect: guest_state := UNTRUSTED
    Meaning: session terminated; IDE keys no longer valid
```

### 3.4 IDE Stream Sub-Machine (Abstract)

```
States = { UNCONFIGURED, KEYS_PROGRAMMED, SECURE, INSECURE }

Transitions:
    UNCONFIGURED → KEYS_PROGRAMMED:
        IDE_KM KEY_PROG for all substreams (PR/NPR/CPL) + KP_ACK received
    KEYS_PROGRAMMED → SECURE:
        IDE_KM KEY_SET_GO + K_GOSTOP_ACK; enable bits set
    SECURE → INSECURE:
        (async) link error, adversary action, key expiry without refresh
    INSECURE → UNCONFIGURED:
        teardown / reconfiguration
    SECURE → UNCONFIGURED:
        graceful teardown (STOP path)

Constraint: TDI can enter CONFIG_LOCKED only if IDE stream ∈ {SECURE}
Constraint: TDI in RUN requires IDE stream = SECURE at all times
```

### 3.5 Lock Epoch / Nonce Sub-Machine

```
States = { NO_EPOCH, EPOCH_ACTIVE, EPOCH_CONSUMED, EPOCH_INVALIDATED }

Transitions:
    NO_EPOCH → EPOCH_ACTIVE:
        LOCK_INTERFACE_RESPONSE received with nonce N
        Action: store (N, session_id, config_snapshot)
    EPOCH_ACTIVE → EPOCH_CONSUMED:
        START_INTERFACE_REQUEST issued using N
        Action: N cannot be reused
    EPOCH_ACTIVE → EPOCH_INVALIDATED:
        Any of: ERROR, STOP, reset, SPDM session loss
    EPOCH_CONSUMED → NO_EPOCH:
        Normal lifecycle progression (now in RUN)
    EPOCH_INVALIDATED → NO_EPOCH:
        Cleanup complete

Invariant: |active epochs per TDI| ≤ 1
Invariant: START valid iff epoch_state = EPOCH_ACTIVE ∧ nonce matches
```

---

## 4. Global Invariants

These must hold in **every reachable state**.

```
INV-1 (Exclusive Assignment):
    ∀ tdi: at most one TD owns tdi at any time
    ∀ td, tdi1, tdi2: if td owns tdi1 ∧ td owns tdi2 ∧ tdi1 ≠ tdi2,
        they may share a default IDE stream only if on same physical function

INV-2 (No Trusted Traffic Before RUN):
    guest_state(tdi) ∉ {TRUSTED_RUN} →
        ¬∃ tlp: (tlp.T = 1 ∧ tlp.target = td_private_memory ∧ tlp.source = tdi)

INV-3 (IDE Stream Binding):
    ∀ tdi in {LOCKED_UNVERIFIED .. TRUSTED_RUN}:
        tdi.bound_stream ≠ ⊥ ∧ tdi.bound_stream.state = SECURE

INV-4 (T-bit Consistency):
    ∀ request tlp from TD to TDI in TRUSTED_RUN: tlp.T = 1
    ∀ completion for T=1 request: completion.T = 1
    ∀ completion for T=0 request: completion.T = 0

INV-5 (MMIO Exclusivity):
    ∀ mmio_page:
        |{td : mmio_page ∈ td.mapped_mmio}| ≤ 1
    ∀ td, gpa1, gpa2:
        mmio_page_at(gpa1) = mmio_page_at(gpa2) → gpa1 = gpa2
        (no aliasing: one physical MMIO page maps to at most one GPA)

INV-6 (Resource Set Containment):
    used_mmio(tdi) ⊆ accepted_mmio(tdi) ⊆ reported_mmio(tdi)
    used_dma(tdi) ⊆ accepted_dma(tdi) ⊆ reported_dma(tdi)

INV-7 (Session Binding):
    ∀ tdi in {LOCKED_UNVERIFIED .. TRUSTED_RUN}:
        tdi.lock_session = tdi.ide_key_session
        (IDE keys were programmed over the same SPDM session used for LOCK)

INV-8 (Nonce Freshness):
    ∀ tdi: nonce_used_in_START(tdi) was produced by the immediately
    preceding LOCK_INTERFACE_RESPONSE for that tdi (no replay across epochs)

INV-9 (Secret Scrub on Exit):
    guest_state transitions to UNASSIGNED →
        device IDE keys = ⊥ ∧ SPDM session keys = ⊥ ∧
        residual TD data in device buffers = ⊥

INV-10 (No Confidential Data in Unlocked State):
    guest_state ∈ {UNASSIGNED, ASSIGNED_PENDING} →
        ¬∃ data: (data.confidential ∧ data.location = tdi.registers)

INV-11 (Trusted DMA Table Integrity):
    ∀ dma_table entries for td:
        dma_table is managed exclusively by TDX Module (SEAM SAI)
        ∧ dma_table entries are integrity-protected
```

---

## 5. Per-State Invariants

### 5.1 UNASSIGNED / ASSIGNED_PENDING

```
PSI-1: tdi.bound_stream = ⊥ ∨ tdi.bound_stream.state ≠ SECURE
PSI-2: accepted_mmio(tdi) = ∅ ∧ accepted_dma(tdi) = ∅
PSI-3: lock_epoch(tdi) = NO_EPOCH
PSI-4: Any T=1 memory request targeting TD from this tdi MUST be rejected
        (by hardware; property is checked, not enforced by guest)
```

### 5.2 LOCKED_UNVERIFIED

```
PSI-5: lock_epoch(tdi) = EPOCH_ACTIVE
PSI-6: accepted_mmio(tdi) = ∅ ∧ accepted_dma(tdi) = ∅
        (TD has NOT yet accepted any resources)
PSI-7: reported_mmio(tdi) = ⊥ (report not yet acquired)
PSI-8: tdi.bound_stream.state = SECURE
PSI-9: No START_INTERFACE may be issued
PSI-10: T=1 DMA from device may reach TD private memory (device is
         locked and IDE is active), BUT TD has not validated this is safe.
         Guest must NOT use MMIO or process DMA results yet.
```

### 5.3 REPORT_ACQUIRED

```
PSI-11: report(tdi) ≠ ⊥ ∧ report(tdi).complete = true
PSI-12: report(tdi).verified = false
PSI-13: lock_epoch(tdi) = EPOCH_ACTIVE
PSI-14: accepted_mmio(tdi) = ∅ ∧ accepted_dma(tdi) = ∅
```

### 5.4 REPORT_VERIFIED

```
PSI-15: report(tdi).verified = true
PSI-16: device_info_hash_matches_tdx_module(tdi) = true
PSI-17: spdm_identity_matches_policy(tdi) = true
PSI-18: measurements_match_policy(tdi) = true
PSI-19: lock_epoch(tdi) = EPOCH_ACTIVE
PSI-20: accepted_mmio(tdi) = ∅ ∧ accepted_dma(tdi) = ∅
         (resources not yet accepted; verification ≠ acceptance)
```

### 5.5 RESOURCES_ACCEPTED

```
PSI-21: accepted_mmio(tdi) = reported_mmio(tdi)
         (TD accepted exactly what the report declared)
PSI-22: accepted_dma(tdi) ⊆ reported_dma(tdi) ∧ accepted_dma(tdi) ≠ ∅
PSI-23: ∀ page ∈ accepted_mmio(tdi):
            page.mapped_exclusively_to(td) ∧ ¬page.aliased
PSI-24: lock_epoch(tdi) = EPOCH_ACTIVE (START not yet issued)
PSI-25: TD may now safely access accepted MMIO
         (but device DMA to TD memory is gated on START in practice)
```

### 5.6 TRUSTED_RUN

```
PSI-26: lock_epoch(tdi) = EPOCH_CONSUMED
PSI-27: tdi.device_state = RUN
PSI-28: tdi.bound_stream.state = SECURE
PSI-29: used_mmio(tdi) ⊆ accepted_mmio(tdi)
PSI-30: used_dma(tdi) ⊆ accepted_dma(tdi)
PSI-31: All TLPs to/from tdi use bound selective stream with T=1
PSI-32: Device DMA to TD private memory is permitted (T=1, correct stream)
PSI-33: P2P streams may be bound/unbound (only in this state)
```

### 5.7 UNTRUSTED

```
PSI-34: No new trusted operations may be initiated
PSI-35: T=1 memory requests from tdi MUST be rejected (or will be
         rejected by hardware due to IDE insecure / stream teardown)
PSI-36: Confidential data may still reside in device until STOP + scrub
PSI-37: Guest must issue STOP_INTERFACE_REQUEST to proceed to cleanup
PSI-38: After STOP response: used_mmio := ∅, used_dma := ∅
```

---

## 6. Transition Preconditions and Postconditions

### 6.1 LOCK_INTERFACE

```
Pre:
    guest_state = ASSIGNED_PENDING
    ide_stream.state = SECURE
    spdm_session.active = true
    spdm_session.algo = AES-256-GCM
    ide_keys programmed via same spdm_session

Post:
    guest_state = LOCKED_UNVERIFIED
    lock_epoch = EPOCH_ACTIVE
    lock_epoch.nonce = response.start_interface_nonce
    lock_epoch.session = spdm_session.id
    lock_epoch.config_snapshot = (stream_id, mmio_offset, flags)
    device.config_locked = true
    device.pre_lock_dma_aborted = true
```

### 6.2 GET_DEVICE_INTERFACE_REPORT (chunked)

```
Pre:
    guest_state = LOCKED_UNVERIFIED
    lock_epoch = EPOCH_ACTIVE

Post (on final chunk):
    guest_state = REPORT_ACQUIRED
    report.complete = true
    report.content = concatenation of all chunks in order
    report.offset_verified = (no gaps, no overlaps in chunk assembly)

Intermediate (per chunk):
    chunk.offset + chunk.portion_length ≤ report.total_length
    chunks are contiguous and non-overlapping
    If any chunk fails: guest_state remains LOCKED_UNVERIFIED (may retry or abort)
```

### 6.3 Report Verification (Guest-Local)

```
Pre:
    guest_state = REPORT_ACQUIRED
    report.complete = true

Verification steps (all must pass):
    V1: hash(device_info_from_tpa) = tdx_module.stored_device_info_hash(tdi)
    V2: report.device_identity matches spdm_peer_certificate
    V3: report.measurements satisfy td_owner_policy
    V4: report.mmio_ranges match expected device configuration
    V5: report.interface_info consistent with lock parameters
    V6: report freshness — tied to current lock epoch (nonce binding)

Post (all pass):
    guest_state = REPORT_VERIFIED
    reported_mmio(tdi) = report.mmio_ranges
    reported_dma(tdi) = report.dma_ranges

Post (any fail):
    guest_state remains REPORT_ACQUIRED (TD may abort → UNTRUSTED)
```

### 6.4 Resource Acceptance (Guest-Local)

```
Pre:
    guest_state = REPORT_VERIFIED

For each MMIO page p in reported_mmio(tdi):
    Pre:  p.state = PENDING (host provisioned, not yet accepted)
    Check: p ∈ reported_mmio(tdi)
    Check: p.gpa is unique within td (no aliasing)
    Check: p not mapped to any other TD
    Action: p.state := PRESENT (accepted)

For each DMA mapping m in reported_dma(tdi):
    Pre:  m.state = PENDING
    Check: m ∈ reported_dma(tdi)
    Action: m.state := PRESENT

Post:
    guest_state = RESOURCES_ACCEPTED
    accepted_mmio(tdi) = reported_mmio(tdi)
    accepted_dma(tdi) ⊇ minimum_required_dma(tdi)
```

### 6.5 START_INTERFACE

```
Pre:
    guest_state = RESOURCES_ACCEPTED
    lock_epoch = EPOCH_ACTIVE
    lock_epoch.nonce = N (the nonce from LOCK response)
    accepted_mmio(tdi) = reported_mmio(tdi) (all pages accepted)
    accepted_dma(tdi) ≠ ∅

Message:
    START_INTERFACE_REQUEST contains nonce N

Post (success response):
    guest_state = TRUSTED_RUN
    lock_epoch = EPOCH_CONSUMED
    device.tdi_state = RUN
    device DMA with T=1 now reaches TD private memory

Post (failure / INVALID_INTERFACE_STATE):
    guest_state → UNTRUSTED (lock epoch likely invalidated)
```

### 6.6 STOP_INTERFACE

```
Pre:
    guest_state ∈ {LOCKED_UNVERIFIED, REPORT_ACQUIRED, REPORT_VERIFIED,
                   RESOURCES_ACCEPTED, TRUSTED_RUN, UNTRUSTED}

Effects on device:
    - abort/complete all in-flight DMA
    - abort/complete all ATS translations
    - complete all outstanding responses
    - clear interrupt state
    - scrub IDE keys, SPDM keys, residual secrets

Post:
    guest_state → UNTRUSTED (then → UNASSIGNED after cleanup)
    lock_epoch = NO_EPOCH
    accepted_mmio(tdi) = ∅
    accepted_dma(tdi) = ∅
    used_mmio(tdi) = ∅
    used_dma(tdi) = ∅
    ide_stream.state = UNCONFIGURED
```

### 6.7 BIND_P2P_STREAM (Runtime Only)

```
Pre:
    guest_state = TRUSTED_RUN
    target_stream.state = SECURE
    target_stream.session = tdi.lock_session (same SPDM session)

Post:
    p2p_streams(tdi) = p2p_streams(tdi) ∪ {target_stream}
    Device may use target_stream for peer-to-peer traffic

Ordering constraint:
    Fence required before device uses new stream
```

### 6.8 UNBIND_P2P_STREAM (Runtime Only)

```
Pre:
    guest_state = TRUSTED_RUN
    target_stream ∈ p2p_streams(tdi)

Post:
    p2p_streams(tdi) = p2p_streams(tdi) \ {target_stream}
    All in-flight DMA on target_stream aborted/completed
    Device reverts to default stream (fence before use)
```

---

## 7. Security Properties (Temporal Logic)

Using CTL notation: `AG` = in all states on all paths,
`AF` = eventually on all paths, `EF` = exists a path where eventually,
`→` = implies, `U` = until.

### 7.1 Safety Properties

```
SAFE-1 (No premature trust):
    AG(guest_state ≠ TRUSTED_RUN →
        ¬(td_issues_trusted_mmio_access(tdi) ∨ td_processes_dma_from(tdi)))

SAFE-2 (Report before START):
    AG(START_issued(tdi) →
        previously(report_verified(tdi) ∧ resources_accepted(tdi)))

SAFE-3 (Nonce single-use):
    AG(nonce_used_in_START(N, tdi) →
        AG(¬nonce_used_in_START(N, tdi)))
    (once consumed, never reused)

SAFE-4 (Session binding):
    AG(START_issued(tdi) →
        lock_session(tdi) = ide_key_session(tdi))

SAFE-5 (No stale resources after STOP):
    AG(STOP_completed(tdi) →
        AX(accepted_mmio(tdi) = ∅ ∧ accepted_dma(tdi) = ∅))

SAFE-6 (IDE insecure forces untrust):
    AG(ide_stream_insecure(tdi) ∧ guest_state(tdi) ∈ {LOCKED..TRUSTED_RUN} →
        AX(guest_state(tdi) = UNTRUSTED))

SAFE-7 (No MMIO access before acceptance):
    AG(guest_state(tdi) ∈ {LOCKED_UNVERIFIED, REPORT_ACQUIRED, REPORT_VERIFIED} →
        ¬td_accesses_mmio(tdi))

SAFE-8 (Exclusive MMIO):
    AG(∀ page: page ∈ accepted_mmio(tdi1) ∧ page ∈ accepted_mmio(tdi2) →
        tdi1 = tdi2)

SAFE-9 (No T=1 in unlocked):
    AG(guest_state(tdi) ∈ {UNASSIGNED, ASSIGNED_PENDING} →
        ¬(∃ tlp: tlp.T=1 ∧ tlp.accepted_by(tdi)))

SAFE-10 (Completion T-bit preservation):
    AG(∀ req, cpl: cpl.is_completion_of(req) → cpl.T = req.T)
```

### 7.2 Conditional Liveness (Under Fair Scheduling)

```
LIVE-1 (Eventual cleanup):
    AG(guest_state = UNTRUSTED →
        AF(guest_state = UNASSIGNED) ∨ adversary_denies_service)

LIVE-2 (Lock epoch resolution):
    AG(lock_epoch = EPOCH_ACTIVE →
        AF(lock_epoch ∈ {EPOCH_CONSUMED, EPOCH_INVALIDATED, NO_EPOCH})
        ∨ adversary_denies_service)
```

---

## 8. Ordering Constraints (Happens-Before)

```
ORD-1: ide_keys_programmed(stream) < LOCK_INTERFACE(tdi using stream)
ORD-2: LOCK_INTERFACE_RESPONSE < GET_DEVICE_INTERFACE_REPORT
ORD-3: report_verified < resource_acceptance
ORD-4: resource_acceptance(all_mmio) < START_INTERFACE
ORD-5: resource_acceptance(some_dma) < START_INTERFACE
ORD-6: START_INTERFACE < any_trusted_device_operation
ORD-7: STOP_INTERFACE < MMIO_unmap (from TDX module perspective)
ORD-8: IOTLB_invalidation < MMIO_reassignment_to_other_TD
ORD-9: fence < stream_switch (for BIND/UNBIND P2P)
ORD-10: abort_inflight_DMA < STOP_INTERFACE_RESPONSE
ORD-11: spdm_session_established < ide_key_programming
ORD-12: tpa_device_info_delivery < td_hash_verification_against_tdx_module
ORD-13: all_chunks_received < report_verification
ORD-14: STOP_INTERFACE_RESPONSE < secret_scrub_confirmation
```

---

## 9. Concurrency and Message Constraints

```
CONC-1 (Request serialization):
    At most NUM_REQ_THIS outstanding TDISP requests to same responder.
    Next request to same responder only after response/timeout/transport error.

CONC-2 (BUSY handling):
    If response = BUSY, requester must retry (not advance state).
    Repeated BUSY does not change device state.

CONC-3 (Report chunk ordering):
    Chunks must be requested with monotonically increasing offsets.
    Total: offset + portion_length of chunk_i = offset of chunk_{i+1}.
    remainder_length of final chunk = 0.

CONC-4 (No concurrent lock/start):
    LOCK and START for same TDI are never in-flight simultaneously.
    LOCK must complete (response received) before START can be issued.

CONC-5 (Async event preemption):
    An async adversary event (§3.3) may arrive between any two messages.
    Guest must check device state after any operation that could be preempted.
```

---

## 10. Key Verification Obligations (Guest Must Check)

These are the checks the guest TD MUST perform; failure to perform
any of these enables an attack.

```
CHECK-1: device_info_hash
    hash(device_info_received_from_tpa) == tdx_module.query_device_info_hash(tdi)
    Attack if skipped: adversary substitutes device identity

CHECK-2: SPDM certificate chain
    Verify against trusted CA / expected device identity
    Attack if skipped: MITM with rogue device cert

CHECK-3: Firmware measurements
    report.measurements ∈ allowed_measurements_policy
    Attack if skipped: compromised firmware runs trusted

CHECK-4: MMIO range consistency
    ∀ page offered by VMM: page.physical_addr ∈ report.mmio_ranges
    Attack if skipped: adversary maps attacker-controlled MMIO

CHECK-5: No MMIO aliasing
    All accepted GPA→MMIO mappings are injective (1:1)
    Attack if skipped: confused deputy via shared MMIO page

CHECK-6: Nonce freshness
    nonce_in_START == nonce_from_most_recent_LOCK_RESPONSE
    Attack if skipped: replay of stale LOCK from prior epoch

CHECK-7: Session continuity
    SPDM session for LOCK == session for IDE keys == session for report
    Attack if skipped: mix-and-match across different device sessions

CHECK-8: Stream identity
    default_stream_id in report == stream actually bound in hardware
    Attack if skipped: traffic routed to wrong/unencrypted stream

CHECK-9: Report completeness
    report covers all expected interfaces/resources for this TDI
    Attack if skipped: adversary hides resources not in report
```

---

## 11. Error Codes and Their Significance

```
INVALID_INTERFACE_STATE:
    Request inappropriate for current TDI state.
    Guest implication: do not advance local state; may need to query state.

BUSY:
    Responder overloaded; no state change.
    Guest implication: retry with backoff; do not advance state.

VERSION_MISMATCH / UNSUPPORTED_REQUEST:
    Negotiation failure.
    Guest implication: cannot proceed; abort assignment.

INVALID_REQUEST:
    Malformed or invalid parameters.
    Guest implication: implementation bug; do not retry same params.

UNSPECIFIED:
    Generic failure.
    Guest implication: abort; transition to UNTRUSTED.
```

---

## 12. Modeling Recommendations for Formal Verification

### 12.1 Abstraction Levels

```
LEVEL 1 (Protocol state machine):
    Model guest acceptance state machine (§3.2) + lock epoch (§3.5).
    Abstract SPDM to a boolean "session_valid".
    Abstract IDE to a boolean "stream_secure".
    Properties: SAFE-1 through SAFE-10, ordering constraints.

LEVEL 2 (Resource tracking):
    Add set-valued variables for MMIO/DMA resources.
    Model resource acceptance protocol.
    Properties: INV-5, INV-6, CHECK-4, CHECK-5.

LEVEL 3 (Concurrency):
    Model message interleaving with async adversary events.
    Properties: CONC-1 through CONC-5, SAFE-6.

LEVEL 4 (Cryptographic binding):
    Model session identity, nonce freshness, key provenance.
    Properties: INV-7, INV-8, CHECK-6, CHECK-7.
```

### 12.2 Key State Variables for Model Checker

```
-- Per-TDI state
guest_state       : enum {UNASSIGNED, ASSIGNED_PENDING, LOCKED_UNVERIFIED,
                          REPORT_ACQUIRED, REPORT_VERIFIED,
                          RESOURCES_ACCEPTED, TRUSTED_RUN, UNTRUSTED}
device_tdi_state  : enum {CONFIG_UNLOCKED, CONFIG_LOCKED, RUN, ERROR}
lock_epoch_state  : enum {NO_EPOCH, EPOCH_ACTIVE, EPOCH_CONSUMED, EPOCH_INVALIDATED}
lock_nonce        : Nonce ∪ {⊥}
lock_session_id   : SessionId ∪ {⊥}

-- Per-TDI resource sets
reported_mmio     : Set<Page>
accepted_mmio     : Set<Page>
used_mmio         : Set<Page>
reported_dma      : Set<Mapping>
accepted_dma      : Set<Mapping>
used_dma          : Set<Mapping>

-- Per-TDI stream state
default_stream    : StreamId ∪ {⊥}
stream_state      : enum {UNCONFIGURED, KEYS_PROGRAMMED, SECURE, INSECURE}
p2p_streams       : Set<StreamId>

-- Per-TDI verification flags
device_info_hash_verified : bool
report_complete           : bool
report_verified           : bool
measurements_match        : bool
spdm_identity_match       : bool

-- Global
spdm_session_active       : bool
ide_key_session           : SessionId ∪ {⊥}
```

### 12.3 Non-Deterministic Adversary Actions (for Model Checker)

```
The adversary may non-deterministically choose at each step:
    1. Do nothing (allow guest to proceed)
    2. Fire IDE_STREAM_INSECURE
    3. Fire FUNCTION_LEVEL_RESET
    4. Fire CONVENTIONAL_RESET
    5. Fire CONFIG_CHANGE_DETECTED
    6. Fire SPDM_SESSION_LOST
    7. Send BUSY response to any pending request
    8. Drop a message (no response)
    9. Delay a response arbitrarily
    10. Propose incorrect MMIO/DMA mappings (caught by CHECK-4/5)
    11. Deliver stale/forged device_info (caught by CHECK-1)

The model checker should explore all interleavings of guest actions
with adversary actions to verify safety properties hold.
```

---

## 13. Summary of Critical Invariant Violations (Attack Classes)

| Violation | Attack | Property Broken |
|-----------|--------|-----------------|
| START before report verification | Malicious device runs trusted | SAFE-2 |
| Nonce reuse across epochs | Replay old config into new session | SAFE-3 |
| Accept MMIO not in report | Adversary maps controlled registers | CHECK-4, INV-6 |
| MMIO alias (2 GPAs → 1 page) | Confused deputy | CHECK-5, INV-5 |
| Session mismatch (LOCK ≠ IDE keys) | MITM decryption of traffic | SAFE-4, INV-7 |
| Continue after IDE insecure | Plaintext traffic observable | SAFE-6 |
| Access MMIO before acceptance | Read from adversary-controlled page | SAFE-7 |
| Skip device_info hash check | Substituted device identity | CHECK-1 |
| No cleanup after ERROR | Stale keys enable future decryption | INV-9 |

---

*End of formal verification reference.*
