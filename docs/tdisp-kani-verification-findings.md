# TDISP Kani Verification — Findings

This document summarizes the formal verification campaign against the
VPCI client TDISP state machine
([`vm/devices/pci/vpci_client/src/tdisp.rs`](../vm/devices/pci/vpci_client/src/tdisp.rs))
using the [Kani](https://github.com/model-checking/kani) Rust verifier.

All harnesses live in
[`vm/devices/pci/vpci_client/src/kani_proofs.rs`](../vm/devices/pci/vpci_client/src/kani_proofs.rs)
and are gated behind `#[cfg(kani)]`. They drive the production TDISP
APIs end-to-end against a fully **symbolic, malicious host**: the host's
TDISP responses (status, payload variant, `tdi_state_after`, etc.) are
nondeterministic, modeling an attacker that controls the host channel.

The threat model is **integrity / confidentiality only**, not
availability — the host can refuse service or return errors at will;
what it must never do is convince the paravisor to enter an inconsistent
or unsafe state.

## Results table

| # | Harness | Property (plain English) | Status | VCCs / Time |
|---|---|---|---|---|
| 1 | `verify_bind_cannot_cache_inconsistent_state_on_success` | If `tdisp_bind_interface` returns `Ok`, the cached `tdi_state` equals the host-reported state and is in `{Locked, Run}`. On `Err`, no successful cache state is recorded. Universal cache invariant. | ✅ VERIFIED | 2006 / 4.8 s |
| 2 | `verify_dma_unblock_gating` | DMA is unblocked **iff** the bind succeeded and `tdi_state_after == Run`. Cache and DMA controller stay coherent. | ✅ VERIFIED | 2165 / 6.4 s |
| 3 | `verify_paravisor_never_unblocks_when_gate_closed` | When the policy gate is closed, the paravisor never calls `unblock_dma()` regardless of host behavior. | ✅ VERIFIED | 2001 / 8.6 s |
| 4 | `verify_start_device_post_check` | `tdisp_start_device(Ok)` ⇒ host-reported `tdi_state_after == Run`. | ❌ FAILS — audit finding **AF-1** | — |
| 5 | `verify_unbind_post_check` | `tdisp_unbind(Ok)` ⇒ host-reported `tdi_state_after == Unlocked`. | ❌ FAILS — audit finding **AF-2** | — |
| 6 | `verify_get_device_report_post_check` | `tdisp_get_device_report(Ok)` ⇒ cached `tdi_state ∈ {Locked, Run}` at call time. | ❌ FAILS — audit finding **AF-3** | — |
| 7 | `verify_unbind_reblocks_previously_unblocked_resources` | `tdisp_unbind` re-blocks **every** previously-unblocked MMIO BAR with the exact `(bar_id, base_gpa, length)` recorded at bind time, re-blocks DMA iff it was previously unblocked, and **never** issues an unblock during teardown — for any host response and any starting `tdi_state`. | ✅ VERIFIED | 2345 / 26.9 s |

The three FAILing harnesses are intentionally retained to document
real audit findings against the current implementation. Per project
direction, the implementation is **not** modified to make them pass —
they serve as executable specifications of the missing checks.

## Audit findings

### AF-1 — `start_device` post-check is bypassable when prior cached state is `Run`

**Harness:** `verify_start_device_post_check`

**Counter-example:** `state_before == Run`; the host returns `Success`
with a `tdi_state_after` byte that does not decode to a known
`TdispTdiState`.

**Mechanism:** `send_tdisp_command` skips its `update_tdi_state` call
when the wire byte is undecodable. The per-method post-check in
`tdisp_start_device_inner` then observes the **prior** cached `Run`
and accepts the response as valid.

**Recommended fix:** require the host to always supply a decodable
`tdi_state_after`; or check the wire-level field explicitly in
`tdisp_start_device_inner` before consulting the cache.

### AF-2 — `unbind` has no `tdi_state_after` post-check at all

**Harness:** `verify_unbind_post_check`

**Counter-example:** the host returns `Success` with an `Unbind`
payload but claims `tdi_state_after == Run`.

**Mechanism:** `tdisp_unbind_inner` returns `Ok` regardless of the
host's claimed terminal state. The cache becomes incoherent with the
(purportedly) actual device state.

**Recommended fix:** assert `tdi_state_after == Unlocked` (or the
documented terminal state) in `tdisp_unbind_inner` before returning
`Ok`.

### AF-3 — `GetTdiReport` lacks a cached-state precondition

**Harness:** `verify_get_device_report_post_check`

**Counter-example:** cached `tdi_state ∈ {ConfigUnlocked, Unlocked,
Error, ...}` (i.e. the device has never been bound) and the host
returns `Success` with an arbitrary report buffer.

**Mechanism:** Production performs no cached-state check before
issuing `GetTdiReport`. A device report can be obtained — and trusted —
before any bind has occurred.

**Recommended fix:** gate `tdisp_get_device_report_inner` on
`cached tdi_state ∈ {Locked, Run}` and reject locally without
contacting the host otherwise.

## Positive guarantees newly proven

- **Bind cache coherence (Harness 1)** — five sub-properties, all
  discharged under a universal cache invariant covering both `Ok` and
  `Err` paths.
- **DMA unblock is tightly gated (Harness 2)** — `unblock_dma` is
  reachable only on a successful bind transitioning the device to
  `Run`.
- **Closed-gate denial (Harness 3)** — even with full host control,
  a closed paravisor policy gate makes `unblock_dma` unreachable.
- **Re-block chain-of-custody (Harness 7)** — the paravisor cannot
  "forget" a previously-unblocked BAR or DMA region during teardown.
  The re-block step happens **before** the host is contacted, so no
  host response can prevent it. Verified for symbolic
  `(bar_id, base_gpa, length)`, symbolic prior `dma_unblocked` flag,
  symbolic starting `tdi_state`, and symbolic host response.

## Reproducing locally

Prerequisites: Kani 0.67+, rustc nightly-2025-11-21, the project's
vendored `protoc`. From the crate directory:

```bash
cd vm/devices/pci/vpci_client
PROTOC=<path-to-protoc> cargo kani --harness <harness-name> --verbose
```

Substitute any harness name from the table above. Each harness
verifies independently in well under a minute on a developer
workstation.

## Engineering notes

Adapting the production code for Kani required a small set of
mechanical changes that do not affect the runtime build:

- **Inner-method forwarder pattern** — each verified entry point is
  split into a public wrapper returning `anyhow::Result` (`#[cfg(not(kani))]`)
  and a parallel wrapper returning `crate::Result` (`#[cfg(kani)]`),
  both delegating to a shared `_inner` returning `crate::Result`. This
  keeps the `anyhow::Backtrace`/`std::error::Error` Drop chain (which
  pulls in `memchr`, `getenv`, etc. and explodes CBMC reachability)
  out of the verified call graph.
- **`err_shim`** — under `cfg(kani)`, `crate::Error`/`crate::Result`/
  `crate::err!`/`crate::Context` resolve to a zero-sized stub. Under
  the runtime build they re-export `anyhow`'s versions unchanged.
- **`tracing` with `max_level_off`** — gated under
  `[target.'cfg(kani)'.dependencies]` to compile out every
  `tracing::*!` call.
- **Trait bridges** — public trait impls (e.g.
  `TdispVpciAttestationInterface for VpciDevice`) keep their
  `anyhow::Result` signatures; under `cfg(kani)` they translate the
  inner result via `.map_err(|_| anyhow::anyhow!("..."))`.
- **`kani_new_for_unbind` constructor** — pre-populates a single
  `validated_mmio_bars` entry at construction time. `BTreeMap::insert`
  inside a harness body causes CBMC OOM (~12 k VCCs from B-tree node
  manipulation); pre-populating one entry is small enough to verify.
- **`kani_run_async!` macro** — single-poll executor using
  `Waker::noop()` + `pin!` + `Future::poll`, sufficient because all
  TDISP entry points complete in one poll under the symbolic mock host.

---

## Concrete attack scenarios for failing harnesses

The three failing harnesses each correspond to a counter-example trace
that Kani produced. Below, each finding is restated as a step-by-step
operational scenario from the perspective of a malicious host (or a
host compromised mid-session). All scenarios assume the attacker
controls the response payload that traverses the VMBus channel; this
is the explicit threat model for a paravisor-isolated guest.

The relevant production code paths are
[`tdisp.rs#send_tdisp_command`](../vm/devices/pci/vpci_client/src/tdisp.rs)
(state caching from host claim) and the per-method `*_inner`
functions.

### Attack AF-1 — Bypass `start_device` post-check via stale cached `Run`

**Target.** [`tdisp_start_device_inner`](../vm/devices/pci/vpci_client/src/tdisp.rs).

**Pre-conditions.**
1. The paravisor's cached `tdi_state` is already `Run` for some
   `vpci_device_id` (e.g. left over from an earlier successful
   bind+start cycle, or as a result of AF-2 chaining).
2. The guest re-issues `StartTdi` (e.g. after a transient error) and
   the paravisor calls `tdisp_start_device`.

**Attack trace.**
1. Guest → paravisor: `StartTdi(vpci_device_id)`.
2. Paravisor → host: `GuestToHostCommand{ StartTdi }`.
3. **Malicious host → paravisor:**
   ```
   GuestToHostResponse {
       result: Success,
       tdi_state_after: <undecodable byte, e.g. 0xFF>,
       response: Some(StartTdi(TdispCommandResponseStartTdi {})),
   }
   ```
4. `send_tdisp_command` calls `res.tdi_state_after_enum()`, gets
   `None`, takes the `None` arm: it **logs a warning and skips**
   `update_tdi_state`. The cache stays at the prior `Run`.
5. `tdisp_start_device_inner` then matches `self.tdi_state()` →
   `TdispTdiState::Run` → "device successfully transitioned to Run
   state". Returns `Ok(())`.

**Effect.** The paravisor is convinced the device moved into `Run` in
response to *this specific* `StartTdi`. The host never actually had to
acknowledge the request — it can have done anything (or nothing) on
its side. Combined with AF-2 below, an attacker that has already
poisoned the cache to `Run` can keep the paravisor in that belief
indefinitely, regardless of the real device state.

**Why current code is vulnerable.** The post-check reads `self.tdi_state()`,
not the wire field `res.tdi_state_after`. A `None`-decoded wire field
silently keeps the cache pinned, so the post-check observes its own
prior state instead of the host's claim about *this* command.

**Suggested mitigation.** In `tdisp_start_device_inner`, branch on
`res.tdi_state_after_enum()` directly:

```rust
let claimed = res.tdi_state_after_enum()
    .ok_or_else(|| crate::err!("host did not claim a decodable tdi_state_after for StartTdi"))?;
if claimed != TdispTdiState::Run {
    return Err(crate::err!("host claimed wrong state for StartTdi: {claimed:?}"));
}
```

The same shape applies to bind / unbind reconciliation.

---

### Attack AF-2 — Forge a successful `Unbind` while keeping the device "in Run"

**Target.** [`tdisp_unbind_inner`](../vm/devices/pci/vpci_client/src/tdisp.rs).

**Pre-conditions.**
1. The guest has just issued `Unbind(vpci_device_id, reason)` (graceful
   tear-down or error-recovery path).
2. The cached `tdi_state` may be anything — `Run`, `Locked`, etc.

**Attack trace.**
1. Paravisor calls `tdisp_unbind_inner`. The re-block-loop runs first:
   any previously unblocked MMIO BARs and DMA are flipped back to
   shared. (Harness 7 confirms this happens regardless of host
   response — this part is safe.)
2. Paravisor → host: `GuestToHostCommand{ Unbind, reason }`.
3. **Malicious host → paravisor:**
   ```
   GuestToHostResponse {
       result: Success,
       tdi_state_after: Run as i32,        // or Locked, or any value
       response: Some(Unbind(TdispCommandResponseUnbind {})),
   }
   ```
4. `send_tdisp_command` calls `update_tdi_state(Run)` → cache is now
   `Run`. Result is `Success`, so it returns `Ok(res)`.
5. `tdisp_unbind_inner` matches `res.response::<TdispCommandResponseUnbind>()`
   → `Ok(_)` → clears `validated_mmio_bars`, `dma_unblocked`,
   `tdi_report` (if requested). **Returns `Ok(())`.**
6. **There is no per-method check that `tdi_state` is now `Unlocked`.**

**Effect.** From the guest's point of view the unbind succeeded
(`Ok(())`). From the paravisor cache's point of view the device is
still in `Run`. This sets up two chained attacks:

- **AF-1 chaining.** A subsequent `StartTdi` re-issued by the guest
  (or any recovery code) will hit AF-1 and be accepted as a successful
  transition, again without the host doing anything.
- **AF-3 chaining.** A subsequent `tdisp_get_device_report` will be
  accepted (per AF-3 nothing checks the cache), and the paravisor will
  expose the host-supplied buffer to the attestation layer as if it
  came from a `Run`-state TDI.

**Why current code is vulnerable.** `tdisp_bind_interface` and
`tdisp_start_device_inner` both perform a post-state match against the
cache; `tdisp_unbind_inner` does not. The asymmetry is the bug.

**Suggested mitigation.** Add the same shape of post-check in
`tdisp_unbind_inner` that bind/start use. The expected terminal state
is documented as `Unlocked` (or whatever the negotiated protocol's
unbind terminal is); reject anything else.

---

### Attack AF-3 — Obtain a "TDI report" for a never-bound device

**Target.** [`tdisp_get_device_report_inner`](../vm/devices/pci/vpci_client/src/tdisp.rs).

**Pre-conditions.**
1. The paravisor's cached `tdi_state` is *not* in `{Locked, Run}` — for
   example `Uninitialized`, `ConfigUnlocked`, `Unlocked`, or `Error`.
   This is the natural state at boot, after a fresh `Unbind`, or after
   an error.
2. The guest (or compromised code path inside the guest) calls
   `tdisp_get_tdi_report`, which calls
   `tdisp_get_device_report(InterfaceReport)`.

**Attack trace.**
1. Paravisor → host: `GuestToHostCommand{ GetTdiReport }`.
2. **Malicious host → paravisor:**
   ```
   GuestToHostResponse {
       result: Success,
       tdi_state_after: Run as i32,        // optional poisoning
       response: Some(GetTdiReport(TdispCommandResponseGetTdiReport {
           report_type: InterfaceReport as i32,
           report_buffer: <attacker-chosen bytes>,
       })),
   }
   ```
3. `send_tdisp_command` returns `Ok(res)`. `update_tdi_state(Run)`
   silently poisons the cache (AF-3 *also* doubles as a free AF-2-style
   cache poisoning vector).
4. `tdisp_get_device_report_inner` extracts `r.report_buffer` and
   returns `Ok(<attacker-chosen bytes>)`.
5. The caller (`tdisp_get_tdi_report`) deserializes the buffer as a
   `TdiReportStruct` and hands it to the attestation layer.

**Effect.** The attestation layer is asked to validate / consume a
"device report" for a device that was never bound. Depending on the
attestation flow, this can:
- short-circuit attestation policy (if the layer trusts the report
  envelope's existence as a "we got here, so bind succeeded" signal),
- feed attacker-controlled bytes into a downstream parser that may
  not be hardened against arbitrary input (because under normal
  protocol flow the report is supposed to be host-blessed and
  protocol-bracketed by Bind+Lock first),
- and — combined with AF-2 — leave the cache in `Run` so subsequent
  reads are also accepted.

The harness counter-example explicitly enumerates `state_before ∈
{Uninitialized, ConfigUnlocked, Unlocked, Error}` cases and shows the
function returns `Ok` in all of them.

**Why current code is vulnerable.** `tdisp_get_device_report_inner` is
a thin pass-through: it sends the command, deserializes the typed
response, and returns the buffer. There is no precondition on
`self.tdi_state()` and no validation of `res.tdi_state_after` against
any expected value.

**Suggested mitigation.** Gate the call at the top of
`tdisp_get_device_report_inner` on the cached state without contacting
the host:

```rust
match self.tdi_state() {
    TdispTdiState::Locked | TdispTdiState::Run => {}
    other => return Err(crate::err!(
        "tdisp_get_device_report refused: device is in state {other:?}, expected Locked or Run"
    )),
}
```

This both blocks the direct attack and breaks the AF-2 → AF-3 chain
(the cache poisoning to `Run` happens *during* the call, so the gate
fires before the host is contacted).

---

## Chained attack scenario (AF-1 + AF-2 + AF-3)

The three findings compose into a single end-to-end exploit allowing a
malicious host to convince a paravisor that an attacker-chosen buffer
is a valid attestation report from a device that is in `Run`, **without
ever having to actually bind, start, or attest the device**:

1. Guest calls `tdisp_unbind` (or this is the natural post-boot state).
   Paravisor cache is `Unlocked` (or `Uninitialized`).
2. Guest (or driver re-init code) calls `tdisp_get_tdi_report`.
   - Per **AF-3**, the host returns `Success` + arbitrary
     `report_buffer` + `tdi_state_after = Run`. Paravisor accepts the
     report and the cache is now `Run`.
3. Guest calls `tdisp_start_device` (an idempotent recovery path).
   - Per **AF-1**, the host returns `Success` + undecodable
     `tdi_state_after`. The cache stays `Run`. Paravisor returns `Ok`.
4. Guest later calls `tdisp_unbind` again.
   - Per **AF-2**, the host returns `Success` + `tdi_state_after = Run`
     + Unbind payload. The unbind reports success but the cache stays
     `Run`. Inspector tooling, isolation-snapshot consumers, etc.
     continue to see a `Run` device.

Note that **Stage E (Harness 7) cuts this chain in one specific
place**: the re-block of MMIO/DMA at unbind happens before the host is
contacted, so even though the cache stays `Run`, the actual MMIO/DMA
isolation does get re-tightened. That is the only positive guarantee
preventing the chained exploit from translating into live data leakage
through stale unblocks. Fixing AF-1/2/3 closes the cache-truthfulness
gap that this last-line defence currently has to compensate for.

---

## Re-evaluation against the TDISP protocol threat model

The attack scenarios above are written from the perspective of a
verifier who treats the paravisor's locally-cached `tdi_state` field
as **authoritative**. This section steps back and re-evaluates them
against the actual TDISP protocol model documented in
[`tdisp-formal-verification-reference.md`](tdisp-formal-verification-reference.md),
which makes a key distinction between (a) the paravisor's local
acceptance state machine and (b) the protocol-level guarantees provided
by trusted components (TDX Module / TPA, device DSM, IDE/SPDM crypto,
PCIe T-bit hardware).

### What the protocol assumes the paravisor is *not* responsible for

Several invariants in the protocol reference are enforced by trusted
components that the paravisor does not implement and cannot bypass
unilaterally:

| Protocol guarantee | Trusted enforcer | Effect on the attacks |
|---|---|---|
| `V1: hash(device_info) = TDX_module.stored_hash(tdi)` (§6.3) | **TDX Module** (Axiom `TDX_MODULE_CORRECT`) | A forged report buffer cannot pass downstream attestation. |
| `SAFE-3: nonce single-use`; START requires the nonce from the immediately preceding LOCK response (INV-8, §6.5) | **Device DSM** (Axiom `DEVICE_CORRECT`) | A "stale" StartTdi against a device whose lock epoch was invalidated is rejected at the wire. |
| `INV-2: no trusted traffic before RUN`; `INV-4: T-bit consistency` | **CPU hardware / root complex** (Axiom `CPU_HARDWARE_CORRECT`) | T=1 TLPs are dropped unless the device is genuinely in RUN with a SECURE IDE stream. |
| `SAFE-6: IDE insecure forces untrust` | **PCIe IDE engine + DSM** | The paravisor's belief about state cannot make a torn-down IDE stream secure. |

In other words, the cached `tdi_state` field in
`VpciClientTdispMutableState` is **paravisor-local bookkeeping**, not
the protocol-level authority. Lying to it does not, by itself,
authorize trusted I/O.

### Re-rating each finding

#### AF-1 — viability: **low as a primary attack, real as a defence-in-depth gap**

The concrete trace requires `state_before == Run` (the cache was
already `Run` before this StartTdi). There are two cases:

1. **Cache faithfully reflects device.** Device is genuinely in RUN; a
   second StartTdi is at worst idempotent. Not an attack.
2. **Cache lies because of an earlier AF-2.** The device is actually
   Unbound, but the cache stuck at `Run`. AF-1 then keeps the cache
   stuck. No new trusted I/O is enabled by this — `INV-2` /
   `CPU_HARDWARE_CORRECT` still prevent T=1 traffic, because the
   device-side DSM is no longer in RUN and the IDE keys / SPDM session
   are gone (§6.6 effects).

So AF-1 does not produce an end-to-end confidentiality or integrity
breach on its own. It is, however, a **faithfulness violation** of the
guest-local acceptance state machine (§3.2): the paravisor's
`TRUSTED_RUN` belief no longer corresponds to a START issued under a
live `EPOCH_ACTIVE` nonce (PSI-26, SAFE-2). Future consumers that gate
on the cache without re-deriving the protocol invariants would
inherit a real bug.

#### AF-2 — viability: **low as a primary attack, real as a defence-in-depth gap**

`tdisp_unbind_inner` *does* clear the security-relevant bookkeeping on
the `Ok` path before returning:
- `validated_mmio_bars.clear()` → no future MMIO unblock can fire (the
  `!validated_mmio_bars.contains_key(bar)` predicate holds vacuously
  for an empty map; but the OTHER predicates fail too).
- `dma_unblocked = false` → DMA re-block bookkeeping is consistent.
- `tdi_report = None` (under `clear_cached_report = true`) → Stage E's
  `tdi_report.is_some()` predicate now fails for any future
  `tdisp_on_mmio_reconfigured` call. **This is the dominant defence:
  even with `tdi_state == Run` cached, no unblock fires because there
  is no report.**
- Harness 7 separately proves that any previously-unblocked MMIO/DMA
  was re-blocked **before** the host was contacted.

So the host's "I claim Run" lie at unbind time is rendered inert by
the report and bar-map clears. The cache field itself is wrong, but
no security-relevant consumer in the current code base trusts it
without ALSO checking `tdi_report.is_some()` (Stage E).

The AF-2 risk is therefore **not** "device data leaks after unbind"
(it does not), it is "the paravisor's local view of the §3.2 state
machine drifts from `UNTRUSTED → UNASSIGNED` to `TRUSTED_RUN`". This
is a **state-tracking hygiene bug** that becomes a vulnerability if a
future patch adds a security-relevant consumer that gates on
`tdi_state == Run` alone.

#### AF-3 — viability: **bounded by downstream attestation, but a real chain-of-custody violation**

Per §6.2, the report is only meaningful after `LOCKED_UNVERIFIED`
(PSI-7: `reported_mmio = ⊥` until report acquisition). Per §6.3, the
report's contents are not trusted until verification step `V1`
succeeds, and `V1` is enforced by the **TDX Module** comparing
`hash(device_info_from_tpa)` against
`TDX_module.stored_device_info_hash(tdi)`.

What a malicious host gains by exploiting AF-3 depends on what the
paravisor's downstream caller does with the buffer:

- **If the buffer flows into a TPA-TD / TDX-Module verification step
  (V1-V6)** → AF-3 is harmless. V1 fails for an unverifiable buffer
  and the guest-local state stays in `REPORT_ACQUIRED`, never
  advancing to `REPORT_VERIFIED`.
- **If a downstream consumer caches "we got a report" without
  re-verifying against the lock epoch (V6 freshness check) or the
  TDX-Module hash (V1)** → AF-3 lets the host plant a buffer that
  looks like a valid report from a never-bound device. Combined with
  `tdisp::devicereport::deserialize_tdi_report` succeeding on
  attacker-chosen well-formed bytes, this is a **chain-of-custody
  violation** of `ORD-2`/`ORD-3` (`LOCK_RESPONSE < GET_REPORT <
  report_verified`).

The paravisor itself does *not* perform V1, so the safety of AF-3
hinges on whether every downstream consumer does. That is outside the
verified surface of these harnesses. Treating AF-3 as a real audit
finding is the conservative posture, because a `Result::Ok` from
`tdisp_get_device_report` against an `Unlocked` device is, by §6.2's
precondition, an out-of-spec response from the paravisor regardless of
what downstream does with it.

#### The chained AF-3 → AF-2 → AF-1 scenario — viability: **state-tracking only**

The chained scenario described above moves the paravisor's cached
state through `Unlocked → Run → Run → Run` against a never-bound
device. Under the protocol's trusted-component axioms:

- No T=1 DMA reaches TD private memory (`INV-2`,
  `CPU_HARDWARE_CORRECT`).
- No nonce-bound START succeeds (the device DSM has no
  `EPOCH_ACTIVE`; `SAFE-3`, `DEVICE_CORRECT`).
- No MMIO/DMA unblock fires from Stage E (the report cache is `None`
  whenever the host did not actually run the LOCK→REPORT→VERIFY flow).
- No report verifies (`V1` fails at the TDX Module).

So the chain produces a **paravisor that is internally inconsistent
with §3.2** but does **not** translate into a confidentiality or
integrity breach against TD private memory or trusted MMIO under the
TDISP trust model.

### Bottom line

Against the formal TDISP threat model:

- **CONFIDENTIALITY (`GOAL_CONFIDENTIALITY`)**: not breached by any of
  AF-1/2/3 alone or chained. Requires a violation of an axiomatic
  trusted component (TDX Module, device DSM, or T-bit hardware) that
  the paravisor cannot induce by mismanaging its own cache.
- **INTEGRITY (`GOAL_INTEGRITY`)**: not breached for the same reason.
- **REPLAY PROTECTION (`GOAL_REPLAY_PROTECTION`)**: not affected.
- **Guest-local acceptance state-machine faithfulness (§3.2,
  `SAFE-2`)**: **violated** by all three findings. The paravisor's
  cached state can drift arbitrarily far from the protocol-mandated
  `UNASSIGNED → … → TRUSTED_RUN → … → UNASSIGNED` lifecycle.
- **Chain-of-custody / ordering (§8, `ORD-2`/`ORD-3`)**: AF-3 in
  particular violates `ORD-2: LOCK_INTERFACE_RESPONSE <
  GET_DEVICE_INTERFACE_REPORT` from the paravisor's local view.

The findings remain **valid audit observations**: the production
paravisor under-enforces its share of the protocol invariants and
relies entirely on trusted external components and on the (currently
holding) coincidence that no internal consumer trusts the cached
`tdi_state` without an accompanying check on `tdi_report.is_some()`.
The risk is **future regression**: any new code path that gates on
`tdi_state == Run` alone — or that treats a `tdisp_get_device_report`
`Ok` as evidence of being bound — would convert these state-tracking
gaps into real CONFIDENTIALITY/INTEGRITY violations of `INV-2`/`INV-6`.

Recommend keeping the failing harnesses checked in as
**executable specifications** of the missing checks, with the severity
re-classified from "remote code attack" to "defence-in-depth gap
against future regressions". Fixing them is cheap (each is a 2–3 line
post-check) and turns the harnesses green, restoring the §3.2 state
machine as a verified local mirror of the protocol-level state.

---

## Correction: state tracking IS a paravisor-local enforcement boundary

The previous section understated the severity by leaning on
`Axiom CPU_HARDWARE_CORRECT` and assuming "the paravisor's cache is
just bookkeeping that mirrors the protocol-authoritative state". That
is wrong for this codebase. There are at least three places where the
cached fields (`tdi_state`, `tdi_report`, `validated_mmio_bars`,
`dma_unblocked`) are consulted **without** any TDX-Module / DSM /
hardware re-derivation, and the paravisor takes a direct
security-relevant action based on the answer.

### Local enforcement points

#### 1. `tdisp_on_mmio_reconfigured` — flips GPA pages host-visible

[`tdisp_on_mmio_reconfigured_inner`](../vm/devices/pci/vpci_client/src/tdisp.rs)
gates exclusively on cached state:

```rust
if self.tdi_state() != TdispTdiState::Run {            // cache lookup
    return Ok(());
}
if self.mutable_state.validated_mmio_bars.contains_key(&bar_id) { … }
match self.classify_bar(bar_id) {                       // reads tdi_report
    ResourceIsolation::PRIVATE => { /* fall through */ }
    SHARED | INVALID => return …,
}
validator.tdisp_unblock_mmio(self.target_vtl, device_id, base_address, 0, length, bar_id)?;
…
validator.tdisp_unblock_dma(self.target_vtl, device_id)?;
```

`validator.tdisp_unblock_mmio` resolves to
[`SevTio::tdisp_unblock_mmio`](../openhcl/openhcl_tdisp/src/sevtio.rs),
which issues
`HvCallModifySparseGpaPageHostVisibility(SHARED)` — i.e. **the
paravisor unilaterally flips the BAR's GPA pages to host-visible**.
There is no TDX Module on SNP. There is no DSM round-trip on this
path. The page-visibility change takes effect on the RMP and on the
IOMMU translation tables that the paravisor itself owns; once it
returns, the host (and the device, post-DMA-unblock) can read those
pages as plaintext.

This is exactly an `INV-2` / `INV-6` / `SAFE-9` style enforcement that
the paravisor performs **on its own authority**. The cached
`tdi_state` and `tdi_report` are the *only* inputs to the gate.

#### 2. `isolation_snapshot` → `VpciIsolatedResourcesReply` to the guest

[`isolation_snapshot`](../vm/devices/pci/vpci_client/src/tdisp.rs)
returns BAR/DMA isolation classifications to the guest based on
`self.mutable_state.tdi_report` and `self.mutable_state.dma_unblocked`.
The reply is what the guest TD uses to decide which BARs it may treat
as TEE memory. A wrong report cached here is a **direct integrity
attack on the guest's view of the world** — the guest cannot
cross-check (it has no other source of truth for which BARs the
device claims as TEE memory).

#### 3. `tdisp_unbind_preserve_report` exists *because* the cached report outlives `Unlocked`

The very existence of
[`tdisp_unbind_preserve_report`](../vm/devices/pci/vpci_client/src/tdisp.rs)
(deliberately keeping `tdi_report.is_some()` after the device is
unbound and the cached `tdi_state` becomes `Unlocked`) is documentary
evidence that **`isolation_snapshot` is expected to return a `Ready`
classification based on a cached report while the device is in
`Unlocked`**. This is exactly the user's hypothetical: "a desynced
cached state resulting in returning a cached report while the device
is actually unlocked".

It is by-design under that API. But it also means that the lifecycle
of the cached report is decoupled from the lifecycle of the device's
real state — and any cache-poisoning attack that lands a fabricated
report into `tdi_report` outlives every subsequent unbind that uses
the `preserve_report` variant.

### Re-rating the chained attack

With (1)–(3) on the table, the chained AF-3 → AF-2 → AF-1 attack does
**not** stop at "internally inconsistent paravisor". The actual
end-to-end exploit is:

1. **Set up:** the guest issues `tdisp_attest_device`, which performs
   `Bind → StartTdi → GetTdiDeviceId → GetTdiReport` and then caches
   the report into `self.mutable_state.tdi_report`. Per AF-3, neither
   `tdisp_get_tdi_device_id` nor `tdisp_get_tdi_report` checks the
   cached state at the call site. The bind / start checks (cache ==
   `Locked` / cache == `Run`) only need the host to claim the matching
   `tdi_state_after`. So a malicious host can pass the entire
   `tdisp_attest_device` pipeline **without ever actually putting the
   device into TDISP** — by claiming `Locked` then `Run` then returning
   a fabricated report.
2. **Cached report poisoning:** `self.mutable_state.tdi_report` now
   holds attacker-chosen `mmio_interface_info` with attacker-chosen
   `is_non_tee_mem` flags per BAR. Cache `tdi_state == Run`.
3. **Trigger:** the guest enables a BAR via the guest command register
   write path, which invokes `tdisp_on_mmio_reconfigured`. The gate
   sees `tdi_state == Run` ✓, BAR not yet in `validated_mmio_bars` ✓,
   `classify_bar()` returns `PRIVATE` because the fabricated report
   says so ✓.
4. **Action:** the paravisor calls `validator.tdisp_unblock_mmio(...)`
   → `HvCallModifySparseGpaPageHostVisibility(SHARED)`. The BAR's GPA
   pages are now **host-visible**.
5. **DMA:** the next iteration of the gate calls
   `validator.tdisp_unblock_dma(...)`. From this point on, the device
   may DMA-write to GPAs that the host has just been granted SHARED
   visibility on. The host can both read the BAR contents and observe
   any DMA the device performs to the (now-shared) memory.

This sequence violates `INV-2` (no trusted traffic before RUN) and
`SAFE-9` (no T=1 in unlocked) **at the paravisor-local enforcement
layer**. The TDX Module / device DSM / IDE hardware are not in this
loop on SNP — the paravisor's cache is the gate.

### What still does not work

For completeness, the chain *does* hit some real defences:

- **Guest TD acceptance (§3.2 step `REPORT_ACQUIRED → REPORT_VERIFIED`).**
  If the TD itself is a TDX guest performing V1–V6 against its TDX
  Module, V1 (`hash(device_info) = TDX_module.stored_hash`) fails for
  a fabricated report. The guest does not advance to
  `RESOURCES_ACCEPTED` and does not issue trusted I/O. **But** this
  defence lives in the *guest* — by the time it kicks in, the
  paravisor has already flipped the GPA pages SHARED. The host already
  wins on confidentiality of the BAR's MMIO contents and any DMA the
  device performs into the (now-shared) GPA region during the window.
- **`tdisp_unblock_mmio` on intercepted BARs.** `mark_bar_intercepted`
  filters out MSI-X table / PBA BARs because the underlying
  `HvCallModifySparseGpaPageHostVisibility` would terminate the
  partition on a non-convertible GPA. So the attack cannot target
  intercepted BARs — but it can target every other BAR.

### Revised risk classification

| Finding | Previous (re-eval) | Corrected |
|---|---|---|
| AF-1 (`start_device` post-check bypass) | Defence-in-depth gap | **Required link in the cache-poisoning chain that opens the gate at (1) above**. |
| AF-2 (`unbind` no post-check) | Defence-in-depth gap | **Allows the cache to stay `Run` after unbind**, so a re-attack can skip even the `Bind → StartTdi` re-issue and reuse a previously-poisoned `tdi_report`. The `clear_cached_report = true` arm clears the report but leaves `tdi_state == Run`; combined with a subsequent `query_capabilities` returning the *cached* `cached_capabilities`, the attacker can avoid touching the host on the re-attack. |
| AF-3 (`get_device_report` no precondition) | Bounded by downstream attestation | **Lands the fabricated buffer into `self.mutable_state.tdi_report` via `tdisp_attest_device`**, which is the cache that `tdisp_on_mmio_reconfigured` and `isolation_snapshot` consult locally to make page-visibility decisions. |

The end-to-end consequence under the SNP/SEV-TIO threat model is
**confidentiality compromise of BAR MMIO regions** that the paravisor
classifies as `PRIVATE` based on a fabricated report, and DMA exposure
of any GPA the device subsequently writes into a now-shared region.
This **does** breach `GOAL_CONFIDENTIALITY` for the data resident on
those pages during the attack window — at the paravisor layer,
without any TDX Module / DSM / hardware axiom being violated.

The user's specific question — "could a desynced cached state result
in returning a cached report while the device is actually unlocked?" —
is answered by `tdisp_unbind_preserve_report` plus AF-2 / AF-3:

- `tdisp_unbind_preserve_report` deliberately preserves
  `tdi_report` when the device transitions to `Unlocked`. Subsequent
  `isolation_snapshot()` returns `Ready { bars, dma }` derived from
  the stale report.
- AF-2 lets `tdi_state` stay `Run` after a normal `tdisp_unbind` if
  the host claims so. The next `tdisp_on_mmio_reconfigured` (e.g.
  triggered by the guest re-enabling a BAR after a perceived
  reconfiguration cycle) opens the gate.
- AF-3 lets the cached report be attacker-chosen in the first place.

### Updated recommendation

The failing harnesses are **not** "defence-in-depth gaps" — they are
**directly exploitable cache-poisoning vectors** for the local
page-visibility enforcement at
`tdisp_on_mmio_reconfigured` and the guest-facing
`isolation_snapshot`. The fixes (per-method state-after post-checks
in `start_device`, `unbind`, and `get_device_report`) are the same
2–3 line additions identified earlier, but the severity is **high**
under the SNP/SEV-TIO threat model where the paravisor — not a TDX
Module — is the local enforcement authority. The harnesses should
remain checked in until those fixes land, at which point they will
verify and serve as the regression gate.

---

## Final consensus (after expert peer review)

The "Correction" section above contains **a critical factual error**
that was caught and corrected through three rounds of adversarial
review against the
[TDISP formal verification reference](tdisp-formal-verification-reference.md)
and the SEV-TIO implementation in
[`openhcl/openhcl_tdisp/src/sevtio.rs`](../openhcl/openhcl_tdisp/src/sevtio.rs).
This section is the consensus position; it supersedes the "Correction"
section's severity classification.

### The error in the "Correction" section

The "Correction" claimed
`tdisp_unblock_mmio` flips BAR GPA pages to `HostVisibilityType::SHARED`
("host-visible"), opening a confidentiality breach. **This is wrong.**
The actual implementation at
[`SevTio::tdisp_unblock_mmio`](../openhcl/openhcl_tdisp/src/sevtio.rs)
calls `modify_gpa_visibility(HostVisibilityType::PRIVATE, &pfns)` —
it flips pages from host-visible (SHARED) to **guest-exclusive
(PRIVATE)**, which is the *secure* direction. The reverse direction —
`HostVisibilityType::SHARED` — is the
[`tdisp_block_mmio`](../openhcl/openhcl_tdisp/src/sevtio.rs)
teardown path, called from `tdisp_unbind`, and is the path that
Harness 7 (`verify_unbind_reblocks_previously_unblocked_resources`)
proves is correctly invoked for every previously unblocked BAR.

Because the `unblock` path is the *secure* direction, a poisoned
cache that opens the gate at
`tdisp_on_mmio_reconfigured_inner` does not produce a confidentiality
leak. At worst it produces a denial-of-service: the SEV PSP firmware
will reject the subsequent `tio_msg_mmio_validate_req` for an unbound
device, leaving the page locked PRIVATE without a TDI mapping.
Availability is explicitly out of scope (`NON_GOAL_AVAILABILITY`).

### The two trust boundaries that hold the chained attack at bay

Even granting AF-1 + AF-2 + AF-3 cache poisoning, the chained attack
cannot reach a confidentiality breach because two trust boundaries
defined in the TDISP / SEV-TIO formal model still hold:

1. **Guest TD V1 verification (§3.2 `REPORT_ACQUIRED → REPORT_VERIFIED`,
   `CHECK-1`).** The guest TD — *not* the paravisor — is obligated by
   the formal model to perform `hash(device_info) =
   PSP.stored_hash(tdi)` against the secure processor before
   advancing to `RESOURCES_ACCEPTED` and issuing `START`. A fabricated
   report relayed by the paravisor (whether via `tdisp_get_tdi_report`
   or via `isolation_snapshot`) fails V1 at the guest, and the guest
   never enables MMIO. The paravisor's `isolation_snapshot` is an
   integrity hint that the guest is required to cross-check, not an
   authoritative classification the guest is obligated to trust.

2. **PSP enforces device-binding on `tio_msg_*_req`** (analogous to
   `Axiom DEVICE_CORRECT` in the reference). The SEV-TIO architecture
   requires the PSP to validate device-binding state before accepting
   `TIO_MSG_MMIO_VALIDATE_REQ` or `TIO_MSG_SDTE_WRITE_REQ`. This is
   load-bearing: if the PSP did not enforce binding, the host VMM
   could already issue these requests directly without going through
   the paravisor at all, and the entire SEV-TIO threat model would
   be vacuous. The paravisor relies on this PSP enforcement the same
   way it relies on T-bit hardware (`Axiom CPU_HARDWARE_CORRECT`).

### Final severity matrix

| Finding | Final classification | Reasoning |
|---|---|---|
| GPA-visibility direction in the "Correction" section | **Documentation error** | `tdisp_unblock_mmio` makes pages PRIVATE (secure), not SHARED. |
| AF-1 (`start_device` post-check bypass) | **Defence-in-depth gap** | State-machine faithfulness violation against §3.2; no live confidentiality/integrity breach because PSP gates on actual binding. |
| AF-2 (`unbind` no `tdi_state` post-check) | **Defence-in-depth gap** | Cached `tdi_state` may stay `Run` after unbind; bookkeeping (`validated_mmio_bars`, `dma_unblocked`, optionally `tdi_report`) is still cleared, and Harness 7 proves re-block runs first. |
| AF-3 (`get_device_report` no precondition) | **Defence-in-depth gap** | Violates `ORD-2` (`LOCK_RESPONSE < GET_REPORT`) at the paravisor layer; bounded by guest V1 verification (`CHECK-1`) before any guest action that depends on the report. |
| Chained AF-3 → AF-2 → AF-1 → page flip | **Not a confidentiality breach** | "Unblock" makes pages PRIVATE, not SHARED; PSP further gates on device binding; guest V1 catches fabricated report before MMIO is enabled. |
| `isolation_snapshot` returning stale/fabricated classification | **Hint disagreement, not a guest breach** | Guest is required by §3.2 / `CHECK-1..9` to perform its own PSP-mediated verification; a paravisor classification that disagrees with the guest's verified report is discarded by the guest. |

### Final position

AF-1, AF-2, and AF-3 are **state-tracking faithfulness violations** of
the §3.2 guest-acceptance state machine as locally mirrored by the
paravisor. They are **not** exploitable confidentiality or integrity
breaches under the formal TDISP / SEV-TIO threat model, because the
paravisor's cached `tdi_state` and `tdi_report` are not the
ultimate authority — the guest TD's PSP-mediated V1 verification and
the PSP's own enforcement of device-binding on
`tio_msg_*_req` are. The findings remain valid audit observations,
worth fixing as **defence-in-depth against future regressions**:
any future paravisor consumer that gates on `tdi_state == Run` alone,
or that treats `tdisp_get_device_report(Ok)` as evidence of a bound
device without re-checking, would convert these gaps into real
violations of `INV-2` / `INV-6`. The fixes are 2–3 lines per method
(per-`*_inner` post-checks against `res.tdi_state_after_enum()` and
the cached `tdi_state`), and the failing harnesses should be left
checked in as executable specifications until the fixes land, at
which point all seven harnesses will verify and serve as the
permanent regression gate.
---

## Addendum: yes, the guest can query the paravisor and get a desynced answer

The "Final consensus" above leaned on "the guest TD performs its own
PSP-mediated V1 verification" to discharge AF-1/2/3 as not exploitable.
That argument is about what the guest *should* do; it does not address
**what the paravisor's own guest-facing APIs actually return**. A
direct audit of the API surface shows that the paravisor itself can
be queried by the guest and answer with a state that does not
correspond to the device's real state — including reporting a
`Ready` isolation snapshot for a BAR while the device is in fact
`Unlocked`.

### Guest-facing API surface

The guest's only path to the paravisor's TDISP state is over VMBus:

```
guest TD
   │  VMBus
   ▼
VPCI device emulator  ──  protocol::MessageType::VPCI_QUERY_ISOLATED_RESOURCES
   │                      vm/devices/pci/vpci/src/device.rs (line 512)
   ▼
TdispVpciAttestationInterface::tdisp_isolation_snapshot()
   │
   ▼
VpciClientTdispState::isolation_snapshot()
   │
   ▼
returns IsolationSnapshot::{Ready { bars, dma } | NotReady}
                derived purely from cached fields:
                   self.mutable_state.tdi_report
                   self.mutable_state.dma_unblocked
                   self.mutable_state.intercepted_bars
```

There is no PSP cross-check, no fresh wire query, and no consultation
of [`tdisp_query_firmware_tdi_state`](../vm/devices/pci/vpci_client/src/tdisp.rs)
inside `isolation_snapshot()`. The cached fields are the entire input.

### Three concrete desync cases the guest can observe

| # | Guest-visible API | Real device state | Cached state returned to guest | Cause |
|---|---|---|---|---|
| 1 | `VPCI_QUERY_ISOLATED_RESOURCES` → `Ready { bars, dma }` | `Unlocked` | `Ready` derived from stale `tdi_report` | **By-design** via `tdisp_unbind_preserve_report` (the doc-comment explicitly documents this so the guest's query keeps working after a graceful re-attestation cycle). |
| 2 | `tdisp_get_tdi_state()` → `Run` | `Unlocked` | `Run` (`isolation_snapshot` returns `NotReady` in this specific case because the report-clear path ran on Ok) | **AF-2**: malicious host returns `Success` + claimed `tdi_state_after == Run` on the unbind response; the per-method post-check does not exist, so the cache is updated to `Run`. |
| 3 | `VPCI_QUERY_ISOLATED_RESOURCES` → `Ready { bars, dma }` with attacker-chosen `bars` classifications | `Unlocked` (never bound) | `Ready` derived from a fabricated `tdi_report` | **AF-3 + AF-1**: the host walks the paravisor through `tdisp_attest_device` (`Bind → StartTdi → GetTdiDeviceId → GetTdiReport`) without ever putting the device into TDISP, by claiming `Locked`/`Run` on the bind/start post-checks (AF-1) and returning a fabricated report payload (AF-3, no state precondition). The fabricated report is cached. |

Case 1 is by-design under the API contract of
`tdisp_unbind_preserve_report` and would not be considered a finding
on its own, but it is concrete evidence that the rest of the system
**is built around the assumption that the cached snapshot may not
match the real device state**. Cases 2 and 3 are the AF-2 / AF-3
findings expressed in terms of the guest's observable API surface.

### What this means for the consensus

The "Final consensus" remains correct in its conclusion that no
trusted-component axiom is violated and that a competently-implemented
guest TD that performs `CHECK-1` against the PSP will not act on a
fabricated isolation snapshot. **But** the user's question — "can the
guest ask the paravisor and get a desynced device state or report
while UNLOCKED?" — is answered **yes**. The paravisor's
`isolation_snapshot()` and `tdisp_get_tdi_state()` are not
authoritative; they reflect cached belief, and the cached belief can
be wrong both by-design (case 1) and as a result of AF-2 / AF-3
(cases 2–3).

The implication is that **any guest-side or paravisor-side caller
that treats `VPCI_QUERY_ISOLATED_RESOURCES`'s `Ready` reply, or
`tdisp_get_tdi_state() == Run`, as evidence of a real bound TDI is
operating on an assumption the paravisor does not enforce**. A guest
that does its own PSP-mediated `CHECK-1` is safe; a guest that does
not is not. The findings document records this as a paravisor-API
contract gap independent of whether any specific guest implementation
in tree happens to do `CHECK-1`. Closing AF-1 / AF-2 / AF-3 with the
2–3-line per-method post-checks tightens the API contract to "the
cached state agrees with the host's most recent claim about
`tdi_state_after`" — still not authoritative against the device, but
no longer free-standing fiction. Going further (calling
`tdisp_query_firmware_tdi_state` from inside `isolation_snapshot()`
on platforms that support it, and rejecting `Ready` if the firmware
state is not `Locked`/`Run`) would tighten the contract to "the
cached state agrees with the PSP's view of the device".

---

## Security properties the paravisor is expected to uphold

The previous sections repeatedly reached for "the guest TD performs
V1" as a defence. That framing collapses once you put the paravisor
in the right slot of the TDISP reference's role table:

> In the OpenVMM/OpenHCL architecture, the paravisor (in VTL2) is the
> entity that speaks SPDM/TDISP to the host TSM, programs IDE keys,
> issues `LOCK_INTERFACE_REQUEST` / `START_INTERFACE_REQUEST`, and
> consumes the device interface report. The VTL0 guest payload speaks
> only VPCI to the paravisor and never sees the TDISP wire. From the
> [TDISP reference document](tdisp-formal-verification-reference.md)'s
> perspective, **the paravisor *is* the "guest TD"** of §3.2 / §6 /
> CHECK-1..9. The `Axiom TDX_MODULE_CORRECT` /
> `Axiom DEVICE_CORRECT` clauses become `Axiom SEV_PSP_CORRECT` and
> `Axiom DEVICE_CORRECT` for the SNP/SEV-TIO codepath.

Under that mapping, every guest-TD obligation in the reference
becomes a **paravisor obligation**. The downstream VTL0 guest is not
in a position to do CHECK-1 — it has no SPDM session, no PSP query
right, no view of the host TSM. If the paravisor does not enforce
these properties, nobody else will. The list below restates the
reference's obligations in that mapping and grades the current code
against each.

### Obligation table

| # | Reference clause | Paravisor obligation in this codebase | Current status |
|---|---|---|---|
| **O-1** | §3.2 `LOCKED_UNVERIFIED → REPORT_VERIFIED`; CHECK-1 | `tdisp_attest_device` MUST verify `hash(device_info_from_report) == SEV_PSP.stored_hash(guest_device_id)` before treating the report as authoritative. | **Not enforced.** No PSP-mediated hash check is wired in `tdisp_attest_device`. The cached `tdi_report` is whatever the host returned. |
| **O-2** | §3.2; CHECK-2 / CHECK-3 | Verify the device's SPDM identity certificate chain and measurements against an owner policy before advancing to `REPORT_VERIFIED`. | **Not enforced** at the paravisor's TDISP layer (delegated to the host TSM, which is adversarial). |
| **O-3** | §6.5 START preconditions; SAFE-2 (`START → previously(report_verified ∧ resources_accepted)`) | `tdisp_start_device` MUST refuse to issue `START_INTERFACE_REQUEST` unless the cached state says report is verified and resources are accepted. | **Not enforced.** `tdisp_start_device_inner` has no precondition on `tdi_report.is_some()` or any "verified" flag, and `tdisp_attest_device` performs `Bind → StartTdi → GetTdiReport` in that order — START is issued *before* the report is even fetched. |
| **O-4** | §3.5 / SAFE-3 / CHECK-6 | Track the lock epoch nonce and refuse to issue `START` with anything other than the nonce returned by the immediately preceding `LOCK_INTERFACE_RESPONSE`. | **Not enforced.** No nonce field is tracked in `VpciClientTdispMutableState`; the production `new_start_tdi_command` does not carry a nonce. Bind/Start are correlated only by the host channel reply. |
| **O-5** | INV-7 / CHECK-7 | Bind LOCK / IDE-key-programming / report retrieval / START to a single SPDM session id; reject mix-and-match. | **Not enforced** at the paravisor's TDISP layer (delegated to host TSM). |
| **O-6** | §6.3 V4 / CHECK-4 / INV-6 | For every MMIO page that is later flipped to PRIVATE on behalf of the device, the page MUST belong to a range present in the verified report. | **Partially enforced.** `tdisp_on_mmio_reconfigured_inner` consults `classify_bar()`, which checks the report; but `classify_bar()` checks only `range_id == bar_id` and the `is_non_tee_mem` flag — it does **not** check that the configured `(base_address, length)` lies within the report's claimed range, only that the BAR has *some* range_id entry. |
| **O-7** | INV-5 / CHECK-5 | No GPA aliasing: every MMIO page maps to at most one GPA across all TDIs in this guest. | **Not enforced** at the TDISP layer; relies on the VPCI emulator's BAR-mapping uniqueness. Worth a separate audit. |
| **O-8** | §3.5 EPOCH_ACTIVE → EPOCH_INVALIDATED on async events; SAFE-6 | On any of: `IDE_STREAM_INSECURE`, `FLR`, `CONFIG_CHANGE_DETECTED`, `SPDM_SESSION_LOST`, transition local cache out of `Run` and force a re-attestation before any further unblock. | **Not enforced.** Paravisor has no event hooks for IDE-insecure / SPDM-loss; it only reacts to host-supplied `tdi_state_after` updates, which an adversary can withhold. |
| **O-9** | §6.6 STOP postconditions; INV-9; SAFE-5 | After `tdisp_unbind`: scrub IDE/SPDM keys, re-block all MMIO/DMA, clear `validated_mmio_bars` / `dma_unblocked` / `tdi_report` (when not preserving). | **Mostly enforced.** Harness 7 proves `tdisp_unbind` re-blocks all previously-unblocked MMIO/DMA before contacting the host. `validated_mmio_bars` / `dma_unblocked` are cleared on `Ok`. **AF-2 gap:** the cached `tdi_state` is not asserted to be `Unlocked` before clearing, leaving an inconsistency between "I cleared the bookkeeping" and "I think the device is in Run". |
| **O-10** | INV-2 (no trusted traffic before RUN); SAFE-9 (no T=1 in unlocked) | Refuse to call `tdisp_unblock_mmio` / `tdisp_unblock_dma` while cached state is anything other than `Run` AND a verified report is present AND a verified bind/start chain produced the current `Run`. | **Partially enforced.** `tdisp_on_mmio_reconfigured_inner` gates on `tdi_state == Run` (Harness 2/3 verified) and on `tdi_report.is_some()` via `classify_bar()`. **It does NOT verify the report or the chain that produced Run** — so AF-1 + AF-3 cache poisoning lets the gate open without an actual bound TDI. |
| **O-11** | §11 error-code semantics; §3.2 ERROR sink | On any host response with `INVALID_INTERFACE_STATE` / `UNSPECIFIED` / unexpected `tdi_state_after`, transition the cached state to a sink that requires explicit re-attestation; do not silently retry. | **Not enforced.** AF-1 / AF-2 / AF-3 are exactly this gap — host-claimed state is accepted without per-method verification of the wire-level `tdi_state_after`. |
| **O-12** | §6.2 ORD-2 (`LOCK_RESPONSE < GET_REPORT`); §3.2 chain ordering | Refuse to issue `GET_DEVICE_INTERFACE_REPORT` unless the cached state says `LOCKED_UNVERIFIED` (paravisor terms: cached `tdi_state ∈ {Locked, Run}` and a Bind has succeeded). | **Not enforced** — this is exactly AF-3. |
| **O-13** | INV-1 (exclusive assignment) | Each `(vpci_device_id, guest_device_id)` is owned by exactly one `VpciClientTdispState`; no double-bind. | **Enforced** by the VPCI client architecture (one `VpciClientTdispState` per VPCI device). Worth a confirmatory check. |
| **O-14** | API contract for the paravisor's *own* downstream consumers | `isolation_snapshot()`, `tdisp_get_tdi_state()`, and `VPCI_QUERY_ISOLATED_RESOURCES` MUST either return a state that corresponds to a verified bound device or return `NotReady`. | **Not enforced.** As documented in the Addendum above, all three of these surfaces can return `Ready` / `Run` against an unbound device under AF-2 / AF-3, and intentionally return `Ready` for an `Unlocked` device under `tdisp_unbind_preserve_report`. |

### What the harnesses currently cover, against this list

| Obligation | Covered by harness | Notes |
|---|---|---|
| O-9 (re-block on unbind) | ✅ Harness 7 (`verify_unbind_reblocks_previously_unblocked_resources`) | Verified end-to-end against symbolic host. |
| O-10 (no unblock outside Run) | ✅ Harness 2 (`verify_dma_unblock_gating`) and Harness 3 (`verify_paravisor_never_unblocks_when_gate_closed`) | Verified — but only against the gate as written, which trusts the cached state without re-deriving Bind→Start→Verify. |
| O-1 / O-2 (V1, SPDM identity, measurements) | ❌ Not covered | Out of scope of these harnesses; needs a different verification strategy. |
| O-3 / O-12 (ordering: report verified before START; lock before report) | ❌ Not covered, **and AF-3 + the production order in `tdisp_attest_device` actively violate this** | Production fetches the report *after* START; reference says verify *before* START. This is independent of AF-3; it is an ordering bug in `tdisp_attest_device` itself. |
| O-4 / O-5 (nonce, session binding) | ❌ Not modelled — the paravisor has no nonce field to verify | Would require adding nonce tracking to production first. |
| O-6 (page-level MMIO containment in report) | ⚠️ Partially modelled by `classify_bar()` invariant; the harness does not assert per-page containment of `(base_address, length)` ⊂ `report.range`. | A new harness "verify\_unblock\_only\_within\_reported\_range" would close this. |
| O-8 (async event response) | ❌ Not modelled | Outside the current harness shape; needs an event-driven model. |
| O-11 (per-method state-after enforcement on host responses) | ✅ Harnesses 4, 5, 6 (`verify_*_post_check`) — all currently FAIL | The failing harnesses *are* the executable specification of O-11 for the three `*_inner` methods. |
| O-14 (API contract: no `Ready`/`Run` against unbound) | ❌ Not directly modelled (Addendum documents the gap by code-audit) | A new harness "`isolation_snapshot()` returns `NotReady` whenever cached state is not derivable from a verified bind+start chain" would close this. |

### Bottom line

The paravisor is the §3.2 guest. CHECK-1..9 and SAFE-1..10 are
**its** obligations. The current code:

- **Provably upholds O-9 and O-10** (Harnesses 2, 3, 7) under
  the trust assumption that the cached state was honestly produced.
- **Provably (intentionally) fails O-11** (Harnesses 4, 5, 6) — the
  paravisor accepts the host's word on per-method state transitions
  without per-method post-checks.
- **Does not enforce O-1, O-2, O-3, O-4, O-5, O-12** at all — these
  are either delegated to host TSM (which is adversarial) or simply
  absent. O-3 (verify *before* START) is in tension with the order of
  operations inside `tdisp_attest_device` itself.
- **Partially enforces O-6** — the report-derived classification
  doesn't check page-level containment of the reconfigured MMIO range.
- **Does not enforce O-14** at the API surface — `isolation_snapshot()`
  / `tdisp_get_tdi_state()` reflect cached belief, including
  intentionally for `tdisp_unbind_preserve_report` and unintentionally
  under AF-2 / AF-3.

The Kani harnesses currently formalize a meaningful but bounded
slice — primarily O-9, O-10, and the negative space around O-11.
Closing AF-1/2/3 brings O-11 from "specified-by-failing-harness" to
"verified". Closing O-1/2/3/4/5/6/12 requires adding actual production
logic (PSP hash check, nonce tracking, report-content verification,
strict ordering inside `tdisp_attest_device`), at which point new
harnesses can verify those too. Until then, the paravisor's §3.2
state machine is **accurately characterized as: a faithful executor
of host-claimed transitions, gated by a few cached-state safety nets,
with no independent trust derivation against the SEV PSP except via
the optional `tdisp_query_firmware_tdi_state` hook that no production
gate currently calls.**

---

## Revised security impact assessment (supersedes "Final consensus")

The "Final consensus" section above downgraded AF-1 / AF-2 / AF-3 to
"defence-in-depth gaps" by appealing to the guest TD's `CHECK-1`
(PSP-mediated `device_info` hash verification) as the load-bearing
defence that catches a fabricated report before any unsafe action.
**That argument no longer holds once the paravisor is correctly
placed as the §3.2 guest TD.** This section is the corrected impact
assessment; it supersedes the "Final consensus" position on severity.

### Why the previous defence collapses

1. The downstream VTL0 guest is not a TDISP `guest TD`. It speaks only
   VPCI to the paravisor; it has no SPDM session with the device, no
   right to query the SEV PSP about a TDI's `device_info_hash`, no
   view of the host TSM. It cannot perform `CHECK-1`. It cannot
   perform any of `CHECK-1..9`.
2. The paravisor in VTL2 is the only entity in the architecture with
   the SPDM session, the PSP access, and the TDISP wire. By the
   reference's role mapping, the paravisor *is* the §3.2 guest TD.
   `CHECK-1..9` are paravisor obligations.
3. As graded in the obligation table above (O-1..O-14), the paravisor
   does **not** perform `CHECK-1` (no PSP-mediated hash verification of
   the report), does **not** perform `CHECK-2`/`CHECK-3` (no SPDM
   identity / measurement validation), and does **not** perform
   `CHECK-6` (no nonce tracking).
4. Therefore the chain of reasoning that the round-3 consensus relied
   on — *"fabricated report → guest does V1 → guest rejects, no
   unsafe action"* — has no actor. The fabricated report is consumed
   by the paravisor's own `classify_bar()` and `isolation_snapshot()`
   without any V1 step ever taking place.

### What changes per finding

| Finding | Previous (round-3) classification | Revised classification | Why it changes |
|---|---|---|---|
| AF-1 (`start_device` post-check bypass) | Defence-in-depth gap | **O-11 violation. Direct gap.** Combined with the absence of O-1/2/3, the paravisor's belief that the device is in `Run` is reachable without the device ever having been bound. Subsequent O-10 gates (which depend on the cached `Run`) are then satisfiable by the adversary. |
| AF-2 (`unbind` no `tdi_state` post-check) | Defence-in-depth gap | **O-11 violation. Direct gap.** After AF-2 the cached `tdi_state` can stay `Run` while the device is in fact `Unlocked`; this directly violates O-14 for `tdisp_get_tdi_state()`. |
| AF-3 (`get_device_report` no precondition) | Defence-in-depth gap | **O-12 violation. Direct gap.** The paravisor accepts a "report" before any LOCK has succeeded, in plain violation of `ORD-2`. The fabricated report lands in `tdi_report` and is consumed by `classify_bar()` and `isolation_snapshot()` *as the paravisor's own authoritative belief*, because no V1 step is downstream of it. |
| Chained AF-3 → AF-2 → AF-1 → page flip | Not a confidentiality breach (because of guest V1) | **There is no V1.** The chain produces a paravisor that calls `tdisp_unblock_mmio` for a fabricated `(bar_id, base_gpa, length)` against a `guest_device_id` the host also fabricated. The local action (`modify_gpa_visibility(PRIVATE)`) is still the secure direction, so the page itself is not exposed to the host by *this* call. **But** the call is followed by `tio_msg_mmio_validate_req` and `rmpadjust_pages(rw=true, vmpl=guest)`, which together commit the fabricated `(device_id, base_gpa, length, range_id)` to the SEV firmware's TDI mapping table and to VMPL0 access for VTL0. Whether this is exploitable end-to-end depends entirely on `Axiom SEV_PSP_CORRECT`'s strength on `TIO_MSG_MMIO_VALIDATE_REQ` for an unbound `device_id` (see O-1 below). The paravisor itself provides no upstream gate. |
| `isolation_snapshot` returning stale/fabricated classification | Hint disagreement, not a guest breach | **O-14 violation. Direct gap.** There is no downstream consumer that re-derives the truth. The reply *is* the paravisor's authoritative answer to `VPCI_QUERY_ISOLATED_RESOURCES`. |
| PSP enforces device-binding on validate/SDTE | Load-bearing axiom | **Still load-bearing**, but now it is the **only** remaining defence against the chained attack instead of being a backstop behind paravisor enforcement + guest V1. |

### Net effect on threat model

- **Confidentiality (`GOAL_CONFIDENTIALITY`)**: not directly breached
  by the AF-1/2/3 chain at the paravisor's local actions, because
  `tdisp_unblock_mmio` flips pages PRIVATE (the secure direction).
  However, the previous "consensus" claim that the chain is *safely
  caught* before any unsafe action is wrong; the chain is caught only
  by the SEV PSP's enforcement of device-binding on
  `TIO_MSG_MMIO_VALIDATE_REQ` (O-1's axiomatic backstop). If the PSP
  accepts a fabricated `(device_id, range_id, base_gpa, length)` —
  whether because the device is actually bound to *some* TDI and the
  PSP only checks the range_id/base/length internally, or because of
  any other firmware behaviour we cannot read off the openvmm code —
  the chain reaches a confused-deputy state.
- **Integrity (`GOAL_INTEGRITY`)**: directly breached at the
  paravisor's API surface. `VPCI_QUERY_ISOLATED_RESOURCES` and
  `tdisp_get_tdi_state()` can return attacker-chosen classifications
  for an unbound device; any consumer (paravisor-internal or guest)
  that acts on those answers acts on adversary input. The breach is
  realized whether or not the PSP catches the downstream
  `tio_msg_mmio_validate_req`.
- **State-machine faithfulness (§3.2)**: directly violated. The
  paravisor's local mirror of the §3.2 state machine can be driven
  arbitrarily far from the real device state — **and** there is no
  in-architecture entity downstream of the paravisor that re-derives
  the protocol-mandated state.

### Revised severity classification

| Finding | Severity (final) | Action |
|---|---|---|
| AF-1 / AF-2 / AF-3 (O-11, O-12, partial O-14) | **High** under the SEV-TIO model where the paravisor is the §3.2 guest. The 2–3-line per-method post-checks should be treated as security fixes, not hygiene. The failing harnesses become regression gates once those fixes land. | Add per-method post-checks; verify Harnesses 4, 5, 6 turn green. |
| O-1 (PSP-mediated `device_info` hash verification) | **High**, currently absent. This is the single most important paravisor-side TDISP property and is not implemented anywhere. | Add the V1 check in `tdisp_attest_device`; add a Kani harness that asserts a successful attest implies V1 was called. |
| O-3 (verify report before START; SAFE-2) | **High**, currently violated by the production order in `tdisp_attest_device` (`Bind → StartTdi → GetTdiReport`). | Reorder to `Bind → GetTdiReport → V1 → StartTdi`, matching the reference §6 ordering. |
| O-4 (lock-epoch nonce; CHECK-6 / SAFE-3) | **High**, currently absent. Without nonce binding, START cannot be tied to the immediately preceding LOCK, making replay across epochs undetectable at the paravisor. | Add nonce field to `VpciClientTdispMutableState`; thread through bind/start; add a Kani harness for nonce single-use. |
| O-6 (page-level MMIO containment check) | **Medium**. `classify_bar()` checks the BAR's range_id but not the actual `(base_address, length)` against the reported range. A host that lies about base/length within an otherwise-valid `range_id` slips past. | Add containment check; new Kani harness. |
| O-14 (`isolation_snapshot()` API contract) | **Medium → High** depending on consumer. Currently can be `Ready` for an `Unlocked` device by-design (`tdisp_unbind_preserve_report`) and as a result of AF-3. | Either fold the freshness check into `isolation_snapshot()` itself (e.g. consult `tdisp_query_firmware_tdi_state` on platforms where available) or document that the reply is advisory and add a separate authoritative API. |

### Revised bottom line

**Severity goes back up.** The previous "defence-in-depth"
classification was an artifact of mis-locating the §3.2 guest TD
role; once the paravisor is in the right slot, AF-1/2/3 are not
hygiene gaps but real per-method enforcement gaps that the paravisor
is supposed to close on its own authority. They sit alongside several
larger absent properties (O-1, O-3, O-4, O-6) that the current
production code does not implement at all and that no Kani harness
yet covers. The seven existing harnesses are still correct as far
as they go (O-9, O-10, and the negative space around O-11), and the
three failing harnesses still document real bugs — but the
remediation work is wider than fixing those three; it is "implement
the paravisor's share of the §3.2 guest-TD obligations". Until that
larger work is done, the paravisor's overall TDISP posture is best
described as **gated on host honesty, with the SEV PSP as the only
non-paravisor backstop on the load-bearing path**.

---

## Role-mapping correction: TDX Module / SEV PSP is not the paravisor

The "Security properties the paravisor is expected to uphold" section
mapped the paravisor onto the §3.2 *guest TD* role for shorthand.
**That is imprecise and worth correcting:** the TDX Module (on Intel
TDX) and the AMD SEV PSP (on SNP/SEV-TIO) are trusted firmware
entities running outside both the paravisor and the guest. They are
the §2.2 trusted-component oracle (`Axiom TDX_MODULE_CORRECT` /
the analogous PSP axiom), not anything the paravisor implements.

The accurate role mapping for OpenVMM/OpenHCL on SNP is:

| Reference role | OpenHCL/SNP entity | Notes |
|---|---|---|
| Trusted firmware oracle (TDX Module on Intel; analogous on SEV) | **AMD SEV PSP** | Lives in CPU firmware. Holds `device_info_hash` for a bound TDI. Validates `TIO_MSG_*_REQ`. Out of paravisor reach except via `sev_guest::tio_msg_*_req` and `tdisp_query_firmware_tdi_state`. |
| TPA TD (performs SPDM on behalf of the guest, measurement-verified by the TDX Module) | **OpenHCL paravisor in VTL2** | Holds the SPDM session, programs IDE keys, issues `LOCK_INTERFACE` / `START_INTERFACE`, fetches and caches the device interface report. From the guest's perspective the paravisor is a measurement-anchored intermediary; from the host's perspective it is the TDISP wire endpoint. |
| Guest TD | **VTL0 guest payload** | Actual workload. Speaks only VPCI to the paravisor. Has its own SNP attestation channel to the PSP (`SNP_GUEST_REQUEST`), but does not have an independent SPDM session with the device. |
| TSM (host-side adversary) | **Host VPCI relay / VMM** | Adversarial. Carries TDISP wire messages between paravisor and device DSM. |
| DSM | **Device firmware** | Trusted under `Axiom DEVICE_CORRECT`. |

### Where this changes the impact assessment, and where it does not

The "Revised security impact assessment" section is still correct in
substance, but the obligation labelling needs the following clarifications:

1. **O-1 (PSP-mediated `device_info` hash verification) is unchanged.**
   The paravisor is the only in-architecture entity with both the SPDM
   session (to receive the report from the host TSM) and a path to the
   PSP (via `sev_guest::tio_msg_*` / `tdisp_query_firmware_tdi_state`).
   The PSP is the trusted oracle that *holds* the
   `stored_device_info_hash`; the paravisor is the entity obligated to
   *fetch* it and *compare* it against the host-relayed report. Neither
   the PSP nor the VTL0 guest can do this comparison alone — the PSP
   doesn't see the host-relayed report, the guest doesn't have the
   SPDM session. The obligation remains with the paravisor; it is the
   *axiomatic backstop* (the PSP's stored hash) that lives outside the
   paravisor.
2. **O-2 / O-5 (SPDM identity, session binding) — same shape.** The
   paravisor owns the SPDM session and is the only entity that can
   verify the certificate chain and bind LOCK / IDE-key /
   GET\_REPORT / START to a single session id. The trusted CA / policy
   may live outside (e.g. in a guest-supplied policy or
   provisioned-at-deploy-time root), but the *enforcement* is in the
   paravisor.
3. **O-4 (nonce / CHECK-6 / SAFE-3) — same shape.** Nonce tracking is
   pure paravisor bookkeeping over a value the device DSM produces and
   the host TSM relays; the PSP is not involved.
4. **O-6 (page-level MMIO containment) — same shape.** The paravisor
   verifies the configured `(base_address, length)` against the
   verified report; the PSP separately validates the MMIO range on
   `TIO_MSG_MMIO_VALIDATE_REQ`. Both checks should hold.
5. **O-9 / O-10 / O-11 / O-12 / O-14** — all still paravisor-local.
6. **The "guest TD does V1" defence stays dead.** Even with the
   precise role mapping, the VTL0 guest does not get SPDM-session
   visibility into the device; it cannot perform `CHECK-1` for *this*
   TDI's report. A guest attestation flow against its own SNP report
   is orthogonal — it attests the guest workload, not the device.
   So the round-3 consensus argument ("guest TD performs V1, breach
   is bounded") still has no actor.
7. **The PSP backstop survives, but is narrower than previously
   framed.** The PSP enforces device-binding state on
   `TIO_MSG_MMIO_VALIDATE_REQ` and `TIO_MSG_SDTE_WRITE_REQ`. It does
   *not* perform the V1 comparison on the paravisor's behalf — V1 is
   the paravisor's responsibility, the PSP merely supplies the
   ground-truth hash. So the chain "AF-3 → fabricated report →
   paravisor classifies BARs → unblock → PSP rejects validate" still
   holds **only** to the extent the PSP rejects validate for an
   unbound device; it does **not** hold via "the PSP would have caught
   the fake hash" because the paravisor never asked the PSP for the
   hash in the first place.

### Net effect on severity

No severity downgrade from the revised assessment. The relabelling
makes the obligations cleaner — the paravisor is the §3.2 guest TD's
**TDISP-protocol agent**, with the PSP as the external trusted
oracle and the VTL0 guest as the actual workload — but the
unenforced obligations (O-1, O-2, O-3, O-4, O-5, O-11, O-12, O-14)
remain exactly where the previous section put them: on the paravisor.
The PSP's role is to be the source of truth for `stored_device_info_hash`,
the validator of `TIO_MSG_*_REQ`, and the executor of
`modify_gpa_visibility` — none of which absolves the paravisor from
performing V1, tracking the lock-epoch nonce, or refusing to issue
START before a verified report.


