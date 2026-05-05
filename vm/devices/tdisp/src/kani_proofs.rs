// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kani formal verification harnesses for the `tdisp` crate.
//!
//! This module covers:
//! - State machine transitions (`TdispHostStateMachine`)
//! - Guest request pre-condition guards
//! - Protocol negotiation invariants
//! - Serialization validation
//! - Device-report parsing safety
//!
//! Because this module is placed inside the `tdisp` crate (not in an external
//! harness crate), it has access to all private fields and methods.
//!
//! # Running
//! ```text
//! cd vm/devices/tdisp
//! cargo kani
//! # or a single named harness:
//! cargo kani --harness verify_is_valid_state_transition_exhaustive
//! ```

#[cfg(kani)]
mod kani_proofs {
    use crate::TDISP_STATE_HISTORY_LEN;
    use crate::TdispGuestRequestInterface;
    use crate::TdispHostDeviceInterface;
    use crate::TdispHostStateMachine;
    use crate::devicereport;
    use crate::serialize_proto;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use tdisp_proto::GuestToHostCommand;
    use tdisp_proto::GuestToHostResponse;
    use tdisp_proto::TdispCommandRequestBind;
    use tdisp_proto::TdispCommandRequestGetDeviceInterfaceInfo;
    use tdisp_proto::TdispCommandRequestGetTdiReport;
    use tdisp_proto::TdispCommandRequestStartTdi;
    use tdisp_proto::TdispCommandRequestUnbind;
    use tdisp_proto::TdispDeviceInterfaceInfo;
    use tdisp_proto::TdispGuestOperationError;
    use tdisp_proto::TdispGuestOperationErrorCode;
    use tdisp_proto::TdispGuestProtocolType;
    use tdisp_proto::TdispGuestUnbindReason;
    use tdisp_proto::TdispReportType;
    use tdisp_proto::TdispTdiState;
    use tdisp_proto::guest_to_host_command::Command;
    use tdisp_proto::guest_to_host_response::Response;

    // ── Shared mock infrastructure ────────────────────────────────────────────

    /// A minimal concrete implementation of [`TdispHostDeviceInterface`] for
    /// use in Kani harnesses.
    ///
    /// Every method succeeds unconditionally, returning valid placeholder values.
    /// Using a *concrete* type (rather than `dyn`) pins the vtable to a single
    /// known implementation, which significantly helps Kani reason about
    /// dynamic dispatch (see Challenge 2 in the plan).
    ///
    /// The report buffer returns 32 zero bytes (2 × `TdispTdiReportMmioInterfaceInfo`
    /// element slots) so that harnesses testing `request_attestation_report`
    /// receive a non-empty, structurally valid buffer.
    struct KaniMockHostInterface;

    impl TdispHostDeviceInterface for KaniMockHostInterface {
        fn tdisp_negotiate_protocol(
            &mut self,
            _requested: TdispGuestProtocolType,
        ) -> anyhow::Result<TdispDeviceInterfaceInfo> {
            // Return IntelTdxConnectV1 — this codebase targets Intel® TDX Connect,
            // not AMD SEV-TIO. The mock always agrees with whatever the guest asks.
            Ok(TdispDeviceInterfaceInfo {
                guest_protocol_type: TdispGuestProtocolType::IntelTdxConnectV1 as i32,
                supported_features: 0,
                tdisp_device_id: 0,
            })
        }

        fn tdisp_bind_device(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        fn tdisp_start_device(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        fn tdisp_unbind_device(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        fn tdisp_get_device_report(
            &mut self,
            _report_type: TdispReportType,
        ) -> anyhow::Result<Vec<u8>> {
            // Return a non-empty buffer of 32 zero bytes.  The caller only
            // checks that the buffer is non-empty; the content is opaque.
            Ok(vec![0u8; 32])
        }
    }

    /// Create a fresh, *unnegotiated* state machine backed by `KaniMockHostInterface`.
    ///
    /// Use this for harnesses that explicitly test protocol negotiation.
    fn new_kani_machine() -> TdispHostStateMachine {
        let iface: Arc<Mutex<dyn TdispHostDeviceInterface>> =
            Arc::new(Mutex::new(KaniMockHostInterface));
        TdispHostStateMachine::new(iface)
    }

    /// Create a state machine that has already completed protocol negotiation
    /// (i.e., `guest_protocol_type == IntelTdxConnectV1`, `current_state == Unlocked`).
    ///
    /// Use this for harnesses that test post-negotiation behaviour.
    fn new_negotiated_kani_machine() -> TdispHostStateMachine {
        let mut m = new_kani_machine();
        m.tdisp_negotiate_protocol(TdispGuestProtocolType::IntelTdxConnectV1)
            .expect("KaniMockHostInterface::tdisp_negotiate_protocol always succeeds");
        m
    }

    /// Create a state machine with `guest_protocol_type` set directly —
    /// without going through `parking_lot::Mutex::lock()` or vtable dispatch.
    ///
    /// Use this for harnesses that only test pure state-transition logic (H3, H5–H8):
    /// those methods do NOT touch `host_interface` at all, so skipping the full
    /// negotiate call chain keeps the CBMC model small and fast.
    fn new_direct_machine() -> TdispHostStateMachine {
        let iface: Arc<Mutex<dyn TdispHostDeviceInterface>> =
            Arc::new(Mutex::new(KaniMockHostInterface));
        let mut m = TdispHostStateMachine::new(iface);
        // Set negotiated state directly — avoids CBMC modelling the
        // parking_lot lock + vtable dispatch that new_negotiated_kani_machine uses.
        m.guest_protocol_type = TdispGuestProtocolType::IntelTdxConnectV1;
        m
    }

    // ── Harness H2 ───────────────────────────────────────────────────────────

    /// Verifies that `is_valid_state_transition` is an *exact* specification
    /// of the TDISP security policy table — it returns `true` for the 5
    /// explicitly allowed state pairs and `false` for all others.
    ///
    /// # Property
    /// For all `(current_state, new_state)` ∈ `{Unlocked, Locked, Run}²`,
    /// `is_valid_state_transition(new_state)` returns `true` **if and only if**
    /// the pair is one of:
    ///   - `(Unlocked, Locked)`  — forward: bind device
    ///   - `(Locked, Run)`       — forward: start TDI
    ///   - `(Run, Unlocked)`     — reset: unbind from Run
    ///   - `(Locked, Unlocked)`  — reset: unbind from Locked
    ///   - `(Unlocked, Unlocked)`— reset: unbind from Unlocked (no-op but allowed)
    ///
    /// # Why this matters
    /// `is_valid_state_transition` is the gatekeeper for every state change.
    /// If any disallowed pair were to return `true`, a malicious guest could:
    /// - Skip attestation by jumping directly to `Run` without going through `Locked`
    /// - Re-bind an already-locked device without resetting attestation state
    ///
    /// # Pre-conditions
    /// - `current_state` ∈ `{Unlocked(1), Locked(2), Run(3)}`:
    ///   `Uninitialized(0)` is excluded because `TdispHostStateMachine::new()`
    ///   starts in `Unlocked`, so an uninitialized machine state is unreachable
    ///   in normal operation. We test only reachable states.
    /// - `new_state` ∈ `{Unlocked(1), Locked(2), Run(3)}`: same rationale.
    /// - Protocol is already negotiated: `is_valid_state_transition` checks
    ///   `ensure_negotiated_protocol` and returns `false` if the protocol has
    ///   not been set. The negotiation guard is separately verified in H9/H10.
    ///
    /// # Post-conditions
    /// - `result == expected`, where `expected` is the manually-computed
    ///   security-policy answer for this `(current_state, new_state)` pair.
    ///
    /// # Kani notes
    /// - Pure function; no loops; no heap allocation. Verifies in <10 s.
    /// - 3×3 = 9 total pairs are exhaustively enumerated.
    #[kani::proof]
    fn verify_is_valid_state_transition_exhaustive() {
        let mut machine = new_negotiated_kani_machine();

        // Pre-condition: set current_state to a symbolic but valid state.
        let current_raw: i32 = kani::any();
        kani::assume(current_raw >= 1 && current_raw <= 3);
        machine.current_state = TdispTdiState::from_i32(current_raw).unwrap();

        // Pre-condition: choose a symbolic target state.
        let new_raw: i32 = kani::any();
        kani::assume(new_raw >= 1 && new_raw <= 3);
        let new_state = TdispTdiState::from_i32(new_raw).unwrap();

        let result = machine.is_valid_state_transition(&new_state);

        // Manually compute the expected answer from the security policy table.
        let expected = matches!(
            (machine.current_state, new_state),
            (TdispTdiState::Unlocked, TdispTdiState::Locked)
                | (TdispTdiState::Locked, TdispTdiState::Run)
                | (TdispTdiState::Run, TdispTdiState::Unlocked)
                | (TdispTdiState::Locked, TdispTdiState::Unlocked)
                | (TdispTdiState::Unlocked, TdispTdiState::Unlocked)
        );

        // Post-condition: the function must agree with the specification.
        assert_eq!(
            result, expected,
            "is_valid_state_transition must exactly match the TDISP security policy table"
        );
    }

    // ── Diagnostic: concrete call to transition_state_to ────────────────────

    /// Minimal concrete harness for `transition_state_to`.
    ///
    /// Uses fully concrete (non-symbolic) values so CBMC has zero symbolic
    /// state to track.  This harness exercises the **production**
    /// `transition_state_to` (with the full `anyhow::Result<()>` signature)
    /// because all values are concrete — CBMC can statically resolve which
    /// branch is taken, so the failure-branch's `anyhow::anyhow!(...)` chain
    /// (and its `Backtrace::capture` → `env::var` → `memchr_naive` cost)
    /// is dead-code eliminated by the goto-instrument pass before SAT
    /// solving.  See `verify_transition_state_to_success_postcondition`
    /// for the symbolic version, which uses the `transition_state_to_kani`
    /// sibling for the same reason.
    #[kani::proof]
    fn verify_transition_concrete_smoke() {
        let mut machine = new_direct_machine();
        // Concrete: Unlocked → Locked (a known-valid transition).
        let result = machine.transition_state_to(TdispTdiState::Locked);
        assert!(result.is_ok());
        assert_eq!(machine.current_state, TdispTdiState::Locked);
        // Skip Drop chain to keep CBMC reachability set small.
        core::mem::forget(machine);
    }

    // ── Harness H3 ───────────────────────────────────────────────────────────

    /// Verifies that a **valid** `transition_state_to` call correctly updates
    /// `current_state`.
    ///
    /// # Properties
    /// 1. **Success post-condition:** After `transition_state_to(new_state)` returns
    ///    `Ok(())`, `current_state == new_state`.
    ///
    /// # Why this matters
    /// Property 1 ensures that a successful transition actually moved the
    /// machine to the intended state — the core correctness property of the
    /// state machine.
    ///
    /// # Pre-conditions
    /// - Protocol is negotiated (set directly via `new_direct_machine`).
    /// - `current_state` and `new_state` are valid non-Uninitialized values.
    /// - The pair is a valid transition (restricts to the success path).
    ///
    /// # Post-conditions
    /// - `current_state == new_state`.
    ///
    /// # Function under test: `transition_state_to_kani`
    /// We verify the `#[cfg(kani)] fn transition_state_to_kani` sibling of
    /// the production `transition_state_to`.  It is a **line-by-line copy**
    /// of the meaningful state-transition logic — same `is_valid_state_transition`
    /// gatekeeper, same `self.current_state = new_state` mutation, same
    /// "no mutation on failure" guarantee.  Only the error-payload type
    /// differs (`()` vs `anyhow::Error`).  See the doc comment on
    /// `transition_state_to_kani` for the full equivalence argument.
    ///
    /// **Why we cannot call the production function directly:** under
    /// symbolic input, CBMC's reachability analysis includes the failure
    /// branch's `anyhow::anyhow!(...)` chain — which captures a backtrace
    /// via `std::env::var(...)` → `core::slice::memchr::memchr_naive`.
    /// CBMC unwinds `memchr_naive` thousands of times trying to find a
    /// fixed point on a symbolic-length C string, and verification never
    /// terminates.  The Kani sibling avoids this entirely.
    ///
    /// # Kani notes
    /// - Uses a 2-bit index into the three concrete enum variants instead of
    ///   `kani::any::<i32>()` + `from_i32().unwrap()`.  This avoids pulling
    ///   in `panic!`/backtrace machinery (`addr2line`, `gimli`) which
    ///   multiplies CBMC's check count.
    /// - History `Vec` push/remove is guarded with `#[cfg(not(kani))]` in
    ///   the production code so CBMC never needs to model heap mutations
    ///   here.  The history cap invariant is verified independently in
    ///   `verify_state_history_cap_invariant`.
    /// - The failure post-condition (state unchanged on error) is covered
    ///   separately by `verify_transition_state_to_error_no_state_change`.
    /// - `core::mem::forget(machine)` at end of harness skips the `Drop`
    ///   chain (Arc/Mutex/dyn-trait vtable drop), keeping the CBMC
    ///   reachability set small.  Drop is not part of the property under
    ///   test.
    #[kani::proof]
    fn verify_transition_state_to_success_postcondition() {
        let mut machine = new_direct_machine();

        // Pre-condition: symbolic starting state via a 2-bit index (avoids
        // from_i32 + unwrap → panic machinery).
        let ci: u8 = kani::any();
        kani::assume(ci <= 2);
        machine.current_state = match ci {
            0 => TdispTdiState::Unlocked,
            1 => TdispTdiState::Locked,
            _ => TdispTdiState::Run,
        };

        // Pre-condition: symbolic target state.
        let ni: u8 = kani::any();
        kani::assume(ni <= 2);
        let new_state = match ni {
            0 => TdispTdiState::Unlocked,
            1 => TdispTdiState::Locked,
            _ => TdispTdiState::Run,
        };

        // Pre-condition: restrict to valid transitions (success path only).
        // We exhaustively list the 5 allowed (current, new) pairs from the
        // TDISP security policy.  This `matches!` predicate is a direct
        // translation of the `is_valid_state_transition` security table.
        kani::assume(matches!(
            (machine.current_state, new_state),
            (TdispTdiState::Unlocked, TdispTdiState::Locked)
                | (TdispTdiState::Locked, TdispTdiState::Run)
                | (TdispTdiState::Run, TdispTdiState::Unlocked)
                | (TdispTdiState::Locked, TdispTdiState::Unlocked)
                | (TdispTdiState::Unlocked, TdispTdiState::Unlocked)
        ));

        // Function under test: see the "Function under test" section of
        // the harness doc comment for why this is the Kani sibling and not
        // the production `transition_state_to`.
        let result = machine.transition_state_to_kani(new_state);

        // The assume above guarantees Ok — assert anyway to catch regressions.
        assert!(result.is_ok(), "transition must succeed on a valid pair");

        // Post-condition: current_state must now equal the target.
        assert_eq!(
            machine.current_state, new_state,
            "on Ok(()), current_state must equal the requested new_state"
        );

        // Skip Drop chain — see "Kani notes" above.  Sound because Drop is
        // not part of the property under test (`transition_state_to_kani`
        // only mutates `current_state` and returns a `Result`).  Memory is
        // reclaimed by Kani's harness teardown.
        core::mem::forget(machine);
    }

    /// Verifies that an **invalid** `transition_state_to` call does NOT alter
    /// `current_state` (failure is non-destructive).
    ///
    /// # Property
    /// If `is_valid_state_transition` returns `false`, then `transition_state_to`
    /// returns `Err(...)` and `current_state` is unchanged.
    ///
    /// # Why this matters
    /// A rejected transition must not silently corrupt the machine state.  If
    /// `current_state` changed on an error return, downstream guards would
    /// operate on an incorrect state, potentially bypassing attestation.
    ///
    /// # Pre-conditions
    /// - Protocol is negotiated (set directly via `new_direct_machine`).
    /// - The pair is an *invalid* transition.
    ///
    /// # Post-conditions
    /// - Returns `Err`.
    /// - `current_state == original_state` (unchanged).
    ///
    /// # Function under test: `transition_state_to_kani`
    /// Same rationale as `verify_transition_state_to_success_postcondition`:
    /// we call the Kani sibling, which performs the same gatekeeper check
    /// (`is_valid_state_transition`) and preserves the same "no mutation on
    /// failure" guarantee as the production function.  See the doc comment
    /// on `transition_state_to_kani` for the full equivalence argument.
    ///
    /// # Kani notes
    /// - Same 2-bit index pattern as the success harness (no from_i32/unwrap).
    /// - `core::mem::forget(machine)` at end of harness skips `Drop`, same
    ///   rationale as the success harness.
    #[kani::proof]
    fn verify_transition_state_to_error_no_state_change() {
        let mut machine = new_direct_machine();

        let ci: u8 = kani::any();
        kani::assume(ci <= 2);
        machine.current_state = match ci {
            0 => TdispTdiState::Unlocked,
            1 => TdispTdiState::Locked,
            _ => TdispTdiState::Run,
        };

        let ni: u8 = kani::any();
        kani::assume(ni <= 2);
        let new_state = match ni {
            0 => TdispTdiState::Unlocked,
            1 => TdispTdiState::Locked,
            _ => TdispTdiState::Run,
        };

        // Pre-condition: only test transitions that must fail.
        // We exhaustively enumerate the 5 *valid* transitions and negate.
        kani::assume(!matches!(
            (machine.current_state, new_state),
            (TdispTdiState::Unlocked, TdispTdiState::Locked)
                | (TdispTdiState::Locked, TdispTdiState::Run)
                | (TdispTdiState::Run, TdispTdiState::Unlocked)
                | (TdispTdiState::Locked, TdispTdiState::Unlocked)
                | (TdispTdiState::Unlocked, TdispTdiState::Unlocked)
        ));

        let original_state = machine.current_state;
        let result = machine.transition_state_to_kani(new_state);

        // Post-condition: must have returned an error.
        assert!(result.is_err(), "transition must fail on an invalid pair");

        // Post-condition: state must be unchanged on failure.
        assert_eq!(
            machine.current_state, original_state,
            "on Err, current_state must remain unchanged (no silent state corruption)"
        );

        // Skip Drop chain — see equivalent note on the success harness.
        core::mem::forget(machine);
    }

    // ── Harness H3c ──────────────────────────────────────────────────────────

    /// Verifies the history ring-buffer cap invariant by directly exercising
    /// the ring-buffer logic in isolation.
    ///
    /// # Property
    /// After any number of push+rotate operations (up to 12 iterations), a
    /// `Vec` that uses the same cap-check + `remove(0)` + `push` pattern
    /// as `state_history` and `unbind_reason_history` never exceeds
    /// `TDISP_STATE_HISTORY_LEN` elements.
    ///
    /// # Why this is separate
    /// The `Vec::push` / `Vec::remove` operations involve CBMC heap models that
    /// cause state-space explosion when combined with the full state machine.
    /// Verifying the ring-buffer logic in a tiny standalone harness lets CBMC
    /// focus on just the bounded arithmetic + allocation model.
    ///
    /// # Pre-conditions
    /// - Vec starts empty with `with_capacity(TDISP_STATE_HISTORY_LEN)`.
    ///
    /// # Post-conditions
    /// - `v.len() <= TDISP_STATE_HISTORY_LEN` after every iteration.
    ///
    /// # Kani notes
    /// - `#[kani::unwind(13)]`: loop runs `TDISP_STATE_HISTORY_LEN + 2 = 12`
    ///   times; +1 for the unwinding check itself.
    #[kani::proof]
    #[kani::unwind(13)]
    fn verify_state_history_cap_invariant() {
        // Mirror the ring-buffer logic from transition_state_to / unbind_all.
        let mut v: Vec<u8> = Vec::with_capacity(TDISP_STATE_HISTORY_LEN);

        // Drive TDISP_STATE_HISTORY_LEN + 2 pushes to confirm the cap holds
        // even after the rotate-on-full path is triggered.
        for _ in 0..(TDISP_STATE_HISTORY_LEN + 2) {
            if v.len() == TDISP_STATE_HISTORY_LEN {
                v.remove(0);
            }
            v.push(kani::any());

            // Invariant: must never exceed cap.
            assert!(
                v.len() <= TDISP_STATE_HISTORY_LEN,
                "ring-buffer must never exceed TDISP_STATE_HISTORY_LEN"
            );
        }
    }

    // ── Harness H4 ───────────────────────────────────────────────────────────

    /// Verifies that `unbind_all` always transitions the device to the
    /// `Unlocked` state, regardless of the starting state and regardless
    /// of whether the host-side unbind callback succeeds or fails.
    ///
    /// # Property
    /// For all valid starting states `s ∈ {Unlocked, Locked, Run}` and
    /// all possible outcomes `host_call ∈ {Ok, Err}` of the host's
    /// `tdisp_unbind_device()` callback:
    ///
    ///   `current_state == Unlocked`  *after*  `unbind_all(reason)` returns,
    ///
    /// regardless of whether `unbind_all` itself returns `Ok` or `Err`.
    /// Additionally:
    ///
    ///   `unbind_all(...) returns Ok(())  ⟺  host_call succeeded`
    ///   (the transition itself always succeeds from a reachable
    ///   pre-state because `Unlocked` is a valid target from every
    ///   reachable state per the H2-verified security policy).
    ///
    /// # Why this matters
    /// `unbind_all` is the universal reset path for the TDISP state
    /// machine.  It is invoked in error-recovery scenarios (e.g., the
    /// guest issued an invalid operation) and on explicit unbind
    /// requests.  The critical security guarantee is that **the device
    /// is reset to `Unlocked` even when the host callback fails**.  If
    /// the state mutation were ordered *after* the host callback (or if
    /// a host failure could leave `current_state` in `Locked` or `Run`),
    /// a confused-deputy could re-use a partially-unbound device
    /// without re-attestation.  This harness pins the safety ordering.
    ///
    /// # Function under test: `unbind_all_kani`
    /// We verify the `#[cfg(kani)] fn unbind_all_kani` sibling of the
    /// production `unbind_all`.  See its doc comment in `lib.rs` for
    /// the full equivalence argument.  In short, the sibling preserves
    /// the same `transition_state_to_kani(Unlocked)` call (which
    /// invokes the same `is_valid_state_transition` gatekeeper as
    /// production) and the same operation ordering (state mutation
    /// **before** host callback), but abstracts away:
    /// - the `parking_lot::Mutex::lock()` + `dyn` vtable call into the
    ///   host (modeled by a nondeterministic `host_call_succeeds` bool);
    /// - the `anyhow::Error` allocation chain on the impossible-state
    ///   error path (replaced with `()`);
    /// - the `unbind_reason_history` `Vec::push` (verified independently
    ///   by `verify_state_history_cap_invariant`).
    ///
    /// # Pre-conditions
    /// - Protocol is negotiated (set directly via `new_direct_machine`,
    ///   bypassing `parking_lot::Mutex::lock()` during setup — see
    ///   anti-pattern #7 in the kani-harness-debug skill).
    /// - `current_state ∈ {Unlocked, Locked, Run}`.  `Uninitialized` is
    ///   excluded because [`TdispHostStateMachine::new`] starts in
    ///   `Unlocked`.
    /// - `host_call_succeeds: bool` — symbolic over both Ok and Err
    ///   outcomes of the host's unbind callback.
    ///
    /// # Post-conditions
    /// - `current_state == TdispTdiState::Unlocked` — **always**, on both
    ///   `Ok` and `Err` returns.  This is the central safety property.
    /// - `result.is_ok()` iff `host_call_succeeds` is true (because the
    ///   pre-state is always a reachable state and `Unlocked` is a
    ///   valid transition target from every reachable state).
    ///
    /// # Kani notes
    /// - Uses the bounded-index `u8` pattern instead of
    ///   `from_i32().unwrap()` (anti-pattern #2 in the
    ///   kani-harness-debug skill).
    /// - Uses `new_direct_machine` to skip `parking_lot::Mutex::lock()`
    ///   during machine construction (anti-pattern #7).
    /// - Calls `unbind_all_kani` (the sibling) instead of `unbind_all`
    ///   (anti-pattern #1: anyhow → memchr unwinding).
    /// - Ends with `core::mem::forget(machine)` to skip the `Drop`
    ///   chain on `Arc<Mutex<dyn TdispHostDeviceInterface>>`
    ///   (anti-pattern #4).
    /// - No `#[kani::unwind(...)]` is needed: the sibling has no loops,
    ///   and the history `Vec::push` is `cfg(not(kani))`-gated in the
    ///   production code.
    #[kani::proof]
    fn verify_unbind_all_always_reaches_unlocked() {
        let mut machine = new_direct_machine();

        // Pre-condition: symbolic starting state via 2-bit u8 index
        // (avoids from_i32 + unwrap → panic machinery).
        let ci: u8 = kani::any();
        kani::assume(ci <= 2);
        machine.current_state = match ci {
            0 => TdispTdiState::Unlocked,
            1 => TdispTdiState::Locked,
            _ => TdispTdiState::Run,
        };

        // Symbolic host callback outcome.  This is the abstraction of
        // `self.host_interface.lock().tdisp_unbind_device()` — any
        // conforming implementation can return either Ok or Err, and
        // the property must hold for both.
        let host_call_succeeds: bool = kani::any();

        let result = machine.unbind_all_kani(host_call_succeeds);

        // ── Central safety post-condition ────────────────────────────────
        // Regardless of whether the host call succeeded or failed, the
        // device must be in the Unlocked state.  This is the strong
        // guarantee that a host-side failure cannot leave the device
        // partially-unbound.
        assert_eq!(
            machine.current_state,
            TdispTdiState::Unlocked,
            "unbind_all must reset current_state to Unlocked even on host-callback failure"
        );

        // ── Functional post-condition ────────────────────────────────────
        // From any reachable pre-state, the transition to Unlocked is
        // valid (per H2's exhaustive security-policy proof).  So the
        // overall result is Ok iff the host call succeeded.
        if host_call_succeeds {
            assert!(
                result.is_ok(),
                "from a valid pre-state with host_call=Ok, unbind_all must return Ok"
            );
        } else {
            assert!(
                result.is_err(),
                "when host_call=Err, unbind_all must propagate the error"
            );
        }

        // Skip Drop chain — see "Kani notes" above.  Sound because Drop
        // is not part of the property under test.  Memory is reclaimed
        // by Kani's harness teardown.
        core::mem::forget(machine);
    }

    // ── Harness H5 ───────────────────────────────────────────────────────────

    /// Verifies the pre-condition enforcement of `request_lock_device_resources`.
    ///
    /// # Property
    /// - `request_lock_device_resources()` returns `Ok(())` **only if**
    ///   `current_state == Unlocked` before the call **and** the host's
    ///   `tdisp_bind_device()` callback succeeded.
    /// - If `current_state != Unlocked`, it returns
    ///   `Err(InvalidDeviceState)` **and** the device is reset to
    ///   `Unlocked` (via `unbind_all`). This holds even when the unbind
    ///   path's host-callback fails (the state mutation precedes the
    ///   callback, per H4's P4 property).
    ///
    /// # Why this matters
    /// The Unlocked → Locked transition is the entry point for binding a
    /// device to a guest partition (TDISP §11.2 CONFIG_LOCKED entry). If
    /// this guard were bypassed, a guest could attempt to re-bind a device
    /// that is already `Locked` (potentially with different guest
    /// contexts), defeating the security promise of P5.
    ///
    /// # Function under test: `request_lock_device_resources_kani`
    /// We verify the `#[cfg(kani)] fn request_lock_device_resources_kani`
    /// sibling. See its doc comment in `lib.rs` for the equivalence
    /// argument. In short, the sibling preserves:
    /// - the `ensure_negotiated_protocol` guard;
    /// - the `current_state != Unlocked` pre-condition check;
    /// - the `unbind_all` reset on the wrong-state path;
    /// - the `transition_state_to(Locked)` mutation on success;
    /// - the host-callback ordering (success only when both bind callback
    ///   succeeds *and* the transition succeeds).
    /// It abstracts away `parking_lot::Mutex::lock()`, the `dyn`-trait
    /// dispatch into `tdisp_bind_device()`, and `anyhow::Error` payloads.
    /// The host callback outcome is modeled by `bind_call_succeeds: bool`,
    /// covering every possible behaviour of any conforming
    /// `TdispHostDeviceInterface`.
    ///
    /// # Pre-conditions
    /// - Protocol is negotiated (set directly via `new_direct_machine`,
    ///   bypassing `parking_lot` during setup — anti-pattern #7 in the
    ///   kani-harness-debug skill).
    /// - `current_state ∈ {Unlocked, Locked, Run}` (every reachable state).
    /// - `bind_call_succeeds: bool` symbolic.
    /// - `unbind_call_succeeds: bool` symbolic (only relevant on the
    ///   wrong-state-reset path; included for completeness).
    ///
    /// # Post-conditions
    /// - Result classification:
    ///   - `Ok` iff `original_state == Unlocked` AND `bind_call_succeeds`.
    ///   - `Err(InvalidDeviceState)` iff `original_state != Unlocked`.
    ///   - `Err(HostFailedToProcessCommand)` iff `original_state == Unlocked`
    ///     and `!bind_call_succeeds` (or, on the unbind path, the unbind
    ///     itself failed — note: cannot happen because `transition_state_to(Unlocked)`
    ///     is always valid from a reachable state, so the production code's
    ///     "impossible" branch is unreachable here too).
    /// - State post-condition:
    ///   - `Ok` → `current_state == Locked`.
    ///   - Wrong-state path → `current_state == Unlocked` (device reset),
    ///     **even when `unbind_call_succeeds == false`** (the safety
    ///     ordering guarantee P4).
    ///   - `Err(HostFailedToProcessCommand)` from `Unlocked` start +
    ///     failed bind → `current_state == Unlocked` (no mutation
    ///     because bind callback fails *before* `transition_state_to_kani`
    ///     is called — same ordering as production).
    ///
    /// # Kani notes
    /// - Bounded-index pattern for the symbolic state.
    /// - `new_direct_machine` to skip `parking_lot::Mutex::lock()` setup.
    /// - `core::mem::forget(machine)` to skip the Drop chain.
    /// - No `#[kani::unwind]`: history `Vec::push` is `cfg(not(kani))`-gated
    ///   in production; the sibling has no loops.
    #[kani::proof]
    fn verify_request_lock_pre_condition() {
        let mut machine = new_direct_machine();

        // Pre-condition: symbolic starting state via 2-bit index.
        let ci: u8 = kani::any();
        kani::assume(ci <= 2);
        machine.current_state = match ci {
            0 => TdispTdiState::Unlocked,
            1 => TdispTdiState::Locked,
            _ => TdispTdiState::Run,
        };
        let original_state = machine.current_state;

        // Symbolic host-callback outcomes.
        let bind_call_succeeds: bool = kani::any();
        let unbind_call_succeeds: bool = kani::any();

        let result =
            machine.request_lock_device_resources_kani(bind_call_succeeds, unbind_call_succeeds);

        match result {
            Ok(()) => {
                // Success → state is Locked, original was Unlocked,
                // bind callback succeeded.
                assert_eq!(
                    machine.current_state,
                    TdispTdiState::Locked,
                    "on Ok, state must be Locked"
                );
                assert_eq!(
                    original_state,
                    TdispTdiState::Unlocked,
                    "request_lock_device_resources can only succeed from Unlocked"
                );
                assert!(
                    bind_call_succeeds,
                    "Ok requires that the host's bind callback succeeded"
                );
            }
            Err(err) => {
                if original_state == TdispTdiState::Unlocked {
                    // From Unlocked + bind failed: state is unchanged
                    // (failure happens before transition_state_to_kani).
                    assert!(
                        !bind_call_succeeds,
                        "Err from Unlocked start requires that the host bind callback failed"
                    );
                    assert_eq!(
                        machine.current_state,
                        TdispTdiState::Unlocked,
                        "no state mutation when bind callback fails before transition"
                    );
                    assert!(
                        matches!(err, TdispGuestOperationError::HostFailedToProcessCommand),
                        "Err from Unlocked + failed bind must be HostFailedToProcessCommand"
                    );
                } else {
                    // Wrong-state path: state is reset to Unlocked
                    // regardless of unbind_call_succeeds (P4 — safety
                    // ordering: state mutation precedes host call).
                    assert_eq!(
                        machine.current_state,
                        TdispTdiState::Unlocked,
                        "on wrong-state Err, state must be reset to Unlocked even on unbind callback failure"
                    );
                    assert!(
                        matches!(
                            err,
                            TdispGuestOperationError::InvalidDeviceState
                                | TdispGuestOperationError::HostFailedToProcessCommand
                        ),
                        "on wrong-state Err, expected InvalidDeviceState or HostFailedToProcessCommand"
                    );
                }
            }
        }

        core::mem::forget(machine);
    }

    // ── Harness H6 ───────────────────────────────────────────────────────────

    /// Verifies the pre-condition enforcement of `request_start_tdi`.
    ///
    /// # Property
    /// - `request_start_tdi()` returns `Ok(())` **only if** `current_state ==
    ///   Locked` AND the host's `tdisp_start_device()` callback succeeded.
    /// - From any other state it returns `Err(InvalidDeviceState)` and the
    ///   state is reset to `Unlocked` (per P4: even when the unbind
    ///   callback fails).
    ///
    /// # Why this matters
    /// The `StartTDI` command transitions a device from `Locked` to `Run`
    /// (TDISP §11.2 RUN entry). If this could be called from `Unlocked` or
    /// `Run`, a device could enter `Run` without being locked (and thus
    /// without completing attestation) or could restart from `Run`
    /// without re-attestation — defeating P1 and P5.
    ///
    /// # Function under test: `request_start_tdi_kani`
    /// Mirror image of H5 with `Locked → Run` instead of `Unlocked →
    /// Locked`. See the doc comment on `request_start_tdi_kani` in
    /// `lib.rs` for the equivalence argument. Same abstractions
    /// (`parking_lot`/anyhow/tracing).
    ///
    /// # Pre-conditions
    /// - Protocol negotiated (set directly via `new_direct_machine`).
    /// - `current_state ∈ {Unlocked, Locked, Run}` (every reachable state).
    /// - `start_call_succeeds: bool` symbolic (host start-device outcome).
    /// - `unbind_call_succeeds: bool` symbolic (only relevant on the
    ///   wrong-state-reset path).
    ///
    /// # Post-conditions
    /// - `Ok` iff `original_state == Locked` AND `start_call_succeeds`.
    ///   On Ok, `current_state == Run`.
    /// - From `Locked` start with failed start callback:
    ///   `Err(HostFailedToProcessCommand)` and `current_state == Locked`
    ///   (no mutation; failure precedes `transition_state_to_kani`).
    /// - From wrong state (`Unlocked` or `Run`): state reset to
    ///   `Unlocked`, `Err` is `InvalidDeviceState` or
    ///   `HostFailedToProcessCommand`.
    ///
    /// # Kani notes
    /// - Bounded-index pattern, `new_direct_machine`, `core::mem::forget`.
    #[kani::proof]
    fn verify_request_start_tdi_pre_condition() {
        let mut machine = new_direct_machine();

        let ci: u8 = kani::any();
        kani::assume(ci <= 2);
        machine.current_state = match ci {
            0 => TdispTdiState::Unlocked,
            1 => TdispTdiState::Locked,
            _ => TdispTdiState::Run,
        };
        let original_state = machine.current_state;

        let start_call_succeeds: bool = kani::any();
        let unbind_call_succeeds: bool = kani::any();

        let result = machine.request_start_tdi_kani(start_call_succeeds, unbind_call_succeeds);

        match result {
            Ok(()) => {
                assert_eq!(
                    machine.current_state,
                    TdispTdiState::Run,
                    "on Ok, state must be Run"
                );
                assert_eq!(
                    original_state,
                    TdispTdiState::Locked,
                    "request_start_tdi can only succeed from Locked"
                );
                assert!(
                    start_call_succeeds,
                    "Ok requires that the host start callback succeeded"
                );
            }
            Err(err) => {
                if original_state == TdispTdiState::Locked {
                    // From Locked + start failed: state unchanged.
                    assert!(
                        !start_call_succeeds,
                        "Err from Locked requires the start callback failed"
                    );
                    assert_eq!(
                        machine.current_state,
                        TdispTdiState::Locked,
                        "no state mutation when start callback fails before transition"
                    );
                    assert!(
                        matches!(err, TdispGuestOperationError::HostFailedToProcessCommand),
                        "Err from Locked + failed start must be HostFailedToProcessCommand"
                    );
                } else {
                    // Wrong state: reset to Unlocked even on unbind failure (P4).
                    assert_eq!(
                        machine.current_state,
                        TdispTdiState::Unlocked,
                        "on wrong-state Err, state must be reset to Unlocked even on unbind callback failure"
                    );
                    assert!(
                        matches!(
                            err,
                            TdispGuestOperationError::InvalidDeviceState
                                | TdispGuestOperationError::HostFailedToProcessCommand
                        ),
                        "on wrong-state Err, expected InvalidDeviceState or HostFailedToProcessCommand"
                    );
                }
            }
        }

        core::mem::forget(machine);
    }

    // ── Harness H7 ───────────────────────────────────────────────────────────

    /// Verifies the state guard of `request_attestation_report`.
    ///
    /// # Property
    /// - `request_attestation_report(report_type)` succeeds **only if**
    ///   `current_state ∈ {Locked, Run}` AND `report_type != Invalid`
    ///   AND the host's report-fetch callback succeeded.
    /// - From `Unlocked`, returns `Err(InvalidGuestAttestationReportState)`
    ///   and the state is reset to `Unlocked` (per P4: even when the
    ///   unbind callback fails).
    /// - From `Locked` or `Run` with `report_type == Invalid`, returns
    ///   `Err(InvalidGuestAttestationReportType)` **without** mutating
    ///   state (P3 — no mutation on rejected operation).
    /// - On success the state is unchanged (the spec permits
    ///   `GET_DEVICE_INTERFACE_REPORT` in CONFIG_LOCKED and RUN; it
    ///   does not change the TDI state).
    ///
    /// # Why this matters
    /// Per TDISP §11.2 ("The TSM is permitted to issue a
    /// GET_DEVICE_INTERFACE_REPORT in CONFIG_LOCKED and RUN"), reports
    /// must only be available after configuration freeze. A report
    /// requested before `Locked` would not reflect the bound
    /// configuration and could mislead the TVM's attestation review.
    ///
    /// # Function under test: `request_attestation_report_kani`
    /// See its doc comment in `lib.rs`. Models the host-fetch result
    /// with a `bool`; returns `Result<(), TdispGuestOperationError>`
    /// instead of `Result<Vec<u8>, _>` (the harness checks the result
    /// classification + post-state, not the buffer content).
    ///
    /// # Pre-conditions
    /// - Protocol negotiated (`new_direct_machine`).
    /// - `current_state ∈ {Unlocked, Locked, Run}` symbolic.
    /// - `report_type` symbolic over `{Invalid, MmioInterfaceInfo,
    ///   InterruptInformation, IoTransition, AddressMapping,
    ///   AttestationReport}` (i.e., 0 through 5; the wire enum's full
    ///   range).
    /// - `report_call_succeeds: bool` symbolic.
    /// - `unbind_call_succeeds: bool` symbolic.
    ///
    /// # Post-conditions
    /// Listed in detail in the assertions below; in summary:
    /// - From `Unlocked`: state reset; `Err(InvalidGuestAttestation
    ///   ReportState)` (or `HostFailedToProcessCommand` on unbind
    ///   failure path — though the strong P4 invariant guarantees
    ///   state == Unlocked regardless).
    /// - From `Locked`/`Run` with `Invalid` report type: state
    ///   unchanged; `Err(InvalidGuestAttestationReportType)`.
    /// - From `Locked`/`Run` with valid report type: state unchanged;
    ///   `Ok` iff host call succeeded, else `Err(HostFailedToProcessCommand)`.
    #[kani::proof]
    fn verify_request_attestation_report_state_guard() {
        let mut machine = new_direct_machine();

        // Bounded-index pattern for state.
        let ci: u8 = kani::any();
        kani::assume(ci <= 2);
        machine.current_state = match ci {
            0 => TdispTdiState::Unlocked,
            1 => TdispTdiState::Locked,
            _ => TdispTdiState::Run,
        };
        let original_state = machine.current_state;

        // Bounded-index pattern for report type, including Invalid (0).
        let ri: u8 = kani::any();
        kani::assume(ri <= 5);
        let report_type = match ri {
            0 => TdispReportType::Invalid,
            1 => TdispReportType::GuestDeviceId,
            2 => TdispReportType::InterfaceReport,
            3 => TdispReportType::CertificateChain,
            4 => TdispReportType::Measurements,
            _ => TdispReportType::IsRegistered,
        };

        let report_call_succeeds: bool = kani::any();
        let unbind_call_succeeds: bool = kani::any();

        let result = machine.request_attestation_report_kani(
            report_type,
            report_call_succeeds,
            unbind_call_succeeds,
        );

        let in_valid_state =
            original_state == TdispTdiState::Locked || original_state == TdispTdiState::Run;

        if !in_valid_state {
            // From Unlocked: state must be reset to Unlocked (P4).
            assert_eq!(
                machine.current_state,
                TdispTdiState::Unlocked,
                "state must be Unlocked after wrong-state error, regardless of unbind callback outcome"
            );
            assert!(
                matches!(
                    result,
                    Err(TdispGuestOperationError::InvalidGuestAttestationReportState
                        | TdispGuestOperationError::HostFailedToProcessCommand)
                ),
                "wrong-state must yield InvalidGuestAttestationReportState or HostFailedToProcessCommand"
            );
        } else if report_type == TdispReportType::Invalid {
            // Right state + Invalid report type: state unchanged (P3).
            assert_eq!(
                machine.current_state, original_state,
                "Invalid report type must not mutate state"
            );
            assert!(
                matches!(
                    result,
                    Err(TdispGuestOperationError::InvalidGuestAttestationReportType)
                ),
                "Invalid report type must yield InvalidGuestAttestationReportType"
            );
        } else {
            // Right state + valid report type: state unchanged regardless
            // of host call outcome.
            assert_eq!(
                machine.current_state, original_state,
                "successful report path must not mutate state"
            );
            if report_call_succeeds {
                assert!(
                    result.is_ok(),
                    "valid state + valid report + successful host call must Ok"
                );
            } else {
                assert!(
                    matches!(
                        result,
                        Err(TdispGuestOperationError::HostFailedToProcessCommand)
                    ),
                    "valid state + valid report + failed host call must yield HostFailedToProcessCommand"
                );
            }
        }

        core::mem::forget(machine);
    }

    // ── Harness H8 ───────────────────────────────────────────────────────────

    /// Verifies that `request_unbind` always returns `Ok` and always leaves
    /// the device in the `Unlocked` state, from any starting state and any
    /// `TdispGuestUnbindReason`.
    ///
    /// # Property
    /// For all `current_state ∈ {Unlocked, Locked, Run}`, all
    /// `TdispGuestUnbindReason` values, and all host-callback outcomes:
    ///   - `current_state == Unlocked` after the call (P2 — universal
    ///     reset reachability), even if the host-side `tdisp_unbind_device()`
    ///     callback fails (P4 — reset before host-fail).
    ///   - `Ok(())` iff the host callback succeeded.
    ///
    /// # Why this matters
    /// The guest may call `Unbind` at any point during the assignment
    /// lifecycle (TDISP §11.2 — STOP_INTERFACE_REQUEST is valid in any
    /// state). The invariant that unbind always reaches `Unlocked`
    /// ensures the device can be reclaimed without additional cleanup
    /// and that no "stuck" state exists.
    ///
    /// # Function under test: `request_unbind_kani`
    /// See its doc comment in `lib.rs`. The sibling discards the
    /// reason classification (since reason has no effect on the
    /// post-state) and avoids the `anyhow::anyhow!(...)` wrapping the
    /// production code uses for non-Graceful reasons.
    ///
    /// # Pre-conditions
    /// - Protocol negotiated.
    /// - `current_state ∈ {Unlocked, Locked, Run}` symbolic.
    /// - `reason ∈ {Unknown, Graceful}` symbolic (the two valid
    ///   `TdispGuestUnbindReason` discriminants).
    /// - `host_call_succeeds: bool` symbolic.
    ///
    /// # Post-conditions
    /// - `current_state == Unlocked` (always, P2 + P4).
    /// - `result.is_ok() == host_call_succeeds`.
    #[kani::proof]
    fn verify_request_unbind_always_returns_unlocked() {
        let mut machine = new_direct_machine();

        let ci: u8 = kani::any();
        kani::assume(ci <= 2);
        machine.current_state = match ci {
            0 => TdispTdiState::Unlocked,
            1 => TdispTdiState::Locked,
            _ => TdispTdiState::Run,
        };

        // Symbolic reason (the two known discriminants).
        let ri: u8 = kani::any();
        kani::assume(ri <= 1);
        let reason = match ri {
            0 => TdispGuestUnbindReason::Unknown,
            _ => TdispGuestUnbindReason::Graceful,
        };

        let host_call_succeeds: bool = kani::any();
        let result = machine.request_unbind_kani(reason, host_call_succeeds);

        // Central safety post-condition: device is always in Unlocked
        // after request_unbind, regardless of host call outcome (P2 + P4).
        assert_eq!(
            machine.current_state,
            TdispTdiState::Unlocked,
            "request_unbind must always leave the device in Unlocked, even on host callback failure"
        );

        // Functional correctness: result reflects host call outcome.
        if host_call_succeeds {
            assert!(
                result.is_ok(),
                "request_unbind must return Ok when host callback succeeds"
            );
        } else {
            assert!(
                matches!(
                    result,
                    Err(TdispGuestOperationError::HostFailedToProcessCommand)
                ),
                "request_unbind must return HostFailedToProcessCommand when host callback fails"
            );
        }

        core::mem::forget(machine);
    }

    // ── Harness H9 ───────────────────────────────────────────────────────────

    /// Verifies that `tdisp_negotiate_protocol` cannot be called twice
    /// (re-entrancy guard).
    ///
    /// # Property
    /// Once `guest_protocol_type != Invalid` (i.e., after a successful
    /// first negotiation), every subsequent call to
    /// `tdisp_negotiate_protocol` returns `Err(InvalidGuestProtocolRequest)`,
    /// regardless of the requested protocol or the host callback's
    /// outcome. The pre-existing `guest_protocol_type` is **not** modified
    /// by the rejected second call (P3 — no mutation on rejection).
    ///
    /// # Why this matters
    /// Re-negotiation after a protocol has been established could allow
    /// a guest to change the protocol type mid-flight (e.g., upgrading
    /// from an older to a newer protocol after resources have already
    /// been locked under the old protocol). This would break the
    /// attestation chain (the TVM's measurements would no longer reflect
    /// the protocol now in use) and could allow device resources to be
    /// accessed under mismatched protocol assumptions.
    ///
    /// # Function under test: `tdisp_negotiate_protocol_kani`
    /// See its doc comment in `lib.rs`. The sibling reproduces all
    /// three early-return paths of production
    /// (re-entrancy guard / Invalid-type guard / host-fail / host-returned-
    /// Invalid) and the success path. The harness exercises the
    /// re-entrancy path.
    ///
    /// # Pre-conditions
    /// - Machine is constructed via `new_direct_machine` (which sets
    ///   `guest_protocol_type = IntelTdxConnectV1` directly, equivalent
    ///   to having completed a first negotiation). This avoids running
    ///   the production `tdisp_negotiate_protocol` (which would drag
    ///   `parking_lot` + the host vtable into reachability).
    /// - `current_state` set explicitly to `Unlocked` (the post-first-
    ///   negotiation state).
    /// - `second_protocol` symbolic over `{Invalid, AmdSevTioV1,
    ///   IntelTdxConnectV1}`.
    /// - `host_call_succeeds` and `host_returned_invalid` symbolic
    ///   (these paths are unreachable when re-entrancy guard fires, but
    ///   we make them symbolic for completeness).
    ///
    /// # Post-conditions
    /// - Result is `Err(InvalidGuestProtocolRequest)` — the re-entrancy
    ///   guard fires regardless of any other parameter.
    /// - `guest_protocol_type == IntelTdxConnectV1` (unchanged).
    /// - `current_state == Unlocked` (unchanged).
    #[kani::proof]
    fn verify_negotiate_protocol_no_reentrancy() {
        let mut machine = new_direct_machine();
        // Make the post-first-negotiation state explicit.
        machine.current_state = TdispTdiState::Unlocked;
        // Sanity precondition the harness depends on.
        kani::assume(machine.guest_protocol_type == TdispGuestProtocolType::IntelTdxConnectV1);

        // Symbolic second-call protocol: any of the 3 known discriminants.
        let pi: u8 = kani::any();
        kani::assume(pi <= 2);
        let second_protocol = match pi {
            0 => TdispGuestProtocolType::Invalid,
            1 => TdispGuestProtocolType::AmdSevTioV1,
            _ => TdispGuestProtocolType::IntelTdxConnectV1,
        };

        let host_call_succeeds: bool = kani::any();
        let host_returned_invalid: bool = kani::any();

        let result = machine.tdisp_negotiate_protocol_kani(
            second_protocol,
            host_call_succeeds,
            host_returned_invalid,
        );

        // Re-entrancy guard fires regardless of any other input.
        assert!(
            matches!(
                result,
                Err(TdispGuestOperationError::InvalidGuestProtocolRequest)
            ),
            "re-negotiation must return InvalidGuestProtocolRequest"
        );

        // No mutation: protocol type is preserved (P3).
        assert_eq!(
            machine.guest_protocol_type,
            TdispGuestProtocolType::IntelTdxConnectV1,
            "guest_protocol_type must not change on rejected re-negotiation"
        );

        // No mutation: state is preserved.
        assert_eq!(
            machine.current_state,
            TdispTdiState::Unlocked,
            "current_state must not change on rejected re-negotiation"
        );

        core::mem::forget(machine);
    }

    // ── Harness H10 ──────────────────────────────────────────────────────────

    /// Verifies that `tdisp_negotiate_protocol` rejects
    /// `TdispGuestProtocolType::Invalid` on a fresh machine.
    ///
    /// # Property
    /// On a machine with `guest_protocol_type == Invalid` (fresh state),
    /// calling `tdisp_negotiate_protocol(Invalid, ...)` returns
    /// `Err(InvalidGuestProtocolRequest)` regardless of the host
    /// callback's outcome. The `guest_protocol_type` remains `Invalid`
    /// (P3 — no mutation on rejected operation).
    ///
    /// # Why this matters
    /// The `Invalid` protocol discriminant is a sentinel meaning "no
    /// protocol". A guest could construct a request with
    /// `protocol_type = 0` either intentionally or through a bug.
    /// Accepting it would either set `guest_protocol_type = Invalid`
    /// (defeating subsequent `ensure_negotiated_protocol` checks) or
    /// fall through to the host call with an undefined semantics.
    /// The guard rejects it with the *specific* error code
    /// `InvalidGuestProtocolRequest` (not a generic
    /// `HostFailedToProcessCommand`), so the guest gets a deterministic
    /// signal of the problem.
    ///
    /// # Function under test: `tdisp_negotiate_protocol_kani`
    /// See its doc comment in `lib.rs`. The Invalid-type guard is the
    /// second early-return after the re-entrancy guard; we exercise it
    /// here.
    ///
    /// # Pre-conditions
    /// - Machine is fresh (no prior negotiation): `new_kani_machine`
    ///   creates a state machine with `guest_protocol_type == Invalid`.
    /// - `host_call_succeeds` and `host_returned_invalid` symbolic
    ///   (these paths are unreachable when the Invalid-type guard fires,
    ///   but symbolic for completeness).
    ///
    /// # Post-conditions
    /// - Returns `Err(InvalidGuestProtocolRequest)`.
    /// - `guest_protocol_type == Invalid` (unchanged).
    #[kani::proof]
    fn verify_negotiate_protocol_rejects_invalid_type() {
        let mut machine = new_kani_machine();
        kani::assume(machine.guest_protocol_type == TdispGuestProtocolType::Invalid);

        let host_call_succeeds: bool = kani::any();
        let host_returned_invalid: bool = kani::any();

        let result = machine.tdisp_negotiate_protocol_kani(
            TdispGuestProtocolType::Invalid,
            host_call_succeeds,
            host_returned_invalid,
        );

        // Invalid type is always rejected with the specific error code.
        assert!(
            matches!(
                result,
                Err(TdispGuestOperationError::InvalidGuestProtocolRequest)
            ),
            "TdispGuestProtocolType::Invalid must always return InvalidGuestProtocolRequest"
        );

        // Machine state is unchanged.
        assert_eq!(
            machine.guest_protocol_type,
            TdispGuestProtocolType::Invalid,
            "guest_protocol_type must remain Invalid after rejected negotiation"
        );

        core::mem::forget(machine);
    }

    // ── Harness H11 ──────────────────────────────────────────────────────────

    /// Verifies that `validate_command` does not falsely reject well-formed commands.
    ///
    /// # Property
    /// For every valid `Command` variant with valid enum fields,
    /// `validate_command` returns `Ok(())`.
    ///
    /// # Why this matters
    /// `validate_command` is the first filter on guest-supplied data. A
    /// false-reject (returning `Err` for a valid command) would break
    /// correctness and could be exploited as a denial-of-service. This harness
    /// proves no such false-reject exists for well-formed inputs.
    ///
    /// # Pre-conditions
    /// - `command.command` is `Some(variant)` (required by `validate_command`).
    /// - Enum fields within the command payload use valid discriminants.
    ///
    /// # Post-conditions
    /// - `validate_command(&command)` returns `Ok(())`.
    ///
    /// # Function under test: `validate_command_kani`
    /// We verify the `#[cfg(kani)] fn validate_command_kani` sibling in
    /// `serialize_proto.rs`. The sibling is a line-by-line copy of
    /// `validate_command`'s decision logic; only the error type differs
    /// (`()` vs `anyhow::Error`). The production function uses
    /// `require_field!` / `require_enum!` macros that call
    /// `anyhow::anyhow!(...)`, which transitively triggers the
    /// memchr-on-symbolic-env-var unwinding chain documented in the
    /// kani-harness-debug skill (anti-pattern #1). The harness only
    /// checks `is_ok()` / `is_err()`, never inspects the error payload.
    ///
    /// # Kani notes
    /// - Structs are constructed directly (not via prost decode) to avoid the
    ///   prost-related challenges documented in Challenge 4 of the plan.
    /// - Each command variant is covered in a separate `if let` branch.
    #[kani::proof]
    fn verify_validate_command_no_false_rejects() {
        use tdisp_proto::TdispCommandRequestBind;
        use tdisp_proto::TdispCommandRequestGetDeviceInterfaceInfo;
        use tdisp_proto::TdispCommandRequestGetTdiReport;
        use tdisp_proto::TdispCommandRequestStartTdi;
        use tdisp_proto::TdispCommandRequestUnbind;
        use tdisp_proto::guest_to_host_command::Command;

        // Symbolically choose which command variant to test.
        let variant: u8 = kani::any();
        kani::assume(variant <= 4);

        let command = GuestToHostCommand {
            device_id: kani::any(),
            command: Some(match variant {
                0 => {
                    // GetDeviceInterfaceInfo: requires a valid non-zero protocol type.
                    let proto_raw: i32 = kani::any();
                    // Pre-condition: valid, non-Invalid protocol type discriminant.
                    kani::assume(proto_raw >= 1 && proto_raw <= 2);
                    Command::GetDeviceInterfaceInfo(TdispCommandRequestGetDeviceInterfaceInfo {
                        guest_protocol_type: proto_raw,
                    })
                }
                1 => {
                    // Bind: no payload fields to validate.
                    Command::Bind(TdispCommandRequestBind {})
                }
                2 => {
                    // GetTdiReport: requires a valid, non-zero report type.
                    let report_raw: i32 = kani::any();
                    // Pre-condition: valid non-Invalid report type.
                    kani::assume(report_raw >= 1 && report_raw <= 5);
                    Command::GetTdiReport(TdispCommandRequestGetTdiReport {
                        report_type: report_raw,
                    })
                }
                3 => {
                    // StartTdi: no payload fields.
                    Command::StartTdi(TdispCommandRequestStartTdi {})
                }
                _ => {
                    // Unbind: requires a valid unbind reason.
                    let reason_raw: i32 = kani::any();
                    // Pre-condition: valid unbind reason discriminant (0 or 1).
                    kani::assume(reason_raw >= 0 && reason_raw <= 1);
                    Command::Unbind(TdispCommandRequestUnbind {
                        unbind_reason: reason_raw,
                    })
                }
            }),
        };

        let result = serialize_proto::validate_command_kani(&command);

        // Post-condition: a well-formed command is never falsely rejected.
        assert!(
            result.is_ok(),
            "validate_command must accept a well-formed command"
        );
    }

    // ── Harness H12 ──────────────────────────────────────────────────────────

    /// Verifies the `validate_response` success-path invariant: a response
    /// with `result == Success` is valid **only if** the `response` field is
    /// `Some`, and invalid if it is `None`.
    ///
    /// # Property
    /// For a `GuestToHostResponse` with:
    ///   - `result == TdispGuestOperationErrorCode::Success`
    ///   - valid `tdi_state_before` and `tdi_state_after`
    /// then `validate_response` returns:
    ///   - `Ok(())` iff `response.is_some()`
    ///   - `Err(...)` iff `response.is_none()`
    ///
    /// # Why this matters
    /// The success path in `validate_response` enforces that every successful
    /// TDISP operation includes a response payload. A missing response payload
    /// on a "success" result would allow the host to signal success without
    /// actually providing the data the guest needs (e.g., no `TdiReport`
    /// buffer on a successful `GetTdiReport`).
    ///
    /// # Pre-conditions
    /// - `result == Success` (i32 value = 1).
    /// - `tdi_state_before` and `tdi_state_after` are valid state discriminants.
    /// - `response` is symbolically `Some` or `None`.
    ///
    /// # Post-conditions
    /// - `response.is_some()` → `validate_response` returns `Ok`.
    /// - `response.is_none()` → `validate_response` returns `Err`.
    ///
    /// # Function under test: `validate_response_kani`
    /// We verify the `#[cfg(kani)] fn validate_response_kani` sibling in
    /// `serialize_proto.rs`. Same rationale as
    /// `verify_validate_command_no_false_rejects`: the production
    /// `validate_response` uses `anyhow::anyhow!(...)` on every reject
    /// path (which triggers the memchr unwinding chain). The sibling is
    /// a line-by-line copy of the decision logic with `Result<(), ()>`.
    ///
    /// # Kani notes
    /// - Uses a `Bind` response (no sub-validation required) to keep the
    ///   test tractable and focused on the `response != None` check.
    #[kani::proof]
    fn verify_validate_response_success_requires_response_field() {
        use tdisp_proto::TdispCommandResponseBind;
        use tdisp_proto::guest_to_host_response::Response;

        // Pre-condition: valid before/after state discriminants.
        let before_raw: i32 = kani::any();
        let after_raw: i32 = kani::any();
        kani::assume(before_raw >= 1 && before_raw <= 3);
        kani::assume(after_raw >= 1 && after_raw <= 3);

        // Symbolic choice: is the response field present?
        let has_response: bool = kani::any();

        let response_field = if has_response {
            // Provide a valid Bind response (empty payload — no sub-validation).
            Some(Response::Bind(TdispCommandResponseBind {}))
        } else {
            None
        };

        let resp = GuestToHostResponse {
            // Pre-condition: result is Success (discriminant 1).
            result: TdispGuestOperationErrorCode::Success as i32,
            tdi_state_before: before_raw,
            tdi_state_after: after_raw,
            response: response_field,
        };

        let validation_result = serialize_proto::validate_response_kani(&resp);

        if has_response {
            // Post-condition: present response → validation passes.
            assert!(
                validation_result.is_ok(),
                "validate_response must accept a Success response with a response field"
            );
        } else {
            // Post-condition: absent response → validation fails.
            assert!(
                validation_result.is_err(),
                "validate_response must reject a Success response with no response field"
            );
        }
    }

    // ── Harness H13 ──────────────────────────────────────────────────────────

    /// Verifies a **concrete** round-trip for the `Bind` command.
    ///
    /// # Property
    /// `deserialize_command(serialize_command(&cmd))` returns `Ok(cmd2)` where
    /// `cmd2.device_id == cmd.device_id` and `cmd2.command` matches the
    /// original `Bind` variant — for the specific concrete `device_id == 42`.
    ///
    /// # Scope limitation (descoped from symbolic to concrete)
    /// The original H13 was intended to verify the round-trip for all
    /// `device_id < 256`. CBMC cannot tractably reason about prost's
    /// `encode_to_vec` because the resulting `Vec<u8>` has symbolic
    /// capacity, which drags `RawVecInner::with_capacity_in` →
    /// `Layout::repeat` → `handle_alloc_error` → the entire `prost::alloc`
    /// allocation tree into reachability. Verification with symbolic
    /// `device_id` does not terminate.
    ///
    /// Per "Challenge 4 Plan B" in the verification priorities document
    /// (`tdisp_kani_verification_priorities.md`), the round-trip property is
    /// descoped to a concrete-input smoke test under Kani. The full
    /// symbolic round-trip is verified by the existing `cargo test` suite
    /// (which exercises `serialize_proto`'s round-trip with many concrete
    /// values), and the OPEN bug class this harness was meant to catch
    /// (a wire-format incompatibility between encode and decode for the
    /// `Bind` variant) is detectable with the concrete check too.
    ///
    /// # What this still proves under Kani
    /// - `serialize_command` does not panic on a well-formed `Bind`
    ///   command.
    /// - `deserialize_command` does not panic on the byte stream produced
    ///   by `serialize_command`.
    /// - The decoded `Bind` variant survives the round-trip
    ///   (variant + `device_id` field).
    ///
    /// # What this does NOT prove (vs the original symbolic intent)
    /// - Round-trip for all `device_id` values — only the specific value
    ///   `42` is checked.
    /// - Round-trip for other command variants (`GetDeviceInterfaceInfo`,
    ///   `GetTdiReport`, `StartTdi`, `Unbind`).
    ///
    /// # Kani notes
    /// - `#[kani::unwind(64)]`: prost varint encoder loops; 64 is
    ///   conservative.
    /// - This harness uses the production `serialize_command` /
    ///   `deserialize_command` because under fully-concrete inputs CBMC
    ///   can statically resolve the allocation sizes; the goto-program
    ///   for the prost code remains tractable. (The hang only manifests
    ///   with symbolic inputs.)
    #[kani::proof]
    #[kani::unwind(64)]
    fn verify_bind_command_round_trip() {
        let device_id: u64 = 42;

        let original = GuestToHostCommand {
            device_id,
            command: Some(Command::Bind(TdispCommandRequestBind {})),
        };

        let bytes = serialize_proto::serialize_command(&original);
        let decoded = serialize_proto::deserialize_command(&bytes);

        assert!(decoded.is_ok(), "Bind command round-trip must succeed");

        if let Ok(cmd) = decoded {
            assert_eq!(
                cmd.device_id, device_id,
                "device_id must survive round-trip"
            );
            assert!(
                matches!(cmd.command, Some(Command::Bind(_))),
                "command variant must survive round-trip"
            );
        }
    }

    // ── Harness H14 ──────────────────────────────────────────────────────────

    /// Verifies that `deserialize_tdi_report` never panics on any bounded
    /// symbolic byte slice up to a fixed length.
    ///
    /// # Property
    /// For any byte buffer of length ≤ 64, `deserialize_tdi_report`
    /// either returns `Ok(...)` or `Err(...)` — it never panics.
    /// Additionally, when `Ok`, the count of successfully-decoded MMIO
    /// entries does not exceed what the buffer can physically hold
    /// (`(len - 16) / 16`).
    ///
    /// # Why this matters
    /// `deserialize_tdi_report` processes data from the host interface
    /// (the device's reply to `GET_DEVICE_INTERFACE_REPORT`). The key
    /// field `mmio_range_count` is a `u32` decoded from the buffer.
    /// The code then uses it as the element count for a
    /// `zerocopy::ref_from_prefix_with_elems` call. If `mmio_range_count`
    /// is adversarially large (e.g., 2³¹), and zerocopy did not
    /// correctly check the buffer size, this could cause an
    /// out-of-bounds read or integer overflow.
    ///
    /// Kani proves that the zerocopy error path is correctly exercised
    /// for all bounded inputs in this length range — the function always
    /// returns `Err` rather than panicking on adversarial inputs.
    ///
    /// # Function under test: `deserialize_tdi_report_kani`
    /// We verify the `#[cfg(kani)] pub fn deserialize_tdi_report_kani`
    /// sibling in `devicereport.rs`. The sibling makes the **same two
    /// zerocopy calls** as production (which is what the no-panic
    /// property is fundamentally about); it only abstracts away the
    /// `anyhow::Error` payload (preventing memchr unwinding) and the
    /// `to_vec()` allocations at the end (irrelevant to no-panic). See
    /// the doc comment on `deserialize_tdi_report_kani` for the full
    /// equivalence argument.
    ///
    /// # Pre-conditions
    /// - `len <= BUF_LEN` where `BUF_LEN = 64` is a fixed constant. Using
    ///   a fixed-size buffer with a symbolic prefix length avoids the
    ///   `Vec<u8>` heap-allocation modeling that defeats CBMC.
    ///
    /// # Post-conditions
    /// - The function returns `Ok` or `Err` (no `unreachable!()` /
    ///   `unwrap` panic — the property under proof).
    /// - When `Ok`: the returned MMIO element count is consistent with
    ///   the data physically present in the buffer.
    ///
    /// # Kani notes
    /// - Buffer length capped at 64 (16-byte header + up to 3 MMIO entries
    ///   of 16 bytes each = 64 bytes). Sufficient to exercise both the
    ///   "no entries fit" and "some entries fit" paths.
    /// - Fixed-size array (`[u8; 64]`) instead of `Vec<u8>` to avoid heap
    ///   allocation modeling.
    /// - `#[kani::unwind(17)]`: legacy bound for the `to_vec()` loop in
    ///   the original production function call; harmless to keep.
    #[kani::proof]
    #[kani::unwind(17)]
    fn verify_deserialize_tdi_report_no_panic() {
        const BUF_LEN: usize = 64;

        // Symbolic fixed-size array (no heap allocation modeling).
        let buffer: [u8; BUF_LEN] = kani::any();

        // Symbolic prefix length within the array.
        let len: usize = kani::any();
        kani::assume(len <= BUF_LEN);
        let data = &buffer[..len];

        let result = devicereport::deserialize_tdi_report_kani(data);

        // Post-condition: the function must not panic. Reaching here
        // proves it (the match below is exhaustive).
        match result {
            Ok(mmio_count) => {
                // Each TdispTdiReportMmioInterfaceInfo is 16 bytes. The
                // header TdiReportStructSerialized is also 16 bytes.
                // Maximum possible MMIO entries = (len - 16) / 16.
                let max_possible_entries = if len >= 16 { (len - 16) / 16 } else { 0 };
                assert!(
                    mmio_count <= max_possible_entries,
                    "mmio_count must not exceed what the buffer can hold"
                );
            }
            Err(_) => {
                // An error is correct and expected for many inputs
                // (truncated header, impossible mmio_range_count). No
                // additional assertion needed — reaching here proves
                // no panic.
            }
        }
    }
}
