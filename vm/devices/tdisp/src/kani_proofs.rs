// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kani formal-verification harnesses for the TDISP host state machine.
//!
//! These harnesses verify the security-critical core of
//! [`crate::TdispHostStateMachine`]: the **state-transition gate**
//! [`crate::TdispHostStateMachine::is_valid_state_transition`] that
//! every mutation of `current_state` funnels through. The dispatcher
//! in [`crate::TdispHostDeviceTargetEmulator`] is only a protobuf
//! demux and is intentionally not in scope; every safety property of
//! TDISP (negotiation gating, state-transition ordering) is enforced
//! by the state machine itself.
//!
//! Harnesses begin with the state machine in an **unconstrained
//! starting state**: `current_state` and `guest_protocol_type` are
//! fully symbolic over their protobuf-enum domains. Verifying from
//! an unconstrained start rules out attacks that exploit residual
//! state — e.g. a prior failed transition leaving an unexpected
//! value in `guest_protocol_type`.
//!
//! # Why these proofs can terminate at all
//!
//! The crate's internal helpers (`ensure_negotiated_protocol`,
//! `transition_state_to`, `unbind_all`) and the
//! `TdispUnbindReason::InvalidGuestUnbindReason` variant use
//! [`crate::Result`] / [`crate::err!`] / [`crate::Context`] (see the
//! `err_shim` module in `lib.rs`). Under non-Kani these resolve to
//! `anyhow`; under Kani they resolve to a unit-like stub that does
//! not invoke `Backtrace::capture` → `getenv` →
//! `core::slice::memchr::memchr_naive`, which CBMC cannot bound on a
//! symbolic-length C string. The `tracing` crate is also entirely
//! removed from the dep graph under `cfg(kani)` and replaced by a
//! local `mod tracing` of no-op macros (see the `tracing` shim in
//! `lib.rs`). Together, these eliminate the two reachability
//! blow-ups documented in `.github/skills/model-checking/SKILL.md`.

use crate::TdispGuestRequestInterface;
use crate::test_helpers::any_guest_protocol_type;
use crate::test_helpers::any_optional_tdi_state;
use crate::test_helpers::any_requested_op;
use crate::test_helpers::any_tdi_state;
use crate::test_helpers::new_symbolic_tdisp_state_machine;
use tdisp_proto::TdispGuestProtocolType;
use tdisp_proto::TdispReportType;
use tdisp_proto::TdispTdiState;

/// Exhaustive proof of the
/// [`crate::TdispHostStateMachine::is_valid_state_transition`]
/// predicate.
///
/// This is a **pure-function** proof: no host callbacks, no state
/// mutation. The predicate decides, for a symbolic
/// `(current_state, new_state, guest_protocol_type)` triple,
/// whether the transition is allowed. It is the gate that every
/// mutating operation in [`crate::TdispHostStateMachine`] funnels
/// through, so verifying its full truth table directly is the most
/// concise statement of the state-machine's transition safety.
///
/// # Setup
///
/// `current_state`, `new_state`, and `guest_protocol_type` are all
/// fully symbolic over their protobuf-enum domains.
///
/// # Property
///
/// `is_valid_state_transition` returns `true` iff:
///
/// - a non-`Invalid` protocol has been negotiated, AND
/// - the `(current_state, new_state)` pair is one of the five
///   allowed transitions:
///   - `Unlocked → Locked`, `Locked → Run`           (forward progress)
///   - `Run → Unlocked`, `Locked → Unlocked`         (graceful unbind)
///   - `Unlocked → Unlocked`                          (idempotent reset)
///
/// In particular, with `guest_protocol_type == Invalid` the
/// predicate must reject **every** transition (the
/// `ensure_negotiated_protocol` gate) — including the no-op
/// `Unlocked → Unlocked` self-transition.
///
/// # Why this is the strongest statement of single-step safety
///
/// `is_valid_state_transition` is the only predicate consulted by
/// [`crate::TdispHostStateMachine::transition_state_to`], which is
/// the only path by which `current_state` is ever mutated (apart
/// from the unconditional `Unlocked` reset in
/// [`crate::TdispHostStateMachine::unbind_all`], which is itself
/// gated on the same allowed-successor table). Verifying this
/// predicate exhaustively therefore characterizes the entire
/// state-transition surface of the crate without exercising the
/// (slow) host-callback machinery.
#[kani::proof]
fn verify_is_valid_state_transition_truth_table() {
    let current_state = any_tdi_state();
    let new_state = any_tdi_state();
    let guest_protocol_type = any_guest_protocol_type();

    let sm = new_symbolic_tdisp_state_machine("kani-device", current_state, guest_protocol_type);

    let actual = sm.is_valid_state_transition(&new_state);

    let protocol_negotiated = guest_protocol_type != TdispGuestProtocolType::Invalid;
    let pair_allowed = matches!(
        (current_state, new_state),
        (TdispTdiState::Unlocked, TdispTdiState::Locked)
            | (TdispTdiState::Locked, TdispTdiState::Run)
            | (TdispTdiState::Run, TdispTdiState::Unlocked)
            | (TdispTdiState::Locked, TdispTdiState::Unlocked)
            | (TdispTdiState::Unlocked, TdispTdiState::Unlocked)
    );
    let expected = protocol_negotiated && pair_allowed;

    assert_eq!(actual, expected);

    // Avoid Drop chains for `Arc<Mutex<dyn>>`, `Vec<TdispTdiState>`,
    // and `Vec<TdispUnbindReason>` — they dominate CBMC reachability
    // and add nothing to the verified property.
    core::mem::forget(sm);
}

// ----------------------------------------------------------------------------
// guest_protocol_type monotonicity / no-downgrade
// ----------------------------------------------------------------------------
//
// Once `guest_protocol_type` has been set to a non-`Invalid` value
// by a successful `tdisp_negotiate_protocol`, no subsequent call on
// the `TdispGuestRequestInterface` may change it — neither back to
// `Invalid` nor to a different non-`Invalid` value. This rules out
// the classic downgrade-attack pattern (TLS-style "renegotiate to
// a weaker cipher"): a malicious host returning further negotiation
// responses cannot demote the device's protocol mid-session.
//
// `tdisp_negotiate_protocol` has its own first-call gate (the
// "already negotiated" early-return) that prevents replays *for that
// method*; the four other methods have no business mutating
// `guest_protocol_type` at all. Each harness below asserts the
// invariant for one method, so each runs against minimal symbolic
// state and stays well clear of the multi-method SAT blowup that
// killed the combined harness.

/// `tdisp_negotiate_protocol` is **one-shot**: once a non-`Invalid`
/// protocol is in place, the method short-circuits with the
/// "already negotiated" check and `guest_protocol_type` is
/// unchanged regardless of the (symbolic) host response.
///
/// # Property
///
/// > `guest_protocol_type_before != Invalid`
/// > ⟹ `guest_protocol_type_after == guest_protocol_type_before`
///
/// This is the **anti-downgrade** invariant for the negotiation
/// path itself — the only method that has any legitimate reason to
/// touch `guest_protocol_type`.
#[kani::proof]
fn verify_negotiate_does_not_downgrade_protocol() {
    let current_state = any_tdi_state();
    let guest_protocol_type = any_guest_protocol_type();
    kani::assume(guest_protocol_type != TdispGuestProtocolType::Invalid);

    let mut sm =
        new_symbolic_tdisp_state_machine("kani-device", current_state, guest_protocol_type);

    let _ = sm.tdisp_negotiate_protocol(any_guest_protocol_type());

    assert_eq!(sm.kani_guest_protocol_type(), guest_protocol_type);

    core::mem::forget(sm);
}

/// `request_lock_device_resources` (Bind) must not mutate
/// `guest_protocol_type` regardless of starting state or
/// (symbolic) host response.
#[kani::proof]
fn verify_bind_does_not_change_protocol() {
    let current_state = any_tdi_state();
    let guest_protocol_type = any_guest_protocol_type();

    let mut sm =
        new_symbolic_tdisp_state_machine("kani-device", current_state, guest_protocol_type);

    let _ = sm.request_lock_device_resources();

    assert_eq!(sm.kani_guest_protocol_type(), guest_protocol_type);

    core::mem::forget(sm);
}

/// `request_start_tdi` must not mutate `guest_protocol_type`
/// regardless of starting state or (symbolic) host response.
#[kani::proof]
fn verify_start_tdi_does_not_change_protocol() {
    let current_state = any_tdi_state();
    let guest_protocol_type = any_guest_protocol_type();

    let mut sm =
        new_symbolic_tdisp_state_machine("kani-device", current_state, guest_protocol_type);

    let _ = sm.request_start_tdi();

    assert_eq!(sm.kani_guest_protocol_type(), guest_protocol_type);

    core::mem::forget(sm);
}

/// `request_attestation_report` must not mutate
/// `guest_protocol_type` regardless of starting state, requested
/// report type, or (symbolic) host response.
#[kani::proof]
fn verify_get_report_does_not_change_protocol() {
    let current_state = any_tdi_state();
    let guest_protocol_type = any_guest_protocol_type();
    let report_type = if kani::any() {
        TdispReportType::InterfaceReport
    } else {
        TdispReportType::Invalid
    };

    let mut sm =
        new_symbolic_tdisp_state_machine("kani-device", current_state, guest_protocol_type);

    let _ = sm.request_attestation_report(report_type);

    assert_eq!(sm.kani_guest_protocol_type(), guest_protocol_type);

    core::mem::forget(sm);
}

/// `request_unbind` must not mutate `guest_protocol_type`
/// regardless of starting state, unbind reason, or (symbolic) host
/// response. (The TDI state may be reset to `Unlocked`, but the
/// negotiated protocol persists across an unbind — the device does
/// not need to renegotiate to be re-Locked.)
#[kani::proof]
fn verify_unbind_does_not_change_protocol() {
    let current_state = any_tdi_state();
    let guest_protocol_type = any_guest_protocol_type();
    let reason = if kani::any() {
        tdisp_proto::TdispGuestUnbindReason::Graceful
    } else {
        tdisp_proto::TdispGuestUnbindReason::Unknown
    };

    let mut sm =
        new_symbolic_tdisp_state_machine("kani-device", current_state, guest_protocol_type);

    let _ = sm.request_unbind(reason);

    assert_eq!(sm.kani_guest_protocol_type(), guest_protocol_type);

    core::mem::forget(sm);
}

// ----------------------------------------------------------------------------
// Malicious-host cached-state safety (paravisor-as-TDISP-guest direction)
// ----------------------------------------------------------------------------
//
// The proofs above target the paravisor-as-TDISP-host direction (threat
// boundary b: VTL0 guest → VTL2). The harness below targets the
// paravisor-as-TDISP-guest direction (threat boundary a: untrusted host
// → VTL2 paravisor), which is the direction that matters for the CVM
// malicious-host audit.
//
// `vpci_client::tdisp::send_tdisp_command` advances cached TDI state on
// any recognized `tdi_state_after`, then performs a per-method
// post-check (e.g. `tdisp_bind_interface` checks that cached state ==
// `Locked`). A malicious host can therefore leave the cached state in
// a value the paravisor never asked for — see audit finding #2 in
// `docs/openhcl-knowledge-base.md`.
//
// `crate::reconcile::reconcile_host_claim` is the pure decision
// function that closes that gap. The harness exhaustively explores the
// adversary's choice of `(host_success, host_state_after)` and the
// paravisor's `(requested, state_before)` and verifies that whenever
// the function returns `Ok(new_state)`, `(state_before, new_state)` is
// a transition the requested operation could legitimately produce.
// Equivalently: a malicious host cannot trick the paravisor into
// caching a state that is inconsistent with the operation it actually
// issued.

/// Exhaustive proof of [`crate::reconcile::reconcile_host_claim`]'s
/// malicious-host-safety contract.
///
/// # Setup
///
/// Symbolic over the paravisor's request `(requested, state_before)`
/// AND over the host-controlled response `(host_success,
/// host_state_after)`. CBMC explores all 5 × 4 × 2 × 5 = 200
/// combinations of the protobuf-enum domains plus the `None` case for
/// `host_state_after`.
///
/// # Property
///
/// If `reconcile_host_claim` returns `Ok(new_state)`, then **all** of:
///
/// 1. The host actually claimed success.
/// 2. The host actually claimed a recognized post-state, and that
///    post-state equals `new_state`.
/// 3. `(state_before, new_state)` is a transition consistent with
///    `requested`:
///    - `Bind`: `Unlocked → Locked`
///    - `StartTdi`: `Locked → Run`
///    - `Unbind`: `* → Unlocked`
///    - `GetDeviceInterfaceInfo` / `GetTdiReport`: `s → s`
///
/// Equivalently, no adversary choice of `(host_success,
/// host_state_after)` can cause the function to return `Ok` for an
/// `(requested, state_before, new_state)` triple outside this table.
#[kani::proof]
fn verify_reconcile_host_claim_safety() {
    use crate::reconcile::ParavisorRequestedTdispOp;
    use crate::reconcile::reconcile_host_claim;

    let requested = any_requested_op();
    let state_before = any_tdi_state();
    let host_success: bool = kani::any();
    let host_state_after = any_optional_tdi_state();

    let result = reconcile_host_claim(requested, state_before, host_success, host_state_after);

    if let Ok(new_state) = result {
        // (1) Host must have claimed success.
        assert!(host_success);

        // (2) Host must have claimed a recognized post-state, and it
        //     must equal the new cached state we are about to commit.
        assert_eq!(host_state_after, Some(new_state));

        // (3) `(state_before, new_state)` must match the requested op.
        match requested {
            ParavisorRequestedTdispOp::Bind => {
                assert_eq!(state_before, TdispTdiState::Unlocked);
                assert_eq!(new_state, TdispTdiState::Locked);
            }
            ParavisorRequestedTdispOp::StartTdi => {
                assert_eq!(state_before, TdispTdiState::Locked);
                assert_eq!(new_state, TdispTdiState::Run);
            }
            ParavisorRequestedTdispOp::Unbind => {
                assert_eq!(new_state, TdispTdiState::Unlocked);
            }
            ParavisorRequestedTdispOp::GetDeviceInterfaceInfo
            | ParavisorRequestedTdispOp::GetTdiReport => {
                assert_eq!(new_state, state_before);
            }
        }
    }
}
