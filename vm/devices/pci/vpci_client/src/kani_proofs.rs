// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kani formal-verification harnesses for the paravisor-as-TDISP-guest
//! direction (threat boundary **a**: untrusted host → VTL2 paravisor).
//!
//! The harnesses in this module drive **production** methods on
//! [`crate::tdisp::VpciClientTdispState`] under fully-symbolic host
//! responses, modelling a malicious host that may return any
//! combination of `result` / `tdi_state_after` / oneof payload. The
//! host channel is replaced (under `cfg(kani)`) by
//! [`crate::tdisp::HostChannel::KaniMock`], which short-circuits the
//! mesh / VMBus / async-runtime layers without changing the logic of
//! the production code itself.
//!
//! # Property → harness mapping
//!
//! Properties are defined in `docs/tdisp-paravisor-security-properties.md`.
//! Audit-finding IDs (TDISP-001..008) are defined in `docs/bugs/`.
//!
//! | Property | Harness | Status |
//! |----------|---------|--------|
//! | F-1, F-2 (Bind)        | [`verify_bind_cannot_cache_inconsistent_state_on_success`] | PASS |
//! | F-1, F-2 (StartTdi)    | [`verify_start_device_post_check`]      | FAIL — TDISP-004 |
//! | F-1, F-2 (Unbind)      | [`verify_unbind_post_check`]            | FAIL — TDISP-005 |
//! | F-1, F-2 (GetReport)   | [`verify_get_device_report_post_check`] | FAIL — TDISP-006 |
//! | F-7 (positive gate)    | [`verify_dma_unblock_gating`]           | PASS |
//! | F-7 (negative gate)    | [`verify_paravisor_never_unblocks_when_gate_closed`] | PASS |
//! | F-12 (re-block local)  | [`verify_unbind_reblocks_previously_unblocked_resources`] | PASS |
//! | F-11                   | [`verify_isolation_snapshot_only_ready_when_run`] | FAIL — TDISP-008 |
//! | F-13                   | [`verify_unbind_clears_per_bind_bookkeeping`] | PASS |
//! | F-14                   | [`verify_unbind_preserve_report_semantics`] | FAIL — TDISP-005/008 |
//!
//! # Deferred properties (no harness today)
//!
//! These properties depend on production state fields or external
//! oracles that are not yet modelled in `vpci_client`. See the
//! commented-out spec block at the end of this file for the executable
//! intent of each.
//!
//! - **F-3** Report integrity (V1 hash check): needs `verified` flag
//!   on cached report and an oracle `device_info_hash`.
//! - **F-4** Lock-epoch nonce binding: needs `lock_epoch` nonce field
//!   tied to LOCK_INTERFACE_RESPONSE.
//! - **F-5** New LOCK invalidates prior epoch: depends on F-4 fields.
//! - **F-6** MMIO containment + injectivity: needs containment check
//!   in `tdisp_on_mmio_reconfigured` and aliasing check across BARs.
//! - **F-8** IDE = SECURE before LOCK: needs `ide_state` and
//!   `lock_session` fields plus IDE-state-machine axiom.
//! - **F-9** Async insecure-event response: needs async event model.
//! - **F-10** `default_stream_id` binding: needs IDE-stream id field.
//! - **F-12** key/secret scrub ordering: needs IDE/SPDM key model.
//! - **F-15** Recovery-path cleanliness: needs explicit `Untrusted`
//!   state and recovery API.
//! - **F-16** Measurement / identity policy: lives in
//!   `underhill_attestation`, out of scope for this crate.
//! - **F-17** TDI-ID binding across LOCK/REPORT/START: needs response
//!   `tdi_id` field validation in `send_tdisp_command`.
//! - **F-17a** SPDM peer-identity rebinding: needs SPDM cert-chain
//!   model.

use crate::tdisp::VpciClientTdispState;
use openhcl_tdisp::GuestToHostResponse;
use openhcl_tdisp::TdispGuestOperationErrorCode;
use openhcl_tdisp::TdispTdiState;

/// Fully-symbolic [`TdispTdiState`] over the four protobuf variants.
fn any_tdi_state() -> TdispTdiState {
    match kani::any::<u8>() % 4 {
        0 => TdispTdiState::Uninitialized,
        1 => TdispTdiState::Unlocked,
        2 => TdispTdiState::Locked,
        _ => TdispTdiState::Run,
    }
}

/// Symbolic-enough host result. Covers `Success`, every defined
/// failure code, and an "unknown" integer that decodes to `None` via
/// [`GuestToHostResponse::error_code`]. The exact failure code value
/// is unimportant; what matters is the `Success` vs not-`Success`
/// branch.
fn any_result_code() -> i32 {
    if kani::any() {
        TdispGuestOperationErrorCode::Success as i32
    } else if kani::any() {
        // Some recognised non-Success code.
        TdispGuestOperationErrorCode::InvalidDeviceState as i32
    } else {
        // Out-of-domain integer — `error_code()` will return `None`.
        i32::MIN
    }
}

/// Symbolic `tdi_state_after` integer. Covers all four defined
/// variants plus an out-of-domain value that decodes to `None` via
/// [`GuestToHostResponse::tdi_state_after_enum`].
fn any_state_after_int() -> i32 {
    if kani::any() {
        any_tdi_state() as i32
    } else {
        // Out-of-domain integer.
        i32::MIN
    }
}

/// Construct a fully-symbolic [`GuestToHostResponse`]. The oneof
/// `response` payload is left as `None` because the Bind path does
/// not inspect any inner field; the adversarial bits exercised here
/// are `result` and `tdi_state_after`, which drive the post-check.
fn any_host_response() -> GuestToHostResponse {
    GuestToHostResponse {
        result: any_result_code(),
        tdi_state_before: any_state_after_int(),
        tdi_state_after: any_state_after_int(),
        response: None,
    }
}

/// Drive [`VpciClientTdispState::tdisp_bind_interface`] against a
/// symbolic host response and verify that the cached `tdi_state` is
/// not advanced to a value inconsistent with what the operation
/// requested.
///
/// # Setup
///
/// - Cached `tdi_state_before` is fully symbolic over all four
///   [`TdispTdiState`] variants.
/// - The host's [`GuestToHostResponse`] is fully symbolic over
///   `result`, `tdi_state_before`, `tdi_state_after`, and oneof
///   payload (including a wrong-typed payload).
///
/// # Property (current production behaviour)
///
/// On success (`Ok(())`):
///
/// - The host claimed `Success` (`error_code() == Some(Success)`).
/// - The host claimed `tdi_state_after == Locked` (per the per-method
///   post-check in [`VpciClientTdispState::tdisp_bind_interface`]).
/// - The cached `tdi_state` after the call is `Locked`.
///
/// On failure (`Err(_)`):
///
/// - No assertion on cached `tdi_state` — the current production
///   `send_tdisp_command` advances cached state on any recognised
///   `tdi_state_after`, so a malicious host can leave it in a value
///   the paravisor never asked for. This clause documents the open
///   audit finding (#2 in `docs/openhcl-knowledge-base.md`); it
///   should tighten to `assert_eq!(cached_after, state_before)` once
///   the reconciliation gate lands.
#[kani::proof]
#[kani::unwind(2)]
fn verify_bind_cannot_cache_inconsistent_state_on_success() {
    let state_before = any_tdi_state();
    let response = any_host_response();
    // Capture the symbolic claims for use in the post-condition.
    let host_result = response.result;
    let host_state_after_int = response.tdi_state_after;

    let mut state = VpciClientTdispState::kani_new_with_response(state_before, response);

    // Drive the production async method to completion using a
    // single-poll executor on a no-op waker.
    //
    // We deliberately avoid `futures::executor::block_on` here:
    // although it appears to "verify" in ~5s, the speed is illusory.
    // `futures::executor::block_on` calls `std::thread::current()`
    // which Kani treats as an unsupported FFI (`pthread_key_create`)
    // and short-circuits via `assume(false)` BEFORE the production
    // body runs — so all of the post-conditions below would be
    // vacuously true. Using a hand-rolled single-poll executor
    // forces CBMC to actually explore the production code path.
    //
    // The `KaniMock` channel resolves on the first poll, so a single
    // `poll` with a no-op `Waker` is sufficient and matches what an
    // executor would do for a `Ready`-on-first-poll future.
    let result = {
        use core::future::Future;
        use core::pin::pin;
        use core::task::Context;
        use core::task::Poll;
        use core::task::Waker;

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = pin!(state.tdisp_bind_interface());
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(r) => r,
            Poll::Pending => {
                // The KaniMock channel is one-shot synchronous, so the
                // production method must complete on the first poll.
                panic!("tdisp_bind_interface unexpectedly returned Pending under KaniMock");
            }
        }
        // `fut` borrows `state` mutably; drop it at end-of-block so
        // the post-condition can re-borrow `state` immutably.
    };

    let cached_after = state.kani_tdi_state();

    // Decode the host's claimed `tdi_state_after` the same way
    // `GuestToHostResponse::tdi_state_after_enum` does, so we can
    // assert what the cache is *allowed* to take.
    let host_state_after_decoded: Option<TdispTdiState> = match host_state_after_int {
        x if x == TdispTdiState::Uninitialized as i32 => Some(TdispTdiState::Uninitialized),
        x if x == TdispTdiState::Unlocked as i32 => Some(TdispTdiState::Unlocked),
        x if x == TdispTdiState::Locked as i32 => Some(TdispTdiState::Locked),
        x if x == TdispTdiState::Run as i32 => Some(TdispTdiState::Run),
        _ => None,
    };

    // Universal invariant (holds on both Ok and Err): the cached
    // state may only ever take one of two values — the prior cached
    // value (if the host's claim was undecodable) or the decoded
    // claim. The paravisor must never invent a fresh state out of
    // thin air. This pins down the *shape* of the audit finding #2
    // before the reconciliation gate lands.
    match host_state_after_decoded {
        Some(decoded) => assert!(cached_after == state_before || cached_after == decoded),
        None => assert_eq!(cached_after, state_before),
    }

    if result.is_ok() {
        // Property 1: host must have claimed Success.
        assert_eq!(host_result, TdispGuestOperationErrorCode::Success as i32);

        // Property 2: host must have claimed `Locked` as the
        // post-state (per the bind post-check).
        assert_eq!(host_state_after_int, TdispTdiState::Locked as i32);

        // Property 3: cached state ends in `Locked`.
        assert_eq!(cached_after, TdispTdiState::Locked);

        // Property 4: on Ok, the cached state always advances (or
        // stays) at exactly the decoded host claim — Bind's
        // post-check guarantees the host claim was `Locked`, and
        // `send_tdisp_command` already wrote it.
        assert_eq!(host_state_after_decoded, Some(TdispTdiState::Locked));
    } else {
        // Property 5 (Err branch — documents audit finding #2):
        // the cache moved to whatever the host claimed when the
        // claim decoded, even though the operation failed. This is
        // the *current* (broken) production behaviour. When the
        // reconciliation gate lands, this should tighten to
        // `assert_eq!(cached_after, state_before)`.
        if let Some(decoded) = host_state_after_decoded {
            // Cache either kept its old value (if the host's claim
            // happened to equal it) or now reflects the host's
            // claim.
            assert!(cached_after == state_before || cached_after == decoded);
        } else {
            // Undecodable claim: cache must stay put.
            assert_eq!(cached_after, state_before);
        }
    }

    // Avoid Drop chains for the cached `Vec`/`HashMap`/`Arc` fields
    // that dominate CBMC reachability and add nothing to the verified
    // property.
    core::mem::forget(state);
}

// ----------------------------------------------------------------------------
// Per-method post-check harnesses for the other state-changing methods on
// `VpciClientTdispState`. Each follows the same "fully-symbolic host
// response" recipe as `verify_bind_cannot_cache_inconsistent_state_on_success`
// and proves three security properties under a malicious host:
//
//   (a) Universal cache invariant: the cached `tdi_state` after the call
//       is always either the prior cached value or the host's decoded
//       claim. The host cannot inject a value it never claimed, and an
//       undecodable claim must leave the cache untouched.
//   (b) Per-method post-state: a successful return implies the host
//       claimed the operation's expected post-state (Locked / Run /
//       Unlocked) AND the cache reflects it.
//   (c) Per-method response payload: a successful return implies the
//       host's `response` oneof was the matching variant (Bind /
//       StartTdi / Unbind / GetTdiReport).
// ----------------------------------------------------------------------------

use openhcl_tdisp::GuestToHostResponseVariantOneof as Response;
use openhcl_tdisp::TdispCommandResponseBind;
use openhcl_tdisp::TdispCommandResponseStartTdi;
use openhcl_tdisp::TdispCommandResponseUnbind;
use openhcl_tdisp::TdispGuestUnbindReason;

/// Build a fully-symbolic [`GuestToHostResponse`] whose `response`
/// oneof is one of: `None`, the *matching* variant for the operation
/// under test, or a *mismatched* variant (Bind payload). The
/// mismatched variant is included so the harness covers the malicious
/// case where the host returns Success + claims the right state +
/// returns a wrong-typed payload.
///
/// `which_matching` lets each per-method harness inject its own
/// matching variant.
fn any_host_response_with_payload(matching: Response, mismatched: Response) -> GuestToHostResponse {
    let response = match kani::any::<u8>() % 3 {
        0 => None,
        1 => Some(matching),
        _ => Some(mismatched),
    };
    GuestToHostResponse {
        result: any_result_code(),
        tdi_state_before: any_state_after_int(),
        tdi_state_after: any_state_after_int(),
        response,
    }
}

/// Decode `tdi_state_after_int` the same way
/// [`GuestToHostResponse::tdi_state_after_enum`] does. Helper for
/// post-condition assertions.
fn decode_tdi_state(int_value: i32) -> Option<TdispTdiState> {
    match int_value {
        x if x == TdispTdiState::Uninitialized as i32 => Some(TdispTdiState::Uninitialized),
        x if x == TdispTdiState::Unlocked as i32 => Some(TdispTdiState::Unlocked),
        x if x == TdispTdiState::Locked as i32 => Some(TdispTdiState::Locked),
        x if x == TdispTdiState::Run as i32 => Some(TdispTdiState::Run),
        _ => None,
    }
}

/// Drive an `async fn(&mut VpciClientTdispState) -> R` to completion
/// using a single-poll no-op-waker executor. The `KaniMock` host
/// channel resolves on the first poll, so a single `poll` matches an
/// executor's behaviour exactly. This avoids
/// `futures::executor::block_on`, which short-circuits on
/// `pthread_key_create` (`assume(false)`) and would make the
/// post-conditions vacuously true.
macro_rules! kani_run_async {
    ($state:ident, $expr:expr) => {{
        use core::future::Future;
        use core::pin::pin;
        use core::task::Context;
        use core::task::Poll;
        use core::task::Waker;

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = pin!($expr);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(r) => r,
            Poll::Pending => panic!("KaniMock future returned Pending unexpectedly"),
        }
    }};
}

/// Per-method post-check harness for
/// [`VpciClientTdispState::tdisp_start_device`].
///
/// # Security properties (malicious-host adversary)
///
/// 1. **Cache integrity (universal):** the cached `tdi_state` after
///    the call is `state_before` (if the host's claim was undecodable)
///    or `decoded(host_state_after)` — the host cannot make the
///    paravisor invent a state.
/// 2. **Ok-implies-claim:** an `Ok(())` return implies the host
///    claimed `Success` AND `tdi_state_after == Run`.
/// 3. **Ok-implies-cache:** an `Ok(())` return implies
///    `cached_after == Run`.
/// 4. **Ok-implies-payload:** an `Ok(())` return implies the host's
///    `response` oneof was the `StartTdi` variant — a Bind-typed
///    payload (or `None`) cannot satisfy `tdisp_start_device`.
/// 5. **Audit-finding-#2 negative space (Err branch):** the cache may
///    still take the host's decoded claim on Err. Documented in the
///    universal invariant; tightens to `cached_after == state_before`
///    once the reconciliation gate lands.
#[kani::proof]
#[kani::unwind(2)]
fn verify_start_device_post_check() {
    let state_before = any_tdi_state();
    let response = any_host_response_with_payload(
        Response::StartTdi(TdispCommandResponseStartTdi {}),
        Response::Bind(TdispCommandResponseBind {}),
    );
    let host_result = response.result;
    let host_state_after_int = response.tdi_state_after;
    let host_payload_was_matching = matches!(response.response, Some(Response::StartTdi(_)));

    let mut state = VpciClientTdispState::kani_new_with_response(state_before, response);
    let result = kani_run_async!(state, state.tdisp_start_device());
    let cached_after = state.kani_tdi_state();

    let host_state_after_decoded = decode_tdi_state(host_state_after_int);

    // Property 1.
    match host_state_after_decoded {
        Some(decoded) => assert!(cached_after == state_before || cached_after == decoded),
        None => assert_eq!(cached_after, state_before),
    }

    if result.is_ok() {
        // Property 2 (host_result + host claim).
        assert_eq!(host_result, TdispGuestOperationErrorCode::Success as i32);
        // Property 2': the host MUST have explicitly claimed `Run`
        // for this call. This is the strict ideal: a malicious host
        // returning Success must back its claim with the right
        // `tdi_state_after`.
        //
        // **AUDIT FINDING (currently FAILS):** Kani produces a
        // counter-example where `state_before == Run` and the
        // host returns Success + an undecodable `tdi_state_after`.
        // `send_tdisp_command` skips its `update_tdi_state` call,
        // and the per-method post-check happily observes the prior
        // cached `Run`. So a malicious host can ride a stale
        // cached `Run` through StartTdi without ever claiming it.
        // Tightens once `update_tdi_state` is replaced with a
        // request-aware reconciliation step.
        assert_eq!(host_state_after_int, TdispTdiState::Run as i32);
        // Property 3 (cache reflects Run).
        assert_eq!(cached_after, TdispTdiState::Run);
        // Property 4 (payload was the matching variant).
        assert!(host_payload_was_matching);
    }

    core::mem::forget(state);
}

/// Per-method post-check harness for
/// [`VpciClientTdispState::tdisp_unbind`].
///
/// # Security properties (malicious-host adversary)
///
/// 1. **Cache integrity (universal):** the cached `tdi_state` after
///    the call is `state_before` (if the host's claim was undecodable)
///    or `decoded(host_state_after)`.
/// 2. **Ok-implies-Success:** an `Ok(())` return implies the host
///    claimed `Success`.
/// 3. **Ok-implies-payload:** an `Ok(())` return implies the host's
///    `response` oneof was the `Unbind` variant — a Bind-typed payload
///    (or `None`) cannot satisfy `tdisp_unbind`.
/// 4. **Ok-implies-Unlocked (STRICT IDEAL):** a successful unbind
///    should imply the host claimed `tdi_state_after == Unlocked` AND
///    the cache reflects it. This is the protocol-mandated post-state.
///
///    **AUDIT FINDING (expected to FAIL):** the production
///    [`VpciClientTdispState::tdisp_unbind_inner`] body has no
///    per-method post-check on `tdi_state` (unlike
///    `tdisp_bind_interface` and `tdisp_start_device`). A malicious
///    host can return Success + claim `tdi_state_after == Run` (or
///    any other state) + return the Unbind payload — and the
///    paravisor returns `Ok` while caching `Run`, leaving the
///    paravisor convinced the device is still attested even after
///    the unbind succeeded.
///
/// 5. **Ok-implies-cleared bookkeeping:** `validated_mmio_bars` and
///    `dma_unblocked` are cleared on `Ok` (modelled implicitly via
///    the `kani_dma_unblocked` accessor; the harness does not
///    construct an `intercepted` or `validated_already` state since
///    it would invoke `BTreeMap` operations that explode CBMC — see
///    `kani-debugging.md`).
#[kani::proof]
#[kani::unwind(2)]
fn verify_unbind_post_check() {
    let state_before = any_tdi_state();
    let response = any_host_response_with_payload(
        Response::Unbind(TdispCommandResponseUnbind {}),
        Response::Bind(TdispCommandResponseBind {}),
    );
    let host_result = response.result;
    let host_state_after_int = response.tdi_state_after;
    let host_payload_was_matching = matches!(response.response, Some(Response::Unbind(_)));

    let mut state = VpciClientTdispState::kani_new_with_response(state_before, response);
    let result = kani_run_async!(state, state.tdisp_unbind(TdispGuestUnbindReason::Graceful));
    let cached_after = state.kani_tdi_state();

    let host_state_after_decoded = decode_tdi_state(host_state_after_int);

    // Property 1.
    match host_state_after_decoded {
        Some(decoded) => assert!(cached_after == state_before || cached_after == decoded),
        None => assert_eq!(cached_after, state_before),
    }

    if result.is_ok() {
        // Property 2.
        assert_eq!(host_result, TdispGuestOperationErrorCode::Success as i32);
        // Property 3.
        assert!(host_payload_was_matching);
        // Property 4 (STRICT IDEAL — currently FAILS, see doc above).
        assert_eq!(host_state_after_int, TdispTdiState::Unlocked as i32);
        assert_eq!(cached_after, TdispTdiState::Unlocked);
        // Property 5 (DMA bookkeeping cleared).
        assert!(!state.kani_dma_unblocked());
    }

    core::mem::forget(state);
}

/// Per-method post-check harness for
/// [`VpciClientTdispState::tdisp_get_device_report`]
/// (the underlying primitive for `tdisp_get_tdi_report` and
/// `tdisp_get_tdi_device_id`).
///
/// # Security properties (malicious-host adversary)
///
/// 1. **Cache integrity (universal):** the cached `tdi_state` after
///    the call is `state_before` (if the host's claim was undecodable)
///    or `decoded(host_state_after)`.
/// 2. **Ok-implies-Success:** an `Ok(_)` return implies the host
///    claimed `Success`.
/// 3. **Ok-implies-payload:** an `Ok(_)` return implies the host's
///    `response` oneof was the `GetTdiReport` variant — a Bind-typed
///    payload (or `None`) cannot satisfy `tdisp_get_device_report`.
/// 4. **Ok-implies-bound (STRICT IDEAL):** the report should only
///    succeed when cached `tdi_state ∈ {Locked, Run}`. Asking for a
///    TDI report from an `Unlocked` or `Uninitialized` device is
///    semantically meaningless and should be refused.
///
///    **AUDIT FINDING (expected to FAIL):** the production
///    `tdisp_get_device_report` performs no cached-state check.
///    A malicious host can return Success + the GetTdiReport payload
///    while the device is `Unlocked` (or even `Uninitialized`), and
///    the paravisor will return `Ok(buffer)` — handing a
///    host-controlled blob to the attestation layer for an
///    unattestable device. Combined with audit finding #2, the host
///    can also use this call to push a stale `Run` claim into the
///    cache without the cache ever having been advanced through Bind
///    + StartTdi.
#[kani::proof]
#[kani::unwind(2)]
fn verify_get_device_report_post_check() {
    let state_before = any_tdi_state();
    let response = any_host_response_with_payload(
        Response::GetTdiReport(openhcl_tdisp::TdispCommandResponseGetTdiReport {
            report_type: openhcl_tdisp::TdispReportType::InterfaceReport as i32,
            report_buffer: Vec::new(),
        }),
        Response::Bind(TdispCommandResponseBind {}),
    );
    let host_result = response.result;
    let host_state_after_int = response.tdi_state_after;
    let host_payload_was_matching = matches!(response.response, Some(Response::GetTdiReport(_)));

    let mut state = VpciClientTdispState::kani_new_with_response(state_before, response);
    let result = kani_run_async!(
        state,
        state.tdisp_get_device_report(&openhcl_tdisp::TdispReportType::InterfaceReport)
    );
    let cached_after = state.kani_tdi_state();

    let host_state_after_decoded = decode_tdi_state(host_state_after_int);

    // Property 1.
    match host_state_after_decoded {
        Some(decoded) => assert!(cached_after == state_before || cached_after == decoded),
        None => assert_eq!(cached_after, state_before),
    }

    if result.is_ok() {
        // Property 2.
        assert_eq!(host_result, TdispGuestOperationErrorCode::Success as i32);
        // Property 3.
        assert!(host_payload_was_matching);
        // Property 4 (STRICT IDEAL — currently FAILS, see doc above).
        assert!(
            cached_after == TdispTdiState::Locked || cached_after == TdispTdiState::Run,
            "GetTdiReport returned Ok with cached state not in {{Locked, Run}}",
        );
    }

    // The Ok branch returns a `Vec<u8>` — `core::mem::forget` it
    // along with the state to keep CBMC reach bounded.
    if let Ok(buf) = result {
        core::mem::forget(buf);
    }
    core::mem::forget(state);
}

//
// Verifies the synchronous gate inside
// [`VpciClientTdispState::tdisp_on_mmio_reconfigured`]: the production
// code MUST call `validator.tdisp_unblock_dma` (and
// `validator.tdisp_unblock_mmio`) iff and only iff every gate
// predicate is satisfied.
//
// The gate predicate, distilled from the production method:
//
//   gate(S, bar) =
//          S.tdi_state == Run
//       && S.tdi_report.is_some()
//       && classify_bar(S, bar) == PRIVATE
//       && !S.validated_mmio_bars.contains_key(bar)
//
// `tdisp_unblock_mmio` fires iff `gate(S, bar)`.
// `tdisp_unblock_dma` fires iff `gate(S, bar) && !S.dma_unblocked`.
//
// classify_bar returns:
//   - SHARED   if bar in intercepted_bars
//   - SHARED   if cached report has a matching range with is_non_tee_mem
//   - PRIVATE  if cached report has a matching range with !is_non_tee_mem
//   - INVALID  otherwise (no report, or no matching range)
// ----------------------------------------------------------------------------

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use openhcl_tdisp::TdispResourceValidationInterface;
use std::sync::Arc;
use tdisp::devicereport::TdiReportStruct;
use tdisp::devicereport::TdispTdiReportInterfaceInfo;
use tdisp::devicereport::TdispTdiReportMmioFlags;
use tdisp::devicereport::TdispTdiReportMmioInterfaceInfo;
use vpci_protocol::ResourceIsolation;

/// Recording mock validator for Kani harnesses. Uses [`AtomicBool`]
/// (rather than `parking_lot::Mutex` or `core::cell::Cell`) for two
/// reasons:
///   1. The trait `TdispResourceValidationInterface` requires
///      `Send + Sync`, which rules out `Cell`.
///   2. `parking_lot` reaches `pthread_key_create` via the global
///      parking-lot table — see the model-checking SKILL playbook.
/// `AtomicBool` is `Sync`, has no FFI / TLS reachability, and the
/// harness is single-threaded so memory ordering is irrelevant.
struct KaniRecordingValidator {
    unblock_mmio_called: AtomicBool,
    unblock_dma_called: AtomicBool,
}

impl KaniRecordingValidator {
    fn new() -> Self {
        Self {
            unblock_mmio_called: AtomicBool::new(false),
            unblock_dma_called: AtomicBool::new(false),
        }
    }
}

impl TdispResourceValidationInterface for KaniRecordingValidator {
    fn tdisp_unblock_mmio(
        &self,
        _target_vtl: hvdef::Vtl,
        _device_id: u16,
        _base_gpa: u64,
        _base_offset: u32,
        _length_in_bytes: u32,
        _range_id: u16,
    ) -> anyhow::Result<()> {
        self.unblock_mmio_called.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn tdisp_unblock_dma(&self, _target_vtl: hvdef::Vtl, _device_id: u16) -> anyhow::Result<()> {
        self.unblock_dma_called.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn tdisp_block_mmio(
        &self,
        _target_vtl: hvdef::Vtl,
        _device_id: u16,
        _base_gpa: u64,
        _base_offset: u32,
        _length_in_bytes: u32,
        _range_id: u16,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn tdisp_block_dma(&self, _target_vtl: hvdef::Vtl, _device_id: u16) -> anyhow::Result<()> {
        Ok(())
    }

    fn tdisp_query_firmware_tdi_state(
        &self,
        _device_id: u16,
    ) -> anyhow::Result<Option<openhcl_tdisp::TdispTdiState>> {
        Ok(None)
    }
}

/// Drive [`VpciClientTdispState::tdisp_on_mmio_reconfigured`] against a
/// fully-symbolic mutable-state and verify that the resource validator
/// is invoked iff and only iff the documented gate predicate holds.
///
/// # Setup
///
/// - `bar_id` is fixed to `0` (gate logic is identical across BARs;
///   see plan rationale).
/// - `tdi_state` symbolic over all four `TdispTdiState` variants.
/// - `tdi_report` is either `None` or `Some` with a one-element
///   `mmio_interface_info` whose `range_id` matches `bar_id` and
///   whose `is_non_tee_mem` flag is symbolic.
/// - `intercepted`, `validated_already`, `dma_unblocked_before`
///   independently symbolic.
///
/// # Properties (current production behaviour)
///
/// Define `gate = (tdi_state == Run) && tdi_report.is_some()
///                 && classify(...) == PRIVATE && !validated_already`.
///
/// 1. `unblock_mmio_called == gate`.
/// 2. `unblock_dma_called == (gate && !dma_unblocked_before)`.
/// 3. `dma_unblocked_after == (dma_unblocked_before || unblock_dma_called)`.
#[kani::proof]
#[kani::unwind(2)]
fn verify_dma_unblock_gating() {
    const BAR_ID: u16 = 0;

    // Symbolic mutable-state inputs.
    let tdi_state = any_tdi_state();
    let intercepted: bool = kani::any();
    let validated_already: bool = kani::any();
    let dma_unblocked_before: bool = kani::any();
    let has_report: bool = kani::any();
    let range_present: bool = kani::any();
    let range_is_non_tee: bool = kani::any();

    // Construct the optional TDI report. Single-range to keep the
    // `Vec` bounded; `mmio_interface_info` is empty when
    // `range_present` is false to model "report cached but no entry
    // for this BAR".
    let tdi_report: Option<TdiReportStruct> = if has_report {
        let mmio_interface_info = if range_present {
            let flags = TdispTdiReportMmioFlags::new().with_is_non_tee_mem(range_is_non_tee);
            vec![TdispTdiReportMmioInterfaceInfo {
                first_4k_page_offset: 0,
                num_4k_pages: 1,
                flags,
                range_id: BAR_ID,
            }]
        } else {
            Vec::new()
        };
        Some(TdiReportStruct {
            interface_info: TdispTdiReportInterfaceInfo::new(),
            msi_x_message_control: 0,
            lnr_control: 0,
            tph_control: 0,
            mmio_interface_info,
        })
    } else {
        None
    };

    // Compute the expected gate predicate from the symbolic inputs.
    // This mirrors `classify_bar` and the four early-return branches
    // inside `tdisp_on_mmio_reconfigured`.
    let classification = if intercepted {
        ResourceIsolation::SHARED
    } else if !has_report {
        ResourceIsolation::INVALID
    } else if !range_present {
        ResourceIsolation::INVALID
    } else if range_is_non_tee {
        ResourceIsolation::SHARED
    } else {
        ResourceIsolation::PRIVATE
    };

    let gate = tdi_state == TdispTdiState::Run
        && tdi_report.is_some()
        && classification == ResourceIsolation::PRIVATE
        && !validated_already;

    let expected_unblock_mmio = gate;
    let expected_unblock_dma = gate && !dma_unblocked_before;
    let expected_dma_unblocked_after = dma_unblocked_before || expected_unblock_dma;

    // Build a single recording alidator and hand the production
    // code a `dyn` clone; the typed `recorder` clone lets us read
    // back the recorded bits after the call.
    let recorder: Arc<KaniRecordingValidator> = Arc::new(KaniRecordingValidator::new());
    let validator: Arc<dyn TdispResourceValidationInterface> = recorder.clone();

    let mut state = VpciClientTdispState::kani_new_for_mmio_reconfigured(
        tdi_state,
        tdi_report,
        BAR_ID,
        intercepted,
        validated_already,
        dma_unblocked_before,
        validator,
    );

    // Concrete arguments — gate decision is independent of these.
    let _ = state.tdisp_on_mmio_reconfigured(
        BAR_ID, /* base_address = */ 0x1000, /* length = */ 0x1000,
    );

    let dma_unblocked_after = state.kani_dma_unblocked();
    let mmio_was_called = recorder.unblock_mmio_called.load(Ordering::Relaxed);
    let dma_was_called = recorder.unblock_dma_called.load(Ordering::Relaxed);

    assert_eq!(mmio_was_called, expected_unblock_mmio);
    assert_eq!(dma_was_called, expected_unblock_dma);
    assert_eq!(dma_unblocked_after, expected_dma_unblocked_after);

    // Avoid Drop chains for `Vec<TdispTdiReportMmioInterfaceInfo>`
    // and `Arc<dyn TdispResourceValidationInterface>` that dominate
    // CBMC reachability without contributing to the verified property.
    core::mem::forget(state);
    core::mem::forget(recorder);
}

/// A `TdispResourceValidationInterface` that **panics** if either
/// unblock method is invoked, and returns a synthetic `Err` from the
/// re-block / firmware-state methods so they can never be silently
/// observed as success either.
///
/// Used by [`verify_paravisor_never_unblocks_when_gate_closed`] to
/// prove that, no matter what the host returned during attestation
/// or what stale state the paravisor cached, the production code
/// **never** asks the platform to flip MMIO / DMA into the guest's
/// private domain unless the documented gate predicate is satisfied.
///
/// Panicking inside the trait method is observed by Kani as an
/// assertion violation, so any call from `tdisp_on_mmio_reconfigured`
/// would fail verification with a counter-example.
struct KaniDenyValidator;

impl TdispResourceValidationInterface for KaniDenyValidator {
    fn tdisp_unblock_mmio(
        &self,
        _target_vtl: hvdef::Vtl,
        _device_id: u16,
        _base_gpa: u64,
        _base_offset: u32,
        _length_in_bytes: u32,
        _range_id: u16,
    ) -> anyhow::Result<()> {
        // Reaching this is a verification failure — the closed-gate
        // harness `assume`s the gate predicate is false, so no call
        // here is allowed.
        kani::assert(
            false,
            "tdisp_unblock_mmio called even though gate predicate is closed",
        );
        Ok(())
    }

    fn tdisp_unblock_dma(&self, _target_vtl: hvdef::Vtl, _device_id: u16) -> anyhow::Result<()> {
        kani::assert(
            false,
            "tdisp_unblock_dma called even though gate predicate is closed",
        );
        Ok(())
    }

    fn tdisp_block_mmio(
        &self,
        _target_vtl: hvdef::Vtl,
        _device_id: u16,
        _base_gpa: u64,
        _base_offset: u32,
        _length_in_bytes: u32,
        _range_id: u16,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn tdisp_block_dma(&self, _target_vtl: hvdef::Vtl, _device_id: u16) -> anyhow::Result<()> {
        Ok(())
    }

    fn tdisp_query_firmware_tdi_state(
        &self,
        _device_id: u16,
    ) -> anyhow::Result<Option<openhcl_tdisp::TdispTdiState>> {
        Ok(None)
    }
}

/// Negative companion to [`verify_dma_unblock_gating`].
///
/// Drives [`VpciClientTdispState::tdisp_on_mmio_reconfigured`] from
/// every reachable `(tdi_state, tdi_report shape, intercepted,
/// validated_already, dma_unblocked_before)` configuration that
/// makes the documented gate predicate **false**, with a validator
/// that asserts on any unblock call. Verification succeeds iff the
/// production code never invokes `tdisp_unblock_mmio` or
/// `tdisp_unblock_dma` from any such state.
///
/// In other words: regardless of what the host previously returned
/// during attestation, regardless of what stale state the paravisor
/// cached, and regardless of which BAR is being reconfigured, the
/// paravisor will not flip MMIO/DMA into the guest's private
/// domain unless **all** of the gate clauses hold.
#[kani::proof]
#[kani::unwind(2)]
fn verify_paravisor_never_unblocks_when_gate_closed() {
    const BAR_ID: u16 = 0;

    // Symbolic mutable-state inputs — same shape as the positive
    // gating harness so the same set of reachable configurations is
    // explored.
    let tdi_state = any_tdi_state();
    let intercepted: bool = kani::any();
    let validated_already: bool = kani::any();
    let dma_unblocked_before: bool = kani::any();
    let has_report: bool = kani::any();
    let range_present: bool = kani::any();
    let range_is_non_tee: bool = kani::any();

    let tdi_report: Option<TdiReportStruct> = if has_report {
        let mmio_interface_info = if range_present {
            let flags = TdispTdiReportMmioFlags::new().with_is_non_tee_mem(range_is_non_tee);
            vec![TdispTdiReportMmioInterfaceInfo {
                first_4k_page_offset: 0,
                num_4k_pages: 1,
                flags,
                range_id: BAR_ID,
            }]
        } else {
            Vec::new()
        };
        Some(TdiReportStruct {
            interface_info: TdispTdiReportInterfaceInfo::new(),
            msi_x_message_control: 0,
            lnr_control: 0,
            tph_control: 0,
            mmio_interface_info,
        })
    } else {
        None
    };

    // Same gate computation as the positive harness.
    let classification = if intercepted {
        ResourceIsolation::SHARED
    } else if !has_report {
        ResourceIsolation::INVALID
    } else if !range_present {
        ResourceIsolation::INVALID
    } else if range_is_non_tee {
        ResourceIsolation::SHARED
    } else {
        ResourceIsolation::PRIVATE
    };

    let gate = tdi_state == TdispTdiState::Run
        && tdi_report.is_some()
        && classification == ResourceIsolation::PRIVATE
        && !validated_already;

    // Constrain the symbolic state to the closed-gate slice of the
    // input space. Kani then explores every closed-gate
    // configuration; the deny validator asserts if any unblock is
    // attempted.
    kani::assume(!gate);

    let validator: Arc<dyn TdispResourceValidationInterface> = Arc::new(KaniDenyValidator);

    let mut state = VpciClientTdispState::kani_new_for_mmio_reconfigured(
        tdi_state,
        tdi_report,
        BAR_ID,
        intercepted,
        validated_already,
        dma_unblocked_before,
        validator,
    );

    let _ = state.tdisp_on_mmio_reconfigured(
        BAR_ID, /* base_address = */ 0x1000, /* length = */ 0x1000,
    );

    // Belt-and-suspenders: the cached `dma_unblocked` flag must not
    // have flipped from false to true. (If `dma_unblocked_before`
    // was already true, the closed-gate path never touches it
    // anyway.)
    let dma_unblocked_after = state.kani_dma_unblocked();
    assert_eq!(dma_unblocked_after, dma_unblocked_before);

    core::mem::forget(state);
}

// ----------------------------------------------------------------------------
// Unbind re-block harness: prove that `tdisp_unbind` re-blocks every
// previously-unblocked MMIO range and DMA before sending the host the
// unbind command. Without this, a malicious host could observe pages
// that were once mapped into the device's private domain after an
// unbind, defeating the chain-of-custody.
// ----------------------------------------------------------------------------

/// Recording validator for the unbind re-block harness. Captures
/// the arguments of the *first* `tdisp_block_mmio` call and a flag
/// for `tdisp_block_dma`. The harness only ever has one BAR
/// pre-populated (single-entry `BTreeMap`), so a single recorded
/// call is sufficient.
///
/// Each captured field is wrapped in [`AtomicU64`] / [`AtomicU32`]
/// / [`AtomicBool`] so the validator can be `Send + Sync` and the
/// `Arc<dyn>` upcast works.
struct KaniReblockRecordingValidator {
    block_mmio_called: AtomicBool,
    block_mmio_bar_id: core::sync::atomic::AtomicU32, // u16 widened
    block_mmio_base_gpa: core::sync::atomic::AtomicU64,
    block_mmio_length: core::sync::atomic::AtomicU32,
    block_dma_called: AtomicBool,
    // Sentinel: the unblock methods MUST NOT be invoked from the
    // unbind path. If they are, that's a verification failure.
    unblock_mmio_called: AtomicBool,
    unblock_dma_called: AtomicBool,
}

impl KaniReblockRecordingValidator {
    fn new() -> Self {
        Self {
            block_mmio_called: AtomicBool::new(false),
            block_mmio_bar_id: core::sync::atomic::AtomicU32::new(0),
            block_mmio_base_gpa: core::sync::atomic::AtomicU64::new(0),
            block_mmio_length: core::sync::atomic::AtomicU32::new(0),
            block_dma_called: AtomicBool::new(false),
            unblock_mmio_called: AtomicBool::new(false),
            unblock_dma_called: AtomicBool::new(false),
        }
    }
}

impl TdispResourceValidationInterface for KaniReblockRecordingValidator {
    fn tdisp_unblock_mmio(
        &self,
        _target_vtl: hvdef::Vtl,
        _device_id: u16,
        _base_gpa: u64,
        _base_offset: u32,
        _length_in_bytes: u32,
        _range_id: u16,
    ) -> anyhow::Result<()> {
        self.unblock_mmio_called.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn tdisp_unblock_dma(&self, _target_vtl: hvdef::Vtl, _device_id: u16) -> anyhow::Result<()> {
        self.unblock_dma_called.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn tdisp_block_mmio(
        &self,
        _target_vtl: hvdef::Vtl,
        _device_id: u16,
        base_gpa: u64,
        _base_offset: u32,
        length_in_bytes: u32,
        range_id: u16,
    ) -> anyhow::Result<()> {
        self.block_mmio_called.store(true, Ordering::Relaxed);
        self.block_mmio_bar_id
            .store(range_id as u32, Ordering::Relaxed);
        self.block_mmio_base_gpa.store(base_gpa, Ordering::Relaxed);
        self.block_mmio_length
            .store(length_in_bytes, Ordering::Relaxed);
        Ok(())
    }

    fn tdisp_block_dma(&self, _target_vtl: hvdef::Vtl, _device_id: u16) -> anyhow::Result<()> {
        self.block_dma_called.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn tdisp_query_firmware_tdi_state(
        &self,
        _device_id: u16,
    ) -> anyhow::Result<Option<openhcl_tdisp::TdispTdiState>> {
        Ok(None)
    }
}

/// Drive [`VpciClientTdispState::tdisp_unbind`] from a state that
/// has one previously-unblocked MMIO BAR (length > 0) and a
/// symbolic `dma_unblocked_before`. Verify that:
///
/// 1. `tdisp_block_mmio` is called with **exactly** the recorded
///    `(bar_id, base_gpa, length_in_bytes)` of the pre-populated
///    entry — proving the paravisor cannot "forget" to re-block a
///    range it previously exposed.
/// 2. `tdisp_block_dma` is called iff `dma_unblocked_before == true`.
/// 3. The unblock methods are NEVER called from the unbind path.
///
/// These properties hold **regardless of the host's response**.
/// Even if the host returns Err / a wrong-typed payload / claims a
/// stale `tdi_state_after`, the re-block step happens up front
/// (before `send_tdisp_command`) and is best-effort logged but not
/// gated on the host's reply.
#[kani::proof]
#[kani::unwind(2)]
fn verify_unbind_reblocks_previously_unblocked_resources() {
    const BAR_ID: u16 = 0;
    const BASE_GPA: u64 = 0x4000;
    // Length is symbolic but constrained to be non-zero (otherwise
    // the production sentinel "length == 0 means classified SHARED,
    // never unblocked" applies and `block_mmio` is intentionally
    // skipped — that's a separate property already covered by the
    // gate harness).
    let length_in_bytes: u32 = kani::any();
    kani::assume(length_in_bytes > 0);

    let dma_unblocked_before: bool = kani::any();
    let tdi_state = any_tdi_state();

    // The host's response can be anything. The re-block step runs
    // BEFORE `send_tdisp_command`, so it is independent of the
    // response. Use a fully-symbolic response.
    let response = any_host_response_with_payload(
        Response::Unbind(TdispCommandResponseUnbind {}),
        Response::Bind(TdispCommandResponseBind {}),
    );

    let recorder: Arc<KaniReblockRecordingValidator> =
        Arc::new(KaniReblockRecordingValidator::new());
    let validator: Arc<dyn TdispResourceValidationInterface> = recorder.clone();

    let mut state = VpciClientTdispState::kani_new_for_unbind(
        tdi_state,
        BAR_ID,
        BASE_GPA,
        length_in_bytes,
        dma_unblocked_before,
        response,
        validator,
    );

    let _ = kani_run_async!(state, state.tdisp_unbind(TdispGuestUnbindReason::Graceful));

    // Property 1: block_mmio was called with the exact pre-populated
    // values.
    assert!(recorder.block_mmio_called.load(Ordering::Relaxed));
    assert_eq!(
        recorder.block_mmio_bar_id.load(Ordering::Relaxed),
        BAR_ID as u32
    );
    assert_eq!(
        recorder.block_mmio_base_gpa.load(Ordering::Relaxed),
        BASE_GPA
    );
    assert_eq!(
        recorder.block_mmio_length.load(Ordering::Relaxed),
        length_in_bytes
    );

    // Property 2: block_dma fired iff dma was previously unblocked.
    assert_eq!(
        recorder.block_dma_called.load(Ordering::Relaxed),
        dma_unblocked_before
    );

    // Property 3: unblock methods were NEVER called from unbind.
    assert!(!recorder.unblock_mmio_called.load(Ordering::Relaxed));
    assert!(!recorder.unblock_dma_called.load(Ordering::Relaxed));

    core::mem::forget(state);
    core::mem::forget(recorder);
}

// ----------------------------------------------------------------------------
// F-11: `isolation_snapshot()` returns `Ready` only when the cached
// `tdi_state` is `Run`.
//
// Per the paravisor TDISP security-properties document:
//
//   F-11: `isolation_snapshot()` returns `Ready` only if cached
//         `tdi_state == Run` ∧ verified report cached ∧
//         resource-acceptance step has completed for the BARs the
//         VTL0 guest can address as trusted. (`Locked` is **never**
//         a safe `Ready` state.)
//
// The TDISP §3.2 / PSI-6 / PSI-10 reasoning: only `START_INTERFACE_RESPONSE`
// success transitions device-side to `RUN`, the first state in which
// MMIO/DMA accesses from the TDI's trusted side are enforced against the
// accepted resource set. Reporting `Ready` to VTL0 in `Locked` /
// `Unlocked` / `Uninitialized` would let VTL0 touch MMIO that is not yet
// covered by the device's accepted set.
//
// **Expected to FAIL today** (audit finding TDISP-008): production
// `isolation_snapshot()` returns `Ready { ... }` whenever
// `tdi_report.is_some()`, regardless of `tdi_state`. The harness is
// the executable spec of the intended behaviour.
// ----------------------------------------------------------------------------

use crate::tdisp::IsolationSnapshot;

/// Drive [`VpciClientTdispState::isolation_snapshot`] from a fully
/// symbolic cached `(tdi_state, tdi_report.is_some())` configuration
/// and assert that `Ready` implies `tdi_state == Run`.
///
/// The harness re-uses [`VpciClientTdispState::kani_new_for_mmio_reconfigured`]
/// because that constructor already exposes both knobs symbolically;
/// `isolation_snapshot` ignores `validated_mmio_bars`,
/// `intercepted_bars`, and `dma_unblocked` for this property (they
/// affect classification but not the `Ready`-vs-`NotReady` decision).
///
/// **Expected verification result: FAIL.** Production violates F-11 by
/// returning `Ready` whenever `tdi_report.is_some()`. Once the F-11
/// fix lands (`isolation_snapshot` gates `Ready` on
/// `tdi_state == Run`), this harness should verify.
#[kani::proof]
// `isolation_snapshot` iterates over all 6 BARs; CBMC needs N+1 unwindings
// (7) to discharge the termination assertion on `0..6`.
#[kani::unwind(7)]
fn verify_isolation_snapshot_only_ready_when_run() {
    const BAR_ID: u16 = 0;

    let tdi_state = any_tdi_state();
    // Always a cached report present; the F-11 obligation is about
    // `tdi_state`, not about report presence (that's the existing
    // production gate).
    let tdi_report = Some(TdiReportStruct {
        interface_info: TdispTdiReportInterfaceInfo::new(),
        msi_x_message_control: 0,
        lnr_control: 0,
        tph_control: 0,
        mmio_interface_info: vec![TdispTdiReportMmioInterfaceInfo {
            first_4k_page_offset: 0,
            num_4k_pages: 1,
            flags: TdispTdiReportMmioFlags::new().with_is_non_tee_mem(false),
            range_id: BAR_ID,
        }],
    });

    // The non-tdi_state, non-tdi_report inputs are irrelevant to F-11
    // — fix them to neutral values to keep the SAT formula small.
    let validator: Arc<dyn TdispResourceValidationInterface> =
        Arc::new(KaniRecordingValidator::new());
    let state = VpciClientTdispState::kani_new_for_mmio_reconfigured(
        tdi_state, tdi_report, BAR_ID, /* intercepted = */ false,
        /* validated_already = */ false, /* dma_unblocked_before = */ false, validator,
    );

    let snapshot = state.isolation_snapshot();

    // F-11: `Ready` ⇒ tdi_state == Run.
    if matches!(snapshot, IsolationSnapshot::Ready { .. }) {
        assert_eq!(
            tdi_state,
            TdispTdiState::Run,
            "isolation_snapshot returned Ready while tdi_state is not Run \
             (audit finding TDISP-008)",
        );
    }

    core::mem::forget(state);
}

// ----------------------------------------------------------------------------
// F-13: After `tdisp_unbind` returns Ok, the per-bind bookkeeping is
// fully cleared.
//
//   F-13: After `tdisp_unbind` returns `Ok`: `tdi_state == Unassigned`
//         (mapped to `TdispTdiState::Unlocked` in this codebase),
//         no cached report is treated as verified, `lock_epoch ==
//         NO_EPOCH`, `validated_mmio_bars == ∅`, `dma_unblocked == false`.
//
// Only the fields that exist in the production state today are
// asserted on:
//   - `validated_mmio_bars` cleared.
//   - `dma_unblocked == false`.
//   - `tdi_report == None` (the closest analogue to the
//     "no cached report treated as verified" clause; the production
//     code lacks an explicit `verified` flag).
//
// The `tdi_state == Unlocked` clause is part of F-1 / F-4's strict
// post-state ideal and is already asserted (and known to FAIL today
// per TDISP-005) by `verify_unbind_post_check`. It is intentionally
// NOT re-asserted here so that this harness can isolate the
// bookkeeping-clear behaviour, which is independent of the post-state
// gap.
//
// **Expected verification result: PASS today.** The production
// `tdisp_unbind_inner`'s `Ok(_)` arm clears all three observable
// fields. This harness pins that behaviour down so a future
// refactor cannot regress F-13 silently.
// ----------------------------------------------------------------------------

/// Drive [`VpciClientTdispState::tdisp_unbind`] from a state with one
/// pre-unblocked MMIO BAR, symbolic `dma_unblocked_before`, and a
/// cached `tdi_report`. Verify that every per-bind bookkeeping field
/// is cleared on the Ok path, regardless of what the host claimed
/// for `tdi_state_after`.
///
/// Builds on the existing [`KaniReblockRecordingValidator`] but only
/// reads the post-state of the `VpciClientTdispState`; the validator
/// is present because `tdisp_unbind_inner`'s re-block loop short-
/// circuits without it.
#[kani::proof]
#[kani::unwind(2)]
fn verify_unbind_clears_per_bind_bookkeeping() {
    const BAR_ID: u16 = 0;
    const BASE_GPA: u64 = 0x4000;
    let length_in_bytes: u32 = kani::any();
    kani::assume(length_in_bytes > 0);
    let dma_unblocked_before: bool = kani::any();
    let tdi_state = any_tdi_state();

    // Pre-cache an empty TDI report so we can observe whether
    // `tdisp_unbind` (default variant, clear_cached_report = true)
    // clears it on Ok. Empty `mmio_interface_info` keeps CBMC reach
    // bounded.
    let tdi_report = Some(TdiReportStruct {
        interface_info: TdispTdiReportInterfaceInfo::new(),
        msi_x_message_control: 0,
        lnr_control: 0,
        tph_control: 0,
        mmio_interface_info: Vec::new(),
    });

    let response = any_host_response_with_payload(
        Response::Unbind(TdispCommandResponseUnbind {}),
        Response::Bind(TdispCommandResponseBind {}),
    );

    let recorder: Arc<KaniReblockRecordingValidator> =
        Arc::new(KaniReblockRecordingValidator::new());
    let validator: Arc<dyn TdispResourceValidationInterface> = recorder.clone();

    let mut state = VpciClientTdispState::kani_new_for_unbind_with_report(
        tdi_state,
        BAR_ID,
        BASE_GPA,
        length_in_bytes,
        dma_unblocked_before,
        tdi_report,
        response,
        validator,
    );

    let result = kani_run_async!(state, state.tdisp_unbind(TdispGuestUnbindReason::Graceful));

    if result.is_ok() {
        // F-13 clauses that today's production code can be asked to
        // honour:
        assert!(
            state.kani_validated_mmio_bars_is_empty(),
            "tdisp_unbind Ok did not clear validated_mmio_bars",
        );
        assert!(
            !state.kani_dma_unblocked(),
            "tdisp_unbind Ok did not clear dma_unblocked",
        );
        assert!(
            !state.kani_tdi_report_is_some(),
            "tdisp_unbind Ok did not clear tdi_report",
        );
    }

    core::mem::forget(state);
    core::mem::forget(recorder);
}

// ----------------------------------------------------------------------------
// F-14: `tdisp_unbind_preserve_report` semantics.
//
//   F-14: `tdisp_unbind_preserve_report` preserves only the report
//         bytes; it MUST clear the `verified` flag, `accepted_mmio`,
//         `accepted_dma`, `lock_epoch`, and any cached "Run" indicator.
//         A preserved report is downgraded to *unverified*; it is
//         never accepted in a new epoch without re-running F-3 + F-4
//         against a fresh nonce.
//
// Mapped to today's production state:
//   - report bytes preserved   → `tdi_report.is_some()` after Ok.    [PASS path]
//   - `accepted_mmio` cleared  → `validated_mmio_bars.is_empty()`.   [PASS path]
//   - `accepted_dma` cleared   → `dma_unblocked == false`.           [PASS path]
//   - cached "Run" cleared     → `tdi_state != Run` after Ok.        [FAIL path: TDISP-005]
//   - `verified` flag cleared, `lock_epoch == NO_EPOCH` — these
//     fields don't exist in the production state today; covered by
//     the deferred F-4 spec.
//
// **Expected verification result: FAIL** on the "cached Run cleared"
// clause. The production `send_tdisp_command` updates the cached
// `tdi_state` directly from the host's claimed `tdi_state_after`, so
// a malicious host can leave the cache at `Run` after a successful
// preserve-report unbind. The bookkeeping clauses pass.
//
// Composes with F-11 (TDISP-008): if cached `tdi_state == Run` AND
// preserved report is in cache, `isolation_snapshot()` returns
// `Ready{...}` against an unbound device.
// ----------------------------------------------------------------------------

/// Drive [`VpciClientTdispState::tdisp_unbind_preserve_report`] from a
/// state with one pre-unblocked MMIO BAR, symbolic
/// `dma_unblocked_before`, and a cached `tdi_report`. Verify that on
/// Ok: the bookkeeping is cleared, the report is preserved, and the
/// cached `tdi_state` no longer indicates `Run`.
#[kani::proof]
#[kani::unwind(2)]
fn verify_unbind_preserve_report_semantics() {
    const BAR_ID: u16 = 0;
    const BASE_GPA: u64 = 0x4000;
    let length_in_bytes: u32 = kani::any();
    kani::assume(length_in_bytes > 0);
    let dma_unblocked_before: bool = kani::any();
    let tdi_state = any_tdi_state();

    let tdi_report = Some(TdiReportStruct {
        interface_info: TdispTdiReportInterfaceInfo::new(),
        msi_x_message_control: 0,
        lnr_control: 0,
        tph_control: 0,
        mmio_interface_info: Vec::new(),
    });

    let response = any_host_response_with_payload(
        Response::Unbind(TdispCommandResponseUnbind {}),
        Response::Bind(TdispCommandResponseBind {}),
    );

    let recorder: Arc<KaniReblockRecordingValidator> =
        Arc::new(KaniReblockRecordingValidator::new());
    let validator: Arc<dyn TdispResourceValidationInterface> = recorder.clone();

    let mut state = VpciClientTdispState::kani_new_for_unbind_with_report(
        tdi_state,
        BAR_ID,
        BASE_GPA,
        length_in_bytes,
        dma_unblocked_before,
        tdi_report,
        response,
        validator,
    );

    let result = kani_run_async!(
        state,
        state.tdisp_unbind_preserve_report(TdispGuestUnbindReason::Graceful)
    );

    if result.is_ok() {
        // PASS-path clauses (production already honours these).
        assert!(
            state.kani_validated_mmio_bars_is_empty(),
            "preserve_report Ok did not clear validated_mmio_bars",
        );
        assert!(
            !state.kani_dma_unblocked(),
            "preserve_report Ok did not clear dma_unblocked",
        );
        assert!(
            state.kani_tdi_report_is_some(),
            "preserve_report Ok did not preserve tdi_report",
        );
        // FAIL-path clause (TDISP-005 / TDISP-008): cached Run
        // indicator MUST be cleared. Production today leaves it at
        // whatever the host claimed.
        assert_ne!(
            state.kani_tdi_state(),
            TdispTdiState::Run,
            "preserve_report Ok left cached tdi_state at Run \
             (audit findings TDISP-005, TDISP-008)",
        );
    }

    core::mem::forget(state);
    core::mem::forget(recorder);
}
