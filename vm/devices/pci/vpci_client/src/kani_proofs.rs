// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kani formal-verification harnesses for the OpenHCL paravisor (TVM)
//! TDISP request/response handler.
//!
//! These harnesses exercise the production methods on
//! [`crate::tdisp::VpciClientTdispState`] under a fully-symbolic,
//! malicious host. The host-channel is replaced under `cfg(kani)` by
//! [`crate::tdisp::HostChannel::KaniMock`] so the harness can inject
//! arbitrary [`GuestToHostResponse`] payloads without standing up a
//! mesh runtime under CBMC.
//!
//! The properties verified here are derived directly from the PCI-SIG
//! TDISP v2022-07-27 specification (TVM-1..TVM-20). Each
//! `#[kani::proof]` carries a one-line citation back to the spec
//! section that motivates it.

use crate::tdisp::VpciClientTdispState;
use openhcl_tdisp::GuestToHostResponse;
use openhcl_tdisp::GuestToHostResponseVariantOneof as Response;
use openhcl_tdisp::TdispCommandResponseBind;
use openhcl_tdisp::TdispGuestOperationErrorCode;
use tdisp::TdispTdiState;

// --------------------------------------------------------------------
// Symbolic-input helpers.
// --------------------------------------------------------------------

/// Symbolic [`TdispTdiState`] over all four protobuf variants.
fn any_tdi_state() -> TdispTdiState {
    match kani::any::<u8>() % 4 {
        0 => TdispTdiState::Uninitialized,
        1 => TdispTdiState::Unlocked,
        2 => TdispTdiState::Locked,
        _ => TdispTdiState::Run,
    }
}

/// Symbolic host result code — covers `Success`, a recognised
/// non-`Success` failure code, and an unrecognised integer that
/// decodes to `None` via [`GuestToHostResponse::error_code`].
fn any_result_code() -> i32 {
    if kani::any() {
        TdispGuestOperationErrorCode::Success as i32
    } else if kani::any() {
        TdispGuestOperationErrorCode::InvalidDeviceState as i32
    } else {
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
        i32::MIN
    }
}

/// Build a fully-symbolic [`GuestToHostResponse`] whose `response`
/// oneof is `None`, the *matching* variant for the operation under
/// test, or a *mismatched* variant. Lets each per-method harness
/// inject its own matching variant.
fn any_response_with_payload(matching: Response, mismatched: Response) -> GuestToHostResponse {
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

/// Drive an `async fn(&mut VpciClientTdispState) -> R` to completion
/// using a single-poll, no-op-waker executor. The `KaniMock` host
/// channel resolves on the first poll, which matches what an executor
/// would do for a `Ready`-on-first-poll future.
///
/// Avoids `futures::executor::block_on`, which under Kani triggers
/// `pthread_key_create` (`assume(false)`) and would make
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

// --------------------------------------------------------------------
// TVM-1 — Outgoing-request precondition gate on `LOCK_INTERFACE_REQUEST`.
//
// Spec basis: PCI-SIG TDISP v2022-07-27 §11.3.1 Table 3 ("Legal TDISP
// states for Device") and §11.2 (state machine). A
// `LOCK_INTERFACE_REQUEST` may be transmitted for a TDI iff the TVM's
// locally tracked TDI state is `CONFIG_UNLOCKED`. Issuing LOCK from
// any other cached state is a TVM-side state-machine violation.
//
// This is a PRECONDITION property on the outgoing request, not a
// post-condition on the response. The property is independent of
// what the host returns: even if the host happens to reply with a
// well-formed `Success + tdi_state_after = Locked`, the TVM must
// have refused to issue the LOCK in the first place when the cached
// state was anything other than `Unlocked`.
//
// This harness asserts the strict spec ideal: an `Ok(())` return
// from `tdisp_bind_interface` implies `state_before == Unlocked`.
// --------------------------------------------------------------------

/// Verify TVM-1: `tdisp_bind_interface` (`LOCK_INTERFACE_REQUEST`) is
/// only issued from cached state `Unlocked`.
///
/// # Threat model
/// The host's [`GuestToHostResponse`] is fully symbolic — `result`,
/// `tdi_state_before`, `tdi_state_after`, and the oneof payload (None
/// / matching Bind / mismatched). The cached `tdi_state_before` is
/// also fully symbolic over all four variants.
///
/// # Assertion
/// `result.is_ok()  ⇒  state_before == Unlocked`.
///
/// Equivalently: if the function returns Ok, the precondition gate
/// must have been honoured.
#[kani::proof]
#[kani::unwind(2)]
fn verify_tvm1_bind_only_from_unlocked() {
    let state_before = any_tdi_state();
    let response = any_response_with_payload(
        Response::Bind(TdispCommandResponseBind {}),
        Response::Bind(TdispCommandResponseBind {}),
    );

    let mut state = VpciClientTdispState::kani_new_with_response(state_before, response);
    let result = kani_run_async!(state, state.tdisp_bind_interface());

    if result.is_ok() {
        assert_eq!(
            state_before,
            TdispTdiState::Unlocked,
            "TVM-1 violation: tdisp_bind_interface returned Ok from a \
             cached state other than Unlocked (TDISP §11.3.1 Table 3)",
        );
    }

    core::mem::forget(state);
}

// --------------------------------------------------------------------
// TVM-3 — Outgoing-request precondition gate on `START_INTERFACE_REQUEST`.
//
// Spec basis: PCI-SIG TDISP v2022-07-27 §11.3.1 Table 3 (Legal TDISP
// states for Device for `START_INTERFACE_REQUEST` = `CONFIG_LOCKED`)
// and §11.3.14 (the device must fail START with
// `INVALID_INTERFACE_STATE` when the TDI is not in `CONFIG_LOCKED`).
//
// The TVM-side TDISP request emitter must not transmit
// `START_INTERFACE_REQUEST` unless its locally tracked TDI state is
// `CONFIG_LOCKED`. Issuing START from any other cached state risks:
//   - Driving the cached state to `Run` on a forged host reply
//     while the device-side state machine is in some other state,
//     desynchronising the TVM's per-epoch trust caches from the
//     real device epoch (§11.6.3 chain-of-custody).
//   - Composing with TVM-1 (cf. `verify_tvm1_bind_only_from_unlocked`)
//     to amplify any prior cached-state corruption.
//
// This harness asserts the strict spec ideal: an `Ok(())` return
// from `tdisp_start_device` implies `state_before == Locked`.
// --------------------------------------------------------------------

use openhcl_tdisp::TdispCommandResponseStartTdi;

/// Verify TVM-3: `tdisp_start_device` (`START_INTERFACE_REQUEST`) is
/// only issued from cached state `Locked`.
#[kani::proof]
#[kani::unwind(2)]
fn verify_tvm3_start_only_from_locked() {
    let state_before = any_tdi_state();
    let response = any_response_with_payload(
        Response::StartTdi(TdispCommandResponseStartTdi {}),
        Response::Bind(TdispCommandResponseBind {}),
    );

    let mut state = VpciClientTdispState::kani_new_with_response(state_before, response);
    let result = kani_run_async!(state, state.tdisp_start_device());

    if result.is_ok() {
        assert_eq!(
            state_before,
            TdispTdiState::Locked,
            "TVM-3 violation: tdisp_start_device returned Ok from a \
             cached state other than Locked (TDISP §11.3.1 Table 3, §11.3.14)",
        );
    }

    core::mem::forget(state);
}

// --------------------------------------------------------------------
// TVM-2 — Outgoing-request precondition gate on
// `GET_DEVICE_INTERFACE_REPORT`.
//
// Spec basis: PCI-SIG TDISP v2022-07-27 §11.3.1 Table 3 (Legal TDISP
// states for `GET_DEVICE_INTERFACE_REPORT_REQUEST` =
// `CONFIG_LOCKED | RUN`) and §11.3.10 (the device must reject GET
// REPORT unless the TDI is `CONFIG_LOCKED` or `RUN`).
//
// The TVM-side emitter must not transmit `GET_DEVICE_INTERFACE_REPORT`
// unless its locally tracked TDI state is `CONFIG_LOCKED` or `RUN`.
// Otherwise the TVM:
//   - Hands a host-controlled blob back to the attestation layer for a
//     TDI that has never been bound, with no cached lock-epoch
//     binding to anchor it (§11.3.11, §11.6.3).
//   - May enable the host to seed cached `tdi_state` to `Run` via a
//     forged `tdi_state_after` on the response (cf. AF-3 in the prior
//     iteration's bug catalog), bypassing the LOCK→START chain entirely.
//
// This harness asserts: an `Ok(_)` return implies
// `state_before ∈ {Locked, Run}`.
// --------------------------------------------------------------------

use openhcl_tdisp::TdispCommandResponseGetTdiReport;
use openhcl_tdisp::TdispReportType;

/// Verify TVM-2: `tdisp_get_device_report` (`GET_DEVICE_INTERFACE_REPORT`)
/// is only issued from cached state `Locked` or `Run`.
#[kani::proof]
#[kani::unwind(2)]
fn verify_tvm2_get_report_only_from_locked_or_run() {
    let state_before = any_tdi_state();
    let response = any_response_with_payload(
        Response::GetTdiReport(TdispCommandResponseGetTdiReport {
            report_type: TdispReportType::InterfaceReport as i32,
            report_buffer: Vec::new(),
        }),
        Response::Bind(TdispCommandResponseBind {}),
    );

    let mut state = VpciClientTdispState::kani_new_with_response(state_before, response);
    let result = kani_run_async!(
        state,
        state.tdisp_get_device_report(&TdispReportType::InterfaceReport)
    );

    if let Ok(buf) = &result {
        assert!(
            state_before == TdispTdiState::Locked || state_before == TdispTdiState::Run,
            "TVM-2 violation: tdisp_get_device_report returned Ok from a \
             cached state other than Locked|Run (TDISP §11.3.1 Table 3, §11.3.10)",
        );
        // `buf` is `&Vec<u8>`; nothing to forget separately — `result` is
        // forgotten below.
        let _ = buf;
    }
    if let Ok(buf) = result {
        core::mem::forget(buf);
    }
    core::mem::forget(state);
}

// --------------------------------------------------------------------
// TVM-5 — Response opcode/payload discipline.
//
// Spec basis: PCI-SIG TDISP v2022-07-27 §11.3.2 Table 4. For every
// outstanding request of opcode X, the only acceptable response codes
// are response(X) and `TDISP_ERROR`. Any other code (including
// undefined / unsupported / wrong opcode) must be treated as
// `TDISP_ERROR` and must not advance state.
//
// In the OpenHCL prost wire encoding, the analogue is the
// `GuestToHostResponse.response` oneof variant. The
// `response::<T>()` helper in `tdisp_proto` returns `Err` if the
// oneof variant doesn't match the requested type `T`. Each per-method
// handler in `tdisp.rs` calls `res.response::<T>()` with the matching
// `T` (e.g. `TdispCommandResponseBind` for `tdisp_bind_interface`),
// so a wrong-typed payload propagates as `Err`.
//
// This harness asserts the positive direction: an `Ok(())` return
// from `tdisp_bind_interface` implies the host's `response` oneof was
// the matching `Bind` variant. A `None`-payload or `StartTdi` payload
// must not satisfy a Bind request.
// --------------------------------------------------------------------

/// Verify TVM-5 (Bind variant): `tdisp_bind_interface().is_ok()`
/// implies the host returned a matching `Bind` oneof variant.
///
/// Combined with the in-flight serialization invariant of
/// `send_tdisp_command` (one outstanding request per `host_channel`),
/// this also discharges TVM-20 (request/response pairing) for the
/// Bind opcode: a Bind request cannot be satisfied by a wrong-typed
/// or absent payload.
#[kani::proof]
#[kani::unwind(2)]
fn verify_tvm5_bind_payload_discipline() {
    let state_before = any_tdi_state();
    let response = any_response_with_payload(
        Response::Bind(TdispCommandResponseBind {}),
        Response::StartTdi(TdispCommandResponseStartTdi {}),
    );
    let host_payload_was_matching = matches!(response.response, Some(Response::Bind(_)));

    let mut state = VpciClientTdispState::kani_new_with_response(state_before, response);
    let result = kani_run_async!(state, state.tdisp_bind_interface());

    if result.is_ok() {
        assert!(
            host_payload_was_matching,
            "TVM-5 violation: tdisp_bind_interface returned Ok with a \
             non-Bind oneof payload (TDISP §11.3.2 Table 4)",
        );
    }

    core::mem::forget(state);
}

// --------------------------------------------------------------------
// TVM-18 — On observed/induced ERROR, the TVM must not have advanced
// its cached `tdi_state` ahead of a successful state-changing
// transition.
//
// Spec basis: PCI-SIG TDISP v2022-07-27 §11.3.13 Table 17 (TDISP_ERROR
// response: TDI state may stay or transition to ERROR/UNLOCKED but is
// NOT defined to advance to the requested-target state),
// §11.3.24 (ERROR semantics), §11.6.3 (a host-claimed `tdi_state_after`
// on a non-Success response cannot be trusted to reflect device-side
// reality).
//
// In particular: when `tdisp_bind_interface` returns `Err` because the
// host responded with a non-`Success` `result` code, the TVM-side
// cached `tdi_state` MUST NOT have been advanced to whatever
// `tdi_state_after` the host claimed. Otherwise a malicious host can
// stuff arbitrary cached states by returning a non-Success error code
// alongside an attractive `tdi_state_after` claim.
//
// The OpenHCL production order in `send_tdisp_command` is:
//   1. update_tdi_state(tdi_state_after_enum())  — runs first.
//   2. match error_code()                          — Err returned here.
// So a non-Success response WITH a decodable `tdi_state_after` flips
// the cache before the function returns Err. Expected: harness FAILS
// (real finding).
// --------------------------------------------------------------------

/// Verify TVM-18 (Bind branch): an `Err` return from
/// `tdisp_bind_interface` driven by a host non-`Success` response
/// must not have advanced the cached `tdi_state` beyond
/// `state_before`.
///
/// More precisely: if `result.is_err()` AND the host's
/// `error_code() != Some(Success)`, then `cached_after == state_before`.
#[kani::proof]
#[kani::unwind(2)]
fn verify_tvm18_err_response_does_not_advance_cache_on_bind() {
    let state_before = any_tdi_state();
    let response = any_response_with_payload(
        Response::Bind(TdispCommandResponseBind {}),
        Response::Bind(TdispCommandResponseBind {}),
    );
    // Capture the host's claimed result before moving `response`.
    let host_result = response.result;

    let mut state = VpciClientTdispState::kani_new_with_response(state_before, response);
    let result = kani_run_async!(state, state.tdisp_bind_interface());
    let cached_after = state.kani_tdi_state();

    let host_claimed_success = host_result == TdispGuestOperationErrorCode::Success as i32;

    if result.is_err() && !host_claimed_success {
        assert_eq!(
            cached_after, state_before,
            "TVM-18 violation: cached tdi_state advanced from {:?} to {:?} \
             on a non-Success host response (TDISP §11.3.13, §11.6.3)",
            state_before, cached_after,
        );
    }

    core::mem::forget(state);
}

// --------------------------------------------------------------------
// TVM-19 — Teardown scrubbing on `STOP_INTERFACE_REQUEST` / unbind.
//
// Spec basis: PCI-SIG TDISP v2022-07-27 §11.3.16 (device-side scrub on
// STOP), §11.3.9 (nonce destruction on UNLOCKED/ERROR exit from
// LOCKED), §11.6.3 (LOCK→REPORT→START chain-of-custody — per-epoch
// trust state must not survive into a new epoch).
//
// Mapped to the production state today (no `lock_epoch` /
// `start_interface_nonce` fields exist yet, see TVM-8): on a
// successful `tdisp_unbind`, the per-bind trust state must be cleared:
//   - `validated_mmio_bars` empty
//   - `dma_unblocked == false`
//   - `tdi_report == None` (the closest analogue to the §11.3.16
//     "TVM-side device data scrub" obligation today)
//
// Additionally, the cached `tdi_state` on a successful `tdisp_unbind`
// must reflect the device-side terminal state (`Unlocked`, per
// §11.2 Figure 11-5: STOP_INTERFACE_REQUEST returns the TDI to
// CONFIG_UNLOCKED).
//
// Properties verified here, on the Ok path:
//   (a) bookkeeping cleared (validated_mmio_bars, dma_unblocked, tdi_report).
//   (b) cached tdi_state == Unlocked (per §11.2 Figure 11-5).
//
// (a) is expected to PASS (production `tdisp_unbind_inner` clears all
// three on the Ok path). (b) is a strict spec ideal that is expected
// to FAIL today: production has no per-method post-check that the
// host's `tdi_state_after` matches `Unlocked`, so a malicious host can
// return Success + `tdi_state_after = Run` + matching Unbind payload
// and the cached state is left at Run.
// --------------------------------------------------------------------

use crate::tdisp::IsolationSnapshot;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use openhcl_tdisp::TdispCommandResponseUnbind;
use openhcl_tdisp::TdispGuestUnbindReason;
use openhcl_tdisp::TdispResourceValidationInterface;
use std::sync::Arc;
use tdisp::devicereport::TdiReportStruct;
use tdisp::devicereport::TdispTdiReportInterfaceInfo;

/// No-op resource validator for unbind harnesses. The unbind path
/// invokes `tdisp_block_mmio` / `tdisp_block_dma` to re-block prior
/// epoch resources before sending STOP; we only care about the
/// post-unbind cached state, not what the validator does, so we
/// accept all calls without side-effects.
struct KaniNoopValidator;

impl TdispResourceValidationInterface for KaniNoopValidator {
    fn tdisp_unblock_mmio(
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
    fn tdisp_unblock_dma(&self, _target_vtl: hvdef::Vtl, _device_id: u16) -> anyhow::Result<()> {
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

// Suppress unused-warnings for AtomicBool/Ordering — kept imported in
// case future harnesses need them; explicit `_` consumes them quietly.
#[allow(dead_code)]
const _UNUSED_ATOMIC: fn() = || {
    let _ = AtomicBool::new(false);
    let _ = Ordering::Relaxed;
};

/// Verify TVM-19 part (a): on a successful `tdisp_unbind`, the
/// per-bind bookkeeping (`validated_mmio_bars`, `dma_unblocked`,
/// `tdi_report`) is cleared.
///
/// This is the production-honored half of the property. Expected:
/// PASS today. Any future regression that leaks per-bind trust state
/// across an unbind would break the §11.6.3 chain-of-custody.
#[kani::proof]
#[kani::unwind(2)]
fn verify_tvm19_unbind_scrubs_per_bind_state() {
    const BAR_ID: u16 = 0;
    const BASE_GPA: u64 = 0x4000;
    let length_in_bytes: u32 = kani::any();
    kani::assume(length_in_bytes > 0);
    let dma_unblocked_before: bool = kani::any();
    let tdi_state = any_tdi_state();

    // Pre-cache an empty TDI report so we can observe whether
    // `tdisp_unbind` (default variant, clear_cached_report = true)
    // clears it on the Ok path.
    let tdi_report = Some(TdiReportStruct {
        interface_info: TdispTdiReportInterfaceInfo::new(),
        msi_x_message_control: 0,
        lnr_control: 0,
        tph_control: 0,
        mmio_interface_info: Vec::new(),
    });

    let response = any_response_with_payload(
        Response::Unbind(TdispCommandResponseUnbind {}),
        Response::Bind(TdispCommandResponseBind {}),
    );

    let validator: Arc<dyn TdispResourceValidationInterface> = Arc::new(KaniNoopValidator);
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
        assert!(
            state.kani_validated_mmio_bars_is_empty(),
            "TVM-19(a) violation: tdisp_unbind Ok did not clear validated_mmio_bars",
        );
        assert!(
            !state.kani_dma_unblocked(),
            "TVM-19(a) violation: tdisp_unbind Ok did not clear dma_unblocked",
        );
        assert!(
            !state.kani_tdi_report_is_some(),
            "TVM-19(a) violation: tdisp_unbind Ok did not clear tdi_report",
        );
    }

    core::mem::forget(state);
}

/// Verify TVM-19 part (b) — strict spec ideal: on a successful
/// `tdisp_unbind`, the cached `tdi_state` must equal `Unlocked` (the
/// device-side terminal state per §11.2 Figure 11-5 +
/// §11.3.16).
///
/// Expected: FAIL today. `tdisp_unbind_inner` performs no
/// per-method post-check on `tdi_state_after`, so a malicious host
/// can claim `tdi_state_after = Run` and the cached state is left at
/// `Run` while the function returns `Ok`.
#[kani::proof]
#[kani::unwind(2)]
fn verify_tvm19_unbind_settles_cache_to_unlocked() {
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

    let response = any_response_with_payload(
        Response::Unbind(TdispCommandResponseUnbind {}),
        Response::Bind(TdispCommandResponseBind {}),
    );

    let validator: Arc<dyn TdispResourceValidationInterface> = Arc::new(KaniNoopValidator);
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
        assert_eq!(
            state.kani_tdi_state(),
            TdispTdiState::Unlocked,
            "TVM-19(b) violation: tdisp_unbind Ok left cached tdi_state at \
             {:?} (TDISP §11.2 Figure 11-5, §11.3.16)",
            state.kani_tdi_state(),
        );
    }

    // Avoid `IsolationSnapshot` Drop chain warnings; reference the
    // type so the import isn't dead.
    let _: Option<IsolationSnapshot> = None;

    core::mem::forget(state);
}
