// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kani formal-verification harnesses for the OpenHCL paravisor (TVM)
//! TDISP request/response handler, driven via the **public lib.rs API**
//! (`VpciDevice::tdisp_on_device_activate` /
//! `VpciDevice::tdisp_on_device_deactivate`) rather than the internal
//! `VpciClientTdispState` primitives in `tdisp.rs`.
//!
//! The properties verified here are the same TVM-1..TVM-19 set
//! exercised by [`crate::kani_proofs`], restated against the higher-
//! level public surface that the chipset MMIO write path actually
//! invokes. Where a property is internal (e.g. precondition gates on
//! Bind/Start/GetReport), an `#[cfg(kani)]` audit trail recorded
//! inside `send_tdisp_command` makes the per-issue cached state
//! observable to the harness.
//!
//! The mock host channel (`HostChannel::KaniMock`) is single-shot per
//! the existing scaffolding; harnesses driving the deactivate path
//! (which sends exactly one TDISP command) work directly. Harnesses
//! for the activate path are deferred until the multi-shot symbolic
//! mock and feature-gate shim are in place.

use crate::VpciClientTdispState;
use crate::VpciDevice;
use crate::tdisp::IsolationSnapshot;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use openhcl_tdisp::GuestToHostResponse;
use openhcl_tdisp::GuestToHostResponseVariantOneof as Response;
use openhcl_tdisp::TdispCommandResponseBind;
use openhcl_tdisp::TdispCommandResponseUnbind;
use openhcl_tdisp::TdispGuestOperationErrorCode;
use openhcl_tdisp::TdispResourceValidationInterface;
use std::sync::Arc;
use tdisp::TdispTdiState;
use tdisp::devicereport::TdiReportStruct;
use tdisp::devicereport::TdispTdiReportInterfaceInfo;

// --------------------------------------------------------------------
// Symbolic-input helpers (mirror `kani_proofs.rs`).
// --------------------------------------------------------------------

fn any_tdi_state() -> TdispTdiState {
    match kani::any::<u8>() % 4 {
        0 => TdispTdiState::Uninitialized,
        1 => TdispTdiState::Unlocked,
        2 => TdispTdiState::Locked,
        _ => TdispTdiState::Run,
    }
}

fn any_result_code() -> i32 {
    if kani::any() {
        TdispGuestOperationErrorCode::Success as i32
    } else if kani::any() {
        TdispGuestOperationErrorCode::InvalidDeviceState as i32
    } else {
        i32::MIN
    }
}

fn any_state_after_int() -> i32 {
    if kani::any() {
        any_tdi_state() as i32
    } else {
        i32::MIN
    }
}

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

/// Drive an `async fn` to completion using a single-poll, no-op-waker
/// executor. See `kani_proofs.rs` for rationale.
macro_rules! kani_run_async {
    ($expr:expr) => {{
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

/// No-op resource validator (mirror of `KaniNoopValidator` in
/// `kani_proofs.rs`).
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

#[allow(dead_code)]
const _UNUSED_ATOMIC: fn() = || {
    let _ = AtomicBool::new(false);
    let _ = Ordering::Relaxed;
};

// --------------------------------------------------------------------
// TVM-19(a) — `tdisp_on_device_deactivate` clears per-bind bookkeeping.
//
// Spec basis: PCI-SIG TDISP v2022-07-27 §11.3.16 (TVM-side scrub on
// STOP), §11.3.20 (post-STOP cache invariants), §11.6.3 (chain-of-
// custody — per-epoch trust state must not survive into a new epoch).
//
// At the public-API layer, `tdisp_on_device_deactivate` is the only
// path that issues an unbind on the disable edge. It calls
// `tdisp_unbind_preserve_report` which clears `validated_mmio_bars`
// and `dma_unblocked` on the Ok path while intentionally retaining
// `tdi_report` (the preserve-report variant).
//
// This harness asserts: precondition `tdi_state == Run`,
// `validated_mmio_bars` non-empty, `dma_unblocked == true`,
// `tdi_report == Some(_)`. After `tdisp_on_device_deactivate()` —
// regardless of the symbolic host response — IF the cached state
// after the call still reflects a successful unbind path (i.e. the
// production code reached the Ok branch of `tdisp_unbind_inner`),
// then the bookkeeping must have been scrubbed.
//
// Since `tdisp_on_device_deactivate` returns `()` (no Result), the
// only observable that distinguishes Ok-from-Err is whether
// bookkeeping was cleared. The strongest assertion at this layer is
// a structural invariant: after deactivate, EITHER (the unbind
// failed and bookkeeping is left as-is) OR (the unbind succeeded and
// bookkeeping is cleared). We bound the failed case via the
// host-mock side: if the host response had Success and matching
// Unbind payload, bookkeeping must be cleared.
// --------------------------------------------------------------------

/// Verify TVM-19(a) at the public-API layer:
/// `tdisp_on_device_deactivate` clears per-bind bookkeeping when the
/// host returns a well-formed Success/Unbind response.
#[kani::proof]
#[kani::unwind(2)]
fn verify_tvm19a_deactivate_scrubs_bookkeeping_via_lib() {
    const BAR_ID: u16 = 0;
    const BASE_GPA: u64 = 0x4000;
    let length_in_bytes: u32 = kani::any();
    kani::assume(length_in_bytes > 0);

    // Build a TDISP state pre-cached in Run with one validated MMIO BAR,
    // dma unblocked, and a cached interface report — i.e. a fully-
    // attested device about to be deactivated.
    let tdi_report = Some(TdiReportStruct {
        interface_info: TdispTdiReportInterfaceInfo::new(),
        msi_x_message_control: 0,
        lnr_control: 0,
        tph_control: 0,
        mmio_interface_info: Vec::new(),
    });

    // Pin the host's reply to a well-formed Success+Unbind payload so
    // the unbind reaches its Ok branch; `tdi_state_after` is symbolic
    // (the malicious-host degree of freedom this property care about).
    let response = GuestToHostResponse {
        result: TdispGuestOperationErrorCode::Success as i32,
        tdi_state_before: any_state_after_int(),
        tdi_state_after: any_state_after_int(),
        response: Some(Response::Unbind(TdispCommandResponseUnbind {})),
    };

    let validator: Arc<dyn TdispResourceValidationInterface> = Arc::new(KaniNoopValidator);
    let tdisp_state = VpciClientTdispState::kani_new_for_unbind_with_report(
        TdispTdiState::Run,
        BAR_ID,
        BASE_GPA,
        length_in_bytes,
        /* dma_unblocked_before */ true,
        tdi_report,
        response,
        validator,
    );

    let device = VpciDevice::kani_new(tdisp_state);

    kani_run_async!(device.tdisp_on_device_deactivate());

    // After the call, inspect the inner TDISP state through the
    // async-mutex shim. `try_lock` always succeeds because the harness
    // is single-threaded under CBMC.
    let guard = device
        .__kani_tdisp_try_lock()
        .expect("tdisp mutex unexpectedly contended under Kani");

    assert!(
        guard.kani_validated_mmio_bars_is_empty(),
        "TVM-19(a) violation via lib.rs: tdisp_on_device_deactivate did \
         not clear validated_mmio_bars",
    );
    assert!(
        !guard.kani_dma_unblocked(),
        "TVM-19(a) violation via lib.rs: tdisp_on_device_deactivate did \
         not clear dma_unblocked",
    );
    // Preserve-report semantics: tdi_report must SURVIVE deactivate.
    assert!(
        guard.kani_tdi_report_is_some(),
        "TVM-19(a) regression: tdisp_on_device_deactivate (preserve-report \
         variant) cleared the cached TDI interface report",
    );

    drop(guard);

    // Reference IsolationSnapshot to keep the import non-dead.
    let _: Option<IsolationSnapshot> = None;

    core::mem::forget(device);
}

// --------------------------------------------------------------------
// TVM-19(b) — `tdisp_on_device_deactivate` settles cached `tdi_state`
// to `Unlocked`.
//
// Spec basis: PCI-SIG TDISP v2022-07-27 §11.2 Figure 11-5
// (`STOP_INTERFACE_REQUEST` returns the TDI to `CONFIG_UNLOCKED`),
// §11.3.16, §11.6.3.
//
// At the public-API layer, `tdisp_on_device_deactivate` issues
// `tdisp_unbind_preserve_report` from cached state `Run`. After the
// call the cached `tdi_state` MUST equal `Unlocked` — anything else
// means the TVM cache disagrees with the spec-mandated post-STOP TDI
// state and a malicious-host `tdi_state_after = Run`/`Locked` claim
// has poisoned the cache.
//
// Expected: FAIL today. `send_tdisp_command` writes the cache from
// `tdi_state_after_enum()` BEFORE checking the error code, and
// neither the inner `tdisp_unbind_inner` nor
// `tdisp_on_device_deactivate` perform a per-method post-check that
// the resulting state == `Unlocked`. This is the same root cause as
// `docs/bugs/tdisp-tvm19-unbind-cache-not-settled.md` surfaced via
// the public API.
// --------------------------------------------------------------------

/// Verify TVM-19(b) at the public-API layer:
/// `tdisp_on_device_deactivate` Ok ⇒ cached `tdi_state == Unlocked`.
#[kani::proof]
#[kani::unwind(2)]
fn verify_tvm19b_deactivate_settles_cache_to_unlocked_via_lib() {
    const BAR_ID: u16 = 0;
    const BASE_GPA: u64 = 0x4000;
    let length_in_bytes: u32 = kani::any();
    kani::assume(length_in_bytes > 0);

    let tdi_report = Some(TdiReportStruct {
        interface_info: TdispTdiReportInterfaceInfo::new(),
        msi_x_message_control: 0,
        lnr_control: 0,
        tph_control: 0,
        mmio_interface_info: Vec::new(),
    });

    // Pin Success+Unbind so the unbind reaches its Ok branch; leave
    // `tdi_state_after` symbolic — that is the malicious-host
    // degree of freedom under test.
    let response = GuestToHostResponse {
        result: TdispGuestOperationErrorCode::Success as i32,
        tdi_state_before: any_state_after_int(),
        tdi_state_after: any_state_after_int(),
        response: Some(Response::Unbind(TdispCommandResponseUnbind {})),
    };

    let validator: Arc<dyn TdispResourceValidationInterface> = Arc::new(KaniNoopValidator);
    let tdisp_state = VpciClientTdispState::kani_new_for_unbind_with_report(
        TdispTdiState::Run,
        BAR_ID,
        BASE_GPA,
        length_in_bytes,
        true,
        tdi_report,
        response,
        validator,
    );

    let device = VpciDevice::kani_new(tdisp_state);
    kani_run_async!(device.tdisp_on_device_deactivate());

    let guard = device
        .__kani_tdisp_try_lock()
        .expect("tdisp mutex unexpectedly contended under Kani");

    assert_eq!(
        guard.kani_tdi_state(),
        TdispTdiState::Unlocked,
        "TVM-19(b) violation via lib.rs: tdisp_on_device_deactivate left \
         cached tdi_state at {:?} (TDISP §11.2 Figure 11-5, §11.3.16). \
         The host returned Success+Unbind with a symbolic tdi_state_after; \
         cached state must be force-settled to Unlocked regardless.",
        guard.kani_tdi_state(),
    );

    drop(guard);
    core::mem::forget(device);
}

// --------------------------------------------------------------------
// TVM-18 (Unbind branch via deactivate) — Err response on
// `tdisp_unbind_preserve_report` must not poison cached `tdi_state`.
//
// Spec basis: PCI-SIG TDISP v2022-07-27 §11.3.13 (TDISP_ERROR — TDI
// state may stay or transition to ERROR/UNLOCKED but is NOT defined
// to advance to a host-claimed target), §11.3.24 (ERROR semantics),
// §11.6.3 (host-claimed `tdi_state_after` on a non-Success response
// cannot be trusted).
//
// At the public-API layer, `tdisp_on_device_deactivate` issues
// `tdisp_unbind_preserve_report` from cached state `Run`. When the
// host returns a non-`Success` `result` code, the TVM cache MUST NOT
// have been advanced to whatever `tdi_state_after` the host claimed.
// Currently `send_tdisp_command` writes the cache from
// `tdi_state_after_enum()` BEFORE checking `error_code()`, so a
// malicious host can stuff the cache with any state on an error
// response.
//
// Expected: FAIL today. Same root cause as
// `docs/bugs/tdisp-tvm18-err-advances-cache.md`, now confirmed via
// the public-API surface.
// --------------------------------------------------------------------

/// Verify TVM-18 (Unbind branch) at the public-API layer:
/// after `tdisp_on_device_deactivate`, if the host's response had
/// `error_code != Success`, the cached `tdi_state` must equal
/// the entry state (`Run`) — not whatever the host claimed.
#[kani::proof]
#[kani::unwind(2)]
fn verify_tvm18_deactivate_err_response_does_not_advance_cache_via_lib() {
    const BAR_ID: u16 = 0;
    const BASE_GPA: u64 = 0x4000;
    let length_in_bytes: u32 = kani::any();
    kani::assume(length_in_bytes > 0);

    let tdi_report = Some(TdiReportStruct {
        interface_info: TdispTdiReportInterfaceInfo::new(),
        msi_x_message_control: 0,
        lnr_control: 0,
        tph_control: 0,
        mmio_interface_info: Vec::new(),
    });

    let response = any_response_with_payload(
        Response::Unbind(TdispCommandResponseUnbind {}),
        Response::Unbind(TdispCommandResponseUnbind {}),
    );
    let host_result = response.result;

    let validator: Arc<dyn TdispResourceValidationInterface> = Arc::new(KaniNoopValidator);
    let tdisp_state = VpciClientTdispState::kani_new_for_unbind_with_report(
        TdispTdiState::Run,
        BAR_ID,
        BASE_GPA,
        length_in_bytes,
        true,
        tdi_report,
        response,
        validator,
    );

    let device = VpciDevice::kani_new(tdisp_state);
    kani_run_async!(device.tdisp_on_device_deactivate());

    let guard = device
        .__kani_tdisp_try_lock()
        .expect("tdisp mutex unexpectedly contended under Kani");

    let cached_after = guard.kani_tdi_state();
    let host_claimed_success = host_result == TdispGuestOperationErrorCode::Success as i32;

    if !host_claimed_success {
        assert_eq!(
            cached_after,
            TdispTdiState::Run,
            "TVM-18 violation via lib.rs: tdisp_on_device_deactivate \
             advanced cached tdi_state from Run to {:?} on a non-Success \
             host response (TDISP §11.3.13, §11.6.3). The malicious \
             host returned an error code with a forged tdi_state_after \
             and the TVM accepted it.",
            cached_after,
        );
    }

    drop(guard);
    core::mem::forget(device);
}
// Suppress unused-import warnings for symbols that will be used by
// activate-path harnesses once the multi-shot symbolic mock and
// dev_snp gate shim land.
#[allow(dead_code)]
const _UNUSED_BIND_RESPONSE: fn() -> Response = || Response::Bind(TdispCommandResponseBind {});
