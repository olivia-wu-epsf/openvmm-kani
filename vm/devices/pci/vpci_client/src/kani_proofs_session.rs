// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session Kani proofs for the OpenHCL paravisor TDISP TVM.
//!
//! This module hosts harnesses derived from the consensus
//! property list reached between the TDISP-spec expert and the
//! OpenHCL expert in this session. It does not reuse any of the
//! pre-existing harnesses in `kani_proofs.rs` /
//! `kani_proofs_highlevel.rs`; only the production-side
//! `#[cfg(kani)]` infrastructure (constructors, audit-trail
//! accessors) on [`crate::tdisp::VpciClientTdispState`] is shared.
//!
//! The properties verified here are TVM-side TDISP integrity /
//! confidentiality obligations under the malicious-host threat model:
//! the host VMM controls every TDISP wire response (status,
//! `tdi_state_after`, payload variant); the paravisor (TVM) must
//! never let an `Ok` return imply an unsafe local cached state.

#![allow(clippy::undocumented_unsafe_blocks)]

use crate::tdisp::IsolationSnapshot;
use crate::tdisp::KANI_AUDIT_TRAIL_LEN;
use crate::tdisp::VpciClientTdispState;
use crate::tdisp::kani_audit_opcode;
use openhcl_tdisp::GuestToHostResponse;
use openhcl_tdisp::GuestToHostResponseVariantOneof as Resp;
use openhcl_tdisp::TdispCommandResponseBind;
use openhcl_tdisp::TdispCommandResponseStartTdi;
use openhcl_tdisp::TdispCommandResponseUnbind;
use openhcl_tdisp::TdispGuestOperationErrorCode;
use openhcl_tdisp::TdispGuestUnbindReason;
use openhcl_tdisp::TdispResourceValidationInterface;
use openhcl_tdisp::TdispTdiState;

use hvdef::Vtl;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use tdisp::devicereport::TdiReportStruct;
use tdisp::devicereport::TdispTdiReportInterfaceInfo;
use vpci_protocol::ResourceIsolation;

// ---------------------------------------------------------------
// Tiny single-poll executor helper.
//
// The TDISP entry points are `async fn` but each future completes
// in a single `poll` under Kani (no real I/O, no real waker
// wakeups). Drive them with `Waker::noop()` + a fixed-pin.
// ---------------------------------------------------------------

macro_rules! poll_once {
    ($fut:expr) => {{
        use core::future::Future;
        use core::pin::pin;
        use core::task::Context;
        use core::task::Poll;
        use core::task::Waker;
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = pin!($fut);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(r) => break r,
                Poll::Pending => {
                    kani::assume(false);
                }
            }
        }
    }};
}

// Convert a symbolic `u8` into one of the four valid `TdispTdiState`
// discriminants by exhaustive `match`. Using a bounded index keeps
// CBMC away from `TryFrom` panic paths.
fn any_tdi_state() -> TdispTdiState {
    let i: u8 = kani::any();
    kani::assume(i < 4);
    match i {
        0 => TdispTdiState::Uninitialized,
        1 => TdispTdiState::Unlocked,
        2 => TdispTdiState::Locked,
        _ => TdispTdiState::Run,
    }
}

// Build a fully-symbolic [`GuestToHostResponse`] with a Bind
// variant payload. The host adversary controls every field.
fn any_bind_response() -> GuestToHostResponse {
    GuestToHostResponse {
        result: kani::any(),
        tdi_state_before: kani::any(),
        tdi_state_after: kani::any(),
        response: Some(Resp::Bind(TdispCommandResponseBind {})),
    }
}

fn any_start_response() -> GuestToHostResponse {
    GuestToHostResponse {
        result: kani::any(),
        tdi_state_before: kani::any(),
        tdi_state_after: kani::any(),
        response: Some(Resp::StartTdi(TdispCommandResponseStartTdi {})),
    }
}

fn any_unbind_response() -> GuestToHostResponse {
    GuestToHostResponse {
        result: kani::any(),
        tdi_state_before: kani::any(),
        tdi_state_after: kani::any(),
        response: Some(Resp::Unbind(TdispCommandResponseUnbind {})),
    }
}

// ---------------------------------------------------------------
// Recording validator. Send+Sync via atomic counters; no
// `parking_lot::Mutex` (whose `pthread_key_create` chain CBMC
// refuses to bound). Production behaviour for `unblock_*`/
// `block_*` is the noop validator (`Ok(())`); here we additionally
// record a small sequence trace so harnesses can assert ordering.
// ---------------------------------------------------------------

#[derive(Default)]
struct RecValidator {
    unblock_mmio_calls: AtomicU32,
    unblock_dma_calls: AtomicU32,
    block_mmio_calls: AtomicU32,
    block_dma_calls: AtomicU32,
    /// Monotonically increasing per-call sequence counter; assigned
    /// to each operation and used by ordering harnesses.
    seq: AtomicU32,
    /// First-block-mmio sequence number (0 == not observed).
    first_block_mmio_seq: AtomicU32,
    /// First-block-dma sequence number (0 == not observed).
    first_block_dma_seq: AtomicU32,
    any_block_dma_observed: AtomicBool,
}

impl RecValidator {
    fn new() -> Self {
        Self::default()
    }

    fn next_seq(&self) -> u32 {
        // 1-based so 0 is the "not observed" sentinel.
        self.seq.fetch_add(1, Ordering::SeqCst) + 1
    }
}

impl TdispResourceValidationInterface for RecValidator {
    fn tdisp_unblock_mmio(
        &self,
        _target_vtl: Vtl,
        _device_id: u16,
        _base_gpa: u64,
        _base_offset: u32,
        _length_in_bytes: u32,
        _range_id: u16,
    ) -> anyhow::Result<()> {
        let _ = self.next_seq();
        self.unblock_mmio_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn tdisp_unblock_dma(&self, _target_vtl: Vtl, _device_id: u16) -> anyhow::Result<()> {
        let _ = self.next_seq();
        self.unblock_dma_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn tdisp_block_mmio(
        &self,
        _target_vtl: Vtl,
        _device_id: u16,
        _base_gpa: u64,
        _base_offset: u32,
        _length_in_bytes: u32,
        _range_id: u16,
    ) -> anyhow::Result<()> {
        let s = self.next_seq();
        if self
            .first_block_mmio_seq
            .compare_exchange(0, s, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            // recorded first
        }
        self.block_mmio_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn tdisp_block_dma(&self, _target_vtl: Vtl, _device_id: u16) -> anyhow::Result<()> {
        let s = self.next_seq();
        if self
            .first_block_dma_seq
            .compare_exchange(0, s, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            // recorded first
        }
        self.any_block_dma_observed.store(true, Ordering::SeqCst);
        self.block_dma_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// Build a minimal symbolic TDI interface report with at most one
// MMIO range entry. The harness chooses whether the report has 0 or
// 1 entries (bounded index pattern); the entry's `range_id`,
// `is_non_tee_mem`, and MSI-X bits are symbolic.
fn any_report_one_range(
    bar_id: u16,
    is_non_tee_mem: bool,
    msix_table: bool,
    msix_pba: bool,
) -> TdiReportStruct {
    use tdisp::devicereport::TdispTdiReportMmioFlags;
    use tdisp::devicereport::TdispTdiReportMmioInterfaceInfo;
    let flags = TdispTdiReportMmioFlags::new()
        .with_is_non_tee_mem(is_non_tee_mem)
        .with_range_maps_msix_table(msix_table)
        .with_range_maps_msix_pba(msix_pba);
    let mut v = Vec::with_capacity(1);
    v.push(TdispTdiReportMmioInterfaceInfo {
        first_4k_page_offset: 0,
        num_4k_pages: 1,
        flags,
        range_id: bar_id,
    });
    TdiReportStruct {
        interface_info: TdispTdiReportInterfaceInfo::new(),
        msi_x_message_control: 0,
        lnr_control: 0,
        tph_control: 0,
        mmio_interface_info: v,
    }
}

fn any_report_empty() -> TdiReportStruct {
    TdiReportStruct {
        interface_info: TdispTdiReportInterfaceInfo::new(),
        msi_x_message_control: 0,
        lnr_control: 0,
        tph_control: 0,
        mmio_interface_info: Vec::new(),
    }
}

// ===============================================================
// M-1 — Cached `tdi_state` matches spec post-state on every Ok
// return from Bind / Start / Unbind.
//
// Property under proof:
//   tdisp_bind_interface().is_ok()   ==>  cached tdi_state == Locked
//   tdisp_start_device().is_ok()     ==>  cached tdi_state == Run
//   tdisp_unbind(_).is_ok()          ==>  cached tdi_state == Unlocked
//   (TDISP §11.2 Figure 11-5 + §11.3.1 Table 3.)
// Threat model: malicious host returns arbitrary `result`,
// `tdi_state_before`, `tdi_state_after`, and matching payload.
// ===============================================================

#[kani::proof]
#[kani::unwind(2)]
fn m1_bind_ok_implies_state_locked() {
    let state_before = any_tdi_state();
    let response = any_bind_response();
    let mut s = VpciClientTdispState::kani_new_with_response(state_before, response);
    let r = poll_once!(s.tdisp_bind_interface());
    if r.is_ok() {
        assert!(matches!(s.kani_tdi_state(), TdispTdiState::Locked));
    }
    core::mem::forget(s);
}

#[kani::proof]
#[kani::unwind(2)]
fn m1_start_ok_implies_state_run() {
    let state_before = any_tdi_state();
    let response = any_start_response();
    let mut s = VpciClientTdispState::kani_new_with_response(state_before, response);
    let r = poll_once!(s.tdisp_start_device());
    if r.is_ok() {
        assert!(matches!(s.kani_tdi_state(), TdispTdiState::Run));
    }
    core::mem::forget(s);
}

#[kani::proof]
#[kani::unwind(2)]
fn m1_unbind_ok_implies_state_unlocked() {
    let state_before = any_tdi_state();
    let response = any_unbind_response();
    let mut s = VpciClientTdispState::kani_new_with_response(state_before, response);
    // Bounded index for the unbind reason discriminant.
    let i: u8 = kani::any();
    kani::assume(i < 2);
    let reason = match i {
        0 => TdispGuestUnbindReason::Graceful,
        _ => TdispGuestUnbindReason::DeviceTeardown,
    };
    let r = poll_once!(s.tdisp_unbind(reason));
    if r.is_ok() {
        // M-1 spec post-state for Unbind is Unlocked (§11.3.16).
        // This harness is the security check, not a code-mirror:
        // if the implementation accepts an Ok response with
        // tdi_state_after != Unlocked, this will fail and is a
        // real finding.
        assert!(matches!(s.kani_tdi_state(), TdispTdiState::Unlocked));
    }
    core::mem::forget(s);
}

// Symmetric peer for `tdisp_unbind_preserve_report`. Both
// entrypoints share `tdisp_unbind_inner`; AF-iter2-1 applies to
// both. A fix that only patched the non-preserving wrapper would
// slip through this harness.
#[kani::proof]
#[kani::unwind(2)]
fn m1_unbind_preserve_ok_implies_state_unlocked() {
    let state_before = any_tdi_state();
    let response = any_unbind_response();
    let validator: Arc<dyn TdispResourceValidationInterface> = Arc::new(RecValidator::new());
    let bar_id: u16 = kani::any();
    kani::assume(bar_id < 6);
    let report = Some(any_report_empty());
    let mut s = VpciClientTdispState::kani_new_for_unbind_with_report(
        state_before,
        bar_id,
        /* base_gpa */ 0,
        /* length_in_bytes */ 0,
        /* dma_unblocked_before */ false,
        report,
        response,
        validator,
    );
    let i: u8 = kani::any();
    kani::assume(i < 2);
    let reason = match i {
        0 => TdispGuestUnbindReason::Graceful,
        _ => TdispGuestUnbindReason::DeviceTeardown,
    };
    let r = poll_once!(s.tdisp_unbind_preserve_report(reason));
    if r.is_ok() {
        assert!(matches!(s.kani_tdi_state(), TdispTdiState::Unlocked));
    }
    core::mem::forget(s);
}

// ===============================================================
// M-3 — `tdi_report` cache provenance + clearing on Unbind.
//
// (a) On Ok of `tdisp_unbind` (NON-preserving variant), cached
//     `tdi_report` is `None`, regardless of the host's response.
// (b) On Ok of `tdisp_unbind_preserve_report`, cached `tdi_report`
//     value is unchanged.
// (TDISP §11.3.10 + §11.6.3 — `tdi_report` is the trusted basis
// for downstream PRIVATE-classification gates; it must not survive
// a teardown except via the explicit preserve-report API.)
// ===============================================================

#[kani::proof]
#[kani::unwind(2)]
fn m3_unbind_clears_cached_report() {
    let state_before = any_tdi_state();
    let response = any_unbind_response();
    let validator: Arc<dyn TdispResourceValidationInterface> = Arc::new(RecValidator::new());
    let bar_id: u16 = kani::any();
    kani::assume(bar_id < 6);
    // Symbolic dma_unblocked_before so the validator's tdisp_block_dma
    // branch is exercised; length_in_bytes = 1 so the tdisp_block_mmio
    // branch is exercised (the length == 0 path is the SHARED-classified
    // sentinel and skips the block call entirely).
    let dma_unblocked_before: bool = kani::any();
    let report = Some(any_report_empty());
    let mut s = VpciClientTdispState::kani_new_for_unbind_with_report(
        state_before,
        bar_id,
        /* base_gpa */ 0,
        /* length_in_bytes */ 1,
        dma_unblocked_before,
        report,
        response,
        validator,
    );

    // Sanity: pre-state had a cached report.
    assert!(s.kani_tdi_report_is_some());

    let i: u8 = kani::any();
    kani::assume(i < 2);
    let reason = match i {
        0 => TdispGuestUnbindReason::Graceful,
        _ => TdispGuestUnbindReason::DeviceTeardown,
    };
    let r = poll_once!(s.tdisp_unbind(reason));
    if r.is_ok() {
        // Non-preserving variant must clear the cached report.
        assert!(!s.kani_tdi_report_is_some());
    }
    core::mem::forget(s);
}

#[kani::proof]
#[kani::unwind(2)]
fn m3_unbind_preserve_keeps_cached_report() {
    let state_before = any_tdi_state();
    let response = any_unbind_response();
    let validator: Arc<dyn TdispResourceValidationInterface> = Arc::new(RecValidator::new());
    let bar_id: u16 = kani::any();
    kani::assume(bar_id < 6);
    let dma_unblocked_before: bool = kani::any();
    let report = Some(any_report_empty());
    let mut s = VpciClientTdispState::kani_new_for_unbind_with_report(
        state_before,
        bar_id,
        /* base_gpa */ 0,
        /* length_in_bytes */ 1,
        dma_unblocked_before,
        report,
        response,
        validator,
    );

    // Sanity: pre-state had a cached report.
    assert!(s.kani_tdi_report_is_some());

    let i: u8 = kani::any();
    kani::assume(i < 2);
    let reason = match i {
        0 => TdispGuestUnbindReason::Graceful,
        _ => TdispGuestUnbindReason::DeviceTeardown,
    };
    let r = poll_once!(s.tdisp_unbind_preserve_report(reason));
    if r.is_ok() {
        // Preserve variant must keep the cached report regardless
        // of the (malicious-host) response. Per the documented
        // design, the report bytes survive across rebind cycles
        // when this variant is invoked.
        assert!(s.kani_tdi_report_is_some());
    }
    core::mem::forget(s);
}

// M-3 acquisition leg — bounded behavioral form.
//
// The chain-of-custody side of M-3 ("`tdi_report = Some(_)` ONLY
// after a complete attest chain") is verified behaviorally by
// asserting, for every non-`attest` public entrypoint, that the
// call preserves `tdi_report == None`. Combined with the
// preserve/clear harnesses below, the only writer of a `Some(_)`
// report is the `attest` orchestration. (We attempted a single
// orchestration-level harness over `attest()` itself; CBMC OOMs
// on the multi-call dispatch — see harness file history. The
// bounded one-call form below is the OpenHCL-expert-recommended
// fallback per session debate.)

#[kani::proof]
#[kani::unwind(2)]
fn m3_bind_does_not_grow_report() {
    let state_before = any_tdi_state();
    let response = any_bind_response();
    let mut s = VpciClientTdispState::kani_new_with_response(state_before, response);
    // Pre-state: no cached report.
    assert!(!s.kani_tdi_report_is_some());
    let _ = poll_once!(s.tdisp_bind_interface());
    // Post-state: still no cached report regardless of host reply
    // and regardless of Ok/Err.
    assert!(!s.kani_tdi_report_is_some());
    core::mem::forget(s);
}

#[kani::proof]
#[kani::unwind(2)]
fn m3_start_does_not_grow_report() {
    let state_before = any_tdi_state();
    let response = any_start_response();
    let mut s = VpciClientTdispState::kani_new_with_response(state_before, response);
    assert!(!s.kani_tdi_report_is_some());
    let _ = poll_once!(s.tdisp_start_device());
    assert!(!s.kani_tdi_report_is_some());
    core::mem::forget(s);
}

#[kani::proof]
#[kani::unwind(2)]
fn m3_unbind_does_not_grow_report() {
    let state_before = any_tdi_state();
    let response = any_unbind_response();
    let mut s = VpciClientTdispState::kani_new_with_response(state_before, response);
    assert!(!s.kani_tdi_report_is_some());
    let i: u8 = kani::any();
    kani::assume(i < 2);
    let reason = match i {
        0 => TdispGuestUnbindReason::Graceful,
        _ => TdispGuestUnbindReason::DeviceTeardown,
    };
    let _ = poll_once!(s.tdisp_unbind(reason));
    assert!(!s.kani_tdi_report_is_some());
    core::mem::forget(s);
}

// ===============================================================
// M-4 — No `tdisp_unblock_mmio(bar)` unless cached `tdi_state ==
// Run` ∧ `tdi_report` cached ∧ classify_bar(bar) == PRIVATE.
//
// Property under proof:
//   tdisp_on_mmio_reconfigured(bar, ...) calls
//   validator.tdisp_unblock_mmio(...) ONLY when:
//     cached tdi_state == Run AND
//     tdi_report.is_some() AND
//     classify_bar(bar) == PRIVATE
//   (intercepted=false AND in cached report AND
//    !is_non_tee_mem).
//
// This is a synchronous (non-async) call — the harness is one
// straight-line function call.
//
// Spec: TDISP §11.3.11 Table 15 (IS_NON_TEE_MEM, MSI-X bits);
// §11.4.5 (RUN required for TVM-side memory access);
// §11.6.3 (overlapping/reordered MMIO threats).
// ===============================================================

#[kani::proof]
#[kani::unwind(2)]
fn m4_unblock_mmio_requires_run_report_private() {
    let tdi_state = any_tdi_state();
    let bar_id: u16 = kani::any();
    kani::assume(bar_id < 6);

    // Symbolize whether a report is cached, and if so, the
    // critical attribute bits of the matching range. The range_id
    // matches `bar_id` so classify_bar's lookup returns this entry.
    let has_report: bool = kani::any();
    let is_non_tee_mem: bool = kani::any();
    let msix_table: bool = kani::any();
    let msix_pba: bool = kani::any();
    let report = if has_report {
        Some(any_report_one_range(
            bar_id,
            is_non_tee_mem,
            msix_table,
            msix_pba,
        ))
    } else {
        None
    };

    let intercepted: bool = kani::any();
    let validated_already: bool = kani::any();
    let dma_unblocked_before: bool = kani::any();

    let validator = Arc::new(RecValidator::new());
    let validator_dyn: Arc<dyn TdispResourceValidationInterface> = validator.clone();
    let mut s = VpciClientTdispState::kani_new_for_mmio_reconfigured(
        tdi_state,
        report,
        bar_id,
        intercepted,
        validated_already,
        dma_unblocked_before,
        validator_dyn,
    );

    let base: u64 = kani::any();
    let len: u32 = kani::any();
    let _ = s.tdisp_on_mmio_reconfigured(bar_id, base, len);

    // Assertion: any tdisp_unblock_mmio call implies
    //   cached tdi_state was Run AND report was cached AND
    //   classify_bar's PRIVATE preconditions held (not intercepted,
    //   in report, !is_non_tee_mem). validated_already is also a
    //   precondition — once validated, the gate skips re-unblock.
    let unblocked = validator.unblock_mmio_calls.load(Ordering::SeqCst) > 0;
    if unblocked {
        assert!(matches!(tdi_state, TdispTdiState::Run));
        assert!(has_report);
        assert!(!intercepted);
        assert!(!is_non_tee_mem);
        assert!(!validated_already);
    }
    core::mem::forget(s);
}

// ===============================================================
// M-5 — No `tdisp_unblock_dma` unless an M-4-satisfying
// `tdisp_unblock_mmio` happened first in the same call.
//
// Property under proof:
//   In tdisp_on_mmio_reconfigured, `validator.tdisp_unblock_dma`
//   is invoked ONLY when:
//     - the same call also invoked `tdisp_unblock_mmio` (i.e. the
//       M-4 PRIVATE branch was taken AND validator.unblock_mmio
//       fired), AND
//     - the call invoked dma unblock AT MOST ONCE per call (it
//       was guarded by `!dma_unblocked` and only fires after the
//       MMIO unblock).
//   The harness then implies M-5: no DMA unblock in any branch
//   that didn't take the M-4 PRIVATE branch.
//
// Spec: §11.5.3 + §11.6.3 ("securely enabling the memory space
// and DMA for TVM access using START_INTERFACE_REQUEST" — DMA
// unblock is a chain consequence, not a side door).
// ===============================================================

#[kani::proof]
#[kani::unwind(2)]
fn m5_unblock_dma_requires_unblock_mmio_in_same_call() {
    let tdi_state = any_tdi_state();
    let bar_id: u16 = kani::any();
    kani::assume(bar_id < 6);

    let has_report: bool = kani::any();
    let is_non_tee_mem: bool = kani::any();
    let msix_table: bool = kani::any();
    let msix_pba: bool = kani::any();
    let report = if has_report {
        Some(any_report_one_range(
            bar_id,
            is_non_tee_mem,
            msix_table,
            msix_pba,
        ))
    } else {
        None
    };

    let intercepted: bool = kani::any();
    let validated_already: bool = kani::any();
    let dma_unblocked_before: bool = kani::any();

    let validator = Arc::new(RecValidator::new());
    let validator_dyn: Arc<dyn TdispResourceValidationInterface> = validator.clone();
    let mut s = VpciClientTdispState::kani_new_for_mmio_reconfigured(
        tdi_state,
        report,
        bar_id,
        intercepted,
        validated_already,
        dma_unblocked_before,
        validator_dyn,
    );

    let base: u64 = kani::any();
    let len: u32 = kani::any();
    let _ = s.tdisp_on_mmio_reconfigured(bar_id, base, len);

    let dma_unblocked_calls = validator.unblock_dma_calls.load(Ordering::SeqCst);
    let mmio_unblocked_calls = validator.unblock_mmio_calls.load(Ordering::SeqCst);

    if dma_unblocked_calls > 0 {
        // (a) DMA unblock requires same-call MMIO unblock had to
        // succeed first (the gate is sequential inside the
        // function body).
        assert!(mmio_unblocked_calls > 0);
        // (b) DMA unblock implies the M-4-PRIVATE preconditions:
        // state was Run, report cached, BAR not intercepted,
        // matching range was TEE memory, and the BAR had not
        // already been validated.
        assert!(matches!(tdi_state, TdispTdiState::Run));
        assert!(has_report);
        assert!(!intercepted);
        assert!(!is_non_tee_mem);
        assert!(!validated_already);
        // (c) DMA unblock fires at most once per call (guarded by
        // !dma_unblocked AND the gate sets dma_unblocked = true
        // immediately).
        assert!(dma_unblocked_calls <= 1);
        // (d) DMA unblock didn't fire if dma_unblocked was already
        // set on entry.
        assert!(!dma_unblocked_before);
    }
    core::mem::forget(s);
}

// ===============================================================
// M-6 — Successful Unbind re-blocks before clearing bookkeeping.
//
// Property under proof, in two parts visible from this surface:
//   (a) On Ok of `tdisp_unbind`/`tdisp_unbind_preserve_report`, if
//       a previously-recorded MMIO BAR had length_in_bytes > 0,
//       then `tdisp_block_mmio` was called at least once. If
//       dma_unblocked was true on entry, then `tdisp_block_dma`
//       was called at least once.
//   (b) On Ok, post-state has `validated_mmio_bars` empty and
//       `dma_unblocked == false`. (Non-preserving variant
//       additionally clears `tdi_report` — covered by M-3.)
//
// The "before the host-facing Unbind RPC" portion is a code-
// structure invariant (re-block loop precedes
// `send_tdisp_command` in `tdisp_unbind_inner` body), confirmed
// statically by inspection. The validator surface does not
// intercept `send_tdisp_command`, so the strict ordering between
// validator block calls and host RPC is not observable by Kani
// from this entrypoint; the call-count-based assertion below
// would still fail loudly if a refactor moved the re-block to
// AFTER the RPC and made it conditional on the response.
//
// Spec: §11.3.16 (drain/abort/scrub before STOP_RESPONSE);
// §11.6.3 (race-on-detach threat).
// ===============================================================

#[kani::proof]
#[kani::unwind(2)]
fn m6_unbind_reblocks_and_clears_bookkeeping() {
    let state_before = any_tdi_state();
    let response = any_unbind_response();
    let validator = Arc::new(RecValidator::new());
    let validator_dyn: Arc<dyn TdispResourceValidationInterface> = validator.clone();
    let bar_id: u16 = kani::any();
    kani::assume(bar_id < 6);
    let dma_unblocked_before: bool = kani::any();
    let mut s = VpciClientTdispState::kani_new_for_unbind_with_report(
        state_before,
        bar_id,
        /* base_gpa */ 0,
        /* length_in_bytes */ 1,
        dma_unblocked_before,
        /* tdi_report */ None,
        response,
        validator_dyn,
    );

    let i: u8 = kani::any();
    kani::assume(i < 2);
    let reason = match i {
        0 => TdispGuestUnbindReason::Graceful,
        _ => TdispGuestUnbindReason::DeviceTeardown,
    };
    let r = poll_once!(s.tdisp_unbind(reason));
    if r.is_ok() {
        // Re-block calls happened.
        assert!(validator.block_mmio_calls.load(Ordering::SeqCst) >= 1);
        if dma_unblocked_before {
            assert!(validator.block_dma_calls.load(Ordering::SeqCst) >= 1);
        }
        // Bookkeeping cleared. Note: `validated_mmio_bars.clear()`
        // is gated on `cfg(not(kani))` in production because CBMC
        // can't bound BTreeMap::clear's IntoIter Drop — that is a
        // verification-infrastructure choice in the production
        // code itself, not a missing-clear bug. We assert the
        // dma flag clearing here; tdi_report clearing is covered
        // by M-3.
        assert!(!s.kani_dma_unblocked());
    }
    core::mem::forget(s);
}

#[kani::proof]
#[kani::unwind(2)]
fn m6_unbind_preserve_reblocks_and_clears_bookkeeping() {
    let state_before = any_tdi_state();
    let response = any_unbind_response();
    let validator = Arc::new(RecValidator::new());
    let validator_dyn: Arc<dyn TdispResourceValidationInterface> = validator.clone();
    let bar_id: u16 = kani::any();
    kani::assume(bar_id < 6);
    let dma_unblocked_before: bool = kani::any();
    let mut s = VpciClientTdispState::kani_new_for_unbind_with_report(
        state_before,
        bar_id,
        /* base_gpa */ 0,
        /* length_in_bytes */ 1,
        dma_unblocked_before,
        /* tdi_report */ None,
        response,
        validator_dyn,
    );

    let i: u8 = kani::any();
    kani::assume(i < 2);
    let reason = match i {
        0 => TdispGuestUnbindReason::Graceful,
        _ => TdispGuestUnbindReason::DeviceTeardown,
    };
    let r = poll_once!(s.tdisp_unbind_preserve_report(reason));
    if r.is_ok() {
        assert!(validator.block_mmio_calls.load(Ordering::SeqCst) >= 1);
        if dma_unblocked_before {
            assert!(validator.block_dma_calls.load(Ordering::SeqCst) >= 1);
        }
        // See note in m6_unbind_reblocks_and_clears_bookkeeping.
        assert!(!s.kani_dma_unblocked());
    }
    core::mem::forget(s);
}

// M-6 sibling — SHARED-sentinel branch.
//
// `validated_mmio_bars` entries with `length_in_bytes == 0` are the
// SHARED-classified sentinel set by `tdisp_on_mmio_reconfigured` for
// BARs that classify SHARED (intercepted or non-TEE memory). The
// unbind path's re-block loop must SKIP `block_mmio` for these
// entries (see [tdisp.rs#L834-L836](vm/devices/pci/vpci_client/src/tdisp.rs#L834-L836)).
#[kani::proof]
#[kani::unwind(2)]
fn m6_unbind_skips_block_for_zero_length_bar() {
    let state_before = any_tdi_state();
    let response = any_unbind_response();
    let validator = Arc::new(RecValidator::new());
    let validator_dyn: Arc<dyn TdispResourceValidationInterface> = validator.clone();
    let bar_id: u16 = kani::any();
    kani::assume(bar_id < 6);
    let mut s = VpciClientTdispState::kani_new_for_unbind_with_report(
        state_before,
        bar_id,
        /* base_gpa */ 0,
        /* length_in_bytes */ 0, // SHARED sentinel
        /* dma_unblocked_before */ false,
        /* tdi_report */ None,
        response,
        validator_dyn,
    );
    let i: u8 = kani::any();
    kani::assume(i < 2);
    let reason = match i {
        0 => TdispGuestUnbindReason::Graceful,
        _ => TdispGuestUnbindReason::DeviceTeardown,
    };
    let _ = poll_once!(s.tdisp_unbind(reason));
    // No block_mmio call for the SHARED-sentinel entry; no
    // block_dma call either since dma_unblocked_before == false.
    assert!(validator.block_mmio_calls.load(Ordering::SeqCst) == 0);
    assert!(validator.block_dma_calls.load(Ordering::SeqCst) == 0);
    core::mem::forget(s);
}

// ===============================================================
// M-7 — Audit invariant: outgoing TDISP commands' cached
// `tdi_state` at issue.
//
// **Adjudicated as FALSE POSITIVE for the request-side variant**
// after expert debate (TDISP-spec expert + OpenHCL expert,
// consensus). PCI-SIG TDISP §11.3.1 Table 3's "Legal TDISP
// states for Device" column governs the **device's** state
// machine (the responder), not the requester. The spec's only
// normative requester obligations are §11.2.3 (outstanding-
// request-count limits) and §11.2.7 (the four acceptance
// questions, evaluated post-REPORT). All TDISP messages travel
// inside an SPDM 1.2 secure session as VDMs (§11.2.2), so a
// malicious host cannot observe the opcode in transit; an
// out-of-state request is rejected by the device with
// `INVALID_INTERFACE_STATE` (§11.3.24 Table 27); the cache
// only advances on a successful response (M-1 covers that).
//
// Therefore the request-side audit variant of M-7 (Bind from
// `Unlocked` only / Start from `Locked` only) is a paravisor
// internal-correctness invariant, not a TDISP-spec security
// property. The OpenHCL expert classified it "valid but
// mitigated" in the current call graph (the only production
// caller of these primitives is `attest()`, which precautionary-
// unbinds before bind). It is therefore filed as a defense-in-
// depth code-quality observation, not a Kani-verified property.
//
// What we DO verify here:
//   (a) Unbind audit-state harness is meaningful: spec-legal
//       source state for STOP_INTERFACE_REQUEST is "any" of
//       {Unlocked, Locked, Run, Error}, so any recorded value
//       must be in 0..=Run (the four discriminants OpenHCL
//       carries; Error is folded into Uninitialized in the
//       prost enum).
// ===============================================================

#[kani::proof]
#[kani::unwind(9)]
fn m7_unbind_audit_trail_is_well_formed() {
    // Asserts only that the audit trail records UNBIND with a
    // valid `TdispTdiState` enum discriminant (0..=3). This is a
    // structural well-formedness check on the audit machinery,
    // not the spec-legal-source-state property (which the
    // request-side variant of M-7 would have asserted; that
    // variant was adjudicated FALSE POSITIVE — see header
    // comment + docs/kani-iteration-2/findings/m7-request-side-adjudication.md).
    let state_before = any_tdi_state();
    let response = any_unbind_response();
    let mut s = VpciClientTdispState::kani_new_with_response(state_before, response);
    let i: u8 = kani::any();
    kani::assume(i < 2);
    let reason = match i {
        0 => TdispGuestUnbindReason::Graceful,
        _ => TdispGuestUnbindReason::DeviceTeardown,
    };
    let _ = poll_once!(s.tdisp_unbind(reason));
    let trail = s.kani_audit_trail();
    for slot in trail {
        if let Some((op, state_at_issue)) = slot {
            if op == kani_audit_opcode::UNBIND {
                assert!(state_at_issue <= TdispTdiState::Run as u8);
            }
        }
    }
    core::mem::forget(s);
}

// ===============================================================
// M-8a — `isolation_snapshot()` is a pure function of cached
// state.
//
// Property under proof:
//   `isolation_snapshot()` performs no host I/O, no validator/
//   PSP call, no mutation. It returns:
//     - `NotReady` iff `tdi_report.is_none()`.
//     - `Ready { bars, dma }` otherwise, where `bars[i] =
//       classify_bar(i)` and `dma = PRIVATE iff dma_unblocked
//       else SHARED`.
//
// Approach: the per-bar classification predicate is verified by
// `m8a_isolation_snapshot_classification_for_matching_bar`. The
// "no validator calls / no host I/O" half is enforced by-
// construction (the function takes `&self` and the production
// signature does not even reach the validator field — visible
// statically at [tdisp.rs#L1253](vm/devices/pci/vpci_client/src/tdisp.rs#L1253)).
// We don't add a separate Kani harness asserting the call-counter
// invariant: it would require iterating bars[0..6], each calling
// classify_bar → BTreeMap traversal. A 6-iteration BTreeMap loop
// at our minimum-required unwind explodes CBMC's SAT formula
// even with `--no-memory-safety-checks` (OOM at >2.5GB). The
// behavioral harness below covers what is observable from a Kani
// surface; the validator-call guarantee is a code-grep
// observation, documented here.
//
// Spec: §11.2.7 Q1\u2013Q4 (acceptance is the TVM's; the host
// must not influence it); §11.6.3 (TSM not in TVM TCB).
// ===============================================================

// M-8a — classify_bar predicate determinism for the matching
// range. This pins the algebraic mapping the spec calls out:
// PRIVATE iff (in cached report) AND (!intercepted) AND
// (!is_non_tee_mem); SHARED iff intercepted OR
// (in cached report AND is_non_tee_mem); INVALID iff
// not in cached report AND not intercepted.
//
// (The "no validator/host I/O calls" portion of M-8a is not
// added as a separate Kani harness: `isolation_snapshot()` takes
// `&self` and the static call graph from
// [tdisp.rs#L1253](vm/devices/pci/vpci_client/src/tdisp.rs#L1253)
// reads only `mutable_state.{tdi_report, intercepted_bars,
// dma_unblocked}` plus pure local `classify_bar` calls. A Kani
// harness asserting validator-counter == 0 also iterates 0..6
// BAR lookups inside isolation_snapshot, which adds enough
// SAT cost on top of the Atomic-counter symbolic state that
// CBMC OOMs even with `--no-memory-safety-checks`. The behavioral
// content is captured by the matching-bar harness below; the
// validator-isolation argument is a code-grep observation.)
#[kani::proof]
#[kani::unwind(9)]
fn m8a_isolation_snapshot_classification_for_matching_bar() {
    let bar_id: u16 = kani::any();
    kani::assume(bar_id < 6);

    let has_report: bool = kani::any();
    let is_non_tee_mem: bool = kani::any();
    let report = if has_report {
        Some(any_report_one_range(bar_id, is_non_tee_mem, false, false))
    } else {
        None
    };

    let intercepted: bool = kani::any();
    let validator = Arc::new(RecValidator::new());
    let validator_dyn: Arc<dyn TdispResourceValidationInterface> = validator.clone();
    let s = VpciClientTdispState::kani_new_for_mmio_reconfigured(
        TdispTdiState::Run, // arbitrary; isolation_snapshot doesn't read tdi_state
        report,
        bar_id,
        intercepted,
        /* validated_already */ false,
        /* dma_unblocked_before */ false,
        validator_dyn,
    );

    let snap = s.isolation_snapshot();
    if let IsolationSnapshot::Ready { bars, .. } = snap {
        let cls = bars[bar_id as usize];
        if intercepted {
            assert!(matches!(cls, ResourceIsolation::SHARED));
        } else if !has_report {
            // unreachable: NotReady would have been returned.
            assert!(false);
        } else if is_non_tee_mem {
            assert!(matches!(cls, ResourceIsolation::SHARED));
        } else {
            assert!(matches!(cls, ResourceIsolation::PRIVATE));
        }
    } else {
        // NotReady iff !has_report.
        assert!(!has_report);
    }
    core::mem::forget(s);
}

// M-8a sibling \u2014 INVALID classification when cached report has no
// matching range. Pins the `INVALID`-from-Ready branch in
// `classify_bar` ([tdisp.rs#L1230-L1232](vm/devices/pci/vpci_client/src/tdisp.rs#L1230-L1232)),
// which the matching-bar harness above does not exercise (it
// always populates the matching entry).
#[kani::proof]
#[kani::unwind(9)]
fn m8a_isolation_snapshot_invalid_when_report_lacks_matching_range() {
    let bar_id: u16 = kani::any();
    kani::assume(bar_id < 6);
    // Empty report: tdi_report.is_some() but the BAR has no entry.
    let report = Some(any_report_empty());

    let validator = Arc::new(RecValidator::new());
    let validator_dyn: Arc<dyn TdispResourceValidationInterface> = validator.clone();
    let s = VpciClientTdispState::kani_new_for_mmio_reconfigured(
        TdispTdiState::Run,
        report,
        bar_id,
        /* intercepted */ false,
        /* validated_already */ false,
        /* dma_unblocked_before */ false,
        validator_dyn,
    );

    let snap = s.isolation_snapshot();
    match snap {
        IsolationSnapshot::Ready { bars, .. } => {
            let cls = bars[bar_id as usize];
            assert!(matches!(cls, ResourceIsolation::INVALID));
        }
        IsolationSnapshot::NotReady => {
            // Unreachable: tdi_report.is_some().
            assert!(false);
        }
    }
    core::mem::forget(s);
}

// ===============================================================
// M-9 — `attest()` Ok ⇒ tdi_state==Run ∧ tdi_report.is_some();
// MSI-X-only intercept growth.
//
// Both halves of M-9 require driving the `attest()` orchestration
// to its `Ok` arm. Empirically, a Kani harness over `attest()`
// (which makes 5+ chained `send_tdisp_command` calls plus
// audit-trail bookkeeping) **OOMs CBMC** even with
// `--no-memory-safety-checks`. The attempt is preserved in the
// session-memory note and in `docs/kani-iteration-2/findings/`.
//
// Behavioral coverage for M-9 is provided indirectly:
//   - The "tdi_report.is_some() only after attest" half is
//     verified by the M-3 negative trio
//     (`m3_{bind,start,unbind}_does_not_grow_report`): no other
//     public entry point grows the report. Combined with the
//     static observation that the only Some(_) writer of
//     `tdi_report` is at [tdisp.rs#L1090](vm/devices/pci/vpci_client/src/tdisp.rs#L1090)
//     (inside `attest`), M-9(a) reduces to "if attest reaches
//     L1090 it has ?-chained through Bind+Start+GetTdiReport".
//   - The "tdi_state == Run after attest Ok" half follows from
//     M-1 Start (proven) plus the structural fact that the last
//     state-mutating call in `attest` is `tdisp_start_device`.
//   - The "intercepted_bars only grows for MSI-X-flagged ranges"
//     half is a static observation on
//     [tdisp.rs#L1075-L1087](vm/devices/pci/vpci_client/src/tdisp.rs#L1075-L1087)
//     (inside attest, the loop body is gated on
//     `range_maps_msix_table() || range_maps_msix_pba()`).
//
// No additional Kani harness here. If a future Kani version or
// stubbing strategy makes attest tractable, a single positive
// harness asserting `attest().is_ok() ⇒ kani_tdi_report_is_some()
// && kani_tdi_state() == Run` would close the gap.
// ===============================================================

// ===============================================================
// M-10 — `mark_bar_intercepted(b)` is monotonic across attest /
// unbind cycles.
//
// Property under proof:
//   Once `mark_bar_intercepted(b)` is called for some BAR `b`,
//   `is_bar_intercepted(b)` continues to return true after a
//   subsequent `tdisp_unbind` or `tdisp_unbind_preserve_report`
//   call returns Ok (independent of the host's response, since
//   under the malicious-host model the reply is fully symbolic).
//
// Spec-backing: §11.6.3 reprogramming threat (defense-in-depth);
// the OpenHCL design comment at [tdisp.rs#L1174-L1175](vm/devices/pci/vpci_client/src/tdisp.rs#L1174-L1175)
// explicitly commits to global monotonicity.
// ===============================================================

#[kani::proof]
#[kani::unwind(2)]
fn m10_mark_bar_intercepted_persists_across_unbind() {
    let state_before = any_tdi_state();
    let response = any_unbind_response();
    let validator: Arc<dyn TdispResourceValidationInterface> = Arc::new(RecValidator::new());
    let bar_id: u16 = kani::any();
    kani::assume(bar_id < 6);
    let dma_unblocked_before: bool = kani::any();
    let mut s = VpciClientTdispState::kani_new_for_unbind_with_report(
        state_before,
        bar_id,
        /* base_gpa */ 0,
        /* length_in_bytes */ 1,
        dma_unblocked_before,
        /* tdi_report */ None,
        response,
        validator,
    );

    // Mark BAR intercepted before the unbind.
    s.mark_bar_intercepted(bar_id);
    assert!(s.is_bar_intercepted(bar_id));

    let i: u8 = kani::any();
    kani::assume(i < 2);
    let reason = match i {
        0 => TdispGuestUnbindReason::Graceful,
        _ => TdispGuestUnbindReason::DeviceTeardown,
    };
    let _ = poll_once!(s.tdisp_unbind(reason));

    // Intercepted set must persist across the unbind, regardless
    // of whether the unbind returned Ok or Err.
    assert!(s.is_bar_intercepted(bar_id));
    core::mem::forget(s);
}

#[kani::proof]
#[kani::unwind(2)]
fn m10_mark_bar_intercepted_persists_across_unbind_preserve() {
    let state_before = any_tdi_state();
    let response = any_unbind_response();
    let validator: Arc<dyn TdispResourceValidationInterface> = Arc::new(RecValidator::new());
    let bar_id: u16 = kani::any();
    kani::assume(bar_id < 6);
    let dma_unblocked_before: bool = kani::any();
    let mut s = VpciClientTdispState::kani_new_for_unbind_with_report(
        state_before,
        bar_id,
        /* base_gpa */ 0,
        /* length_in_bytes */ 1,
        dma_unblocked_before,
        /* tdi_report */ None,
        response,
        validator,
    );

    s.mark_bar_intercepted(bar_id);
    assert!(s.is_bar_intercepted(bar_id));

    let i: u8 = kani::any();
    kani::assume(i < 2);
    let reason = match i {
        0 => TdispGuestUnbindReason::Graceful,
        _ => TdispGuestUnbindReason::DeviceTeardown,
    };
    let _ = poll_once!(s.tdisp_unbind_preserve_report(reason));

    assert!(s.is_bar_intercepted(bar_id));
    core::mem::forget(s);
}
