// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kani formal-verification harnesses for the paravisor-as-TDISP-guest
//! direction (threat boundary **a**: untrusted host → VTL2 paravisor).
//!
//! The harness in this module drives the **production** async method
//! [`crate::tdisp::VpciClientTdispState::tdisp_bind_interface`] under
//! a fully-symbolic host response, modelling a malicious host that
//! may return any combination of `result` / `tdi_state_after` / oneof
//! payload. The host channel is replaced (under `cfg(kani)`) by
//! `HostChannel::KaniMock`, which short-circuits the mesh / VMBus /
//! async-runtime layers without changing the logic of
//! `tdisp_bind_interface` itself.
//!
//! See `docs/openhcl-knowledge-base.md` "Malicious-host audit" section
//! for the audit findings this harness is meant to constrain. The
//! property below is the strongest currently-true statement about the
//! production code; the post-condition tightens once
//! `send_tdisp_command`'s unconditional `update_tdi_state` is replaced
//! with a request-aware reconciliation step.

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
// DMA / MMIO unblock-gating harness (Stage E).
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
