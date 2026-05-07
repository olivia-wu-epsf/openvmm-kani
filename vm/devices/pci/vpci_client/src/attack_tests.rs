// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bug-demonstration tests for TDISP-001..008.
//!
//! Each test reproduces the attack scenario from the matching bug
//! report under `docs/bugs/tdisp-bug-NNN-*.md` using a tiny mock VPCI
//! host that returns attacker-controlled responses to TDISP commands.
//!
//! Each test asserts the **secure** outcome that the matching security
//! property in `docs/tdisp-paravisor-security-properties.md` demands
//! (e.g. "`tdisp_unbind` must reject a host claim of state-after ==
//! Run"). Today these properties are violated, so each test
//! **currently fails** when run — the failure *is* the demonstration
//! of the attack. When a bug is fixed, the corresponding test should
//! flip from failing to passing with no changes to the test body.
//!
//! For the bugs whose attack surface depends on API the codebase does
//! not yet have (TDISP-001 oracle hash, TDISP-003 lock-epoch nonce),
//! the test is a `#[ignore]`-gated stub with a TODO pointing at the
//! property that must first land.
//!
//! ## Mapping to bugs and security properties
//!
//! See `docs/tdisp-paravisor-security-properties.md` for the property
//! definitions referenced in the table below.
//!
//! | Bug       | Property | Test fn                                                          |
//! | --------- | -------- | ---------------------------------------------------------------- |
//! | TDISP-001 | F-3      | `attack_v1_report_hash_unchecked` (stub, needs API)              |
//! | TDISP-002 | F-2/F-17 | `attack_attest_starts_tdi_before_fetching_report`                |
//! | TDISP-003 | F-4      | `attack_lock_replay_no_nonce` (stub, needs API)                  |
//! | TDISP-004 | F-2      | `attack_start_device_accepts_undecodable_state_after`            |
//! | TDISP-005 | F-2      | `attack_unbind_accepts_run_state_after`                          |
//! | TDISP-006 | F-2      | `attack_get_device_report_runs_in_uninitialized_state`           |
//! | TDISP-007 | F-6      | `attack_mmio_reconfigured_uses_lying_caller_range`               |
//! | TDISP-008 | F-11     | `attack_isolation_snapshot_ready_when_not_in_run`                |

#![cfg(test)]

use crate::WorkerRequest;
use crate::tdisp::IsolationSnapshot;
use crate::tdisp::VpciClientTdispState;
use futures::StreamExt;
use openhcl_tdisp::GuestToHostResponse;
use openhcl_tdisp::GuestToHostResponseVariantOneof as Response;
use openhcl_tdisp::TdispCommandResponseGetTdiReport;
use openhcl_tdisp::TdispCommandResponseStartTdi;
use openhcl_tdisp::TdispCommandResponseUnbind;
use openhcl_tdisp::TdispGuestUnbindReason;
use openhcl_tdisp::TdispReportType;
use openhcl_tdisp::mocks::TdispNoopResourceValidator;
use pal_async::DefaultDriver;
use pal_async::async_test;
use pal_async::task::Spawn;
use pal_async::task::Task;
use std::sync::Arc;
use tdisp::Command;
use tdisp::TdispTdiState;
use tdisp::devicereport::TdiReportStruct;
use tdisp::devicereport::TdispTdiReportInterfaceInfo;
use tdisp::devicereport::TdispTdiReportMmioFlags;
use tdisp::devicereport::TdispTdiReportMmioInterfaceInfo;
use test_with_tracing::test;

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/// Spawn a tiny mock VPCI worker that replies to each incoming
/// `WorkerRequest::TdispCommand` with the next canned
/// `GuestToHostResponse` from `responses`. Panics if the production
/// code issues more TDISP commands than the test prepared responses
/// for (which would mean the test does not faithfully model the
/// attack).
fn spawn_mock_host(
    driver: &DefaultDriver,
    mut responses: Vec<GuestToHostResponse>,
) -> (mesh::Sender<WorkerRequest>, Task<()>) {
    let (worker_req, mut worker_recv) = mesh::channel::<WorkerRequest>();
    responses.reverse();
    let task = driver.spawn("mock-vpci-host", async move {
        while let Some(req) = worker_recv.next().await {
            match req {
                WorkerRequest::TdispCommand(rpc) => {
                    let (_input, reply) = rpc.split();
                    let resp = responses
                        .pop()
                        .expect("mock host ran out of canned TDISP responses");
                    reply.complete(Ok(resp));
                }
                // Other request variants are not exercised by these tests.
                _ => {}
            }
        }
    });
    (worker_req, task)
}

/// Build a [`GuestToHostResponse`] with the given fields. Centralised
/// so each attack scenario reads as "host returns Success +
/// `<state-after>` + `<payload>`".
fn host_response(
    result: openhcl_tdisp::TdispGuestOperationErrorCode,
    state_before: TdispTdiState,
    state_after_int: i32,
    payload: Option<Response>,
) -> GuestToHostResponse {
    GuestToHostResponse {
        result: result as i32,
        tdi_state_before: state_before as i32,
        tdi_state_after: state_after_int,
        response: payload,
    }
}

/// Build a minimal [`TdiReportStruct`] containing a single TEE MMIO
/// range with the given `range_id`, `first_4k_page_offset`, and
/// `num_4k_pages`. The page-offset / page-count fields are how the
/// host is *supposed* to express the BAR's containment box; the bug
/// in TDISP-007 is that `tdisp_on_mmio_reconfigured` ignores them.
fn report_with_one_tee_range(
    range_id: u16,
    first_4k_page_offset: u32,
    num_4k_pages: u32,
) -> TdiReportStruct {
    TdiReportStruct {
        interface_info: TdispTdiReportInterfaceInfo::new(),
        msi_x_message_control: 0,
        lnr_control: 0,
        tph_control: 0,
        mmio_interface_info: vec![TdispTdiReportMmioInterfaceInfo {
            first_4k_page_offset: first_4k_page_offset.into(),
            num_4k_pages,
            flags: TdispTdiReportMmioFlags::new().with_is_non_tee_mem(false),
            range_id,
        }],
    }
}

// ----------------------------------------------------------------------------
// TDISP-001: missing V1 report-hash check (F-3).
// ----------------------------------------------------------------------------

/// **STUB.** TDISP-001 alleges that the V1 protocol's hash of the
/// device report measurement is never verified before the report is
/// trusted. Demonstrating this attack requires API the codebase does
/// not yet have:
///
/// * a `verified: bool` flag on the cached report (so we can observe
///   whether the paravisor consulted the oracle), and
/// * a hash-comparison oracle injected into
///   `VpciClientTdispState`.
///
/// Once F-3's prerequisites (see
/// `docs/tdisp-paravisor-security-properties.md`) land, replace this
/// stub with a test that supplies a tampered report bytes plus a
/// matching expected-hash oracle and asserts that
/// `tdisp_get_tdi_report` rejects the mismatch.
#[ignore = "TDISP-001: needs verified-flag + hash oracle (F-3 prerequisites)"]
#[test]
fn attack_v1_report_hash_unchecked() {
    panic!(
        "TODO: implement once F-3 prerequisites land (verified flag + hash \
         oracle). See docs/bugs/tdisp-bug-001-*.md and \
         docs/tdisp-paravisor-security-properties.md F-3."
    );
}

// ----------------------------------------------------------------------------
// TDISP-002: `attest_device` issues StartTdi before GetTdiReport
// (F-2 / F-17). Concrete observation: the worker receives the
// StartTdi command (which transitions the TDI to RUN) before it ever
// receives the GetTdiReport(InterfaceReport) command — so the
// paravisor's measurement of the TDI is taken *after* the device has
// already been started, defeating the binding of the running TDI to
// a measured identity.
// ----------------------------------------------------------------------------

#[async_test]
async fn attack_attest_starts_tdi_before_fetching_report(driver: DefaultDriver) {
    use std::sync::Mutex;

    let observed: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_inner = observed.clone();

    let (worker_req, mut worker_recv) = mesh::channel::<WorkerRequest>();
    let _server: Task<()> = driver.spawn("mock-vpci-host", async move {
        while let Some(req) = worker_recv.next().await {
            if let WorkerRequest::TdispCommand(rpc) = req {
                let (input, reply) = rpc.split();
                // Decode the wire payload to see which command this is.
                let decoded = openhcl_tdisp::deserialize_command(input.data.as_slice());
                let cmd_variant = decoded.ok().and_then(|c| c.command);
                let (label, response): (&'static str, GuestToHostResponse) = match cmd_variant {
                    Some(Command::Bind(_)) => (
                        "Bind",
                        host_response(
                            openhcl_tdisp::TdispGuestOperationErrorCode::Success,
                            TdispTdiState::Unlocked,
                            TdispTdiState::Locked as i32,
                            Some(Response::Bind(openhcl_tdisp::TdispCommandResponseBind {})),
                        ),
                    ),
                    Some(Command::StartTdi(_)) => (
                        "StartTdi",
                        host_response(
                            openhcl_tdisp::TdispGuestOperationErrorCode::Success,
                            TdispTdiState::Locked,
                            TdispTdiState::Run as i32,
                            Some(Response::StartTdi(TdispCommandResponseStartTdi {})),
                        ),
                    ),
                    Some(Command::GetTdiReport(g)) => {
                        let label = if g.report_type == TdispReportType::GuestDeviceId as i32 {
                            "GetTdiReport(GuestDeviceId)"
                        } else if g.report_type == TdispReportType::InterfaceReport as i32 {
                            "GetTdiReport(InterfaceReport)"
                        } else {
                            "GetTdiReport(other)"
                        };
                        // Return an 8-byte buffer for GuestDeviceId so the
                        // caller's u64 conversion succeeds; for the
                        // interface report any buffer suffices because the
                        // caller's deserialize is allowed to fail (we only
                        // care about the call ORDER, not the result).
                        let buf = if g.report_type == TdispReportType::GuestDeviceId as i32 {
                            vec![0u8; 8]
                        } else {
                            Vec::new()
                        };
                        (
                            label,
                            host_response(
                                openhcl_tdisp::TdispGuestOperationErrorCode::Success,
                                TdispTdiState::Run,
                                TdispTdiState::Run as i32,
                                Some(Response::GetTdiReport(TdispCommandResponseGetTdiReport {
                                    report_type: g.report_type,
                                    report_buffer: buf,
                                })),
                            ),
                        )
                    }
                    _ => (
                        "Other",
                        host_response(
                            openhcl_tdisp::TdispGuestOperationErrorCode::Success,
                            TdispTdiState::Uninitialized,
                            TdispTdiState::Uninitialized as i32,
                            None,
                        ),
                    ),
                };
                observed_inner.lock().unwrap().push(label);
                reply.complete(Ok(response));
            }
        }
    });

    // Drive the production attestation orchestration.
    let validator = Arc::new(TdispNoopResourceValidator::new());
    let mut state = VpciClientTdispState::test_new_with_state(
        worker_req,
        Some(validator.clone()),
        TdispTdiState::Unlocked,
        None,
        Vec::new(),
        false,
    );

    // Drive the same call sequence that `VpciDevice::attest()` performs.
    // We invoke the inherent methods directly so the test does not need
    // a full `VpciDevice`.
    let _ = state.tdisp_bind_interface().await;
    let _ = state.tdisp_start_device().await;
    let _ = state.tdisp_get_tdi_device_id().await;
    let _ = state.tdisp_get_tdi_report().await;

    // Secure assertion (currently FAILS, demonstrating TDISP-002):
    // the paravisor must fetch and verify the InterfaceReport BEFORE
    // sending StartTdi, so a measurement of the device under test is
    // bound to the device that actually starts running. The fix
    // satisfies F-2/F-17 of `tdisp-paravisor-security-properties.md`.
    let log = observed.lock().unwrap().clone();
    let start_idx = log.iter().position(|s| *s == "StartTdi");
    let report_idx = log
        .iter()
        .position(|s| *s == "GetTdiReport(InterfaceReport)");
    match (start_idx, report_idx) {
        (Some(s), Some(r)) => {
            assert!(
                r < s,
                "TDISP-002: GetTdiReport(InterfaceReport) at index {r} \
                 was issued AFTER StartTdi at index {s}. The TDI is \
                 measured only after it has already started running. \
                 Observed: {log:?}",
            );
        }
        _ => panic!("test never observed both StartTdi and GetTdiReport: {log:?}"),
    }
}

// ----------------------------------------------------------------------------
// TDISP-003: lock-epoch nonce missing (F-4).
// ----------------------------------------------------------------------------

/// **STUB.** TDISP-003 alleges that there is no lock-epoch nonce
/// binding LOCK to subsequent operations, so the host can replay an
/// older LOCK reply. Demonstrating this attack requires a `lock_epoch`
/// nonce field on `VpciClientTdispMutableState` and on the
/// guest-issued LOCK command — neither exists today.
///
/// Once F-4's prerequisites land, replace this stub with a test that
/// (a) drives one full LOCK / BIND, (b) drives a second LOCK that
/// rotates the nonce, then (c) attempts to use a host reply that
/// carries the original nonce and asserts that the paravisor rejects
/// it.
#[ignore = "TDISP-003: needs lock_epoch nonce field (F-4 prerequisite)"]
#[test]
fn attack_lock_replay_no_nonce() {
    panic!(
        "TODO: implement once F-4 prerequisite lands (lock_epoch nonce). \
         See docs/bugs/tdisp-bug-003-*.md and \
         docs/tdisp-paravisor-security-properties.md F-4."
    );
}

// ----------------------------------------------------------------------------
// TDISP-004: `tdisp_start_device` post-check accepts an undecodable
// `tdi_state_after` so long as the cached state is already RUN (F-2 /
// AF-1).
// ----------------------------------------------------------------------------

#[async_test]
async fn attack_start_device_accepts_undecodable_state_after(driver: DefaultDriver) {
    // Host returns Success + an out-of-range `tdi_state_after`
    // (-1 decodes to None) + the matching StartTdi payload. The
    // `update_tdi_state` call sees `None` and leaves the cached
    // `tdi_state` untouched at its prior value RUN — and the post-
    // check then accepts on the basis of the prior cached value
    // rather than on a fresh host claim.
    let response = host_response(
        openhcl_tdisp::TdispGuestOperationErrorCode::Success,
        TdispTdiState::Run,
        i32::MIN, // undecodable
        Some(Response::StartTdi(TdispCommandResponseStartTdi {})),
    );
    let (worker_req, _server) = spawn_mock_host(&driver, vec![response]);
    let mut state = VpciClientTdispState::test_new_with_state(
        worker_req,
        None,
        TdispTdiState::Run, // prior cached state
        None,
        Vec::new(),
        false,
    );

    let result = state.tdisp_start_device().await;
    // Secure assertion (currently FAILS, demonstrating TDISP-004):
    // when the host's response carries an undecodable
    // `tdi_state_after`, `tdisp_start_device` must reject rather than
    // silently fall back to the prior cached state. F-2 of
    // `tdisp-paravisor-security-properties.md`.
    assert!(
        result.is_err(),
        "TDISP-004: tdisp_start_device returned {result:?} \
         despite the host never claiming the TDI is in Run state \
         (tdi_state_after was undecodable). The post-check is \
         silently falling back to the prior cached state."
    );
}

// ----------------------------------------------------------------------------
// TDISP-005: `tdisp_unbind` returns Ok when the host claims state
// after == RUN (F-2 / AF-2). The cached state is left at RUN, so a
// follow-up `isolation_snapshot()` (after a `preserve_report` unbind)
// would still report Ready.
// ----------------------------------------------------------------------------

#[async_test]
async fn attack_unbind_accepts_run_state_after(driver: DefaultDriver) {
    let response = host_response(
        openhcl_tdisp::TdispGuestOperationErrorCode::Success,
        TdispTdiState::Run,
        TdispTdiState::Run as i32, // host *claims* the TDI is still RUN
        Some(Response::Unbind(TdispCommandResponseUnbind {})),
    );
    let (worker_req, _server) = spawn_mock_host(&driver, vec![response]);
    let validator = Arc::new(TdispNoopResourceValidator::new());
    let mut state = VpciClientTdispState::test_new_with_state(
        worker_req,
        Some(validator.clone()),
        TdispTdiState::Run, // prior cached state
        None,
        // Pre-populate one validated MMIO BAR so the unbind path has
        // something to re-block (matches a typical post-attest state).
        vec![(0u16, 0xF000_0000u64, 0x1000u32)],
        true,
    );

    let result = state.tdisp_unbind(TdispGuestUnbindReason::Graceful).await;
    // Secure assertion (currently FAILS, demonstrating TDISP-005):
    // when the host claims the TDI is still in Run after an Unbind,
    // `tdisp_unbind` must reject. Allowing it leaves the cached
    // `tdi_state == Run`, so a subsequent `isolation_snapshot()` would
    // (per F-11) still report Ready even though the device has not
    // actually unbound. F-2 of
    // `tdisp-paravisor-security-properties.md`.
    assert!(
        result.is_err(),
        "TDISP-005: tdisp_unbind returned {result:?} when host \
         claimed state-after == Run. The method must reject any \
         state-after != Unlocked|Uninitialized after Unbind."
    );
    assert_ne!(
        state.test_tdi_state(),
        TdispTdiState::Run,
        "TDISP-005: after a 'failed' unbind, the cached tdi_state is \
         still Run. The paravisor accepted the host's claim that the \
         TDI never actually unbound."
    );
}

// ----------------------------------------------------------------------------
// TDISP-006: `tdisp_get_device_report` has no precondition on the
// cached `tdi_state` — it will issue the command and return whatever
// buffer the host sends, even from `Uninitialized` (F-2 / AF-3).
// ----------------------------------------------------------------------------

#[async_test]
async fn attack_get_device_report_runs_in_uninitialized_state(driver: DefaultDriver) {
    let attacker_buffer: Vec<u8> = b"ATTACKER-CONTROLLED-BYTES".to_vec();
    let response = host_response(
        openhcl_tdisp::TdispGuestOperationErrorCode::Success,
        TdispTdiState::Uninitialized,
        TdispTdiState::Uninitialized as i32,
        Some(Response::GetTdiReport(TdispCommandResponseGetTdiReport {
            report_type: TdispReportType::InterfaceReport as i32,
            report_buffer: attacker_buffer.clone(),
        })),
    );
    let (worker_req, _server) = spawn_mock_host(&driver, vec![response]);
    let mut state = VpciClientTdispState::test_new_with_state(
        worker_req,
        None,
        TdispTdiState::Uninitialized, // no Bind, no Lock — cache is fresh
        None,
        Vec::new(),
        false,
    );

    let result = state
        .tdisp_get_device_report(&TdispReportType::InterfaceReport)
        .await;
    // Secure assertion (currently FAILS, demonstrating TDISP-006):
    // `tdisp_get_device_report` must refuse to issue the command —
    // and certainly must not propagate the host's buffer back to the
    // caller — when the cached `tdi_state` is Uninitialized (no Bind,
    // no Lock). F-2 of `tdisp-paravisor-security-properties.md`.
    assert!(
        result.is_err(),
        "TDISP-006: tdisp_get_device_report returned Ok({len} bytes) \
         despite the TDI being in Uninitialized state. The method has \
         no cached-state precondition, so the host can supply an \
         attacker-controlled report at any time.",
        len = result.as_ref().map(|b: &Vec<u8>| b.len()).unwrap_or(0),
    );
}

// ----------------------------------------------------------------------------
// TDISP-007: `tdisp_on_mmio_reconfigured` does not check that the
// guest-supplied (base, length) is contained within the report's
// declared MMIO range for that BAR (F-6 / CHECK-4 + CHECK-5). The
// paravisor calls `tdisp_unblock_mmio` with the LYING (base, length)
// rather than the report-declared one.
// ----------------------------------------------------------------------------

#[test]
fn attack_mmio_reconfigured_uses_lying_caller_range() {
    let validator = Arc::new(TdispNoopResourceValidator::new());

    // Build a TDI report saying BAR 0 covers exactly one 4K page
    // starting at offset 0 (so 0..0x1000 within whatever the report's
    // base is — the report itself does not even carry an absolute
    // base; the production code today just trusts the caller's).
    let report = report_with_one_tee_range(/*range_id=*/ 0, 0, 1);

    // Need a dangling worker sender to satisfy the constructor; the
    // sync MMIO-reconfigured path never uses it.
    let (worker_req, _worker_recv) = mesh::channel::<WorkerRequest>();
    let mut state = VpciClientTdispState::test_new_with_state(
        worker_req,
        Some(validator.clone()),
        TdispTdiState::Run,
        Some(report),
        Vec::new(),
        false,
    );

    // The guest "reconfigures" BAR 0 to a wildly different, much
    // larger range than the report describes (one 4K page).
    let lying_base: u64 = 0xDEAD_0000;
    let lying_length: u32 = 0x10_0000; // 1 MiB, vs report's 4 KiB.
    state
        .tdisp_on_mmio_reconfigured(0, lying_base, lying_length)
        .expect("tdisp_on_mmio_reconfigured returned Err in attack scenario");

    // Secure assertion (currently FAILS, demonstrating TDISP-007):
    // the validator must NOT have been called with the
    // attacker-supplied (base, length). F-6 (CHECK-4 + CHECK-5) of
    // `tdisp-paravisor-security-properties.md` requires the paravisor
    // to (a) reject the call, or (b) substitute the report-declared
    // range, when the caller's range is not contained within the
    // report's declared MMIO range for that BAR.
    let calls = validator.unblocked_mmio_ranges();
    assert!(
        !calls.iter().any(|r| r.base_gpa == lying_base
            && r.length_in_bytes == lying_length
            && r.range_id == 0),
        "TDISP-007: validator was called with the LYING range \
         (base=0x{lying_base:x}, length=0x{lying_length:x}); recorded \
         calls: {calls:?}. The report only describes a 4 KiB range \
         starting at offset 0, so this call should have been refused \
         or substituted."
    );
}

// ----------------------------------------------------------------------------
// TDISP-008: `isolation_snapshot()` returns Ready solely on the basis
// of "a TDI report has been cached", without checking that the cached
// `tdi_state` is RUN (F-11). After `tdisp_unbind_preserve_report`, or
// while still in Locked, the snapshot still claims Ready.
// ----------------------------------------------------------------------------

#[test]
fn attack_isolation_snapshot_ready_when_not_in_run() {
    // Need a dangling worker sender; isolation_snapshot is sync and
    // touches no I/O.
    let (worker_req, _worker_recv) = mesh::channel::<WorkerRequest>();
    let report = report_with_one_tee_range(0, 0, 1);
    let state = VpciClientTdispState::test_new_with_state(
        worker_req,
        None,
        // Cache says we're NOT in Run — say, after preserve-report
        // unbind dropped us back to Unlocked. The snapshot must NOT
        // claim Ready in this state.
        TdispTdiState::Unlocked,
        Some(report),
        Vec::new(),
        false,
    );

    let snap = state.isolation_snapshot();
    // Secure assertion (currently FAILS, demonstrating TDISP-008):
    // F-11 of `tdisp-paravisor-security-properties.md` requires that
    // `isolation_snapshot()` only returns `Ready` when the cached
    // `tdi_state == Run`. Today it returns `Ready` whenever a report
    // is cached, regardless of the state — so a stale cache after
    // `tdisp_unbind_preserve_report` (or while in Locked) will
    // incorrectly advertise the device as isolated.
    assert!(
        matches!(snap, IsolationSnapshot::NotReady),
        "TDISP-008: isolation_snapshot returned {snap:?} in Unlocked \
         state — must be NotReady when tdi_state != Run."
    );
}
