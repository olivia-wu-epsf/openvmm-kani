// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Malicious-host reconciliation of cached TDI state.
//!
//! When the paravisor (acting as a TDISP guest to the untrusted host)
//! issues a TDISP command and receives a [`crate::GuestToHostResponse`],
//! it must decide whether — and to what value — its **cached**
//! [`TdispTdiState`] may be advanced. The host is in the threat model:
//! the response bytes (including the `result` error code and the
//! `tdi_state_after` field) are adversary-controlled.
//!
//! Today, [`vpci_client`](../../../../pci/vpci_client/src/tdisp.rs)
//! advances cached state unconditionally on any recognized
//! `tdi_state_after`, then performs a per-method post-check (e.g.
//! `tdisp_bind_interface` checks that cached state == `Locked`). That
//! ordering means a malicious host can leave the paravisor's cached
//! state in a value the paravisor never asked for (e.g. host returns
//! `Success`+`Run` for a `Bind`; the per-method check bails, but the
//! cached state is now `Run`).
//!
//! [`reconcile_host_claim`](crate::reconcile::reconcile_host_claim)
//! is the pure decision function that closes
//! that gap: given the operation the paravisor sent, the cached state
//! before the call, and the host's claimed `(error_code, state_after)`,
//! it returns either the safe new cached state or a typed rejection.
//! The Kani harness `verify_reconcile_host_claim_safety` (in
//! `src/kani_proofs.rs`, gated on `cfg(kani)`) proves that the
//! function NEVER returns `Ok(new_state)` for a `(state_before,
//! new_state)` pair that the requested operation could not
//! legitimately produce — for any adversarial input.

use tdisp_proto::TdispTdiState;

/// The TDISP operation the paravisor most recently sent to the
/// (untrusted) host. Used by [`reconcile_host_claim`] to decide
/// whether the host's claimed post-state is consistent with the
/// request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParavisorRequestedTdispOp {
    /// `GetDeviceInterfaceInfo` — informational query; never moves the
    /// TDI state machine.
    GetDeviceInterfaceInfo,
    /// `Bind` — legitimate transition is `Unlocked → Locked`.
    Bind,
    /// `StartTdi` — legitimate transition is `Locked → Run`.
    StartTdi,
    /// `GetTdiReport` — never moves the TDI state machine.
    GetTdiReport,
    /// `Unbind` — legitimate post-state is `Unlocked` from any
    /// predecessor (the TDISP spec allows `STOP_INTERFACE` at any
    /// point).
    Unbind,
}

/// Why a host claim was rejected by [`reconcile_host_claim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostClaimRejection {
    /// Host reported a non-Success result. The paravisor must not
    /// advance cached state on a failed operation.
    HostReportedFailure,
    /// Host did not include a recognized `tdi_state_after` (the
    /// integer was outside the [`TdispTdiState`] domain).
    MissingStateAfter,
    /// Host returned a `tdi_state_after` that does not match the
    /// `(predecessor → successor)` transition the requested
    /// operation is supposed to perform.
    StateAfterInconsistentWithRequest,
}

/// Decide what cached [`TdispTdiState`] the paravisor is allowed to
/// remember after sending `requested` to the (untrusted) host and
/// receiving a response with `(host_success, host_state_after)`.
///
/// This is the malicious-host gate for cached TDI state: a host can
/// return any byte sequence, but the paravisor must only advance its
/// cached state to a value consistent with the operation it actually
/// issued.
///
/// # Returns
///
/// - `Ok(new_state)` — safe to advance cached state to `new_state`.
///   The caller may then propagate success up the stack.
/// - `Err(rejection)` — host claim is inconsistent with `requested`.
///   The paravisor MUST NOT mutate cached state from this response,
///   and MUST treat the operation as failed (which in turn drives
///   `tdisp_unbind` to re-block MMIO/DMA before the host gets another
///   chance).
///
/// # Honest-host outcomes
///
/// | `requested`               | Allowed `(state_before → new_state)` |
/// |---------------------------|---------------------------------------|
/// | `Bind`                    | `Unlocked → Locked`                   |
/// | `StartTdi`                | `Locked → Run`                        |
/// | `Unbind`                  | `* → Unlocked`                        |
/// | `GetDeviceInterfaceInfo`  | `s → s` (no transition)               |
/// | `GetTdiReport`            | `s → s` (no transition)               |
pub fn reconcile_host_claim(
    requested: ParavisorRequestedTdispOp,
    state_before: TdispTdiState,
    host_success: bool,
    host_state_after: Option<TdispTdiState>,
) -> core::result::Result<TdispTdiState, HostClaimRejection> {
    if !host_success {
        return Err(HostClaimRejection::HostReportedFailure);
    }

    let claimed = host_state_after.ok_or(HostClaimRejection::MissingStateAfter)?;

    let ok = match requested {
        ParavisorRequestedTdispOp::Bind => {
            state_before == TdispTdiState::Unlocked && claimed == TdispTdiState::Locked
        }
        ParavisorRequestedTdispOp::StartTdi => {
            state_before == TdispTdiState::Locked && claimed == TdispTdiState::Run
        }
        ParavisorRequestedTdispOp::Unbind => claimed == TdispTdiState::Unlocked,
        ParavisorRequestedTdispOp::GetDeviceInterfaceInfo
        | ParavisorRequestedTdispOp::GetTdiReport => claimed == state_before,
    };

    if ok {
        Ok(claimed)
    } else {
        Err(HostClaimRejection::StateAfterInconsistentWithRequest)
    }
}
