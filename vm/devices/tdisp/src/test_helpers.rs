// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::TdispHostDeviceInterface;
use crate::TdispHostDeviceTargetEmulator;
use parking_lot::Mutex;
use std::sync::Arc;
use tdisp_proto::TdispDeviceInterfaceInfo;
use tdisp_proto::TdispGuestProtocolType;
use tdisp_proto::TdispReportType;
#[cfg(kani)]
use tdisp_proto::TdispTdiState;

/// Guest protocol that will be negotiated by the mock device.
pub const TDISP_MOCK_GUEST_PROTOCOL: TdispGuestProtocolType = TdispGuestProtocolType::AmdSevTioV1;

/// Device features that will be negotiated by the mock device.
pub const TDISP_MOCK_SUPPORTED_FEATURES: u64 = 0xDEAD;

/// Device ID that will be negotiated by the mock device.
pub const TDISP_MOCK_DEVICE_ID: u64 = 99;

/// Implements the host side of the TDISP interface for the mock NullDevice.
///
/// Not built under Kani: the trait signature uses `crate::Result<T>`,
/// which under `cfg(kani)` is aliased by `err_shim` to a different
/// concrete `Error` type than `anyhow::Error`. This impl is only
/// used by non-Kani tests, so gating it here lets the non-Kani build
/// keep the conventional `anyhow::Result` return type without
/// breaking the Kani build.
#[cfg(not(kani))]
pub struct NullTdispHostInterface {}
#[cfg(not(kani))]
impl TdispHostDeviceInterface for NullTdispHostInterface {
    fn tdisp_negotiate_protocol(
        &mut self,
        _requested_guest_protocol: TdispGuestProtocolType,
    ) -> anyhow::Result<TdispDeviceInterfaceInfo> {
        Ok(TdispDeviceInterfaceInfo {
            guest_protocol_type: TDISP_MOCK_GUEST_PROTOCOL as i32,
            supported_features: TDISP_MOCK_SUPPORTED_FEATURES,
            tdisp_device_id: TDISP_MOCK_DEVICE_ID,
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
        Ok(vec![])
    }
}

/// Implements the host side of the TDISP interface for a mock device that does nothing.
#[cfg(not(kani))]
pub fn new_null_tdisp_interface(debug_device_id: &str) -> TdispHostDeviceTargetEmulator {
    TdispHostDeviceTargetEmulator::new(
        Arc::new(Mutex::new(NullTdispHostInterface {})),
        debug_device_id,
    )
}

/// Symbolic Kani-only host interface.
///
/// Each host callback non-deterministically returns either `Ok(...)`
/// (with a symbolic payload where applicable) or `Err(crate::Error)`.
/// This lets a single Kani harness explore *both* the success and
/// failure branches of every host callback that
/// [`crate::TdispHostStateMachine`] can invoke, without having to
/// author one harness per Ok/Err permutation.
///
/// Construction note: under Kani the trait's error type is the
/// unit-like [`crate::Error`] stub from the `err_shim` module — not
/// `anyhow::Error`. That is the only reason this mock can construct
/// `Err` cheaply; an `anyhow::Error` would drag in
/// `Backtrace::capture` → `getenv` → `memchr_naive`, which CBMC
/// cannot bound (see `.github/skills/model-checking/SKILL.md`,
/// anti-pattern #1).
#[cfg(kani)]
pub struct KaniSymbolicHostInterface {}

#[cfg(kani)]
impl TdispHostDeviceInterface for KaniSymbolicHostInterface {
    fn tdisp_negotiate_protocol(
        &mut self,
        _requested_guest_protocol: TdispGuestProtocolType,
    ) -> crate::Result<TdispDeviceInterfaceInfo> {
        if kani::any() {
            Ok(TdispDeviceInterfaceInfo {
                guest_protocol_type: kani::any(),
                supported_features: kani::any(),
                tdisp_device_id: kani::any(),
            })
        } else {
            Err(crate::Error)
        }
    }

    fn tdisp_bind_device(&mut self) -> crate::Result<()> {
        if kani::any() {
            Ok(())
        } else {
            Err(crate::Error)
        }
    }

    fn tdisp_start_device(&mut self) -> crate::Result<()> {
        if kani::any() {
            Ok(())
        } else {
            Err(crate::Error)
        }
    }

    fn tdisp_unbind_device(&mut self) -> crate::Result<()> {
        if kani::any() {
            Ok(())
        } else {
            Err(crate::Error)
        }
    }

    fn tdisp_get_device_report(&mut self, _report_type: TdispReportType) -> crate::Result<Vec<u8>> {
        // Return an empty `Vec` on success: a symbolic-length `Vec`
        // would force CBMC to unwind allocator/Drop machinery on
        // every reachable path. The proofs that use this mock do not
        // currently inspect report contents.
        if kani::any() {
            Ok(Vec::new())
        } else {
            Err(crate::Error)
        }
    }
}

/// Constructs a fresh [`crate::TdispHostStateMachine`] backed by
/// [`KaniSymbolicHostInterface`], with the internal
/// `current_state` and `guest_protocol_type` initialised to
/// caller-supplied (typically symbolic) values rather than the
/// production defaults of `(Unlocked, Invalid)`. This lets a
/// harness verify properties starting from an unconstrained
/// state-machine state.
#[cfg(kani)]
pub fn new_symbolic_tdisp_state_machine(
    debug_device_id: &str,
    current_state: TdispTdiState,
    guest_protocol_type: TdispGuestProtocolType,
) -> crate::TdispHostStateMachine {
    let mut sm =
        crate::TdispHostStateMachine::new(Arc::new(Mutex::new(KaniSymbolicHostInterface {})));
    sm.set_debug_device_id(debug_device_id.to_owned());
    sm.kani_set_internal_state(current_state, guest_protocol_type);
    sm
}

/// Returns a fully-symbolic [`TdispTdiState`] suitable for
/// initialising a Kani harness. CBMC explores all four protobuf
/// variants (`Uninitialized`, `Unlocked`, `Locked`, `Run`).
#[cfg(kani)]
pub fn any_tdi_state() -> TdispTdiState {
    match kani::any::<u8>() % 4 {
        0 => TdispTdiState::Uninitialized,
        1 => TdispTdiState::Unlocked,
        2 => TdispTdiState::Locked,
        _ => TdispTdiState::Run,
    }
}

/// Returns a fully-symbolic [`TdispGuestProtocolType`] suitable for
/// initialising a Kani harness. CBMC explores all three protobuf
/// variants (`Invalid`, `AmdSevTioV1`, `IntelTdxConnectV1`).
#[cfg(kani)]
pub fn any_guest_protocol_type() -> TdispGuestProtocolType {
    match kani::any::<u8>() % 3 {
        0 => TdispGuestProtocolType::Invalid,
        1 => TdispGuestProtocolType::AmdSevTioV1,
        _ => TdispGuestProtocolType::IntelTdxConnectV1,
    }
}

/// Returns a fully-symbolic `Option<TdispTdiState>`, modelling the
/// `tdi_state_after_enum()` return shape on a host response: `None`
/// represents an unrecognized integer (host returned a value outside
/// the [`TdispTdiState`] domain), `Some(state)` represents one of the
/// four known variants.
#[cfg(kani)]
pub fn any_optional_tdi_state() -> Option<TdispTdiState> {
    if kani::any() {
        Some(any_tdi_state())
    } else {
        None
    }
}

/// Returns a fully-symbolic
/// [`crate::reconcile::ParavisorRequestedTdispOp`] suitable for
/// initialising a Kani harness. CBMC explores all five variants.
#[cfg(kani)]
pub fn any_requested_op() -> crate::reconcile::ParavisorRequestedTdispOp {
    use crate::reconcile::ParavisorRequestedTdispOp;
    match kani::any::<u8>() % 5 {
        0 => ParavisorRequestedTdispOp::GetDeviceInterfaceInfo,
        1 => ParavisorRequestedTdispOp::Bind,
        2 => ParavisorRequestedTdispOp::StartTdi,
        3 => ParavisorRequestedTdispOp::GetTdiReport,
        _ => ParavisorRequestedTdispOp::Unbind,
    }
}
