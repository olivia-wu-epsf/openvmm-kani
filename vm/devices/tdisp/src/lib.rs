// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![forbid(unsafe_code)]

//!
//! TDISP is a standardized interface for end-to-end encryption and attestation
//! of trusted assigned devices to confidential/isolated partitions. This crate
//! implements structures and interfaces for the host and guest to prepare and
//! assign trusted devices. Examples of technologies that implement TDISP
//! include:
//! - Intel® TDX Connect
//! - AMD® SEV-TIO
//!
//! This crate is primarily used to implement the host side of the guest-to-host
//! interface for TDISP as well as the serialization of guest-to-host commands for both
//! the host and HCL.
//!
//! These structures and interfaces are used by the host virtualization stack
//! to prepare and assign trusted devices to guest partitions.
//!
//! The host is responsible for dispatching guest commands to this machinery by
//! creating a [`TdispHostDeviceTargetEmulator`] and calling through appropriate
//! trait methods to pass guest commands received from the guest to the emulator.
//!
//! This crate will handle incoming guest message structs and manage the state transitions
//! of the TDISP device and ensure valid transitions are made. Once a valid transition is made, the
//! [`TdispHostDeviceTargetEmulator`] will call back into the host through the
//! [`TdispHostDeviceInterface`] trait to allow the host to perform platform actions
//! such as binding the device to a guest partition or retrieving attestation reports.
//! It is the responsibility of the host to provide a [`TdispHostDeviceInterface`]
//! implementation that performs the necessary platform actions.

/// Protobuf serialization of guest commands and responses.
pub mod serialize_proto;

/// Serialization code from PCI standard structures reported from the TDISP device directly.
pub mod devicereport;

#[cfg(test)]
mod tests;

/// Mocks for the host interface and the emulator.
pub mod test_helpers;

#[cfg(kani)]
mod kani_proofs;

use anyhow::Context;
use parking_lot::Mutex;
use std::sync::Arc;
pub use tdisp_proto::GuestToHostCommand;
pub use tdisp_proto::GuestToHostCommandExt;
pub use tdisp_proto::GuestToHostResponse;
pub use tdisp_proto::GuestToHostResponseExt;
pub use tdisp_proto::TdispCommandResponseBind;
pub use tdisp_proto::TdispCommandResponseGetDeviceInterfaceInfo;
pub use tdisp_proto::TdispCommandResponseGetTdiReport;
pub use tdisp_proto::TdispCommandResponseStartTdi;
pub use tdisp_proto::TdispCommandResponseUnbind;
pub use tdisp_proto::TdispDeviceInterfaceInfo;
pub use tdisp_proto::TdispGuestOperationError;
pub use tdisp_proto::TdispGuestOperationErrorCode;
pub use tdisp_proto::TdispGuestProtocolType;
pub use tdisp_proto::TdispGuestUnbindReason;
pub use tdisp_proto::TdispReportType;
pub use tdisp_proto::TdispTdiState;
pub use tdisp_proto::guest_to_host_command::Command;
pub use tdisp_proto::guest_to_host_response::Response;

use tracing::instrument;

/// Callback for receiving TDISP commands from the guest.
pub type TdispCommandCallback = dyn Fn(&GuestToHostCommand) -> anyhow::Result<()> + Send + Sync;

/// Describes the interface that host software should implement to provide TDISP
/// functionality for a device. These interfaces might dispatch to a physical
/// device, or might be implemented by a software emulator.
pub trait TdispHostDeviceInterface: Send + Sync {
    /// Request versioning and protocol negotiation from the host.
    fn tdisp_negotiate_protocol(
        &mut self,
        _requested_guest_protocol: TdispGuestProtocolType,
    ) -> anyhow::Result<TdispDeviceInterfaceInfo>;

    /// Bind a tdi device to the current partition. Transitions device to the Locked
    /// state from Unlocked.
    fn tdisp_bind_device(&mut self) -> anyhow::Result<()>;

    /// Start a bound device by transitioning it to the Run state from the Locked state.
    /// This allows attestation and resources to be accepted into the guest context.
    fn tdisp_start_device(&mut self) -> anyhow::Result<()>;

    /// Unbind a tdi device from the current partition.
    fn tdisp_unbind_device(&mut self) -> anyhow::Result<()>;

    /// Get a device interface report for the device.
    fn tdisp_get_device_report(&mut self, _report_type: TdispReportType)
    -> anyhow::Result<Vec<u8>>;
}

/// Trait added to host virtual devices to dispatch TDISP commands from guests.
pub trait TdispHostDeviceTarget: Send + Sync {
    /// Dispatch a TDISP command from a guest.
    fn tdisp_handle_guest_command(
        &mut self,
        _command: GuestToHostCommand,
    ) -> anyhow::Result<GuestToHostResponse>;
}

/// An emulator which runs the TDISP state machine for a synthetic device.
pub struct TdispHostDeviceTargetEmulator {
    machine: TdispHostStateMachine,
    debug_device_id: String,
}

impl TdispHostDeviceTargetEmulator {
    /// Create a new emulator which runs the TDISP state machine for a synthetic device.
    pub fn new(
        host_interface: Arc<Mutex<dyn TdispHostDeviceInterface>>,
        debug_device_id: &str,
    ) -> Self {
        Self {
            machine: TdispHostStateMachine::new(host_interface),
            debug_device_id: debug_device_id.to_owned(),
        }
    }

    /// Set the debug device ID string.
    pub fn set_debug_device_id(&mut self, debug_device_id: &str) {
        self.machine.set_debug_device_id(debug_device_id.to_owned());
        self.debug_device_id = debug_device_id.to_owned();
    }

    /// Reset the emulator.
    pub fn reset(&self) {}
}

impl TdispHostDeviceTarget for TdispHostDeviceTargetEmulator {
    /// Main entry point for handling a guest command sent to the host.
    /// Dispatches relevant trait interface methods to handle the command.
    /// Formats and returns a response packet.
    #[instrument(fields(device_id = %self.debug_device_id), skip(self))]
    fn tdisp_handle_guest_command(
        &mut self,
        command: GuestToHostCommand,
    ) -> anyhow::Result<GuestToHostResponse> {
        let mut error = TdispGuestOperationError::Success;
        let mut response: Option<Response> = None;
        let state_before = self.machine.state();
        match &command.command {
            Some(Command::GetDeviceInterfaceInfo(req)) => {
                let protocol_type = TdispGuestProtocolType::from_i32(req.guest_protocol_type);

                match protocol_type {
                    Some(protocol_type) => {
                        let interface_info = self.machine.tdisp_negotiate_protocol(protocol_type);
                        match interface_info {
                            Ok(interface_info) => {
                                response = Some(Response::GetDeviceInterfaceInfo(
                                    TdispCommandResponseGetDeviceInterfaceInfo {
                                        interface_info: Some(interface_info),
                                    },
                                ));
                            }
                            Err(err) => {
                                error = err;
                            }
                        }
                    }
                    None => {
                        error = TdispGuestOperationError::InvalidGuestProtocolRequest;
                    }
                }
            }
            Some(Command::Bind(_)) => {
                let bind_res = self.machine.request_lock_device_resources();
                if let Err(err) = bind_res {
                    error = err;
                } else {
                    response = Some(Response::Bind(TdispCommandResponseBind {}));
                }
            }
            Some(Command::StartTdi(_)) => {
                let start_tdi_res = self.machine.request_start_tdi();
                if let Err(err) = start_tdi_res {
                    error = err;
                } else {
                    response = Some(Response::StartTdi(TdispCommandResponseStartTdi {}));
                }
            }
            Some(Command::Unbind(cmd)) => {
                let unbind_reason = TdispGuestUnbindReason::from_i32(cmd.unbind_reason);

                match unbind_reason {
                    Some(reason) => {
                        let unbind_res = self.machine.request_unbind(reason);
                        if let Err(err) = unbind_res {
                            error = err;
                        }
                        response = Some(Response::Unbind(TdispCommandResponseUnbind {}));
                    }
                    None => {
                        error = TdispGuestOperationError::InvalidGuestUnbindReason;
                    }
                }
            }
            Some(Command::GetTdiReport(cmd)) => {
                let report_type = TdispReportType::from_i32(cmd.report_type);
                match report_type {
                    Some(report_type) => {
                        let report_buffer = self.machine.request_attestation_report(report_type);

                        match report_buffer {
                            Ok(report_buffer) => {
                                response = Some(Response::GetTdiReport(
                                    TdispCommandResponseGetTdiReport {
                                        report_type: cmd.report_type,
                                        report_buffer,
                                    },
                                ));
                            }
                            Err(err) => {
                                error = err;
                            }
                        }
                    }
                    None => {
                        error = TdispGuestOperationError::InvalidGuestAttestationReportType;
                    }
                }
            }
            _ => {
                error = TdispGuestOperationError::InvalidGuestCommandId;
            }
        }
        let state_after = self.machine.state();
        let error_code: TdispGuestOperationErrorCode = error.into();
        let resp = GuestToHostResponse {
            result: error_code.into(),
            tdi_state_before: state_before.into(),
            tdi_state_after: state_after.into(),
            response,
        };

        match error {
            TdispGuestOperationError::Success => {
                tracing::info!(?resp, "tdisp_handle_guest_command success");
            }
            _ => {
                tracing::error!(?resp, "tdisp_handle_guest_command error");
            }
        }

        Ok(resp)
    }
}

/// Trait implemented by TDISP-capable devices on the client side. This includes devices that
/// are assigned to isolated partitions other than the host.
pub trait TdispClientDevice: Send + Sync {
    /// Send a TDISP command to the host for this device.
    /// TODO TDISP: Async? Better handling of device_id in GuestToHostCommand?
    fn tdisp_command_to_host(&self, command: GuestToHostCommand) -> anyhow::Result<()>;
}

/// The number of states to keep in the state history for debug.
const TDISP_STATE_HISTORY_LEN: usize = 10;

/// The reason for an `Unbind` call. This can be guest or host initiated.
/// `Unbind` can be called any time during the assignment flow.
/// This is used for telemetry and debugging.
#[derive(Debug)]
pub enum TdispUnbindReason {
    /// Unknown reason.
    Unknown(anyhow::Error),

    /// The device was unbound manually by the guest or host for a non-error reason.
    GuestInitiated(TdispGuestUnbindReason),

    /// The device attempted to perform an invalid state transition.
    ImpossibleStateTransition(anyhow::Error),

    /// The guest tried to transition the device to the Locked state while the device was not
    /// in the Unlocked state.
    InvalidGuestTransitionToLocked,

    /// The guest tried to transition the device to the Run state while the device was not
    /// in the Locked state.
    InvalidGuestTransitionToRun,

    /// The guest tried to retrieve the attestation report while the device was not in the
    /// Locked or Run state.
    InvalidGuestGetAttestationReportState,

    /// The guest tried to accept the attestation report while the device was not in the
    /// Locked or Run state.
    InvalidGuestAcceptAttestationReportState,

    /// The guest tried to unbind the device while the device with an unbind reason that is
    /// not recognized as a valid guest unbind reason. The unbind still succeeds but the
    /// recorded reason is discarded.
    InvalidGuestUnbindReason(anyhow::Error),
}

/// The state machine for the TDISP assignment flow for a device on the host. Both the guest and host
/// synchronize this state machine with each other as they move through the assignment flow.
pub struct TdispHostStateMachine {
    /// The current state of the TDISP device emulator.
    current_state: TdispTdiState,
    /// A record of the last states the device was in.
    state_history: Vec<TdispTdiState>,
    /// The device ID of the device being assigned.
    debug_device_id: String,
    /// A record of the last unbind reasons for the device.
    unbind_reason_history: Vec<TdispUnbindReason>,
    /// Calls back into the host to perform TDISP actions.
    host_interface: Arc<Mutex<dyn TdispHostDeviceInterface>>,
    /// The guest protocol type that was negotiated with the host interface.
    guest_protocol_type: TdispGuestProtocolType,
}

impl TdispHostStateMachine {
    /// Create a new TDISP state machine with the `Unlocked` state.
    pub fn new(host_interface: Arc<Mutex<dyn TdispHostDeviceInterface>>) -> Self {
        Self {
            current_state: TdispTdiState::Unlocked,
            // Pre-allocate to the known cap to avoid runtime reallocations and to
            // keep the CBMC/Kani state space small (no realloc paths to model).
            state_history: Vec::with_capacity(TDISP_STATE_HISTORY_LEN),
            debug_device_id: "".to_owned(),
            unbind_reason_history: Vec::with_capacity(TDISP_STATE_HISTORY_LEN),
            host_interface,
            guest_protocol_type: TdispGuestProtocolType::Invalid,
        }
    }

    /// Set the debug device ID string.
    pub fn set_debug_device_id(&mut self, debug_device_id: String) {
        self.debug_device_id = debug_device_id;
    }

    /// Get the current state of the TDI.
    fn state(&self) -> TdispTdiState {
        self.current_state
    }

    fn ensure_negotiated_protocol(&self) -> anyhow::Result<()> {
        if self.guest_protocol_type == TdispGuestProtocolType::Invalid {
            #[cfg(not(kani))]
            tracing::error!(
                "Guest tried to perform a state transition without negotiating a protocol with the host!"
            );
            return Err(anyhow::anyhow!(
                "Guest tried to perform a state transition without negotiating a protocol with the host!"
            ));
        }
        Ok(())
    }

    /// Check if the state machine can transition to the new state. This protects the underlying state machinery
    /// while higher level transition machinery tries to avoid these conditions. If the new state is impossible,
    /// `false` is returned.
    #[cfg_attr(not(kani), instrument(fields(device_id = %self.debug_device_id), skip(self)))]
    fn is_valid_state_transition(&self, new_state: &TdispTdiState) -> bool {
        // All state machine transitions are specifically denied until the host as negotiated a protocol.
        match self.ensure_negotiated_protocol() {
            Ok(_) => {}
            Err(e) => {
                #[cfg(not(kani))]
                tracing::error!("Failed to transition state: {e:?}");
                #[cfg(kani)]
                let _ = e;
                return false;
            }
        }

        match (self.current_state, *new_state) {
            // Valid forward progress states from Unlocked -> Run
            (TdispTdiState::Unlocked, TdispTdiState::Locked) => true,
            (TdispTdiState::Locked, TdispTdiState::Run) => true,

            // Device can always return to the Unlocked state with `Unbind`
            (TdispTdiState::Run, TdispTdiState::Unlocked) => true,
            (TdispTdiState::Locked, TdispTdiState::Unlocked) => true,
            (TdispTdiState::Unlocked, TdispTdiState::Unlocked) => true,

            // Every other state transition is invalid
            _ => false,
        }
    }

    /// Transitions the state machine to the new state if it is valid. If the new state is invalid,
    /// the state of the device is reset to the `Unlocked` state.
    #[cfg_attr(not(kani), instrument(fields(device_id = %self.debug_device_id), skip(self)))]
    fn transition_state_to(&mut self, new_state: TdispTdiState) -> anyhow::Result<()> {
        #[cfg(not(kani))]
        tracing::info!(
            "Request to transition from {:?} -> {:?}",
            self.current_state,
            new_state
        );

        // Ensure the state transition is valid
        if !self.is_valid_state_transition(&new_state) {
            #[cfg(not(kani))]
            tracing::info!(
                "Invalid state transition {:?} -> {:?}",
                self.current_state,
                new_state
            );
            // Under Kani, skip Debug formatting of symbolic enum values to avoid
            // state-space expansion from std::fmt machinery.
            #[cfg(not(kani))]
            return Err(anyhow::anyhow!(
                "Invalid state transition {:?} -> {:?}",
                self.current_state,
                new_state
            ));
            #[cfg(kani)]
            return Err(anyhow::anyhow!("Invalid state transition"));
        }

        // Record the state history.
        // Under Kani, skip Vec push/remove so CBMC does not need to model
        // heap mutations here; the history cap invariant is verified
        // independently in verify_state_history_cap_invariant.
        #[cfg(not(kani))]
        {
            if self.state_history.len() == TDISP_STATE_HISTORY_LEN {
                self.state_history.remove(0);
            }
            self.state_history.push(self.current_state);
        }

        // Transition to the new state
        self.current_state = new_state;
        #[cfg(not(kani))]
        tracing::info!("Transitioned to {:?}", self.current_state);

        Ok(())
    }

    /// Kani-only sibling of [`transition_state_to`] that exercises the
    /// **same security-critical state-transition logic** but uses a unit
    /// error type to avoid the `anyhow::Error` allocation chain.
    ///
    /// # Why this exists
    /// The production [`transition_state_to`] returns `anyhow::Result<()>`.
    /// On the failure branch it allocates an `anyhow::Error` via
    /// `anyhow::anyhow!(...)`, which expands to
    /// `anyhow::__private::format_err(...)`. That, in turn, calls
    /// `std::backtrace::Backtrace::capture()`, which checks the
    /// `RUST_BACKTRACE` / `RUST_LIB_BACKTRACE` environment variables via
    /// `std::env::var()`. On Linux that boils down to a `getenv` plus a
    /// loop in `core::slice::memchr::memchr_naive` to find the NUL
    /// terminator of the C string returned from `getenv`.
    ///
    /// CBMC's reachability analysis includes the failure branch in the
    /// goto-program even when our harness uses `kani::assume(...)` to
    /// restrict to the success path: assumptions are runtime constraints
    /// on the SAT formula, not compile-time pruning of MIR. As a result,
    /// CBMC unwinds `memchr_naive` thousands of times searching for a
    /// fixed point on a symbolic-length C string, and verification
    /// effectively never terminates.
    ///
    /// # What this method preserves
    /// This sibling method is a **line-by-line copy** of the meaningful
    /// state-transition logic of [`transition_state_to`]:
    ///
    /// 1. It calls the same `is_valid_state_transition(&new_state)`
    ///    method — the security policy gatekeeper that decides whether a
    ///    `(current_state, new_state)` pair is legal under TDISP.
    /// 2. On failure (invalid pair) it returns an error and **does not
    ///    mutate** `self.current_state`. This preserves the
    ///    "no silent state corruption on rejection" invariant.
    /// 3. On success (valid pair) it sets `self.current_state = new_state`
    ///    — the same exact assignment performed by the production code.
    ///
    /// # What this method abstracts away (and why that is sound)
    /// - **Error type:** the production code returns `anyhow::Error`,
    ///   which the security property never inspects (callers only check
    ///   `is_ok()` / `is_err()`). The harness asserts the same `Ok`/`Err`
    ///   shape — the *value* inside `Err(_)` is irrelevant to TDISP
    ///   correctness.
    /// - **Tracing:** `tracing::info!` calls are informational only and
    ///   never affect control flow or state mutation.
    /// - **History recording:** `state_history` push/remove is a separate
    ///   ring-buffer mechanism whose bounded-capacity invariant is
    ///   verified independently by `verify_state_history_cap_invariant`.
    ///   Recording is *purely additive* and never reads back into the
    ///   transition decision.
    ///
    /// # Equivalence sketch
    /// For all `(current_state, new_state)` ∈ `TdispTdiState²`, both
    /// methods agree on:
    ///   - whether the call returns `Ok` or `Err`;
    ///   - the value of `self.current_state` after the call.
    /// They differ only in (a) the `Err` payload type, (b) whether
    /// `state_history` is mutated, and (c) whether tracing is emitted.
    /// None of (a–c) are part of the property under proof.
    ///
    /// # Inputs / pre-conditions / post-conditions
    /// Identical to [`transition_state_to`].
    #[cfg(kani)]
    fn transition_state_to_kani(&mut self, new_state: TdispTdiState) -> Result<(), ()> {
        // Step 1: gatekeeper — same call as production.
        if !self.is_valid_state_transition(&new_state) {
            // Step 2: return Err WITHOUT mutating current_state.
            return Err(());
        }
        // Step 3: success — perform the same mutation as production.
        self.current_state = new_state;
        Ok(())
    }

    /// Transition the device to the `Unlocked` state regardless of the current state.
    #[cfg_attr(not(kani), instrument(fields(device_id = %self.debug_device_id), skip(self)))]
    fn unbind_all(&mut self, reason: TdispUnbindReason) -> anyhow::Result<()> {
        #[cfg(not(kani))]
        tracing::info!("Unbind called with reason {:?}", reason);

        // All states can be reset to the Unlocked state. This can only happen if the
        // state is corrupt beyond the state machine.
        if let Err(reason) = self.transition_state_to(TdispTdiState::Unlocked) {
            // Under Kani, avoid formatting anyhow::Error (which involves heap allocation)
            // since this path is statically unreachable for valid states.
            #[cfg(not(kani))]
            return Err(anyhow::anyhow!(
                "Impossible state machine violation during TDISP Unbind: {:?}",
                reason
            ));
            #[cfg(kani)]
            {
                let _ = reason;
                return Err(anyhow::anyhow!(
                    "Impossible state machine violation during TDISP Unbind"
                ));
            }
        }

        // Call back into the host to bind the device.
        let res = self
            .host_interface
            .lock()
            .tdisp_unbind_device()
            .context("host failed to unbind TDI");

        if let Err(e) = res {
            #[cfg(not(kani))]
            tracing::error!("Failed to unbind TDI: {:?}", e);
            return Err(e);
        }

        // Record the unbind reason.
        // Under Kani, skip Vec push/remove (same rationale as in transition_state_to).
        #[cfg(not(kani))]
        {
            if self.unbind_reason_history.len() == TDISP_STATE_HISTORY_LEN {
                self.unbind_reason_history.remove(0);
            }
            self.unbind_reason_history.push(reason);
        }

        Ok(())
    }

    /// Kani-only sibling of [`unbind_all`] that exercises the
    /// **same security-critical reset logic** but avoids `anyhow::Error`
    /// allocation, `parking_lot::Mutex::lock()`, and `dyn`-trait vtable
    /// dispatch into the host interface.
    ///
    /// # Why this exists
    /// Production [`unbind_all`] performs three operations:
    /// 1. `transition_state_to(Unlocked)` — the security-critical state
    ///    mutation.
    /// 2. `host_interface.lock().tdisp_unbind_device()` — host-side
    ///    plumbing that informs the host the device is being unbound.
    /// 3. Push the unbind reason into `unbind_reason_history`.
    ///
    /// Step 1 is the property we are proving (the device is *always*
    /// reset to `Unlocked`, no matter the host's response).  Steps 2
    /// and 3 are not part of that property:
    ///
    /// - Step 2 brings `parking_lot` internals (atomic ops, futex paths,
    ///   condition variables) and the `dyn TdispHostDeviceInterface`
    ///   vtable into CBMC reachability, ballooning the goto-program.
    /// - The error path of step 1 calls
    ///   `anyhow::anyhow!("Impossible state machine violation...")`,
    ///   which transitively triggers the `Backtrace::capture()` →
    ///   `env::var()` → `memchr_naive` chain (see the doc comment on
    ///   [`transition_state_to_kani`]).  Even though that path is
    ///   logically unreachable for valid pre-states (transition to
    ///   `Unlocked` is valid from every reachable state), CBMC's
    ///   reachability analysis still includes it.
    /// - Step 3 is a `Vec::push` that we already verify in isolation
    ///   via `verify_state_history_cap_invariant`.
    ///
    /// # What this method preserves
    /// 1. The same gatekeeper call — delegates to
    ///    [`transition_state_to_kani`], which calls the *same*
    ///    `is_valid_state_transition` method as production.
    /// 2. The same **safety ordering**: the state mutation
    ///    (`current_state = Unlocked`) happens **before** the host
    ///    callback simulation.  This means `current_state == Unlocked`
    ///    holds even when the host call fails — the device is reset
    ///    even if the host plumbing later errors out.  This is the
    ///    critical security guarantee.
    /// 3. Both Ok and Err return paths are reachable via a
    ///    nondeterministic `host_call_succeeds` parameter
    ///    (matching production: success iff transition succeeded *and*
    ///    host call succeeded).
    ///
    /// # What this method abstracts away (and why that is sound)
    /// - **Host interface call:** the production code calls into the
    ///   host via `dyn` dispatch.  The harness models the *outcome* of
    ///   that call (Ok vs Err) via a `bool` parameter, which captures
    ///   every possible behaviour of any conforming
    ///   `TdispHostDeviceInterface` implementation.  We do not verify
    ///   the host's own logic here — that is the host implementor's
    ///   responsibility.
    /// - **Error type:** `()` instead of `anyhow::Error`.  The property
    ///   never inspects the `Err` payload.
    /// - **History `Vec::push`:** verified separately by
    ///   `verify_state_history_cap_invariant`.
    /// - **Tracing emission:** informational, no control-flow effect.
    ///
    /// # Equivalence sketch
    /// For all `(current_state, host_call_result)` and any reason, the
    /// production `unbind_all` and this Kani sibling agree on:
    ///   - the value of `self.current_state` after the call (always
    ///     `Unlocked` if the pre-state was reachable);
    ///   - whether the call returns `Ok` or `Err` (Ok iff both the
    ///     transition succeeded and the host call succeeded).
    ///
    /// # Pre-conditions
    /// - `current_state ∈ {Unlocked, Locked, Run}` — every reachable
    ///   state.  `Uninitialized` is excluded because
    ///   [`TdispHostStateMachine::new`] starts in `Unlocked`.
    ///
    /// # Post-conditions
    /// - `current_state == Unlocked` (always — even on `Err` return,
    ///   because the state mutation happens before the host call).
    /// - Returns `Ok(())` iff the transition was valid (always true for
    ///   valid pre-states) **and** `host_call_succeeds == true`.
    #[cfg(kani)]
    fn unbind_all_kani(&mut self, host_call_succeeds: bool) -> Result<(), ()> {
        // Step 1: same gatekeeper + state mutation as production.
        // For valid pre-states, this always succeeds (transition to
        // Unlocked is allowed from every reachable state per the
        // security policy table verified in H2).
        self.transition_state_to_kani(TdispTdiState::Unlocked)?;

        // Step 2: simulate the host callback's outcome.  Production
        // calls `host_interface.lock().tdisp_unbind_device()`; we model
        // its return value nondeterministically.  Crucially, this
        // happens AFTER the state mutation above — matching production
        // ordering and preserving the safety guarantee that the device
        // is reset even if the host call fails.
        if !host_call_succeeds {
            return Err(());
        }

        Ok(())
    }
}

/// Represents an interface by which guest commands can be dispatched to a
/// backing TDISP state handler in the host. This could be an emulated TDISP device or an
/// assigned TDISP device that is actually connected to the guest.
pub trait TdispGuestRequestInterface {
    /// Before a guest can communicate with the host, the guest must negotiate a
    /// protocol with the host. This is done by calling this function with the
    /// guest's desired protocol type. The host responds with the protocol that
    /// it will use to communicate with the guest and includes information about
    /// the TDISP capabilities of the device.
    ///
    /// If the host reports that this device not TDISP capable,
    /// [`TdispDeviceInterfaceInfo::guest_protocol_type`] will be
    /// [`TdispGuestProtocolType::Invalid`].
    fn tdisp_negotiate_protocol(
        &mut self,
        requested_guest_protocol: TdispGuestProtocolType,
    ) -> Result<TdispDeviceInterfaceInfo, TdispGuestOperationError>;

    /// Transition the device from the Unlocked to Locked state. This takes place after the
    /// device has been assigned to the guest partition and the resources for the device have
    /// been configured by the guest by not yet validated.
    /// The device will in the `Locked` state can still perform unencrypted operations until it has
    /// been transitioned to the `Run` state. The device will be attested and moved to the `Run` state.
    ///
    /// Attempting to transition the device to the `Locked` state while the device is not in the
    /// `Unlocked` state will cause an error and unbind the device.
    fn request_lock_device_resources(&mut self) -> Result<(), TdispGuestOperationError>;

    /// Transition the device from the Locked to the Run state. This takes place after the
    /// device has been assigned resources and the resources have been locked to the guest.
    /// The device will then transition to the `Run` state, where it will be non-functional
    /// until the guest undergoes attestation and resources are accepted into the guest context.
    ///
    /// Attempting to transition the device to the `Run` state while the device is not in the
    /// `Locked` state will cause an error and unbind the device.
    fn request_start_tdi(&mut self) -> Result<(), TdispGuestOperationError>;

    /// Retrieves the attestation report for the device when the device is in the `Locked` or
    /// `Run` state. The device resources will not be functional until the
    /// resources have been accepted into the guest while the device is in the
    /// `Run` state.
    ///
    /// Attempting to retrieve the attestation report while the device is not in
    /// the `Locked` or `Run` state will cause an error and unbind the device.
    fn request_attestation_report(
        &mut self,
        report_type: TdispReportType,
    ) -> Result<Vec<u8>, TdispGuestOperationError>;

    /// Guest initiates a graceful unbind of the device. The guest might
    /// initiate an unbind for a variety of reasons:
    ///  - Device is being detached/deactivated and is no longer needed in a functional state
    ///  - Device is powering down or entering a reset
    ///
    /// The device will transition to the `Unlocked` state. The guest can call
    /// this function at any time in any state to reset the device to the
    /// `Unlocked` state.
    fn request_unbind(
        &mut self,
        reason: TdispGuestUnbindReason,
    ) -> Result<(), TdispGuestOperationError>;
}

impl TdispGuestRequestInterface for TdispHostStateMachine {
    /// Request versioning and protocol negotiation from the host.
    #[cfg_attr(not(kani), instrument(fields(device_id = %self.debug_device_id), skip(self)))]
    fn tdisp_negotiate_protocol(
        &mut self,
        requested_guest_protocol: TdispGuestProtocolType,
    ) -> Result<TdispDeviceInterfaceInfo, TdispGuestOperationError> {
        if self.guest_protocol_type != TdispGuestProtocolType::Invalid {
            #[cfg(not(kani))]
            tracing::error!(
                "Guest tried to negotiate a protocol with the host while a protocol was already negotiated!"
            );
            return Err(TdispGuestOperationError::InvalidGuestProtocolRequest);
        }

        if requested_guest_protocol == TdispGuestProtocolType::Invalid {
            #[cfg(not(kani))]
            tracing::error!("Guest tried to negotiate Invalid as a protocol");
            return Err(TdispGuestOperationError::InvalidGuestProtocolRequest);
        }

        // Call back into the host to negotiate protocol information.
        let res = self
            .host_interface
            .lock()
            .tdisp_negotiate_protocol(requested_guest_protocol)
            .context("failed to call to negotiate protocol");

        match res {
            Ok(interface_info) => {
                match TdispGuestProtocolType::from_i32(interface_info.guest_protocol_type) {
                    Some(guest_protocol_type) => {
                        if guest_protocol_type == TdispGuestProtocolType::Invalid {
                            #[cfg(not(kani))]
                            tracing::error!(
                                ?guest_protocol_type,
                                "Guest protocol negotiated with invalid value"
                            );
                            Err(TdispGuestOperationError::InvalidGuestProtocolRequest)
                        } else {
                            self.guest_protocol_type = guest_protocol_type;
                            #[cfg(not(kani))]
                            tracing::info!(
                                ?interface_info,
                                "Guest protocol negotiated successfully to"
                            );
                            Ok(interface_info)
                        }
                    }
                    None => {
                        #[cfg(not(kani))]
                        tracing::error!(
                            ?interface_info,
                            "Guest protocol negotiated with none value"
                        );
                        Err(TdispGuestOperationError::InvalidGuestProtocolRequest)
                    }
                }
            }
            Err(e) => {
                #[cfg(not(kani))]
                tracing::error!(?e, "Failed to negotiate protocol with host interface");
                #[cfg(kani)]
                let _ = e;
                Err(TdispGuestOperationError::HostFailedToProcessCommand)
            }
        }
    }

    #[cfg_attr(not(kani), instrument(fields(device_id = %self.debug_device_id), skip(self)))]
    fn request_lock_device_resources(&mut self) -> Result<(), TdispGuestOperationError> {
        // Ensure the guest protocol is negotiated.
        self.ensure_negotiated_protocol()
            .map_err(|_| TdispGuestOperationError::InvalidDeviceState)?;

        // If the guest attempts to transition the device to the Locked state while the device
        // is not in the Unlocked state, the device is reset to the Unlocked state.
        if self.current_state != TdispTdiState::Unlocked {
            #[cfg(not(kani))]
            tracing::error!(
                "Unlocked to Locked state called while device was not in Unlocked state."
            );

            self.unbind_all(TdispUnbindReason::InvalidGuestTransitionToLocked)
                .map_err(|_| TdispGuestOperationError::HostFailedToProcessCommand)?;
            return Err(TdispGuestOperationError::InvalidDeviceState);
        }

        #[cfg(not(kani))]
        tracing::info!("Device bind requested, trying to transition from Unlocked to Locked state");

        // Call back into the host to bind the device.
        let res = self
            .host_interface
            .lock()
            .tdisp_bind_device()
            .context("failed to call to bind TDI");

        if let Err(e) = res {
            #[cfg(not(kani))]
            tracing::error!("Failed to bind TDI: {e:?}");
            #[cfg(kani)]
            let _ = e;
            return Err(TdispGuestOperationError::HostFailedToProcessCommand);
        }

        #[cfg(not(kani))]
        tracing::info!("Device transition from Unlocked to Locked state");
        match self.transition_state_to(TdispTdiState::Locked) {
            Ok(_) => {}
            Err(e) => {
                #[cfg(not(kani))]
                tracing::error!("Failed to transition to Locked state: {e:?}");
                #[cfg(kani)]
                let _ = e;
                return Err(TdispGuestOperationError::HostFailedToProcessCommand);
            }
        }
        Ok(())
    }

    #[cfg_attr(not(kani), instrument(fields(device_id = %self.debug_device_id), skip(self)))]
    fn request_start_tdi(&mut self) -> Result<(), TdispGuestOperationError> {
        // Ensure the guest protocol is negotiated.
        self.ensure_negotiated_protocol()
            .map_err(|_| TdispGuestOperationError::InvalidDeviceState)?;

        if self.current_state != TdispTdiState::Locked {
            #[cfg(not(kani))]
            tracing::error!("StartTDI called while device was not in Locked state.");
            self.unbind_all(TdispUnbindReason::InvalidGuestTransitionToRun)
                .map_err(|_| TdispGuestOperationError::HostFailedToProcessCommand)?;

            return Err(TdispGuestOperationError::InvalidDeviceState);
        }

        #[cfg(not(kani))]
        tracing::info!("Device start requested, trying to transition from Locked to Run state");

        // Call back into the host to bind the device.
        let res = self
            .host_interface
            .lock()
            .tdisp_start_device()
            .context("failed to call to start TDI");

        if let Err(e) = res {
            #[cfg(not(kani))]
            tracing::error!("Failed to start TDI: {e:?}");
            #[cfg(kani)]
            let _ = e;
            return Err(TdispGuestOperationError::HostFailedToProcessCommand);
        }

        #[cfg(not(kani))]
        tracing::info!("Device transition from Locked to Run state");
        match self.transition_state_to(TdispTdiState::Run) {
            Ok(_) => {}
            Err(e) => {
                #[cfg(not(kani))]
                tracing::error!("Failed to transition to Run state: {e:?}");
                #[cfg(kani)]
                let _ = e;
                return Err(TdispGuestOperationError::HostFailedToProcessCommand);
            }
        }

        Ok(())
    }

    #[cfg_attr(not(kani), instrument(fields(device_id = %self.debug_device_id), skip(self)))]
    fn request_attestation_report(
        &mut self,
        report_type: TdispReportType,
    ) -> Result<Vec<u8>, TdispGuestOperationError> {
        // Ensure the guest protocol is negotiated.
        self.ensure_negotiated_protocol()
            .map_err(|_| TdispGuestOperationError::InvalidDeviceState)?;

        if self.current_state != TdispTdiState::Locked && self.current_state != TdispTdiState::Run {
            #[cfg(not(kani))]
            tracing::error!(
                "Request to retrieve attestation report called while device was not in Locked or Run state."
            );
            self.unbind_all(TdispUnbindReason::InvalidGuestGetAttestationReportState)
                .map_err(|_| TdispGuestOperationError::HostFailedToProcessCommand)?;

            return Err(TdispGuestOperationError::InvalidGuestAttestationReportState);
        }

        if report_type == TdispReportType::Invalid {
            #[cfg(not(kani))]
            tracing::error!("Invalid report type TdispReportId::INVALID requested");
            return Err(TdispGuestOperationError::InvalidGuestAttestationReportType);
        }

        let report_buffer = self
            .host_interface
            .lock()
            .tdisp_get_device_report(report_type)
            .context("failed to call to get device report from host");

        match report_buffer {
            Ok(report_buffer) => {
                #[cfg(not(kani))]
                tracing::info!("Retrieve attestation report called successfully");
                Ok(report_buffer)
            }
            Err(e) => {
                #[cfg(not(kani))]
                tracing::error!("Failed to get device report from host: {e:?}");
                #[cfg(kani)]
                let _ = e;
                Err(TdispGuestOperationError::HostFailedToProcessCommand)
            }
        }
    }

    #[cfg_attr(not(kani), instrument(fields(device_id = %self.debug_device_id), skip(self)))]
    fn request_unbind(
        &mut self,
        reason: TdispGuestUnbindReason,
    ) -> Result<(), TdispGuestOperationError> {
        // Ensure the guest protocol is negotiated.
        self.ensure_negotiated_protocol()
            .map_err(|_| TdispGuestOperationError::InvalidDeviceState)?;

        // The guest can provide a reason for the unbind. If the unbind reason isn't valid for a guest (such as
        // if the guest says it is unbinding due to a host-related error), the reason is discarded and InvalidGuestUnbindReason
        // is recorded in the unbind history.
        let reason = match reason {
            TdispGuestUnbindReason::Graceful => TdispUnbindReason::GuestInitiated(reason),
            _ => {
                #[cfg(not(kani))]
                tracing::error!(
                    "Invalid guest unbind reason {} requested",
                    reason.as_str_name()
                );
                TdispUnbindReason::InvalidGuestUnbindReason(anyhow::anyhow!(
                    "Invalid guest unbind reason {} requested",
                    reason.as_str_name()
                ))
            }
        };

        #[cfg(not(kani))]
        tracing::info!(
            "Guest request to unbind succeeds while device is in {:?} (reason: {:?})",
            self.current_state,
            reason
        );

        self.unbind_all(reason)
            .map_err(|_| TdispGuestOperationError::HostFailedToProcessCommand)?;

        Ok(())
    }
}

/// Kani-only sibling methods for `TdispHostStateMachine`.
///
/// Each sibling here mirrors the security-critical logic of a corresponding
/// production method in `impl TdispGuestRequestInterface for TdispHostStateMachine`,
/// but abstracts away two classes of incidental machinery that defeat CBMC:
///
/// 1. **`anyhow::anyhow!(...)` allocation chains.** Even on logically
///    unreachable error branches (pruned by harness `kani::assume`), CBMC's
///    reachability analysis includes them, leading to
///    `Backtrace::capture()` → `env::var()` → `core::slice::memchr::memchr_naive`
///    being unwound for thousands of iterations. See the doc comment on
///    [`TdispHostStateMachine::transition_state_to_kani`] for the full
///    explanation.
///
/// 2. **`parking_lot::Mutex::lock()` + `dyn TdispHostDeviceInterface`
///    vtable dispatch** for the `host_interface.lock().tdisp_<x>_device()`
///    callbacks. These pull `parking_lot` internals (atomic ops, futex
///    paths) and the entire vtable for every method on
///    `TdispHostDeviceInterface` into reachability. The siblings model
///    the *outcome* of each host callback with a `bool` parameter, which
///    captures every behaviour any conforming implementation can exhibit
///    without bringing the lock + vtable into the goto-program.
///
/// Each sibling method's doc comment justifies what is preserved (the
/// security-critical control-flow and state mutations) and what is
/// abstracted (anyhow payloads, lock plumbing, tracing). The harnesses
/// in `kani_proofs.rs` call these siblings; reviewers should audit the
/// equivalence claims when changing the production code.
#[cfg(kani)]
impl TdispHostStateMachine {
    /// Kani sibling of [`Self::ensure_negotiated_protocol`].
    ///
    /// Returns `true` when the protocol has been negotiated, `false`
    /// otherwise. Production version returns `anyhow::Result<()>`; we
    /// reduce to `bool` because the harness only branches on the boolean
    /// outcome and never inspects the error payload.
    fn ensure_negotiated_protocol_kani(&self) -> bool {
        self.guest_protocol_type != TdispGuestProtocolType::Invalid
    }

    /// Kani sibling of [`Self::tdisp_negotiate_protocol`] (a method on the
    /// `TdispGuestRequestInterface` impl).
    ///
    /// # What this preserves
    /// - **Re-entrancy guard:** if `self.guest_protocol_type != Invalid`,
    ///   returns `Err(InvalidGuestProtocolRequest)` without touching the
    ///   host. This is the same first check as production (lib.rs line 738).
    /// - **Invalid-type guard:** if `requested == Invalid`, returns
    ///   `Err(InvalidGuestProtocolRequest)` without touching the host.
    ///   Same as production line 746.
    /// - **State mutation on success:** `self.guest_protocol_type =
    ///   negotiated_protocol` — same as production line 771.
    /// - **Three error paths from the host-call section, modelled by two
    ///   bool parameters:**
    ///   1. `host_call_succeeds == false` → `Err(HostFailedToProcessCommand)`
    ///      (production line 795).
    ///   2. `host_returned_invalid == true` → `Err(InvalidGuestProtocolRequest)`
    ///      (production line 763 + 769, when host echoes back `Invalid`).
    ///   3. Otherwise → success: protocol set, `Ok(_)` returned.
    ///
    /// # What this abstracts
    /// - The actual `host_interface.lock().tdisp_negotiate_protocol(...)`
    ///   call (modelled by `host_call_succeeds: bool`).
    /// - The `from_i32` decode of the host-returned protocol type and the
    ///   `Some/None` unwrap (collapsed: `host_returned_invalid: bool`
    ///   captures both "host returned Invalid discriminant" and "host
    ///   returned an out-of-range value the from_i32 cannot decode").
    /// - The returned `TdispDeviceInterfaceInfo` payload — the harnesses
    ///   only check `is_ok()` / `is_err()` and the post-state, never the
    ///   payload contents.
    fn tdisp_negotiate_protocol_kani(
        &mut self,
        requested: TdispGuestProtocolType,
        host_call_succeeds: bool,
        host_returned_invalid: bool,
    ) -> Result<(), TdispGuestOperationError> {
        // Step 1: re-entrancy guard.
        if self.guest_protocol_type != TdispGuestProtocolType::Invalid {
            return Err(TdispGuestOperationError::InvalidGuestProtocolRequest);
        }
        // Step 2: invalid-type guard.
        if requested == TdispGuestProtocolType::Invalid {
            return Err(TdispGuestOperationError::InvalidGuestProtocolRequest);
        }
        // Step 3: simulated host call.
        if !host_call_succeeds {
            return Err(TdispGuestOperationError::HostFailedToProcessCommand);
        }
        // Step 4: simulated host-returned protocol validation.
        if host_returned_invalid {
            return Err(TdispGuestOperationError::InvalidGuestProtocolRequest);
        }
        // Step 5: state mutation — same as production.
        self.guest_protocol_type = requested;
        Ok(())
    }

    /// Kani sibling of [`Self::request_lock_device_resources`].
    ///
    /// # What this preserves
    /// - **Negotiated-protocol guard:** rejects with
    ///   `Err(InvalidDeviceState)` when protocol is unset (production
    ///   line 803).
    /// - **State pre-condition:** if `current_state != Unlocked`, calls
    ///   `unbind_all_kani` to reset the device, then returns
    ///   `Err(InvalidDeviceState)` (production lines 808–817). The reset
    ///   is observable via `current_state` after the call — the same
    ///   safety property as in `unbind_all`.
    /// - **Host-bind callback simulation** (`bind_call_succeeds: bool`).
    ///   On failure → `Err(HostFailedToProcessCommand)` (production line
    ///   834).
    /// - **State mutation on success:** delegates to
    ///   `transition_state_to_kani(Locked)` — same gatekeeper +
    ///   `current_state = Locked` mutation as production line 839.
    ///
    /// # What this abstracts
    /// - `parking_lot::Mutex::lock()` + `dyn`-trait dispatch into
    ///   `tdisp_bind_device()` (modelled by `bind_call_succeeds: bool`).
    /// - The host-unbind callback that fires on the wrong-state-reset
    ///   path (modelled by `unbind_call_succeeds: bool`).
    /// - All `anyhow::Error` payloads.
    fn request_lock_device_resources_kani(
        &mut self,
        bind_call_succeeds: bool,
        unbind_call_succeeds: bool,
    ) -> Result<(), TdispGuestOperationError> {
        if !self.ensure_negotiated_protocol_kani() {
            return Err(TdispGuestOperationError::InvalidDeviceState);
        }
        if self.current_state != TdispTdiState::Unlocked {
            self.unbind_all_kani(unbind_call_succeeds)
                .map_err(|_| TdispGuestOperationError::HostFailedToProcessCommand)?;
            return Err(TdispGuestOperationError::InvalidDeviceState);
        }
        if !bind_call_succeeds {
            return Err(TdispGuestOperationError::HostFailedToProcessCommand);
        }
        self.transition_state_to_kani(TdispTdiState::Locked)
            .map_err(|_| TdispGuestOperationError::HostFailedToProcessCommand)?;
        Ok(())
    }

    /// Kani sibling of [`Self::request_start_tdi`]. Mirror image of
    /// `request_lock_device_resources_kani` with `Locked → Run` instead
    /// of `Unlocked → Locked`.
    ///
    /// # What this preserves
    /// - Negotiated-protocol guard.
    /// - **State pre-condition:** if `current_state != Locked`, calls
    ///   `unbind_all_kani` to reset to `Unlocked`, then returns
    ///   `Err(InvalidDeviceState)` (production lines 858–865).
    /// - Host-start callback simulation.
    /// - **State mutation on success:** delegates to
    ///   `transition_state_to_kani(Run)`.
    fn request_start_tdi_kani(
        &mut self,
        start_call_succeeds: bool,
        unbind_call_succeeds: bool,
    ) -> Result<(), TdispGuestOperationError> {
        if !self.ensure_negotiated_protocol_kani() {
            return Err(TdispGuestOperationError::InvalidDeviceState);
        }
        if self.current_state != TdispTdiState::Locked {
            self.unbind_all_kani(unbind_call_succeeds)
                .map_err(|_| TdispGuestOperationError::HostFailedToProcessCommand)?;
            return Err(TdispGuestOperationError::InvalidDeviceState);
        }
        if !start_call_succeeds {
            return Err(TdispGuestOperationError::HostFailedToProcessCommand);
        }
        self.transition_state_to_kani(TdispTdiState::Run)
            .map_err(|_| TdispGuestOperationError::HostFailedToProcessCommand)?;
        Ok(())
    }

    /// Kani sibling of [`Self::request_attestation_report`].
    ///
    /// # What this preserves
    /// - Negotiated-protocol guard.
    /// - **State pre-condition:** allowed only in `Locked` or `Run`
    ///   (production line 910). On wrong state, calls `unbind_all_kani`
    ///   and returns `Err(InvalidGuestAttestationReportState)`.
    /// - **Report-type guard:** `Invalid` report type → `Err(...)` with
    ///   the same error code as production line 924.
    /// - Host-call simulation for the report-fetch (`report_call_succeeds:
    ///   bool`).
    /// - **No state mutation on success:** the production function does not
    ///   mutate `current_state` on the success path; nor does the sibling.
    ///
    /// # What this abstracts
    /// - The returned `Vec<u8>` report buffer (replaced with `()` —
    ///   harness only checks `is_ok()` and post-state, not buffer content).
    /// - The `dyn`-trait `tdisp_get_device_report(...)` dispatch.
    fn request_attestation_report_kani(
        &mut self,
        report_type: TdispReportType,
        report_call_succeeds: bool,
        unbind_call_succeeds: bool,
    ) -> Result<(), TdispGuestOperationError> {
        if !self.ensure_negotiated_protocol_kani() {
            return Err(TdispGuestOperationError::InvalidDeviceState);
        }
        if self.current_state != TdispTdiState::Locked && self.current_state != TdispTdiState::Run {
            self.unbind_all_kani(unbind_call_succeeds)
                .map_err(|_| TdispGuestOperationError::HostFailedToProcessCommand)?;
            return Err(TdispGuestOperationError::InvalidGuestAttestationReportState);
        }
        if report_type == TdispReportType::Invalid {
            return Err(TdispGuestOperationError::InvalidGuestAttestationReportType);
        }
        if !report_call_succeeds {
            return Err(TdispGuestOperationError::HostFailedToProcessCommand);
        }
        Ok(())
    }

    /// Kani sibling of [`Self::request_unbind`].
    ///
    /// # What this preserves
    /// - Negotiated-protocol guard.
    /// - **Reason classification:** distinguishes `Graceful`
    ///   (guest-valid) from any other guest-supplied reason (production
    ///   lines 961–973). Unlike production we do NOT construct an
    ///   `anyhow::Error` for the `Invalid` case (which would trigger
    ///   `Backtrace::capture` → memchr); instead we discard the reason
    ///   silently. The reason itself is informational and never affects
    ///   the post-state.
    /// - **Universal reset:** delegates to `unbind_all_kani`, which
    ///   performs the same `transition_state_to(Unlocked)` and the same
    ///   pre-host-call ordering as production.
    fn request_unbind_kani(
        &mut self,
        _reason: TdispGuestUnbindReason,
        host_call_succeeds: bool,
    ) -> Result<(), TdispGuestOperationError> {
        if !self.ensure_negotiated_protocol_kani() {
            return Err(TdispGuestOperationError::InvalidDeviceState);
        }
        // Reason classification is informational and does not affect the
        // post-state; we elide it here. (Production discards the reason
        // when not Graceful and substitutes InvalidGuestUnbindReason
        // wrapping an anyhow::Error — incidental to the property.)
        self.unbind_all_kani(host_call_succeeds)
            .map_err(|_| TdispGuestOperationError::HostFailedToProcessCommand)?;
        Ok(())
    }
}
