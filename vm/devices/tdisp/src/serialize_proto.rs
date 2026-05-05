// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Protobuf serialization of TDISP guest-to-host commands and responses using
//! the types defined in [`tdisp_proto`].

use anyhow::Context;
use prost::Message as _;
use tdisp_proto::GuestToHostCommand;
use tdisp_proto::GuestToHostResponse;
use tdisp_proto::TdispGuestOperationErrorCode;
use tdisp_proto::TdispGuestProtocolType;
use tdisp_proto::TdispGuestUnbindReason;
use tdisp_proto::TdispReportType;
use tdisp_proto::TdispTdiState;
use tdisp_proto::guest_to_host_command::Command;
use tdisp_proto::guest_to_host_response::Response;

/// All fields in proto3 are optional regardless of definition. This runtime requires that a protobuf field is not `None`.
macro_rules! require_field {
    ($val:expr) => {
        $val.as_ref()
            .ok_or_else(|| anyhow::anyhow!("proto validation: {} must be set", stringify!($val)))
    };
}

/// All enums in proto3 are optional regardless of definition. This runtime requires that a protobuf enum is valid and
/// within the range of the enum.
macro_rules! require_enum {
    ($field:expr, $enum_ty:ty) => {
        <$enum_ty>::from_i32($field).ok_or_else(|| {
            anyhow::anyhow!(
                "proto validation: {} is not a valid {}: {}",
                stringify!($field),
                stringify!($enum_ty),
                $field
            )
        })
    };
}

/// Serialize a [`GuestToHostCommand`] to a protobuf-encoded byte vector.
pub fn serialize_command(command: &GuestToHostCommand) -> Vec<u8> {
    command.encode_to_vec()
}

/// Deserialize a [`GuestToHostCommand`] from a protobuf-encoded byte slice.
pub fn deserialize_command(bytes: &[u8]) -> anyhow::Result<GuestToHostCommand> {
    let res = GuestToHostCommand::decode(bytes)
        .map_err(|e| anyhow::anyhow!("failed to deserialize GuestToHostCommand: {e}"))?;

    // Then, validate the command to ensure that it matches the expected format.
    validate_command(&res).with_context(|| "failed to validate command in deserialize_command")?;

    Ok(res)
}

/// Serialize a [`GuestToHostResponse`] to a protobuf-encoded byte vector.
pub fn serialize_response(response: &GuestToHostResponse) -> Vec<u8> {
    response.encode_to_vec()
}

/// Deserialize a [`GuestToHostResponse`] from a protobuf-encoded byte slice.
pub fn deserialize_response(bytes: &[u8]) -> anyhow::Result<GuestToHostResponse> {
    let res = GuestToHostResponse::decode(bytes).map_err(|e: prost::DecodeError| {
        anyhow::anyhow!("failed to deserialize GuestToHostResponse: {e}")
    })?;

    // Then, validate the response to ensure that it matches the expected format.
    validate_response(&res)
        .with_context(|| "failed to validate response in deserialize_response")?;

    Ok(res)
}

/// Validate the invariants of a [`GuestToHostCommand`] to ensure that it matches the
/// expected required protocol format.
pub fn validate_command(command: &GuestToHostCommand) -> anyhow::Result<()> {
    require_field!(command.command)?;

    if let Some(Command::GetDeviceInterfaceInfo(req)) = &command.command {
        require_enum!(req.guest_protocol_type, TdispGuestProtocolType)?;
    } else if let Some(Command::GetTdiReport(req)) = &command.command {
        require_enum!(req.report_type, TdispReportType)?;
    } else if let Some(Command::Unbind(req)) = &command.command {
        require_enum!(req.unbind_reason, TdispGuestUnbindReason)?;
    }

    Ok(())
}

/// Validate the invariants of a [`GuestToHostResponse`] to ensure that it matches the
/// expected required protocol format.
pub fn validate_response(response: &GuestToHostResponse) -> anyhow::Result<()> {
    require_enum!(response.result, TdispGuestOperationErrorCode)?;
    require_enum!(response.tdi_state_before, TdispTdiState)?;
    require_enum!(response.tdi_state_after, TdispTdiState)?;

    // Only require a result field if the response is a success.
    if response.result == TdispGuestOperationErrorCode::Success as i32 {
        require_field!(response.response)?;
        if let Some(Response::GetTdiReport(req)) = &response.response {
            require_enum!(req.report_type, TdispReportType)?;
            if req.report_buffer.is_empty() {
                return Err(anyhow::anyhow!(
                    "proto validation: report_buffer must not be empty"
                ));
            }
        } else if let Some(Response::GetDeviceInterfaceInfo(req)) = &response.response {
            require_field!(req.interface_info)?;
        }
    }

    Ok(())
}

/// Kani-only sibling of [`validate_command`].
///
/// # Why this exists
/// `validate_command` and the `require_field!` / `require_enum!` macros it
/// uses build `anyhow::Error` values via `anyhow::anyhow!(...)` on every
/// failure path. CBMC's reachability analysis includes those failure paths
/// in the goto program even when our harness `kani::assume`s only valid
/// inputs, which drags `Backtrace::capture()` → `std::env::var()` →
/// `core::slice::memchr::memchr_naive` into the model and unwinds memchr
/// for thousands of iterations. (See the doc comment on
/// [`crate::TdispHostStateMachine::transition_state_to_kani`] for the full
/// chain.)
///
/// # What this preserves
/// Line-by-line copy of [`validate_command`]'s decision logic:
///
/// 1. `command.command.is_some()` — same `require_field!` semantics.
/// 2. For each oneof variant carrying a discriminant field, the same
///    "is the i32 a valid `from_i32` discriminant?" check, expressed as
///    `<EnumType>::from_i32(...).is_some()`.
///
/// The decision boundary (which inputs are accepted vs rejected) is
/// **bit-identical** to production.
///
/// # What this abstracts
/// - Error payload (`()` instead of `anyhow::Error`). The harness only
///   checks `is_ok()` / `is_err()`, never inspects the payload string.
#[cfg(kani)]
pub fn validate_command_kani(command: &GuestToHostCommand) -> Result<(), ()> {
    if command.command.is_none() {
        return Err(());
    }
    if let Some(Command::GetDeviceInterfaceInfo(req)) = &command.command {
        if TdispGuestProtocolType::from_i32(req.guest_protocol_type).is_none() {
            return Err(());
        }
    } else if let Some(Command::GetTdiReport(req)) = &command.command {
        if TdispReportType::from_i32(req.report_type).is_none() {
            return Err(());
        }
    } else if let Some(Command::Unbind(req)) = &command.command {
        if TdispGuestUnbindReason::from_i32(req.unbind_reason).is_none() {
            return Err(());
        }
    }
    Ok(())
}

/// Kani-only sibling of [`validate_response`]. Same rationale as
/// [`validate_command_kani`]: the production function uses
/// `anyhow::anyhow!(...)` on every failure path, which is incidental
/// to the property under proof but defeats CBMC.
///
/// # What this preserves
/// Line-by-line copy of [`validate_response`]'s decision logic:
///
/// 1. Three `from_i32` range checks for `result`, `tdi_state_before`,
///    `tdi_state_after`.
/// 2. If `result == Success`: `response.is_some()` check.
/// 3. If response is `GetTdiReport`: report-type discriminant check
///    plus non-empty `report_buffer` check.
/// 4. If response is `GetDeviceInterfaceInfo`: `interface_info.is_some()`
///    check.
#[cfg(kani)]
pub fn validate_response_kani(response: &GuestToHostResponse) -> Result<(), ()> {
    if TdispGuestOperationErrorCode::from_i32(response.result).is_none() {
        return Err(());
    }
    if TdispTdiState::from_i32(response.tdi_state_before).is_none() {
        return Err(());
    }
    if TdispTdiState::from_i32(response.tdi_state_after).is_none() {
        return Err(());
    }
    if response.result == TdispGuestOperationErrorCode::Success as i32 {
        if response.response.is_none() {
            return Err(());
        }
        if let Some(Response::GetTdiReport(req)) = &response.response {
            if TdispReportType::from_i32(req.report_type).is_none() {
                return Err(());
            }
            if req.report_buffer.is_empty() {
                return Err(());
            }
        } else if let Some(Response::GetDeviceInterfaceInfo(req)) = &response.response {
            if req.interface_info.is_none() {
                return Err(());
            }
        }
    }
    Ok(())
}
