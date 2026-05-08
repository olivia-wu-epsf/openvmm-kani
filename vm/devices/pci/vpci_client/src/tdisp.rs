// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TDISP interface implementation for VPCI devices.

use anyhow::Context;
use hvdef::Vtl;
use inspect::Inspect;
use mesh::rpc::RpcSend;
use openhcl_tdisp::GuestToHostCommand;
use openhcl_tdisp::GuestToHostCommandExt;
use openhcl_tdisp::GuestToHostResponse;
use openhcl_tdisp::GuestToHostResponseExt;
use openhcl_tdisp::TdispCommandResponseBind;
use openhcl_tdisp::TdispCommandResponseGetDeviceInterfaceInfo;
use openhcl_tdisp::TdispCommandResponseGetTdiReport;
use openhcl_tdisp::TdispCommandResponseStartTdi;
use openhcl_tdisp::TdispCommandResponseUnbind;
use openhcl_tdisp::TdispDeviceInterfaceInfo;
use openhcl_tdisp::TdispGuestOperationErrorCode;
use openhcl_tdisp::TdispGuestProtocolType;
use openhcl_tdisp::TdispGuestUnbindReason;
use openhcl_tdisp::TdispReportType;
use openhcl_tdisp::TdispVirtualDeviceInterface;
use tdisp::TdispTdiState;
use tdisp::devicereport::TdiReportStruct;
use virt::IsolationType;
use vpci_protocol::MAX_VPCI_TDISP_COMMAND_SIZE;
use vpci_protocol::ResourceIsolation;
use vpci_protocol::SlotNumber;

use super::VpciDevice;
use super::WorkerRequest;
use openhcl_tdisp::TdispResourceValidationInterface;

// Under Kani, swap the two hash-based collections in
// `VpciClientTdispMutableState` for ordered tree-based collections. The
// hash-based ones pull in `std::collections::hash_map::RandomState::new()`
// → `getrandom()`, which is a foreign "C" `syscall` call that Kani
// refuses to model
// (see <https://github.com/model-checking/kani/issues/2423>).
// `BTreeMap`/`BTreeSet` have no such initialisation. The API surface used
// in this file (`.insert`, `.contains`, `.contains_key`, `.iter()` via
// `&map`, `.clear`) is identical between the two collections, so the swap
// is invisible to the rest of the file. The set is tiny (≤6 BAR ids) in
// production so the perf characteristics of the swap are irrelevant for
// the analogous purpose under Kani.
#[cfg(not(kani))]
type MmioBarMap = std::collections::HashMap<u16, ValidatedMmio>;
#[cfg(kani)]
type MmioBarMap = std::collections::BTreeMap<u16, ValidatedMmio>;

#[cfg(not(kani))]
type BarSet = std::collections::HashSet<u16>;
#[cfg(kani)]
type BarSet = std::collections::BTreeSet<u16>;

// Under Kani, the real `tracing` / `tracelimit` crates are absent; bring
// the crate-local no-op shims (defined in `lib.rs`) into scope so paths
// like `tracing::info!()` resolve here instead of failing to find an
// extern crate.
#[cfg(kani)]
use crate::tracelimit;
#[cfg(kani)]
use crate::tracing;
use std::sync::Arc;

/// Abstraction over the path used to send a TDISP command to the host.
///
/// In production this wraps a `mesh::Sender<WorkerRequest>` and goes
/// through the VPCI client's worker task → VMBus → host. Under
/// `cfg(kani)` it can be constructed as a one-shot mock that returns a
/// caller-supplied (typically symbolic) [`GuestToHostResponse`], which
/// is what makes [`VpciClientTdispState::tdisp_bind_interface`] (and
/// peers) tractable to model-check without standing up a full mesh
/// runtime under CBMC.
//
// The `Mesh` variant is gated out under `cfg(kani)` because merely
// having `mesh::Sender<WorkerRequest>` as a field type forces CBMC
// to instantiate the mesh runtime's `LocalNode` thread-local plumbing
// (Drop chains, `pthread_key_create`, `VecDeque::handle_capacity_increase`
// underflow checks). Even though no `Mesh` value is ever constructed
// in the harness, the variant's type alone drags the whole graph in.
pub(super) enum HostChannel {
    /// The production mesh-RPC path through the VPCI client worker.
    #[cfg(not(kani))]
    Mesh(mesh::Sender<WorkerRequest>),
    /// One-shot symbolic response for Kani harnesses. Populated by
    /// [`VpciClientTdispState::kani_new_with_response`]; consumed on
    /// the next [`HostChannel::send`] call.
    //
    // Uses `Cell` rather than `parking_lot::Mutex` because the latter
    // statically pulls in `parking_lot_core::HashTable::new` →
    // `std::thread::Inner` → `pthread_key_create`, which Kani refuses
    // to model. Under CBMC the harness is single-threaded so interior
    // mutability via `Cell` is sufficient. `Cell` is also `!Sync`, but
    // the harness never crosses threads.
    #[cfg(kani)]
    KaniMock(core::cell::Cell<Option<GuestToHostResponse>>),
}

impl HostChannel {
    /// Send a single TDISP command and await the host response.
    async fn send(
        &self,
        cmd: vpci_protocol::VpciTdispCommand,
    ) -> Result<GuestToHostResponse, mesh::rpc::RpcError<mesh::error::RemoteError>> {
        match self {
            #[cfg(not(kani))]
            Self::Mesh(s) => s.call_failable(WorkerRequest::TdispCommand, cmd).await,
            #[cfg(kani)]
            Self::KaniMock(slot) => {
                let _ = cmd;
                // Take any pre-populated response (used by
                // single-call deactivate harnesses). For multi-call
                // (activate-path) harnesses the slot is left empty
                // and the call site in `send_tdisp_command`
                // fabricates a matching-variant response based on
                // the command payload (which the wire-format `cmd`
                // here does not carry under Kani because
                // serialization is elided).
                Ok(slot.take().unwrap_or_else(kani_empty_response))
            }
        }
    }
}

/// Kani-only fabricator: build a fully-symbolic
/// [`GuestToHostResponse`] using `kani::any()` for every primitive
/// field. The `response` oneof is selected from None plus all five
/// matching response variants; payload fields inside each variant
/// are likewise symbolic via `kani::any()`. Vec-shaped fields
/// (e.g. the report buffer) are returned empty because the Kani
/// build elides the corresponding deserializer (see
/// `tdisp_get_tdi_report` and `tdisp_get_tdi_device_id`).
#[cfg(kani)]
fn kani_any_response() -> GuestToHostResponse {
    use openhcl_tdisp::GuestToHostResponseVariantOneof as Resp;

    let response = match kani::any::<u8>() % 6 {
        0 => None,
        1 => Some(Resp::GetDeviceInterfaceInfo(
            TdispCommandResponseGetDeviceInterfaceInfo {
                interface_info: Some(TdispDeviceInterfaceInfo {
                    guest_protocol_type: kani::any(),
                    supported_features: kani::any(),
                    tdisp_device_id: kani::any(),
                }),
            },
        )),
        2 => Some(Resp::Bind(TdispCommandResponseBind {})),
        3 => Some(Resp::GetTdiReport(TdispCommandResponseGetTdiReport {
            report_type: kani::any(),
            report_buffer: Vec::new(),
        })),
        4 => Some(Resp::StartTdi(TdispCommandResponseStartTdi {})),
        _ => Some(Resp::Unbind(TdispCommandResponseUnbind {})),
    };
    GuestToHostResponse {
        result: kani::any(),
        tdi_state_before: kani::any(),
        tdi_state_after: kani::any(),
        response,
    }
}

// ----------------------------------------------------------------------------
// Kani-only audit trail.
//
// Records the (opcode, cached_state_at_issue) of every TDISP command
// issued via [`VpciClientTdispState::send_tdisp_command`]. Used by the
// public-API harnesses in `kani_proofs_highlevel.rs` to express
// internal precondition properties (TVM-1, TVM-2, TVM-3) on a
// black-box surface that returns `()`.
//
// Fixed-size 8-slot array — the activate path issues at most 6
// commands (conditional pre-unbind, GetDeviceInterfaceInfo, Bind,
// StartTdi, GetTdiReport for device id, GetTdiReport for the
// interface report). Held in a `Cell` because the trail is
// snapshot/append from a single `&mut self` send path; harnesses
// read it back after the orchestration call returns.
#[cfg(kani)]
pub(super) const KANI_AUDIT_TRAIL_LEN: usize = 8;

/// Kani-only opcode tag for the audit trail. Values are stable so
/// harnesses can compare against them as plain `u8` literals.
#[cfg(kani)]
#[allow(dead_code)]
pub mod kani_audit_opcode {
    pub const GET_DEVICE_INTERFACE_INFO: u8 = 1;
    pub const BIND: u8 = 2;
    pub const START_TDI: u8 = 3;
    pub const GET_TDI_REPORT: u8 = 4;
    pub const UNBIND: u8 = 5;
    /// Sentinel for unknown/unmapped opcodes (defensive; should not
    /// be reachable in practice).
    pub const UNKNOWN: u8 = 0xFF;
}

/// Map the protobuf [`GuestToHostCommand`] variant to a stable
/// [`kani_audit_opcode`] u8 by matching on the prost-generated
/// `command` oneof discriminant directly. This deliberately avoids
/// `GuestToHostCommandExt::type_name`, whose `match Some("Bind")`
/// arms compile down to slice equality (`<builtin-library-memcmp>`)
/// and force CBMC's universal `--unwind` to the longest literal
/// length (22 chars for "GetDeviceInterfaceInfo"), exploding loop
/// reachability across every harness.
#[cfg(kani)]
fn kani_opcode_id(payload: &GuestToHostCommand) -> u8 {
    use openhcl_tdisp::GuestToHostCommandVariantOneof as Cmd;
    match payload.command {
        Some(Cmd::GetDeviceInterfaceInfo(_)) => kani_audit_opcode::GET_DEVICE_INTERFACE_INFO,
        Some(Cmd::Bind(_)) => kani_audit_opcode::BIND,
        Some(Cmd::StartTdi(_)) => kani_audit_opcode::START_TDI,
        Some(Cmd::GetTdiReport(_)) => kani_audit_opcode::GET_TDI_REPORT,
        Some(Cmd::Unbind(_)) => kani_audit_opcode::UNBIND,
        None => kani_audit_opcode::UNKNOWN,
    }
}

/// Fallback [`GuestToHostResponse`] used by [`HostChannel::send`]
/// when the [`HostChannel::KaniMock`] slot is empty AND the higher
/// call site has not provided a fabricated response. Returns a
/// minimal "no payload, no claimed state" response which the
/// `send_tdisp_command` post-checks treat as an error path. Multi-
/// call activate-path harnesses route through
/// [`VpciClientTdispState::kani_fabricate_for`] instead, which
/// builds a matching-variant Success response based on the prost
/// command discriminant.
#[cfg(kani)]
fn kani_empty_response() -> GuestToHostResponse {
    GuestToHostResponse {
        result: TdispGuestOperationErrorCode::Success as i32,
        tdi_state_before: i32::MIN,
        tdi_state_after: i32::MIN,
        response: None,
    }
}

/// Build a matching-variant Success [`GuestToHostResponse`] for the
/// given outgoing [`GuestToHostCommand`]. `tdi_state_after` is left
/// symbolic via `kani::any()` so harnesses retain the malicious-
/// host degree of freedom for cache-poisoning attacks. The payload
/// fields inside each variant are zero-initialised; the activate
/// orchestration only reads `interface_info` (filled with a fresh
/// `Some(TdispDeviceInterfaceInfo { .. })` carrying the SEV-TIO
/// `guest_protocol_type` so [`VpciClientTdispState::query_capabilities`]
/// reaches its Ok arm) and the report buffers (which are bypassed
/// under Kani \u2014 see `tdisp_get_tdi_report`).
#[cfg(kani)]
fn kani_fabricate_for(payload: &GuestToHostCommand) -> GuestToHostResponse {
    use openhcl_tdisp::GuestToHostCommandVariantOneof as Cmd;
    use openhcl_tdisp::GuestToHostResponseVariantOneof as Resp;
    let response = match payload.command {
        Some(Cmd::GetDeviceInterfaceInfo(_)) => Some(Resp::GetDeviceInterfaceInfo(
            TdispCommandResponseGetDeviceInterfaceInfo {
                interface_info: Some(TdispDeviceInterfaceInfo {
                    guest_protocol_type: TdispGuestProtocolType::AmdSevTioV1 as i32,
                    supported_features: 0,
                    tdisp_device_id: 0,
                }),
            },
        )),
        Some(Cmd::Bind(_)) => Some(Resp::Bind(TdispCommandResponseBind {})),
        Some(Cmd::StartTdi(_)) => Some(Resp::StartTdi(TdispCommandResponseStartTdi {})),
        Some(Cmd::GetTdiReport(_)) => Some(Resp::GetTdiReport(TdispCommandResponseGetTdiReport {
            report_type: 0,
            report_buffer: Vec::new(),
        })),
        Some(Cmd::Unbind(_)) => Some(Resp::Unbind(TdispCommandResponseUnbind {})),
        None => None,
    };
    GuestToHostResponse {
        result: TdispGuestOperationErrorCode::Success as i32,
        tdi_state_before: kani::any(),
        tdi_state_after: kani::any(),
        response,
    }
}

/// TDISP state for a VPCI device.
#[derive(Inspect)]
pub struct VpciClientTdispState {
    #[inspect(skip)]
    host_channel: HostChannel,
    // The device ID if the VPCI channel. Not to be confused with the guest device ID returned by the host in TDISP reports.
    vpci_device_id: u64,
    isolation_type: IsolationType,
    vtom: u64,
    #[inspect(debug)]
    target_vtl: Vtl,
    mutable_state: VpciClientTdispMutableState,
    #[inspect(skip)]
    resource_validator: Option<Arc<dyn TdispResourceValidationInterface>>,
    /// Kani-only audit trail of (opcode, cached state at issue) for
    /// every TDISP command issued. See module-level comment.
    /// Per-element [`core::cell::Cell`]s avoid a whole-array
    /// memcpy on `Cell::set` (which under CBMC pulls
    /// `<builtin-library-memcmp>` into reachability and forces
    /// large unwind values everywhere). Storing opcode and state
    /// as separate `u8` arrays keeps every Cell op a single-byte
    /// write. Sentinel value `0xFF` in `audit_opcode` means
    /// "empty slot" (matches [`kani_audit_opcode::UNKNOWN`]).
    #[cfg(kani)]
    #[inspect(skip)]
    audit_opcode: [core::cell::Cell<u8>; KANI_AUDIT_TRAIL_LEN],
    /// Per-entry cached `TdispTdiState` (encoded as `u8` via the
    /// generated `i32` discriminant truncated; the four valid
    /// values 0..3 fit in `u8`) at the time the matching opcode in
    /// [`Self::audit_opcode`] was issued.
    #[cfg(kani)]
    #[inspect(skip)]
    audit_state: [core::cell::Cell<u8>; KANI_AUDIT_TRAIL_LEN],
    /// Next free index into the audit arrays.
    #[cfg(kani)]
    #[inspect(skip)]
    audit_count: core::cell::Cell<usize>,
}

/// Point-in-time classification of a device's BAR and DMA isolation.
///
/// Returned by [`VpciClientTdispState::isolation_snapshot`] and used to
/// populate `VpciIsolatedResourcesReply` on the paravisor's guest-facing
/// VPCI channel.
#[derive(Debug, Clone, Copy)]
pub enum IsolationSnapshot {
    /// The TDI is not in the `Run` state, or is in `Run` but no resource
    /// has been unblocked yet. The paravisor cannot answer the isolation
    /// query in this state. Callers should map this to an error reply.
    NotReady,
    /// The TDI is in `Run` and at least one BAR or DMA has been unblocked.
    /// BAR entries may be `SHARED`, `PRIVATE`, or `INVALID` (for BAR IDs
    /// outside the device's known range, e.g. upper halves of 64-bit
    /// BARs). `dma` is always `SHARED` or `PRIVATE`.
    Ready {
        /// Classification for each of the device's six BARs.
        bars: [ResourceIsolation; 6],
        /// Classification for the device's DMA path.
        dma: ResourceIsolation,
    },
}

#[derive(Inspect)]
struct VpciClientTdispMutableState {
    tdi_state: TdispTdiState,
    guest_device_id: u16,
    /// Map of BAR ID to the `(base_gpa, length_in_bytes)` that was passed
    /// to `tdisp_unblock_mmio`. Populated on unblock and used during
    /// unbind to call `tdisp_block_mmio` with the same parameters so
    /// private pages can be flipped back to shared. Cleared on unbind.
    #[inspect(iter_by_key)]
    validated_mmio_bars: MmioBarMap,
    /// Whether DMA has been unblocked via `tdisp_unblock_dma`. Cleared on
    /// unbind so that DMA is re-unblocked after re-attestation.
    dma_unblocked: bool,
    /// The most recently obtained TDI interface report, populated during attestation.
    /// Cleared on unbind so that it is re-fetched after re-attestation.
    #[inspect(debug)]
    tdi_report: Option<TdiReportStruct>,
    /// Set of BAR IDs whose MMIO pages are intercepted (e.g. a BAR that hosts
    /// the MSI-X table / PBA emulated by the host). These pages are not backed
    /// by convertible guest RAM on the host.
    #[inspect(iter_by_index)]
    intercepted_bars: BarSet,
    /// Cached result of the first successful `query_capabilities` call.
    /// The capabilities of a device are static across the VM's lifetime,
    /// so we cache the first successful response to avoid re-issuing the
    /// host command on every subsequent activation.
    #[inspect(skip)]
    #[cfg_attr(not(feature = "dev_snp_ohcl_tio_support"), allow(dead_code))]
    cached_capabilities: Option<TdispDeviceInterfaceInfo>,
}

/// Tracks the parameters used to unblock a BAR's MMIO pages, so the same
/// range can be re-blocked on unbind.
#[derive(Inspect, Clone, Copy, Debug)]
struct ValidatedMmio {
    #[inspect(hex)]
    base_gpa: u64,
    #[inspect(hex)]
    length_in_bytes: u32,
}

impl VpciClientTdispMutableState {
    fn update_tdi_state(&mut self, new_state: TdispTdiState) {
        tracing::info!(
            old_state = %self.tdi_state,
            new_state = %new_state,
            "updating TDI state based on host response"
        );
        self.tdi_state = new_state;
    }

    fn update_guest_device_id(&mut self, new_device_id: u16) {
        tracing::info!(
            old_device_id = self.guest_device_id,
            new_device_id = new_device_id,
            "updating guest device ID based on host response"
        );
        self.guest_device_id = new_device_id;
    }
}

/// Manages the TDISP protocol for a TDISP-capable VPCI device.
impl VpciClientTdispState {
    // The production constructor takes a `mesh::Sender<WorkerRequest>`,
    // which is gated out of the Kani build along with the matching
    // `HostChannel::Mesh` variant. Under Kani, the harness builds the
    // state via `kani_new_with_response` (below) instead.
    #[cfg(not(kani))]
    pub(super) fn new(
        worker_req: mesh::Sender<WorkerRequest>,
        device_id: u64,
        resource_validator: Option<Arc<dyn TdispResourceValidationInterface>>,
        isolation_type: IsolationType,
        vtom: u64,
        target_vtl: Vtl,
    ) -> Self {
        Self {
            host_channel: HostChannel::Mesh(worker_req),
            vpci_device_id: device_id,
            mutable_state: VpciClientTdispMutableState {
                tdi_state: TdispTdiState::Uninitialized,
                guest_device_id: 0,
                validated_mmio_bars: MmioBarMap::new(),
                dma_unblocked: false,
                tdi_report: None,
                intercepted_bars: BarSet::new(),
                cached_capabilities: None,
            },
            isolation_type,
            vtom,
            target_vtl,
            resource_validator,
        }
    }

    /// Get the TDI state returned by the host for the most recent operation.
    fn tdi_state(&self) -> TdispTdiState {
        self.mutable_state.tdi_state
    }

    pub(super) async fn send_tdisp_command(
        &mut self,
        payload: GuestToHostCommand,
    ) -> crate::Result<GuestToHostResponse> {
        // Kani audit trail: record the (opcode, cached state at issue)
        // BEFORE issuing the host call, so harnesses asserting
        // precondition-gate properties (TVM-1, TVM-2, TVM-3) can
        // observe each transmitted command's entry-state from the
        // public API surface.
        #[cfg(kani)]
        {
            let op = kani_opcode_id(&payload);
            let st = self.mutable_state.tdi_state as u8;
            let idx = self.audit_count.get();
            if idx < KANI_AUDIT_TRAIL_LEN {
                self.audit_opcode[idx].set(op);
                self.audit_state[idx].set(st);
                self.audit_count.set(idx + 1);
            }
        }

        // Wire-format serialization is auxiliary I/O plumbing that
        // the verifier does not need to reason about (and prost's
        // varint encoding + Vec growth dominates CBMC reachability,
        // pulling in `alloc::raw_vec::handle_error`,
        // `std::alloc::handle_alloc_error::rt_error`, and the full
        // `Layout`/`TryReserveError` chain). Under Kani we elide it
        // entirely and pass an empty payload — the `KaniMock` host
        // channel ignores `cmd` anyway.
        #[cfg(not(kani))]
        let serialized = openhcl_tdisp::serialize_command(&payload);
        #[cfg(kani)]
        let serialized: Vec<u8> = Vec::new();

        // Ensure that the length does not exceed the VMBUS maximum packet size.
        // This shouldn't be possible since the host should reject the command anyways,
        // but fail earlier for safety.
        #[cfg(not(kani))]
        if serialized.len() > MAX_VPCI_TDISP_COMMAND_SIZE {
            return Err(crate::err!(
                "serialized TDISP command exceeds VMBUS maximum packet size ({} > {})",
                serialized.len(),
                MAX_VPCI_TDISP_COMMAND_SIZE
            ));
        }

        // Send the TDISP command to the host (in production, through
        // the VPCI client worker → VMBus → host) and await the
        // response.
        #[cfg(not(kani))]
        let res = self
            .host_channel
            .send(vpci_protocol::VpciTdispCommand {
                header: vpci_protocol::VpciTdispCommandHeader {
                    message_type: vpci_protocol::MessageType::VPCI_TDISP_COMMAND,
                    slot: SlotNumber::from_bits(self.vpci_device_id as u32),
                    data_length: serialized.len() as u64,
                },
                data: serialized,
            })
            .await
            .map_err(|err: mesh::rpc::RpcError<mesh::error::RemoteError>| {
                tracing::error!(
                    error = &err as &dyn std::error::Error,
                    "failed to send tdisp command"
                );
                crate::err!("failed to send tdisp command")
            })?;

        // Kani fast path: bypass [`HostChannel::send`] entirely so
        // we can fabricate a matching-variant response based on the
        // outgoing payload (the wire-format `VpciTdispCommand`
        // doesn't carry the prost discriminant since serialization
        // is elided under Kani). Single-call deactivate harnesses
        // pre-populate the slot via `kani_new_with_response`/peers;
        // multi-call activate-path harnesses leave it `None` and
        // [`kani_fabricate_for`] supplies a `Success` + matching-
        // variant response for each step of the orchestration.
        #[cfg(kani)]
        let res = match &self.host_channel {
            HostChannel::KaniMock(slot) => slot
                .take()
                .unwrap_or_else(|| kani_fabricate_for(&payload)),
        };

        // Record state transitions based on the TDI state returned by the host in the response, if available.
        match res.tdi_state_after_enum() {
            Some(state) => self.mutable_state.update_tdi_state(state),
            None => tracing::warn!("host did not return valid TDI state in response"),
        }

        match res.error_code() {
            Some(TdispGuestOperationErrorCode::Success) => Ok(res),
            other => {
                tracing::error!(
                    error_code = ?other,
                    result = res.result,
                    command = ?payload.type_name(),
                    "send_tdisp_command failed because host responded with an error"
                );
                Err(crate::err!(
                    "send_tdisp_command {:?} failed because host responded with an error: {:?}",
                    payload.type_name(),
                    other
                ))
            }
        }
    }

    /// See: [`TdispVirtualDeviceInterface::tdisp_get_device_interface_info`]
    #[cfg(not(kani))]
    pub async fn tdisp_get_device_interface_info(
        &mut self,
        target_protocol: TdispGuestProtocolType,
    ) -> anyhow::Result<TdispDeviceInterfaceInfo> {
        let res = self
            .send_tdisp_command(openhcl_tdisp::new_get_device_interface_info_command(
                self.vpci_device_id,
                target_protocol,
            ))
            .await?;

        match res.response::<TdispCommandResponseGetDeviceInterfaceInfo>() {
            Ok(info) => info.interface_info.ok_or_else(|| {
                anyhow::anyhow!("missing interface_info after validation, this should never happen")
            }),
            Err(err) => Err(anyhow::anyhow!(
                "error response in get_device_interface_info: {err}"
            )),
        }
    }

    /// Kani forwarder: returns `crate::Result` so the inner body can
    /// avoid `anyhow::Error` Drop chains that otherwise dominate
    /// CBMC reachability. See `kani-debugging.md` "anyhow contagion".
    #[cfg(kani)]
    pub async fn tdisp_get_device_interface_info(
        &mut self,
        target_protocol: TdispGuestProtocolType,
    ) -> crate::Result<TdispDeviceInterfaceInfo> {
        let res = self
            .send_tdisp_command(openhcl_tdisp::new_get_device_interface_info_command(
                self.vpci_device_id,
                target_protocol,
            ))
            .await?;

        match res.response::<TdispCommandResponseGetDeviceInterfaceInfo>() {
            Ok(info) => info
                .interface_info
                .ok_or_else(|| crate::err!("missing interface_info")),
            Err(_) => Err(crate::err!("error response in get_device_interface_info")),
        }
    }

    /// See: [`TdispVirtualDeviceInterface::tdisp_bind_interface`]
    pub async fn tdisp_bind_interface(&mut self) -> crate::Result<()> {
        let state_before = self.tdi_state();
        let res = self
            .send_tdisp_command(openhcl_tdisp::new_bind_command(self.vpci_device_id))
            .await?;

        // The host should have transitioned the device to the Bind state if the bind was successful.
        match self.tdi_state() {
            TdispTdiState::Locked => {
                tracing::info!("device successfully transitioned to Bind state after bind command")
            }
            state_after => {
                tracing::error!(
                    %state_before,
                    state_after = %state_after,
                    "device is in unexpected TDI state after bind command, expected Locked"
                );
                return Err(crate::err!(
                    "device is in unexpected TDI state after bind command, expected Locked"
                ));
            }
        }

        match res.response::<TdispCommandResponseBind>() {
            Ok(_) => Ok(()),
            Err(err) => Err(crate::err!("error response in tdisp_bind_interface: {err}")),
        }
    }

    /// See: [`TdispVirtualDeviceInterface::tdisp_start_device`]
    #[cfg(not(kani))]
    pub async fn tdisp_start_device(&mut self) -> anyhow::Result<()> {
        self.tdisp_start_device_inner().await
    }

    /// Kani forwarder: returns `crate::Result` so the inner body can
    /// avoid `anyhow::Error` Drop chains that otherwise dominate
    /// CBMC reachability. See `kani-debugging.md` "anyhow contagion".
    #[cfg(kani)]
    pub async fn tdisp_start_device(&mut self) -> crate::Result<()> {
        self.tdisp_start_device_inner().await
    }

    async fn tdisp_start_device_inner(&mut self) -> crate::Result<()> {
        let state_before = self.tdi_state();
        let res = self
            .send_tdisp_command(openhcl_tdisp::new_start_tdi_command(self.vpci_device_id))
            .await?;

        match self.tdi_state() {
            TdispTdiState::Run => {
                tracing::info!("device successfully transitioned to Run state after start command")
            }
            state_after => {
                tracing::error!(
                    %state_before,
                    state_after = %state_after,
                    "device is in unexpected TDI state after start command, expected Run"
                );
                return Err(crate::err!(
                    "device is in unexpected TDI state after start command, expected Run"
                ));
            }
        }

        match res.response::<TdispCommandResponseStartTdi>() {
            Ok(_) => Ok(()),
            Err(err) => Err(crate::err!("error response in tdisp_start_device: {err}")),
        }
    }

    /// See: [`TdispVirtualDeviceInterface::tdisp_get_device_report`]
    #[cfg(not(kani))]
    pub async fn tdisp_get_device_report(
        &mut self,
        report_type: &TdispReportType,
    ) -> anyhow::Result<Vec<u8>> {
        self.tdisp_get_device_report_inner(report_type).await
    }

    /// Kani forwarder. See `kani-debugging.md` "anyhow contagion".
    #[cfg(kani)]
    pub async fn tdisp_get_device_report(
        &mut self,
        report_type: &TdispReportType,
    ) -> crate::Result<Vec<u8>> {
        self.tdisp_get_device_report_inner(report_type).await
    }

    async fn tdisp_get_device_report_inner(
        &mut self,
        report_type: &TdispReportType,
    ) -> crate::Result<Vec<u8>> {
        let res = self
            .send_tdisp_command(openhcl_tdisp::new_get_tdi_report_command(
                self.vpci_device_id,
                *report_type,
            ))
            .await?;

        match res.response::<TdispCommandResponseGetTdiReport>() {
            Ok(r) => Ok(r.report_buffer),
            Err(err) => Err(crate::err!(
                "error response in tdisp_get_device_report: {err}"
            )),
        }
    }

    /// See: [`TdispVirtualDeviceInterface::tdisp_get_tdi_report`]
    #[cfg(not(kani))]
    pub async fn tdisp_get_tdi_report(&mut self) -> anyhow::Result<TdiReportStruct> {
        let buffer = self
            .tdisp_get_device_report(&TdispReportType::InterfaceReport)
            .await
            .context("failed to get TDI report")?;

        tdisp::devicereport::deserialize_tdi_report(&buffer)
            .context("failed to deserialize TDI report from host")
    }

    /// Kani-only variant: skips the prost-like report deserializer,
    /// which iterates over the response `Vec<u8>` and pulls
    /// `alloc::raw_vec::handle_error` plus `Layout`/`TryReserveError`
    /// into CBMC reachability. The harness only cares that an
    /// activate path drives **some** report through, so we issue the
    /// host command (so the audit trail records the
    /// `GetTdiReport` opcode + cached state at issue) and then
    /// fabricate a synthetic [`TdiReportStruct`] with an empty MMIO
    /// list — enough for downstream `mmio_interface_info`
    /// iteration and `tdi_report = Some(...)` bookkeeping to run
    /// faithfully.
    #[cfg(kani)]
    pub async fn tdisp_get_tdi_report(&mut self) -> crate::Result<TdiReportStruct> {
        let _ = self
            .tdisp_get_device_report(&TdispReportType::InterfaceReport)
            .await?;
        Ok(TdiReportStruct {
            interface_info: tdisp::devicereport::TdispTdiReportInterfaceInfo::new(),
            msi_x_message_control: 0,
            lnr_control: 0,
            tph_control: 0,
            mmio_interface_info: Vec::new(),
        })
    }

    /// See: [`TdispVirtualDeviceInterface::tdisp_get_tdi_device_id`]
    #[cfg(not(kani))]
    pub async fn tdisp_get_tdi_device_id(&mut self) -> anyhow::Result<u64> {
        let buffer = self
            .tdisp_get_device_report(&TdispReportType::GuestDeviceId)
            .await
            .context("failed to get TDI device ID")?;

        // Ensure it's a u64
        if buffer.len() != size_of::<u64>() {
            return Err(anyhow::anyhow!("unexpected buffer size for TDI device ID"));
        }

        Ok(u64::from_le_bytes(buffer.try_into().unwrap()))
    }

    /// Kani-only variant: skips the `try_into() / from_le_bytes`
    /// dance (which under symbolic `Vec<u8>` lengths drags
    /// `TryFromSliceError`/`unwrap` panic paths into CBMC) and
    /// returns a fresh `kani::any::<u64>()` symbolic device id.
    /// The host command is still sent so the audit trail captures
    /// it.
    #[cfg(kani)]
    pub async fn tdisp_get_tdi_device_id(&mut self) -> crate::Result<u64> {
        let _ = self
            .tdisp_get_device_report(&TdispReportType::GuestDeviceId)
            .await?;
        Ok(kani::any::<u64>())
    }

    /// See: [`TdispVirtualDeviceInterface::tdisp_unbind`]
    #[cfg(not(kani))]
    pub async fn tdisp_unbind(&mut self, reason: TdispGuestUnbindReason) -> anyhow::Result<()> {
        self.tdisp_unbind_inner(reason, /* clear_cached_report = */ true)
            .await
    }

    /// Kani forwarder for [`Self::tdisp_unbind`]. See
    /// `kani-debugging.md` "anyhow contagion".
    #[cfg(kani)]
    pub async fn tdisp_unbind(&mut self, reason: TdispGuestUnbindReason) -> crate::Result<()> {
        self.tdisp_unbind_inner(reason, /* clear_cached_report = */ true)
            .await
    }

    /// Same as [`Self::tdisp_unbind`], but preserves the cached
    /// `tdi_report` and `intercepted_bars` so that
    /// [`Self::isolation_snapshot`] can continue to classify BAR/DMA
    /// isolation while the TDI sits in the `Unlocked` state awaiting a
    /// guest-initiated re-attestation.
    ///
    /// Host-side per-bind state (`validated_mmio_bars`, `dma_unblocked`)
    /// is still cleared, since that bookkeeping is specific to a single
    /// bind/attest cycle and will be rebuilt when the guest drives
    /// attestation again.
    #[cfg(not(kani))]
    pub async fn tdisp_unbind_preserve_report(
        &mut self,
        reason: TdispGuestUnbindReason,
    ) -> anyhow::Result<()> {
        self.tdisp_unbind_inner(reason, /* clear_cached_report = */ false)
            .await
    }

    /// Kani forwarder for [`Self::tdisp_unbind_preserve_report`]. Returns
    /// `crate::Result<()>` to keep `anyhow::Error` Drop chains
    /// (`Backtrace`, `dyn std::error::Error`) out of CBMC reachability.
    /// See `kani-debugging.md` "anyhow contagion".
    #[cfg(kani)]
    pub async fn tdisp_unbind_preserve_report(
        &mut self,
        reason: TdispGuestUnbindReason,
    ) -> crate::Result<()> {
        self.tdisp_unbind_inner(reason, /* clear_cached_report = */ false)
            .await
    }

    async fn tdisp_unbind_inner(
        &mut self,
        reason: TdispGuestUnbindReason,
        clear_cached_report: bool,
    ) -> crate::Result<()> {
        // Flip all unblocked MMIO ranges and DMA back to shared before
        // we tell the host to unbind the TDI. This is best-effort: a
        // failure here is logged but doesn't abort the unbind, because
        // the channel is already being torn down and the host-side TDI
        // state is our only source of truth for what remains bound.
        if let Some(validator) = self.resource_validator.clone() {
            let device_id = self.mutable_state.guest_device_id;
            for (bar_id, mmio) in &self.mutable_state.validated_mmio_bars {
                // length == 0 is the "classified SHARED, never unblocked"
                // sentinel meaning there is nothing to block.
                if mmio.length_in_bytes == 0 {
                    continue;
                }
                if let Err(e) = validator.tdisp_block_mmio(
                    self.target_vtl,
                    device_id,
                    mmio.base_gpa,
                    0,
                    mmio.length_in_bytes,
                    *bar_id,
                ) {
                    tracing::error!(
                        bar_id,
                        base_gpa = format_args!("{:#x}", mmio.base_gpa),
                        length_in_bytes = mmio.length_in_bytes,
                        error = &*e as &dyn std::error::Error,
                        "tdisp_unbind: failed to re-block MMIO range"
                    );
                }
            }

            if self.mutable_state.dma_unblocked {
                if let Err(e) = validator.tdisp_block_dma(self.target_vtl, device_id) {
                    tracing::error!(
                        device_id,
                        error = &*e as &dyn std::error::Error,
                        "tdisp_unbind: failed to re-block DMA"
                    );
                }
            }
        }

        let res = self
            .send_tdisp_command(openhcl_tdisp::new_unbind_command(
                self.vpci_device_id,
                reason,
            ))
            .await?;

        match res.response::<TdispCommandResponseUnbind>() {
            Ok(_) => {
                // Under Kani, `BTreeMap::clear` dispatches to its
                // `IntoIter` Drop, whose symbolic loops blow up
                // CBMC's unwinding budget (the `Dying` /
                // `deallocating_end` traversals at unwind=9). The
                // map is constructed empty in the activate-path
                // harnesses, so skipping the call has no effect on
                // the property under verification.
                #[cfg(not(kani))]
                self.mutable_state.validated_mmio_bars.clear();
                self.mutable_state.dma_unblocked = false;
                if clear_cached_report {
                    self.mutable_state.tdi_report = None;
                }
                Ok(())
            }
            Err(err) => Err(crate::err!("error response in tdisp_unbind: {err}")),
        }
    }

    /// Detects TDISP capabilities for the device. If the device supports TDISP
    /// and a guest protocol type that we support given the current VM's
    /// isolation level, then returns the interface info. Otherwise, returns an
    /// error representing why the device is not suitable for TDISP.
    ///
    /// Caches the first successful result on the state. Device
    /// capabilities are static across the VM's lifetime, so subsequent
    /// calls return the cached copy without issuing another host
    /// command. A failure is not cached, so the next call will retry.
    #[cfg(feature = "dev_snp_ohcl_tio_support")]
    pub async fn query_capabilities(&mut self) -> anyhow::Result<TdispDeviceInterfaceInfo> {
        if let Some(cached) = self.mutable_state.cached_capabilities.as_ref() {
            tracing::debug!(
                ?cached,
                "query_capabilities: returning cached device interface info"
            );
            return Ok(cached.clone());
        }

        tracing::info!(
            ?self.isolation_type,
            "querying TDISP capabilities for device given VM isolation type"
        );

        let target_protocol = match self.isolation_type {
            IsolationType::Snp => TdispGuestProtocolType::AmdSevTioV1,
            IsolationType::Tdx => {
                tracing::warn!(
                    "query_capabilities: VM is running with TDX isolation (NOT SUPPORTED)"
                );
                anyhow::bail!("TDX isolation is not currently supported for TDISP")
            }
            IsolationType::Vbs => {
                tracing::warn!(
                    "query_capabilities: VM is running with VBS isolation (NOT SUPPORTED)"
                );
                anyhow::bail!("VBS isolation is not currently supported for TDISP")
            }
            IsolationType::None => {
                tracing::warn!("query_capabilities: VM is running with no isolation (no TDISP)");
                anyhow::bail!("TDISP is not supported without isolation")
            }
        };

        let device_interface_info = self
            .tdisp_get_device_interface_info(target_protocol)
            .await
            .context("tdisp_query_capabilities: failed to get device interface info")?;

        tracing::info!(
            ?device_interface_info,
            "tdisp_query_capabilities: device interface info",
        );

        // TDISP TODO: Support TDX
        let expected_guest_protocol = TdispGuestProtocolType::AmdSevTioV1;
        if device_interface_info.guest_protocol_type == expected_guest_protocol as i32 {
            tracing::info!(
                ?device_interface_info.guest_protocol_type,
                "tdisp_query_capabilities: TDISP is supported",
            );

            self.mutable_state.cached_capabilities = Some(device_interface_info.clone());
            Ok(device_interface_info)
        } else {
            tracing::info!(
                ?device_interface_info.guest_protocol_type,
                ?expected_guest_protocol,
                "tdisp_query_capabilities: device does not support a guest protocol we support",
            );

            anyhow::bail!("device does not support expected guest protocol we support");
        }
    }

    #[cfg(all(not(feature = "dev_snp_ohcl_tio_support"), not(kani)))]
    /// See: [`TdispVpciAttestationInterface::tdisp_attest_device`]
    pub async fn query_capabilities(&mut self) -> anyhow::Result<TdispDeviceInterfaceInfo> {
        anyhow::bail!("TDISP feature not enabled during compile time")
    }

    /// Kani-only [`Self::query_capabilities`] returning
    /// [`crate::Result`] to keep anyhow Drop chains out of CBMC
    /// reachability. Mirrors the SEV-feature-gated production body
    /// closely enough that the audit trail records the
    /// `GetDeviceInterfaceInfo` opcode at the cached state at issue,
    /// then returns either the cached info or a freshly-fabricated
    /// symbolic [`TdispDeviceInterfaceInfo`]. The harness pre-sets
    /// `IsolationType::Snp` so the production gate reads the same
    /// way as on real hardware.
    #[cfg(kani)]
    pub async fn query_capabilities(&mut self) -> crate::Result<TdispDeviceInterfaceInfo> {
        if let Some(cached) = self.mutable_state.cached_capabilities.as_ref() {
            return Ok(cached.clone());
        }

        // Only `Snp` is a supported guest protocol; bail symmetrically
        // for any other isolation type so harnesses that exercise the
        // failure edge can still drive it.
        let target_protocol = match self.isolation_type {
            IsolationType::Snp => TdispGuestProtocolType::AmdSevTioV1,
            _ => return Err(crate::err!("unsupported isolation type")),
        };

        let device_interface_info = self
            .tdisp_get_device_interface_info(target_protocol)
            .await?;

        let expected_guest_protocol = TdispGuestProtocolType::AmdSevTioV1;
        if device_interface_info.guest_protocol_type == expected_guest_protocol as i32 {
            self.mutable_state.cached_capabilities = Some(device_interface_info.clone());
            Ok(device_interface_info)
        } else {
            Err(crate::err!("protocol mismatch"))
        }
    }

    /// See: [`TdispVpciAttestationInterface::tdisp_attest_device`]
    #[cfg(not(kani))]
    pub async fn attest(&mut self, interface_info: TdispDeviceInterfaceInfo) -> anyhow::Result<()> {
        tracing::info!(
            ?interface_info,
            "tdisp_attest_device: beginning attestation flow"
        );

        // The host-side state machine only accepts Bind from Unlocked. If
        // the TDI is in any other state (e.g. Locked from a partial prior
        // attempt, or Run from a previous attest cycle), issue a full
        // tdisp_unbind first to reset the host state. Use `tdisp_unbind`
        // (not `tdisp_unbind_preserve_report`) so all per-bind bookkeeping
        // is cleared before the new attestation rebuilds it.
        if self.tdi_state() != TdispTdiState::Unlocked {
            tracing::info!(
                current_state = %self.tdi_state(),
                "tdisp_attest_device: TDI not in Unlocked, unbinding before rebind"
            );
            self.tdisp_unbind(TdispGuestUnbindReason::Graceful)
                .await
                .context("tdisp_attest_device: failed to unbind before rebind")?;
        }

        self.tdisp_bind_interface()
            .await
            .context("tdisp_attest_device: failed to bind device interface")?;

        // get report
        // check report

        self.tdisp_start_device()
            .await
            .context("tdisp_attest_device: failed to start device")?;

        // Request the guest device ID to use in firmware calls to unblock resources
        let guest_device_id = self
            .tdisp_get_tdi_device_id()
            .await
            .context("tdisp_attest_device: failed to get TDI device ID after starting device")?;

        // Platforms require a u16 device ID even though the report returns a
        // u64. Ensure the returned device ID fits within that constraint before
        // proceeding.
        let guest_device_id_u16 = u16::try_from(guest_device_id)
            .context("tdisp_attest_device: guest device ID must fit within u16")?;

        // Fetch and save the TDI interface report so callers can inspect the
        // attested device's reported capabilities and MMIO ranges.
        let tdi_report = self.tdisp_get_tdi_report().await.context(
            "tdisp_attest_device: failed to get TDI interface report after starting device",
        )?;

        tracing::info!(
            ?tdi_report,
            %guest_device_id,
            "tdisp_attest_device: device attestation flow completed successfully, waiting on resources to be assigned"
        );

        self.mutable_state
            .update_guest_device_id(guest_device_id_u16);

        // Auto-mark any MMIO range that the device reports as mapping the MSI-X
        // table or PBA as intercepted. Intercepted BARs are not backed by RAM
        // on the host and therefore cannot be made private.
        for range in &tdi_report.mmio_interface_info {
            if range.flags.range_maps_msix_table() || range.flags.range_maps_msix_pba() {
                tracing::info!(
                    bar_id = range.range_id,
                    maps_msix_table = range.flags.range_maps_msix_table(),
                    maps_msix_pba = range.flags.range_maps_msix_pba(),
                    "auto-marking MSI-X table/PBA BAR as intercepted based on TDI report"
                );
                self.mutable_state.intercepted_bars.insert(range.range_id);
            }
        }

        self.mutable_state.tdi_report = Some(tdi_report);

        // Device is now in the Run state without resource validation being
        // performed. Platform specific validation methods will be called on
        // command register write to unblock resources.
        Ok(())
    }

    /// Kani-only [`Self::attest`] returning [`crate::Result`].
    ///
    /// Mirrors the production attestation orchestration:
    /// (1) precautionary `tdisp_unbind` if cached state is not Unlocked,
    /// (2) bind, (3) start, (4) get device id, (5) get + cache report,
    /// (6) auto-mark MSI-X-mapped BARs as intercepted.
    ///
    /// The interior calls all dispatch to the matching
    /// `crate::Result` Kani forwarders (`tdisp_unbind`,
    /// `tdisp_bind_interface`, `tdisp_start_device`,
    /// `tdisp_get_tdi_device_id`, `tdisp_get_tdi_report`), so the
    /// bridge into anyhow happens only at the public-API boundary in
    /// `lib.rs`. CBMC therefore never observes [`anyhow::Error`]
    /// construction inside the orchestration loop.
    #[cfg(kani)]
    pub async fn attest(&mut self, interface_info: TdispDeviceInterfaceInfo) -> crate::Result<()> {
        let _ = interface_info;

        if self.tdi_state() != TdispTdiState::Unlocked {
            self.tdisp_unbind(TdispGuestUnbindReason::Graceful).await?;
        }

        self.tdisp_bind_interface().await?;
        self.tdisp_start_device().await?;

        let guest_device_id = self.tdisp_get_tdi_device_id().await?;
        let guest_device_id_u16 =
            u16::try_from(guest_device_id).map_err(|_| crate::err!("device id overflow"))?;

        let tdi_report = self.tdisp_get_tdi_report().await?;

        self.mutable_state
            .update_guest_device_id(guest_device_id_u16);

        for range in &tdi_report.mmio_interface_info {
            if range.flags.range_maps_msix_table() || range.flags.range_maps_msix_pba() {
                self.mutable_state.intercepted_bars.insert(range.range_id);
            }
        }

        self.mutable_state.tdi_report = Some(tdi_report);
        Ok(())
    }

    /// Get the TDI state of the device. This is used for testing and validation purposes, and is not part of the standard TDISP flow.
    pub fn tdisp_get_tdi_state(&self) -> TdispTdiState {
        self.tdi_state()
    }

    /// Query the platform firmware (when available) for the current TDI
    /// state of the device, bypassing the paravisor's cached
    /// [`Self::tdi_state`]. Returns `Ok(None)` if no resource validator is
    /// attached or the validator does not support direct firmware queries
    /// (e.g. non-SEV platforms).
    ///
    /// Use this to sanity-check the cached state before issuing
    /// state-sensitive TDISP commands.
    pub fn tdisp_query_firmware_tdi_state(&self) -> anyhow::Result<Option<TdispTdiState>> {
        let Some(validator) = self.resource_validator.as_ref() else {
            return Ok(None);
        };
        validator.tdisp_query_firmware_tdi_state(self.mutable_state.guest_device_id)
    }

    /// Mark a BAR as being intercepted and virtualized by the paravisor
    /// (e.g. a BAR whose memory is registered as [`BarMemoryKind::Intercept`]).
    /// The classic case is the MSI-X table / PBA BAR, which is handled
    /// entirely inside the paravisor's VPCI layer and has no host-side
    /// backing page.
    ///
    /// `tdisp_on_mmio_reconfigured` must NOT call `tdisp_unblock_mmio` on
    /// such a BAR: the underlying `HvCallModifySparseGpaPageHostVisibility`
    /// hypercall on a non-convertible GPA terminates the partition. This
    /// provides the paravisor a way to tell TDISP "I handle this BAR, leave
    /// it alone" before any guest configuration occurs.
    ///
    /// Intentionally intercept-vs-not is a static property of the device's
    /// emulator, so this state is *not* cleared on unbind.
    pub fn mark_bar_intercepted(&mut self, bar_id: u16) {
        if self.mutable_state.intercepted_bars.insert(bar_id) {
            tracing::info!(
                bar_id,
                "marking BAR as intercepted; TDISP MMIO unblock will be skipped for this BAR"
            );
        }
    }

    /// Returns true if the given BAR has been marked intercepted
    /// via [`Self::mark_bar_intercepted`].
    pub fn is_bar_intercepted(&self, bar_id: u16) -> bool {
        self.mutable_state.intercepted_bars.contains(&bar_id)
    }

    /// Classify a single BAR's isolation, based solely on the cached TDI
    /// interface report and `intercepted_bars`.
    ///
    /// This is the single source of truth used by both
    /// [`Self::isolation_snapshot`] and [`Self::tdisp_on_mmio_reconfigured`]:
    /// a BAR whose classification here is `PRIVATE` is exactly one that
    /// `tdisp_on_mmio_reconfigured` will call `tdisp_unblock_mmio` for;
    /// `SHARED` is skipped. `INVALID` means the BAR has no entry in the
    /// cached report (or there is no cached report yet).
    fn classify_bar(&self, bar_id: u16) -> ResourceIsolation {
        // Host-intercepted BARs (MSI-X table / PBA) have no host-RAM
        // backing and can never be flipped private, so always SHARED,
        // independent of what the report says.
        if self.mutable_state.intercepted_bars.contains(&bar_id) {
            return ResourceIsolation::SHARED;
        }

        // No cached report yet (attestation hasn't run) → we don't know
        // if this BAR is claimed at all, so INVALID rather than SHARED.
        let Some(report) = self.mutable_state.tdi_report.as_ref() else {
            return ResourceIsolation::INVALID;
        };

        // `range_id` == PCI BAR index for the guest protocols we
        // support. A missing entry is an unused slot or the upper half
        // of a 64-bit BAR (not reported independently).
        let Some(range) = report
            .mmio_interface_info
            .iter()
            .find(|r| r.range_id == bar_id)
        else {
            return ResourceIsolation::INVALID;
        };

        // `is_non_tee_mem` ranges have no protected backing and must
        // never be passed to `tdisp_unblock_mmio`. Report SHARED and
        // skip. Everything else is TEE memory the TDI owns → PRIVATE.
        if range.flags.is_non_tee_mem() {
            ResourceIsolation::SHARED
        } else {
            ResourceIsolation::PRIVATE
        }
    }

    /// Classify BAR and DMA isolation for this device at this instant,
    /// suitable for populating a `VpciIsolatedResourcesReply` on the
    /// guest-facing side.
    ///
    /// Returns [`IsolationSnapshot::NotReady`] iff no TDI interface
    /// report has been cached yet (attestation has not run). Once a
    /// report is cached, always returns `Ready`, including after a
    /// `tdisp_unbind_preserve_report` has returned the TDI to
    /// `Unlocked`. Classification mirrors the logic that
    /// [`Self::tdisp_on_mmio_reconfigured`] applies when the guest
    /// enables MMIO: a BAR is `PRIVATE` exactly when
    /// `tdisp_unblock_mmio` would be called for it, `SHARED` when it
    /// would be skipped, and `INVALID` when the cached TDI report has
    /// no entry for it.
    ///
    /// DMA classification rules:
    /// - `PRIVATE` iff `dma_unblocked` is true.
    /// - `SHARED` otherwise.
    pub fn isolation_snapshot(&self) -> IsolationSnapshot {
        if self.mutable_state.tdi_report.is_none() {
            return IsolationSnapshot::NotReady;
        }

        let mut bars = [ResourceIsolation::INVALID; 6];
        for bar_id in 0..6u16 {
            bars[bar_id as usize] = self.classify_bar(bar_id);
        }

        let dma = if self.mutable_state.dma_unblocked {
            ResourceIsolation::PRIVATE
        } else {
            ResourceIsolation::SHARED
        };

        IsolationSnapshot::Ready { bars, dma }
    }

    /// Called when a BAR MMIO range is reconfigured by the guest. If a resource
    /// validator is present, unblocks the MMIO range for the device.
    ///
    /// Consults the TDI interface report saved during attestation to decide
    /// whether the MMIO range actually requires validation. Ranges whose
    /// `is_non_tee_mem` flag is set are not protected memory and must NOT be
    /// passed to `tdisp_unblock_mmio`; only ranges with `is_non_tee_mem` clear
    /// are validated.
    ///
    /// BARs that the paravisor has marked as intercepted (see
    /// [`Self::mark_bar_intercepted`]) are skipped unconditionally, because these
    /// pages have no host-side RAM backing and must never be flipped to
    /// private.
    ///
    /// # Arguments
    ///
    /// * `bar_id` - The BAR index being configured. Matched against the
    ///   `range_id` of the MMIO ranges reported in the TDI interface report.
    /// * `base_address` - The base guest physical address of the MMIO range.
    /// * `length` - The length in bytes of the MMIO range.
    //
    // Under Kani the return type is the unit-error `crate::Result` to
    // keep `anyhow::Error`'s Drop chain (`Backtrace`,
    // `dyn std::error::Error`) out of CBMC reachability. Production
    // builds keep the original `anyhow::Result`.
    #[cfg(not(kani))]
    pub fn tdisp_on_mmio_reconfigured(
        &mut self,
        bar_id: u16,
        base_address: u64,
        length: u32,
    ) -> anyhow::Result<()> {
        self.tdisp_on_mmio_reconfigured_inner(bar_id, base_address, length)
    }

    #[cfg(kani)]
    pub fn tdisp_on_mmio_reconfigured(
        &mut self,
        bar_id: u16,
        base_address: u64,
        length: u32,
    ) -> crate::Result<()> {
        self.tdisp_on_mmio_reconfigured_inner(bar_id, base_address, length)
    }

    /// Inner implementation of [`Self::tdisp_on_mmio_reconfigured`].
    /// The return type alias `crate::Result` resolves to `anyhow::Result`
    /// in production and to a unit-error `Result` under Kani; either way
    /// the body is identical.
    fn tdisp_on_mmio_reconfigured_inner(
        &mut self,
        bar_id: u16,
        base_address: u64,
        length: u32,
    ) -> crate::Result<()> {
        if let Some(validator) = &self.resource_validator {
            // If the device is not attested and in Run state, don't attempt to unblock resources
            if self.tdi_state() != TdispTdiState::Run {
                tracing::warn!(
                    bar_id,
                    base_address,
                    length,
                    "ignoring MMIO reconfiguration callback because device is not in Run state"
                );
                return Ok(());
            }

            if self.mutable_state.validated_mmio_bars.contains_key(&bar_id) {
                tracing::debug!(
                    bar_id,
                    "skipping MMIO unblock for BAR that has already been validated"
                );
                return Ok(());
            }

            match self.classify_bar(bar_id) {
                ResourceIsolation::SHARED => {
                    tracing::info!(
                        bar_id,
                        base_address,
                        length,
                        "skipping MMIO unblock for BAR classified SHARED \
                         (intercepted or non-TEE memory)"
                    );
                    // Record with a zero-length entry so we don't repeatedly
                    // fall through here on subsequent reconfigurations. The
                    // unbind path uses length == 0 as a sentinel for "no
                    // block call needed."
                    //
                    // Under Kani, BTreeMap::insert blows up CBMC's SAT
                    // formula (12k+ VCCs from btree node manipulation).
                    // The harnesses don't observe the map; skip the insert.
                    #[cfg(not(kani))]
                    self.mutable_state.validated_mmio_bars.insert(
                        bar_id,
                        ValidatedMmio {
                            base_gpa: base_address,
                            length_in_bytes: 0,
                        },
                    );
                    return Ok(());
                }
                ResourceIsolation::INVALID => {
                    return Err(crate::err!(
                        "tdisp_on_mmio_reconfigured: BAR {bar_id} has no entry in \
                         the TDI interface report (or report not available); \
                         device has not been attested"
                    ));
                }
                ResourceIsolation::PRIVATE => {}
                other => {
                    return Err(crate::err!(
                        "tdisp_on_mmio_reconfigured: unexpected BAR {bar_id} \
                         classification {:?}",
                        other
                    ));
                }
            }

            let device_id = self.mutable_state.guest_device_id;

            // The `?` paths below propagate `anyhow::Error` whose
            // `Drop` impl drags `Backtrace`/`std::error::Error` into
            // CBMC reachability and explodes the SAT formula. Under
            // Kani the recording validator never errs, so we can
            // discard the result without altering the verified
            // property. Production builds keep the original error
            // propagation.
            #[cfg(not(kani))]
            validator.tdisp_unblock_mmio(
                self.target_vtl,
                device_id,
                base_address,
                0,
                length,
                bar_id,
            )?;
            #[cfg(kani)]
            let _ = validator.tdisp_unblock_mmio(
                self.target_vtl,
                device_id,
                base_address,
                0,
                length,
                bar_id,
            );
            // See note above re: BTreeMap and CBMC.
            #[cfg(not(kani))]
            self.mutable_state.validated_mmio_bars.insert(
                bar_id,
                ValidatedMmio {
                    base_gpa: base_address,
                    length_in_bytes: length,
                },
            );

            // After the first successful MMIO unblock following attestation,
            // unblock DMA as well so the device can issue DMA traffic to the
            // guest. Guard with `dma_unblocked` so it only fires once per
            // bind/attest cycle (cleared on unbind).
            if !self.mutable_state.dma_unblocked {
                #[cfg(not(kani))]
                validator
                    .tdisp_unblock_dma(self.target_vtl, device_id)
                    .context("tdisp_on_mmio_reconfigured: failed to unblock DMA")?;
                #[cfg(kani)]
                let _ = validator.tdisp_unblock_dma(self.target_vtl, device_id);
                self.mutable_state.dma_unblocked = true;
                tracing::info!(device_id, "tdisp_on_mmio_reconfigured: DMA unblocked");
            }

            Ok(())
        } else {
            Ok(())
        }
    }

    /// Construct a [`VpciClientTdispState`] backed by a one-shot
    /// symbolic [`HostChannel::KaniMock`]. The next call to
    /// [`Self::send_tdisp_command`] (or any of the higher-level
    /// methods that wrap it) will receive `response` as the host's
    /// reply, with no real mesh / VMBus / async runtime involved.
    ///
    /// The cached `tdi_state` is initialised to `tdi_state_before` so
    /// the harness can model an arbitrary starting cached state.
    /// `resource_validator` is left `None` — the resource-validator
    /// path is exercised by separate harnesses.
    #[cfg(kani)]
    pub fn kani_new_with_response(
        tdi_state_before: TdispTdiState,
        response: GuestToHostResponse,
    ) -> Self {
        Self {
            host_channel: HostChannel::KaniMock(core::cell::Cell::new(Some(response))),
            vpci_device_id: 0,
            mutable_state: VpciClientTdispMutableState {
                tdi_state: tdi_state_before,
                guest_device_id: 0,
                validated_mmio_bars: MmioBarMap::new(),
                dma_unblocked: false,
                tdi_report: None,
                intercepted_bars: BarSet::new(),
                cached_capabilities: None,
            },
            isolation_type: IsolationType::Snp,
            vtom: 0,
            target_vtl: Vtl::Vtl0,
            resource_validator: None,
            audit_opcode: [const { core::cell::Cell::new(kani_audit_opcode::UNKNOWN) };
                KANI_AUDIT_TRAIL_LEN],
            audit_state: [const { core::cell::Cell::new(0u8) }; KANI_AUDIT_TRAIL_LEN],
            audit_count: core::cell::Cell::new(0),
        }
    }

    /// Snapshot the current cached `tdi_state`. Used by Kani harnesses
    /// to assert post-conditions on
    /// [`VpciClientTdispState::tdisp_bind_interface`] (and peers).
    #[cfg(kani)]
    pub fn kani_tdi_state(&self) -> TdispTdiState {
        self.mutable_state.tdi_state
    }

    /// Snapshot of the Kani audit trail — for each populated slot,
    /// returns `Some((opcode, cached_state_at_issue))` (state encoded
    /// as `u8` via the generated `i32` discriminant truncated; the
    /// four valid values 0..3 fit in `u8`). Empty slots return
    /// `None`. Returns the full fixed-size array so harnesses can
    /// iterate without bounds-checking.
    #[cfg(kani)]
    pub fn kani_audit_trail(&self) -> [Option<(u8, u8)>; KANI_AUDIT_TRAIL_LEN] {
        // Fully unrolled — no runtime loop — to keep the universal
        // CBMC `--unwind` value low (avoids exploding BTreeMap and
        // other downstream loops to large unwind counts).
        let n = self.audit_count.get();
        let g = |i: usize| -> Option<(u8, u8)> {
            if i < n {
                Some((self.audit_opcode[i].get(), self.audit_state[i].get()))
            } else {
                None
            }
        };
        [g(0), g(1), g(2), g(3), g(4), g(5), g(6), g(7)]
    }

    /// Construct a [`VpciClientTdispState`] for activate-path
    /// (multi-call) Kani harnesses. The [`HostChannel::KaniMock`]
    /// slot is left empty so every [`Self::send_tdisp_command`] call
    /// goes through [`kani_fabricate_for`], which returns a Success
    /// + matching-variant response with a symbolic `tdi_state_after`
    /// per call. Pre-populates [`IsolationType::Snp`] so
    /// [`Self::query_capabilities`] reaches its Ok arm. The
    /// [`TdispDeviceInterfaceInfo`] cache is also pre-populated so
    /// the activate orchestration's first `query_capabilities` call
    /// is fully deterministic and the subsequent attest steps are
    /// what actually drive the audit trail.
    #[cfg(kani)]
    pub fn kani_new_for_activate(tdi_state_before: TdispTdiState) -> Self {
        Self {
            host_channel: HostChannel::KaniMock(core::cell::Cell::new(None)),
            vpci_device_id: 0,
            mutable_state: VpciClientTdispMutableState {
                tdi_state: tdi_state_before,
                guest_device_id: 0,
                validated_mmio_bars: MmioBarMap::new(),
                dma_unblocked: false,
                tdi_report: None,
                intercepted_bars: BarSet::new(),
                cached_capabilities: Some(TdispDeviceInterfaceInfo {
                    guest_protocol_type: TdispGuestProtocolType::AmdSevTioV1 as i32,
                    supported_features: 0,
                    tdisp_device_id: 0,
                }),
            },
            isolation_type: IsolationType::Snp,
            vtom: 0,
            target_vtl: Vtl::Vtl0,
            resource_validator: None,
            audit_opcode: [const { core::cell::Cell::new(kani_audit_opcode::UNKNOWN) };
                KANI_AUDIT_TRAIL_LEN],
            audit_state: [const { core::cell::Cell::new(0u8) }; KANI_AUDIT_TRAIL_LEN],
            audit_count: core::cell::Cell::new(0),
        }
    }

    /// Construct a [`VpciClientTdispState`] for verifying the
    /// synchronous [`Self::tdisp_on_mmio_reconfigured`] gate. Unlike
    /// [`Self::kani_new_with_response`], this constructor takes a
    /// resource validator so the harness can observe whether the gate
    /// fires `tdisp_unblock_mmio` / `tdisp_unblock_dma`. The
    /// [`HostChannel::KaniMock`] slot is left empty because the
    /// synchronous reconfigure path never sends a TDISP command.
    ///
    /// Inputs let the harness drive each gate predicate independently:
    /// `tdi_state`, presence of a TDI report (with one symbolic
    /// range), whether `bar_id` is in `intercepted_bars`, whether
    /// `bar_id` is already in `validated_mmio_bars`, and the prior
    /// value of `dma_unblocked`.
    #[cfg(kani)]
    pub fn kani_new_for_mmio_reconfigured(
        tdi_state: TdispTdiState,
        tdi_report: Option<TdiReportStruct>,
        bar_id: u16,
        intercepted: bool,
        validated_already: bool,
        dma_unblocked_before: bool,
        validator: Arc<dyn TdispResourceValidationInterface>,
    ) -> Self {
        let mut validated_mmio_bars = MmioBarMap::new();
        if validated_already {
            validated_mmio_bars.insert(
                bar_id,
                ValidatedMmio {
                    base_gpa: 0,
                    length_in_bytes: 0,
                },
            );
        }
        let mut intercepted_bars = BarSet::new();
        if intercepted {
            intercepted_bars.insert(bar_id);
        }
        Self {
            host_channel: HostChannel::KaniMock(core::cell::Cell::new(None)),
            vpci_device_id: 0,
            mutable_state: VpciClientTdispMutableState {
                tdi_state,
                guest_device_id: 0,
                validated_mmio_bars,
                dma_unblocked: dma_unblocked_before,
                tdi_report,
                intercepted_bars,
                cached_capabilities: None,
            },
            isolation_type: IsolationType::None,
            vtom: 0,
            target_vtl: Vtl::Vtl0,
            resource_validator: Some(validator),
            audit_opcode: [const { core::cell::Cell::new(kani_audit_opcode::UNKNOWN) };
                KANI_AUDIT_TRAIL_LEN],
            audit_state: [const { core::cell::Cell::new(0u8) }; KANI_AUDIT_TRAIL_LEN],
            audit_count: core::cell::Cell::new(0),
        }
    }

    /// Snapshot of the cached `dma_unblocked` flag for Kani harnesses
    /// to assert post-conditions on [`Self::tdisp_on_mmio_reconfigured`].
    #[cfg(kani)]
    pub fn kani_dma_unblocked(&self) -> bool {
        self.mutable_state.dma_unblocked
    }

    /// Snapshot of `validated_mmio_bars.is_empty()` for Kani harnesses
    /// asserting F-13 / F-14 post-conditions on the unbind path.
    #[cfg(kani)]
    pub fn kani_validated_mmio_bars_is_empty(&self) -> bool {
        self.mutable_state.validated_mmio_bars.is_empty()
    }

    /// Snapshot of `tdi_report.is_some()` for Kani harnesses asserting
    /// F-13 (full unbind clears report) and F-14
    /// (`tdisp_unbind_preserve_report` keeps report bytes).
    #[cfg(kani)]
    pub fn kani_tdi_report_is_some(&self) -> bool {
        self.mutable_state.tdi_report.is_some()
    }

    /// Construct a [`VpciClientTdispState`] for verifying that
    /// [`Self::tdisp_unbind`] re-blocks every previously-unblocked
    /// MMIO range plus DMA before sending the host the unbind
    /// command.
    ///
    /// Pre-populates a single `validated_mmio_bars` entry with the
    /// caller-supplied `bar_id`, `base_gpa`, and `length_in_bytes`
    /// (mirroring "host previously reconfigured BAR `bar_id` with a
    /// length-`length_in_bytes` PRIVATE range, paravisor unblocked
    /// it and recorded it"). The single-entry `BTreeMap` keeps CBMC
    /// reachability bounded.
    #[cfg(kani)]
    pub fn kani_new_for_unbind(
        tdi_state: TdispTdiState,
        bar_id: u16,
        base_gpa: u64,
        length_in_bytes: u32,
        dma_unblocked_before: bool,
        response: GuestToHostResponse,
        validator: Arc<dyn TdispResourceValidationInterface>,
    ) -> Self {
        let mut validated_mmio_bars = MmioBarMap::new();
        validated_mmio_bars.insert(
            bar_id,
            ValidatedMmio {
                base_gpa,
                length_in_bytes,
            },
        );
        Self {
            host_channel: HostChannel::KaniMock(core::cell::Cell::new(Some(response))),
            vpci_device_id: 0,
            mutable_state: VpciClientTdispMutableState {
                tdi_state,
                guest_device_id: 0,
                validated_mmio_bars,
                dma_unblocked: dma_unblocked_before,
                tdi_report: None,
                intercepted_bars: BarSet::new(),
                cached_capabilities: None,
            },
            isolation_type: IsolationType::None,
            vtom: 0,
            target_vtl: Vtl::Vtl0,
            resource_validator: Some(validator),
            audit_opcode: [const { core::cell::Cell::new(kani_audit_opcode::UNKNOWN) };
                KANI_AUDIT_TRAIL_LEN],
            audit_state: [const { core::cell::Cell::new(0u8) }; KANI_AUDIT_TRAIL_LEN],
            audit_count: core::cell::Cell::new(0),
        }
    }

    /// Like [`Self::kani_new_for_unbind`] but additionally lets the
    /// caller pre-populate `tdi_report`, so harnesses for F-13
    /// (`tdisp_unbind` clears the report) and F-14
    /// (`tdisp_unbind_preserve_report` keeps it) can observe what
    /// happens to the report on the Ok path.
    #[cfg(kani)]
    pub fn kani_new_for_unbind_with_report(
        tdi_state: TdispTdiState,
        bar_id: u16,
        base_gpa: u64,
        length_in_bytes: u32,
        dma_unblocked_before: bool,
        tdi_report: Option<TdiReportStruct>,
        response: GuestToHostResponse,
        validator: Arc<dyn TdispResourceValidationInterface>,
    ) -> Self {
        let mut validated_mmio_bars = MmioBarMap::new();
        validated_mmio_bars.insert(
            bar_id,
            ValidatedMmio {
                base_gpa,
                length_in_bytes,
            },
        );
        Self {
            host_channel: HostChannel::KaniMock(core::cell::Cell::new(Some(response))),
            vpci_device_id: 0,
            mutable_state: VpciClientTdispMutableState {
                tdi_state,
                guest_device_id: 0,
                validated_mmio_bars,
                dma_unblocked: dma_unblocked_before,
                tdi_report,
                intercepted_bars: BarSet::new(),
                cached_capabilities: None,
            },
            isolation_type: IsolationType::None,
            vtom: 0,
            target_vtl: Vtl::Vtl0,
            resource_validator: Some(validator),
            audit_opcode: [const { core::cell::Cell::new(kani_audit_opcode::UNKNOWN) };
                KANI_AUDIT_TRAIL_LEN],
            audit_state: [const { core::cell::Cell::new(0u8) }; KANI_AUDIT_TRAIL_LEN],
            audit_count: core::cell::Cell::new(0),
        }
    }

    /// Test-only constructor used by the bug-demonstration tests in
    /// `attack_tests.rs`. Mirrors the production `new` constructor but
    /// also lets the caller pre-populate the cached `tdi_state`,
    /// `tdi_report`, `validated_mmio_bars`, and `dma_unblocked` fields
    /// so each attack scenario can be expressed without having to drive
    /// the full attestation handshake first.
    ///
    /// `validated_mmio_bars` is a list of `(bar_id, base_gpa,
    /// length_in_bytes)` triples that get inserted into the
    /// `validated_mmio_bars` map.
    #[cfg(test)]
    pub(crate) fn test_new_with_state(
        worker_req: mesh::Sender<WorkerRequest>,
        resource_validator: Option<Arc<dyn TdispResourceValidationInterface>>,
        tdi_state: TdispTdiState,
        tdi_report: Option<TdiReportStruct>,
        validated_mmio_bars: Vec<(u16, u64, u32)>,
        dma_unblocked: bool,
    ) -> Self {
        let mut bars = MmioBarMap::new();
        for (bar_id, base_gpa, length_in_bytes) in validated_mmio_bars {
            bars.insert(
                bar_id,
                ValidatedMmio {
                    base_gpa,
                    length_in_bytes,
                },
            );
        }
        Self {
            host_channel: HostChannel::Mesh(worker_req),
            vpci_device_id: 0,
            mutable_state: VpciClientTdispMutableState {
                tdi_state,
                guest_device_id: 0,
                validated_mmio_bars: bars,
                dma_unblocked,
                tdi_report,
                intercepted_bars: BarSet::new(),
                cached_capabilities: None,
            },
            isolation_type: IsolationType::None,
            vtom: 0,
            target_vtl: Vtl::Vtl0,
            resource_validator,
        }
    }

    /// Test-only accessor for the cached `tdi_state`.
    #[cfg(test)]
    pub(crate) fn test_tdi_state(&self) -> TdispTdiState {
        self.mutable_state.tdi_state
    }

    /// Test-only accessor for the cached `tdi_report.is_some()`.
    #[cfg(test)]
    pub(crate) fn test_tdi_report_is_some(&self) -> bool {
        self.mutable_state.tdi_report.is_some()
    }
}

// The `TdispVirtualDeviceInterface` trait impl on `VpciDevice` is
// gated out under Kani: the harness drives `VpciClientTdispState`'s
// inherent methods directly, and the trait impl returns `anyhow::Result`,
// which would otherwise force a `From<crate::Error> for anyhow::Error`
// conversion that defeats the err-shim's purpose.
#[cfg(not(kani))]
impl TdispVirtualDeviceInterface for VpciDevice {
    async fn send_tdisp_command(
        &self,
        payload: GuestToHostCommand,
    ) -> Result<GuestToHostResponse, anyhow::Error> {
        let mut guard = self.tdisp.0.lock().await;
        guard.send_tdisp_command(payload).await
    }

    async fn tdisp_get_device_interface_info(
        &self,
        target_protocol: TdispGuestProtocolType,
    ) -> anyhow::Result<TdispDeviceInterfaceInfo> {
        let mut guard = self.tdisp.0.lock().await;
        guard.tdisp_get_device_interface_info(target_protocol).await
    }

    async fn tdisp_bind_interface(&self) -> anyhow::Result<()> {
        let mut guard = self.tdisp.0.lock().await;
        guard.tdisp_bind_interface().await
    }

    async fn tdisp_start_device(&self) -> anyhow::Result<()> {
        let mut guard = self.tdisp.0.lock().await;
        #[cfg(not(kani))]
        {
            guard.tdisp_start_device().await
        }
        #[cfg(kani)]
        {
            guard
                .tdisp_start_device()
                .await
                .map_err(|_| anyhow::anyhow!("tdisp_start_device failed"))
        }
    }

    async fn tdisp_get_device_report(
        &self,
        report_type: &TdispReportType,
    ) -> anyhow::Result<Vec<u8>> {
        let mut guard = self.tdisp.0.lock().await;
        #[cfg(not(kani))]
        {
            guard.tdisp_get_device_report(report_type).await
        }
        #[cfg(kani)]
        {
            guard
                .tdisp_get_device_report(report_type)
                .await
                .map_err(|_| anyhow::anyhow!("tdisp_get_device_report failed"))
        }
    }

    async fn tdisp_get_tdi_report(&self) -> anyhow::Result<TdiReportStruct> {
        let mut guard = self.tdisp.0.lock().await;
        guard.tdisp_get_tdi_report().await
    }

    async fn tdisp_get_tdi_device_id(&self) -> anyhow::Result<u64> {
        let mut guard = self.tdisp.0.lock().await;
        guard.tdisp_get_tdi_device_id().await
    }

    async fn tdisp_unbind(&self, reason: TdispGuestUnbindReason) -> anyhow::Result<()> {
        let mut guard = self.tdisp.0.lock().await;
        #[cfg(not(kani))]
        {
            guard.tdisp_unbind(reason).await
        }
        #[cfg(kani)]
        {
            guard
                .tdisp_unbind(reason)
                .await
                .map_err(|_| anyhow::anyhow!("tdisp_unbind failed"))
        }
    }
}

/// Higher level interface for TDISP operations on a VPCI device.
#[allow(async_fn_in_trait)]
pub trait TdispVpciAttestationInterface: Sync + Send {
    /// Attests the device using the TDISP flow. This includes binding the
    /// device, starting it, and any other validation steps on reports that are
    /// necessary for the device to be considered attested.
    ///
    /// This is a higher level function that wraps the lower level TDISP
    /// operations such as bind and start, and is designed to be called by
    /// higher level code that just wants to attest the device without needing
    /// to orchestrate the individual steps of the TDISP flow.
    ///
    /// Resources will remain locked until the guest calls platform-specific validation
    /// methods to unblock them (e.g. SEV platform firmware calls). This method does not perform those
    /// validation steps.
    ///
    /// The resulting device state will be Run if attestation is successful (Ok() is returned), or
    /// Unlocked if attestation fails (Err() is returned).
    async fn tdisp_attest_device(
        &self,
        interface_info: TdispDeviceInterfaceInfo,
    ) -> anyhow::Result<()>;

    /// Detects TDISP capabilities for the device. If the device supports TDISP
    /// and a guest protocol type that we support given the current VM's
    /// isolation level, then returns the interface info. Otherwise, returns an
    /// error representing why the device is not suitable for TDISP.
    async fn tdisp_query_capabilities(&self) -> anyhow::Result<TdispDeviceInterfaceInfo>;

    /// Get the TDI state of the device. This is used for testing and validation purposes, and is not part of the standard TDISP flow.
    async fn tdisp_tdi_state(&self) -> TdispTdiState;

    /// Query the platform firmware for the current TDI state of the
    /// device, bypassing the paravisor's cached state. Returns `Ok(None)`
    /// if the platform does not support direct firmware queries.
    async fn tdisp_query_firmware_tdi_state(&self) -> anyhow::Result<Option<TdispTdiState>>;

    /// Called when a BAR MMIO range is reconfigured by the guest. If a resource
    /// validator is present, unblocks the MMIO range for the device.
    ///
    /// # Arguments
    ///
    /// * `bar_id` - The BAR index being configured.
    /// * `base_address` - The base guest physical address of the MMIO range.
    /// * `length` - The length in bytes of the MMIO range.
    async fn tdisp_on_mmio_reconfigured(
        &self,
        bar_id: u16,
        base_address: u64,
        length: u32,
    ) -> anyhow::Result<()>;

    /// Mark a BAR as paravisor-intercepted so that TDISP will skip calling
    /// `tdisp_unblock_mmio` on it during MMIO reconfiguration. Use this for
    /// BARs whose memory is registered as a paravisor MMIO intercept region
    /// (e.g. the MSI-X table / PBA BAR) and therefore has no host-side RAM
    /// backing that could be flipped to private.
    async fn tdisp_mark_bar_intercepted(&self, bar_id: u16);

    /// Return a classification of BAR and DMA isolation for this device.
    /// Callers on the guest-facing VPCI channel use this to synthesize the
    /// `VpciIsolatedResourcesReply` for `VPCI_QUERY_ISOLATED_RESOURCES`.
    async fn tdisp_isolation_snapshot(&self) -> IsolationSnapshot;

    /// Unbind the TDI on the host side while preserving the cached TDI
    /// interface report. After this call, [`Self::tdisp_isolation_snapshot`]
    /// can still return a classified snapshot even though the TDI has been
    /// returned to `Unlocked`. Used by the relay to re-arm the device for
    /// guest-driven attestation after pre-warming the report at init.
    async fn tdisp_unbind_preserve_report(
        &self,
        reason: TdispGuestUnbindReason,
    ) -> anyhow::Result<()>;
}

impl TdispVpciAttestationInterface for VpciDevice {
    async fn tdisp_attest_device(
        &self,
        interface_info: TdispDeviceInterfaceInfo,
    ) -> anyhow::Result<()> {
        let mut guard = self.tdisp.0.lock().await;
        #[cfg(not(kani))]
        {
            guard.attest(interface_info).await
        }
        #[cfg(kani)]
        {
            guard
                .attest(interface_info)
                .await
                .map_err(|_| anyhow::anyhow!("attest failed"))
        }
    }

    async fn tdisp_query_capabilities(&self) -> anyhow::Result<TdispDeviceInterfaceInfo> {
        let mut guard = self.tdisp.0.lock().await;
        #[cfg(not(kani))]
        {
            guard.query_capabilities().await
        }
        #[cfg(kani)]
        {
            guard
                .query_capabilities()
                .await
                .map_err(|_| anyhow::anyhow!("query_capabilities failed"))
        }
    }

    async fn tdisp_tdi_state(&self) -> TdispTdiState {
        let guard = self.tdisp.0.lock().await;
        guard.tdi_state()
    }

    async fn tdisp_query_firmware_tdi_state(&self) -> anyhow::Result<Option<TdispTdiState>> {
        let guard = self.tdisp.0.lock().await;
        guard.tdisp_query_firmware_tdi_state()
    }

    async fn tdisp_on_mmio_reconfigured(
        &self,
        bar_id: u16,
        base_address: u64,
        length: u32,
    ) -> anyhow::Result<()> {
        let mut guard = self.tdisp.0.lock().await;
        #[cfg(not(kani))]
        {
            guard.tdisp_on_mmio_reconfigured(bar_id, base_address, length)
        }
        #[cfg(kani)]
        {
            guard
                .tdisp_on_mmio_reconfigured(bar_id, base_address, length)
                .map_err(|_| anyhow::anyhow!("tdisp_on_mmio_reconfigured failed"))
        }
    }

    async fn tdisp_mark_bar_intercepted(&self, bar_id: u16) {
        let mut guard = self.tdisp.0.lock().await;
        guard.mark_bar_intercepted(bar_id);
    }

    async fn tdisp_isolation_snapshot(&self) -> IsolationSnapshot {
        let guard = self.tdisp.0.lock().await;
        guard.isolation_snapshot()
    }

    async fn tdisp_unbind_preserve_report(
        &self,
        reason: TdispGuestUnbindReason,
    ) -> anyhow::Result<()> {
        let mut guard = self.tdisp.0.lock().await;
        #[cfg(not(kani))]
        {
            guard.tdisp_unbind_preserve_report(reason).await
        }
        #[cfg(kani)]
        {
            guard
                .tdisp_unbind_preserve_report(reason)
                .await
                .map_err(|_| anyhow::anyhow!("tdisp_unbind_preserve_report failed"))
        }
    }
}

impl VpciDevice {
    /// Non-blocking variant of
    /// [`TdispVpciAttestationInterface::tdisp_isolation_snapshot`] for
    /// synchronous callers (e.g. the guest-facing VPCI channel dispatch
    /// thread, which cannot await).
    ///
    /// Returns `None` if the TDISP mutex is contended. All vpci packets
    /// for a given device are serialized through the same VMBus channel
    /// worker, so this lock should not be contended during normal
    /// guest-driven queries. Contention indicates an internal bug and
    /// callers should treat it as an error.
    pub fn tdisp_try_isolation_snapshot(&self) -> Option<IsolationSnapshot> {
        self.tdisp
            .0
            .try_lock()
            .map(|guard| guard.isolation_snapshot())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tdisp::devicereport::TdispTdiReportInterfaceInfo;
    use tdisp::devicereport::TdispTdiReportMmioFlags;
    use tdisp::devicereport::TdispTdiReportMmioInterfaceInfo;

    /// Build a `VpciClientTdispState` with default fields and a dangling
    /// worker sender. `send_tdisp_command` must not be called on the
    /// returned value, but `isolation_snapshot` and the mutable-state
    /// fields it inspects are safe to poke directly.
    fn new_state() -> VpciClientTdispState {
        let (worker_req, _worker_recv) = mesh::channel::<WorkerRequest>();
        VpciClientTdispState::new(
            worker_req,
            /* device_id = */ 0,
            /* resource_validator = */ None,
            IsolationType::None,
            /* vtom = */ 0,
            Vtl::Vtl0,
        )
    }

    /// Build a minimal `TdiReportStruct` containing only the given
    /// `mmio_interface_info` ranges, enough for `isolation_snapshot`.
    fn make_report(ranges: Vec<TdispTdiReportMmioInterfaceInfo>) -> TdiReportStruct {
        TdiReportStruct {
            interface_info: TdispTdiReportInterfaceInfo::new(),
            msi_x_message_control: 0,
            lnr_control: 0,
            tph_control: 0,
            mmio_interface_info: ranges,
        }
    }

    fn tee_range(range_id: u16) -> TdispTdiReportMmioInterfaceInfo {
        TdispTdiReportMmioInterfaceInfo {
            first_4k_page_offset: 0,
            num_4k_pages: 1,
            flags: TdispTdiReportMmioFlags::new().with_is_non_tee_mem(false),
            range_id,
        }
    }

    fn non_tee_range(range_id: u16) -> TdispTdiReportMmioInterfaceInfo {
        TdispTdiReportMmioInterfaceInfo {
            first_4k_page_offset: 0,
            num_4k_pages: 1,
            flags: TdispTdiReportMmioFlags::new().with_is_non_tee_mem(true),
            range_id,
        }
    }

    #[test]
    fn isolation_snapshot_not_ready_without_report() {
        // No cached TDI report → NotReady, regardless of TDI state.
        let state = new_state();
        assert!(matches!(
            state.isolation_snapshot(),
            IsolationSnapshot::NotReady
        ));

        let mut state = new_state();
        state.mutable_state.tdi_state = TdispTdiState::Run;
        assert!(matches!(
            state.isolation_snapshot(),
            IsolationSnapshot::NotReady
        ));
    }

    #[test]
    fn isolation_snapshot_ready_with_empty_report() {
        // Cached (empty) report → Ready; every BAR INVALID, DMA SHARED.
        // No TDI-state requirement.
        let mut state = new_state();
        state.mutable_state.tdi_report = Some(make_report(vec![]));
        let IsolationSnapshot::Ready { bars, dma } = state.isolation_snapshot() else {
            panic!("expected Ready");
        };
        assert_eq!(bars, [ResourceIsolation::INVALID; 6]);
        assert_eq!(dma, ResourceIsolation::SHARED);
    }

    #[test]
    fn isolation_snapshot_classifies_report_ranges() {
        // BAR 0: TEE memory → PRIVATE.
        // BAR 2: non-TEE memory → SHARED.
        // BAR 4: TEE memory but intercepted → SHARED.
        // BARs 1, 3, 5: no entry → INVALID.
        let mut state = new_state();
        state.mutable_state.intercepted_bars.insert(4);
        state.mutable_state.tdi_report = Some(make_report(vec![
            tee_range(0),
            non_tee_range(2),
            tee_range(4),
        ]));
        let IsolationSnapshot::Ready { bars, dma } = state.isolation_snapshot() else {
            panic!("expected Ready");
        };
        assert_eq!(
            bars,
            [
                ResourceIsolation::PRIVATE,
                ResourceIsolation::INVALID,
                ResourceIsolation::SHARED,
                ResourceIsolation::INVALID,
                ResourceIsolation::SHARED,
                ResourceIsolation::INVALID,
            ]
        );
        assert_eq!(dma, ResourceIsolation::SHARED);
    }

    #[test]
    fn isolation_snapshot_dma_private_after_unblock() {
        let mut state = new_state();
        state.mutable_state.tdi_report = Some(make_report(vec![]));
        state.mutable_state.dma_unblocked = true;
        let IsolationSnapshot::Ready { bars, dma } = state.isolation_snapshot() else {
            panic!("expected Ready");
        };
        assert_eq!(bars, [ResourceIsolation::INVALID; 6]);
        assert_eq!(dma, ResourceIsolation::PRIVATE);
    }

    /// Simulates the post-`tdisp_unbind_preserve_report` state: the cached
    /// report and intercepted-BAR markings survive the unbind, while
    /// `dma_unblocked` and `validated_mmio_bars` are cleared. The resulting
    /// snapshot should still classify BARs against the cached report (so
    /// `QueryIsolatedResources` can answer) even though the TDI has been
    /// returned to `Unlocked`.
    #[test]
    fn isolation_snapshot_ready_after_preserving_report() {
        let mut state = new_state();
        state.mutable_state.intercepted_bars.insert(4);
        state.mutable_state.tdi_report = Some(make_report(vec![
            tee_range(0),
            non_tee_range(2),
            tee_range(4),
        ]));

        // Pretend the device was in Run and is now Unlocked after a
        // preserve-report unbind. `validated_mmio_bars` and
        // `dma_unblocked` are cleared; `tdi_report` and
        // `intercepted_bars` survive.
        state.mutable_state.tdi_state = TdispTdiState::Unlocked;
        state.mutable_state.validated_mmio_bars.clear();
        state.mutable_state.dma_unblocked = false;

        let IsolationSnapshot::Ready { bars, dma } = state.isolation_snapshot() else {
            panic!("expected Ready even in Unlocked with cached report");
        };
        assert_eq!(
            bars,
            [
                ResourceIsolation::PRIVATE,
                ResourceIsolation::INVALID,
                ResourceIsolation::SHARED,
                ResourceIsolation::INVALID,
                ResourceIsolation::SHARED,
                ResourceIsolation::INVALID,
            ]
        );
        assert_eq!(dma, ResourceIsolation::SHARED);
    }
}
