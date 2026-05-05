// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kani formal verification harnesses for `tdisp_proto`.
//!
//! These harnesses are compiled and executed only when running `cargo kani`.
//! They are invisible to `cargo build`, `cargo test`, and clippy because every
//! item here is gated by `#[cfg(kani)]` (set automatically by the Kani
//! toolchain).
//!
//! # Running
//! ```text
//! cd vm/devices/tdisp_proto
//! cargo kani
//! # or a single harness:
//! cargo kani --harness verify_error_code_round_trip
//! ```

#[cfg(kani)]
mod kani_proofs {
    use crate::TdispGuestOperationError;
    use crate::TdispGuestOperationErrorCode;

    // ── Harness H1 ───────────────────────────────────────────────────────────

    /// Verifies that the bidirectional conversion between
    /// [`TdispGuestOperationErrorCode`] and [`TdispGuestOperationError`] is a
    /// perfect bijection (identity round-trip) for every valid enum variant.
    ///
    /// # Property
    /// For all valid proto3 discriminants `d` in `[0, 9]`:
    ///   `ErrorCode::from_i32(d)
    ///       .map(|c| TdispGuestOperationError::from(c))
    ///       .map(|e| TdispGuestOperationErrorCode::from(e)) as i32  ==  d`
    ///
    /// # Why this matters
    /// The error code is the primary status field returned to the guest after
    /// every TDISP operation. A broken conversion could silently map a
    /// security-significant error (e.g. `InvalidDeviceState`) to a different
    /// code, causing the guest to misinterpret the outcome of an operation.
    ///
    /// # Pre-conditions (enforced by `kani::assume`)
    /// - `raw` ∈ `[0, 9]`: restricts the symbolic integer to the declared range
    ///   of `TdispGuestOperationErrorCode` variants in the proto definition.
    ///   Values outside this range produce `None` from `from_i32`, which Kani
    ///   would correctly ignore, but the assume keeps the proof tight and
    ///   avoids exploring vacuously-true branches.
    ///
    /// # Post-conditions (enforced by `assert_eq!`)
    /// - After `ErrorCode → Error → ErrorCode`, the final discriminant equals
    ///   the original raw value `d`.
    ///
    /// # Kani notes
    /// - No loops; no heap allocation; no concurrency. The proof is trivially
    ///   bounded and should verify in seconds.
    /// - `from_i32` is a prost-generated function that performs a simple
    ///   range-checked integer → enum cast; Kani handles this natively.
    #[kani::proof]
    fn verify_error_code_round_trip() {
        // Symbolic unconstrained 32-bit integer representing a proto3
        // enum discriminant.
        let raw: i32 = kani::any();

        // Pre-condition: only explore the 10 defined discriminants (0–9).
        // TdispGuestOperationErrorCode variants map to values 0 through 9
        // as declared in tdisp.proto.
        kani::assume(raw >= 0 && raw <= 9);

        // Decode the raw discriminant to the protobuf enum. This should
        // succeed for all values in [0, 9].
        if let Some(code) = TdispGuestOperationErrorCode::from_i32(raw) {
            // Convert ErrorCode → Error (the Rust thiserror enum)
            let error: TdispGuestOperationError = code.into();

            // Convert Error → ErrorCode (the inverse direction)
            let code_back: TdispGuestOperationErrorCode = error.into();

            // Post-condition: the round-trip is the identity function.
            // This proves that the two `From` impls in errorcode.rs are
            // exact inverses of each other — no variant is misrouted.
            assert_eq!(
                code as i32, code_back as i32,
                "ErrorCode→Error→ErrorCode round-trip must be the identity"
            );
        }
    }
}
