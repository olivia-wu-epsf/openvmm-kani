# Bug TDISP-002 — `tdisp_attest_device` issues `START` before fetching the report

**Severity:** High
**Obligation violated:** O-3 (SAFE-2, ORD-4)
**Status:** Open. The current order is `Bind → StartTdi → GetTdiReport`.

See [shared context](tdisp-bug-template-shared-context.md).

## Summary

The reference's safety property
`SAFE-2: AG(START_issued → previously(report_verified ∧ resources_accepted))`
requires the TDISP-protocol agent to issue
`START_INTERFACE_REQUEST` only after a verified report exists and
resources have been accepted. The paravisor's `tdisp_attest_device`
issues `START_INTERFACE_REQUEST` *before* the report has been
fetched, let alone verified.

This is a separate bug from
[TDISP-001](tdisp-bug-001-missing-v1-hash-check.md) (V1 missing). Even
if V1 were added at the current location, the START would still have
been sent against an unverified report, irreversibly transitioning
the device's wire-protocol state and consuming the lock-epoch nonce
before any verification happens.

## Technical details

[`tdisp_attest_device`](../../vm/devices/pci/vpci_client/src/tdisp.rs)
performs:

```rust
self.tdisp_bind_interface().await?;          // LOCK_INTERFACE
self.tdisp_start_device().await?;            // START_INTERFACE  ← before report
let guest_device_id = self.tdisp_get_tdi_device_id().await?;
let tdi_report = self.tdisp_get_tdi_report().await?;  // GET_DEVICE_INTERFACE_REPORT
…
self.mutable_state.tdi_report = Some(tdi_report);
```

The reference's prescribed order (§6, ORD-1..ORD-4) is:

1. `LOCK_INTERFACE_REQUEST` → `LOCK_INTERFACE_RESPONSE` (nonce N).
2. `GET_DEVICE_INTERFACE_REPORT` (chunked) → report assembled.
3. Local report verification (V1..V6 / CHECK-1..3).
4. Local resource acceptance (CHECK-4..5).
5. `START_INTERFACE_REQUEST(N)` → `START_INTERFACE_RESPONSE`.

## Why this lands on the paravisor

The paravisor is the entity issuing the wire commands. The order of
calls inside `tdisp_attest_device` is a paravisor implementation
choice, not a host-protocol constraint — the reference §6.2 lists no
precondition on `GET_DEVICE_INTERFACE_REPORT` other than `guest_state
= LOCKED_UNVERIFIED` (i.e. LOCK has succeeded). There is no spec or
host-protocol reason that requires START to precede GET_REPORT.

## Attack scenario

Even with TDISP-001 fixed in the current location, a malicious host
gains the following window:

1. Paravisor sends `LOCK_INTERFACE_REQUEST`.
2. Host returns `LOCK_INTERFACE_RESPONSE` (Success), claiming
   `tdi_state_after = Locked`.
3. Paravisor sends `START_INTERFACE_REQUEST` *before* fetching the
   report. The wire request irreversibly consumes the lock-epoch
   nonce on the device DSM (or, under TDISP-004, would do so once
   the nonce is tracked).
4. Host returns `START_INTERFACE_RESPONSE` (Success), claiming
   `tdi_state_after = Run`. Paravisor caches `Run`.
5. Paravisor now fetches the report. Whether or not the paravisor
   verifies it (TDISP-001), the device has *already been instructed*
   to enter `Run` based on a report that did not exist at the time
   of the request.

If verification (TDISP-001) then fails, the paravisor must roll back
by issuing `STOP_INTERFACE` — but the lock-epoch is consumed and the
device must redo the entire LOCK→GET_REPORT→VERIFY→START cycle from
scratch. This both wastes the nonce and creates an additional state
where the paravisor's cache says `Run` while the device actually is
in `Run` because of an unverified attestation.

It also undermines `SAFE-2`'s temporal guarantee: any external
observer (e.g. a future paravisor consumer that gates on "did
`tdisp_attest_device` return Ok?") cannot rely on the implication
"START was issued ⇒ previously the report was verified".

## Impact

- **State-machine faithfulness (§3.2):** the §3.2 transition
  `RESOURCES_ACCEPTED → TRUSTED_RUN` cannot be witnessed locally
  because it is preceded by the wire START. The paravisor's local
  state machine is forced out of agreement with the reference.
- **Composability with TDISP-001:** even after V1 is added, V1 has
  no opportunity to refuse START before it is sent. V1 becomes a
  rollback trigger, not a precondition.
- **Lock-epoch consumption (TDISP-004 interaction):** once nonce
  tracking is added, every `tdisp_attest_device` call consumes a
  nonce regardless of whether the report verifies, weakening
  rate-limiting and giving the host an easy way to force repeated
  re-attestation cycles.

## Suggested remediation

Reorder `tdisp_attest_device` to:

```rust
self.tdisp_bind_interface().await?;                        // LOCK
let tdi_report = self.tdisp_get_tdi_report().await?;       // GET_REPORT
self.verify_tdi_report_v1(&tdi_report).await?;             // CHECK-1 (TDISP-001)
self.verify_tdi_report_policy(&tdi_report)?;               // CHECK-2/3 (out of scope)
self.accept_resources_from_report(&tdi_report)?;           // CHECK-4/5 (out of scope)
self.tdisp_start_device().await?;                          // START (TDISP-004 supplies nonce)
let guest_device_id = self.tdisp_get_tdi_device_id().await?;
self.mutable_state.tdi_report = Some(tdi_report);
```

`tdisp_get_tdi_device_id` may need to move depending on whether the
device exposes the guest device ID through the LOCK response or only
post-START; if the latter, document it and treat the post-START
device-ID fetch as a separate, gated step.

## Acceptance criteria

- `tdisp_attest_device` calls `START_INTERFACE_REQUEST` strictly
  after a successful V1 verification of the report.
- A new Kani harness `verify_attest_device_orders_start_after_verify`
  asserts that no path through `tdisp_attest_device` reaches
  `tdisp_start_device` without first having called `tdisp_get_tdi_report`
  *and* the V1 verification helper.
