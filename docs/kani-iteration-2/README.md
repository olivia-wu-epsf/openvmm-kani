# Iteration 2 Kani Verification — Findings

This directory documents true-positive findings produced by the
iteration-2 OpenHCL paravisor TDISP TVM Kani verification campaign.

## Threat model recap

- OpenHCL paravisor = TVM in PCI-SIG TDISP v2022-07-27 role mapping.
- Host VMM = fully untrusted adversary; controls every TDISP wire
  response field (`error_code`, `tdi_state_after`, payload variant).
- Goals: confidentiality + integrity of TVM and its TDISP
  communications. Availability is **not** a goal — any `Ok(_)` return
  must never imply an unsafe local cached state.

## Sources of truth

- `.github/skills/tdisp-spec/SKILL.md` (PCI-SIG TDISP v2022-07-27).
- `.github/skills/openhcl-knowledge-base/SKILL.md` and
  `docs/openhcl-knowledge-base.md`.
- `.github/skills/model-checking/SKILL.md`.

## Property list

See [../security-properties-2/tdisp-tvm-properties.md](../security-properties-2/tdisp-tvm-properties.md).

## Future-iteration verification opportunities

8 of the 10 M-relay-N properties were exercised in iteration 2 via
logical-equivalent harnesses in vpci_client's existing Kani setup
(per the OpenHCL expert's recommended workaround for the
vpci_relay-direct Kani build's blocking issues with vmbus_client /
vmbus_server / mesh dependencies). Results: 5 verified
(M-relay-3/4/6/8/10) plus 3 failed (M-relay-1, M-relay-2-focused,
M-relay-7 split into Ok+Err arms — surfacing AF-iter2-1 +
AF-iter2-2). M-relay-5 and M-relay-9 are partially covered by
M-8a. Full catalog with status:
[../security-properties-2/vpci-relay-verification-opportunities.md](../security-properties-2/vpci-relay-verification-opportunities.md).

## Summary

- **24 harnesses verified** across properties M-1, M-3, M-4, M-5, M-6, M-7 (unbind), M-8a, M-10, M-relay-3, M-relay-4, M-relay-6, M-relay-8, M-relay-10.
- **2 true-positive findings** (both adjudicated by independent expert debate):
  - **AF-iter2-1**: M-1 unbind post-state check missing (4 corroborating harnesses fail with same root cause: `m1_unbind_ok_*`, `m1_unbind_preserve_ok_*`, `m_relay_1_*`, `m_relay_2_focused_*`).
  - **AF-iter2-2**: M-relay-7 Err-arm — `vpci_relay` admits device when post-attest unbind fails AND `send_tdisp_command` updates the cached `tdi_state` *before* checking `error_code` (3 corroborating harnesses fail: `m_relay_7_err_arm_*`, `m_relay_7_arrival_cycle_*`, plus the union one). Distinct upstream lever from AF-iter2-1; same downstream consequence.
- **2 false-positive harnesses** for M-7 (request-side variant): adjudicated by skill-restricted expert debate. Spec text (§11.3.1 Table 3 + §11.3.8/14/16/17 + §11.5/§11.6.3) places the source-state legality obligation on the device (DSM), not the requester (TVM). Removed from the harness file.
- **2 properties deferred** because CBMC OOMs on multi-call orchestration (M-3 attest leg + M-9 attest Ok leg). Behavioral coverage via M-3 negative trio + M-1 Start + static observation.
- **1 property dropped (purity sub-check of M-8a)** because CBMC OOMs on the 6×BTreeMap-traversal path.

## Findings index

| ID | Property | Verdict | Severity | File |
|---|---|---|---|---|
| AF-iter2-1 | M-1 (Unbind post-state check missing); same root cause manifests at relay-driven entrypoints (M-relay-1, M-relay-2-focused, M-relay-7 Ok-arm) | TRUE POSITIVE | high | [findings/m1-unbind-missing-post-check.md](findings/m1-unbind-missing-post-check.md) |
| AF-iter2-2 | M-relay-7 Err-arm: `vpci_relay` log-and-continue on post-attest unbind failure + `send_tdisp_command` updates cache before error check | TRUE POSITIVE | high | [findings/m-relay-7-err-arm.md](findings/m-relay-7-err-arm.md) |
| — | M-7 request-side (Bind/Start pre-check) | FALSE POSITIVE (adjudicated) | n/a | [findings/m7-request-side-adjudication.md](findings/m7-request-side-adjudication.md) |
