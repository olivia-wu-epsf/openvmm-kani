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

The OpenHCL expert's focused review of `vpci_relay`'s TDISP edges
during the AF-iter2-1 exploit-path expansion identified 10
additional Kani verification opportunities that are state-machine,
ordering, or cache invariants enforced by the relay itself (not
delegated to `vpci_client`). These are catalogued in
[../security-properties-2/vpci-relay-verification-opportunities.md](../security-properties-2/vpci-relay-verification-opportunities.md)
as **M-relay-1 .. M-relay-10**. They are not yet implemented as
Kani harnesses; M-relay-1, M-relay-7, and the M-relay-2/M-relay-9
pair are the recommended priorities for a future iteration.

## Summary

- **17 harnesses verified** across properties M-1, M-3, M-4, M-5, M-6, M-7 (unbind), M-8a, M-10.
- **1 true-positive finding** (AF-iter2-1: M-1 unbind post-state check missing). Two harnesses fail with the same root cause.
- **2 false-positive harnesses** for M-7 (request-side variant): adjudicated by skill-restricted expert debate. Spec text (§11.3.1 Table 3 + §11.3.8/14/16/17 + §11.5/§11.6.3) places the source-state legality obligation on the device (DSM), not the requester (TVM). Removed from the harness file.
- **2 properties deferred** because CBMC OOMs on multi-call orchestration (M-3 attest leg + M-9 attest Ok leg). Behavioral coverage via M-3 negative trio + M-1 Start + static observation.
- **1 property dropped (purity sub-check of M-8a)** because CBMC OOMs on the 6×BTreeMap-traversal path.

## Findings index

| ID | Property | Verdict | Severity | File |
|---|---|---|---|---|
| AF-iter2-1 | M-1 (Unbind post-state check missing) | TRUE POSITIVE | high | [findings/m1-unbind-missing-post-check.md](findings/m1-unbind-missing-post-check.md) |
| — | M-7 request-side (Bind/Start pre-check) | FALSE POSITIVE (adjudicated) | n/a | [findings/m7-request-side-adjudication.md](findings/m7-request-side-adjudication.md) |
