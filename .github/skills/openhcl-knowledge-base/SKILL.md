---
name: openhcl-knowledge-base
description: "Navigate the OpenHCL / Underhill paravisor-side per-crate knowledge base at docs/openhcl-knowledge-base.md. Load when answering questions about what a paravisor crate does, where TDISP / attestation / VTL memory / VMBus / VPCI / device emulation code lives, which crates run inside VTL2 vs are excluded as host-side, the VTL2 boot/no_std runtime, the underhill control plane (init/entry/core/threadpool/crash/dump), or trust-boundary considerations for any paravisor crate."
---

# OpenHCL Knowledge Base — Navigation Skill

## Source file

- [docs/openhcl-knowledge-base.md](../../../docs/openhcl-knowledge-base.md) — 3,346 lines, per-crate reference for OpenHCL/Underhill.

This skill is purely a **navigation aid** for that document. The doc itself is the source of truth; do not paraphrase from this skill if the user wants exact crate behavior — `read_file` the relevant range and quote it.

## What the document covers

A per-crate reference for the **paravisor-side** code in this repository — every crate that ships into the OpenHCL VTL2 image (formerly "Underhill"). For each documented crate it gives:

- **Responsibility** — one-paragraph role summary.
- **Modules** — file-by-file breakdown with [link]() citations into the source tree.
- **Public API / consumed by** — what other crates depend on it.
- **Trust** — which of the three trust boundaries `(a) Host→VTL2`, `(b) VTL0 guest→VTL2`, `(c) Hypervisor→VTL2` (CVM-only) the crate sits on, and what untrusted input it must not panic on.

Host-side and build-time-only code (e.g. `ohcldiag-dev`, `diag_client`, `vmfirmwareigvm_dll`, `minimal_rt_build`) is **explicitly excluded** and listed in the Excluded table at lines 123–146.

The doc opens with an architectural overview (boot shim → OpenHCL Linux kernel → `underhill_init` PID 1 → `openvmm_hcl` VMM), an ASCII block diagram of the runtime stack, and a definition of the three trust boundaries (lines 8–80). All subsequent sections drill into individual crates.

## Section / crate map (line numbers in the .md)

### Front matter (lines 1–146)
| Lines | Topic |
|---|---|
| 1–62 | "What is OpenHCL?" — image layers, ASCII stack diagram |
| 64–79 | **Trust boundaries (a)/(b)/(c)** definitions and the "never panic on adversarial input" rule |
| 80–122 | **Inventory table** of documented paravisor-runtime crates → section pointers |
| 123–146 | **Excluded** crates table (host-side / build-time-only) and rationale |

### Boot & no_std runtime (lines 148–608)
| Lines | Crate | Role |
|---|---|---|
| 150–278 | `openhcl_boot` | IGVM-launched bare-metal boot shim (`no_std`/`no_main`); host-FDT parse, VTL2 memory + APs, optional sidecar launch, jump to Linux |
| 279–329 | `minimal_rt` | Bare-metal runtime crate (panic handler, allocator stubs, entry asm) |
| 330–358 | `minimal_rt_reloc` | ELF self-relocation glue |
| 359–400 | `host_fdt_parser` | Untrusted-host FDT parser (unconditionally `no_std`) — boundary (a) |
| 401–474 | `sidecar` | Sidecar minimal kernel binary (`no_std`/`no_main`) |
| 475–515 | `sidecar_defs` | Wire format for the sidecar shared page (`no_std`) |
| 516–564 | `sidecar_client` | VTL2 user-mode client of the sidecar Linux driver |
| 565–608 | `bootloader_fdt_parser` | User-mode re-parse of the OpenHCL DT after Linux boot |

### Hypervisor interface & memory (lines 610–1418)
| Lines | Crate | Role |
|---|---|---|
| 612–722 | `hcl` | `/dev/mshv*` ioctl + userspace bindings; foundation for VTL switches, hypercalls, intercept dispatch |
| 723–749 | `hcl_mapper` | `PoolSource` over `/dev/mshv_vtl_low` |
| 750–861 | `virt_mshv_vtl` | OpenVMM `Partition` backend over `mshv_vtl` (the main `Partition` impl in the paravisor) |
| 862–938 | `underhill_mem` | VTL2 memory manager + **page acceptance** for SNP/TDX |
| 939–976 | `lower_vtl_permissions_guard` | RAII helper that lowers VTL permissions on a memory range |
| 977–1037 | `openhcl_dma_manager` | Shared/private DMA pool allocator (CVM-aware) |
| **1038–1388** | **TDISP subsystem** (see breakdown below) | |
| 1389–1418 | `kmsg_defs` | Shared kmsg/syslog constants |

#### TDISP-in-OpenHCL breakdown (lines 1038–1388)
This is the densest part of the doc and the most likely target for TDISP questions.

| Lines | Subsection |
|---|---|
| 1038–1065 | **Overview** — feature gate (`dev_snp_ohcl_tio_support`), branch context, the cross-crate role table (`tdisp` / `tdisp_proto` / `openhcl_tdisp` / `vpci_protocol` / `vpci` / `vpci_client` / `vpci_relay` / `sev_guest_device(_tio)` / `chipset_device::tdisp`) |
| 1066–1136 | **`tdisp` crate** — protocol-agnostic state machine (`Unlocked ↔ Locked ↔ Run`), `TdispHostDeviceInterface` trait, `TdispHostDeviceTargetEmulator`, `TdispIsolationReporter`/`TdispIsolationReport`/`TdispResourceIsolation`/`TdispUnbindReason` taxonomy, prost serialize/validate, devicereport parser, Kani harnesses |
| 1137–1152 | `tdisp_proto` — generated protobuf wire types & error-code enums |
| 1153–1248 | `openhcl_tdisp` — paravisor glue: `TdispVirtualDeviceInterface` (guest cmd transport), `TdispResourceValidationInterface` (platform unblock/block), SEV-TIO impl, mocks |
| 1249–1325 | Updates to `vpci_protocol` / `vpci` / `vpci_client` / `vpci_relay` (`VPCI_TDISP_COMMAND` `0x4249001D`, `VPCI_QUERY_ISOLATED_RESOURCES` `0x4249001E`, `ProtocolVersion::GE_TDISP` = `0x00010007`, deferred command-register edges, unbind on teardown) |
| 1326–1369 | **End-to-end paravisor TDISP flow** (malicious-host adversarial view) — bind → start → attest → unbind, MMIO/DMA blocking points |
| 1370–1388 | **Malicious-host audit findings on this branch** — open issues / known-good properties |

### Underhill control plane (lines 1420–1916)
| Lines | Crate | Role |
|---|---|---|
| 1422–1449 | `underhill_entry` | Multi-binary `argv[0]` dispatcher |
| 1450–1519 | `underhill_init` | PID 1 — mounts, sysctl, modules, kmsg, then `exec`s `openvmm_hcl` |
| 1520–1738 | `underhill_core` | Control plane / VMM worker (the largest paravisor crate); GET, VTL2 main loop, mesh, device wiring |
| 1739–1791 | `underhill_threadpool` | Per-CPU `io_uring` runtime |
| 1792–1845 | `underhill_crash` | Core-dump → host crashdump VMBus channel |
| 1846–1882 | `underhill_dump` | `elfcore` writer (sub-process spawned by crash) |
| 1883–1916 | `build_info` | Compile-time build metadata in `.build_info` ELF section |

### Attestation, confidentiality, TEE (lines 1917–2332)
| Lines | Crate | Role |
|---|---|---|
| 1919–1992 | `tee_call` | TEE attestation report + derived-key abstraction |
| 1993–2043 | `underhill_confidentiality` | CVM/debug env-var query helpers |
| 2044–2143 | `openhcl_attestation_protocol` | IGVM_ATTEST + VMGS wire formats |
| 2144–2332 | `underhill_attestation` | SKR (Secure Key Release), VMGS unlock, AK-cert orchestrator |

### VMM-in-paravisor, diag, profiling (lines 2333–2719)
| Lines | Crate | Role |
|---|---|---|
| 2335–2365 | `openvmm_hcl` | The paravisor VMM binary entry point |
| 2366–2422 | `openvmm_hcl_resources` | Static device/worker resource registrations |
| 2423–2526 | `diag_server` | In-paravisor diagnostics ttrpc server (AF_VSOCK) |
| 2527–2586 | `diag_proto` | `diag` package protobuf definitions |
| 2587–2644 | `profiler_worker` | One-shot perf profiling mesh worker |
| 2645–2678 | `azure_profiler_proto` | `profile` package protobuf definitions |
| 2679–2719 | `mem_profile_tracing` | dhat heap profiler wrapper |

### Shared device crates used by the paravisor (lines 2720–3346)
| Lines | Crate(s) | Role |
|---|---|---|
| 2730–2776 | `chipset_device` framework (`vm/chipset_device`, `chipset_device_resources`, `chipset_arc_mutex_device`) | Device trait surface + capability accessors (incl. `supports_tdisp` and `supports_tdisp_isolation`) |
| 2777–2810 | `vmotherboard` | Chipset/bus assembly used by the paravisor's emulated chipset |
| 2811–2881 | `chipset` / `chipset_legacy` / `chipset_resources` / `missing_dev` | Chipset device implementations |
| 2882–2938 | Serial UARTs (`serial_core`, `serial_16550`, `serial_pl011`, `serial_socket`) | UART emulation surface |
| 2939–3007 | vTPM (`tpm_device`, `tpm_lib`, `tpm_protocol`) | Virtual TPM stack |
| 3008–3082 | StorVSP / SCSI (`storvsp`, `storvsp_protocol`, `scsidisk`, `scsi_core`, `scsi_defs`, `scsi_buffers`) | VMBus storage stack |
| 3083–3150 | NVMe controller emulator (`nvme`, `nvme_common`, `nvme_spec`, `nvme_resources`) | NVMe spec types + emulator |
| 3151–3206 | Disk backends (`disk_striped`, `disk_nvme`, `disk_blockdevice`) | Block backends used by storage stack |
| 3207–3293 | VPCI relay & client (`vpci`, `vpci_protocol`, `vpci_relay`, `vpci_client`) | VPCI server, host-VPCI client, relay glue (also see TDISP breakdown above) |
| 3294–3346 | `nvme_manager` (in `underhill_core/src/nvme_manager`) | Lock-ordered NVMe device lifecycle manager |

## How to use this skill

- **"What does crate X do in the paravisor?"** → look up X in the inventory table at lines 80–122 (which points to a section), or jump straight to the section in the map above. `read_file` the line range; do not paraphrase.
- **"Where does TDISP live?"** → lines 1038–1388, with the cross-crate role table at 1066. For the spec-level questions behind those crates, also load the `tdisp-spec` skill.
- **"Is crate Y in the paravisor or host-side?"** → check the **Excluded** table at lines 123–146 first. Anything not in either inventory table is outside the doc's scope (it's neither a paravisor runtime crate nor a host-side companion the author chose to document).
- **"What untrusted input does crate Z handle?"** → every crate entry has a **Trust** subsection that names the boundary (`(a)`/`(b)`/`(c)`). Cite that subsection's line range.
- **"What attestation/SKR flow does the paravisor run?"** → §`underhill_attestation` (2144–2332), with wire formats in `openhcl_attestation_protocol` (2044–2143) and TEE primitives in `tee_call` (1919–1992).
- **"How does the paravisor boot?"** → §Boot & no_std runtime (148–608), starting with `openhcl_boot` (150–278). The ASCII stack diagram at lines 28–62 is the quickest orientation.

## Caveats

- The TDISP subsection (1038–1388) is dated to branch `tdisp_tio_vpci`, commit `9675d6bc`. If the user is on a different branch, verify the cross-crate role table is still accurate before citing it.
- Line numbers above were captured against the current revision of the file. The document is large but stable; if a `read_file` of a quoted range doesn't match, re-run `grep -nE "^#{1,4} " docs/openhcl-knowledge-base.md` and re-derive ranges.
- The doc uses Markdown links of the form `[file](relative/path)` from the repo root — those paths are clickable in VS Code from this file too.
