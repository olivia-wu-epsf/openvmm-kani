# OpenHCL / Underhill Guest-Side Knowledge Base

This document is a per-crate reference for the **paravisor-side** code in this
repository — the components that run inside VTL2 and that, collectively, are
called *OpenHCL* (formerly *Underhill*) or *OpenVMM-HCL*. Host-side and
VMM-only code is **out of scope**.

## What is OpenHCL?

OpenHCL is a small Linux-based "paravisor" image that the host (Hyper-V or
OpenVMM) loads into a guest's **VTL2** (Virtual Trust Level 2). It runs
strictly more privileged than the guest OS in VTL0/VTL1 but strictly less
privileged than the hypervisor. From inside VTL2 it provides the guest with
synthetic devices, an emulated chipset, attestation/sealed-key services, and a
stable VMBus interface — so the same guest image can run unchanged across
hypervisor generations and inside confidential VMs (SEV-SNP, TDX, VBS).

The image is composed of three layers:

1. A bare-metal **boot shim** (`openhcl_boot`, optionally `sidecar`) that runs
   from the IGVM measured launch.
2. A purpose-built **OpenHCL Linux kernel**.
3. A user-mode **paravisor** rooted at `underhill_init` (PID 1) which
   `exec`s `openvmm_hcl` — the in-paravisor VMM that talks to the
   `/dev/mshv*` kernel driver, the host (over GET/VMBus), and the guest.

```
        IGVM measured image
                │
                ▼
    ┌──────────────────────┐    no_std, no_main
    │  openhcl_boot        │◀── minimal_rt, minimal_rt_reloc
    │  (+ sidecar, opt.)   │    host_fdt_parser, sidecar_defs
    └──────────┬───────────┘
               │ jumps to
               ▼
    ┌──────────────────────┐
    │  OpenHCL Linux kernel│
    └──────────┬───────────┘
               │ initrd → PID 1
               ▼
    ┌──────────────────────┐
    │  underhill_init      │ ← mounts, sysctl, modules, kmsg
    └──────────┬───────────┘
               │ execs
               ▼
    ┌──────────────────────────────────────────────────────────┐
    │  openvmm_hcl  ──►  underhill_entry → underhill_core      │
    │                                                          │
    │   ├─ virt_mshv_vtl  ── via ── hcl ── /dev/mshv_vtl       │
    │   ├─ underhill_mem  (page accept, VTL protections)       │
    │   ├─ underhill_attestation (IGVM_ATTEST, VMGS unlock)    │
    │   ├─ openhcl_dma_manager (shared/private DMA pools)      │
    │   ├─ vmbus relay + emulated devices (storvsp, netvsp,    │
    │   │  TPM, VPCI/NVMe, UART, framebuffer, …)               │
    │   ├─ diag_server  ── AF_VSOCK ──► host (ohcldiag-dev)    │
    │   └─ profiler_worker, mem_profile_tracing                │
    └──────────────────────────────────────────────────────────┘
            │                          │
            ▼                          ▼
       VTL0 guest (untrusted)     Host VMM / IGVM Agent (untrusted on CVMs)
```

## Trust boundaries

Three trust boundaries are relevant to this code base. Each crate entry below
calls out which of these it sits on.

| Code | Boundary | Description |
|------|----------|-------------|
| **(a)** | **Host/VMM → VTL2 paravisor** | The host VMM (OpenVMM, Hyper-V) and the IGVm Agent are untrusted on confidential VMs. GET messages, IGVM/FDT parameters, VMGS contents, attestation responses, AF_VSOCK diag traffic, sidecar/kernel-driver state all originate here. |
| **(b)** | **VTL0 guest → VTL2 paravisor** | The VTL0 guest is *always* untrusted. VMBus ring traffic, MMIO/PIO emulator inputs, virtual-firmware NVRAM writes, TPM commands, VPCI configuration, and intercept register state are guest-controlled. |
| **(c)** | **Hypervisor → VTL2** | On confidential VMs (SNP/TDX) the hypervisor itself is untrusted: every register page, run page, VMSA, intercept message, hypercall result, and CPUID leaf must be treated as adversarial. On non-CVM the hypervisor is trusted. |

Code on these boundaries must **never panic** on adversarial input. The
codebase enforces this with `open_enum!` for protocol enums, `zerocopy`
size-checked deserialization, `thiserror` at boundaries, and
`tracelimit::*_ratelimited!` for guest-triggerable trace events.

## Inventory

### Documented (paravisor-runtime)

These crates ship into the OpenHCL image and run inside VTL2.

| Crate | Role | Section |
|-------|------|---------|
| `openhcl_boot` | Boot shim (`no_std`, `no_main`) | [Boot & no_std runtime](#boot--no_std-runtime) |
| `minimal_rt` | Bare-metal runtime | same |
| `minimal_rt_reloc` | ELF self-relocation | same |
| `host_fdt_parser` | Untrusted host DT parser (`no_std`) | same |
| `sidecar` | Sidecar minimal kernel (`no_std`, `no_main`) | same |
| `sidecar_defs` | Sidecar shared-page wire format (`no_std`) | same |
| `sidecar_client` | Userspace client of the sidecar Linux driver | same |
| `bootloader_fdt_parser` | Userspace re-parse of the OpenHCL DT | same |
| `hcl` | `/dev/mshv*` ioctl/userspace bindings | [Hypervisor interface & memory](#hypervisor-interface--memory) |
| `hcl_mapper` | `PoolSource` over `/dev/mshv_vtl_low` | same |
| `virt_mshv_vtl` | OpenVMM `Partition` backend over `mshv_vtl` | same |
| `underhill_mem` | VTL2 memory manager + page acceptance | same |
| `lower_vtl_permissions_guard` | RAII VTL-permission lowering | same |
| `openhcl_dma_manager` | Shared/private DMA pools | same |
| `openhcl_tdisp` | TDISP guest-to-host VPCI surface + SEV-TIO resource validator | [TDISP in OpenHCL — overview](#tdisp-in-openhcl--overview) |
| `kmsg_defs` | Shared kmsg/syslog constants | same |
| `underhill_entry` | Multi-binary `argv[0]` dispatcher | [Underhill control plane](#underhill-control-plane) |
| `underhill_init` | PID 1 inside the paravisor container | same |
| `underhill_core` | Control plane / VMM worker | same |
| `underhill_threadpool` | Per-CPU `io_uring` runtime | same |
| `underhill_crash` | Core-dump → host crashdump VMBus channel | same |
| `underhill_dump` | `elfcore` writer (sub-process of crash) | same |
| `build_info` | Compile-time build metadata in `.build_info` | same |
| `underhill_attestation` | SKR / VMGS unlock / AK-cert orchestrator | [Attestation, confidentiality, TEE](#attestation-confidentiality-tee) |
| `underhill_confidentiality` | CVM/debug env-var query | same |
| `openhcl_attestation_protocol` | IGVM_ATTEST / VMGS wire formats | same |
| `tee_call` | TEE attestation report + derived-key abstraction | same |
| `openvmm_hcl` | Paravisor VMM binary entry point | [VMM-in-paravisor, diag, profiling](#vmm-in-paravisor-diag-profiling) |
| `openvmm_hcl_resources` | Static device/worker resource registrations | same |
| `diag_server` | In-paravisor diagnostics ttrpc server | same |
| `diag_proto` | `diag` package protobuf definitions | same |
| `profiler_worker` | One-shot perf profiling mesh worker | same |
| `azure_profiler_proto` | `profile` package protobuf definitions | same |
| `mem_profile_tracing` | dhat heap profiler wrapper | same |

### Excluded (host-side or build-time only)

These directories live under `openhcl/` for organizational reasons but **do
not run inside the paravisor**, so they are not described further here.

| Crate | Reason for exclusion |
|-------|----------------------|
| `ohcldiag-dev` | Host-side CLI that connects to the in-paravisor `diag_server`. |
| `diag_client` | Host-side library used by `ohcldiag-dev` to talk the `diag` protocol. |
| `vmfirmwareigvm_dll` | Host Windows DLL packaging the IGVM firmware blob. |
| `minimal_rt_build` | Build-script helper crate (`build.rs`-only); not in the runtime image. |

`hcl_mapper` runs inside the paravisor (it is consumed by `openhcl_dma_manager`
and `underhill_core`'s framebuffer plumbing) and is therefore **documented
above**, not excluded.

`sidecar_client` runs in user mode inside VTL2 (it is consumed by `hcl` and
`virt_mshv_vtl` to drive the sidecar Linux driver) and is therefore **documented
above**.

`diag_proto`, `azure_profiler_proto`, and `sidecar_defs` are wire-format
crates also linked by host-side tools. They are documented under guest-side
because the protocols they describe *originate* in the paravisor; the
"Consumed by" notes in each entry call out the host-side consumers.

## Boot & no_std runtime

### `openhcl_boot`

**Responsibility.** The OpenHCL boot shim — a bare-metal, `no_std`, `no_main`
ELF image that runs as the first VTL2 code after the IGVM loader. It parses
host-supplied parameters, sets up VTL2 memory and APs, optionally launches the
sidecar kernel, builds the Linux boot parameters/FDT, and jumps to the OpenHCL
Linux kernel. Builds with the `minimal_rt` cfg using a custom entry assembly;
tests run as a normal `std` binary.

**Modules.**

- [main.rs](openhcl/openhcl_boot/src/main.rs) — Top-level `shim_main`, kernel
  command-line construction (`build_kernel_command_line`), x86
  `boot_params`/E820 builder (`x86_boot`), SEV `cc_blob` setup,
  `validate_vp_hw_ids`, and the final jump to the kernel entry.
- [rt.rs](openhcl/openhcl_boot/src/rt.rs) — Stack with cookie, `start` entry
  trampoline that calls `shim_main`, and the `#[panic_handler]` that reports
  via `minimal_rt::enlightened_panic`.
- [boot_logger.rs](openhcl/openhcl_boot/src/boot_logger.rs) — `log` crate
  backend writing to COM3 (or TDX I/O serial) plus a `string_page_buf::StringBuffer`
  in-memory log persisted into a reserved range and replayed once a real
  serial sink is selected.
- [cmdline.rs](openhcl/openhcl_boot/src/cmdline.rs) — Parses the
  `ParavisorCommandLine` and host bootargs for OpenHCL-specific options
  (`OPENHCL_IGVM_VTL2_GPA_POOL_CONFIG`, `OPENHCL_SIDECAR`,
  `OPENHCL_DISABLE_NVME_KEEP_ALIVE`, `OPENHCL_VTL2_GPA_POOL_NUMA`,
  `OPENHCL_CONFIDENTIAL_DEBUG`).
- [dt.rs](openhcl/openhcl_boot/src/dt.rs) — Builds the OpenHCL devicetree blob
  (`write_dt`) consumed by the OpenHCL kernel and underhill usermode (CPUs,
  memory map, vmbus VTL0/VTL2 nodes, GIC on aarch64, openhcl/sidecar nodes,
  accepted regions, boot times).
- [memory.rs](openhcl/openhcl_boot/src/memory.rs) — `AddressSpaceManager` and
  `AddressSpaceManagerBuilder`: range allocator that classifies VTL2 memory
  into RAM, parameter regions, sidecar image/nodes, persisted state, GPA
  pool, TDX page tables, and the in-memory log buffer.
- [hypercall.rs](openhcl/openhcl_boot/src/hypercall.rs) — `HvCall` wrapper
  providing `initialize`/`uninitialize`, `get_register`, `vtl()`,
  `get_vp_index_from_hw_id`, page-acceptance/visibility hypercalls. Owns the
  static input/output pages and (for TDX) a large hypercall I/O page.
- [sidecar.rs](openhcl/openhcl_boot/src/sidecar.rs) — `SidecarConfig`,
  `start_sidecar`: carves NUMA-aware sidecar nodes, allocates `SidecarParams`/
  `SidecarOutput` shared pages, jumps into the sidecar entry, and emits the
  `boot_cpus=` kernel commandline fragment.
- [single_threaded.rs](openhcl/openhcl_boot/src/single_threaded.rs) —
  `SingleThreaded<T>` (unconditional `Sync`) and the `off_stack!` /
  `OffStackRef` macro that places large structures in `.bss` instead of the
  small bootshim stack.
- [host_params/mod.rs](openhcl/openhcl_boot/src/host_params/mod.rs) —
  `PartitionInfo` aggregate and limits (`MAX_CPU_COUNT=2048`,
  `MAX_NUMA_NODES=64`, `COMMAND_LINE_SIZE`, `MAX_VTL2_RAM_RANGES`,
  `MAX_ENTROPY_SIZE`).
- [host_params/shim_params.rs](openhcl/openhcl_boot/src/host_params/shim_params.rs)
  — `IsolationType` (None/Vbs/Snp/Tdx), `ShimParams` (relocated from
  build-time `ShimParamsRaw`), and `ImportedRegionIter` over the IGVM
  accepted-region descriptors.
- [host_params/mmio.rs](openhcl/openhcl_boot/src/host_params/mmio.rs) —
  `select_vtl2_mmio_range`: carves VTL2 high-MMIO out of the host-provided
  VTL0 MMIO ranges.
- [host_params/dt/mod.rs](openhcl/openhcl_boot/src/host_params/dt/mod.rs) —
  `PartitionInfo::read_from_dt`: drives `host_fdt_parser` over the IGVM
  device tree parameter and translates the result into `PartitionInfo`,
  including private GPA pool selection and persisted-state header parsing.
- [host_params/dt/bump_alloc.rs](openhcl/openhcl_boot/src/host_params/dt/bump_alloc.rs)
  — `BumpAllocator` registered as `#[global_allocator]` (only when
  `minimal_rt`), gated by an explicit enable/disable state machine and only
  used while parsing the host FDT.
- [host_params/dt/dma_hint.rs](openhcl/openhcl_boot/src/host_params/dt/dma_hint.rs)
  — `pick_private_pool_size` lookup tables (release/debug) mapping
  `(vp_count, vtl2_memory_mb)` to a recommended persistent DMA pool size.
- `arch/x86_64/{mod,address_space,memory,hypercall,snp,tdx,vp,vsm}.rs` —
  x86_64 implementation: page tables, `LocalMap`, `setup_vtl2_memory`,
  IGVM imported-regions hash check, hypercall MSR plumbing, SNP GHCB MSR
  protocol, TDX `TDCALL` and AP trampoline, per-VP enable, isolation-type
  detection.
- `arch/aarch64/{mod,memory,vp,vsm,hypercall}.rs` — aarch64 mirror:
  `physical_address_bits` from `ID_AA64MMFR0_EL1`, page acceptance via VTL
  hypercalls, Hyper-V `GuestOsId` and synthetic crash regs configured from
  `entry.S`, kernel handoff that disables MMU before jumping with the FDT
  pointer.

**Public API.** Binary crate; nothing is consumed externally except by the
entry assembly. Internally the boundary types are `ShimParams`,
`PartitionInfo`, `AddressSpaceManager`, `HvCall`, `SidecarConfig`,
`BootCommandLineOptions`, `Vtl2GpaPoolConfig`, `BootTimes`, `MemoryVtlType`,
plus the `write_dt` and `build_e820_map`/`build_boot_params` helpers in
`dt.rs` / `x86_boot`.

**External I/O.**

- *Input:* IGVM-supplied `ParavisorCommandLine`, the IGVM device tree
  parameter (parsed via `host_fdt_parser`), `ShimParamsRaw` (relative-offset
  blob fixed at build time), and the IGVM imported-regions descriptor list.
- *Hypercalls:* `HvCallEnablePartitionVtl`, `HvCallEnableVpVtl`,
  `HvCallStartVirtualProcessor`, `HvCallGetVpIndexFromApicId`,
  `HvCallGetVpRegisters` (VsmCapabilities), page-acceptance,
  `HvCallModifyVtlProtectionMask`, GPA visibility, `HvCallSetVpRegisters`.
  Hypercall page mapped via `HV_X64_MSR_HYPERCALL` (x86) or aarch64
  hypercall ABI.
- *MSRs:* `HV_X64_MSR_GUEST_OS_ID`, `HV_X64_MSR_HYPERCALL`,
  `X86X_MSR_APIC_BASE`, AMD `X86X_AMD_MSR_GHCB`, Hyper-V guest-crash MSRs
  (enlightened panic).
- *TDX:* `TDCALL` (`tdcall_hypercall`, `tdcall_map_gpa`, `tdcall_wrmsr`);
  writes the AP trampoline (`TdxTrampolineContext`) at the reset vector
  page; GHCI-style hypercalls go through a shared large I/O page.
- *SNP:* `VMGEXIT`/GHCB MSR protocol for page state changes and acceptance.
- *Serial:* Direct I/O port writes to COM3 (`0x3E8`) on x86 (or via TDX
  I/O), PL011 on aarch64.
- *DT output:* Produces the OpenHCL devicetree (CPUs, `memory@*`, `openhcl`
  node with `accepted-memory`/`config-ranges`/`vtl2-reserved-range`/
  `vtl2-persisted-*`/`memory-allocation-mode`/`vtl0-alias-map`,
  `vmbus@VTL0/VTL2`, `intc@`/`pmu` on aarch64, `sidecar` node, boot-times).
  On x86 this is appended as a `setup_data` (`SETUP_DTB`) chained into Linux
  `boot_params`; on aarch64 it is the kernel's primary FDT pointer.
- *Linux handoff:* On x86, fills `boot_params` (E820 RAM/RESERVED,
  `cmd_line_ptr`, `ramdisk_image`, `setup_data` chain, `cc_blob_sev_info`
  for SNP). On aarch64, jumps with FDT pointer after disabling MMU and TLB
  flush.

**Trust.** Sits squarely on **(a) Host/VMM → VTL2 paravisor**. Untrusted
inputs: the IGVM-provided host devicetree, `ParavisorCommandLine` (only when
`can_trust_host`), host MMIO ranges, host-claimed CPU/NUMA topology,
host-provided entropy, host-claimed alias map. For confidential VMs (SNP/TDX)
it also sits on **(c) Hypervisor → VTL2** for GHCB/TDCALL responses; the
imported-regions hash check (`verify_imported_regions_hash`) and explicit
page acceptance protect against a malicious hypervisor swapping pages.
`validate_vp_hw_ids` cross-checks host APIC IDs against the hypervisor
mapping for non-isolated VSM guests. Guest (VTL0) input is not consumed at
boot.

### `minimal_rt`

**Responsibility.** A `no_std` runtime support crate shared by `openhcl_boot`
and `sidecar` — the bare minimum needed to run Rust without libc or
compiler-builtins. Provides `mem*`/`bcmp` symbols, the architecture-specific
hypercall page, MSR/serial intrinsics, reference-time access, and the
enlightened-panic crash reporter. Compiled with `cfg(minimal_rt)` to avoid
clashing with `std` in tests.

**Modules.**

- [lib.rs](openhcl/minimal_rt/src/lib.rs) — `#![no_std]` root that re-exports
  `minimal_rt_reloc` as `reloc` and exposes `arch`, `enlightened_panic`,
  `reftime`, `rt`.
- [rt.rs](openhcl/minimal_rt/src/rt.rs) — `#[no_mangle]
  memcpy/memset/memmove/bcmp` and a backward byte-copy helper, only emitted
  under `cfg(minimal_rt)`.
- [enlightened_panic.rs](openhcl/minimal_rt/src/enlightened_panic.rs) —
  `report(tag, panic, va_to_pa)` that writes the Hyper-V
  `GuestCrashCtl`/`GuestCrashP*` registers (with optional 512-byte panic
  message buffer); `enable_enlightened_panic()` arms message reporting.
- [reftime.rs](openhcl/minimal_rt/src/reftime.rs) — `reference_time()`
  returning the hypervisor 100ns reference time.
- `arch/{x86_64,aarch64}/*` — Per-arch implementations of `Serial`,
  `hypercall::{HYPERCALL_PAGE, invoke_hypercall}`, `msr::{read_msr,
  write_msr}`, `dead_loop`, `fault`, and the synthetic crash registers.

**Public API.**

- `minimal_rt::arch::Serial`, `InstrIoAccess`, `IoAccess` trait,
  `msr::{read_msr, write_msr}`.
- `minimal_rt::arch::hypercall::{HYPERCALL_PAGE, invoke_hypercall}`.
- `minimal_rt::arch::{dead_loop, fault}`.
- `minimal_rt::reftime::reference_time`.
- `minimal_rt::enlightened_panic::{report, enable_enlightened_panic}`.
- `minimal_rt::reloc` (re-export of `minimal_rt_reloc`).

**External I/O.** x86 port I/O to COM3 (`0x3E8`) for serial; PL011 MMIO on
aarch64; reads/writes Hyper-V synthetic MSRs (`HV_X64_MSR_GUEST_OS_ID`,
`HV_X64_MSR_HYPERCALL`, `HV_X64_MSR_TIME_REF_COUNT`,
`HV_X64_MSR_GUEST_CRASH_*`); on aarch64 issues `HVC #0` and reads/writes the
equivalent synthetic registers via `HvArm64RegisterName`. Hosts the hypercall
code page that the hypervisor populates after the guest writes the hypercall
MSR.

**Trust.** Library code with no parsed external data — itself does not sit on
a trust boundary. It exposes the hypervisor interface used by callers, so its
outputs (reference time, hypercall results) carry **(c) Hypervisor → VTL2**
trust assumptions for the consumers, but `minimal_rt` itself performs no
validation.

### `minimal_rt_reloc`

**Responsibility.** Standalone `no_std` crate containing the ELF dynamic
relocation routine applied at image load, before any global state is touched.
Lives in its own crate so its build flags can disable code that would itself
emit relocations (no globals, no formatting machinery). Used by both
`openhcl_boot` and `sidecar` from their `entry.S`.

**Modules.**

- [lib.rs](openhcl/minimal_rt_reloc/src/lib.rs) — Entire crate. Defines
  `Elf64Dyn`, `Elf64Rel`, `Elf64Rela`, `ElfDynTag`, the `R_RELATIVE`
  constants per arch (x86_64 `R_X86_64_RELATIVE = 8`, aarch64
  `R_AARCH64_RELATIVE = 0x403`), `apply_rel`/`apply_rela`, the
  `relocate(mapped_addr, vaddr, dynamic_addr)` entry point, and an inline
  `abort(code)` that issues `ud2`/`brk #0` with the error code in registers.

**Public API.**

- `pub unsafe extern "C" fn relocate(mapped_addr: usize, vaddr: usize,
  dynamic_addr: usize)` — invoked from each consumer's `entry.S` before
  jumping to Rust.

**External I/O.** None. Reads `_DYNAMIC` of the running ELF image and
patches `R_*_RELATIVE` entries in-place. On error, traps with the error
code in `rdi`/`x0` and the source line in `rsi`/`x1`.

**Trust.** None — operates only on the loaded image's own dynamic section.

### `host_fdt_parser`

**Responsibility.** `no_std`, `forbid(unsafe_code)` parser for the
host-supplied IGVM device tree parameter, recognizing OpenHCL-specific
extensions (`igvm_defs::dt`). Runs inside `openhcl_boot` to extract CPUs,
memory map, VMBUS VTL0/VTL2 nodes, GIC, command line, and OpenHCL-private
properties before any kernel boots.

**Modules.**

- [lib.rs](openhcl/host_fdt_parser/src/lib.rs) — Entire crate. Defines
  `ParsedDeviceTree<MAX_MEMORY_ENTRIES, MAX_CPU_ENTRIES,
  MAX_COMMAND_LINE_SIZE, MAX_ENTROPY_SIZE>` with `parse(dt, storage)`, the
  `Error`/`ErrorKind` variants enumerating every malformed-host-DT failure
  mode, `MemoryEntry`, `CpuEntry`, `VmbusInfo`, `GicInfo`, and
  `MemoryAllocationMode`. Optional `inspect` and `tracing` features.

**Public API.**

- `ParsedDeviceTree::{new, parse, cpu_count}` and its public fields
  (`memory`, `cpus`, `vmbus_vtl0`, `vmbus_vtl2`, `command_line`,
  `com3_serial`, `memory_allocation_mode`, `entropy`,
  `device_dma_page_count`, `nvme_keepalive`, `vtl0_alias_map`, `gic`,
  `pmu_gsiv`, `boot_cpuid_phys`, `device_tree_size`).
- Types `MemoryEntry`, `CpuEntry`, `VmbusInfo`, `GicInfo`,
  `MemoryAllocationMode`, `Error`.

**External I/O.** Pure parser. Inputs are an opaque `&[u8]` flattened
devicetree blob produced by the host VMM and its IGVM extensions. Recognizes
nodes/properties: `/cpus/cpu@N` (`reg`, `status`, `numa-node-id`),
`memory@*` (`reg`, `numa-node-id`, IGVM type), `chosen` (`bootargs`,
`linux,initrd-{start,end}`, `rng-seed`), `vmbus@VTL{0,2}` (`mmio` ranges,
`microsoft,message-connection-id`), `intc@` (GIC distributor/redistributor
base/size/stride), `pmu` (`interrupts`), `openhcl`
(`memory-allocation-mode`, `memory-size`, `mmio-size`, `vtl0-alias-map`,
`device-dma-page-count`, `nvme-keepalive`, `isolation-type`).

**Trust.** **(a) Host/VMM → VTL2 paravisor.** The entire input is
host-controlled and explicitly untrusted; that is why every property error
is enumerated and `forbid(unsafe_code)` is used. All consumers must treat
the parsed values as host-attested only.

### `sidecar`

**Responsibility.** The OpenHCL sidecar kernel — a `no_std`/`no_main` minimal
x86_64 kernel image loaded alongside the OpenHCL Linux kernel by
`openhcl_boot`. Most VPs run sidecar instead of Linux to avoid the cost of
bringing every CPU into Linux on large VMs. Each sidecar VP runs an HLT-based
dispatch loop driven via shared pages (control + per-VP command/register
pages) and the Linux `mshv_vtl_sidecar` driver, executing `RUN_VP`,
`GET/SET_VP_REGISTERS`, and `TRANSLATE_GVA` requests on behalf of usermode
`openvmm_hcl`. Currently x86_64 only and **not** supported under hardware
isolation.

**Modules.**

- [main.rs](openhcl/sidecar/src/main.rs) — Module declaration plus the
  architectural overview comment; `main` is unreachable when built with
  `MINIMAL_RT_BUILD=1`.
- [arch/x86_64/mod.rs](openhcl/sidecar/src/arch/x86_64/mod.rs) —
  Address-space layout (`addr_space` submodule fixing PTE indexes for
  self-map, hypercall input/output, command/control/register/assist pages,
  stack, and 256-entry temporary map), shared `AFTER_INIT`/`ENABLE_LOG`/
  `VSM_CAPABILITIES`/`VTL_RETURN_OFFSET` statics, `VpGlobals`, hypercall
  helpers, log emit, `entry.S` import.
- [arch/x86_64/init.rs](openhcl/sidecar/src/arch/x86_64/init.rs) — BSP-only
  one-time initialization: copies the hypercall page, builds GDT/IDT and
  exception entry stubs (`exc_gpf`, `exc_pf`, `irq_entry`), allocates
  per-node `ControlPage`s and per-VP page tables/stacks, caches
  `HvRegisterVsmCodePageOffsets`, then fan-out-starts every AP via
  `HvCallEnableVpVtl`+`HvCallStartVirtualProcessor`. Each AP uses an atomic
  `next_vp` counter to claim the next index.
- [arch/x86_64/vp.rs](openhcl/sidecar/src/arch/x86_64/vp.rs) — AP body:
  `ap_entry`, X2APIC enablement, dispatch loop reading `SidecarCommand`
  from the command page (`RUN_VP`, `GET/SET_VP_REGISTERS`, `TRANSLATE_GVA`);
  communicates with the driver via `cpu_status`/`needs_attention` atomics
  on the control page and IPIs.
- [arch/x86_64/temporary_map.rs](openhcl/sidecar/src/arch/x86_64/temporary_map.rs)
  — `Mapper`/`TemporaryMap<T>`: maps a physical page into the per-VP
  temporary slot during init.
- `arch/x86_64/entry.S` — Asm entry, IDT exception stubs, VTL return
  trampoline.

**Public API.** Binary crate; the only callable entry point is the asm entry
hit from `openhcl_boot::sidecar::start_sidecar`. The wire contract is
defined entirely by `sidecar_defs`.

**External I/O.**

- *Input from bootshim:* `SidecarParams` page (hypercall page PA, per-node
  `SidecarNodeParams`, `PerCpuState`, logging flag).
- *Output to bootshim:* `SidecarOutput` (per-node `control_page` PA,
  `shmem_pages_base/size`, command-error string).
- *Runtime control plane:* Per-node `ControlPage` (request/response IPI
  vectors, `cpu_status[]`, `needs_attention`) shared with the Linux
  `mshv_vtl_sidecar` driver. Per-VP `CommandPage` and `HvX64RegisterPage`
  shared with usermode `openvmm_hcl` via the driver's mmap region.
- *Hypercalls:* `HvCallEnableVpVtl`, `HvCallStartVirtualProcessor`,
  `HvCallGetVpRegisters` (VsmCodePageOffsets/VsmCapabilities),
  `HvCallSetVpRegisters`, `HvCallTranslateVirtualAddressEx`, plus the
  VTL-return fast hypercall via the assist page.
- *MSRs:* `HV_X64_MSR_GUEST_OS_ID`, `HV_X64_MSR_HYPERCALL`,
  `X86X_MSR_APIC_BASE`, `X86X_MSR_FS_BASE`, `MSR_IA32_X2APIC_*` (X2APIC SVR
  / ICR for IPIs).
- *Faults:* Handles #GP and #PF directly; a fault during a command is
  reported back through `CommandError`.

**Trust.** Sits on **(c) Hypervisor → VTL2** (consumes hypercall results,
intercept messages) and **(b) VTL0 guest → VTL2** when running guest code via
`RUN_VP` (intercept message and register state from guest must be treated as
untrusted by usermode that consumes the command page). The sidecar kernel
itself trusts the bootshim (which is part of the same trust domain) and
trusts the Linux kernel + usermode VMM that share its pages. It does not
sit on the host/root boundary directly — input from `openhcl_boot` is
sanitized.

### `sidecar_defs`

**Responsibility.** `no_std`, `forbid(unsafe_code)` shared wire-format crate
defining the contract among the `openhcl_boot` shim, the `sidecar` kernel,
the Linux `mshv_vtl_sidecar` driver, the userspace `sidecar_client`, and
`openvmm_hcl`. All shared pages, request/response structures, and constants
live here so all four components agree on layout.

**Modules.**

- [lib.rs](openhcl/sidecar_defs/src/lib.rs) — Single module. Defines
  `PerCpuState`, `SidecarParams`, `SidecarNodeParams`, `SidecarOutput`,
  `SidecarNodeOutput`, `ControlPage` (with atomic fields), `CommandPage`,
  `CommandError`, `CpuContextX64`, `RunVpResponse`,
  `GetSetVpRegisterRequest`, `TranslateGvaRequest`/`TranslateGvaResponse`,
  the `SidecarCommand` open enum (`NONE`/`RUN_VP`/`GET_VP_REGISTERS`/
  `SET_VP_REGISTERS`/`TRANSLATE_GVA`), the `CpuStatus` open enum
  (`REMOVED`/`IDLE`/`RUN`/`STOP`/`REMOVE`), and constants `PAGE_SIZE`,
  `MAX_NODES = 128`, `NUM_CPUS_SUPPORTED_FOR_PER_CPU_STATE = 400`,
  `PER_VP_PAGES = 8 + STACK_PAGES`, `PER_VP_SHMEM_PAGES = 2`,
  `STACK_PAGES = 3`, `MAX_GET_SET_VP_REGISTERS`, plus the
  `required_memory(vp_count)` `const fn`. Compile-time asserts that
  `SidecarParams`, `SidecarOutput`, `ControlPage`, and `CommandPage` are
  exactly one page each.

**Public API.** All of the above types, enums, and constants.
`CpuContextX64` exposes named register-index constants (`RAX`, `RCX`, …,
`R15`, `CR2`).

**External I/O.** None directly — definitions only. Every field defines a
byte layout used by sidecar shared pages and Linux ioctls.

**Consumed by.** `openhcl_boot`, `sidecar`, `sidecar_client` (in-paravisor),
the host-side `mshv_vtl_sidecar` Linux kernel driver (out of repo).

**Trust.** None on its own. The shapes it defines straddle multiple
boundaries (host-controlled IPI vectors flow into `ControlPage`;
guest-controlled register state flows through `CommandPage.cpu_context` and
`intercept_message`); use of `open_enum!` for `SidecarCommand` and
`CpuStatus` ensures unknown values round-trip without panicking.

### `sidecar_client`

**Responsibility.** `target_os = "linux"` userspace client used by
`openvmm_hcl` to drive the sidecar kernel through the `mshv_vtl_sidecar`
Linux driver. Discovers `/dev/mshv_vtl_sidecarN` device nodes, mmaps the
per-VP shared pages, and exposes a `SidecarVp` accessor for issuing sidecar
commands and asynchronously running VPs.

**Modules.**

- [lib.rs](openhcl/sidecar_client/src/lib.rs) — Entire crate. Contains the
  private `ioctl` submodule (with `nix` ioctl bindings), `Mapping` (mmap
  RAII), `SidecarClient`, `SidecarNode`, `SidecarClientState`, `VpState`,
  the async wait loop (`sidecar_wait_loop`), `SidecarVp`, `SidecarRun`,
  `VpSharedPages` (overlay of `CommandPage` + `HvX64RegisterPage`), and the
  error enums.

**Public API.**

- `SidecarClient::new`, `SidecarClient::vp(cpu)`,
  `SidecarClient::base_cpu(cpu)`.
- `SidecarVp::{run, cpu_context, intercept_message, register_page, test,
  get_vp_registers, set_vp_registers, translate_gva}`.
- `SidecarRun::{cancel, wait}`.
- `NewSidecarClientError`, `SidecarError`.

**External I/O.**

- *Device files:* Opens `/dev/mshv_vtl_sidecar{0..}` (one per node) with
  `O_NONBLOCK`.
- *Ioctls* (base `0xb8`): `MSHV_VTL_SIDECAR_INFO` (read base CPU/CPU
  count/per-CPU shmem size), `MSHV_VTL_SIDECAR_START` (begin async run on
  a CPU), `MSHV_VTL_SIDECAR_STOP` (request cancel),
  `MSHV_VTL_SIDECAR_RUN` (synchronous command).
- *Mmap:* `mmap(fd, ..., MAP_SHARED)` over the per-VP shared pages
  (`CommandPage` + `HvX64RegisterPage`).
- *Polling:* `read()` from the sidecar fd inside a `pal_async`
  `PollFdReady` loop to discover which VPs have completed and wake their
  `Waker`s.
- *Wire protocol:* Writes `SidecarCommand` and request data into
  `CommandPage.request_data`; reads results back from the same buffer;
  relays `HvError` from `HvStatus` fields.

**Trust.** Runs in usermode inside VTL2; trusts the Linux kernel and the
sidecar kernel (same trust domain). Receives intercept messages and register
state that originated from VTL0 — anything it returns to higher-level
`openvmm_hcl` carries **(b) VTL0 guest → VTL2** taint that the VMM must
validate.

### `bootloader_fdt_parser`

**Responsibility.** Userspace (`std`, `forbid(unsafe_code)`) parser that
re-reads the OpenHCL devicetree produced by `openhcl_boot` (via
`/sys/firmware/fdt`) inside underhill usermode. Unlike `host_fdt_parser`,
the input here is produced by the trusted bootshim, so this crate is largely
a typed view over already-validated data.

**Modules.**

- [lib.rs](openhcl/bootloader_fdt_parser/src/lib.rs) — Entire crate. Defines
  `Cpu`, `Memory`, `Vtl`, `Mmio`, `AddressRange`, `IsolationType`,
  `MemoryAllocationMode`, `ParsedBootDtInfo`, `BootTimes`, the `parse_*`
  helpers (cpus, memory, openhcl subtree, GIC, PMU), and the public
  constructors that read `/sys/firmware/fdt`.

**Public API.**

- `ParsedBootDtInfo::new()` and `new_from_raw(&[u8])`, with public fields
  `cpus`, `vtl0_alias_map`, `vtl2_memory`, `partition_memory_map`,
  `vtl0_mmio`, `config_ranges`, `vtl2_reserved_range`,
  `vtl2_persisted_header`, `vtl2_persisted_protobuf_region`,
  `accepted_ranges`, `memory_allocation_mode`, `isolation`,
  `private_pool_ranges`, `gic`.
- `BootTimes::new()` / `new_from_raw(&[u8])` with `start`, `end`,
  `sidecar_start`, `sidecar_end`.
- `Cpu`, `Memory`, `Mmio`, `Vtl`, `AddressRange`, `IsolationType`,
  `MemoryAllocationMode`. All types implement `Inspect`.

**External I/O.** Reads the file `/sys/firmware/fdt` (the FDT the kernel
was booted with — i.e., the one produced by `openhcl_boot::dt::write_dt`).
Recognizes the OpenHCL-specific node tree: `/cpus`, `/memory@*`, `/intc@`
and `/pmu` (aarch64), and the `/openhcl` subtree (`vtl0-mmio`,
`config-ranges`, `partition-memory-map` with `IGVM_DT_IGVM_TYPE_PROPERTY`
and `MemoryVtlType` tagging, `vtl2-reserved-range`,
`vtl2-persisted-{header,protobuf-region}`, `accepted-memory`,
`vtl0-alias-map`, `memory-allocation-mode`, `isolation-type`,
`private-pool-ranges`).

**Trust.** None of the relevant adversarial ones. Input is produced by
`openhcl_boot` and read from `/sys/firmware/fdt`, both inside the VTL2
trust domain — the source comment explicitly notes "these values are
trusted, as it's expected that openhcl_boot has already validated the host
provided device tree."

## Hypervisor interface & memory

### `hcl`

**Responsibility.** Userspace bindings to the Linux `mshv` kernel driver
that exposes the Microsoft Hypervisor to the VTL2 paravisor. It opens
`/dev/mshv*` device files, issues ioctls, maps the per-VP run page /
register page / VMSA / APIC pages, and provides a typed Rust API
(hypercalls, register get/set, page acceptance, TLB flush, deferred SINT
actions, `pvalidate`/`rmpadjust`/`tdcall`) used by `virt_mshv_vtl` and
`underhill_mem`. Also handles the `sidecar` worker-thread fast path and
exposes `/proc/mshv` VP statistics.

**Modules.**

- [lib.rs](openhcl/hcl/src/lib.rs) — Crate root; defines `GuestVtl`
  (VTL0/VTL1, statically excluding VTL2) plus `From`/`TryFrom` glue and
  `UnsupportedGuestVtl`.
- [ioctl.rs](openhcl/hcl/src/ioctl.rs) — Main interface to the four `mshv`
  device files; defines all error enums, the device wrappers (`Mshv`,
  `MshvVtl`, `MshvVtlLow`, `MshvHvcall`), the partition-level `Hcl`
  object, and `ProcessorRunner` (per-VP runner that performs
  `HCL_RETURN_TO_LOWER_VTL` ioctls and handles the shared run page).
- [ioctl/x64.rs](openhcl/hcl/src/ioctl/x64.rs) /
  [ioctl/aarch64.rs](openhcl/hcl/src/ioctl/aarch64.rs) — Backings
  `MshvX64`/`MshvArm64` for non-isolated partitions; expose the per-VP
  register page (`HvX64RegisterPage`/`HvAarch64RegisterPage`) and CPU
  context for fast register access.
- [ioctl/snp.rs](openhcl/hcl/src/ioctl/snp.rs) — SEV-SNP backing exposing
  the `SevVmsa` and `SevAvicPage` mappings, plus
  `pvalidate`/`rmpadjust`/`rmpquery` ioctl wrappers and `SnpPageError`.
- [ioctl/tdx.rs](openhcl/hcl/src/ioctl/tdx.rs) — TDX backing exposing the
  `tdx_vp_context`/`VmxApicPage`, `MshvVtlTdcall` adapter, and helpers for
  setting/getting page attributes and per-VP TDX private regs.
- [ioctl/register.rs](openhcl/hcl/src/ioctl/register.rs) — Generic per-VP
  register get/set via `MSHV_GET_VP_REGISTERS`/`MSHV_SET_VP_REGISTERS`
  ioctls or hypercall fallback; defines `GetRegError`/`SetRegError`.
- [ioctl/deferred.rs](openhcl/hcl/src/ioctl/deferred.rs) — Thread-local
  queue (max 8) of `DeferredAction`s (e.g., signal SINT events) that are
  written into the VP assist page and consumed by the kernel on the next
  VTL transition for low-latency intercept handling.
- [protocol.rs](openhcl/hcl/src/protocol.rs) — `#[repr(C)]` structures
  shared with the `mshv_vtl` kernel driver: `hcl_run`,
  `hcl_intr_offload_flags`, `EnterModes`, `hcl_translate_address_info`,
  post-message/signal-event direct payloads, TDX VP context, page offsets
  (`HCL_REG_PAGE_OFFSET`, `HCL_VMSA_PAGE_OFFSET`, `MSHV_APIC_PAGE_OFFSET`).
- [mapped_page.rs](openhcl/hcl/src/mapped_page.rs) — Thin `mmap` helper for
  the various per-VP pages exposed by the kernel via file offsets.
- [vmbus.rs](openhcl/hcl/src/vmbus.rs) — Bindings for `/dev/mshv_sint`:
  post hypervisor messages, signal events, register an eventfd to a SINT,
  pause the message stream (used by VMBus relay).
- [vmsa.rs](openhcl/hcl/src/vmsa.rs) — `VmsaWrapper` that combines an
  `SevVmsa` with the SNP register tweak bitmap, providing safe register
  accessors that XOR the tweak when reading/writing protected fields.
- [stats.rs](openhcl/hcl/src/stats.rs) — Reads `/proc/mshv` for `HclVpStats`
  (VTL transition counters).

**Public API.**

- `GuestVtl`, `UnsupportedGuestVtl`.
- `ioctl::Hcl` — partition-level handle (caps probe, intercept install,
  set VSM partition config, etc.).
- `ioctl::Mshv`, `ioctl::MshvVtl`, `ioctl::MshvVtlLow`, `ioctl::MshvHvcall`
  — device wrappers.
- `ioctl::ProcessorRunner<'a, T: Backing<'a>>`, `ioctl::Backing` (sealed
  trait), backings `ioctl::x64::MshvX64`, `ioctl::aarch64::MshvArm64`,
  `ioctl::snp::Snp`, `ioctl::tdx::Tdx`.
- Hypercall / page helpers: `MshvHvcall::set_allowed_hypercalls`,
  `accept_gpa_pages`, `modify_gpa_visibility`,
  `modify_vtl_protection_mask`, `MshvVtl::add_vtl0_memory`,
  `pvalidate_pages`, `rmpadjust_pages`, `rmpquery_pages`,
  `tdx_set_page_attributes`, `tdx_accept_pages`.
- `ioctl::register::{GetRegError, SetRegError}`, register page accessors.
- `vmsa::VmsaWrapper`, `vmbus` post/signal helpers, `stats::vp_stats`,
  `protocol::*` raw layouts.
- Error families: `Error`, `HypercallError`, `HvcallError`, `IoctlError`,
  `ApplyVtlProtectionsError`, `AcceptPagesError`,
  `TranslateGvaToGpaError`, `TranslateResult`, `CheckVtlAccessResult`,
  `SetVsmPartitionConfigError`, `SetGuestVsmConfigError`,
  `GetVpIndexFromApicIdError`.

**External I/O.**

- *Device files:* `/dev/mshv` (capability probe + create VTL),
  `/dev/mshv_vtl` (per-partition; ioctls `MSHV_RETURN_TO_LOWER_VTL`,
  `MSHV_ADD_VTL0_MEMORY`, `MSHV_GET/SET_VP_REGISTERS`, `MSHV_TLBSYNC`,
  `MSHV_KICKCPUS`, `MSHV_PVALIDATE`, `MSHV_RMPADJUST`, `MSHV_RMPQUERY`,
  `MSHV_TDCALL`, `MSHV_MAP_REDIRECTED_DEVICE_INTERRUPT`,
  `MSHV_RESTORE_PARTITION_TIME`, plus checks via `HCL_CHECK_EXTENSION`),
  `/dev/mshv_vtl_low` (mmap of guest GPA space; bit 63 in offset =
  "shared" mapping), `/dev/mshv_hvcall` (gated, allow-list of
  `HypercallCode`s like `HvCallAcceptGpaPages`,
  `HvCallModifySparseGpaPageHostVisibility`,
  `HvCallModifyVtlProtectionMask`, `HvCallTranslateVirtualAddressEx`,
  `HvCallPostMessageDirect`, `HvCallSignalEventDirect`,
  `HvCallAssertVirtualInterrupt`, etc.), `/dev/mshv_sint`
  (`MSHV_SINT_SIGNAL_EVENT`, `MSHV_SINT_POST_MESSAGE`,
  `MSHV_SINT_SET_EVENTFD`, `MSHV_SINT_PAUSE_MESSAGE_STREAM`).
- *Mmap'd shared pages* at fixed `pg_off`: VP run page (`hcl_run`), HV
  register page, SNP VMSA + guest-VSM VMSA, MSHV APIC page.
- `/proc/mshv` text file for per-VP stats.
- *Sidecar* worker IPC via `sidecar_client` (`SidecarClient`, `SidecarVp`,
  `SidecarRun`).
- *ISA-level instructions* `tdcall` invocation paths used on TDX.

**Trust.** **(c) Hypervisor → VTL2** (every register page, run page,
VMSA, intercept message, and translate result is data produced by an
untrusted hypervisor in the CVM model — must not panic). Also the
foundation that the rest of the paravisor uses to reflect VTL0 guest
state, so the inputs read from these pages are guest-influenced (b) and the
kernel driver was loaded by the host (a) — but no guest input is parsed
here directly.

### `hcl_mapper`

**Responsibility.** Tiny adapter that implements the
`page_pool_alloc::PoolSource` trait on top of `hcl::ioctl::MshvVtlLow`, so
that the OpenHCL page pools can mmap GPA-backed pages out of
`/dev/mshv_vtl_low` either as private or shared (with a vTOM bias and the
`SHARED_MEMORY_FLAG` file-offset bit).

**Modules.**

- [lib.rs](openhcl/hcl_mapper/src/lib.rs) — Defines `HclMapper` plus the
  constructors `new_shared(vtom)` and `new_private()`, and implements
  `PoolSource` (`address_bias`, `file_offset`, `mappable`).

**Public API.** `HclMapper`, `HclMapper::new_shared`,
`HclMapper::new_private`.

**External I/O.** Opens `/dev/mshv_vtl_low` via `MshvVtlLow::new()`; the
resulting fd is used by `sparse_mmap` to back DMA buffers. Adds `vtom` to
GPAs for shared-memory clients and ORs in `MshvVtlLow::SHARED_MEMORY_FLAG
(1 << 63)` in the mmap file offset.

**Trust.** None directly; it is plumbing inside VTL2. Indirectly, the pages
mapped this way are shared with the host (when `is_shared`), so any
consumer DMAing in/out of them must treat their contents as untrusted
**(a) host → VTL2**.

### `virt_mshv_vtl`

**Responsibility.** The Microsoft Hypervisor backend of the OpenVMM
`virt::Partition` trait, used inside OpenHCL to represent a partition whose
lower VTLs are run via the `mshv` kernel driver. It owns
`UhPartition`/`UhProcessor`, dispatches per-VP execution loops, handles
VTL0→VTL2 intercepts, drives an in-paravisor synic/APIC emulator, performs
CPUID composition for hardware CVMs, and hosts isolation-specific backings
for non-isolated, VBS, SNP and TDX partitions, including
hardware-CVM-shared logic (TLB lock, APIC poll, intercept handling).

**Modules.**

- [lib.rs](openhcl/virt_mshv_vtl/src/lib.rs) — Re-exports per-isolation
  `*Backed` types, defines `UhPartition`, `UhPartitionInner`,
  `UhProcessorBox`, `UhPartitionNewParams`/`UhLateParams`/`CvmLateParams`,
  `UhProtoPartition`, `BackingShared`, the `ProtectIsolatedMemory` and
  `TlbFlushLockAccess` traits, `GpnSource`, `SecureRegisterInterceptState`,
  `HostIoPortFastPathHandle`, `VtlCrash`, plus a large `Error`/
  `RevokeGuestVsmError` enum and partition construction.
- [devmsr.rs](openhcl/virt_mshv_vtl/src/devmsr.rs) — `MsrDevice` wrapper
  around `/dev/cpu/N/msr` for reading host MSRs (used to read TSC frequency
  on hardware CVMs).
- `processor/mod.rs` — Re-exports `Backing` and `UhProcessor<'a, T>`;
  defines per-VP state (`VtlsTlbLocked`, `LapicState`, `BackingShared`,
  `BackingSharedParams`, `BackingParams`, `private::BackingPrivate`,
  `UhEmulationState`, `UhHypercallHandler`, sidecar exit reasons, the
  `HardwareIsolatedBacking` trait); implements `virt::Processor::run_vp`
  and the dispatch loop.
- `processor/nice.rs` — Trivial `libc::nice` wrapper used to lower the
  priority of the dispatcher thread.
- `processor/vp_state.rs` — `UhVpStateAccess<'_, '_, T>` plus an `Error`
  enum used by `virt::vp::AccessVpState` impls in each backing.
- `processor/mshv/{mod,x64,arm64,tlb_lock}.rs` — Hypervisor-backed
  (non-hardware-isolated, VBS) backings. `HypervisorBackedX86`/`Arm64`
  implement intercept message handling, register page emulation, MMIO/IO
  port emulation via `virt_support_x86emu`/`aarch64emu`, MSR and CPUID
  intercepts, and SMC/PSCI on aarch64.
- `processor/snp/mod.rs` — `SnpBacked`/`SnpBackedShared`: VMSA-driven exit
  decoding (`SevExitCode`), `#VC` handling, NPF fault handling, GHCB
  hypercall path, paravisor-driven SINT/APIC/timer/INIT/SIPI handling on
  top of `hardware_cvm` traits.
- `processor/tdx/{mod,tlb_flush}.rs` — `TdxBacked`/`TdxBackedShared`:
  `TDG.VP.ENTER` L2 entry, VM-exit qualification decoding,
  EPT/MMIO/IO/CR/MSR exit handlers, TDVMCALL fast paths, and a per-partition
  TLB flush state (ring buffer of INVGLA/INVLPG requests, `FLUSH_GVA_LIST_SIZE
  = 32`).
- `processor/hardware_cvm/{mod,apic,tlb_lock}.rs` — Code shared between SNP
  and TDX backings: common CVM intercept/hypercall/VTL-switch flows,
  `ApicBacking` trait + `poll_apic_core` driving the in-paravisor
  `LocalApic`, and `TlbLockAccess` synchronization between VPs.
- `cvm_cpuid/{mod,masking,snp,tdx,tests/*}.rs` — Hardware-CVM CPUID
  composition (x86_64 only): assembles CPUID tables from PSP CPUID pages
  (SNP) or TDX-provided values; `CpuidResultMask` whitelists supported
  bits per leaf/subleaf; `SnpCpuidInitializer`/`TdxCpuidInitializer`
  populate the table.

**Public API.**

- `UhPartition`, `UhPartitionNewParams`, `UhLateParams`, `CvmLateParams`,
  `UhProtoPartition`, `UhProcessorBox`.
- `Backing` (re-export of `processor::Backing`), `UhProcessor` (re-export).
- Per-isolation backings: `HypervisorBacked` (= `HypervisorBackedX86`/
  `HypervisorBackedArm64` per arch), `SnpBacked`, `TdxBacked`.
- `ProtectIsolatedMemory` trait (implemented externally by
  `underhill_mem`), `TlbFlushLockAccess` trait.
- `GpnSource`, `SecureRegisterInterceptState`, `HostIoPortFastPathHandle`,
  `VtlCrash`.
- `Error`, `RevokeGuestVsmError`.

**External I/O.**

- All hypervisor/kernel I/O is routed through the `hcl` crate (per-VP run,
  register get/set, SINT post/signal, intercept install, VTL protection
  hypercalls, page acceptance, `pvalidate`/`rmpadjust`/`tdcall`).
- VTL0 intercept messages (`HvX64InterceptMessage*`,
  `HvAarch64InterceptMessage*`) read from the kernel-mapped per-VP run
  page (`hcl_run`) and the HV register page; emulated against the
  in-paravisor APIC/synic/timer.
- For hardware CVMs: SNP VMSA fields (RAX/RIP/CS/EFER/etc.,
  `SevEventInjectInfo`, `SecureAvicControl`, `SevFeatures`) accessed
  through `VmsaWrapper`; TDX L2 enter state (`TdxL2EnterGuestState`,
  `TdxL2Ctls`, `TdxVmFlags`, `VmcsField`s) and `tdcall`
  (`TDG.MEM.PAGE.ATTR.WR`, `TDG.VP.ENTER`, `TDG.VP.INVGLA`,
  `TDG.VP.RD/WR`).
- Hypercalls via `MshvHvcall`: `HvCallAssertVirtualInterrupt`,
  `HvCallTranslateVirtualAddress(Ex)`, `HvCallInstallIntercept`
  (`HvInterceptType::Cpuid`/`Msr`/`Hypercall`/etc.),
  `HvCallModifyVtlProtectionMask`, `HvCallEnableVpVtl`,
  `HvCallStartVirtualProcessor`, `HvCallSendSyntheticClusterIpi`,
  deliverability-notification flushes, `HvCallSignalEventDirect`/
  `HvCallPostMessageDirect`.
- `/dev/cpu/N/msr` read via `MsrDevice` for reference TSC frequency
  (hardware CVMs).
- `/proc/mshv` (via `hcl::stats`) for inspect output.
- `mesh::Sender<VtlCrash>` to ship guest crashes outward; `MonitorPage`
  for vmbus monitor-page emulation.

**Trust.**

- **(b) VTL0 guest → VTL2 paravisor** — Every intercept message, register
  page snapshot, MMIO/IO/MSR/CPUID input, GHCB request, TDVMCALL payload,
  hypercall input, VMBus relay traffic, and APIC IRR delivered here
  originates with the untrusted VTL0 guest. None of this code may panic
  on guest input; `tracelimit::*_ratelimited!` is used heavily here.
- **(c) Hypervisor → VTL2** (CVM-relevant) — Even the basic dispatcher
  loop for SNP/TDX treats VMSA/TDX exit info as data produced by an
  untrusted hypervisor; CPUID for CVMs is rebuilt from the SNP CPUID page
  / TDX info rather than trusting hypervisor leaves.
- **(a) Host/VMM → VTL2** — Indirectly, through the `mshv_vtl` driver
  loaded by the host and through the synic relay.

### `underhill_mem`

**Responsibility.** VTL2 memory manager for OpenHCL. Constructs the
`GuestMemory` views over VTL0/VTL1 GPA space (both encrypted/private and
shared mappings on CVMs), tracks per-page validity bitmaps, lazily
registers chunks of guest memory with the kernel `mshv_vtl` driver, and on
hardware-isolated VMs implements `virt_mshv_vtl::ProtectIsolatedMemory`
to perform page acceptance, host-visibility changes, VTL permission
changes, locking of pages for emulation, and overlay-page tracking.

**Modules.**

- [lib.rs](openhcl/underhill_mem/src/lib.rs) — Re-exports the `init` API;
  defines `MemoryAcceptor` (fronts `pvalidate`/`rmpadjust`, TDX page
  attributes, VBS `HvCallAcceptGpaPages`, and
  `HvCallModifySparseGpaPageHostVisibility`),
  `HardwareIsolatedMemoryProtector` (the `ProtectIsolatedMemory` impl that
  owns valid/encrypted/shared bitmaps and overlay/locked-pages
  bookkeeping), `GpaVtlPermissions`, `DefaultVtlPermissions`,
  `MshvVtlWithPolicy` (`RegisterMemory` trait), and the
  `QueryVtlPermissionsError`/`ModifyGpaVisibilityError` errors.
- [init.rs](openhcl/underhill_mem/src/init.rs) — `init(...)` entry point
  and supporting `Init`/`BootInit`/`MemoryMappings`/`CvmMemory` types:
  builds the per-VTL `GuestMemoryMapping`s, the dedicated kernel-exec /
  user-exec views (`vtl0_kernel_exec_gm` / `vtl0_user_exec_gm`), the
  optional shared mapping for CVMs, accepts and applies initial
  protections to RAM, and constructs a `HardwareIsolatedMemoryProtector`
  when applicable.
- [mapping.rs](openhcl/underhill_mem/src/mapping.rs) —
  `GuestPartitionMemoryView`, `GuestValidMemory` (per-page validity
  bitmap), `GuestMemoryMapping` and `GuestMemoryView`/
  `GuestMemoryViewReadType` implementing `GuestMemoryAccess` over
  `SparseMapping`s of `/dev/mshv_vtl_low` for normal/kernel-exec/user-exec
  views; routes per-page reads/writes through the validity bitmap and
  reports `GuestMemoryBackingError`s.
- [registrar.rs](openhcl/underhill_mem/src/registrar.rs) —
  `MemoryRegistrar<T>` lazily registers guest memory with the kernel in
  2 GiB chunks (a bitmap of registered chunks) on first VA leak — amortizes
  the kernel `struct page` setup cost.

**Public API.**

- `init`, `Init`, `BootInit`, `MemoryMappings`.
- `MemoryAcceptor` (`accept_lower_vtl_pages`, `modify_gpa_visibility`,
  `apply_initial_lower_vtl_protections`).
- `HardwareIsolatedMemoryProtector::new` (consumed via `Arc<dyn
  ProtectIsolatedMemory>` from `virt_mshv_vtl`).
- `QueryVtlPermissionsError`, `ModifyGpaVisibilityError`.

**External I/O.**

- `/dev/mshv_vtl_low` mapped via `SparseMapping` to back `GuestMemory`.
  Bit 63 of the file offset selects shared-vs-private mapping for CVMs.
- `/dev/mshv_vtl` `MSHV_ADD_VTL0_MEMORY` ioctl (lazy, in 2 GiB chunks)
  via `MemoryRegistrar`.
- Hypercalls via `MshvHvcall` (allow-list set in `MemoryAcceptor::new`):
  `HvCallAcceptGpaPages`, `HvCallModifySparseGpaPageHostVisibility`,
  `HvCallModifyVtlProtectionMask`.
- SEV-SNP: `pvalidate`/`rmpadjust` via `MshvVtl` ioctls (`SevRmpAdjust`
  flags).
- TDX: `TDG.MEM.PAGE.ATTR.WR` via `MshvVtl::tdx_set_page_attributes` /
  `tdx_accept_pages` (`TdgMemPageGpaAttr`, `TdgMemPageAttrWriteR8`,
  `GpaVmAttributes`, `GpaVmAttributesMask`).

**Trust.**

- **(a) Host/VMM → VTL2** — Memory layout descriptions and host-visibility
  transitions originate in the (untrusted on CVMs) host; the validity
  bitmap and `GuestValidMemory` exist precisely so that reads from
  yet-unaccepted/host-shared pages cannot poison private state.
- **(b) VTL0 guest → VTL2** — `GuestMemory` reads triggered by VTL2
  emulators are reads of guest-authored bytes; data must be range-checked
  and treated as untrusted.
- **(c) Hypervisor → VTL2** — page acceptance and permission hypercalls go
  through the untrusted hypervisor; failures surface as `HvError` rather
  than panics.

### `lower_vtl_permissions_guard`

**Responsibility.** RAII helper for "lowering" VTL2's exclusive permissions
on a set of GPA pages so that a lower VTL (the guest) can DMA into them,
and automatically restoring `HV_MAP_GPA_PERMISSIONS_NONE` on drop. Wraps a
generic `DmaClient` so that buffers it allocates are automatically opened
to a lower VTL for the lifetime of the buffer.

**Modules.**

- [lib.rs](openhcl/lower_vtl_permissions_guard/src/lib.rs) —
  `PagesAccessibleToLowerVtl` guard (calls
  `VtlMemoryProtection::modify_vtl_page_setting` to grant
  `HV_MAP_GPA_PERMISSIONS_ALL` on construction and reset to
  `HV_MAP_GPA_PERMISSIONS_NONE` on drop, **panicking** on rollback failure),
  and `LowerVtlMemorySpawner<T: DmaClient>` that decorates an inner DMA
  client.
- [device_dma.rs](openhcl/lower_vtl_permissions_guard/src/device_dma.rs) —
  `LowerVtlDmaBuffer`, the `MappedDmaTarget` newtype that pairs an inner
  `MemoryBlock` with the guard so they are released together.

**Public API.**

- `LowerVtlMemorySpawner<T>` (implements `user_driver::DmaClient`).
- `LowerVtlDmaBuffer`.

**External I/O.** Only via `Arc<dyn virt::VtlMemoryProtection>` (typically
`HardwareIsolatedMemoryProtector` from `underhill_mem` or
`DmaManagerLowerVtl` in `openhcl_dma_manager`) which in turn issues
`HvCallModifyVtlProtectionMask` hypercalls per PFN.

**Trust.** VTL2-internal trust enforcement. A failure to restore
`PERMISSIONS_NONE` on drop is treated as fatal (`panic!`) because leaving
lowered permissions in place would be a security regression. The buffers
handed out are by definition reachable from the VTL0 guest, so the
consuming device driver must treat their contents as untrusted **(b)** when
read back.

### `openhcl_dma_manager`

**Responsibility.** The single, partition-wide owner of DMA-capable memory
in OpenHCL. It manages a "shared" page pool (host-visible memory backed by
`HclMapper::new_shared(vtom)`) and a "private" page pool (private memory
backed by `HclMapper::new_private`), plus fall-back locked memory; given a
`DmaClientParameters` (visibility + lower-VTL policy + persistence), it
picks an appropriate backing and produces a typed `OpenhclDmaClient`. It is
also save/restore-able so DMA buffers survive servicing.

**Modules.**

- [lib.rs](openhcl/openhcl_dma_manager/src/lib.rs) — Defines
  `OpenhclDmaManager`, `DmaManagerInner`, `DmaManagerLowerVtl` (a
  `VtlMemoryProtection` impl that opens its own `MshvHvcall` and only
  allow-lists `HvCallModifyVtlProtectionMask`), `DmaClientParameters`,
  `LowerVtlPermissionPolicy`, `AllocationVisibility`, `DmaClientSpawner`,
  `DmaClientBacking` (variants `SharedPool`, `PrivatePool`, `LockedMemory`,
  `PrivatePoolLowerVtl`, `LockedMemoryLowerVtl`), `OpenhclDmaClient`. The
  nested `save_restore` module provides `OpenhclDmaManagerState`
  (`Protobuf`, mesh package `openhcl.openhcldmamanager`) and the
  `SaveRestore` impl that delegates to each `PagePool`.

**Public API.**

- `OpenhclDmaManager` (with `SaveRestore`).
- `DmaClientSpawner::new_client(DmaClientParameters) ->
  Arc<OpenhclDmaClient>`.
- `OpenhclDmaClient` (implements `user_driver::DmaClient`).
- `DmaClientParameters`, `LowerVtlPermissionPolicy { Any, Vtl0 }`,
  `AllocationVisibility { Shared, Private }`.
- `save_restore::OpenhclDmaManagerState`.

**External I/O.**

- Backing pages come from the `page_pool_alloc::PagePool` over an
  `HclMapper` (which mmaps `/dev/mshv_vtl_low`) for the shared/private
  pools; `LockedMemorySpawner` for non-pool clients.
- For lower-VTL exposure on non-hardware-isolated VMs, opens
  `/dev/mshv_hvcall` and issues `HvCallModifyVtlProtectionMask` per PFN
  through `MshvHvcall` (allow-list contains only that hypercall).
- Save/restore wire format: mesh `Protobuf`, package
  `openhcl.openhcldmamanager`, fields `shared_pool` and `private_pool`
  (each a `PagePoolState`).
- DMA contracts: `DmaClient::allocate_dma_buffer(len)` returns a
  `MemoryBlock` with stable PFNs and an mmaped VA; `attach_pending_buffers()`
  reattaches buffers reserved across a save/restore (only supported for
  pool-backed clients).

**Trust.**

- **(a) Host/VMM → VTL2** — "Shared" allocations are by definition visible
  to the host; VTL2 code reading those buffers must treat their contents
  as untrusted host input.
- **(b) VTL0 guest → VTL2** — Allocations with
  `LowerVtlPermissionPolicy::Vtl0` are accessible to the VTL0 guest, which
  can mutate them concurrently with VTL2 reads.
- The `DmaManagerLowerVtl` path explicitly notes it must not be used on
  hardware-isolated VMs because it relies on the (untrusted) hypervisor
  enforcing VTL protections.

### TDISP in OpenHCL — overview

> **NOTE.** This whole subsystem is in active development on branch
> `tdisp_tio_vpci`. The description below reflects the state of that
> branch (as of commit `9675d6bc`, "vpci_relay: defer command-register
> write on MMIO-disable edge until after unbind"). Several pieces are
> gated on the `dev_snp_ohcl_tio_support` Cargo feature (a.k.a. the
> "tio" feature) and will not compile into a default OpenHCL image.

TDISP (TEE Device Interface Security Protocol, PCI-SIG ECN) lets a
confidential VM (CVM) verify that a passed-through PCIe device is
operating in a confidentiality-protected ("LOCKED" / "RUN") TDI state
and that its MMIO/DMA resources are isolated from the untrusted host.
In OpenHCL it is split across these crates:

| Crate | Path | Role |
|-------|------|------|
| `tdisp` | `vm/devices/tdisp` | Protocol-agnostic state machine + per-device traits + `TdispIsolationReport` |
| `tdisp_proto` | `vm/devices/tdisp_proto` | Generated protobuf wire types + error-code enums |
| `openhcl_tdisp` | `openhcl/openhcl_tdisp` | Paravisor-side glue: `TdispVirtualDeviceInterface` (guest cmd transport) + `TdispResourceValidationInterface` (platform unblock/block) + SEV-TIO impl + mocks |
| `vpci_protocol` | `vm/devices/pci/vpci_protocol` | `VPCI_TDISP_COMMAND` (`0x4249001D`) and `VPCI_QUERY_ISOLATED_RESOURCES` (`0x4249001E`) wire messages, `ProtocolVersion::GE_TDISP` (`0x00010007`), `ResourceIsolation` enum |
| `vpci` | `vm/devices/pci/vpci` | Guest-facing VPCI server: GE_TDISP version negotiation, TDISP-command dispatch, `QueryIsolatedResources` reply assembly |
| `vpci_client` | `vm/devices/pci/vpci_client` | Paravisor-side host-VPCI client; owns `VpciClientTdispState`, drives the bind/start/attest/unbind flow over the host channel, blocks/unblocks MMIO+DMA via the resource validator |
| `vpci_relay` | `vm/devices/pci/vpci_relay` | Wires host-VPCI → guest-VPCI; implements `TdispIsolationReporter`, defers command-register edges around bind/unbind, unbinds on teardown |
| `sev_guest_device` | `support/sev_guest_device` | `/dev/sev-guest` ioctl wrapper; under feature `dev_snp_ohcl_tio_support` exposes `tio_guest_request` and surfaces ASP/VMM error fields |
| `sev_guest_device_tio` | `support/sev_guest_device/sev_guest_device_tio` | SEV-TIO firmware message structs (per AMD Spec 0.91): `TioMsgTdiInfoReq/Rsp`, `TioMsgMmioValidateReq/Rsp`, `TioMsgSdteWriteReq/Rsp`, `TioMsgTdiStatus` |
| `chipset_device::tdisp` | `vm/chipset_device/src/lib.rs` | Capability accessors `supports_tdisp` (→ `TdispHostDeviceTarget`) and **new** `supports_tdisp_isolation` (→ `TdispIsolationReporter`) |

#### `tdisp` (paravisor + host shared protocol)

**Responsibility.** Hosts the TDISP state machine, the per-device host
trait that virtualization backends implement, and the isolation-report
abstraction the guest-facing VPCI server uses to answer
`QueryIsolatedResources`. `#![forbid(unsafe_code)]`.

**Modules.**

- [lib.rs](vm/devices/tdisp/src/lib.rs) — `TdispHostStateMachine`
  (Unlocked ↔ Locked ↔ Run with explicit `is_valid_state_transition`
  table; protocol must be negotiated before any state move),
  `TdispHostDeviceInterface` trait (negotiate / bind / start / unbind /
  get_report — implemented by virtualization backends),
  `TdispHostDeviceTargetEmulator` (dispatches a deserialized
  `GuestToHostCommand` through the state machine into the backend),
  `TdispIsolationReporter` trait, `TdispIsolationReport` enum
  (`NotTdispCapable` / `NotReady` / `Ready { bars, dma }` / `Error`),
  `TdispResourceIsolation` enum (`Shared` / `Private` / `Invalid`),
  and the `TdispUnbindReason` taxonomy (`GuestInitiated`,
  `ImpossibleStateTransition`, `InvalidGuestTransitionToLocked/Run`,
  `InvalidGuestGetAttestationReportState`,
  `InvalidGuestAcceptAttestationReportState`,
  `InvalidGuestUnbindReason`, `Unknown`). Includes `cfg(kani)`-gated
  `err_shim` and `tracing/max_level_off` plumbing for model checking.
- [serialize_proto.rs](vm/devices/tdisp/src/serialize_proto.rs) —
  prost-based command/response (de)serialization plus `validate_command`
  / `validate_response` that reject unknown enums (`require_enum!`),
  enforce `Success` responses carry the matching response payload, and
  enforce `GetTdiReport` Success carries a non-empty report buffer.
- [devicereport.rs](vm/devices/tdisp/src/devicereport.rs) —
  `TdiReportStruct` + raw-buffer parser used by `vpci_client` after
  the TDI report is fetched from the host.
- [test_helpers.rs](vm/devices/tdisp/src/test_helpers.rs) —
  `NullTdispHostInterface`, `KaniSymbolicHostInterface`, mock
  forged-OK host adversary used by `vpci_client::tests` and Kani.
- [kani_proofs.rs](vm/devices/tdisp/src/kani_proofs.rs) — Kani harness
  proving the state-transition truth table and bind/start/unbind
  gating against an unconstrained adversarial host.

**Public API (selected).**

```rust
pub trait TdispHostDeviceInterface: Send + Sync {
    fn tdisp_negotiate_protocol(
        &mut self, requested: TdispGuestProtocolType,
    ) -> Result<TdispDeviceInterfaceInfo>;
    fn tdisp_bind_device(&mut self) -> Result<()>;
    fn tdisp_start_device(&mut self) -> Result<()>;
    fn tdisp_unbind_device(&mut self) -> Result<()>;
    fn tdisp_get_device_report(&mut self, report_type: TdispReportType)
        -> Result<Vec<u8>>;
}

pub trait TdispIsolationReporter: Send + Sync {
    fn tdisp_isolation_report(&mut self) -> TdispIsolationReport;
}

pub enum TdispIsolationReport {
    NotTdispCapable,
    NotReady,
    Ready { bars: [TdispResourceIsolation; 6], dma: TdispResourceIsolation },
    Error,
}
```

`TdispGuestUnbindReason` was extended on this branch with
`DeviceTeardown` (commit `8b94d4ad`, used by the relay drop path) and
`AttestationFailure` (commit `79b08246`, surfaces attestation failure
through to the host's telemetry).

#### `tdisp_proto`

**Responsibility.** Shared protobuf-derived wire definitions for the
TDISP guest↔host command channel.

**Modules.**

- [lib.rs](vm/devices/tdisp_proto/src/lib.rs) —
  prost-generated `GuestToHostCommand{Ext}` /
  `GuestToHostResponse{Ext}`, all `TdispCommand*` and
  `TdispCommandResponse*` payloads, `TdispDeviceInterfaceInfo`,
  `TdispGuestProtocolType`, `TdispReportType`,
  `TdispGuestUnbindReason`, `TdispGuestOperationErrorCode`.
- [errorcode.rs](vm/devices/tdisp_proto/src/errorcode.rs) —
  `TdispGuestOperationError` and code mapping helpers.

#### `openhcl_tdisp` (paravisor-side glue)

**Responsibility.** The single OpenHCL crate that ties together (1) the
guest-facing TDISP **command transport** the `vpci` server writes into,
(2) the platform-facing TDISP **resource validator** the `vpci_client`
calls to flip MMIO/DMA between SHARED and PRIVATE around bind/unbind,
and (3) the SEV-TIO concrete implementation of that validator. Pure
re-exports of `tdisp` / `tdisp_proto` types are still here so that
downstream crates only depend on `openhcl_tdisp`.

**Modules.**

- [lib.rs](openhcl/openhcl_tdisp/src/lib.rs) —
  - `TdispVirtualDeviceInterface` async trait (methods:
    `send_tdisp_command`, `tdisp_get_device_interface_info`,
    `tdisp_bind_interface`, `tdisp_start_device`,
    `tdisp_get_device_report`, `tdisp_get_tdi_report`,
    `tdisp_get_tdi_device_id`, `tdisp_unbind`). Refactored on this
    branch (commit `f0050d0f`) to provide higher-level async
    operations rather than raw `send_tdisp_command` calls; the
    `attest()` flow (commit `48cf2c8a`) builds on top of this.
  - `TdispResourceValidationInterface` trait (commits `e9aa6dc4`,
    `4ddcfbcf`, `72605ad2`):
    ```rust
    pub trait TdispResourceValidationInterface: Send + Sync {
        fn tdisp_unblock_mmio(
            &self, target_vtl: Vtl, device_id: u16,
            base_gpa: u64, base_offset: u32,
            length_in_bytes: u32, range_id: u16,
        ) -> Result<()>;
        fn tdisp_unblock_dma(&self, target_vtl: Vtl, device_id: u16) -> Result<()>;
        fn tdisp_block_mmio(/* same args */) -> Result<()>;       // commit 54549475
        fn tdisp_block_dma(&self, target_vtl: Vtl, device_id: u16) -> Result<()>;
        fn tdisp_query_firmware_tdi_state(&self, device_id: u16)  // commit 936d0471
            -> Result<Option<TdispTdiState>> { Ok(None) }
    }
    ```
  - Command builders `new_get_device_interface_info_command`,
    `new_bind_command`, `new_start_tdi_command`,
    `new_get_tdi_report_command`, `new_unbind_command`.
- [sevtio.rs](openhcl/openhcl_tdisp/src/sevtio.rs) (feature
  `dev_snp_ohcl_tio_support`) — `TdispSevTioResourceValidator`
  implementing the validator trait against AMD SEV-TIO firmware.
  - `tdisp_unblock_mmio`: flips PFNs to PRIVATE via mshv, sends
    `TIO_MSG_MMIO_VALIDATE_REQ` over `/dev/sev-guest`
    (`tio_guest_request`), then `RMPADJUST`s the pages so the guest
    VMPL has read/write access.
  - `tdisp_unblock_dma`: sends `TIO_MSG_SDTE_WRITE_REQ` with the
    high-order VTOM bits masked off so the IOMMU treats the device's
    DMA as private.
  - `tdisp_block_mmio` / `tdisp_block_dma`: inverse operations,
    issued on guest-driven deactivation, on `tdisp_unbind`, and on
    `RelayedVpciDevice` drop.
  - **Per-request handle creation** (commit `7178dbd1`): a fresh
    `mshv` / `mshv_vtl` handle is opened for every validator call
    rather than caching one, because the SEV-TIO firmware requires
    that the VP that owns the file descriptor be the VP that issues
    the request.
  - **Known sharp edge:** there are still `.context("...").unwrap()`
    sites at approximately lines 43, 215, and 342 that will panic
    the paravisor on firmware/ioctl error rather than propagating
    the `Result` — these need to be converted before the feature
    leaves dev. Tracked under "Malicious-host audit" below.
- [mocks.rs](openhcl/openhcl_tdisp/src/mocks.rs) —
  `TdispNoopResourceValidator` (records calls; used by tests and by
  the non-SEV-TIO path), `firmware_tdi_state_override` test hook.

**External I/O.**

- TDISP guest-to-host wire protocol carried over a VPCI channel
  (transport is the `TdispVirtualDeviceInterface` impl in
  `vpci_client`). Commands/responses go through `tdisp::serialize_proto`.
- `/dev/sev-guest` `TIO_GUEST_REQUEST` ioctls (SEV-TIO path only).
  `sev_guest_device` was hardened on this branch (commit `feea56c3`)
  to surface the ASP firmware return code and the VMM-side error
  fields back as typed errors instead of swallowing them.
- mshv ioctls (`MSHV_GPA_HOST_ACCESS`-style page-state flips and
  `RMPADJUST`) via `hcl` / `hcl_mapper`.

**Trust (paravisor view).**

- **(a) Host/VMM → VTL2 paravisor.** Every TDISP response from the
  host is untrusted. `validate_response()` in
  `tdisp::serialize_proto` rejects unknown enum values; `vpci_client`
  additionally cross-checks `tdi_state_after` against the requested
  state transition (e.g. Bind must land in `Locked`) and bails with
  an error rather than progressing the cached state if the host
  lies. Unknown error codes are formatted as `Unknown(<int>)` and
  surfaced as errors, not `unwrap`ped.
- **(c) Hypervisor / firmware → VTL2.** SEV-TIO firmware responses
  (`TioMsgTdiStatus`, `TioMsgMmioValidateRsp`, etc.) are only as
  trustworthy as the AMD PSP — they are the actual root of trust for
  the unblock decision. The validator does **not** retry on firmware
  error; the paravisor leaves the page SHARED and surfaces the
  failure up to `vpci_client`.

#### Updates to `vpci_protocol` / `vpci` / `vpci_client` / `vpci_relay`

The detailed crate sections appear under
[VPCI relay & client](#vpci-relay--client--vmdevicespcivpci-vpci_protocol-vpci_relay-vpci_client);
the TDISP-specific surface added on this branch is summarised here.

- `vpci_protocol`: new `MessageType::QueryIsolatedResources`
  (`0x4249001E`) request + reply, `ResourceIsolation` enum on the
  wire, `ProtocolVersion::GE_TDISP` (`0x00010007`); existing
  `VPCI_TDISP_COMMAND` (`0x4249001D`) unchanged. New status code
  `STATUS_TDI_NOT_READY`.
- `vpci` (guest-facing server, `vpci/src/device.rs`):
  - GE_TDISP negotiation: if the guest requests ≥ `GE_TDISP` and the
    paravisor was constructed with TDISP support, echo `GE_TDISP`
    back; otherwise downgrade.
  - `QueryIsolatedResources` handler: if version < `GE_TDISP` →
    `NOT_SUPPORTED` + all-`Invalid` BARs. Otherwise call
    `dev.supports_tdisp_isolation()`. The result is mapped through
    `build_isolation_reply()`: `NotTdispCapable` →
    `NOT_SUPPORTED`+all-`Invalid`; `NotReady` → `STATUS_TDI_NOT_READY`;
    `Ready { bars, dma }` → `SUCCESS` + per-BAR / DMA classification;
    `Error` → internal-error status. **No host RPC happens for this
    message** — the answer is computed entirely from the paravisor's
    cached TDI report.
  - `TdispCommand` handler: deserialises via
    `tdisp::serialize_proto::deserialize_command`, dispatches to the
    chipset device's `supports_tdisp()` trait object (which for the
    relay leads back into `vpci_client` over mesh), serialises the
    response, replies. Devices without TDISP reply `NOT_SUPPORTED`.
- `vpci_client` (host-VPCI client, `vpci_client/src/{lib.rs, tdisp.rs}`):
  - Owns `VpciClientTdispState` (per device): cached `tdi_state`,
    `guest_device_id`, `validated_mmio_bars` map, `dma_unblocked`
    flag, `cached_tdi_report`, `intercepted_bars`,
    `cached_capabilities` (commit `4cdaffe1` — preserves the
    interface report across `tdisp_unbind_preserve_report`).
  - `query_capabilities()` (feature-gated, commit `c5f7bce8`)
    discovers the VM isolation type (e.g. `AmdSevTioV1` for SNP)
    and the VTOM offset from `underhill_core` and stamps them into
    the TDISP state; the guest never sees these values.
  - `attest()` (commit `48cf2c8a`) is the high-level helper called by
    the relay during device setup: unbind-if-not-Unlocked → bind →
    start → get_device_id (cast to u16 for firmware) → get_tdi_report
    → mark intercepted BARs (commit `30086100` flipped this to flag
    *all* PFNs as private and track which BARs the paravisor
    intercepts for emulation/passthrough split) → wait for guest
    resource assignment.
  - MMIO/DMA gating around the command-register MMIO-enable bit:
    - `on_mmio_reconfigured` (commit `1ff08f9b`) and
      `tdisp_on_device_activate` (commit `1ae30a73`) drive
      `tdisp_unblock_mmio`/`tdisp_unblock_dma` when the guest
      enables MMIO.
    - `tdisp_on_device_deactivate` runs on the disable edge and
      issues `tdisp_block_mmio`/`tdisp_block_dma`.
    - `tdisp_unbind` and `tdisp_unbind_preserve_report` (commit
      `dd6d9469`) re-block all MMIO and DMA *before* sending the
      unbind to the host so the host cannot DMA-poke a SHARED page
      mid-unbind.
  - `isolation_snapshot()` produces the `TdispIsolationReport` the
    relay reports through `TdispIsolationReporter`.
- `vpci_relay`:
  - `RelayedVpciDevice` implements `TdispIsolationReporter` (commit
    `2782e33e`) using a non-blocking try-lock; lock contention
    returns `Error` rather than blocking the guest's
    `QueryIsolatedResources`.
  - Command-register write path (commits `1ae30a73`, `fbf92b12`,
    `9675d6bc`): on the **enable edge**, write the cfg first then
    spawn `tdisp_on_device_activate`; on the **disable edge**, if
    the TDI is `Locked`/`Run`, defer the cfg write until *after*
    `tdisp_on_device_deactivate` (and therefore after the
    re-blocking) completes. The whole flow is async (commit
    `fbf92b12`).
  - Drop / teardown (commit `3139a180`): if the TDI is not
    `Uninitialized`, send a final
    `tdisp_unbind(TdispGuestUnbindReason::DeviceTeardown)` so the
    host-side TDI is cleaned up and the firmware is told to release
    the device.

#### End-to-end paravisor TDISP flow (malicious-host view)

1. **Version negotiation.** `vpci_client` (paravisor → host) and `vpci`
   (paravisor → guest) both negotiate `GE_TDISP`. If either side
   doesn't support it, the entire TDISP path is bypassed and
   `QueryIsolatedResources` / `VPCI_TDISP_COMMAND` from the guest are
   refused with `NOT_SUPPORTED`. **Host can only downgrade — it cannot
   silently advertise support to one side and not the other** because
   the negotiation values are echoed independently by the paravisor.
2. **Device relay setup.** When `vpci_relay` accepts a host-offered
   device, it (under the `tio` feature) calls
   `vpci_client::attest()` to drive the
   `query_capabilities → bind → start → get_tdi_report →
   unbind_preserve_report` sequence proactively. The TDI report is
   parsed by `tdisp::devicereport`, validated by
   `tdisp::serialize_proto::validate_response`, and cached.
3. **Guest enables MMIO** by writing the command register's
   memory-space-enable bit. `vpci_relay` defers the underlying write
   and runs `tdisp_on_device_activate`, which (a) re-bind/start the
   TDI if not already in `Run`, and (b) calls
   `tdisp_unblock_mmio` / `tdisp_unblock_dma` on the
   `TdispResourceValidationInterface`.
4. **SEV-TIO unblock.** `TdispSevTioResourceValidator` opens fresh
   `mshv` handles, flips the BAR PFNs to PRIVATE, sends
   `TIO_MSG_MMIO_VALIDATE_REQ` to the PSP via `/dev/sev-guest`, then
   `RMPADJUST`s the pages for the guest VMPL. **The PSP — not the
   host — is the authority on whether the unblock succeeds.**
5. **Guest queries isolation** with `QueryIsolatedResources`. The
   reply is built from the paravisor's *own* cached state, not from
   the host. A malicious host can't make a SHARED page look PRIVATE
   to the guest because the per-BAR classification comes from the
   firmware-validated unblock map, not from the host's response.
6. **Guest disables MMIO or paravisor unbinds.** All BARs are
   re-blocked (`tdisp_block_mmio`) and DMA is re-blocked
   (`tdisp_block_dma`) **before** the cfg write or unbind RPC is
   sent to the host. Re-blocking happens unconditionally on
   `RelayedVpciDevice::drop` with reason `DeviceTeardown`.
7. **Firmware sanity check** (commit `936d0471`, no production caller
   yet): `tdisp_query_firmware_tdi_state` lets paravisor code ask the
   PSP what state the TDI is actually in, independent of what the
   host claims. Plumbing for cross-checking is in place; once a
   caller exists, it should compare the firmware view against the
   cached `tdi_state` before any sensitive transition.

#### Malicious-host audit findings (this branch)

| # | Severity | Location | Finding |
|---|----------|----------|---------|
| 1 | High | [openhcl/openhcl_tdisp/src/sevtio.rs](openhcl/openhcl_tdisp/src/sevtio.rs) ~lines 43, 215, 342 | `.context("…").unwrap()` panics the paravisor on `/dev/sev-guest` open / `tio_msg_sdte_write_req` failure. Convert to `?` propagation before this leaves dev-feature. |
| 2 | Medium | [vm/devices/pci/vpci_client/src/tdisp.rs](vm/devices/pci/vpci_client/src/tdisp.rs) ~line 214 | If the host sends an unknown `tdi_state_after`, the paravisor `warn!`s and continues with stale cached state instead of bailing — desyncs the cached `TdispTdiState`. Suggest erroring out and unbinding. |
| 3 | Medium | `vpci_client` cached `cached_tdi_report` after `tdisp_unbind_preserve_report` | The cached TDI report is reused to answer `QueryIsolatedResources` even after the device is `Unlocked`. If the host re-binds with a different physical device under the same slot, the guest sees a stale report until re-attestation. Mitigation: tie cached-report invalidation to slot-level events. |
| 4 | Low | [vm/devices/tdisp_proto/src/lib.rs](vm/devices/tdisp_proto/src/lib.rs) — `TdispGuestUnbindReason` | Host can label any unbind as `AttestationFailure` / `DeviceTeardown` / `Graceful`; it's only used for telemetry, so this is informational only — but consumers of those traces should not treat the reason as authoritative. |
| 5 | Low | [vm/devices/pci/vpci_client/src/tdisp.rs](vm/devices/pci/vpci_client/src/tdisp.rs) ~line 366 | `u64::from_le_bytes(buf.try_into().unwrap())` is preceded by an explicit length check, so it's safe today, but the `unwrap()` should be replaced with an infallible split (`<[u8;8]>::try_from`) so future refactors can't regress this. |
| 6 | Informational | [vm/devices/pci/vpci_relay/src/lib.rs](vm/devices/pci/vpci_relay/src/lib.rs) — MMIO-disable defer | The cfg write is deferred behind an async unbind (commit `9675d6bc`). Verify in test that rapid enable/disable cycles serialise correctly and that there is no window in which the guest's command-register read returns "MMIO-disabled" while the BAR pages are still in PRIVATE. |
| 7 | Mitigated | All TDISP responses | Enum/variant validation is centralised in `tdisp::serialize_proto::validate_{command,response}` with `require_enum!`; `vpci_client` cross-checks `tdi_state_after` against the requested transition. State-machine truth table is Kani-verified ([vm/devices/tdisp/src/kani_proofs.rs](vm/devices/tdisp/src/kani_proofs.rs)). |

For deeper drill-down into either side of the trust boundary, the
single most useful entry points are
[vpci_client/src/tdisp.rs](vm/devices/pci/vpci_client/src/tdisp.rs) (host
↔ paravisor) and
[vpci_relay/src/lib.rs](vm/devices/pci/vpci_relay/src/lib.rs)
(paravisor ↔ guest).

### `kmsg_defs`

**Responsibility.** Header-only crate of constants shared between
`underhill_init` and `underhill_core` for writing structured records to the
Linux kmsg buffer (`/dev/kmsg`). Provides syslog severity levels, the
kernel facility number, the user-mode facility numbers OpenHCL uses, and
the prefix string the kernel `ttyprintk` driver expects.

**Modules.**

- [lib.rs](openhcl/kmsg_defs/src/lib.rs) — Pure constants only;
  `forbid(unsafe_code)`, no dependencies.

**Public API.**

- Severity levels: `LOGLEVEL_EMERG (0)`, `LOGLEVEL_ALERT (1)`,
  `LOGLEVEL_CRIT (2)`, `LOGLEVEL_ERR (3)`, `LOGLEVEL_WARNING (4)`,
  `LOGLEVEL_NOTICE (5)`, `LOGLEVEL_INFO (6)`, `LOGLEVEL_DEBUG (7)`.
- Facilities: `KERNEL_FACILITY (0)`, `UNDERHILL_INIT_KMSG_FACILITY (2)`,
  `UNDERHILL_KMSG_FACILITY (3)`.
- Prefix: `TTYPRINK_PREFIX = "[U] "`.

**External I/O.** None directly; consumers use these values to format
messages they write to `/dev/kmsg` (and to `/dev/ttyprintk` from
`underhill_init`), where the syslog `<priority>` byte is `facility * 8 +
level`.

**Trust.** None — compile-time constants, no untrusted input. Used to make
sure log records produced inside VTL2 are correctly attributed when the
host harvests `dmesg`.

## Underhill control plane

### `underhill_entry`

**Responsibility.** Single entry point for the multi-binary Underhill
executable image (`/bin/openvmm_hcl` plus hardlinks `underhill-init`,
`underhill-crash`, `underhill-dump`). It selects the global allocator
(mimalloc by default, dhat for memory-profile builds), forces the openssl
crate to link `libcrypto` only, swaps in a faster x86_64 memcpy, and
dispatches to the appropriate per-binary `main()` based on `argv[0]`.

**Modules.**

- [lib.rs](openhcl/underhill_entry/src/lib.rs) — The entire crate; declares
  the global allocator, a memcpy shim, and the `underhill_main()` argv0
  router.

**Public API.**

- `pub fn underhill_main() -> anyhow::Result<()>` — argv0 dispatcher.

**External I/O.** None directly; reads `argv[0]` from
`std::env::args_os()`. Indirectly drives every other Underhill binary's I/O
by selecting which `main()` to call.

**Trust.** Sits at the very top of the VTL2 user-mode stack. No untrusted
input is consumed (argv0 is set by `underhill_init` in this same image,
originally by the kernel from initrd contents which are measured / part of
the IGVM image). Effectively all three boundaries lie *below* it.

### `underhill_init`

**Responsibility.** PID 1 inside the VTL2 paravisor container. Mounts
`/proc`, `/sys`, `/dev`, `/dev/pts`; tunes kernel sysctls and vmbus/PCI
driver bindings; folds host-supplied entropy from the device tree into
`/dev/random`; loads kernel modules from `/lib/modules` honoring
kernel-cmdline `module.param=…` options; sets up logging to `/dev/kmsg`
and stderr to `/dev/ttyprintk`; runs optional `--setup-script` shells;
raises `RLIMIT_NOFILE`; then `exec`s `/bin/openvmm_hcl` and reaps zombies.

**Modules.**

- [lib.rs](openhcl/underhill_init/src/lib.rs) — process setup pipeline
  (filesystem mounts, sysctl writes, vmbus uio bindings, kmsg/ttyprintk
  wiring, `RNDADDENTROPY` ioctl, `finit_module()` loader, child supervision
  via blocking `wait()`).
- [options.rs](openhcl/underhill_init/src/options.rs) — minimal hand-rolled
  CLI parser exposing `Options { setup_script: Vec<String>, underhill_args:
  Vec<String> }`; intentionally avoids clap to shrink binary size.
- [syslog.rs](openhcl/underhill_init/src/syslog.rs) — `log::Log`
  implementation that writes a single `<priority>target: msg\n` record per
  call to `/dev/kmsg`, mapping `log::Level` to `kmsg_defs::LOGLEVEL_*` under
  facility `UNDERHILL_INIT_KMSG_FACILITY`.

**Public API.**

- `pub use options::Options` (with `setup_script`, `underhill_args` public
  fields).
- `pub fn main() -> !` — process entry.

**External I/O.**

- *Linux syscalls:* `mount(2)` for proc/sysfs/devtmpfs/devpts;
  `prlimit(2)` for `RLIMIT_NOFILE`; `finit_module(2)` for kernel module
  loading; `wait(2)`; `dup2(2)`; `clock_gettime(CLOCK_BOOTTIME)`;
  `RNDADDENTROPY` ioctl on `/dev/random`.
- `/proc/cmdline` (read; parsed for `module.param=` pairs).
- `/proc/device-tree/openhcl/entropy/reg` (read; host-provided entropy
  block, max 256 B used).
- `/proc/sys/{kernel/threads-max,kernel/kptr_restrict,kernel/core_pattern,
  kernel/core_pipe_limit,vm/panic_on_oom,vm/min_free_kbytes,
  vm/watermark_scale_factor,vm/watermark_boost_factor}` (writes).
- `/sys/kernel/mm/transparent_hugepage/enabled` (writes `madvise`).
- `/sys/bus/vmbus/drivers/uio_hv_generic/new_id` (binds GET, UART, and
  crashdump vmbus device classes to the user-mode `uio_hv_generic` driver
  — three GUIDs: `8dedd1aa-…` GET, `8b60ccf6-…` UART, `427b03e7-…`
  crashdump).
- `/sys/bus/pci/drivers/vfio-pci/new_id` (claims all NVMe devices for VFIO
  when `OPENHCL_NVME_VFIO=1`).
- `/dev/null`, `/dev/ttyprintk` (stdio redirection); `/dev/kmsg` (logger
  sink).
- `/lib/modules/**` (walked, each file `finit_module`'d, then directory
  removed).
- `core_pattern` registers the kernel to pipe core dumps into
  `|/bin/underhill-crash %p %i %s %e` (disabled for confidential VMs).
- Spawns `/bin/openvmm_hcl --pid /run/underhill.pid <args>` as the
  long-lived child.
- *Env vars consumed:* `OPENHCL_NVME_VFIO`, `OPENHCL_WAIT_FOR_MODULES`.
  Env vars exported to child include `KERNEL_BOOT_TIME` and `KEY=VALUE`
  lines printed by setup scripts.

**Trust.** Sits on **(a) Host/VMM → VTL2** (host-supplied DT entropy node,
kernel command line) and implicitly on **(c) Hypervisor → VTL2**. Host
entropy is treated as untrusted: it is folded into `/dev/random` *without*
incrementing the entropy count on confidential VMs (and only with
`RNDADDENTROPY` on non-confidential VMs). The kernel cmdline string is
parsed permissively but only used to populate per-module parameter strings,
never executed. Kernel module file contents from the initrd are treated as
trusted (measured part of the OpenHCL image). No VTL0 surface.

### `underhill_core`

**Responsibility.** The Underhill control plane and "initial" VMM process.
It owns the mesh-process topology (spawns subprocesses for the VM worker,
VNC, gdbstub, profiler), runs the diagnostics server, ferries tracing
events to the host over a vmbus channel, drives VTL2-settings application,
and (in its `vm` subprocess) constructs the `UhPartition`, vmbus relay,
vmbus server, NVMe/MANA managers, emulated firmware/devices, servicing
save-restore, and VP scheduling.

**Modules.**

- [lib.rs](openhcl/underhill_core/src/lib.rs) — mesh-host
  `try_run_mesh_host`, control loop dispatching `diag_server::DiagRequest`
  (`Start`/`Stop`/`Pause`/`Resume`/`Save`/`Restart`/`Inspect`/`Crash`/
  `PacketCapture`/`Profile`/`MemoryProfileTrace`), worker registration
  (`UnderhillVmWorker`, `DiagWorker`, optional `ProfilerWorker`),
  framebuffer wiring through `/dev/mshv_vtl_low`.
- [diag.rs](openhcl/underhill_core/src/diag.rs) — `DiagWorker` that hosts
  `diag_server::DiagServer` on AF_VSOCK ports `diag_proto::VSOCK_CONTROL_PORT`/
  `VSOCK_DATA_PORT`; converts inbound RPCs into `mesh::Sender<DiagRequest>`.
- [dispatch/mod.rs](openhcl/underhill_core/src/dispatch/mod.rs) —
  `LoadedVm`, `UhVmRpc` (`Pause`/`Resume`/`Save`/`ClearHalt`/
  `PacketCapture`/`MemoryProfileTrace`), `LoadedVmNetworkSettings` async
  trait; central save/restore + servicing orchestration.
- [dispatch/pci_shutdown.rs](openhcl/underhill_core/src/dispatch/pci_shutdown.rs)
  — `shutdown_pci_devices()` walks `/sys/bus/pci/devices` and writes each
  device's `driver/unbind` (skipping `vfio-pci`), used to quiesce devices
  before kexec/servicing.
- [dispatch/vtl2_settings_worker.rs](openhcl/underhill_core/src/dispatch/vtl2_settings_worker.rs)
  — applies `Vtl2Settings` (SCSI/NVMe/IDE controllers, NICs); resolves
  disks via `disk_backend`, talks to `NvmeManager`, watches `uevent` for
  PCI hotplug, returns typed `Vtl2SettingsErrorInfo` on bad input.
- `emuplat/*` — Underhill-specific glue between the generic VMM device
  crates and the GET/HCL backends:
  - `firmware.rs` — `UnderhillLogger` mapping UEFI `BootSuccess`/
    `BootFailure`/`NoBootDevice` to GET `EventLogId`s.
  - `framebuffer.rs` — `FramebufferRemoteControl` proxying `map`/`unmap`/
    `set_format` framebuffer ops to the host via GET.
  - `i440bx_host_pci_bridge.rs` — `GetBackedAdjustGpaRange` implementing
    PCAT/SVGA PAM-shadow ROM remapping using GET `CreateRamGpaRange`/
    `RemoteRamGpaRangeHandle`.
  - `local_clock.rs` — `UnderhillLocalClock` that stores RTC offset in
    VMGS and fetches "real time" from the host because VTL2 has no native
    RTC source.
  - `netvsp.rs` — `HclNetworkVFManager` driving MANA VF arrival/departure
    for synthetic netvsp adapters; provides `RuntimeSavedState`/
    `SavedState`, `NetworkAdapterIndex`, packet capture wiring,
    hibernation prep.
  - `non_volatile_store.rs` — `VmgsBrokerNonVolatileStore` trait turning a
    `vmgs_broker::VmgsClient` plus a `vmgs::FileId` into a generic
    `NonVolatileStore` (with optional encryption).
  - `tpm.rs` — `TpmRequestAkCertHelper` that builds `IGVM_ATTEST AK_CERT`
    requests through `underhill_attestation` and `tee_call`, plus a TPM
    event logger over GET; resolvers registered via
    `register_static_resolvers!`.
  - `vga_proxy.rs` — `UhRegisterHostIoFastPath` (registers a fast-path I/O
    port range on the partition) and `GetProxyVgaPciCfgAccess` (proxies
    VGA PCI cfg reads/writes through GET).
  - `watchdog.rs` — `UnderhillWatchdogPlatform` wraps
    `BaseWatchdogPlatform` and on timeout sends a GET event to the host.
  - `mod.rs` — `EmuplatServicing` aggregate that snapshots clock, PAM,
    netvsp, and adapter-index state for save/restore.
- [get_tracing.rs](openhcl/underhill_core/src/get_tracing.rs) +
  `get_tracing/{json_common,json_layer,kmsg_stream}.rs` — opens the
  `GET_LOG_INTERFACE_GUID` vmbus channel via `vmbus_user_channel`,
  multiplexes mesh tracing events from every Underhill subprocess plus a
  `/dev/kmsg` polled stream into JSON `tracelogging` notification buffers
  (`build_tracelogging_notification_buffer`) sent to the host. Honors
  `OPENVMM_LOG`/`OPENVMM_PERF_TRACE` (with legacy `HVLITE_*` fallback).
- [inspect_internal.rs](openhcl/underhill_core/src/inspect_internal.rs) —
  defines a stable internal `uhdiag/...` inspect subtree (notably
  `uhdiag/net/<mac>`) with a documented support window of two releases for
  diagnostic compatibility.
- [inspect_proc.rs](openhcl/underhill_core/src/inspect_proc.rs) — exposes
  `/proc/meminfo`, `/proc/interrupts`, `/proc/<pid>/status` userspace
  process stats, etc., as inspect nodes (`SensitivityLevel::Safe`).
- [livedump.rs](openhcl/underhill_core/src/livedump.rs) — pipes a live
  `underhill-dump <pid>` capture into a forked `underhill-crash` for
  upload to the host; disabled on CVMs.
- [loader/mod.rs](openhcl/underhill_core/src/loader/mod.rs) — Coordinates
  VTL0 boot: builds ACPI tables, applies measured firmware regions,
  supports `LoadKind::{None,Uefi,Pcat,Linux}` and chooses a `VpContext`.
- [loader/vtl0_config.rs](openhcl/underhill_core/src/loader/vtl0_config.rs)
  — Reads/validates IGVM-measured VTL0 config (`MeasuredVtl0Info`,
  `LinuxInfo`, UEFI/PCAT firmware regions) from guest memory.
- [loader/vtl2_config/mod.rs](openhcl/underhill_core/src/loader/vtl2_config/mod.rs)
  — `RuntimeParameters`: combines untrusted host-provided IGVM parameters
  (SLIT, PPTT, MADT, SRAT) with bootloader-validated FDT parameters from
  `bootloader_fdt_parser::ParsedBootDtInfo`; treats the host pages as
  untrusted, the FDT as already validated.
- [nvme_manager/mod.rs](openhcl/underhill_core/src/nvme_manager/mod.rs) —
  public errors (`NamespaceError`, `NvmeSpawnerError`), submodule layout
  for the multi-threaded actor model.
- [nvme_manager/manager.rs](openhcl/underhill_core/src/nvme_manager/manager.rs)
  — `NvmeManager`/`NvmeManagerWorker`/`NvmeManagerClient` with
  `Arc<RwLock<HashMap<String, NvmeDriverManager>>>` device registry;
  resource-resolves `NvmeDiskConfig` (PCI ID + nsid) into `ResolvedDisk`;
  supports save/restore for nvme-keepalive servicing.
- [nvme_manager/device.rs](openhcl/underhill_core/src/nvme_manager/device.rs)
  — `VfioNvmeDevice` (wraps `nvme_driver::NvmeDriver<VfioDevice>`),
  `NvmeDriverManager` per-device serialized worker,
  `VfioNvmeDriverSpawner` implementing `CreateNvmeDriver`, integrates
  with `openhcl_dma_manager`.
- [nvme_manager/save_restore.rs](openhcl/underhill_core/src/nvme_manager/save_restore.rs)
  — `NvmeManagerSavedState`/`NvmeSavedDiskConfig` mesh-protobuf types
  under package `underhill`.
- [nvme_manager/save_restore_helpers.rs](openhcl/underhill_core/src/nvme_manager/save_restore_helpers.rs)
  — small helpers (e.g. `VPInterruptState`) used during restore.
- [options.rs](openhcl/underhill_core/src/options.rs) — VMM-process CLI
  parsing (`Options`), test-scenario hooks (`TestScenarioConfig::{SaveFail,
  RestoreStuck, SaveStuck, VpciTdispFlow}`), keep-alive config,
  encryption-policy parsing.
- [reference_time.rs](openhcl/underhill_core/src/reference_time.rs) —
  `ReferenceTime` 100ns-tick wrapper with wraparound-safe `since()`.
- [servicing.rs](openhcl/underhill_core/src/servicing.rs) — `ServicingState`,
  `ServicingInitState`, `EmuplatSavedState`, `NvmeSavedState`, `Firmware`;
  protobuf-tagged, `SavedStateRoot` with mesh package `underhill`. Encodes
  the GET keep-alive servicing payload.
- [threadpool_vm_task_backend.rs](openhcl/underhill_core/src/threadpool_vm_task_backend.rs)
  — `ThreadpoolBackend`/`ThreadpoolDriver` adapter making
  `underhill_threadpool::AffinitizedThreadpool` look like a
  `vmcore::vm_task::BuildVmTaskDriver`.
- [vmbus_relay_unit.rs](openhcl/underhill_core/src/vmbus_relay_unit.rs) —
  `VmbusRelayHandle` that wraps `vmbus_relay::HostVmbusTransport` as a
  `state_unit::StateUnit` (start/stop/save).
- [vmgs_logger.rs](openhcl/underhill_core/src/vmgs_logger.rs) —
  `GetVmgsLogger` translating `vmgs::logger::VmgsLogEvent::{InitFailed,
  InvalidFormat,CorruptFormat,AccessFailed}` into GET `event_log_fatal`
  calls.
- [vp.rs](openhcl/underhill_core/src/vp.rs) — `spawn_vps()` schedules each
  `UhProcessorBox` on the matching CPU of the affinitized threadpool,
  handling offline CPUs (`is_cpu_online`) and idle-task wiring for
  `IdleControl`.
- [vpci.rs](openhcl/underhill_core/src/vpci.rs) — `HclVpciBusControl`
  implementing `vpci::bus_control::VpciBusControl` for VPCI buses by going
  through GET (`offer_vpci_device`, `connect_to_vpci_event_source`,
  `report_vpci_device_binding_state`).
- [worker.rs](openhcl/underhill_core/src/worker.rs) — `UnderhillVmWorker`
  (`mesh_worker::Worker`), `UnderhillWorkerParameters`, `UnderhillEnvCfg`,
  `UnderhillRemoteConsoleCfg`, `FirmwareType`, `NicConfig`,
  `NetworkSettingsError`. This is where the `LoadedVm` is constructed:
  partition, vmbus, IDE/SCSI/NVMe controllers, UEFI/PCAT/Linux firmware,
  debug worker, watchdog, TPM, framebuffer, NETVSP/MANA, hibernation prep,
  GDB.
- [wrapped_partition.rs](openhcl/underhill_core/src/wrapped_partition.rs) —
  `WrappedPartition(Arc<UhPartition>)` adapter implementing
  `vmm_core::partition_unit::VmPartition` (with `reset` returning an error
  and `accept_initial_pages`/`scrub_vtl` unreachable in the underhill
  case).

**Public API.** Almost the entire crate is `pub(crate)`/private; the
externally observable surface is:

- `pub use options::Options`.
- `pub fn main() -> anyhow::Result<()>`.
- `pub enum ControlRequest { FlushLogs(Rpc<...>), MakeWorker(Rpc<...>) }`.
- Workers exposed via `register_workers!` and `mesh_worker::WorkerId`
  constants: `UnderhillVmWorker` (`worker::UNDERHILL_WORKER`), `DiagWorker`
  (`diag::DIAG_WORKER`), and feature-gated `ProfilerWorker`.
- Mesh RPC enums consumed by the diag layer: `UhVmRpc`, `Vtl2ConfigNicRpc`,
  `LoadedVmNetworkSettings` trait.

**External I/O.**

- **GET (Guest Emulation Transport over vmbus, GUID
  `8dedd1aa-9056-49e4-bfd6-1bf90dc38ef0`):** event logging (UEFI/PCAT/VMGS/
  watchdog event IDs), framebuffer map/unmap, RAM GPA range create/destroy
  (PAM shadowing), VGA PCI cfg proxy, VPCI device offer/teardown and bus
  event subscriptions, tracing notification buffers, `IGVM_ATTEST AK_CERT`
  requests for TPM, `complete_start_vtl0`, `GuestSaveRequest` (servicing),
  platform settings (`DevicePlatformSettings`), host real-time queries.
- **VMGS** (via `vmgs_broker::VmgsClient`): non-volatile-store backing for
  RTC offset, watchdog persistence, encrypted UEFI NVRAM, etc.
- **Vmbus relay** (`virt_mshv_vtl::UhPartition` +
  `vmbus_relay::HostVmbusTransport`): forwards host vmbus channels through
  to VTL0 guest while intercepting selected ones.
- **Vmbus tracing channel:** `vmbus_user_channel::open_uio_device(&GET_LOG_INTERFACE_GUID)`
  + `MessagePipe`.
- **VPCI:** `HclVpciBusControl` over GET; `uevent::UeventListener` for PCI
  hotplug events.
- **NVMe:** VFIO-PCI sysfs (`/sys/bus/pci/drivers/vfio-pci/new_id`,
  per-device unbind), `nvme_driver` over `user_driver::vfio::VfioDevice`
  with `openhcl_dma_manager`-allocated DMA.
- **Inspect/diag RPC:** AF_VSOCK ports `diag_proto::VSOCK_CONTROL_PORT`
  and `VSOCK_DATA_PORT` (gRPC-style protobuf service); supports Inspect,
  Start, Stop, Restart, Pause, Resume, Save, Crash, PacketCapture,
  Profile, MemoryProfileTrace.
- **/proc /sys parsing:** `/proc/meminfo`, `/proc/interrupts`,
  `/proc/<pid>/status`, `/proc/irq/*/smp_affinity_list`,
  `/sys/bus/pci/devices/*`, `/sys/bus/pci/.../driver/unbind`, `/dev/kmsg`,
  `/dev/mshv_vtl_low` (framebuffer second mapping).
- **Live dump** spawns `underhill-dump <pid>` and `underhill-crash` and
  pipes a live ELF core through GET (disabled on CVM).
- **Servicing:** GET `SaveGuestVtl2StateFlags` keep-alive payload
  (`ServicingState`/`ServicingInitState` mesh-protobuf), MANA/NVMe driver
  `keep_alive` save/restore.
- **Subprocess control:** mesh transport (`mesh_process::Mesh`, AF_UNIX)
  for vm/vnc/gdb/profiler hosts; VNC and gdbstub bind AF_VSOCK ports.
- **Kernel command line / env:** consumes `OPENVMM_LOG`,
  `OPENVMM_PERF_TRACE` (legacy `HVLITE_*`), `OPENVMM_WRITE_SAVED_STATE_PROTO`.

**Trust.** Sits on **all three** boundaries:

- **(a) Host/VMM → VTL2 paravisor (root untrusted):** GET messages
  (`DevicePlatformSettings`, `Vtl2Settings`, attestation responses), host
  IGVM parameter pages (`loader/vtl2_config`), VMGS contents
  (logged/error-handled), VNC/gdb sockets, framebuffer-mapping requests.
  All are validated and never trigger panics on bad input.
- **(b) VTL0 guest → VTL2 paravisor (guest untrusted):** vmbus relay
  traffic to/from synthetic devices (storvsp/netvsp/UART/IC), VPCI MMIO,
  virtual-firmware NVRAM writes, TPM commands, watchdog accesses;
  everything routes through `chipset_device`/`vmbus_channel` boundaries.
- **(c) Hypervisor → VTL2:** `UhPartition` register/MSR data, VMSA pages
  on CVMs, shared pages allocated through `openhcl_dma_manager`.
  Confidential paths gate behavior with
  `underhill_confidentiality::confidential_filtering_enabled()` (e.g.
  livedump disabled).

### `underhill_threadpool`

**Responsibility.** Per-CPU `io_uring`-backed async runtime used by every
Underhill subprocess that does VM work. Spins one worker thread per
present CPU, sets each thread's affinity (and io-uring `IORING_REGISTER_IOWQ_AFF`)
to that CPU, exposes both an "affinitized" scheduler (current-CPU dispatch)
and a `RetargetableDriver` (movable target CPU for VP-task retargeting),
and provides idle-task hooks used by VP run loops to block in the io-uring
without losing wakeups.

**Modules.**

- [lib.rs](openhcl/underhill_threadpool/src/lib.rs) — entire crate. Defines
  `AffinitizedThreadpool`, `ThreadpoolBuilder`, `ThreadpoolDriver`,
  `RetargetableDriver`, `Thread`, `TaskInfo`, `is_cpu_online`,
  `set_cpu_online`, `SetAffinityError`. Implements `pal_async`'s `Spawn`/
  `SpawnLocal`/`Schedule`/`Initiate`/`IoUringSubmit`/`FdReadyDriver`/
  `WaitDriver`/`TimerDriver`/`IoUringDriver`. Threads are spawned lazily
  on first use of a per-CPU driver and the affinity is fixed up later if
  the CPU was offline at startup.

**Public API.**

- `pub struct AffinitizedThreadpool` (+ `new`, `current_driver`,
  `driver(ring_id)`, `active_drivers()`).
- `pub struct ThreadpoolBuilder` (+ `new`, `max_bounded_workers`,
  `max_unbounded_workers`, `ring_size`, `build`).
- `pub struct ThreadpoolDriver` (+ `target_cpu`, `is_affinity_set`,
  `wait_for_affinity`, `set_spawn_notifier`).
- `pub struct RetargetableDriver` (+ `new`, `retarget`,
  `current_target_cpu`, `current_driver`).
- `pub struct Thread` (+ `current`, `with_driver`, `set_idle_task`,
  `try_set_affinity`, `first_task`).
- `pub struct TaskInfo`, `pub enum SetAffinityError`.
- Free fns: `pub fn is_cpu_online(cpu: u32)`, `pub fn set_cpu_online(cpu:
  u32)`.

**External I/O.**

- Linux `io_uring` syscalls via `pal_uring::IoUringPool` (per-thread
  rings, `IORING_REGISTER_IOWQ_MAX_WORKERS`, `IORING_REGISTER_IOWQ_AFF`).
- `sched_setaffinity(2)` (via
  `pal::unix::affinity::set_current_thread_affinity`).
- Reads `/sys/devices/system/cpu/cpu<n>/online`,
  `/sys/devices/system/cpu/online`; writes
  `/sys/devices/system/cpu/cpu<n>/online` to bring a CPU online.
- Kernel poll/wait/timer FDs via the `pal_uring` `FdReady`/`FdWait`/
  `Timer` primitives.

**Trust.** None directly. All inputs come from sysfs/io-uring under the
paravisor's own kernel; the crate sits below all three boundaries and
merely runs the tasks that interact with them.

### `underhill_crash`

**Responsibility.** Receives a kernel-piped core dump on stdin (set up via
`core_pattern=|/bin/underhill-crash …` in `underhill_init`) and forwards
it to the host over the dedicated crashdump vmbus device (GUID
`427b03e7-4ceb-4286-b5fc-486f4a1dd439`) using the `get_protocol::crash`
request/response framing. It collects auxiliary OS info (`/proc/version`,
`uname`) and a kmsg snapshot to attach as ELF PT_NOTE entries.

**Modules.**

- [lib.rs](openhcl/underhill_crash/src/lib.rs) — main flow: capture stdin
  core dump, optionally splice in `/dev/kmsg` as a 256 KB ELF note, open
  the crashdump vmbus pipe via `vmbus_user_channel`, do the v1
  `*_NIX_DUMP_*` request/response handshake (capabilities → config →
  start → write 16 KB chunks → complete), supervise stdout/stderr
  redirection.
- [elf.rs](openhcl/underhill_crash/src/elf.rs) — `Elf64_Ehdr`, `Elf64_Phdr`,
  `Elf64_Nhdr`, `PT_NOTE = 4` zerocopy structs used to splice an
  additional kmsg note section into the incoming core dump.
- [options.rs](openhcl/underhill_crash/src/options.rs) — `Options { pid,
  tid, sig, comm, verbose, no_redirect, no_kmsg, timeout }` parser
  matching the `core_pattern` argv layout `{pid} {tid} {signal} {command
  line}`.
- [proto.rs](openhcl/underhill_crash/src/proto.rs) — `make_header()`/
  `check_header()` and `ProtocolError`; whitelists the supported
  `MessageType::*_NIX_DUMP_*` variants from `get_protocol::crash`.

**Public API.**

- `pub use options::Options`.
- `pub fn main()` (called by the multi-binary dispatcher).

**External I/O.**

- *Input:* stdin (kernel-piped core dump from `core_pattern`).
- *Vmbus:* opens `427b03e7-…` via `vmbus_user_channel::open_uio_device`,
  async `MessagePipe` exchanging `get_protocol::crash::Header`-prefixed
  messages: `REQUEST_GET_CAPABILITIES_V1`,
  `REQUEST_GET_NIX_DUMP_CONFIG_V1`, `REQUEST_NIX_DUMP_START_V1`,
  `REQUEST_NIX_DUMP_WRITE_V1` (≤ 16 KB chunks),
  `REQUEST_NIX_DUMP_COMPLETE_V1` and matching `RESPONSE_*`.
- *Files:* `/proc/version`, `/dev/kmsg` (optional 256 KB note), `uname(2)`
  for kernel major/minor.
- *Env:* `UNDERHILL_CRASH_NO_REDIRECT`, `UNDERHILL_CRASH_NO_KMSG` (set by
  `underhill_core::livedump`).

**Trust.** Sits on **(a) Host/VMM → VTL2**: the host's responses on the
crashdump channel are parsed via `check_header()` which rejects
unsupported/invalid `MessageType`s — never panics on bad host frames.
Inputs from inside VTL2 (the dying process via core_pattern) are part of
the trusted user-mode boundary. Disabled entirely on confidential VMs
(caller-side gating in `underhill_init` via `core_pattern=""`).

### `underhill_dump`

**Responsibility.** Tiny standalone process invoked as
`underhill-dump <pid>` that uses the `elfcore` crate to write an ELF core
dump of the target process to stdout, attaching a `KMSG` note containing
the last 256 KB of `/dev/kmsg`. Split out from the diagnostics process so
the diagnostics process itself can be dumped and so its `waitpid()` calls
don't observe ptrace stops.

**Modules.**

- [lib.rs](openhcl/underhill_dump/src/lib.rs) — sole module. Initializes
  `tracing_subscriber` to stderr, refuses to run on confidential VMs,
  parses the single positional `<pid>`, builds `elfcore::CoreDumpBuilder`,
  and adds a `NonBlockingFile("/dev/kmsg")` as a custom note before
  writing to stdout.

**Public API.**

- `pub fn main() -> !`.
- `pub fn do_main() -> anyhow::Result<()>`.

**External I/O.**

- `/dev/kmsg` (opened `O_NONBLOCK`, read until `WouldBlock`; tolerates
  `Interrupted` and `BrokenPipe` ring overruns).
- `ptrace(2)` and `/proc/<pid>/{maps,mem,status,…}` via the `elfcore`
  crate (the actual process-stop and memory-read mechanism).
- *stdout:* ELF64 core dump bytes (typically piped into
  `underhill-crash`).
- *stderr:* human-readable tracing output with uptime timestamps.

**Trust.** Effectively none external — operates only on processes inside
the paravisor user mode. Inputs are PID arg and kmsg ring (both trusted
local sources). Disabled on CVMs by an explicit
`confidential_filtering_enabled()` check.

### `build_info`

**Responsibility.** Static, compile-time-baked build identification (crate
name, git SHAs/branches, `OPENHCL_VERSION`) for both runtime introspection
(via `inspect` and `diag` `build_info` field) and post-mortem debugging.
The struct is placed in a dedicated `.build_info` ELF section under the
unmangled symbol `BUILD_INFO` so it can be located in dumps without
symbols.

**Modules.**

- [lib.rs](openhcl/build_info/src/lib.rs) — sole module. `BuildInfo`/
  `OpenHclVersion` types, `const_parse_version()` strict
  `major.minor.build.platform` parser (enforced at compile time), the
  `BUILD_INFO` static, `get()` accessor that uses `std::hint::black_box`
  so fat-LTO release builds don't dead-strip it.

**Public API.**

- `pub struct BuildInfo` with `pub const fn new()`, `crate_name()`,
  `scm_revision()`, `scm_branch()`, `openhcl_version()`.
- `pub struct OpenHclVersion` with `product_name()`, `major()`, `minor()`,
  `build()`, `platform()` (all `const fn`).
- `pub static OPENHCL_VERSION: OpenHclVersion`.
- `pub fn get() -> &'static BuildInfo`.

**External I/O.** None at runtime. At build time consumes env vars
`BUILD_GIT_SHA`, `BUILD_GIT_BRANCH`, `INTERNAL_GIT_SHA`,
`INTERNAL_GIT_BRANCH`, `OPENHCL_VERSION`, plus `CARGO_PKG_NAME`. Exports
a single ELF symbol `BUILD_INFO` in section `.build_info`.

**Trust.** None. Pure compile-time data; the `inspect` exposure is marked
`safe`. Sits below all three boundaries.

## Attestation, confidentiality, TEE

### `tee_call`

**Responsibility.** Thin abstraction over the per-TEE primitives the
paravisor needs for attestation: pulling a hardware-signed attestation
report (with arbitrary `report_data`) and, where supported, deriving a
hardware-bound symmetric secret. The crate exposes a single `TeeCall`
trait with one concrete implementation per supported isolation technology
(SEV-SNP, TDX, VBS) so that higher-level attestation code is TEE-agnostic.
Linux-only; `#![forbid(unsafe_code)]`.

**Modules.**

- [lib.rs](openhcl/tee_call/src/lib.rs) — The crate's only file. Defines
  the `Error` enum, the `TeeType`/`GetAttestationReportResult` types, the
  `TeeCall` and `TeeCallGetDerivedKey` traits, and the `SnpCall`,
  `TdxCall`, `VbsCall` implementations. Also exposes the constants
  `REPORT_DATA_SIZE` (= `SNP_REPORT_DATA_SIZE`) and
  `HW_DERIVED_KEY_LENGTH` (= `SNP_DERIVED_KEY_SIZE`), with a
  `static_assertions` check that SNP and TDX report-data sizes match.

**Public API.**

- `TeeCall` trait — `get_attestation_report(&[u8; REPORT_DATA_SIZE]) ->
  Result<GetAttestationReportResult, Error>`,
  `supports_get_derived_key() -> Option<&dyn TeeCallGetDerivedKey>`,
  `tee_type() -> TeeType`.
- `TeeCallGetDerivedKey: TeeCall` sub-trait — `get_derived_key(tcb_version:
  u64) -> Result<[u8; HW_DERIVED_KEY_LENGTH], Error>`.
- `TeeType` enum: `Snp`, `Tdx`, `Vbs`.
- `GetAttestationReportResult { report: Vec<u8>, tcb_version: Option<u64> }`.
- `SnpCall` (implements both traits), `TdxCall` (only `TeeCall`; key
  derivation unimplemented), `VbsCall` (only `TeeCall`).
- Constants: `REPORT_DATA_SIZE`, `HW_DERIVED_KEY_LENGTH`.
- `Error` enum with `OpenDevSevGuest`, `GetSnpReport`,
  `GetSnpDerivedKey`, `AllZeroKey`, `OpenDevTdxGuest`, `GetTdxReport`,
  `OpenDevVbsGuest`, `GetVbsReport`.

**External I/O.**

- `/dev/sev-guest` — opened via `sev_guest_device::SevGuestDevice::open()`.
  SNP `MSG_REPORT_REQ` (with caller-supplied `report_data` and `vmpl=0`)
  and `MSG_KEY_REQ` (with `GuestFieldSelect{guest_policy, measurement,
  tcb_version}`, root key select VECK=0, VMPL 0, guest SVN 0,
  caller-supplied TCB version) — returns the SNP attestation report and
  32-byte hardware-derived key. All-zero derived key is rejected as
  `Error::AllZeroKey`.
- `/dev/tdx_guest` — opened via `tdx_guest_device::TdxGuestDevice::open()`.
  TDX `GET_REPORT` ioctl with caller-supplied report-data; returns a TDX
  report; `tcb_version` always `None`.
- VBS attestation report — obtained through `hcl::ioctl::MshvHvcall`
  invoking `HypercallCode::HvCallVbsVmCallReport` (the only allowed
  hypercall on that handle); returns up to `hvdef::vbs::VBS_REPORT_SIZE`
  bytes.
- Optional Cargo feature `dev_snp_ohcl_tio_support` enables the equivalent
  feature on `sev_guest_device` (TIO/IDE-encryption developer support).

**Trust.**

- **(c) Hypervisor → VTL2:** The TEE report is signed by hardware/PSP/Intel
  SEAM, not by the host, so its contents are trusted only to the extent
  that hardware signatures are later verified by the relying party (Azure
  attestation service). The crate itself does no signature verification —
  it just transports raw bytes — so callers must treat the returned
  `report` as data that crosses a hardware-trust boundary.
- **(a) Host/VMM → VTL2:** For the VBS path, the report comes through an
  HVCALL interpreted by the hypervisor; the hypervisor is the trust root
  for VBS. For SNP/TDX the report is self-contained and the host cannot
  forge it, but the host still controls when/whether the device returns
  one (DoS only).
- **(b) VTL0 guest → VTL2:** Not directly relevant — `tee_call` is only
  used internally by the paravisor; `report_data` is always
  paravisor-controlled. The all-zero-key check defends against a hardware/
  firmware bug delivering a degenerate key.

### `underhill_confidentiality`

**Responsibility.** Tiny query crate that exposes whether the running
OpenHCL instance is a confidential VM (CVM) and whether confidential
debugging is enabled. Used throughout the paravisor (notably by
`cvm_tracing`) to decide whether diagnostics must be filtered to avoid
leaking guest secrets. The crate is `#![no_std]` by default and
`#![forbid(unsafe_code)]`; the actual getters live behind the `std` Cargo
feature.

**Modules.**

- [lib.rs](openhcl/underhill_confidentiality/src/lib.rs) — Defines the four
  environment-variable name constants (`OPENHCL_CONFIDENTIAL`,
  `UNDERHILL_CONFIDENTIAL` legacy, `OPENHCL_CONFIDENTIAL_DEBUG`,
  `UNDERHILL_CONFIDENTIAL_DEBUG`) and re-exports `getters` when `std` is
  enabled.
- [getters.rs](openhcl/underhill_confidentiality/src/getters.rs) (feature
  `std`): Implements `is_confidential_vm`, `confidential_debug_enabled`,
  and `confidential_filtering_enabled` by reading the env vars exactly
  once into `OnceLock<bool>` caches. A var is "true" if it is set to a
  non-empty value other than `"0"`.

**Public API.**

- Constants: `OPENHCL_CONFIDENTIAL_ENV_VAR_NAME`,
  `LEGACY_CONFIDENTIAL_ENV_VAR_NAME`,
  `OPENHCL_CONFIDENTIAL_DEBUG_ENV_VAR_NAME`,
  `LEGACY_CONFIDENTIAL_DEBUG_ENV_VAR_NAME`.
- Functions (feature `std`): `is_confidential_vm() -> bool`,
  `confidential_debug_enabled() -> bool`,
  `confidential_filtering_enabled() -> bool` (the canonical "should
  diagnostics be redacted?" check).

**External I/O.** Process environment variables only —
`OPENHCL_CONFIDENTIAL`, `UNDERHILL_CONFIDENTIAL`,
`OPENHCL_CONFIDENTIAL_DEBUG`, `UNDERHILL_CONFIDENTIAL_DEBUG`. The doc
comment notes that querying the HCL ioctl is preferred when available;
this crate is the env-var fallback/seed.

**Trust.**

- **(a) Host/VMM → VTL2:** The env vars are normally set by
  `underhill_init`/`underhill_entry` from IGVM/measured boot parameters,
  not directly by the host, so confidentiality state is not host-controlled.
  However, anything that writes the env in the paravisor process inherits
  that trust assumption — callers must not let untrusted input populate
  these vars.
- **(b)** and **(c)** not applicable; the crate has no guest- or
  hypervisor-facing inputs.

### `openhcl_attestation_protocol`

**Responsibility.** Pure wire-format/data-structure crate (no I/O, no
business logic) that defines the binary and JSON layouts shared between
the paravisor and the host-side IGVm Agent for the `IGVM_ATTEST` GET host
request, plus the on-disk layouts of all VMGS file entries the
attestation flow consumes. Both `underhill_attestation` and the host's
IGVm Agent depend on it so the two ends agree byte-for-byte.
`#![forbid(unsafe_code)]`.

**Modules.**

- [lib.rs](openhcl/openhcl_attestation_protocol/src/lib.rs) — Just
  declares the `igvm_attest` and `vmgs` submodules.
- [igvm_attest/mod.rs](openhcl/openhcl_attestation_protocol/src/igvm_attest/mod.rs)
  — Empty container that exposes `akv`, `cps`, `get`.
- [igvm_attest/get.rs](openhcl/openhcl_attestation_protocol/src/igvm_attest/get.rs)
  — The core IGVM_ATTEST GET wire format — request/response headers,
  request types (`KEY_RELEASE_REQUEST`, `AK_CERT_REQUEST`,
  `WRAPPED_KEY_REQUEST`), report types (VBS/SNP/TDX/TVM), hash types
  (SHA-256/384/512), version enums (V1, V2 with `IgvmErrorInfo`/retry
  signal), per-request response headers, response-buffer page constants
  (`KEY_RELEASE_RESPONSE_BUFFER_SIZE = WRAPPED_KEY_RESPONSE_BUFFER_SIZE =
  16 pages`, `AK_CERT_RESPONSE_BUFFER_SIZE = 1 page`), and the JSON
  `runtime_claims` schema (`RuntimeClaims`, `RsaJwk`,
  `AttestationVmConfig`) appended to every request and hashed into the
  report's `report_data`.
- [igvm_attest/akv.rs](openhcl/openhcl_attestation_protocol/src/igvm_attest/akv.rs)
  — Subset of the Azure Key Vault SKR response shape —
  `AkvKeyReleaseJwtHeader{alg,x5c}`, nested `AkvKeyReleaseJwtBody →
  response → key → key.key_hsm` (base64url), and
  `AkvKeyReleaseKeyBlob{ciphertext}` for the raw wrapped key, covering
  both the AKV ≤7.2 plain-JSON and >7.2 JWT response shapes.
- [igvm_attest/cps.rs](openhcl/openhcl_attestation_protocol/src/igvm_attest/cps.rs)
  — Subset of the CPS-issued VMMD JSON blob: `VmmdBlob →
  DiskEncryptionSettings → encryption_info → {aes_info.ciphertext,
  key_reference: serde_json::Value}`, where `ciphertext` is a
  base64-encoded RSA-OAEP-wrapped DiskEncryptionSettings symmetric key.
- [vmgs.rs](openhcl/openhcl_attestation_protocol/src/vmgs.rs) — On-disk
  layouts of attestation-related VMGS entries: `KeyProtector` (two
  `DekKp`+`GspKp` slots plus `active_kp` index),
  `KeyProtectorById{id_guid, ported}`,
  `SecurityProfile{agent_data: [u8; 2048]}`,
  `HardwareKeyProtector{header(version, length, tcb_version), iv,
  ciphertext, hmac}` (AES-CBC + HMAC-SHA-256, version 1),
  `GuestSecretKey{[u8; 2048]}`, plus all sizing constants
  (`AES_GCM_KEY_LENGTH=32`, `AES_CBC_KEY_LENGTH=32`,
  `AES_CBC_IV_LENGTH=16`, `HMAC_SHA_256_KEY_LENGTH=32`,
  `DEK_BUFFER_SIZE=512`, `GSP_BUFFER_SIZE=512`, `NUMBER_KP=2`).

**Public API.**

- `igvm_attest::get`: constants (`SNP_VM_REPORT_SIZE`,
  `TDX_VM_REPORT_SIZE`, `VBS_VM_REPORT_SIZE`, `TVM_REPORT_SIZE`, the
  response-buffer sizes, `IGVM_ATTEST_REQUEST_CURRENT_VERSION`,
  `IGVM_ATTEST_RESPONSE_CURRENT_VERSION`); `open_enum`s
  `IgvmAttestRequestType`, `IgvmAttestReportType`, `IgvmAttestHashType`,
  `IgvmAttestRequestVersion`, `IgvmAttestResponseVersion`; structs
  `IgvmAttestRequestHeader`, `IgvmAttestRequestData`,
  `IgvmAttestRequestDataExt`, `IgvmAttestRequestBase`,
  `IgvmAttestCommonResponseHeader`, `IgvmErrorInfo`, `IgvmSignal`,
  `IgvmCapabilityBitMap`, `IgvmAttestKeyReleaseResponseHeader`,
  `IgvmAttestWrappedKeyResponseHeader`,
  `IgvmAttestAkCertResponseHeader`; `runtime_claims::{RuntimeClaims,
  RsaJwk, AttestationVmConfig}` with helpers
  `key_release_request_runtime_claims`, `ak_cert_runtime_claims`,
  `get_transfer_key_jwks`, `get_tpm_jwks`.
- `igvm_attest::akv`: `AkvKeyReleaseJwtHeader`, `AkvKeyReleaseJwtBody`,
  `AkvKeyReleaseResponse`, `AkvKeyReleaseKeyObject`, `AkvJwk`,
  `AkvKeyReleaseKeyBlob`.
- `igvm_attest::cps`: `VmmdBlob`, `DiskEncryptionSettings`,
  `EncryptionInfo`, `AesInfo`.
- `vmgs`: `DekKp`, `GspKp`, `KeyProtector`, `KeyProtectorById`,
  `SecurityProfile`, `HardwareKeyProtectorHeader`, `HardwareKeyProtector`,
  `GuestSecretKey`, plus all sizing constants and `HW_KEY_VERSION = 1`.

**External I/O.** None — the crate defines the wire/storage format only.

**Consumed by.** In-paravisor `underhill_attestation`; host-side IGVm
Agent (out of repo) shares byte-exact definitions.

**Trust.**

- **(a) Host/VMM → VTL2:** Every IGVM_ATTEST response header
  (`IgvmAttestCommonResponseHeader`, the per-request response headers,
  `IgvmErrorInfo`), the AKV JWT/JSON payload (`AkvKeyRelease*`), the CPS
  `VmmdBlob`, the AK-cert payload, and the VMGS file entries
  (`KeyProtector`, `KeyProtectorById`, `SecurityProfile`,
  `HardwareKeyProtector`, `GuestSecretKey`) all originate on the host
  side and are deserialised inside the paravisor — they cross the
  host→VTL2 boundary. Use of `open_enum!`, `zerocopy::FromBytes`, and
  `serde_json` (with size checks done by callers) is what allows host
  bytes to round-trip without panicking.
- **(b) VTL0 guest → VTL2:** Not directly applicable; the formats here
  aren't fed by the VTL0 guest. (The `RuntimeClaims.user_data` field for
  AK-cert is paravisor-supplied.)
- **(c) Hypervisor → VTL2:** Indirect: `attestation_report` bytes
  embedded in `IgvmAttestRequestBase` come from the hardware via
  `tee_call`; the protocol crate just describes their layout.

### `underhill_attestation`

**Responsibility.** Implements the paravisor's attestation and
VMGS-key-management state machine: on boot it talks to the host's IGVm
Agent (via the GET transport) to perform secure key release (SKR), unwraps
a tenant key-encryption key (KEK) from VMGS, optionally mixes in
host-provided Guest State Protection (GSP / GSP-by-ID) seeds and a
TEE-derived hardware key, derives ingress/egress AES-GCM keys for the
VMGS, unlocks the VMGS, rolls keys, persists updated key-protector blobs,
and returns the attestation/agent-data context the rest of the paravisor
(notably the vTPM AK-cert path) needs. It also exposes a parser used by
the TPM emulator to validate AK-cert responses. Linux-only;
`#![forbid(unsafe_code)]`.

**Modules.**

- [lib.rs](openhcl/underhill_attestation/src/lib.rs) — Top-level
  orchestration. Defines `AttestationType`, `HostAttestationSettings`,
  `PlatformAttestationData`, the public entry points
  `initialize_platform_security`, `parse_ak_cert_response`, and the typed
  `Error` wrapper. Implements `try_unlock_vmgs`, `get_derived_keys`,
  `get_derived_keys_by_id`, `get_gsp_data`, `unlock_vmgs_data_store`,
  `persist_all_key_protectors`, `derive_key` (KBKDF-HMAC-SHA-256 with
  label `"VMGSKEY"`), and the retry/backoff loop (≤10 attempts when VMGS
  already encrypted, 1 attempt otherwise). Hosts the elaborate
  ingress/egress matrix combining tenant-KEK, GSP, GSP-by-Id, and
  hardware sealing per the `GuestStateEncryptionPolicy` (`Auto`, `None`,
  `GspById`, `GspKey`, `HardwareSealing`).
- [hardware_key_sealing.rs](openhcl/underhill_attestation/src/hardware_key_sealing.rs)
  — Implements `HardwareDerivedKeys::derive_key` using
  `TeeCallGetDerivedKey::get_derived_key(tcb_version)` mixed via
  KBKDF-HMAC-SHA-256 over a JSON-serialised `AttestationVmConfig` with
  label `"ISOHWKEY"`, producing AES-CBC + HMAC-SHA-256 keys. The
  `HardwareKeyProtectorExt` trait (`seal_key`, `unseal_key`) seals/unseals
  the VMGS DEK with AES-256-CBC + HMAC-SHA-256 over `header||iv||
  ciphertext` and stores it in the `HW_KEY_PROTECTOR` VMGS entry — used
  as a recovery path when the host can't release a key.
- [igvm_attest/mod.rs](openhcl/underhill_attestation/src/igvm_attest/mod.rs)
  — Builds `IGVM_ATTEST` request bytes
  (`IgvmAttestRequestHelper::prepare_key_release_request` /
  `prepare_ak_cert_request` / `create_request`), computes the SHA-256 of
  the JSON `RuntimeClaims` to embed in the report's `report_data`, and
  parses the V1/V2 response header, surfacing `IgvmErrorInfo{error_code,
  http_status_code}` and the retry signal as `Error::Attestation`.
- [igvm_attest/ak_cert.rs](openhcl/underhill_attestation/src/igvm_attest/ak_cert.rs)
  — `parse_response` for `AK_CERT_REQUEST` — strips the V1 or V2 response
  header and returns the raw AK-cert bytes (X.509 DER); used by the TPM
  platform code (`emuplat/tpm.rs`) and re-exported as
  `parse_ak_cert_response`.
- [igvm_attest/key_release.rs](openhcl/underhill_attestation/src/igvm_attest/key_release.rs)
  — `parse_response` for `KEY_RELEASE_REQUEST` — accepts either AKV ≤7.2
  plain JSON (`AkvKeyReleaseKeyBlob{ciphertext}`) or AKV >7.2 JWT
  (`AkvKeyReleaseJwtBody`), validates the JWT signature when `x5c` is
  present, and returns the raw RSA-AES-wrapped key blob.
- [igvm_attest/wrapped_key.rs](openhcl/underhill_attestation/src/igvm_attest/wrapped_key.rs)
  — `parse_response` for `WRAPPED_KEY_REQUEST` — deserialises the CPS
  `VmmdBlob`, returning `IgvmWrappedKeyParsedResponse{wrapped_key,
  key_reference}` (the wrapped DiskEncryptionSettings symmetric key plus
  its opaque JSON key reference).
- [jwt.rs](openhcl/underhill_attestation/src/jwt.rs) — Minimal JWT parser:
  `JwtHelper`, `JwtHeader{alg, x5c}` with `JwtAlgorithm::RS256`,
  base64-url decoding of header/body/signature, X.509 chain validation
  via `crypto::x509`, and RS256 signature verification using the leaf
  certificate's RSA public key.
- [key_protector.rs](openhcl/underhill_attestation/src/key_protector.rs)
  — `KeyProtectorExt::unwrap_and_rotate_keys` decodes the active DEK
  slot using the tenant RSA KEK (RSA-OAEP unwrap) — or
  AES-WRAP-WITH-PADDING if a `wrapped_des_key` was provided — and
  produces a fresh egress AES-GCM key wrapped back into the egress slot.
  Defines `AES_WRAPPED_AES_KEY_LENGTH=40` and
  `RSA_WRAPPED_AES_KEY_LENGTH=256`.
- [secure_key_release.rs](openhcl/underhill_attestation/src/secure_key_release.rs)
  — Drives the two-step SKR over the GET transport: optionally first
  issues `WRAPPED_KEY_REQUEST` (CPS) to fetch the DiskEncryptionSettings
  wrapped key + key reference, then issues `KEY_RELEASE_REQUEST` (AKV via
  IGVm Agent) using a freshly generated 2048-bit RSA transfer key whose
  JWK goes into `RuntimeClaims`. Implements `pkcs11_rsa_aes_key_unwrap`
  (RSA-OAEP-SHA1 over the wrapped AES key, then AES-key-wrap-with-padding
  over the wrapped RSA private key, then `RsaKeyPair::from_pkcs8_der`) to
  produce the unwrapped tenant RSA KEK. Returns `VmgsEncryptionKeys{
  ingress_rsa_kek, wrapped_des_key, tcb_version}`.
- [vmgs.rs](openhcl/underhill_attestation/src/vmgs.rs) — Typed read/write
  helpers over the `vmgs` crate for the file IDs `KEY_PROTECTOR`,
  `VM_UNIQUE_ID` (KeyProtectorById), `ATTEST` (SecurityProfile),
  `HW_KEY_PROTECTOR` (HardwareKeyProtector), `GUEST_SECRET_KEY` —
  `read_key_protector`, `write_key_protector`, `read_key_protector_by_id`,
  `write_key_protector_by_id`, `read_security_profile`,
  `read_hardware_key_protector`, `write_hardware_key_protector`,
  `read_guest_secret_key`. Centralises size validation and surfaces
  `EntryNotFound`/`EntrySizeTooSmall`/etc. errors.
- [test_helpers.rs](openhcl/underhill_attestation/src/test_helpers.rs)
  (cfg(test)): Builds self-signed X.509 certs and base64-url-encoded JWT
  components used by the JWT, AK-cert, and key-release unit tests. Also
  provides the test `MockTeeCall`/`MockTeeCallNoGetDerivedKey` (in
  `lib.rs::test_utils`).

**Public API.**

- `initialize_platform_security(get, bios_guid, attestation_vm_config,
  vmgs, tee_call, suppress_attestation, driver,
  guest_state_encryption_policy, strict_encryption_policy) ->
  Result<PlatformAttestationData, Error>` — the single entry point called
  by `underhill_core` to run attestation/SKR and unlock the VMGS.
- `PlatformAttestationData { host_attestation_settings:
  HostAttestationSettings, agent_data: Option<Vec<u8>>, guest_secret_key:
  Option<Vec<u8>> }`.
- `HostAttestationSettings { refresh_tpm_seeds: bool }`.
- `AttestationType` enum (`Snp`, `Tdx`, `Vbs`, `Host`) — `MeshPayload`,
  used by the host/control plane to select the TEE.
- `Error` (opaque transparent wrapper around the internal
  `AttestationErrorInner`).
- `IgvmAttestError` (re-export of `igvm_attest::Error`).
- `IgvmAttestRequestHelper` (re-export) — `prepare_key_release_request`,
  `prepare_ak_cert_request`, `set_request_type`,
  `get_runtime_claims_hash`, `create_request`. Used by the vTPM emuplat to
  build AK-cert requests on demand.
- `parse_ak_cert_response` (re-export of
  `igvm_attest::ak_cert::parse_response`) — used by `emuplat/tpm.rs` to
  validate IGVm Agent AK-cert responses.

**External I/O.**

- **GET transport** (`guest_emulation_transport::GuestEmulationTransportClient`)
  — the actual transport to the host. The crate issues:
  - `IGVM_ATTEST` GET host request with the three sub-types
    `KEY_RELEASE_REQUEST` (1), `AK_CERT_REQUEST` (2), `WRAPPED_KEY_REQUEST`
    (3). Request layout = `IgvmAttestRequestBase` (header + zero-padded
    TEE report up to `SNP_REPORT_SIZE`) `||` `IgvmAttestRequestDataExt`
    (V2+, capability bitmap) `||` raw `RuntimeClaims` JSON. Response
    buffers are pre-allocated 16 pages (key-release/wrapped-key) or 1 page
    (ak-cert) of shared/DMA memory. Header includes signature `'HCLA'`
    (0x414c4348), version 2, and an `IgvmErrorInfo` with HTTP status +
    retry signal in V2 responses.
  - `guest_state_protection_data(encrypted_gsp[NUMBER_KP], flags)` — host
    RPC that returns `GuestStateProtection { encrypted_gsp,
    decrypted_gsp[NUMBER_KP], new_gsp, extended_status_flags }` (host
    fabric per-VM seed). Status flags `no_rpc_server`/
    `requires_rpc_server`/`state_refresh_request`.
  - `guest_state_protection_data_by_id()` — fallback "GSP by ID" host RPC,
    which mixes the BIOS GUID with a fabric-wide seed.
  - `event_log_fatal(EventLogId::ATTESTATION_FAILED |
    DEK_DECRYPTION_FAILED)` for telemetry on fatal failures.
- **VMGS file** (via the `vmgs` crate) — reads/writes the
  `FileId::{KEY_PROTECTOR, VM_UNIQUE_ID, ATTEST, HW_KEY_PROTECTOR,
  GUEST_SECRET_KEY}` entries and uses
  `vmgs::Vmgs::{unlock_with_encryption_key, update_encryption_key,
  encrypted, was_provisioned_this_boot}` with
  `EncryptionAlgorithm::AES_GCM`.
- **TEE** (via `tee_call`): `get_attestation_report(report_data =
  SHA-256(RuntimeClaims_JSON) padded to 64 bytes)` and, where supported
  (SNP only today), `get_derived_key(tcb_version)` — `/dev/sev-guest`,
  `/dev/tdx_guest`, or VBS hypercall as documented above.
- **Crypto** (via `crypto`): KBKDF-HMAC-SHA-256 (label `"VMGSKEY"` for the
  data path, `"ISOHWKEY"` for hardware sealing), AES-256-CBC,
  HMAC-SHA-256, AES-key-wrap-with-padding, RSA-OAEP (SHA-1 for PKCS#11
  RSA-AES unwrap, SHA-256 for transfer key), 2048-bit RSA generation for
  the transfer key, X.509 chain validation for AKV JWT signing certs.

**Trust.**

- **(a) Host/VMM → VTL2:** Almost every input here is host-controlled and
  untrusted: every IGVM_ATTEST response (AK-cert bytes, AKV JWT/JSON, CPS
  VMMD JSON), the GSP and GSP-by-Id RPC payloads, all VMGS file contents
  (`KeyProtector`, `KeyProtectorById`, `SecurityProfile.agent_data`,
  `HardwareKeyProtector`, `GuestSecretKey`), and even the
  `IgvmErrorInfo.error_code`/`http_status_code`/retry bit. Defences:
  every wire struct is `zerocopy::FromBytes` with explicit size validation
  in `igvm_attest::parse_response_header`, every VMGS read goes through
  the `vmgs` helpers that enforce min/max sizes and error rather than
  panic, JWT signatures are verified against the embedded `x5c` chain,
  and the AKV-decoded "wrapped key" must round-trip through RSA-OAEP
  unwrap (any tampering causes a hard crypto failure). The
  hardware-sealing fallback ensures that a malicious or absent host can't
  permanently lose the VMGS as long as the TEE can re-derive the same
  hardware secret.
- **(c) Hypervisor → VTL2:** The TEE attestation report is signed by
  hardware (or in VBS by the hypervisor itself), and `tcb_version` and
  the report bytes flow through `tee_call`. The crate trusts the report
  only insofar as the IGVm Agent / Azure attestation service later
  verifies the signature; locally it's used to bind `runtime_claims` (via
  SHA-256 in `report_data`) and to mix `tcb_version` into hardware-derived
  keys.
- **(b) VTL0 guest → VTL2:** Not directly — this crate runs before/around
  the VTL0 guest boots. The only indirect coupling is that
  `PlatformAttestationData.guest_secret_key` is later provisioned into
  the vTPM and the AK-cert path serves the VTL0 guest's TPM, so any data
  the crate exports is treated by downstream code as VTL2-vouched and
  host-untrusted before that point.

## VMM-in-paravisor, diag, profiling

### `openvmm_hcl`

**Responsibility.** The root binary crate that produces the in-paravisor
VMM executable (`openvmm_hcl`) shipped inside OpenHCL/Underhill. Unlike the
host `openvmm` binary, it runs inside VTL2 on Linux (it `unimplemented!`s
on other targets), is launched by the OpenHCL boot environment, and
delegates to `underhill_entry::underhill_main` for all real logic. It
exists primarily to (a) link in the static resource/worker registrations
from `openvmm_hcl_resources` and (b) gate paravisor-only feature flags
(TPM, NVMe/VPCI, GDB stub, mimalloc-secure, UI/VNC,
mem-profile-tracing, dev SNP TIO).

**Modules.**

- [main.rs](openhcl/openvmm_hcl/src/main.rs) — Tiny entry point: on Linux
  it imports `openvmm_hcl_resources` purely for its side-effect static
  registrations and re-exports `underhill_entry::underhill_main` as
  `main`; on non-Linux it `unimplemented!()`s.

**Public API.** `main` (from `underhill_entry::underhill_main`).

**External I/O.** All argument and environment parsing lives in
`underhill_entry`/`underhill_init`; this binary is invoked by
`underhill_init` (PID 1) inside the paravisor with the OpenHCL kernel
cmdline / `OPENHCL_*` env vars passed through. No direct I/O of its own —
everything is performed by transitively-linked crates (vsock/diag server,
hypercalls, `/dev/mshv*`, vmbus, etc.).

**Trust.** Indirect on all three boundaries; this crate itself contains
no logic and so introduces no new boundary. `#![forbid(unsafe_code)]`.

### `openvmm_hcl_resources`

**Responsibility.** A "side-effect" library whose sole purpose is to call
`vm_resource::register_static_resolvers!` and
`mesh_worker::register_workers!` so that resource kinds and mesh workers
are linked into the `openvmm_hcl` binary. It is the paravisor analogue of
`openvmm_resources` (host) — a deliberately curated subset of devices/
workers appropriate for VTL2 (no host-only chipset, no full UI stack by
default), gated by Cargo features for TPM, UI devices, NVMe/VPCI, GDB
debug-worker, and VNC-worker. Linux-only.

**Modules.**

- [lib.rs](openhcl/openvmm_hcl_resources/src/lib.rs) — Single file with
  two macro invocations:
  - `register_static_resolvers!` registers:
    - *Chipset devices (x86_64):* `chipset::i8042`,
      `chipset_legacy::piix4_uhci` (USB UHCI stub),
      `chipset_legacy::piix4_pci_isa_bridge`, `chipset::pit`,
      `chipset::pic`. *(All arches):* `missing_dev`, optional `tpm_device`
      (feature `tpm`), `serial_16550` (x86_64) / `serial_pl011` (aarch64),
      `chipset::battery`.
    - *Non-volatile stores:* `EphemeralNonVolatileStoreResolver`,
      `vmgs_broker::VmgsFileResolver`.
    - *Serial backends:* `DisconnectedSerialBackendResolver`,
      `VmbusSerialGuestResolver`.
    - *Disks:* `disk_striped::StripedDiskResolver` (`BlockDevice` and
      `NvmeDisk` are registered dynamically elsewhere because they have
      runtime deps).
    - *SCSI:* `scsidisk::SimpleScsiResolver`.
    - *Vmbus devices:* `hyperv_ic::ShutdownIcResolver`,
      `storvsp::StorvspResolver`, optional `uidevices::VmbusUiResolver`
      (feature `uidevices`).
    - *VPCI devices:* optional `nvme::NvmeControllerResolver` (feature
      `nvme`).
  - `register_workers!` registers (both over `vmsocket::VmListener`):
    optional `vnc_worker::VncWorker` (feature `vnc_worker`) and optional
    `debug_worker::DebuggerWorker` (feature `debug_worker`, the GDB stub).

**Public API.** None (all exports are static-registration side effects).

**External I/O.** None directly. The registered resolvers, when later
instantiated by `underhill_core`, use AF_VSOCK (vmbus_serial, VNC,
gdb-stub listeners), `/dev/mshv*`, NVMe via VFIO, and SCSI/VMGS file
backings.

**Trust.**

- **(a) Host/VMM → VTL2:** VNC / GDB-stub workers listen on AF_VSOCK to
  the host — both are dev-only features and are untrusted host channels.
- **(b) VTL0 guest → VTL2:** All registered devices (chipset emulation,
  vmbus IC/storvsp/UI, SCSI, NVMe, TPM, UART) process guest MMIO/PIO/
  ring-buffer traffic — the primary attack surface for OpenHCL. Unsafe
  code is forbidden in this crate.
- **(c) Hypervisor → VTL2:** Indirect via the resolvers' implementations
  (e.g. interrupt routing via `hcl`).

### `diag_server`

**Responsibility.** The Underhill/OpenHCL diagnostics server — a ttrpc/
mesh-RPC server inside VTL2 that exposes lifecycle, inspection, exec,
kmsg/file streaming, packet capture, save-state dump, profiling, and
memory-profile services to a host-side client (`ohcldiag-dev`). It listens
on two AF_VSOCK ports (control + data) — or Unix sockets for tests —
accepts data-channel sockets that are later "claimed" by control-channel
RPCs by id, and forwards lifecycle/inspect requests via a
`mesh::Sender<DiagRequest>` to `underhill_core`. CVMs disable the legacy
`UnderhillDiag`/`OpenhclDiag` services entirely and restrict inspect to
`SensitivityLevel::Safe`.

**Modules.**

- [lib.rs](openhcl/diag_server/src/lib.rs) — Defines `DiagServer` (the
  public type), constructors `new_vsock(VmAddress, VmAddress)` and
  `new_unix(&Path, &Path)`, the `serve()` loop that wires each protobuf
  service into `mesh_rpc::Server` (`UnderhillDiag`, `OpenhclDiag`,
  `inspect_proto::InspectService`, `azure_profiler_proto::AzureProfiler`),
  the `DataConnections` table that pairs incoming data sockets with
  8-byte connection-ids, and the `grpc_result` helper that maps
  `anyhow::Result` / `CancelReason` to ttrpc `Status`/`Code`.
- [diag_service.rs](openhcl/diag_server/src/diag_service.rs) — Implements
  `DiagServiceHandler::process_requests`, which merges all four service
  receivers and dispatches one task per request. Each handler turns a
  protobuf RPC into a `DiagRequest` (or handles it locally): `Exec`
  spawns a Linux child wired to claimed data-conn sockets via pipes/pty/
  raw-socket-fd (with a TDX-glibc `GLIBC_TUNABLES` workaround); `Wait`
  joins the child; `Kmsg`/`ReadFile` open `/dev/kmsg` or arbitrary files
  (char-dev → `PolledPipe`, regular → `futures::io::copy`);
  `PacketCapture` translates Query/Start/Stop into
  `net_packet_capture::PacketCaptureParams` over claimed socket writers;
  `Inspect`/`Update` use `InspectionBuilder` plumbed through
  `inspect::send(&request_send, DiagRequest::Inspect)`; `Profile` builds a
  `profiler_worker::ProfilerRequest` (feature-gated); `MemoryProfileTrace`
  (feature-gated) returns dhat output. Also defines the `DiagRequest`
  mesh enum and `StartParams` as the public surface, and the `relay()`
  helper that bridges a read end and a write end with RDHUP-aware
  shutdown.
- [new_pty.rs](openhcl/diag_server/src/new_pty.rs) — Single
  `pub(crate) fn new_pty() -> io::Result<(File, File)>` calling
  `libc::openpty` (the only `unsafe` block in the crate) to allocate a
  primary/secondary pty pair for `Exec` requests with `tty=true`.

**Public API.**

- `DiagServer` (`new_vsock`, `new_unix`, `serve`).
- `DiagRequest` (mesh-payload enum: `Start`, `Inspect`, `Crash`,
  `Restart`, `Pause`, `Resume`, `Save`, `PacketCapture`, plus
  feature-gated `Profile` and `MemoryProfileTrace`).
- `StartParams { env, args }`.

**External I/O.** Protobuf services served (from
[diag.proto](openhcl/diag_proto/src/diag.proto), package `diag`):

- **`OpenhclDiag`**: `Ping(Empty) -> Empty`;
  `MemoryProfileTrace(MemoryProfileTraceRequest) ->
  MemoryProfileTraceResponse`.
- **`UnderhillDiag`** (legacy): `Exec(ExecRequest) -> ExecResponse`;
  `Wait(WaitRequest) -> WaitResponse`; `Start(StartRequest) -> Empty`;
  `Crash(CrashRequest) -> Empty`; `Kmsg(KmsgRequest) -> Empty`;
  `Restart(Empty) -> Empty`; `Pause(Empty) -> Empty`;
  `Resume(Empty) -> Empty`; `ReadFile(FileRequest) -> Empty`;
  `DumpSavedState(Empty) -> DumpSavedStateResponse`;
  `PacketCapture(NetworkPacketCaptureRequest) ->
  NetworkPacketCaptureResponse`.
- **`inspect_proto::InspectService`**: `Inspect`, `Update`.
- **`azure_profiler_proto::AzureProfiler`**: `Profile`.

Sockets:

- AF_VSOCK control listener (`diag_proto::VSOCK_CONTROL_PORT = 1`) and
  data listener (`VSOCK_DATA_PORT = 2`), or equivalent Unix-socket pairs
  for tests.
- For each accepted data socket, the server writes an 8-byte little-endian
  id and parks the socket in a table; it is later "taken" by a control
  RPC referencing that id.

Files / kernel interfaces:

- `/dev/kmsg` (read/follow for `Kmsg`).
- Arbitrary `/proc`, `/sys`, log files via `ReadFile`.
- `libc::openpty` for tty exec.
- `pal::unix::process::Builder` to fork child processes (with
  stdin/stdout/stderr wired to claimed vsock sockets).

**Trust.**

- **(a) Host/VMM → VTL2 (untrusted):** Every RPC arrives over AF_VSOCK
  from a host client. The server treats them as untrusted: errors are
  converted to ttrpc `Status` rather than panicking; `take_connection`
  returns `Err` for unknown ids; pty creation, file open, and child spawn
  errors propagate as gRPC errors. CVMs disable both legacy diag services
  and force inspect sensitivity to `Safe`. Note that `Exec` itself (run
  arbitrary command in VTL2) is *intentionally* very privileged — its
  safety relies on the surrounding deployment gating diag access.
- **(b) VTL0 guest → VTL2:** Not directly exposed. Packet-capture data
  flowing through can be guest-influenced but is forwarded as opaque
  bytes to host writers.
- **(c) Hypervisor → VTL2:** Only the cpuid probe in `Exec`
  (`HV_CPUID_FUNCTION_MS_HV_ISOLATION_CONFIGURATION`) — it just selects a
  glibc tunable and is non-fatal.

### `diag_proto`

**Responsibility.** Generated protobuf definitions and shared constants
for the OpenHCL diagnostics wire protocol (the `diag` package). Used by
both the in-paravisor `diag_server` and the host-side `diag_client`/
`ohcldiag-dev`. Build script (`build.rs`) runs `prost-build` with
`mesh::MeshPayload`/`#[mesh(prost)]` derives and the
`mesh_build::MeshServiceGenerator`, so generated services integrate
directly with mesh-RPC.

**Modules.**

- [lib.rs](openhcl/diag_proto/src/lib.rs) — `include!`s the generated
  `diag.rs`, plus the constants `VSOCK_CONTROL_PORT = 1`,
  `VSOCK_DATA_PORT = 2`, and `FILE_LINE_MAX = 2048`.
- [diag.proto](openhcl/diag_proto/src/diag.proto) — The wire schema (see
  RPC list below).
- `build.rs` — `prost-build` configuration that adds mesh derives and
  generates service stubs.

**Public API.**

- Generated types in package `diag` (services `OpenhclDiag`,
  `UnderhillDiag` and all `*Request`/`*Response` messages).
- `VSOCK_CONTROL_PORT`, `VSOCK_DATA_PORT`, `FILE_LINE_MAX`.

**External I/O — proto services & RPCs.**

- *service `OpenhclDiag`* (modern, handles unknown methods correctly):
  - `Ping(google.protobuf.Empty) -> google.protobuf.Empty`
  - `MemoryProfileTrace(MemoryProfileTraceRequest{int32 pid}) ->
    MemoryProfileTraceResponse{bytes data}`
- *service `UnderhillDiag`* (legacy):
  - `Exec(ExecRequest) -> ExecResponse{int32 pid}` — fields: `command`,
    `args`, `tty`, `stdin/stdout/stderr` (uint64 data-conn ids),
    `combine_stderr`, `env: repeated EnvPair{name, optional value}`,
    `clear_env`, `raw_socket_io`.
  - `Wait(WaitRequest{int32 pid}) -> WaitResponse{int32 exit_code}`
  - `Start(StartRequest{repeated EnvPair env, repeated string args}) ->
    Empty`
  - `Crash(CrashRequest{int32 pid}) -> Empty`
  - `Kmsg(KmsgRequest{bool follow, uint64 conn}) -> Empty`
  - `Restart(Empty) -> Empty`
  - `Pause(Empty) -> Empty`
  - `Resume(Empty) -> Empty`
  - `ReadFile(FileRequest{bool follow, uint64 conn, string file_path}) ->
    Empty`
  - `DumpSavedState(Empty) -> DumpSavedStateResponse{bytes data}`
  - `PacketCapture(NetworkPacketCaptureRequest{Operation operation ∈
    {Query,Start,Stop}, oneof OpData{StartPacketCaptureData
    start_data{uint32 snaplen, repeated uint64 conns}}}) ->
    NetworkPacketCaptureResponse{uint32 num_streams}`

**Consumed by.** In-paravisor `diag_server`; host-side `diag_client` and
`ohcldiag-dev` CLI.

**Trust.** Pure schema/constants; introduces no boundary itself.
Deserializers generated by `prost` are exercised on the untrusted
host→VTL2 path inside `diag_server`.

### `profiler_worker`

**Responsibility.** A mesh-worker hosted in VTL2 that performs a single
CPU/perf profiling session per request. It validates free memory (>10 MB,
hard-caps profiler RAM at 75% of free), sets `CLOEXEC=false` on a
host-supplied data socket, then `fork+exec`s the external
`/usr/bin/underhill_profiler_binary` with `(duration_seconds, socket_fd,
...profiler_args)` so that binary writes its output (a `.bin` perf
profile) directly to the host over the inherited vsock fd. The worker
waits `duration+1`s, then polls up to 15s for the child to exit, killing
it on timeout, and surfaces stdout/stderr through `tracing`.

**Modules.**

- [lib.rs](openhcl/profiler_worker/src/lib.rs) — Defines
  `ProfilerRequest{duration: u64, profiler_args: Vec<String>, conn:
  Socket}`, `ProfilerWorkerParameters`, the `ProfilerWorker` impl of
  `mesh_worker::Worker` (Worker ID `"ProfilerWorker"`; `restart` is
  `unimplemented!`), the `profile()` async function (the actual profiling
  logic), and helpers `get_free_mem_mb()` / `parse_meminfo_free()` with
  unit tests.

**Public API.**

- `ProfilerRequest`, `ProfilerWorkerParameters`, `ProfilerWorker`.
- `PROFILER_WORKER: WorkerId<ProfilerWorkerParameters>`
  (`"ProfilerWorker"`).
- `pub async fn profile(request, driver)`.
- `MIN_MEMORY_PROFILER_MB = 10`.

**External I/O.**

- Spawns `/usr/bin/underhill_profiler_binary` (Linux child process)
  inheriting the host vsock data socket as its output FD.
- Reads `/proc/meminfo` for memory accounting.
- Service/RPC sent from host (defined in
  [profile.proto](openhcl/azure_profiler_proto/src/profile.proto), package
  `profile`):
  - *service `AzureProfiler`*: `Profile(ProfileRequest{uint64 conn,
    uint64 duration, repeated string profiler_args}) ->
    google.protobuf.Empty`.
- The collected payload is opaque profiler binary output (a `.bin` perf
  trace produced by the external `underhill_profiler_binary`); it is
  streamed back to the host directly over the data-channel vsock claimed
  by id (not back through the RPC response). The protocol itself is the
  `profile.AzureProfiler` mesh-ttrpc service multiplexed alongside the
  diag services on the OpenHCL diag vsock control port.

**Trust.**

- **(a) Host/VMM → VTL2:** `ProfilerRequest` arrives via the diag vsock
  (untrusted). `duration: u64` is summed with `+1` and `+15` — values
  approaching `u64::MAX` would overflow in `Duration::from_secs(duration
  + 1)` (host can DoS / panic-via-overflow if it sends an absurd
  duration; worth a defensive check). `profiler_args` are passed verbatim
  as command-line args to a privileged child binary in VTL2.
- **(b)** and **(c)** not directly applicable.

### `azure_profiler_proto`

**Responsibility.** Tiny prost-generated crate carrying the
`profile.AzureProfiler` service definition shared by `diag_server`
(handler) and the host profiler client. Mirrors `diag_proto`'s build
setup (`mesh::MeshPayload` derives + `MeshServiceGenerator`) so the
generated service plugs into mesh-RPC.

**Modules.**

- [lib.rs](openhcl/azure_profiler_proto/src/lib.rs) — `include!`s the
  generated `profile.rs`; no other code.
- [profile.proto](openhcl/azure_profiler_proto/src/profile.proto) —
  Schema (below).
- `build.rs` — Same `prost-build` + mesh-service-generator wiring as
  `diag_proto`.

**Public API.** Generated `profile::AzureProfiler` service and
`ProfileRequest` message.

**External I/O — proto service & RPCs.**

- *service `AzureProfiler`* (package `profile`):
  - `Profile(ProfileRequest{uint64 conn, uint64 duration, repeated string
    profiler_args}) -> google.protobuf.Empty`.
- The actual profile data is *not* returned in the RPC response; it is
  streamed out on the side-channel data socket whose id is `conn` (the
  same two-port AF_VSOCK control/data scheme used by `diag_server`).

**Consumed by.** `diag_server` (handler) and host-side profiler client.

**Trust.** Schema-only — all deserialization/dispatch happens in
`diag_server` on the untrusted host→VTL2 path.

### `mem_profile_tracing`

**Responsibility.** Thin wrapper around the [`dhat`](https://docs.rs/dhat)
heap profiler that lets OpenHCL components start a heap-profiling session
and then "snapshot + restart" it on demand, so a host caller can
periodically pull a heap-profile blob via `OpenhclDiag.MemoryProfileTrace`.
Linux-only, `#![forbid(unsafe_code)]`.

**Modules.**

- [lib.rs](openhcl/mem_profile_tracing/src/lib.rs) — Defines `HeapProfiler`
  wrapping `dhat::Profiler`, with `new()` (starts
  `dhat::Profiler::new_heap()`) and `capture_and_restart()` which calls
  `drop_and_get_memory_output()` to obtain a `Vec<u8>` and then
  `mem::forget`s the old profiler while installing a fresh `new_heap()`
  one (avoiding a double-Drop now that DHAT global state has been
  transitioned to Ready).

**Public API.**

- `HeapProfiler::new() -> HeapProfiler`
- `HeapProfiler::capture_and_restart(&mut self) -> Vec<u8>`

**External I/O.**

- *dhat output format:* the JSON heap-profile blob produced by
  `dhat::Profiler::drop_and_get_memory_output()` (the standard
  `dhat-heap.json` content, viewable in `dh_view.html`). It is returned as
  a `Vec<u8>` — *no file is written* on disk. The bytes are wrapped in
  `MemoryProfileTraceResponse{data}` and shipped to the host via the
  `OpenhclDiag.MemoryProfileTrace` RPC.
- DHAT itself works by intercepting allocations through Rust's global
  allocator — no kernel/file interface beyond that.

**Trust.**

- **(a) Host/VMM → VTL2:** Triggered only by host requests through
  `diag_server` (gated like all diag access); the request payload is a
  single `int32 pid` which this crate does not even consume.
- **(b)** and **(c)** not applicable.

## Shared device crates used by the paravisor

These crates live outside `openhcl/` (under `vm/`, `vmm_core/`) and are
shared with the host `openvmm` build, but they are linked into the
in-paravisor `openvmm_hcl` binary via
[openhcl/openvmm_hcl_resources/src/lib.rs](openhcl/openvmm_hcl_resources/src/lib.rs)
and form the bulk of the **VTL0 → VTL2 attack surface** (boundary (b)).
Trust notes here focus on the paravisor view; host-side use is out of
scope.

### `chipset_device` framework — `vm/chipset_device`, `vm/chipset_device_resources`, `vm/chipset_arc_mutex_device`

**Responsibility.** The trait abstraction every emulated device implements,
plus the resource-resolution glue that lets a `MeshPayload` device handle
be turned into an instantiated device at VM start-up. `chipset_device` is
deliberately small and dependency-light (no inspect/save-restore bounds);
`chipset_device_resources` adds the `vm_resource`/`vmcore` integration;
`chipset_arc_mutex_device` is a legacy `Arc<CloseableMutex<...>>` wiring
kept only for tests. `#![forbid(unsafe_code)]`.

**Modules.**

- [chipset_device/src/lib.rs](vm/chipset_device/src/lib.rs) — the
  `ChipsetDevice` trait with optional capability accessors
  (`supports_pio`, `supports_mmio`, `supports_pci`, `supports_poll_device`,
  `supports_line_interrupt_target`, `supports_handle_eoi`,
  `supports_acknowledge_pic_interrupt`, `supports_tdisp`).
- [chipset_device/src/io.rs](vm/chipset_device/src/io.rs),
  [pio.rs](vm/chipset_device/src/pio.rs),
  [mmio.rs](vm/chipset_device/src/mmio.rs),
  [pci.rs](vm/chipset_device/src/pci.rs),
  [interrupt.rs](vm/chipset_device/src/interrupt.rs),
  [poll_device.rs](vm/chipset_device/src/poll_device.rs),
  [tdisp.rs](vm/chipset_device/src/tdisp.rs) — per-capability traits
  (`PortIoIntercept`, `MmioIntercept`, `PciConfigSpace`,
  `LineInterruptTarget`, `HandleEoi`, `AcknowledgePicInterrupt`,
  `PollDevice`, `TdispHostDeviceTarget`) and `IoResult`/`IoError` types.
- [chipset_device_resources/src/lib.rs](vm/chipset_device_resources/src/lib.rs)
  — `ResolveChipsetDeviceHandleParams`, `ResolvedChipsetDevice`, the
  `LineSetId` constants (`IRQ_LINE_SET`, `GPE0_LINE_SET`,
  `BSP_LINT_LINE_SET`), and the `vm_resource` plumbing that ties
  `ChipsetDeviceHandleKind` resources to instantiated devices.
- [chipset_arc_mutex_device/src/{device,services,test_chipset}.rs](vm/chipset_arc_mutex_device/src/lib.rs)
  — Legacy `Arc<CloseableMutex<dyn ChipsetDevice>>` plumbing kept only
  for testing (no longer used by OpenVMM/OpenHCL).

**Public API.** The `ChipsetDevice` trait + per-capability sub-traits;
the `ResolveChipsetDeviceHandleParams`, `ResolvedChipsetDevice`, and
`LineSetId` types.

**External I/O.** None directly — these crates provide the *interfaces*
through which all guest MMIO/PIO/PCI accesses reach an emulated device.

**Trust.** Defines the shape of boundary (b). Devices return `IoResult`
rather than panicking on bad accesses; bounds are intentionally minimal so
device crates can be tested in isolation.

### `vmotherboard` — `vmm_core/vmotherboard`

**Responsibility.** Builder pattern that wires all `ChipsetDevice`
instances onto a "virtual motherboard": owns the `BaseChipsetBuilder`,
selects a chipset topology (PIIX4/i440BX for Gen1, modern for Gen2),
allocates IRQ/MMIO/PIO regions, exposes the `Chipset` runtime that
dispatches each guest exit to the right device's intercept range, and
plumbs `PowerEvent`/`DebugEvent` callbacks back to the VMM.
`#![forbid(unsafe_code)]`.

**Modules.**

- [lib.rs](vmm_core/vmotherboard/src/lib.rs) — Public surface:
  `BaseChipsetBuilder`, `BaseChipsetBuilderOutput`,
  `BaseChipsetDeviceInterfaces`, `Chipset`, `ChipsetDevices`,
  `ChipsetBuilder`, `DynamicDeviceUnit`, `ArcMutexChipsetDeviceBuilder`,
  `VmmChipsetDevice` super-trait (adds `InspectMut + ProtobufSaveRestore +
  ChangeDeviceState`), `PowerEvent`/`PowerEventHandler`,
  `DebugEventHandler`, `BusId<T>` typed bus identifiers.
- [base_chipset/](vmm_core/vmotherboard/src/lib.rs) (`mod base_chipset`)
  — `BaseChipsetBuilder` and the `options::BaseChipsetDevices` enum that
  describes which chipset SKU to instantiate.
- [chipset/](vmm_core/vmotherboard/src/lib.rs) (`mod chipset`) — the
  runtime `Chipset` and its `backing::arc_mutex` device storage.

**Public API.** All re-exports above.

**External I/O.** None directly — it is the dispatch layer between the
hypervisor exit handler (`virt_mshv_vtl`) and individual device crates.

**Trust.** Boundary (b) dispatch. The crate forbids `unsafe`, and
intercept ranges are validated against device-declared regions, so a
malicious guest MMIO write cannot reach an out-of-bounds device handler.

### Chipset device implementations — `vm/devices/chipset`, `vm/devices/chipset_legacy`, `vm/devices/chipset_resources`, `vm/devices/missing_dev`

**Responsibility.** The actual emulated platform devices that make up a
synthetic x86/ARM box: PIC/PIT/IOAPIC/8042/CMOS-RTC/PM/battery/DMA in
`chipset`; the Hyper-V Gen1-specific PIIX4 + i440BX bridges, PIIX4 PM,
PIIX4 UHCI USB stub, and Winbond W83977 super-I/O in `chipset_legacy`.
`chipset_resources` defines the `MeshPayload` handles for these devices;
`missing_dev` is a stub device that absorbs accesses to a region with no
real backing (logs and returns 0xff). `#![forbid(unsafe_code)]` everywhere.

**Modules — `chipset`.**

- [battery.rs](vm/devices/chipset/src/battery.rs) — synthetic battery
  device.
- [cmos_rtc.rs](vm/devices/chipset/src/cmos_rtc.rs) — MC146818-style RTC
  + CMOS NVRAM.
- [dma.rs](vm/devices/chipset/src/dma.rs) — 8237 DMA controller stub.
- [i8042.rs](vm/devices/chipset/src/i8042.rs) — PS/2 keyboard/mouse
  controller.
- [ioapic.rs](vm/devices/chipset/src/ioapic.rs) — I/O APIC.
- [pic.rs](vm/devices/chipset/src/pic.rs) — dual 8259 PIC.
- [pit.rs](vm/devices/chipset/src/pit.rs) — 8254 Programmable Interval
  Timer.
- [pm.rs](vm/devices/chipset/src/pm.rs) — generic ACPI power-management.
- [psp.rs](vm/devices/chipset/src/psp.rs) — AMD Platform Security
  Processor stub.

**Modules — `chipset_legacy`.**

- [piix4_pci_bus.rs](vm/devices/chipset_legacy/src/piix4_pci_bus.rs),
  [piix4_pci_isa_bridge.rs](vm/devices/chipset_legacy/src/piix4_pci_isa_bridge.rs),
  [piix4_pm.rs](vm/devices/chipset_legacy/src/piix4_pm.rs),
  [piix4_cmos_rtc.rs](vm/devices/chipset_legacy/src/piix4_cmos_rtc.rs),
  [piix4_uhci.rs](vm/devices/chipset_legacy/src/piix4_uhci.rs),
  [i440bx_host_pci_bridge.rs](vm/devices/chipset_legacy/src/i440bx_host_pci_bridge.rs),
  [winbond83977_sio.rs](vm/devices/chipset_legacy/src/winbond83977_sio.rs).

**Modules — `chipset_resources`.**

- [lib.rs](vm/devices/chipset_resources/src/lib.rs) — `MeshPayload`
  device handles (`I8042DeviceHandle`, `PicDeviceHandle`,
  `PitDeviceHandle`, …) and the `LEGACY_CHIPSET_PCI_BUS_NAME = "i440bx"`
  constant.

**Modules — `missing_dev`.**

- [lib.rs](vm/devices/missing_dev/src/lib.rs) — `MissingDev` chipset
  device that swallows MMIO/PIO/PCI accesses for unbacked regions.

**Public API.** Each `ChipsetDevice` impl plus the corresponding
`*Handle` resource type in `chipset_resources`.

**External I/O.** Each device exposes a fixed MMIO/PIO/PCI region driven
by the guest. `i8042` additionally consumes a `KeyboardInputHandleKind`
resource (synthetic keyboard/mouse input from the host). The PM device
generates ACPI GPE / SCI line interrupts.

**Paravisor use.** Linked into `openvmm_hcl` for x86_64 only:
`i8042`, `pit`, `pic`, `piix4_uhci` (USB stub), `piix4_pci_isa_bridge`,
`battery`. (PIC/PIT/IOAPIC are typically delivered by the hypervisor in
VTL2 deployments; they are still registered for completeness.)
`missing_dev` is registered on all arches.

**Trust.**

- **(b) VTL0 guest → VTL2:** Every byte of every MMIO/PIO/PCI access goes
  through these devices. Guest-supplied addresses, lengths, and command
  bytes are bounds-checked by the framework; legacy devices in particular
  have heavily fuzzed parsers. `unsafe` is forbidden; deserialisation
  uses `zerocopy` with `open_enum!` for protocol fields.

### Serial UARTs — `vm/devices/serial/{serial_core, serial_16550, serial_pl011, serial_socket}`

**Responsibility.** UART emulation and pluggable I/O backends.
`serial_core` defines the `SerialIo` trait every backend implements
(`AsyncRead + AsyncWrite + connect/disconnect polling`) and its
disconnected/null/test variants; `serial_16550` emulates the legacy x86
16550A; `serial_pl011` emulates the ARM PL011 (SBSA-subset) for aarch64
guests; `serial_socket` provides socket/named-pipe backends.
`#![forbid(unsafe_code)]`.

**Modules.**

- [serial_core/src/lib.rs](vm/devices/serial/serial_core/src/lib.rs) —
  `SerialIo` trait.
- [serial_core/src/disconnected.rs](vm/devices/serial/serial_core/src/disconnected.rs),
  [resources.rs](vm/devices/serial/serial_core/src/resources.rs),
  [serial_io.rs](vm/devices/serial/serial_core/src/serial_io.rs) —
  `Disconnected` backend, resource resolvers, and a generic
  `SerialIo` adapter.
- [serial_16550/src/lib.rs](vm/devices/serial/serial_16550/src/lib.rs) —
  `Serial16550` device (FIFO, IER/LCR/MCR/MSR/FCR registers, MMIO-or-PIO
  selectable via `MmioOrIoPort`, line interrupt, RX/TX byte/drop counters
  via `inspect_counters`).
- [serial_16550/src/spec.rs](vm/devices/serial/serial_16550/src/lib.rs)
  (private) — register layout.
- [serial_16550/src/resolver.rs](vm/devices/serial/serial_16550/src/lib.rs)
  — `Serial16550Resolver` registered into `openvmm_hcl_resources`.
- [serial_pl011/src/lib.rs](vm/devices/serial/serial_pl011/src/lib.rs) —
  `SerialPl011` device (ARM PL011 / SBSA subset), MMIO at the address the
  resolver assigns; explicit note that vendor extensions belong in a
  wrapping emulator, not here.
- [serial_pl011/src/resolver.rs](vm/devices/serial/serial_pl011/src/lib.rs)
  — `SerialPl011Resolver` registered into `openvmm_hcl_resources`.
- [serial_socket/src/lib.rs](vm/devices/serial/serial_socket/src/lib.rs)
  — TCP/Unix socket backend (and Windows named-pipe on `cfg(windows)`).

**Public API.** `SerialIo`, `Serial16550`, `SerialPl011`, the
`*Resolver` types, `MmioOrIoPort` (from
`serial_16550_resources`).

**External I/O.** Guest MMIO/PIO at the configured ranges; backend
sockets/pipes (when used) flow through `serial_socket`. The paravisor
uses the `VmbusSerialGuestResolver` (host-side serial over vmbus, see
`vmbus_serial_guest`) and `DisconnectedSerialBackendResolver`
(`/dev/null`) by default.

**Paravisor use.** `serial_16550` registered on x86_64;
`serial_pl011` registered on aarch64. Both via
[openhcl/openvmm_hcl_resources/src/lib.rs](openhcl/openvmm_hcl_resources/src/lib.rs).

**Trust.**

- **(b) VTL0 guest → VTL2:** UART register accesses, FIFO writes, and
  baud-rate divisor traffic are all guest-controlled. RX/TX FIFOs are
  fixed-size; overruns are counted (`rx_dropped`, `tx_dropped`) rather
  than crashing.

### vTPM — `vm/devices/tpm/{tpm_device, tpm_lib, tpm_protocol}`

**Responsibility.** The OpenHCL virtual TPM 2.0 stack. `tpm_device` is
the chipset-facing emulator (MMIO command/response window + IO-port PPI
interface) gated behind `#![cfg(feature = "tpm")]`; `tpm_lib` wraps the
`ms_tpm_20_ref` reference implementation and exposes `TpmEngine`/
`TpmEngineHelper`; `tpm_protocol` defines the TPM 2.0 wire format and the
NV-index constants used for AK-cert / attestation report / guest
attestation input. `#![forbid(unsafe_code)]`.

**Modules — `tpm_device`.**

- [lib.rs](vm/devices/tpm/tpm_device/src/lib.rs) — `Tpm` chipset device.
  MMIO base `0xfed40000` size `0x70`; IO-port range `0x1040..=0x1048`.
  Implements `MmioIntercept`, `PortIoIntercept`, `PollDevice`. Pulls in
  `cvm_tracing` to redact secrets in confidential VMs. Holds the
  `MsTpm20RefPlatform`, a `NonVolatileStore` for vTPM state, and renews
  the AK-cert every 24h via the IGVm Agent.
- [ak_cert.rs](vm/devices/tpm/tpm_device/src/ak_cert.rs) — `TpmAkCertType`
  selecting between trusted (IGVm Agent attested) and untrusted (test)
  AK-cert flows; calls `parse_ak_cert_response` from
  `underhill_attestation`.
- [logger.rs](vm/devices/tpm/tpm_device/src/logger.rs) — `TpmLogger`
  trait plumbed through `event-log_proto` for `TpmLogEvent` telemetry.
- [recover.rs](vm/devices/tpm/tpm_device/src/lib.rs) — Recovery flow for
  corrupt/incompatible NV state.
- [resolver.rs](vm/devices/tpm/tpm_device/src/lib.rs) — Resource resolver
  registered into `openvmm_hcl_resources` when feature `tpm` is on.

**Modules — `tpm_lib`.** `TpmEngine`, `TpmEngineHelper`,
`AllocateNvIndicesParams`, `TpmRsa2kPublic`, `CommandDebugInfo`,
`TpmCommandError`, `TpmEngineError` — all wrap `ms_tpm_20_ref` for command
execution.

**Modules — `tpm_protocol`.** TPM 2.0 wire structures (`tpm20proto::*`,
`CommandCodeEnum`, `TPM20_RH_PLATFORM`) plus the NV-index constants
`TPM_NV_INDEX_AIK_CERT`, `TPM_NV_INDEX_ATTESTATION_REPORT`,
`TPM_NV_INDEX_GUEST_ATTESTATION_INPUT`.

**Public API.** `Tpm` (the device), `TpmAkCertType`,
`TpmEngine`/`TpmEngineHelper`, all the protocol constants and
`tpm20proto` types.

**External I/O.**

- Guest MMIO: TPM 2.0 command/response buffers at
  `TPM_DEVICE_MMIO_REGION_BASE_ADDRESS` (0xfed40000, len 0x70) and the
  PPI command port at `TPM_DEVICE_MMIO_PORT_REGION_BASE_ADDRESS`.
- Guest PIO: `0x1040`/`0x1044` (PPI control + data).
- VMGS-backed `NonVolatileStore` for vTPM persistence.
- Host RPCs (via `underhill_attestation::IgvmAttestRequestHelper`):
  `IGVM_ATTEST AK_CERT_REQUEST` for AK-cert renewal; calls into
  `tee_call::TeeCall::get_attestation_report` for attestation-report
  binding.

**Paravisor use.** Registered when feature `tpm` is enabled; this is the
default for OpenHCL. Driven from `underhill_core::emuplat::tpm`.

**Trust.**

- **(b) VTL0 guest → VTL2:** All TPM commands originate from the VTL0
  guest. Confidential-VM secrets are filtered out of traces via
  `CVM_ALLOWED`/`CVM_CONFIDENTIAL` markers; command parsing goes through
  the `ms_tpm_20_ref` reference implementation, which has been hardened
  upstream against malformed inputs.
- **(a) Host/VMM → VTL2:** AK-cert responses come from the IGVm Agent —
  parsed via `parse_ak_cert_response` and validated against the embedded
  X.509 chain before being installed into the AK-cert NV index.

### StorVSP / SCSI — `vm/devices/storage/{storvsp, storvsp_protocol, scsidisk, scsi_core, scsi_defs, scsi_buffers}`

**Responsibility.** The synthetic SCSI stack the VTL0 guest sees.
`storvsp` is the VMBus-facing controller (multi-worker, sub-channel
parallelism, version negotiation, sub-channel lifecycle); it delegates
each CDB to a `scsidisk::SimpleScsiDisk` (or `SimpleScsiDvd` for ATAPI)
that translates SCSI CDBs into `disk_backend::DiskIo` calls.
`storvsp_protocol` defines the wire format. `scsi_core`/`scsi_defs`/
`scsi_buffers` provide the shared SCSI types and request-buffer
abstractions. `#![forbid(unsafe_code)]`.

**Modules — `storvsp`.**

- [lib.rs](vm/devices/storage/storvsp/src/lib.rs) — `StorageDevice`
  (`VmbusDevice + SaveRestoreVmbusDevice`), `ScsiController`,
  `ScsiControllerDisk`. Multi-worker model with `FuturesUnordered`
  per-worker concurrency; poll-mode optimisation when pending I/O
  exceeds `poll_mode_queue_depth`.
- [resolver.rs](vm/devices/storage/storvsp/src/lib.rs) — `StorvspResolver`
  registered into `openvmm_hcl_resources`.
- [save_restore.rs](vm/devices/storage/storvsp/src/lib.rs) — Save/restore
  payload for live servicing.
- [ring/](vm/devices/storage/storvsp/src/lib.rs) — VMBus-ring helpers.
- [test_helpers.rs](vm/devices/storage/storvsp/src/lib.rs) (cfg(test) or
  feature `test`).

**Modules — `storvsp_protocol`.**

- [lib.rs](vm/devices/storage/storvsp_protocol/src/lib.rs) —
  `SCSI_INTERFACE_ID = ba6163d9-04a1-4d29-b605-72e2ffb1dc7f`,
  `IDE_ACCELERATOR_INTERFACE_ID = 32412632-86cb-44a2-9b5c-50d1417354f5`,
  protocol versions (`VERSION_WIN6 .. VERSION_THRESHOLD`),
  `OfferProperties`, the SCSI request/response packet shapes.

**Modules — `scsidisk`.**

- [lib.rs](vm/devices/storage/scsidisk/src/lib.rs) — `SimpleScsiDisk`:
  CDB parser, READ/WRITE (6/10/12/16), READ_CAPACITY, INQUIRY,
  MODE_SENSE, UNMAP, WRITE_SAME, SYNCHRONIZE_CACHE, PERSISTENT_RESERVE.
  Reports CAPACITY_DATA_CHANGED via UNIT_ATTENTION on disk resize.
- [atapi_scsi.rs](vm/devices/storage/scsidisk/src/lib.rs),
  [scsidvd.rs](vm/devices/storage/scsidisk/src/lib.rs) — DVD/ATAPI
  emulation (MMC commands, eject, media state).
- [getlbastatus.rs / inquiry.rs / reservation.rs / unmap.rs /
  resolver.rs](vm/devices/storage/scsidisk/src/lib.rs).

**Public API.** `StorageDevice`, `ScsiController`, `ScsiControllerDisk`,
`StorvspResolver`; `SimpleScsiDisk`, `SimpleScsiDvd`,
`SimpleScsiResolver`, `INQUIRY_DATA_TEMPLATE`; the protocol constants in
`storvsp_protocol`.

**External I/O.** VMBus channel offered as `SCSI_INTERFACE_ID` (or
`IDE_ACCELERATOR_INTERFACE_ID` for the IDE accelerator path), with
sub-channels offered after negotiation. SCSI CDBs in / data in/out via
GPADL ring pages.

**Paravisor use.** Registered: `storvsp::StorvspResolver` and
`scsidisk::SimpleScsiResolver` (always);
`disk_striped::StripedDiskResolver` (always);
`hyperv_ic::ShutdownIcResolver` for the shutdown IC; `disk_blockdevice`
and `NvmeDisk` are registered dynamically by `underhill_core` because
they have runtime dependencies (Linux block device fds and the NVMe
manager respectively).

**Trust.**

- **(b) VTL0 guest → VTL2:** This is one of the largest VTL0→VTL2 attack
  surfaces in the paravisor. CDBs and request buffers are guest-supplied
  and parsed entirely in software. `scsidisk` validates LBA ranges, UNMAP
  descriptor counts (`UNMAP_RANGE_DESCRIPTOR_COUNT_MAX = 4096`), and
  WRITE_SAME lengths (`VHDMP_MAX_WRITE_SAME_LENGTH_BYTES = 8 MiB`) before
  issuing them to the disk backend; unsupported CDBs return ILLEGAL_REQUEST
  rather than panicking. `storvsp`'s ring traversal uses the audited
  `MultiPagedRangeBuf`/`PagedRange` helpers from `guestmem`.

### NVMe controller emulator — `vm/devices/storage/{nvme, nvme_common, nvme_spec, nvme_resources}`

**Responsibility.** Full NVMe 2.0 controller emulator presented as a PCI
device with MMIO BAR0, MSI-X and admin + I/O queues. Used by the
paravisor only via VPCI in test or pass-through scenarios; the typical
production NVMe path on OpenHCL is host-physical NVMe consumed by the
`disk_nvme` user-mode driver below. `nvme_common` is the conversion layer
between SCSI-style PR semantics and NVMe reservations; `nvme_spec` is the
zerocopy/`open_enum` wire-format crate; `nvme_resources` is the
`MeshPayload` handle. `#![forbid(unsafe_code)]`.

**Modules — `nvme`.**

- [lib.rs](vm/devices/storage/nvme/src/lib.rs) — Re-exports
  `NvmeController`, `NvmeControllerCaps`, `NvmeControllerClient`,
  `NsidConflict`. Constants `MAX_DATA_TRANSFER_SIZE = 256 KiB`, `MAX_QES
  = 256`, `BAR0_LEN = 64 KiB`, vendor `0x1414`, `NVME_VERSION =
  0x0002_0000`.
- [pci.rs](vm/devices/storage/nvme/src/lib.rs) — PCI/MMIO BAR0/MSI-X
  layer (`NvmeController`).
- [workers/](vm/devices/storage/nvme/src/lib.rs) — Coordinator + admin
  worker + per-CQ I/O workers.
- [namespace.rs](vm/devices/storage/nvme/src/lib.rs) — Namespace
  lifecycle, capacity-change events.
- [prp.rs / queue.rs / error.rs / resolver.rs](vm/devices/storage/nvme/src/lib.rs).

**Modules — `nvme_common`.**

- [lib.rs](vm/devices/storage/nvme_common/src/lib.rs) — Bidirectional
  mappings between `disk_backend::pr` and `nvme_spec::nvm` reservation
  types, plus `from_nvme_reservation_report`.

**Modules — `nvme_spec` (`#![no_std]`).**

- [lib.rs](vm/devices/storage/nvme_spec/src/lib.rs) — Top-level
  `Register` enum, common bitfields.
- [nvm.rs](vm/devices/storage/nvme_spec/src/lib.rs) — NVM command set
  (READ/WRITE/FLUSH/DSM/PR), reservation types.

**Modules — `nvme_resources`.**

- [lib.rs](vm/devices/storage/nvme_resources/src/lib.rs) —
  `NvmeControllerHandle{subsystem_id, msix_count, max_io_queues,
  namespaces, requests}` and `NvmeControllerRequest::{AddNamespace,
  RemoveNamespace}`.
- [fault.rs](vm/devices/storage/nvme_resources/src/lib.rs) — Optional
  fault-injection configuration for testing.

**Public API.** `NvmeController`, `NvmeControllerCaps`,
`NvmeControllerClient`, `NsidConflict`; `nvme_spec::*`;
`NvmeControllerHandle`, `NvmeControllerRequest`.

**External I/O.** VPCI bus → MMIO BAR0 (registers + doorbells), MSI-X
interrupts, DMA via PRP lists into guest memory.

**Paravisor use.** `nvme::NvmeControllerResolver` registered when feature
`nvme` is enabled.

**Trust.**

- **(b) VTL0 guest → VTL2:** Doorbells, queue-entry contents, PRP lists,
  and admin commands are all guest-controlled. Queue-entry counts are
  capped at `MAX_QES = 256`; transfer size is capped at
  `MAX_DATA_TRANSFER_SIZE = 256 KiB`; PRP traversal uses
  `guestmem::ranges::PagedRange` (audited). Unsupported commands return
  NVMe error status rather than panicking; firmware update / multi-path
  / end-to-end PI are intentionally not implemented.

### Disk backends used by the paravisor — `vm/devices/storage/{disk_striped, disk_nvme, disk_blockdevice}`

**Responsibility.** Backends that satisfy the `disk_backend::DiskIo`
trait the SCSI/NVMe frontends call into. `disk_striped` aggregates
multiple lower disks into one striped disk. `disk_nvme` is the
**user-mode VFIO NVMe driver** that turns a host-physical NVMe namespace
into a `Disk` — this is the production storage path for OpenHCL.
`disk_blockdevice` is the Linux block-device backend (e.g. `/dev/sdX`),
registered dynamically by `underhill_core`. `#![forbid(unsafe_code)]`.

**Modules — `disk_striped`.**

- [lib.rs](vm/devices/storage/disk_striped/src/lib.rs) — `StripedDisk`,
  `StripedDiskResolver` (`declare_static_async_resolver!` registered into
  `openvmm_hcl_resources`); chunk size validated as a multiple of
  logical sector size; default 128 KiB chunks.

**Modules — `disk_nvme`.**

- [lib.rs](vm/devices/storage/disk_nvme/src/lib.rs) — `NvmeDisk`
  wrapping a `nvme_driver::NamespaceHandle`; `DiskIo` impl with vectored
  read/write that splits at `max_transfer_block_count`. Implements
  `pr::PersistentReservation` when the namespace advertises reservation
  support.
- Internal `nvme_driver` crate (under `vm/devices/storage/nvme_driver/`,
  not part of this section's surface but exercised via VFIO/IOMMU through
  `openhcl_dma_manager`).

**Modules — `disk_blockdevice`.**

- [lib.rs](vm/devices/storage/disk_blockdevice/src/lib.rs) — Linux block
  device backend (registered dynamically by `underhill_core`).

**Public API.** `StripedDisk`/`StripedDiskResolver`; `NvmeDisk`;
`disk_blockdevice::*` resolver.

**External I/O.** `disk_striped` consumes only other `Disk`s.
`disk_nvme` performs MMIO doorbell writes and DMA via the VFIO/IOMMU path
plumbed through `openhcl_dma_manager` and the host kernel's `vfio-pci`
binding (`/dev/vfio/*`). `disk_blockdevice` uses `io_uring`/`pread`/
`pwrite` against a Linux block device fd.

**Paravisor use.** Registered as above; `NvmeDisk` is added dynamically
through `nvme_manager`.

**Trust.**

- **(c) Hypervisor → VTL2 / hardware:** `disk_nvme` talks to physical
  hardware via VFIO; reservation-capability reporting is decoded by
  `nvme_common::from_nvme_reservation_report` with explicit
  `InvalidReservationType` errors rather than panics.
- **(b) VTL0 guest → VTL2:** Sector counts and offsets passed to
  `read_vectored`/`write_vectored` are validated by the SCSI/NVMe
  frontends before reaching the backend; backends additionally bound
  per-request transfer size (`max_transfer_block_count`).

### VPCI relay & client — `vm/devices/pci/{vpci, vpci_protocol, vpci_relay, vpci_client}`

**Responsibility.** The OpenHCL Virtual PCI stack:

- `vpci_protocol` is the wire format used over a VMBus channel to expose
  a virtual PCI bus to a guest (slot selection through MMIO page 0,
  config-space access through MMIO page 0x1000, MSI/MSI-X mapping
  messages, optional TDISP commands).
- `vpci` provides the `bus`/`bus_control`/`device` infrastructure for
  presenting an emulated VPCI bus to the guest.
- `vpci_client` is the **paravisor-side client** of a VPCI bus offered by
  the host: it consumes the host-offered VPCI bus on behalf of a
  pass-through device.
- `vpci_relay` is the OpenHCL-specific consumer that sits between the
  host VPCI bus and the guest-facing VPCI bus, filtering devices,
  remapping MMIO/MSI, and integrating the TDISP guest-to-host command
  translation through `openhcl_tdisp`.

`#![forbid(unsafe_code)]` everywhere.

**Modules — `vpci`.**

- [lib.rs](vm/devices/pci/vpci/src/lib.rs) — Re-exports `bus`,
  `bus_control`, `device`, `test_helpers`.
- [bus.rs](vm/devices/pci/vpci/src/lib.rs) — Virtual bus implementation
  serving the `vpci_protocol` over VMBus.
- [bus_control.rs](vm/devices/pci/vpci/src/lib.rs) — Bus-level control
  (device add/remove, power events).
- [device.rs](vm/devices/pci/vpci/src/lib.rs) — Per-device wrapper.

**Modules — `vpci_protocol`.**

- [lib.rs](vm/devices/pci/vpci_protocol/src/lib.rs) — `MessageType` enum,
  `SlotNumber`, MMIO page constants (`MMIO_PAGE_SLOT_NUMBER`,
  `MMIO_PAGE_CONFIG_SPACE`, `MMIO_PAGE_MASK`), `MsiResourceDescriptor2`,
  `MsiResourceRemapped`, `QueryResourceRequirementsReply`,
  `MAX_VPCI_TDISP_COMMAND_SIZE`, `VpciTdispCommand`.

**Modules — `vpci_relay`.**

- [lib.rs](vm/devices/pci/vpci_relay/src/lib.rs) — `VpciRelay`,
  `VpciRelayOptions{test_tdisp_flow}`,
  `VPCI_RELAY_MMIO_PER_DEVICE`, the `CreateMemoryAccess` trait,
  `RelayedDevice`/`AllowedDevice`. Pulls in `openhcl_tdisp`,
  `vmbus_client`, `vpci_client`.
- [linux_mmio.rs](vm/devices/pci/vpci_relay/src/lib.rs) (cfg(linux)) —
  Linux `/dev/mem`-style MMIO access used to relay the host's BAR
  mappings through.

**Modules — `vpci_client`.**

- [lib.rs](vm/devices/pci/vpci_client/src/lib.rs) — `VpciClient`,
  `VpciDevice`, `VpciDeviceEject`, `MemoryAccess`, `MMIO_SIZE`.
  Implements `MapVpciInterrupt` (for MSI/MSI-X) and the TDISP
  guest-to-host command transport (`TdispCommandResponse*` from
  `openhcl_tdisp`).

**Public API.** Re-exports above; `VpciClient` and `VpciRelay` are the
primary consumer entry points.

**External I/O.**

- VMBus channels exchanging `vpci_protocol` packets with the guest (or,
  in the relay's case, with the host).
- MMIO pages 0 (slot select) and `0x1000` (config space) per device.
- MSI/MSI-X register/unregister messages.
- TDISP commands routed through `openhcl_tdisp`.

**Paravisor use.** `vpci_relay::VpciRelay` is the production NVMe-via-
VPCI passthrough path; `vpci_client` is the building block it sits on
top of. The `vpci` emulator itself is mostly used in non-relay
scenarios.

**Trust.**

- **(a) Host/VMM → VTL2:** The relay consumes a host-offered VPCI bus —
  device IDs, capability lists, and BAR descriptors come from the host
  and must be filtered through the `AllowedDevice` list before exposure to
  the guest.
- **(b) VTL0 guest → VTL2:** Slot/config-space MMIO writes,
  MSI mapping requests, and TDISP commands are all guest-supplied.
  `MAX_VPCI_TDISP_COMMAND_SIZE` and `MMIO_PAGE_MASK` bound the request
  shapes; unknown messages return errors rather than panicking.
- **(c) Hypervisor → VTL2:** `dma_client` (from `openhcl_dma_manager`)
  and the VTOM offset (from `hcl`) gate physical-memory exposure for
  passthrough devices in CVMs.

### NVMe manager — `openhcl/underhill_core/src/nvme_manager`

**Responsibility.** Paravisor-only multi-threaded actor that owns all
user-mode VFIO NVMe drivers (`nvme_driver::NvmeDriver<VfioDevice>`),
serialises per-device operations through dedicated worker tasks,
coordinates concurrent cross-device operations, and supports save/restore
+ NVMe keep-alive across servicing. Exposes a `NvmeDiskResolver` so
`storvsp`/SCSI-frontends can resolve `(pci_id, nsid)` to a `Disk`.
Hosted inside `underhill_core` (Linux-only,
`#![forbid(unsafe_code)]`).

**Modules.**

- [mod.rs](openhcl/underhill_core/src/nvme_manager/mod.rs) — `NvmeDevice`
  trait (test-mockable), `NamespaceError`, `NvmeSpawnerError`.
- [manager.rs](openhcl/underhill_core/src/nvme_manager/manager.rs) —
  `NvmeManager` (coordinator), `NvmeManagerWorker` (registry actor with
  `Arc<RwLock<HashMap<String, NvmeDriverManager>>>`),
  `NvmeDriverManager` + `NvmeDriverManagerWorker` (per-device serialiser),
  `NvmeDiskResolver`, `NvmeDiskConfig`, `VfioNvmeDriverSpawner`.
- [device.rs](openhcl/underhill_core/src/nvme_manager/device.rs) —
  `VfioNvmeDevice` wrapping `nvme_driver::NvmeDriver<VfioDevice>` and
  implementing the `NvmeDevice` trait.
- [save_restore.rs](openhcl/underhill_core/src/nvme_manager/save_restore.rs),
  [save_restore_helpers.rs](openhcl/underhill_core/src/nvme_manager/save_restore_helpers.rs)
  — Servicing-time save/restore; supports NVMe keep-alive when
  `save_restore_supported = true`.

**Public API.** `NvmeManager`, `NvmeDiskResolver`, `NvmeDiskConfig`,
`NamespaceError`, `NvmeSpawnerError`, the `NvmeDevice` trait,
`VfioNvmeDriverSpawner`.

**External I/O.**

- `/dev/vfio/*`, `/sys/bus/pci/...` — VFIO/IOMMU bindings to host PCI
  NVMe devices.
- DMA via `openhcl_dma_manager::DmaClient` (CVM-aware).
- Doorbell MMIO writes and namespace I/O through the `nvme_driver` crate.

**Trust.**

- **(c) Hypervisor → VTL2:** Physical NVMe devices and IOMMU mappings are
  the trust root for I/O integrity. The lock-order discipline (`read()`
  first, `write()` only on create/remove, no nested locks across mesh
  RPC) is documented in the module to prevent deadlocks under concurrent
  guest add/remove storms.
- **(a) Host/VMM → VTL2:** PCI ID strings used to look up devices come
  from configuration delivered by the host through the GET; unknown IDs
  return `NvmeSpawnerError::Vfio` rather than panicking.
- **(b) VTL0 guest → VTL2:** Indirect — guest I/O reaches the manager
  through `storvsp` → `scsidisk` → `disk_nvme` → namespace handle.
  Idempotent `load_driver()` and graceful shutdown handle guest-driven
  attach/detach storms.
