---
name: model-checking
description: "Write, run, and debug Kani Rust verification harnesses for OpenVMM crates. Covers WSL setup, in-crate harness layout, common hangs (memchr/Drop/anyhow chains), the preferred `cfg(kani)`-gated `err_shim` wrapper for `anyhow`, the `tracing/max_level_off` Cargo feature for stripping `tracing` macros, the fallback `#[cfg(kani)]` sibling-function pattern, and how to read CBMC verbose output to diagnose why a proof never terminates."
---

# Kani Harness Authoring & Debugging Guide

[Kani](https://model-checking.github.io/kani/) is a bit-precise model
checker for Rust. It compiles your crate to a goto-program with CBMC
and proves that all reachable safety checks pass under all symbolic
inputs. This skill captures the lessons learned getting Kani to verify
non-trivial OpenVMM code (state machines, protocol parsers,
serialization round-trips) without timing out.

## When to load

- Adding a new `#[kani::proof]` harness to an existing crate.
- A previously-passing harness now hangs or times out.
- CBMC reports loop unwinding for thousands of iterations.
- Reachability count is unexpectedly large (hundreds of unrelated
  std/anyhow/parking_lot functions show up).
- Deciding whether to add a `#[cfg(kani)]` sibling function or to
  modify the harness instead.

## Prerequisites

- **Linux/WSL.** Kani 0.67.0 is Linux-only. Run from WSL on Windows hosts.
- **Kani install.** `cargo install --locked kani-verifier && cargo kani setup`
  on first use. Installs into `~/.kani/kani-<version>/`.
- **protoc on Linux.** Several OpenVMM crates depend on `prost`. The
  Windows protoc binary in `.packages/Google.Protobuf.Tools/tools/`
  doesn't run in WSL — install the Linux one:
  ```bash
  sudo apt-get install -y protobuf-compiler
  ```
  Every `cargo kani` invocation under WSL needs `PROTOC=/usr/bin/protoc`.
- **rust-version compatibility.** Kani bundles a pinned nightly toolchain
  (e.g. Kani 0.67.0 ships nightly-2025-11-21 which reports as rustc
  1.93.0-nightly). If the workspace `rust-version` in root `Cargo.toml`
  is *newer* than what Kani ships, cargo refuses to build. **Temporarily**
  downgrade `rust-version` for local Kani runs and **revert before
  committing** (or commit a separate `[workspace.metadata.kani]` config
  that pins differently — check the Kani docs for the latest mechanism).
- **`cfg(kani)` in check-cfg.** Add `cfg(kani)` to the workspace
  `unexpected_cfgs` lint allowlist in root `Cargo.toml`:
  ```toml
  [workspace.lints.rust]
  unexpected_cfgs = { level = "warn", check-cfg = ["cfg(kani)"] }
  ```
  Otherwise every `#[cfg(kani)]` triggers a clippy warning under normal
  builds.

## Recommended crate layout

Place harnesses **inside the crate**, gated by `cfg(kani)`:

```rust
// src/lib.rs
#[cfg(kani)]
mod kani_proofs;
```

```rust
// src/kani_proofs.rs
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn verify_my_property() { ... }
}
```

Why in-crate:

- A child module has access to all `pub(crate)`/private fields and
  methods. No visibility changes needed in production code.
- `cargo build` and `cargo test` compile right past it (the module
  contents are excluded by `cfg(kani)` for non-Kani builds).
- Clippy and `cargo doc` ignore it for normal targets.

## Running a single harness

Use a shell script written to disk (PowerShell variable expansion
mangles long Linux command lines):

```powershell
@'
#!/bin/bash
cd /mnt/c/path/to/openvmm/<crate-dir> || exit 1
export PATH=/home/<user>/.cargo/bin:$PATH
PROTOC=/usr/bin/protoc cargo kani \
  --harness <harness_name> \
  --verbose > /tmp/kani_out.txt 2>&1
echo "EXIT=$?"
tail -20 /tmp/kani_out.txt
'@ | Out-File -FilePath C:\path\to\openvmm\run_kani.sh -Encoding ASCII -NoNewline
wsl -d Ubuntu bash /mnt/c/path/to/openvmm/run_kani.sh
```

Always pass `--harness <name>` to verify one harness at a time. Running
all harnesses in a crate with one command makes failures hard to
attribute and burns time on harnesses you didn't change.

Key flags:

- `--verbose` — emit reachability stats, loop unwinding, and the CBMC
  command line. Essential when diagnosing hangs.
- `--harness <name>` — verify a single harness. Always use this.
- `--unwind <N>` — global unwind bound override. Prefer per-harness
  `#[kani::unwind(N)]` instead.
- `--solver <kissat|cadical|minisat>` — try a different SAT backend if
  the default (cadical) is slow. Rarely the actual fix — usually the
  problem is reachability bloat, not solver choice.
- `--default-unwind <N>` — fallback unwind for loops without explicit
  `kani::unwind`.

## A successful proof looks like this

```
SUMMARY:
 ** 0 of 31321 failed (1996 unreachable)

VERIFICATION:- SUCCESSFUL
Verification Time: 13.83s
```

A normal "small" harness on OpenVMM-style code typically generates
30,000–40,000 CBMC checks in 10–15 seconds. The `unreachable` count
indicates how many checks were dead-code eliminated — high is fine.

## Anti-patterns that cause hangs

### 1. `anyhow::anyhow!(...)` anywhere on a reachable path

Even with a literal-only message:

```rust
return Err(anyhow::anyhow!("bad input"));
```

expands to `anyhow::__private::format_err(...)` which constructs an
`anyhow::Error::msg(...)` which calls `std::backtrace::Backtrace::capture()`
which calls `std::env::var("RUST_BACKTRACE")` which calls libc `getenv`
which returns a C string that the std needs to find the NUL terminator
of via `core::slice::memchr::memchr_naive`.

**CBMC unwinds `memchr_naive` thousands of times** searching for a fixed
point on a symbolic-length C string. Verification never terminates.

This happens **even when your harness `kani::assume`s the success path**
because assumptions are runtime constraints on the SAT formula, not
compile-time pruning of MIR. CBMC's reachability analysis includes
every branch of every reachable function before SAT solving begins.

#### Preferred fix: a `cfg(kani)`-gated `err_shim` module

Wrap `anyhow` behind a tiny crate-local module that re-exports the
real types under non-Kani builds and a unit-error stub under Kani.
The production call sites remain syntactically unchanged — they just
say `crate::Result<T>`, `crate::err!(...)`, `.context("...")` — and
no Kani-only sibling functions are needed.

Add this near the top of the crate's `lib.rs`:

```rust
#[cfg(not(kani))]
mod err_shim {
    pub use anyhow::Context;
    pub use anyhow::Error;
    pub use anyhow::Result;

    /// Forwards to [`anyhow::anyhow!`].
    #[macro_export]
    macro_rules! err {
        ($($t:tt)*) => { ::anyhow::anyhow!($($t)*) };
    }
}

#[cfg(kani)]
mod err_shim {
    /// Kani stand-in for [`anyhow::Error`]. Constructed without
    /// `Backtrace::capture` / `getenv` / `memchr_naive`.
    #[derive(Debug)]
    pub struct Error;

    /// Kani stand-in for [`anyhow::Result`]. Like `anyhow::Result`,
    /// the error type defaults to [`Error`] but can be overridden so
    /// that signatures like `Result<(), MyEnum>` continue to type-check.
    pub type Result<T, E = Error> = core::result::Result<T, E>;

    /// Kani stand-in for [`anyhow::Context`]. Discards the message
    /// (which is diagnostic-only) and erases the inner error type.
    pub trait Context<T, E> {
        fn context<C>(self, ctx: C) -> Result<T>;
    }

    impl<T, E> Context<T, E> for core::result::Result<T, E> {
        fn context<C>(self, _ctx: C) -> Result<T> {
            self.map_err(|_| Error)
        }
    }

    /// Forwarding macro for [`anyhow::anyhow!`] — discards arguments
    /// (no formatting evaluated, no `core::fmt` or `memchr` chain
    /// dragged in) and yields a bare [`Error`].
    #[macro_export]
    macro_rules! err {
        ($($t:tt)*) => {{ $crate::Error }};
    }
}

pub use err_shim::Context;
pub use err_shim::Error;
pub use err_shim::Result;
```

Then sweep the crate:

- `anyhow::Result<T>` → `crate::Result<T>` on **internal helpers**.
- `anyhow::anyhow!(...)` → `crate::err!(...)`.
- `use anyhow::Context;` → `use crate::Context;` (or just rely on the
  re-export via the prelude pattern of your choice).
- `Foo(anyhow::Error)` enum variants → `Foo(crate::Error)`.

**Important constraints:**

- **Keep `Result<T, E = Error>` with the default-param**, mirroring
  `anyhow::Result`. Without it, signatures like
  `Result<(), TdispGuestOperationError>` fail to type-check under Kani.
- **Do not change public trait signatures** that external crates
  implement. Trait methods returning `anyhow::Result<()>` must keep
  that exact signature so out-of-crate impls still compile. Only
  `crate::Result` the internal helpers and error-variant payloads.
- **Do not reference macro arguments inside the Kani arm** of the
  `err!` macro. Even something innocent like `let _ = ($(&$t,)*);`
  makes the compiler treat literals like `"foo: {}"` as expressions,
  which breaks invocations of the form `err!("msg: {:?}", x)` where
  the format-string syntax is not a valid expression. The
  `($($t:tt)*) => {{ $crate::Error }}` form discards the tokens at
  parse time without evaluating them.

**What this preserves and abstracts:**

- ✅ Production call sites unchanged in shape — same control flow,
  same error-propagation operators, same `?` chaining, same `.context`.
- ✅ Same external API. The harness can call the **production**
  entry point directly; no sibling needed.
- ✅ `Result<T, E>` shape preserved including non-default `E`.
- ❌ Error message content discarded under Kani. Acceptable because
  the property under proof inspects `is_ok()` / `is_err()` (and the
  outer integer error code emitted to clients), not the message.
- ❌ No backtrace under Kani. Always true — Kani does not run.

**Verified working on `tdisp`:** the `verify_bind_without_negotiated_protocol_fails`
harness exercises the production
`TdispHostDeviceTarget::tdisp_handle_guest_command` API on a
fully-constructed `TdispHostDeviceTargetEmulator`. With the `err_shim`
applied (and the `tracing` `max_level_off` feature gated on `cfg(kani)`),
CBMC verifies 35,483 checks in ~16s with `VERIFICATION SUCCESSFUL`.
Without the shim, the same harness times out at 900s.

##### Watch out: `anyhow::Error` in struct/enum fields bypasses the shim

The `err_shim` only redirects the `anyhow` *paths your code names*
(`anyhow::Result`, `anyhow::Error`, `anyhow!`). A type that **stores**
`anyhow::Error` inline — e.g.

```rust
pub enum TdispUnbindReason {
    Unknown(anyhow::Error),                  // ← real anyhow!
    ImpossibleStateTransition(anyhow::Error), // ← real anyhow!
    ...
}
```

— still drags the real `anyhow::Error` into the goto-program through
its `Drop` impl, which in turn pulls in `Box<dyn Error + Send + Sync>`,
`std::io::Error`, and `repr_bitpacked::decode_repr`. CBMC then unwinds
those drops for hundreds of iterations and the harness times out even
though every *call site* in your code uses `crate::Result`.

**Symptom (verbose CBMC output):**

```
Unwinding recursion std::ptr::drop_in_place::<std::io::Error> iteration 168
Unwinding recursion <std::io::error::repr_bitpacked::Repr as std::ops::Drop>::drop iteration 168
Unwinding recursion std::ptr::drop_in_place::<std::boxed::Box<std::io::error::Custom>> iteration 168
```

(climbing without bound — never reaches `run_cbmc`).

**Fix:** also rewrite the field types to `crate::Error`:

```rust
pub enum TdispUnbindReason {
    Unknown(crate::Error),
    ImpossibleStateTransition(crate::Error),
    ...
}
```

Outside `cfg(kani)`, `crate::Error` re-exports `anyhow::Error` so the
public API is unchanged. Under `cfg(kani)`, it becomes the unit-stub
`err_shim::Error` and the `Drop` chain disappears.

**Verified on `tdisp`:** `verify_unbind_does_not_change_protocol`
timed out at 300s (still in symex, hundreds of `Drop` unwind
iterations) until the two `anyhow::Error` variants in
`TdispUnbindReason` were switched to `crate::Error`. After the
switch: 3.3s, `VERIFICATION SUCCESSFUL`.

##### Watch out: trait impls in `cfg(kani)` modules must use `crate::Result`

If a helper module (e.g. `test_helpers.rs`) is compiled under
`cfg(kani)` and contains an `impl SomeTrait for Foo` whose trait
signature uses `crate::Result<T>`, the impl must also use
`crate::Result<T>` — **not** `anyhow::Result<T>`. Under `cfg(kani)`
the two are different concrete types (`err_shim::Error` vs
`anyhow::Error`) and the impl will fail with `E0053: method has an
incompatible type for trait`.

If the impl is only ever used by non-Kani code, the cleanest fix is to
gate the whole impl on `#[cfg(not(kani))]` and keep it on
`anyhow::Result` — there is no need for it under Kani at all.

#### Fallback fix: the `#[cfg(kani)]` sibling-function pattern

Use this only when the wrapper approach is infeasible — for example
when the production function uses many other heavy primitives (panics,
allocators, vtables) that the wrapper cannot abstract, or when the
function is short enough that an inline copy is clearly easier to
audit than the production's shape.

```rust
fn transition_state_to(&mut self, new: State) -> anyhow::Result<()> {
    if !self.is_valid_transition(&new) {
        return Err(anyhow::anyhow!("invalid"));
    }
    self.current = new;
    Ok(())
}

#[cfg(kani)]
fn transition_state_to_kani(&mut self, new: State) -> Result<(), ()> {
    // Line-by-line copy of the meaningful logic. Same gatekeeper call,
    // same mutation, same "no mutation on failure" guarantee.
    if !self.is_valid_transition(&new) {
        return Err(());
    }
    self.current = new;
    Ok(())
}
```

The harness calls the sibling. **Document the equivalence** in a doc
comment so reviewers know what's preserved and what's abstracted away:

- ✅ Same gatekeeper / decision predicate.
- ✅ Same state mutation on success.
- ✅ Same "no mutation on failure" guarantee.
- ✅ Same `Ok` vs `Err` shape (the property under proof never inspects
  the `Err` payload).
- ❌ Different error type (`()` vs `anyhow::Error`). Acceptable because
  the property doesn't depend on the payload.
- ❌ No tracing / no history recording in the sibling. Verify each as
  an independent property in its own harness if needed.

The downside vs the wrapper approach: every behavioural change in the
production function must be hand-mirrored into the sibling, and the
proof loses tightness against the *real* function. Prefer the wrapper
unless you have a specific reason not to.

### 2. `unwrap()` / `expect()` / `panic!()` on a reachable path

Each panic site pulls in `addr2line`, `gimli`, full backtrace
infrastructure, and string formatting. Even a simple
`Option::unwrap()` adds thousands of CBMC checks via the panic
machinery.

**Symptom:** `aborting path on assume(false) at ...gimli...` lines in
verbose output, plus reachability counts >5,000 functions for trivial
harnesses.

**Fix:** replace `kani::any::<i32>().abs() as usize % N` +
`from_i32().unwrap()` with a **bounded index pattern**:

```rust
let i: u8 = kani::any();
kani::assume(i < 3);
let v = match i {
    0 => MyEnum::A,
    1 => MyEnum::B,
    _ => MyEnum::C,
};
```

`kani::assume(i < 3)` constrains the SAT formula directly; the `match`
is exhaustive so the compiler never inserts a panic.

### 3. `Vec::push` on a Vec without `with_capacity`

`Vec::push` may need to grow the backing buffer, which calls
`GlobalAlloc::alloc`. CBMC models the global allocator including
free-list traversal — expensive.

**Fix #1:** if the cap is bounded, use `Vec::with_capacity(MAX)` so no
reallocation ever happens.

**Fix #2:** if the Vec is incidental to the property under test, guard
its mutation with `#[cfg(not(kani))]` and verify the cap invariant in a
separate, focused harness:

```rust
#[cfg(not(kani))]
{
    if self.history.len() == HISTORY_LEN {
        self.history.remove(0);
    }
    self.history.push(self.current);
}
```

```rust
// Separate harness, focused on the ring-buffer logic only.
#[kani::proof]
#[kani::unwind(13)]
fn verify_history_cap_invariant() {
    let mut v: Vec<u8> = Vec::with_capacity(HISTORY_LEN);
    for _ in 0..(HISTORY_LEN + 2) {
        if v.len() == HISTORY_LEN { v.remove(0); }
        v.push(kani::any());
        assert!(v.len() <= HISTORY_LEN);
    }
}
```

### 4. `Drop` chain on `Arc<Mutex<dyn Trait>>` fields

CBMC's reachability includes implicit `Drop` calls at end of scope.
Dropping an `Arc<Mutex<dyn TraitObject>>` walks the vtable to find
`drop_in_place`, then drops the trait object, then frees the heap
allocation.

For OpenVMM-style state machines holding an
`Arc<Mutex<dyn HostInterface>>`, this can balloon reachability from
~100 to ~9,500 functions.

**Fix:** end the harness with `core::mem::forget(machine)`.

```rust
#[kani::proof]
fn verify_property() {
    let mut machine = new_kani_machine();
    // ... symbolic setup, function call, assertions ...
    core::mem::forget(machine);
}
```

This is sound when `Drop` is not part of the property under proof
(which is almost always the case for state-machine correctness
harnesses). The Kani harness process is short-lived; OS reclaims memory.

### 5. `#[instrument]` on the function under test

The `tracing::instrument` macro wraps the entire function body in a
tracing span constructor. That pulls in atomic loads, global dispatch
state, lazy-static initialization, and string formatting.

**Preferred fix (whole crate, one knob):** strip every `tracing` macro
at compile time via the crate's `Cargo.toml` so CBMC never sees the
expansion at all:

```toml
[target.'cfg(kani)'.dependencies]
tracing = { workspace = true, features = ["max_level_off"] }
```

This activates when (and only when) `cargo kani` adds `--cfg kani`.
`tracing`'s `max_level_off` feature is additive across the dep graph,
so every `tracing::info!`/`error!`/`instrument!` site collapses to a
no-op AST. **No source-code edits required.**

**Fallback per-site fix:** if for some reason you cannot use the
crate-level feature (e.g., another dep in the same Kani build needs
`tracing` enabled), guard each attribute and macro by hand:

```rust
#[cfg_attr(not(kani), instrument(fields(device_id = %self.id), skip(self)))]
fn transition(&mut self, ...) -> ... { ... }
```

### 6. `tracing::info!` / `tracing::error!` calls

Same root cause as #5 — every macro site pulls in event dispatch and
formatting machinery, and the `?val` Debug-formatting argument drags
in the `core::fmt` chain (which itself reaches `memchr`).

**Preferred fix:** the same `tracing/max_level_off` feature gate from
#5 strips these too. Apply once per crate; do not write per-site
`#[cfg(not(kani))]` guards.

**Fallback per-site fix** (only when the feature gate is unavailable):

```rust
#[cfg(not(kani))]
tracing::info!("transitioning from {:?} to {:?}", self.current, new);
```

### 7. Calling production functions through `parking_lot::Mutex::lock()`

The vtable dispatch on `dyn TraitObject::lock()` and the parking_lot
internals (atomic ops, futex paths, condition variables) all become
reachable.

**Fix:** if the harness doesn't actually need to test the lock
behavior, construct the state machine and **set the post-negotiation
fields directly** instead of calling through the trait method:

```rust
fn new_direct_machine() -> StateMachine {
    let iface: Arc<Mutex<dyn HostInterface>> = Arc::new(Mutex::new(MockIface));
    let mut m = StateMachine::new(iface);
    // Set directly — no .lock() call, no vtable dispatch.
    m.guest_protocol_type = ProtocolType::Foo;
    m
}
```

### 8. Symbolic-length `Vec<u8>` input (heap-allocation modeling)

A common parser harness pattern is:

```rust
let len: usize = kani::any();
kani::assume(len <= 256);
let data: Vec<u8> = (0..len).map(|_| kani::any::<u8>()).collect();
let result = parse(&data);
```

This drags `Vec::with_capacity_in`, `RawVecInner::finish_grow`,
`Layout::repeat`, and `handle_alloc_error` into reachability. With
symbolic `len`, CBMC must model the allocation at every possible
size, which is intractable.

**Fix:** use a **fixed-size stack array with a symbolic prefix length**:

```rust
const BUF_LEN: usize = 64;
let buf: [u8; BUF_LEN] = kani::any();
let len: usize = kani::any();
kani::assume(len <= BUF_LEN);
let data = &buf[..len];
let result = parse(data);
```

CBMC models a fixed-size array (no allocation) and the slice is just a
fat pointer with symbolic length. Works for any parser that takes
`&[u8]`.

### 9. `prost` (or other serializer) `encode_to_vec` with symbolic input

Round-trip harnesses like `decode(encode(&value))` are tempting but
hit a wall: `encode_to_vec` returns a `Vec<u8>` with symbolic length,
which drags the full heap-allocation tree into reachability:

- `prost::alloc::raw_vec::RawVecInner::with_capacity_in`
- `prost::alloc::raw_vec::RawVecInner::finish_grow`
- `prost::alloc::raw_vec::handle_error`
- `std::alloc::handle_alloc_error`

With symbolic `device_id` (or any other symbolic numeric field), the
varint encoder produces a symbolic-length output. CBMC cannot
terminate.

**Fix:** descope the symbolic round-trip to a **concrete round-trip**:

```rust
// Was: let device_id: u64 = kani::any(); kani::assume(device_id < 256);
// Is:  pin to a single concrete value
let device_id: u64 = 42;
let original = MyMessage { device_id, ... };
let bytes = encode(&original);
let decoded = decode(&bytes);
assert!(decoded.is_ok());
// ... field-equality assertions
```

This still proves: serializer doesn't panic, deserializer doesn't
panic on the encoded bytes, field values survive a round-trip — for
**that one input**. The full symbolic property is more naturally
covered by `cargo test` (or property-testing with `proptest`/`quickcheck`).

Document the descope explicitly in the harness doc comment.

### 10. Module-level free-function siblings (not just impl methods)

Sibling functions don't have to live in `impl` blocks. For free
functions exposed at module level (parsers, validators), add the
sibling at module level:

```rust
// production
pub fn validate_thing(x: &Thing) -> anyhow::Result<()> {
    if !x.ok() { return Err(anyhow::anyhow!("...")); }
    Ok(())
}

// sibling, also at module level
#[cfg(kani)]
pub fn validate_thing_kani(x: &Thing) -> Result<(), ()> {
    if !x.ok() { return Err(()); }
    Ok(())
}
```

The harness imports and calls `validate_thing_kani` instead of
`validate_thing`. Same equivalence-justification doc-comment template
applies.

## Diagnostic workflow when a harness hangs

### Step 1: write a concrete smoke test first

Before adding symbolic inputs, prove the function is even reachable
with concrete values:

```rust
#[kani::proof]
fn smoke_test() {
    let mut machine = new_kani_machine();
    let r = machine.do_thing(ConcreteInput::Foo);
    assert!(r.is_ok());
    core::mem::forget(machine);
}
```

If concrete passes (in 10–15s) and symbolic hangs → input-explosion.
Fix: tighten `kani::assume` bounds, switch to bounded-index pattern,
or split the property into smaller harnesses.

If concrete also hangs → the reachability set itself is too large.
Fix: hunt down the anti-patterns above.

### Step 2: run with `--verbose` and capture to a file

```bash
PROTOC=/usr/bin/protoc cargo kani \
  --harness <name> --verbose > /tmp/kani.txt 2>&1
```

Don't try to read it live — it's tens of thousands of lines. Capture to
a file and grep.

### Step 3: read the reachability summary

Look for the section right after `Reachability Analysis Result`:

```
Total # items: 9484
Total # statements: 154859
Total # expressions: 41377
```

| Item count | Interpretation |
|---|---|
| < 200 | Trivial — proof should solve in seconds |
| 200–1000 | Normal for a small focused harness |
| 1000–3000 | Watch out — likely pulling in std formatting / panic |
| > 3000 | Almost always a problem — anyhow / Arc<Mutex<dyn>> / instrument |

If the number is high, grep the verbose log for unrelated crate names
to find the culprit:

```bash
grep -oE '[a-z_]+::[a-z_]+::[a-z_]+' /tmp/kani.txt \
  | sort -u | head -50
```

Common red flags:

- `anyhow::__private::format_err` → see anti-pattern #1
- `addr2line::*`, `gimli::*` → panic / backtrace machinery (anti-pattern #2)
- `parking_lot::*::lock` → vtable / lock modeling (anti-pattern #7)
- `std::backtrace::Backtrace::capture` → backtrace machinery
- `std::env::var` → environment variable parsing (often via backtrace)
- `prost::alloc::raw_vec::*`, `Layout::repeat`, `handle_alloc_error` →
  serializer growing a `Vec<u8>` with symbolic capacity (anti-pattern
  #9). Combined with `aborting path on assume(false) at ...
  raw_vec::handle_error ...`.

### Step 4: look for `Unwinding loop` lines

```
Unwinding loop _RNvNtNt...memchr_naive iteration 3700 ...
```

If you see iteration counts in the thousands for the same loop, CBMC
can't bound that loop and is unwinding it open-endedly. That loop will
never finish.

The most common offender for OpenVMM is `core::slice::memchr::memchr_naive`,
which means something is parsing a C string with symbolic length —
almost always `getenv` via `Backtrace::capture` via `anyhow::anyhow!`
(see anti-pattern #1).

For your own bounded loops, add `#[kani::unwind(N)]` where `N` is the
iteration cap + 1 (CBMC needs +1 for the loop-bound assertion check).

### Step 5: identify which compilation phase is hanging

The verbose log labels each stage:

```
Finished codegen reachability analysis in 1.05s
Finished goto-cc in 13.32s
Finished goto-cc in 12.45s
Finished goto-instrument in 18.08s
Finished goto-instrument in 14.53s
Finished goto-instrument in 16.48s
Checking harness ...
[Kani] Running: cbmc --no-malloc-may-fail ... --sat-solver cadical ...
CBMC 6.8.0 (cbmc-6.8.0)
```

| Stage | Typical duration | If this hangs |
|---|---|---|
| codegen reachability | < 5s | Crate is huge — check for cyclic/over-broad reachability |
| goto-cc | 10–20s each | Normal; rarely the issue |
| goto-instrument | 10–20s each | Normal; rarely the issue |
| CBMC SAT solving | seconds to ∞ | This is where memchr unwinding shows up |

If you reach `CBMC 6.8.0` but get no further output, it's the SAT
solver spinning on a too-large formula — go back to step 3 and shrink
reachability.

## Pattern: the `cfg(kani)`-gated wrapper module (PREFERRED)

When the production function uses heavy machinery on its error path
(`anyhow`, `tracing`) but the property under test does not depend on
the message text or the backtrace, **wrap the heavy crate behind a
crate-local module that swaps in a unit-error stub under Kani**.
Production call sites stay syntactically and semantically unchanged;
the harness verifies the *real* function.

See **anti-pattern #1** above for the full `err_shim` template, the
required call-site sweep, and the constraints (preserve
`Result<T, E = Error>`'s default param; do not change public trait
signatures; do not reference macro args inside the Kani arm of `err!`).

For `tracing`, the equivalent wrapper is the `cfg(kani)`-gated
`max_level_off` Cargo feature — see **anti-patterns #5 and #6**.

This is the preferred approach because:

- The harness exercises the **production function**, not a sibling.
  Behaviour drift between production and verified code is impossible.
- A single `err_shim` module covers every error-construction site in
  the crate. No per-function maintenance burden.
- Adding a new error-returning helper requires no Kani-specific work
  unless the helper introduces a *new* anti-pattern.

## Pattern: the `#[cfg(kani)]` sibling function (FALLBACK)

Use this only when the wrapper approach is infeasible — for example
when the production function calls multiple heavy primitives that the
wrapper cannot abstract (panics, allocators, vtable dispatch through
`Arc<Mutex<dyn>>`, serializer with symbolic input), or when the
function is short enough that a hand-mirrored copy is clearly easier
to audit than the production's shape.

Template:

```rust
/// Production function — full error context for runtime users.
fn do_thing(&mut self, input: Input) -> anyhow::Result<()> {
    if !self.is_valid(&input) {
        return Err(anyhow::anyhow!("invalid input: {:?}", input));
    }
    self.state = input.into();
    Ok(())
}

/// Kani-only sibling of [`do_thing`].
///
/// # Why this exists
/// The production function pulls in heavy machinery (X, Y, Z) that
/// the crate's `err_shim` wrapper cannot abstract because [reason].
/// This sibling mirrors the security-critical decision logic only.
///
/// # What this preserves
/// - Same `is_valid(&input)` gatekeeper call.
/// - Same `self.state = input.into()` mutation on success.
/// - Same "no mutation on failure" guarantee.
/// - Same `Ok` vs `Err` shape.
///
/// # What this abstracts
/// - Error payload: `()` instead of `anyhow::Error`. The harness
///   only inspects `is_ok()` / `is_err()`, never the payload.
/// - No tracing emission (informational only, no control-flow
///   effect).
#[cfg(kani)]
fn do_thing_kani(&mut self, input: Input) -> Result<(), ()> {
    if !self.is_valid(&input) {
        return Err(());
    }
    self.state = input.into();
    Ok(())
}
```

The harness calls `do_thing_kani`. The doc comment is the audit trail.
**Caveat:** every behavioural change to `do_thing` must be hand-mirrored
into `do_thing_kani`, and the proof loses tightness against the real
function. Prefer the wrapper approach unless you have a specific reason
not to.

## Pattern: split one harness into focused sub-harnesses

A single big harness asserting many properties is harder for CBMC than
the same properties verified by separate harnesses.

Example refactor of one "everything" harness about a state-transition
function:

| Sub-harness | Property |
|---|---|
| `verify_..._success_postcondition` | Valid pair → state updated |
| `verify_..._error_no_state_change` | Invalid pair → state unchanged |
| `verify_..._concrete_smoke` | Diagnostic; concrete values; reachability sanity check |
| `verify_..._history_cap_invariant` | Ring buffer never exceeds cap (independent of state machine) |

Each runs in 1–15s. If one regresses, you know exactly which property
broke.

## Pre-commit checklist for Kani changes

After any change to a `#[cfg(kani)]` block or a function it calls:

1. **Re-run all affected harnesses** one at a time:
   ```bash
   PROTOC=/usr/bin/protoc cargo kani --harness <name>
   ```
2. **Revert temporary `rust-version` downgrade** in workspace
   `Cargo.toml` (if you applied one to satisfy Kani's pinned nightly).
3. **Run the standard pre-commit checklist** for each modified package
   (`cargo clippy --all-targets -p <pkg>`, `cargo doc --no-deps -p <pkg>`,
   `cargo nextest run --profile agent -p <pkg>`, `cargo xtask fmt --fix`).
   `#[cfg(kani)]` code is invisible to clippy/doc/tests under default
   builds, but the *production* code surrounding it is checked.

## Gotcha: prost-generated Rust enum variant names

When writing harnesses that construct prost-generated enum values
symbolically (e.g., for protobuf message types), **do not assume the
Rust variant names match the spec / wire names**. prost converts:

| Source `.proto` (SCREAMING_SNAKE_CASE) | Generated Rust variant (PascalCase) |
|---|---|
| `TDISP_REPORT_TYPE_INVALID` | `Invalid` |
| `TDISP_REPORT_TYPE_GUEST_DEVICE_ID` | `GuestDeviceId` |
| `TDISP_REPORT_TYPE_INTERFACE_REPORT` | `InterfaceReport` |
| `TDISP_REPORT_TYPE_CERTIFICATE_CHAIN` | `CertificateChain` |

Always check the actual `.proto` source for the canonical list of
variants before writing the bounded-index `match`. The Rust generated
file (`OUT_DIR/<crate>.tdisp.rs`) is also a reliable reference.

A typo in a variant name shows up as a clean `cargo check` failure
like:

```
error[E0599]: no variant or associated item named `MmioInterfaceInfo`
found for enum `TdispReportType` in the current scope
```

Fix once and re-run.

## Reference: TDISP harnesses

For a working example of all the patterns above, see:

- `vm/devices/tdisp/src/kani_proofs.rs` — eleven-plus harnesses
  covering state-transition correctness, error guards, and serialization
  round-trips. Demonstrates the sibling-function pattern, `mem::forget`
  Drop avoidance, bounded enum index pattern, and ring-buffer cap
  verification split.
- `vm/devices/tdisp/src/lib.rs` — the `#[cfg(kani)] fn
  transition_state_to_kani(...)` sibling next to the production
  `transition_state_to`.
- `vm/devices/tdisp_proto/src/kani_proofs.rs` — round-trip and
  exhaustive enum coverage harness for protocol error codes.

## Further reading

- [Kani tutorial](https://model-checking.github.io/kani/kani-tutorial.html)
- [Kani reference](https://model-checking.github.io/kani/reference/)
- [Kani limitations](https://model-checking.github.io/kani/limitations.html) —
  especially the sections on unbounded loops, recursive types, and
  concurrency.
- [CBMC manual](https://www.cprover.org/cbmc/) — for understanding the
  goto-program model and unwinding semantics.
