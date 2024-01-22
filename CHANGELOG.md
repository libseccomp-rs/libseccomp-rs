# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Minimum Supported Rust Version (MSRV): 1.63
- `futex_waitv`, `set_mempolicy_home_node`, atmoic_barrier`,
  `atmoic_cmpxchg_32` and `getpagesize` syscalls for the `const-syscall` feature
- Support for `loongarch64`, `m68k`, `sheb` and `sh` architectures. Note that Rust has
  no support for `SuperH` so you can not use libseccomp-rs on such architectures.
  You can however create and export seccomp-bpf for them.
- `SeccompError::sysrawrc()` that queries the system's raw error code directly returned
  by `ScmpFilterAttr::ApiSysRawRc`.
- `const-syscall` support for loongarch64 and m68k
- `ScmpFilterContext::precompute`
- `ScmpFilterContext::get_ctl_waitkill` and `ScmpFilterContext::set_ctl_waitkill`
- `ScmpFilterAttr:CtlWaitkill`
- `SeccmopError::raw_ffi_value`

### Changed

#### Non-breaking
- `get_api_sysrawrc` and `set_api_sysrawrc` can now be used with any API level.
- `get_ctl_optimize` and `set_ctl_optimize` can now be used with any API level.
- Rust 2021 Edition
- updated `const-syscall` syscall definitions
- Some error messages

#### breaking, caught by compiler
- `ScmpFilterContext::{add,remove}_arch` return type changed to `Result<()>`.
  If you actually used the returned bool, call `ScmpFilterContext::is_arch_present` first.
- Rename `ScmpFilterContext::new_filter` to `ScmpFilterContext::new`.
- `ScmpFilterContext` methods support builder pattern.
- IO-Safety for `ScmpFilterContext::export_{bpf,pfc}`.

#### silent breaking, not caught by compiler
- Changed `check_version` logic not to fail even if the `major` version is greater than the specified version.
- Updated bitflags dependency to `~2.4.0`

### Removed
- Drop the libseccomp < 2.5.0 support.

## 0.3.0 - 2022-10-01
### Added
- `impl From<ScmpSyscall> for i32`
- `impl fmt::Display for ScmpSyscall`
- `impl PartialEq<i32> for ScmpSyscall` and `impl PartialEq<ScmpSyscall> for i32`
- `SeccompError::errno` + `SeccompErrno` to query the errno returned by the libseccomp API.
- `ScmpNotifResp::new_val()`, `ScmpNotifResp::new_error()` and `ScmpNotifResp::new_continue()`
- `ScmpNotifRespFlags`
- `const fn ScmpSyscall::new` (behind `const-syscall` feature)

### Changed
- Re-export `notify` module with private so that users can use the more convenient
structure (**Incompatible change**).
- `add_arch`/`remove_arch` return `Ok(false)` if the architecture was already
present/not present in the filter and `Ok(true)` if the architecture was really
added/removed (**Incompatible change**).
- `get_api` returns `u32` instead `Result<u32>` (**Incompatible change**).
- `ScmpArch::native()` panics instead of returning an error (**Incompatible change**).
- `ScmpNotifData.syscall` is now `ScmpSyscall` instead of `i32` (**Incompatible change**).
- Marked `ScmpNotifData`, `ScmpNotifReq` and `ScmpNotifResp` `#[non_exhaustive]` (**Incompatible change**).

### Deprecated
- `NOTIF_FLAG_CONTINUE` use `ScmpNotifRespFlags::CONTINUE.bits()` instead.

### Removed
- `Syscall` trait
- `get_native_arch()`
- `enum error::ErrorKind`
- `type error::Result`

### Fixed
- `scmp_cmp!`: `allow(unused_parens)` in `$mask`

## 0.2.3 - 2022-02-14
### Added
- `"SCMP_ARCH_MIPS64N32"` to `ScmpArch::from_str()`.
- `ScmpFilterContext::{get,set}_act_badarch()` to get/set the default action taken on a syscall for
an architecture not in the filter.
- `ScmpFilterContext::get_act_default()` to get the default action as specified in the call to
`new_filter()` or `reset()`.
- `ScmpFilterContext::get_ctl_nnp` (replaces `ScmpFilterContext::get_no_new_privs_bit`).
- `ScmpFilterContext::set_ctl_nnp` (replaces `ScmpFilterContext::set_no_new_privs_bit`).
- `ScmpFilterContext::{get,set}_ctl_log()` to get/set the state of the `ScmpFilterAttr::CtlLog`.
- `ScmpFilterContext::{get,set}_ctl_ssb()` to get/set the state of the `ScmpFilterAttr::CtlSsb`.
- `ScmpFilterContext::{get,set}_ctl_optimize()` to get/set the level of the `ScmpFilterAttr::CtlOptimize`.
- `ScmpFilterContext::{get,set}_api_sysrawrc()` to get/set the state of the `ScmpFilterAttr::ApiSysRawRc`.
- `ScmpFilterContext::{get,set}_ctl_tsync()` to get/set the state of the `ScmpFilterAttr::CtlTsync`.
- `reset_global_state()` to reset libseccomp's global state.
- `derive(Hash)` for the most types
- `ScmpSyscall` type
  - `ScmpSyscall::from_name()` (replaces `get_syscall_from_name`)
  - `ScmpSyscall::from_name_by_arch()` (replaces `get_syscall_from_name`)
  - `ScmpSyscall::from_name_by_arch_rewrite()` (new)
  - `ScmpSyscall::get_name()` (replaces `get_syscall_name_from_arch`)
  - `ScmpSyscall::get_name_by_arch()` (replaces `get_syscall_name_from_arch`)

### Changed

### Deprecated
- `get_syscall_from_name`, use `ScmpSyscall::from_name*()`
- `get_syscall_name_from_arch`, use `ScmpSyscall::get_name*()`
- `ScmpFilterContext::get_no_new_privs_bit`, use `ScmpFilterContext::get_ctl_nnp`.
- `ScmpFilterContext::set_no_new_privs_bit`, use `ScmpFilterContext::set_ctl_nnp`.

### Removed

## 0.2.2 - 2022-01-01
### Added
- Some more examples to function documentation.

### Changed
- Re-fixed docs.rs build to make the `notify` module visible in the documentations by `doc_cfg`
feature.

## 0.2.1 - 2021-12-31
### Changed
- Fixed docs.rs build to make the `notify` module visible in the documentations.

## 0.2.0 - 2021-12-31
### Added
- `ScmpVersion::current()` as rustified replacement for `get_library_version()`.
- `ScmpFilterContext::get_no_new_privs_bit()` to query the state of the No New Privileges bit.
- `ScmpArch::native()` as rustified replacement for `get_native_arch()`.
- `ScmpFilterContext::as_ptr()` to return a raw pointer to the `scmp_filter_ctx`.
- `scmp_cmp!` macro to create a `ScmpArgCompare` in a more elegant way.
- `impl From<&ScmpArgCompare> for scmp_arg_cmp`.
- `ScmpFilterContext::set_syscall_priority()` to set the priority of a given syscall.
- `ScmpFilterContext::add_rule_conditional()` to add a single rule for a conditional
action on a syscall.
- `ScmpFilterContext::add_rule_exact()` to add a single rule for an unconditional
action on a syscall.
- `ScmpFilterContext::add_rule_conditional_exact()`to add a single rule for a conditional
action on a syscall.
- `impl From<(u32, u32, u32)> for ScmpVersion`.
- `check_version()` to check that the libseccomp version being used is equal to
or greater than the specified version.
- `check_api()` to check that both the libseccomp API level and the libseccomp
version being used are queal to or greater than the specified API level and version.

### Changed
- `get_syscall_name_from_arch` and `get_syscall_from_name` output a syscall number with
an error message when the functions cannot resolve the syscall name.
- `ScmpAction::Trace` now holds an `u16` since you can not use any more bits anyway
(**Incompatible change**).
- `ScmpAction::Errno` now holds an `i32` to make `ScmpAction::Errno(libc::EPERM)`
  work without casting (**Incompatible change**).
- `ScmpArgCompare::new` is now a `const fn`.
- `ScmpFilterContext::export_{pfc,bpf}()` take all types which implement `AsRawFd`.
- `ScmpFilterContext::export_{pfc,bpf}()` take a `&mut` reference instead of consuming the ownership
(**Incompatible change**).
- `ScmpFilterContext::set_filter_attr()` takes `&mut self` rather than `&self` (**Incompatible change**).
- Fixed memory leak in `get_syscall_name_from_arch`.
- Made `ScmpArgCompare::new` to take only one `datum` (**Incompatible change**).
- Made `ScmpCompareOp::MaskedEqual` to contain the mask (**Incompatible change**).
- Implemented a debug trait for `SeccompError` by hand without the derive macro.
- The `libseccomp-sys` crate supports the libseccomp library v2.5.3.
- `ScmpFilterContext::add_rule()` does not take an `Option<&[ScmpArgCompare]>` argument
, use `ScmpFilterContext::add_rule_conditional()` (**Incompatible change**).
- Reworked the seccomp userspace notification APIs to be safer and easier to use them
(**Incompatible change**).

### Deprecated
- `get_library_version()` uses `ScmpVersion::current()` instead.
- `get_native_arch()` uses `ScmpArch::native()` instead.

### Removed
- `ScmpData` (was unused).
- `.to_native()` functions (**Incompatible change**).
- `Clone` on `ScmpFilterContext` because it causes double-free/use-after-free
in the safe code (**Incompatible change**).

### Security
- Fixed double-free/use-after-free when cloning `ScmpFilterContext`.
