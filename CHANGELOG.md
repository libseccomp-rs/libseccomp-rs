# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added

### Changed
- Re-fixed docs.rs build to make the `notify` module visible in the documentations by `doc_cfg`
feature.

### Removed

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
