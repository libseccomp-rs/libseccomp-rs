# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- `ScmpArgCompare::new` is now a `const fn`.

### Changed
- `ScmpAction::Errno` now holds an `i32` to make `ScmpAction::Errno(libc::EPERM)`
  work without casting.
- `ScmpAction::Trace` now holds an `u16` since you can not use any more bits anyway.

### Removed
- `Clone` on `ScmpFilterContext` because it cauesed double-free/use-after-free
   in safe code.

### Security
- Fixed double-free/use-after-free when cloning `ScmpFilterContext`.
