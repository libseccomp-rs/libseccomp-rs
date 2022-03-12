# libseccomp-sys

[![Latest release on crates.io](https://img.shields.io/crates/v/libseccomp-sys.svg)](https://crates.io/crates/libseccomp-sys)
[![Documentation on docs.rs](https://docs.rs/libseccomp-sys/badge.svg)](https://docs.rs/libseccomp-sys)

Low-level bindings for the libseccomp library

The libseccomp-sys crate contains the raw FFI bindings to the
[libseccomp library](https://github.com/seccomp/libseccomp).

These low-level, mostly `unsafe` bindings are then used by the [libseccomp crate](https://crates.io/crates/libseccomp)
which wraps them in a nice to use, mostly safe API.
Therefore most users should not need to interact with this crate directly.

## Optional features

* `bundled`: Downloads, builds, and links the libseccomp library **statically**
  for you. Regarding the installed libseccomp version, see below for version
information. For more information on how this feature works, see the [README
for the libseccomp
crate](https://github.com/libseccomp-rs/libseccomp-rs#building-and-statically-linking-the-libseccomp-library-with-the-bundled-feature).


## Version information

See the file
[versions.rs](https://github.com/libseccomp-rs/libseccomp-rs/blob/main/libseccomp-sys/versions.rs).
Other versions may be built by using the environment variables mentioned above.
