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

* `bundled`: Downloads and builds libseccomp for you. See below for version info. Additionally, several environment variables are available that affect the bundled feature - `LIBSECCOMP_LIB_PATH`, `LIBSECCOMP_LINK_TYPE`, `LIBSECCOMP_SRC_PATH`. See [build.rs](https://github.com/libseccomp-rs/libseccomp-rs/blob/main/libseccomp-sys/build.rs) for more information on how they're used.

## Version information

See the file [versions.rs](https://github.com/libseccomp-rs/libseccomp-rs/blob/main/libseccomp-sys/versions.rs). Other versions may be built by using the environment variables mentioned above.
