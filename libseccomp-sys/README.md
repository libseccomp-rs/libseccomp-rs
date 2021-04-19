# libseccomp-sys

Low-level bindings for the libseccomp library

This crate contains the raw FFI bindings to the [libseccomp](https://github.com/seccomp/libseccomp)
library by using [bindgen](https://github.com/rust-lang/rust-bindgen).

These low level, mostly `unsafe` bindings are then used by [libseccomp-rs](https://crates.io/crates/libseccomp) 
wraps them in a nice to use, mostly safe API.
Therefore most users should not need to interact with this crate directly.

## Version information

Currently, this crate supports libseccomp version 2.5.1 that is the latest version.
