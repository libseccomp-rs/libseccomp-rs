# libseccomp-rs

[![build-test](https://github.com/ManaSugi/libseccomp-rs/actions/workflows/build-test.yaml/badge.svg)](https://github.com/ManaSugi/libseccomp-rs/actions/workflows/build-test.yaml)
[![Latest release on crates.io](https://img.shields.io/crates/v/libseccomp.svg)](https://crates.io/crates/libseccomp)
[![Documentation on docs.rs](https://docs.rs/libseccomp/badge.svg)](https://docs.rs/libseccomp)

Native Rust crate for libseccomp library

This is a set of projects (high-level bindings, low-level bindings and tool for generating low-level bindings automatically) that enables developers 
to use the libseccomp API in Rust easily.

* libseccomp: High-level safe API
* libseccomp-sys: Low-level unsafe API (automatically generated)
* tool: Tool for generating low-level bindings using bindgen

## Example
### Create and load a single seccomp rule

```rust
use libseccomp::*;

// new_filter creates and returns a new filter context.
let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();

// add_arch adds an architecture to the filter.
filter.add_arch(ScmpArch::Native).unwrap();

// get_syscall_from_name returns the number of a syscall by name for a given
// architectures's ABI.
// If arch argument is None, the function returns the number of a syscall
// on the kernel's native architecture.
let syscall = get_syscall_from_name("dup2", None).unwrap();

// add_rule adds a single rule for an unconditional or conditional action on a syscall.
filter.add_rule(ScmpAction::Errno(111), syscall, None).unwrap();

// load loads the filter context into the kernel.
filter.load().unwrap();

// The dup2 fails by the seccomp rule.
assert_eq!(unsafe { libc::dup2(1, 2) } as i32, -libc::EPERM);
assert_eq!(std::io::Error::last_os_error().raw_os_error().unwrap(), 111);
```

## Requirements
Before using the `libseccomp-rs`, you must install the libseccomp library for your system.
The libseccomp version 2.4 or newer is required.

### Installing the libseccomp from the package on debian-based linux

``` sh
$ sudo apt install libseccomp-dev
```

### Building and installing the libseccomp 2.5.1 from the source
If you want to build the libseccomp library from an official release tarball instead of the package,
you should follow the quick step.

```sh
$ wget https://github.com/seccomp/libseccomp/releases/download/v2.5.1/libseccomp-2.5.1.tar.gz
$ tar xvf libseccomp-2.5.1.tar.gz
$ cd libseccomp-2.5.1
$ ./configure
$ make
$ sudo make install
```

For more details, see the [libseccomp library repository](https://github.com/seccomp/libseccomp).

## Setup
If you use the libseccomp crate with dynamically linked the [libseccomp library](https://github.com/seccomp/libseccomp),
you do not need additional settings about environment variables.

However, if you want to use the crate with statically linked the library,
you have to set the `LIBSECCOMP_LINK_TYPE` and `LIBSECCOMP_LIB_PATH` environment variable
like below.

```sh
$ export LIBSECCOMP_LINK_TYPE=static
$ export LIBSECCOMP_LIB_PATH="the path of libseccomp.a"
```

Now, add the following to your `Cargo.toml` to start building the crate.

```
[dependencies]
libseccomp = "0.1.3"
```

## Testing the crate
A number of tests are provided in the Makefile, if you want to run the standard
regression tests, you can execute the following command.

``` sh
$ make test
```

## How to contribute
Anyone is welcome to join and contribute code, documentation and use cases.

- Change or add something
- Make sure you're using the latest Rust version
- Run `rustfmt` to guarantee code style conformance

``` sh
$ rustup component add rustfmt
$ cargo fmt
```

- Open a pull request in Github

## License
This crate is licensed under:

- MIT License (see LICENSE-MIT); or
- Apache 2.0 License (see LICENSE-APACHE),

at your option.
