# SPDX-License-Identifier: Apache-2.0 or MIT
#
# Copyright 2021 Sony Group Corporation
#
# libseccomp-rs
#

.PHONY: all build release debug test check fmt clippy doc clean

all: build

#
# Build
#

build:
	cargo build

release:
	cargo build --release

debug:
	RUSTFLAGS="--deny warnings" cargo build

debug-all:
	RUSTFLAGS="--deny warnings" cargo build --all-features

#
# Test
#

test:
	cargo test --all-features -- --color always --nocapture --test-threads 1

check: fmt clippy test

#
# Format and Lint
#

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets --all-features -- --deny warnings

#
# Documentation
#

doc: doc-libseccomp doc-libseccomp-sys

doc-libseccomp:
	RUSTDOCFLAGS="--cfg docsrs" \
	cargo +nightly doc --lib --no-deps --all-features --manifest-path ./libseccomp/Cargo.toml

doc-libseccomp-sys:
	cargo doc --lib --no-deps --manifest-path ./libseccomp-sys/Cargo.toml

#
# Clean
#

clean:
	cargo clean
