# SPDX-License-Identifier: Apache-2.0 or MIT
#
# Copyright 2021 Sony Group Corporation
#
# libseccomp-rs
#

.PHONY: all build release debug test check fmt clippy clean

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

#
# Test
#

test:
	cargo test -- --color always --nocapture --test-threads 1

check: fmt clippy test

#
# Format and Lint
#

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets --all-features -- --deny warnings

#
# Clean
#

clean:
	cargo clean
