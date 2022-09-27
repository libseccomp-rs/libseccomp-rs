// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use std::{env, path, process::Command, str};

const LIBSECCOMP_LIB_PATH: &str = "LIBSECCOMP_LIB_PATH";

fn main() {
    println!("cargo:rerun-if-env-changed={}", LIBSECCOMP_LIB_PATH);

    match get_rustc_minor_version() {
        Ok(rustc_minor_version) => {
            if rustc_minor_version < 52 {
                // unsafe_block_in_unsafe_fn
                println!("cargo:rustc-cfg=msrv_compat_1_52");
            }
            if rustc_minor_version < 53 {
                // array_into_iter_impl
                println!("cargo:rustc-cfg=msrv_compat_1_53");
            }
        }
        Err(err) => {
            println!(
                "cargo:warning=libseccomp: Could not detect the rustc version: {}",
                err,
            );
        }
    }

    if let Ok(path) = env::var(LIBSECCOMP_LIB_PATH) {
        println!("cargo:rustc-link-search=native={}", path);
        let pkgconfig = path::Path::new(&path).join("pkgconfig");
        env::set_var("PKG_CONFIG_PATH", pkgconfig);
    }

    let target = env::var("TARGET").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();
    if target != host {
        env::set_var("PKG_CONFIG_ALLOW_CROSS", "1");
    }

    if pkg_config::Config::new()
        .atleast_version("2.5.0")
        .probe("libseccomp")
        .is_ok()
    {
        println!("cargo:rustc-cfg=libseccomp_v2_5");
    }
}

fn get_rustc_minor_version() -> Result<u32, Box<dyn std::error::Error>> {
    let rustc_version_output = Command::new(env::var("RUSTC").unwrap())
        .arg("--version")
        .output()
        .map_err(|e| format!("rustc --version failed: {}", e))?
        .stdout;
    let rustc_version_output = str::from_utf8(&rustc_version_output)?;

    let minor_version = rustc_version_output
        .strip_prefix("rustc 1.")
        .ok_or("Unexpected output from rustc --version")?
        .split('.')
        .next()
        .ok_or("Unexpected output from rustc --version")?
        .parse::<u32>()?;

    Ok(minor_version)
}
