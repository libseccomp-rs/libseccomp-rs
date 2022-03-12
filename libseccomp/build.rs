// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use std::{env, path};

const LIBSECCOMP_LIB_PATH: &str = "LIBSECCOMP_LIB_PATH";

fn main() {
    println!("cargo:rerun-if-env-changed={}", LIBSECCOMP_LIB_PATH);

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

    // The bundled version of libseccomp will always be > 2.5.
    // NOTE: We are relying here on the fact that || short-circuits in rust, so that we don't call
    // pkg_config::Config::probe if the bundled feature is enabled, because probe will output cargo
    // build flags to link libseccomp dynamically if it's found.
    if cfg!(feature = "bundled")
        || pkg_config::Config::new()
            .atleast_version("2.5.0")
            .probe("libseccomp")
            .is_ok()
    {
        println!("cargo:rustc-cfg=libseccomp_v2_5");
    }
}
