// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use std::{env, path};

fn main() {
    println!("cargo:rerun-if-env-changed=LIBSECCOMP_LIB_PATH");

    if let Ok(path) = env::var("LIBSECCOMP_LIB_PATH") {
        println!("cargo:rustc-link-search=native={}", path);
        let pkgconfig = path::Path::new(&path).join("pkgconfig");
        env::set_var("PKG_CONFIG_PATH", pkgconfig);
    }

    if pkg_config::Config::new()
        .atleast_version("2.5.0")
        .probe("libseccomp")
        .is_ok()
    {
        println!("cargo:rustc-cfg=libseccomp_v2_5");
    }
}
