// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=LIBSECCOMP_LIB_PATH");
    println!("cargo:rerun-if-env-changed=LIBSECCOMP_LINK_TYPE");

    if let Ok(path) = env::var("LIBSECCOMP_LIB_PATH") {
        println!("cargo:rustc-link-search=native={}", path);
    }

    let link_type = match env::var("LIBSECCOMP_LINK_TYPE") {
        Ok(v) => v, // static, framework, dylib
        Err(_) => String::from("dylib"),
    };

    println!("cargo:rustc-link-lib={}=seccomp", link_type);
}
