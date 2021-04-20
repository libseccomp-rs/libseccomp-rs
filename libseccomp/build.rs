// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

fn main() {
    if pkg_config::Config::new()
        .atleast_version("2.5.0")
        .probe("libseccomp")
        .is_ok()
    {
        println!("cargo:rustc-cfg=libseccomp_v2_5");
    }
}
