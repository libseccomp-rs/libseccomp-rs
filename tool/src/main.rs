// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use std::env;
use std::path::PathBuf;

fn main() {
    let output_file = "../libseccomp-sys/src/libseccomp_bindings.rs";
    let default_header_path = PathBuf::from("/usr/local/include");
    let mut header_path;

    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        header_path = default_header_path;
    } else if args.len() == 2 {
        header_path = PathBuf::from(&args[1]);
    } else {
        eprintln!("Invalid argument");
        eprintln!("Usage: cargo run <include path of seccomop.h>");
        eprintln!(
            "Default header path is {}",
            default_header_path.to_str().unwrap()
        );
        std::process::exit(1);
    }

    header_path.push("seccomp.h");

    let bindings = bindgen::Builder::default()
        //.header(header_path)
        .header_contents(
            "libseccomp_wrapper.h",
            &format!("#include \"{}\"", header_path.to_str().unwrap(),),
        )
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .layout_tests(false)
        .generate_comments(false)
        .whitelist_type("SCMP_.*")
        .whitelist_type("scmp_.*")
        .whitelist_type("seccomp_.*")
        .whitelist_function("seccomp_.*")
        .whitelist_var(".*SCMP_.*")
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(output_file)
        .expect("Cloudn't write bindings");
}
