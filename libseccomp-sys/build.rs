// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use std::env;

mod versions;

const LIBSECCOMP_LIB_PATH: &str = "LIBSECCOMP_LIB_PATH";
const LIBSECCOMP_LINK_TYPE: &str = "LIBSECCOMP_LINK_TYPE";
const LIBSECCOMP_SRC_PATH: &str = "LIBSECCOMP_SRC_PATH";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed={}", LIBSECCOMP_SRC_PATH);
    println!("cargo:rerun-if-env-changed={}", LIBSECCOMP_LIB_PATH);
    println!("cargo:rerun-if-env-changed={}", LIBSECCOMP_LINK_TYPE);

    // We do cfg on blocks here instead of `if cfg!()...` so we don't have to build the cc library
    // at all in the non-bundled case.

    // If bundled feature is enabled, build the library and return any errors.
    #[cfg(feature = "bundled")]
    {
        let lib_dir = build_bundled::build()?;
        build_linked::link(Some(&lib_dir), Some("static"))
    }
    #[cfg(not(feature = "bundled"))]
    {
        // Otherwise, link with system library.
        build_linked::link(None, None)
    }
}

#[cfg(feature = "bundled")]
mod build_bundled {
    use super::*;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use super::versions::*;

    /// Downloads (if `LIBSECCOMP_SRC_PATH` is not set) and builds the libseccomp source.
    pub fn build() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let out_dir =
            PathBuf::from(env::var("OUT_DIR").expect("out dir always exists in build scripts"));
        let lib_path = env::var(LIBSECCOMP_LIB_PATH);

        // If lib path is set, skip build and use lib path directly.
        if let Ok(path) = lib_path {
            return Ok(PathBuf::from(path));
        }

        // Determine whether to download or not:
        // If src is set, use it. Otherwise, download and set src path.
        let src_path = if let Ok(path) = env::var(LIBSECCOMP_SRC_PATH) {
            PathBuf::from(path)
        } else {
            download_libseccomp(out_dir.as_path())?
        };

        let mut build_output_path = build_libseccomp(&src_path, &out_dir)?;

        // Return just the lib path from the build.
        build_output_path.push("lib");

        Ok(build_output_path)
    }

    /// Build source with configure, make, make install, setting the output directory to a
    /// directory in our package's out_dir.
    fn build_libseccomp(
        src_path: &Path,
        out_dir: &Path,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        // Create the directory that libseccomp's output will be written to.
        // Technically, we don't have to do this and can extract it from `libseccomp/src/.libs/` after
        // just `make` is done but it's cleaner this way.
        //
        // If the directory already exists, we delete it and start over. This should only
        // happen if the build is being rerun because the environment variables changed, or the
        // build itself failed.
        let mut build_output_path = out_dir.to_path_buf();
        build_output_path.push("libseccomp-build-out");

        if build_output_path.exists() {
            std::fs::remove_dir_all(&build_output_path)?;
        }
        std::fs::create_dir(&build_output_path)?;

        // Get compiler flags info.
        let cc_info = if cfg!(target_env = "musl") {
            // _FORTIFY_SOURCE=2 is not supported by musl, but it is set by default on some
            // platforms.
            cc::Build::new()
                .flag("-U_FORTIFY_SOURCE")
                .flag("-D_FORTIFY_SOURCE=1")
                .get_compiler()
        } else {
            cc::Build::new().get_compiler()
        };

        let cc_env = cc_info.cc_env();
        let cflags_env = cc_info.cflags_env();

        let makeflags = std::env::var("CARGO_MAKEFLAGS")
            .expect("cargo makeflags are always set in build scripts");

        // TODO: Investigate (via more testing) whether we should be setting some combination of
        // --host, --build, and --target when cross-compiling, or if setting CC via the cc crate is
        // sufficient.
        let configure_result = std::process::Command::new("./configure")
            .current_dir(&src_path)
            .args(["--prefix", build_output_path.to_str().unwrap()])
            .arg(format!("CFLAGS={}", cflags_env.to_str().unwrap()))
            .arg(format!("CC={}", cc_env.to_str().unwrap()))
            .spawn()?
            .wait()?;
        if !configure_result.success() {
            return Err("Running `configure` failed while building libseccomp.".into());
        }

        let make_result = std::process::Command::new("make")
            .current_dir(&src_path)
            .env("MAKEFLAGS", &makeflags)
            .spawn()?
            .wait()?;

        if !make_result.success() {
            return Err("Running `make` failed while building libseccomp.".into());
        }

        let make_install_result = std::process::Command::new("make")
            .current_dir(&src_path)
            .env("MAKEFLAGS", &makeflags)
            .arg("install")
            .spawn()?
            .wait()?;
        if !make_install_result.success() {
            return Err("Running `make install` failed while building libseccomp.".into());
        }

        Ok(build_output_path)
    }

    // NOTE: We could replace the calls to external programs here with the reqwest, flate2, and
    // sha2 crates but it would increase the build-time compile time (on the first run), in
    // exchange for not having to have those commands installed on the machine building the crate.
    /// Uses curl, tar, and sha256sum to download, extract, and verify the libseccomp source.
    fn download_libseccomp(out_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let url = LIBSECCOMP
            .url_template
            .replace("%VERSION%", LIBSECCOMP.version);
        let tarball_name = url
            .split('/')
            .next_back()
            .expect("get the filename from the url");

        use std::process::Command;

        let curl_result = Command::new("curl")
            .current_dir(out_dir)
            .args(["-s", "-L", "-O"])
            .arg(&url)
            .spawn()?
            .wait()?;
        assert!(
            curl_result.success(),
            "Running `curl` failed while building libseccomp."
        );

        let mut shasum_process = Command::new("sha256sum")
            .current_dir(out_dir)
            .stdin(std::process::Stdio::piped())
            .args(["--check", "--status", "--strict"])
            .spawn()?;

        let shasum_stdin = shasum_process
            .stdin
            .as_mut()
            .expect("couldn't acquire stdin of child sh256asum process");
        shasum_stdin
            .write_all(format!("{}  {}\n", LIBSECCOMP.sha256sum, tarball_name).as_bytes())?;

        let shasum_result = shasum_process.wait()?;
        assert!(
            shasum_result.success(),
            "Running `sha256sum` failed while building libseccomp."
        );

        let tar_result = Command::new("tar")
            .current_dir(out_dir)
            .args(["-xf", tarball_name])
            .spawn()?
            .wait()?;
        assert!(
            tar_result.success(),
            "Running `tar` failed while building libseccomp."
        );

        let mut src_dir = out_dir.to_path_buf();
        src_dir.push(["libseccomp-", LIBSECCOMP.version].join(""));

        Ok(src_dir)
    }
}

mod build_linked {
    use super::*;
    use std::path::Path;

    pub fn link(
        lib_path: Option<&Path>,
        lib_link_type: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // If the lib path is set via environment variable, use that to tell cargo where to find
        // libseccomp.
        // Otherwise, use the passed path if it's set from the build step.
        if let Ok(path) = env::var(LIBSECCOMP_LIB_PATH) {
            println!("cargo:rustc-link-search=native={}", path);
        } else if let Some(path) = lib_path {
            println!("cargo:rustc-link-search=native={}", path.to_str().unwrap());
        }

        let link_type = match env::var(LIBSECCOMP_LINK_TYPE) {
            Ok(link_type) if link_type == "framework" => {
                return Err("Seccomp is a Linux specific technology".into());
            }
            Ok(link_type) => link_type, // static or dylib
            Err(_) => {
                if let Some(link_type) = lib_link_type {
                    String::from(link_type)
                } else {
                    String::from("dylib")
                }
            }
        };

        println!("cargo:rustc-link-lib={}=seccomp", link_type);

        Ok(())
    }
}
