#![allow(dead_code)]
//! Contains versioning information about dependencies outside Cargo. This file is used by the
//! build.rs build script.

/// Information about external dependencies using during the build.
pub struct SourceInfo {
    pub description: &'static str,
    pub url_template: &'static str,
    pub version: &'static str,
    pub sha256sum: &'static str,
}

pub static LIBSECCOMP: SourceInfo = SourceInfo {
    description: "High level interface to Linux seccomp filter",
    url_template: "https://github.com/seccomp/libseccomp/releases/download/v%VERSION%/libseccomp-%VERSION%.tar.gz",
    version: "2.5.3",
    sha256sum: "59065c8733364725e9721ba48c3a99bbc52af921daf48df4b1e012fbc7b10a76",
};
