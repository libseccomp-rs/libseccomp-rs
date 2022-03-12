// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use crate::error::ErrorKind::*;
use crate::error::{Result, SeccompError};
use libseccomp_sys::*;
use std::fmt;

/// Represents the version information of the libseccomp library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScmpVersion {
    pub major: u32,
    pub minor: u32,
    pub micro: u32,
}

impl ScmpVersion {
    /// Gets the version of the currently loaded libseccomp library.
    ///
    /// This function returns `ScmpVersion` that represents the currently
    /// loaded libseccomp version.
    ///
    /// # Errors
    ///
    /// If this function encounters an issue while getting the version,
    /// an error will be returned.
    pub fn current() -> Result<Self> {
        if let Some(version) = unsafe { seccomp_version().as_ref() } {
            Ok(Self {
                major: version.major,
                minor: version.minor,
                micro: version.micro,
            })
        } else {
            Err(SeccompError::new(Common(
                "Could not get seccomp version".to_string(),
            )))
        }
    }
}

impl From<(u32, u32, u32)> for ScmpVersion {
    /// Creates a `ScmpVersion` from the specified arbitrary version.
    ///
    /// # Arguments
    ///
    /// * `version` - A tuple that represents the version of the libseccomp library.
    /// The index 0, 1, and 2 represent `major`, `minor`, and `micro` respectively.
    fn from(version: (u32, u32, u32)) -> Self {
        Self {
            major: version.0,
            minor: version.1,
            micro: version.2,
        }
    }
}

impl fmt::Display for ScmpVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.micro)
    }
}
