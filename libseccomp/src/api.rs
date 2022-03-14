// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use crate::error::ErrorKind::*;
use crate::error::{Result, SeccompError};
use crate::version::ensure_supported_version;
use crate::{check_version, ScmpVersion};
use libseccomp_sys::*;

/// Sets the API level forcibly.
///
/// General use of this function is strongly discouraged.
/// See the [seccomp_api_get(3)] man page for details on available API levels.
///
/// [seccomp_api_get(3)]: https://www.man7.org/linux/man-pages/man3/seccomp_api_get.3.html
///
/// # Arguments
///
/// * `level` - The API level
///
/// # Errors
///
/// If the API level can not be detected due to the library being older than v2.4.0,
/// an error will be returned.
pub fn set_api(level: u32) -> Result<()> {
    let ret = unsafe { seccomp_api_set(level) };
    if ret != 0 {
        return Err(SeccompError::new(Common(
            "API level operations are not supported".to_string(),
        )));
    }

    Ok(())
}

/// Gets the API level supported by the system.
///
/// This function returns a positive int containing the API level.
/// See the [seccomp_api_get(3)] man page for details on available API levels.
///
/// [seccomp_api_get(3)]: https://www.man7.org/linux/man-pages/man3/seccomp_api_get.3.html
///
/// # Errors
///
/// If the API level can not be detected due to the library being older than v2.4.0,
/// an error will be returned.
pub fn get_api() -> Result<u32> {
    let ret = unsafe { seccomp_api_get() };
    if ret == 0 {
        return Err(SeccompError::new(Common(
            "API level operations are not supported".to_string(),
        )));
    }

    Ok(ret)
}

/// Checks that both the libseccomp API level and the libseccomp version being
/// used are equal to or greater than the specified API level and version.
///
/// This function returns `Ok(true)` if both the libseccomp API level and the
/// libseccomp version are equal to or greater than the specified API level and
/// version, `Ok(false)` otherwise.
///
/// # Arguments
///
/// * `min_level` - The libseccomp API level you want to check
/// * `expected` - The libseccomp version you want to check
///
/// # Errors
///
/// If an issue is encountered getting the current API level or version,
/// an error will be returned.
pub fn check_api(min_level: u32, expected: ScmpVersion) -> Result<bool> {
    let level = get_api()?;

    if level >= min_level && check_version(expected)? {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Ensures that both the libseccomp API level and the libseccomp version are
/// equal to or greater than the specified API level and version.
///
/// # Arguments
///
/// * `msg` - An arbitrary non-empty operation description, used as a part
/// of the error message returned.
/// * `min_level` - The libseccomp API level you want to check
/// * `expected` - The libseccomp version you want to check
///
/// # Errors
///
/// If the libseccomp API level and the libseccomp version being used are less than
/// the specified version, an error will be returned.
pub(crate) fn ensure_supported_api(msg: &str, min_level: u32, expected: ScmpVersion) -> Result<()> {
    let level = get_api()?;

    if level >= min_level {
        ensure_supported_version(msg, expected)
    } else {
        let current = ScmpVersion::current()?;
        Err(SeccompError::new(Common(format!(
            "{} requires libseccomp >= {} and API level >= {} (current version: {}, API level: {})",
            msg, expected, min_level, current, level
        ))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_supported_api() {
        assert!(ensure_supported_api("test", 3, ScmpVersion::from((2, 4, 0))).is_ok());
        assert!(ensure_supported_api("test", 100, ScmpVersion::from((2, 4, 0))).is_err());
    }
}
