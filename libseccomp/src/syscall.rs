// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use crate::error::{Result, SeccompError};
use crate::ScmpArch;
use libseccomp_sys::*;
use std::ffi::{CStr, CString};
use std::fmt;

/// Represents a syscall number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScmpSyscall {
    nr: i32,
}
impl ScmpSyscall {
    pub(crate) fn to_sys(self) -> i32 {
        self.nr
    }

    pub(crate) fn from_sys(nr: i32) -> Self {
        Self { nr }
    }

    /// Resolves a syscall name to `ScmpSyscall`.
    ///
    /// This function returns a `ScmpSyscall` that can be passed to
    /// [`add_rule`](crate::ScmpFilterContext::add_rule) like functions.
    ///
    /// This function corresponds to
    /// [`seccomp_syscall_resolve_name`](https://man7.org/linux/man-pages/man3/seccomp_syscall_resolve_name.3.html).
    ///
    /// # Arguments
    ///
    /// * `name` - The name of a syscall
    ///
    /// # Errors
    ///
    ///  If an invalid string for the syscall name is specified or a syscall with that
    ///  name is not found, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// let syscall = ScmpSyscall::from_name("chroot")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_name(name: &str) -> Result<Self> {
        Self::from_name_by_arch(name, ScmpArch::Native)
    }

    /// Resolves a syscall name to `ScmpSyscall`.
    ///
    /// NOTE: If you call this function with a foreign architecture token and pass the result
    /// to [`add_rule*`](crate::ScmpFilterContext::add_rule) functions you get unexpected results.
    ///
    /// This function returns a `ScmpSyscall` for the specified architecture.
    ///
    /// This function corresponds to
    /// [`seccomp_syscall_resolve_name_arch`](https://man7.org/linux/man-pages/man3/seccomp_syscall_resolve_name_arch.3.html).
    ///
    /// # Arguments
    ///
    /// * `name` - The name of a syscall
    /// * `arch` - An architecture token
    ///
    /// # Errors
    ///
    ///  If an invalid string for the syscall name is specified or a syscall with that
    ///  name is not found, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// let syscall = ScmpSyscall::from_name_by_arch("chroot", ScmpArch::Aarch64)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_name_by_arch(name: &str, arch: ScmpArch) -> Result<Self> {
        let name_c = CString::new(name)?;
        let nr = unsafe { seccomp_syscall_resolve_name_arch(arch.to_sys(), name_c.as_ptr()) };
        if nr == __NR_SCMP_ERROR {
            return Err(SeccompError::with_msg(format!(
                "Could not resolve syscall name {}",
                name
            )));
        }

        Ok(Self { nr })
    }

    /// Resolves a syscall name to `ScmpSyscall`.
    ///
    /// This function returns a `ScmpSyscall` for the specified architecture
    /// rewritten if necessary.
    ///
    /// This function corresponds to
    /// [`seccomp_syscall_resolve_name_rewrite`](https://man7.org/linux/man-pages/man3/seccomp_syscall_resolve_name_rewrite.3.html).
    ///
    /// # Arguments
    ///
    /// * `name` - The name of a syscall
    /// * `arch` - An architecture token
    ///
    /// # Errors
    ///
    ///  If an invalid string for the syscall name is specified or a syscall with that
    ///  name is not found, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// let syscall = ScmpSyscall::from_name_by_arch_rewrite("socketcall", ScmpArch::X32)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_name_by_arch_rewrite(name: &str, arch: ScmpArch) -> Result<Self> {
        let name_c = CString::new(name)?;
        let nr = unsafe { seccomp_syscall_resolve_name_rewrite(arch.to_sys(), name_c.as_ptr()) };
        if nr == __NR_SCMP_ERROR {
            return Err(SeccompError::with_msg(format!(
                "Could not resolve syscall name {}",
                name
            )));
        }

        Ok(Self { nr })
    }

    /// Resolves this `ScmpSyscall` to it's name for the native architecture.
    ///
    /// This function returns a string containing the name of the syscall.
    ///
    /// This function corresponds to
    /// [`seccomp_syscall_resolve_num_arch`](https://man7.org/linux/man-pages/man3/seccomp_syscall_resolve_num_arch.3.html).
    ///
    /// # Errors
    ///
    /// If the syscall is unrecognized or an issue is encountered getting the
    /// name of the syscall, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// assert_eq!(ScmpSyscall::from_name("mount")?.get_name()?, String::from("mount"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn get_name(self) -> Result<String> {
        Self::get_name_by_arch(self, ScmpArch::Native)
    }

    /// Resolves this `ScmpSyscall` to it's name for a given architecture.
    ///
    /// This function returns a string containing the name of the syscall.
    ///
    /// This function corresponds to
    /// [`seccomp_syscall_resolve_num_arch`](https://man7.org/linux/man-pages/man3/seccomp_syscall_resolve_num_arch.3.html).
    ///
    /// # Arguments
    ///
    /// * `arch` - A valid architecture token
    ///
    /// # Errors
    ///
    /// If the syscall is unrecognized or an issue is encountered getting the
    /// name of the syscall, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// assert_eq!(
    ///     ScmpSyscall::from_name_by_arch("mount", ScmpArch::Mips)?
    ///         .get_name_by_arch(ScmpArch::Mips)?,
    ///     String::from("mount"),
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn get_name_by_arch(self, arch: ScmpArch) -> Result<String> {
        let ret = unsafe { seccomp_syscall_resolve_num_arch(arch.to_sys(), self.to_sys()) };
        if ret.is_null() {
            return Err(SeccompError::with_msg(format!(
                "Could not resolve syscall number {}",
                self.nr
            )));
        }

        let name = unsafe { CStr::from_ptr(ret) }.to_str()?.to_string();
        unsafe { libc::free(ret as *mut libc::c_void) };

        Ok(name)
    }
}

impl From<i32> for ScmpSyscall {
    /// Creates a `ScmpSyscall` from the specified syscall number.
    ///
    /// # Arguments
    ///
    /// * `nr` - The number of syscall
    fn from(nr: i32) -> Self {
        Self::from_sys(nr)
    }
}

impl From<ScmpSyscall> for i32 {
    /// Gets the syscall number of a syscall.
    ///
    /// # Arguments
    ///
    /// * `syscall` - The syscall
    fn from(syscall: ScmpSyscall) -> i32 {
        syscall.nr
    }
}

impl PartialEq<i32> for ScmpSyscall {
    fn eq(&self, other: &i32) -> bool {
        self.nr == *other
    }
}

impl PartialEq<ScmpSyscall> for i32 {
    fn eq(&self, other: &ScmpSyscall) -> bool {
        *self == other.nr
    }
}

impl fmt::Display for ScmpSyscall {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.nr)
    }
}
