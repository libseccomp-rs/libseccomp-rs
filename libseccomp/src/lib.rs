// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

//! Rust Language Bindings for the libseccomp Library
//!
//! The libseccomp library provides an easy to use, platform independent, interface to
//! the Linux Kernel's syscall filtering mechanism. The libseccomp API is designed to
//! abstract away the underlying BPF based syscall filter language and present a more
//! conventional function-call based filtering interface that should be familiar to, and
//! easily adopted by, application developers.
//!
//! The libseccomp crate is a high-level safe API for the libseccomp library.
//!
//! # Examples
//!
//! ```rust
//! use libseccomp::*;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
//!     let syscall = ScmpSyscall::from_name("getuid")?;
//!
//!     filter.add_arch(ScmpArch::X8664)?;
//!     filter.add_rule(ScmpAction::Errno(1), syscall)?;
//!     filter.load()?;
//!
//!     Ok(())
//! }
//! ```

//! ```rust
//! use libseccomp::*;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
//!     let syscall = ScmpSyscall::from_name("dup3")?;
//!     let cmp = ScmpArgCompare::new(0, ScmpCompareOp::Equal, 1);
//!
//!     filter.add_arch(ScmpArch::X8664)?;
//!     filter.add_rule_conditional(ScmpAction::Errno(libc::EPERM), syscall, &[cmp])?;
//!     filter.load()?;
//!
//!     Ok(())
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;

mod action;
mod arch;
mod arg_compare;
mod compare_op;
mod filter_attr;
#[cfg(any(libseccomp_v2_5, doc))]
mod notify;
mod version;

use error::ErrorKind::*;
use error::{Result, SeccompError};
use libseccomp_sys::*;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::unix::io::AsRawFd;
use std::ptr::NonNull;

pub use action::ScmpAction;
pub use arch::ScmpArch;
pub use arg_compare::ScmpArgCompare;
pub use compare_op::ScmpCompareOp;
pub use filter_attr::ScmpFilterAttr;
#[cfg(any(libseccomp_v2_5, doc))]
pub use notify::*;
pub use version::ScmpVersion;

/// Represents a syscall number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScmpSyscall {
    nr: i32,
}
impl ScmpSyscall {
    fn to_sys(self) -> i32 {
        self.nr
    }

    fn from_sys(nr: i32) -> Self {
        Self { nr }
    }

    /// Resolves a syscall name to `ScmpSyscall`.
    ///
    /// This function returns a `ScmpSyscall` that can be passed to
    /// [`add_rule`](ScmpFilterContext::add_rule) like functions.
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
    /// to [`add_rule*`](ScmpFilterContext::add_rule) functions you get unexpected results.
    ///
    /// This function returns a `ScmpSyscall` for the specified architecture.
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
            return Err(SeccompError::new(Common(format!(
                "Could not resolve syscall name {}",
                name
            ))));
        }

        Ok(Self { nr })
    }

    /// Resolves a syscall name to `ScmpSyscall`.
    ///
    /// This function returns a `ScmpSyscall` for the specified architecture
    /// rewritten if necessary.
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
            return Err(SeccompError::new(Common(format!(
                "Could not resolve syscall name {}",
                name
            ))));
        }

        Ok(Self { nr })
    }

    /// Resolves this `ScmpSyscall` to it's name for the native architecture.
    ///
    /// This function returns a string containing the name of the syscall.
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
            return Err(SeccompError::new(Common(format!(
                "Could not resolve syscall number {}",
                self.nr
            ))));
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

/// **Represents a filter context in the libseccomp.**
#[derive(Debug)]
pub struct ScmpFilterContext {
    ctx: NonNull<libc::c_void>,
}

impl ScmpFilterContext {
    /// Creates and returns a new filter context.
    ///
    /// This initializes the internal seccomp filter state and should
    /// be called before any other functions in this crate to ensure the filter
    /// state is initialized.
    ///
    /// This function returns a valid filter context.
    ///
    /// # Arguments
    ///
    /// * `default_action` - A default action to be taken for syscalls which match no rules in the filter
    ///
    /// # Errors
    ///
    /// If the filter context can not be created, an error will be returned.
    pub fn new_filter(default_action: ScmpAction) -> Result<ScmpFilterContext> {
        let ctx_ptr = unsafe { seccomp_init(default_action.to_sys()) };
        let ctx = NonNull::new(ctx_ptr)
            .ok_or_else(|| SeccompError::new(Common("Could not create new filter".to_string())))?;

        Ok(ScmpFilterContext { ctx })
    }

    /// Merges two filters.
    ///
    /// In order to merge two seccomp filters, both filters must have the same
    /// attribute values and no overlapping architectures.
    /// If successful, the `src` seccomp filter is released and all internal memory
    /// associated with the filter is freed.
    ///
    /// # Arguments
    ///
    /// * `src` - A seccomp filter that will be merged into the filter this is called on.
    ///
    /// # Errors
    ///
    /// If merging the filters fails, an error will be returned.
    pub fn merge(&mut self, src: Self) -> Result<()> {
        cvt(unsafe { seccomp_merge(self.ctx.as_ptr(), src.ctx.as_ptr()) })?;

        // The src filter is already released.
        std::mem::forget(src);

        Ok(())
    }

    /// Checks if an architecture is present in a filter.
    ///
    /// If a filter contains an architecture, it uses its default action for
    /// syscalls which do not match rules in it, and its rules can match syscalls
    /// for that ABI.
    /// If a filter does not contain an architecture, all syscalls made to that
    /// kernel ABI will fail with the filter's default Bad Architecture Action
    /// (by default, killing the proc).
    ///
    /// This function returns `Ok(true)` if the architecture is present in the filter,
    /// `Ok(false)` otherwise.
    ///
    /// # Arguments
    ///
    /// * `arch` - An architecture token
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered calling to the libseccomp API, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    /// ctx.add_arch(ScmpArch::Aarch64)?;
    /// assert!(ctx.is_arch_present(ScmpArch::Aarch64)?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn is_arch_present(&self, arch: ScmpArch) -> Result<bool> {
        const NEG_EEXIST: i32 = -libc::EEXIST;

        match unsafe { seccomp_arch_exist(self.ctx.as_ptr(), arch.to_sys()) } {
            0 => Ok(true),
            NEG_EEXIST => Ok(false),
            errno => Err(SeccompError::new(Errno(errno))),
        }
    }

    /// Adds an architecture to the filter.
    ///
    /// # Arguments
    ///
    /// * `arch` - An architecture token
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered adding the architecture, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    /// ctx.add_arch(ScmpArch::X86)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn add_arch(&mut self, arch: ScmpArch) -> Result<()> {
        let ret = unsafe { seccomp_arch_add(self.ctx.as_ptr(), arch.to_sys()) };

        // Libseccomp returns -EEXIST if the specified architecture is already
        // present. Succeed silently in this case, as it's not fatal, and the
        // architecture is present already.
        if ret != 0 && ret != -(libc::EEXIST as i32) {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
    }

    /// Removes an architecture from the filter.
    ///
    /// # Arguments
    ///
    /// * `arch` - An architecture token
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered removing the architecture, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    /// ctx.add_arch(ScmpArch::X86)?;
    /// ctx.remove_arch(ScmpArch::X86)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn remove_arch(&mut self, arch: ScmpArch) -> Result<()> {
        let ret = unsafe { seccomp_arch_remove(self.ctx.as_ptr(), arch.to_sys()) };

        // Similar to add_arch, -EEXIST is returned if the arch is not present
        // Succeed silently in that case, this is not fatal and the architecture
        // is not present in the filter after remove_arch
        if ret != 0 && ret != -(libc::EEXIST as i32) {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
    }

    /// Adds a single rule for an unconditional action on a syscall.
    ///
    /// If the specified rule needs to be rewritten due to architecture specifics,
    /// it will be rewritten without notification.
    ///
    /// # Arguments
    ///
    /// * `action` - An action to be taken on the call being made
    /// * `syscall` - The number of syscall
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered adding the rule, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    /// let syscall = ScmpSyscall::from_name("ptrace")?;
    /// ctx.add_rule(ScmpAction::Errno(libc::EPERM), syscall)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn add_rule<S: Into<ScmpSyscall>>(&mut self, action: ScmpAction, syscall: S) -> Result<()> {
        self.add_rule_conditional(action, syscall, &[])
    }

    /// Adds a single rule for a conditional action on a syscall.
    ///
    /// If the specified rule needs to be rewritten due to architecture specifics,
    /// it will be rewritten without notification.
    /// Comparators are AND'd together (i.e. all must match for the rule to match).
    /// You can only compare each argument once in a single rule.
    ///
    /// # Arguments
    ///
    /// * `action` - An action to be taken on the call being made
    /// * `syscall` - The number of syscall
    /// * `comparators` - An array of the rule in a seccomp filter
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered adding the rule, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    /// let syscall = ScmpSyscall::from_name("open")?;
    /// ctx.add_rule_conditional(
    ///     ScmpAction::Errno(libc::EPERM),
    ///     syscall,
    ///     &[scmp_cmp!($arg1 & (libc::O_TRUNC as u64) == libc::O_TRUNC as u64)],
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn add_rule_conditional<S: Into<ScmpSyscall>>(
        &mut self,
        action: ScmpAction,
        syscall: S,
        comparators: &[ScmpArgCompare],
    ) -> Result<()> {
        cvt(unsafe {
            seccomp_rule_add_array(
                self.ctx.as_ptr(),
                action.to_sys(),
                syscall.into().to_sys(),
                comparators.len() as u32,
                comparators.as_ptr() as *const scmp_arg_cmp,
            )
        })
    }

    /// Adds a single rule for an unconditional action on a syscall.
    ///
    /// The functions will attempt to add the rule exactly as specified so it may
    /// behave differently on different architectures.
    /// If the specified rule can not be represented on the architecture,
    /// the function will fail.
    ///
    /// # Arguments
    ///
    /// * `action` - An action to be taken on the call being made
    /// * `syscall` - The number of syscall
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered adding the rule, an error will be returned.
    pub fn add_rule_exact<S: Into<ScmpSyscall>>(
        &mut self,
        action: ScmpAction,
        syscall: S,
    ) -> Result<()> {
        self.add_rule_conditional_exact(action, syscall, &[])
    }

    /// Adds a single rule for a conditional action on a syscall.
    ///
    /// The functions will attempt to add the rule exactly as specified so it may
    /// behave differently on different architectures.
    /// If the specified rule can not be represented on the architecture,
    /// the function will fail.
    ///
    /// # Arguments
    ///
    /// * `action` - An action to be taken on the call being made
    /// * `syscall` - The number of syscall
    /// * `comparators` - An array of the rule in a seccomp filter
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered adding the rule, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    /// let syscall = ScmpSyscall::from_name("socket")?;
    /// ctx.add_rule_conditional_exact(
    ///     ScmpAction::Errno(libc::EPERM),
    ///     syscall,
    ///     &[scmp_cmp!($arg1 != libc::AF_UNIX as u64)],
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn add_rule_conditional_exact<S: Into<ScmpSyscall>>(
        &mut self,
        action: ScmpAction,
        syscall: S,
        comparators: &[ScmpArgCompare],
    ) -> Result<()> {
        cvt(unsafe {
            seccomp_rule_add_exact_array(
                self.ctx.as_ptr(),
                action.to_sys(),
                syscall.into().to_sys(),
                comparators.len() as u32,
                comparators.as_ptr() as *const scmp_arg_cmp,
            )
        })
    }

    /// Loads a filter context into the kernel.
    ///
    /// If the function succeeds, the new filter will be active when the function returns.
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered loading the rule, an error will be returned.
    pub fn load(&self) -> Result<()> {
        cvt(unsafe { seccomp_load(self.ctx.as_ptr()) })
    }

    /// Sets a syscall's priority.
    ///
    /// This provides a priority hint to the seccomp filter generator in the libseccomp
    /// such that higher priority syscalls are placed earlier in the seccomp filter code
    /// so that they incur less overhead at the expense of lower priority syscalls.
    ///
    /// # Arguments
    ///
    /// * `syscall` - The number of syscall
    /// * `priority` - The priority parameter that is an 8-bit value ranging from 0 to 255;
    /// a higher value represents a higher priority.
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or the number of syscall
    /// is invalid, an error will be returned.
    pub fn set_syscall_priority<S: Into<ScmpSyscall>>(
        &mut self,
        syscall: S,
        priority: u8,
    ) -> Result<()> {
        cvt(unsafe {
            seccomp_syscall_priority(self.ctx.as_ptr(), syscall.into().to_sys(), priority)
        })
    }

    /// Gets a raw filter attribute value.
    ///
    /// The seccomp filter attributes are tunable values that affect how the library behaves
    /// when generating and loading the seccomp filter into the kernel.
    ///
    /// # Arguments
    ///
    /// * `attr` - A seccomp filter attribute
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered retrieving the attribute, an error will be returned.
    pub fn get_filter_attr(&self, attr: ScmpFilterAttr) -> Result<u32> {
        let mut attribute: u32 = 0;

        cvt(unsafe { seccomp_attr_get(self.ctx.as_ptr(), attr.to_sys(), &mut attribute) })?;

        Ok(attribute)
    }

    /// Gets the default action as specified in the call to
    /// [`new_filter()`](ScmpFilterContext::new_filter) or [`reset()`](ScmpFilterContext::reset).
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered getting the action, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    /// let action = ctx.get_act_default()?;
    /// assert_eq!(action, ScmpAction::Allow);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn get_act_default(&self) -> Result<ScmpAction> {
        let ret = self.get_filter_attr(ScmpFilterAttr::ActDefault)?;

        ScmpAction::from_sys(ret)
    }

    /// Gets the default action taken when the loaded filter does not match the architecture
    /// of the executing application.
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered getting the action, an error will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use libseccomp::*;
    /// let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    /// let action = ctx.get_act_badarch()?;
    /// assert_eq!(action, ScmpAction::KillThread);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn get_act_badarch(&self) -> Result<ScmpAction> {
        let ret = self.get_filter_attr(ScmpFilterAttr::ActBadArch)?;

        ScmpAction::from_sys(ret)
    }

    /// Gets the current state of the [`ScmpFilterAttr::CtlNnp`] attribute.
    ///
    /// This function returns `Ok(true)` if the [`ScmpFilterAttr::CtlNnp`] attribute is set to on the filter being
    /// loaded, `Ok(false)` otherwise.
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered getting the current state, an error will be returned.
    pub fn get_ctl_nnp(&self) -> Result<bool> {
        let ret = self.get_filter_attr(ScmpFilterAttr::CtlNnp)?;

        Ok(ret != 0)
    }

    /// Deprecated alias for [`ScmpFilterContext::get_ctl_nnp()`].
    #[deprecated(since = "0.2.3", note = "Use ScmpFilterContext::get_ctl_nnp().")]
    pub fn get_no_new_privs_bit(&self) -> Result<bool> {
        self.get_ctl_nnp()
    }

    /// Gets the current state of the [`ScmpFilterAttr::CtlTsync`] attribute.
    ///
    /// This function returns `Ok(true)` if the [`ScmpFilterAttr::CtlTsync`] attribute set to on the filter being
    /// loaded, `Ok(false)` otherwise.
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter, an issue is encountered
    /// getting the current state, or the libseccomp API level is less than 2, an error will be returned.
    pub fn get_ctl_tsync(&self) -> Result<bool> {
        ensure_supported_api("get_ctl_tsync", 2, ScmpVersion::from((2, 2, 0)))?;
        let ret = self.get_filter_attr(ScmpFilterAttr::CtlTsync)?;

        Ok(ret != 0)
    }

    /// Gets the current state of the [`ScmpFilterAttr::CtlLog`] attribute.
    ///
    /// This function returns `Ok(true)` if the [`ScmpFilterAttr::CtlLog`] attribute set to on the filter being
    /// loaded, `Ok(false)` otherwise.
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter, an issue is encountered
    /// getting the current state, or the libseccomp API level is less than 3, an error will be returned.
    pub fn get_ctl_log(&self) -> Result<bool> {
        ensure_supported_api("get_ctl_log", 3, ScmpVersion::from((2, 4, 0)))?;
        let ret = self.get_filter_attr(ScmpFilterAttr::CtlLog)?;

        Ok(ret != 0)
    }

    /// Gets the current state of the [`ScmpFilterAttr::CtlSsb`] attribute.
    ///
    /// This function returns `Ok(true)` if the [`ScmpFilterAttr::CtlSsb`] attribute set to on the filter being
    /// loaded, `Ok(false)` otherwise.
    /// The [`ScmpFilterAttr::CtlSsb`] attribute is only usable when the libseccomp API level 4 or higher
    /// is supported.
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter, an issue is encountered
    /// getting the current state, or the libseccomp API level is less than 4, an error will be returned.
    pub fn get_ctl_ssb(&self) -> Result<bool> {
        ensure_supported_api("get_ctl_ssb", 4, ScmpVersion::from((2, 5, 0)))?;
        let ret = self.get_filter_attr(ScmpFilterAttr::CtlSsb)?;

        Ok(ret != 0)
    }

    /// Gets the current optimization level of the [`ScmpFilterAttr::CtlOptimize`] attribute.
    ///
    /// See [`set_ctl_optimize()`](ScmpFilterContext::set_ctl_optimize) for more details about
    /// the optimization level.
    /// The [`ScmpFilterAttr::CtlOptimize`] attribute is only usable when the libseccomp API level 4 or higher
    /// is supported.
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter, an issue is encountered
    /// getting the current state, or the libseccomp API level is less than 4, an error will be returned.
    pub fn get_ctl_optimize(&self) -> Result<u32> {
        ensure_supported_api("get_ctl_optimize", 4, ScmpVersion::from((2, 5, 0)))?;
        let ret = self.get_filter_attr(ScmpFilterAttr::CtlOptimize)?;

        Ok(ret)
    }

    /// Gets the current state of the [`ScmpFilterAttr::ApiSysRawRc`] attribute.
    ///
    /// This function returns `Ok(true)` if the [`ScmpFilterAttr::ApiSysRawRc`] attribute set to on the filter
    /// being loaded, `Ok(false)` otherwise.
    /// The [`ScmpFilterAttr::ApiSysRawRc`] attribute is only usable when the libseccomp API level 4 or higher
    /// is supported.
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter, an issue is encountered
    /// getting the current state, or the libseccomp API level is less than 4, an error will be returned.
    pub fn get_api_sysrawrc(&self) -> Result<bool> {
        ensure_supported_api("get_api_sysrawrc", 4, ScmpVersion::from((2, 5, 0)))?;
        let ret = self.get_filter_attr(ScmpFilterAttr::ApiSysRawRc)?;

        Ok(ret != 0)
    }

    /// Sets a raw filter attribute value.
    ///
    /// The seccomp filter attributes are tunable values that affect how the library behaves
    /// when generating and loading the seccomp filter into the kernel.
    ///
    /// # Arguments
    ///
    /// * `attr` - A seccomp filter attribute
    /// * `value` - A value of or the parameter of the attribute
    ///
    /// See the [seccomp_attr_set(3)] man page for details on available attribute values.
    ///
    /// [seccomp_attr_set(3)]: https://www.man7.org/linux/man-pages/man3/seccomp_attr_set.3.html
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered setting the attribute, an error will be returned.
    pub fn set_filter_attr(&mut self, attr: ScmpFilterAttr, value: u32) -> Result<()> {
        cvt(unsafe { seccomp_attr_set(self.ctx.as_ptr(), attr.to_sys(), value) })
    }

    /// Sets the default action taken when the loaded filter does not match the architecture
    /// of the executing application.
    ///
    /// Defaults to on (`action` == [`ScmpAction::KillThread`]).
    ///
    /// # Arguments
    ///
    /// * `action` - An action to be taken on a syscall for an architecture not in the filter.
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered setting the attribute, an error will be returned.
    ///
    /// # Examples
    ///
    ///  ```
    /// # use libseccomp::*;
    /// let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
    /// ctx.set_act_badarch(ScmpAction::KillProcess)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn set_act_badarch(&mut self, action: ScmpAction) -> Result<()> {
        self.set_filter_attr(ScmpFilterAttr::ActBadArch, action.to_sys())
    }

    /// Sets the state of the [`ScmpFilterAttr::CtlNnp`] attribute which will be applied
    /// on filter load.
    ///
    /// Settings this to off (`state` == `false`) means that loading the seccomp filter
    /// into the kernel fill fail if the CAP_SYS_ADMIN is missing.
    ///
    /// Defaults to on (`state` == `true`).
    ///
    /// # Arguments
    ///
    /// * `state` - A state flag to specify whether the [`ScmpFilterAttr::CtlNnp`] attribute should be enabled
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is
    /// encountered setting the attribute, an error will be returned.
    pub fn set_ctl_nnp(&mut self, state: bool) -> Result<()> {
        self.set_filter_attr(ScmpFilterAttr::CtlNnp, state.into())
    }

    /// Deprecated alias for [`ScmpFilterContext::set_ctl_nnp()`].
    #[deprecated(since = "0.2.3", note = "Use ScmpFilterContext::set_ctl_nnp().")]
    pub fn set_no_new_privs_bit(&mut self, state: bool) -> Result<()> {
        self.set_ctl_nnp(state)
    }

    /// Sets the state of the [`ScmpFilterAttr::CtlTsync`] attribute which will be applied
    /// on filter load.
    ///
    /// Settings this to on (`state` == `true`) means that the kernel should attempt to synchronize the filters
    /// across all threads on [`ScmpFilterContext::load()`].
    /// If the kernel is unable to synchronize all of the thread then the load operation will fail.
    /// The [`ScmpFilterAttr::CtlTsync`] attribute is only usable when the libseccomp API level 2 or higher
    /// is supported.
    /// If the libseccomp API level is less than 6, the [`ScmpFilterAttr::CtlTsync`] attribute is unusable
    /// with the userspace notification API simultaneously.
    ///
    /// Defaults to off (`state` == `false`).
    ///
    /// # Arguments
    ///
    /// * `state` - A state flag to specify whether the [`ScmpFilterAttr::CtlTsync`] attribute should be enabled
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter, an issue is encountered
    /// setting the attribute, or the libseccomp API level is less than 2, an error will be returned.
    pub fn set_ctl_tsync(&mut self, state: bool) -> Result<()> {
        ensure_supported_api("set_ctl_tsync", 2, ScmpVersion::from((2, 2, 0)))?;
        self.set_filter_attr(ScmpFilterAttr::CtlTsync, state.into())
    }

    /// Sets the state of the [`ScmpFilterAttr::CtlLog`] attribute which will be applied on filter load.
    ///
    /// Settings this to on (`state` == `true`) means that the kernel should log all filter
    /// actions taken except for the [`ScmpAction::Allow`] action.
    /// The [`ScmpFilterAttr::CtlLog`] attribute is only usable when the libseccomp API level 3 or higher
    /// is supported.
    ///
    /// Defaults to off (`state` == `false`).
    ///
    /// # Arguments
    ///
    /// * `state` - A state flag to specify whether the [`ScmpFilterAttr::CtlLog`] attribute should
    /// be enabled
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter, an issue is encountered
    /// setting the attribute, or the libseccomp API level is less than 3, an error will be returned.
    pub fn set_ctl_log(&mut self, state: bool) -> Result<()> {
        ensure_supported_api("set_ctl_log", 3, ScmpVersion::from((2, 4, 0)))?;
        self.set_filter_attr(ScmpFilterAttr::CtlLog, state.into())
    }

    /// Sets the state of the [`ScmpFilterAttr::CtlSsb`] attribute which will be applied on filter load.
    ///
    /// Settings this to on (`state` == `true`) disables Speculative Store Bypass mitigations for the filter.
    /// The [`ScmpFilterAttr::CtlSsb`] attribute is only usable when the libseccomp API level 4 or higher
    /// is supported.
    ///
    /// Defaults to off (`state` == `false`).
    ///
    /// # Arguments
    ///
    /// * `state` - A state flag to specify whether the [`ScmpFilterAttr::CtlSsb`] attribute should
    /// be enabled
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter, an issue is encountered
    /// setting the attribute, or the libseccomp API level is less than 4, an error will be returned.
    pub fn set_ctl_ssb(&mut self, state: bool) -> Result<()> {
        ensure_supported_api("set_ctl_ssb", 4, ScmpVersion::from((2, 5, 0)))?;
        self.set_filter_attr(ScmpFilterAttr::CtlSsb, state.into())
    }

    /// Sets the [`ScmpFilterAttr::CtlOptimize`] level which will be applied on filter load.
    ///
    /// By default the libseccomp generates a set of sequential "if" statements for each rule in the filter.
    /// [`set_syscall_priority()`](ScmpFilterContext::set_syscall_priority) can be used to prioritize the
    /// order for the default cause. The binary tree optimization sorts by syscall numbers and generates
    /// consistent O(log n) filter traversal for every rule in the filter. The binary tree may be advantageous
    /// for large filters. Note that [`set_syscall_priority()`](ScmpFilterContext::set_syscall_priority) is
    /// ignored when `level` == `2`.
    /// The [`ScmpFilterAttr::CtlOptimize`] attribute is only usable when the libseccomp API level 4 or higher
    /// is supported.
    ///
    /// The different optimization levels are described below:
    /// * `0` - Reserved value, not currently used.
    /// * `1` - Rules sorted by priority and complexity (DEFAULT).
    /// * `2` - Binary tree sorted by syscall number.
    ///
    /// # Arguments
    ///
    /// * `level` - The optimization level of the filter
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter, an issue is encountered
    /// setting the attribute, or the libseccomp API level is less than 4, an error will be returned.
    pub fn set_ctl_optimize(&mut self, level: u32) -> Result<()> {
        ensure_supported_api("set_ctl_optimize", 4, ScmpVersion::from((2, 5, 0)))?;
        self.set_filter_attr(ScmpFilterAttr::CtlOptimize, level)
    }

    /// Sets the state of the [`ScmpFilterAttr::ApiSysRawRc`] attribute which will be applied on filter load.
    ///
    /// Settings this to on (`state` == `true`) means that the libseccomp should pass system error codes
    /// back to the caller instead of the default -ECANCELED.
    /// The [`ScmpFilterAttr::ApiSysRawRc`] attribute is only usable when the libseccomp API level 4 or higher
    /// is supported.
    ///
    /// Defaults to off (`state` == `false`).
    ///
    /// # Arguments
    ///
    /// * `state` - A state flag to specify whether the [`ScmpFilterAttr::ApiSysRawRc`] attribute should
    /// be enabled
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter, an issue is encountered
    /// setting the attribute, or the libseccomp API level is less than 4, an error will be returned.
    pub fn set_api_sysrawrc(&mut self, state: bool) -> Result<()> {
        ensure_supported_api("set_api_sysrawrc", 4, ScmpVersion::from((2, 5, 0)))?;
        self.set_filter_attr(ScmpFilterAttr::ApiSysRawRc, state.into())
    }

    /// Outputs PFC(Pseudo Filter Code)-formatted, human-readable dump of a filter context's rules to a file.
    ///
    /// # Arguments
    ///
    /// * `fd` - A file descriptor to write to (must be open for writing)
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or  writing to the file fails,
    /// an error will be returned.
    pub fn export_pfc<T: AsRawFd>(&self, fd: &mut T) -> Result<()> {
        cvt(unsafe { seccomp_export_pfc(self.ctx.as_ptr(), fd.as_raw_fd()) })
    }

    /// Outputs BPF(Berkeley Packet Filter)-formatted, kernel-readable dump of a
    /// filter context's rules to a file.
    ///
    /// # Arguments
    ///
    /// * `fd` - A file descriptor to write to (must be open for writing)
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or  writing to the file fails,
    /// an error will be returned.
    pub fn export_bpf<T: AsRawFd>(&self, fd: &mut T) -> Result<()> {
        cvt(unsafe { seccomp_export_bpf(self.ctx.as_ptr(), fd.as_raw_fd()) })
    }

    /// Resets a filter context, removing all its existing state.
    ///
    /// # Arguments
    ///
    /// * `action` - A new default action to be taken for syscalls which do not match
    ///
    /// # Errors
    ///
    /// If this function is called with an invalid filter or an issue is encountered
    /// resetting the filter, an error will be returned.
    pub fn reset(&mut self, action: ScmpAction) -> Result<()> {
        cvt(unsafe { seccomp_reset(self.ctx.as_ptr(), action.to_sys()) })
    }

    /// Gets a raw pointer of a seccomp filter.
    ///
    /// This function returns a raw pointer to the [`scmp_filter_ctx`].
    /// The caller must ensure that the filter outlives the pointer this function returns,
    /// or else it will end up pointing to garbage.
    /// You may only modify the filter referenced by the pointer with functions intended
    /// for this (the once provided by [`libseccomp_sys`] crate).
    #[must_use]
    pub fn as_ptr(&self) -> scmp_filter_ctx {
        self.ctx.as_ptr()
    }
}

impl Drop for ScmpFilterContext {
    /// Releases a filter context, freeing its memory.
    ///
    /// After calling this function, the given filter is no longer valid and cannot be used.
    fn drop(&mut self) {
        unsafe { seccomp_release(self.ctx.as_ptr()) }
    }
}

/// Checks that the libseccomp version being used is equal to or greater than
/// the specified version.
///
/// This function returns `Ok(true)` if the libseccomp version is equal to
/// or greater than the specified version, `Ok(false)` otherwise.
///
/// # Arguments
///
/// * `expected` - The libseccomp version you want to check
///
/// # Errors
///
/// If an issue is encountered getting the current version, an error will be returned.
pub fn check_version(expected: ScmpVersion) -> Result<bool> {
    let current = ScmpVersion::current()?;

    if current.major == expected.major
        && (current.minor > expected.minor
            || (current.minor == expected.minor && current.micro >= expected.micro))
    {
        Ok(true)
    } else {
        Ok(false)
    }
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

/// Ensures that the libseccomp version is equal to or greater than the
/// specified version.
///
/// # Arguments
///
/// * `msg` - An arbitrary non-empty operation description, used as a part
/// of the error message returned.
/// * `expected` - The libseccomp version you want to check
///
/// # Errors
///
/// If the libseccomp version being used is less than the specified version,
/// an error will be returned.
// This function will not be used if the libseccomp version is less than 2.5.0.
#[allow(dead_code)]
fn ensure_supported_version(msg: &str, expected: ScmpVersion) -> Result<()> {
    if check_version(expected)? {
        Ok(())
    } else {
        let current = ScmpVersion::current()?;
        Err(SeccompError::new(Common(format!(
            "{} requires libseccomp >= {} (current version: {})",
            msg, expected, current,
        ))))
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
fn ensure_supported_api(msg: &str, min_level: u32, expected: ScmpVersion) -> Result<()> {
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

/// Deprecated alias for [`ScmpVersion::current()`].
#[deprecated(since = "0.2.0", note = "Use ScmpVersion::current().")]
pub fn get_library_version() -> Result<ScmpVersion> {
    ScmpVersion::current()
}

/// Deprecated alias for [`ScmpArch::native()`].
#[deprecated(since = "0.2.0", note = "Use ScmpArch::native().")]
pub fn get_native_arch() -> Result<ScmpArch> {
    ScmpArch::native()
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

/// Resets the libseccomp library's global state.
///
/// This function resets the (internal) global state of the libseccomp library,
/// this includes any notification file descriptors retrieved by
/// [`get_notify_fd`](ScmpFilterContext::get_notify_fd).
/// Normally you do not need this but it may be required to continue using
/// the libseccomp library after a `fork()`/`clone()` to ensure the API level
/// and user notification state is properly reset.
///
/// # Errors
///
/// If the linked libseccomp library is older than v2.5.1 this function will
/// return an error.
pub fn reset_global_state() -> Result<()> {
    cvt(unsafe { seccomp_reset(std::ptr::null_mut(), 0) })
}

/// Retrieves the name of a syscall from its number for a given architecture.
///
/// This function returns a string containing the name of the syscall.
///
/// # Arguments
///
/// * `arch` - A valid architecture token
/// * `syscall` - The number of syscall
///
/// # Errors
///
/// If the syscall is unrecognized or an issue occurs or an issue is
/// encountered getting the name of the syscall, an error will be returned.
#[deprecated(since = "0.2.3", note = "Use ScmpSyscall::get_name_by_arch instead.")]
pub fn get_syscall_name_from_arch(arch: ScmpArch, syscall: i32) -> Result<String> {
    ScmpSyscall::from_sys(syscall).get_name_by_arch(arch)
}

/// Gets the number of a syscall by name for a given architecture's ABI.
///
/// This function returns the number of the syscall.
///
/// # Arguments
///
/// * `name` - The name of a syscall
/// * `arch` - An architecture token as `Option` type
/// If arch argument is `None`, the functions returns the number of a syscall
/// on the kernel's native architecture.
///
/// # Errors
///
/// If an invalid string for the syscall name is specified or a syscall with that
/// name is not found, an error will be returned.
#[deprecated(since = "0.2.3", note = "Use ScmpSyscall::from_name* instead.")]
pub fn get_syscall_from_name(name: &str, arch: Option<ScmpArch>) -> Result<i32> {
    Ok(ScmpSyscall::from_name_by_arch(name, arch.unwrap_or(ScmpArch::Native))?.to_sys())
}

fn cvt(ret: i32) -> Result<()> {
    if ret == 0 {
        Ok(())
    } else {
        Err(SeccompError::new(Errno(ret)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_supported_version() {
        assert!(ensure_supported_version("test", ScmpVersion::from((2, 4, 0))).is_ok());
        assert!(ensure_supported_version("test", ScmpVersion::from((100, 100, 100))).is_err());
    }

    #[test]
    fn test_ensure_supported_api() {
        assert!(ensure_supported_api("test", 3, ScmpVersion::from((2, 4, 0))).is_ok());
        assert!(ensure_supported_api("test", 100, ScmpVersion::from((2, 4, 0))).is_err());
    }

    #[test]
    fn test_as_ptr() {
        let ctx = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();
        assert_eq!(ctx.as_ptr(), ctx.ctx.as_ptr());
    }
}
