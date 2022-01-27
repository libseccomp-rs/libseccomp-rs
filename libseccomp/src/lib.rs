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
#[cfg(any(libseccomp_v2_5, doc))]
pub mod notify;

use error::ErrorKind::*;
use error::{Result, SeccompError};
use libseccomp_sys::*;
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::unix::io::AsRawFd;
use std::ptr::NonNull;

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

/// Represents filter attributes.
///
/// You can set/get the attributes of a filter context with
/// [`ScmpFilterContext::set_filter_attr`] and [`ScmpFilterContext::get_filter_attr`] methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScmpFilterAttr {
    /// The default filter action as specified in the call to seccomp reset.
    ActDefault,
    /// The filter action taken when the loaded filter does not
    /// match the architecture of the executing application.
    ActBadArch,
    /// A flag to specify if the NO_NEW_PRIVS functionality should
    /// be enabled before loading the seccomp filter into the kernel.
    CtlNnp,
    /// A flag to specify if the kernel should attempt to
    /// synchronize the filters across all threads on seccomp load.
    CtlTsync,
    /// A flag to specify if the libseccomp should allow filter rules
    /// to be created for the -1 syscall.
    ApiTskip,
    /// A flag to specify if the kernel should log all filter
    /// actions taken except for the [`ScmpAction::Allow`] action.
    CtlLog,
    /// A flag to disable Speculative Store Bypass mitigations for
    /// this filter.
    CtlSsb,
    /// A flag to specify the optimization level of the seccomp
    /// filter.
    CtlOptimize,
    /// A flag to specify if the libseccomp should pass system error
    /// codes back to the caller instead of the default -ECANCELED.
    ApiSysRawRc,
}

impl ScmpFilterAttr {
    fn to_sys(self) -> scmp_filter_attr {
        match self {
            Self::ActDefault => scmp_filter_attr::SCMP_FLTATR_ACT_DEFAULT,
            Self::ActBadArch => scmp_filter_attr::SCMP_FLTATR_ACT_BADARCH,
            Self::CtlNnp => scmp_filter_attr::SCMP_FLTATR_CTL_NNP,
            Self::CtlTsync => scmp_filter_attr::SCMP_FLTATR_CTL_TSYNC,
            Self::ApiTskip => scmp_filter_attr::SCMP_FLTATR_API_TSKIP,
            Self::CtlLog => scmp_filter_attr::SCMP_FLTATR_CTL_LOG,
            Self::CtlSsb => scmp_filter_attr::SCMP_FLTATR_CTL_SSB,
            Self::CtlOptimize => scmp_filter_attr::SCMP_FLTATR_CTL_OPTIMIZE,
            Self::ApiSysRawRc => scmp_filter_attr::SCMP_FLTATR_API_SYSRAWRC,
        }
    }
}

impl std::str::FromStr for ScmpFilterAttr {
    type Err = SeccompError;

    /// Converts string seccomp filter attribute to `ScmpFilterAttr`.
    ///
    /// # Arguments
    ///
    /// * `attr` - A string filter attribute, e.g. `SCMP_FLTATR_*`.
    ///
    /// See the [seccomp_attr_set(3)] man page for details on valid filter attribute values.
    ///
    /// [seccomp_attr_set(3)]: https://www.man7.org/linux/man-pages/man3/seccomp_attr_set.3.html
    ///
    /// # Errors
    ///
    /// If an invalid filter attribute is specified, an error will be returned.
    fn from_str(attr: &str) -> Result<Self> {
        match attr {
            "SCMP_FLTATR_ACT_DEFAULT" => Ok(Self::ActDefault),
            "SCMP_FLTATR_ACT_BADARCH" => Ok(Self::ActBadArch),
            "SCMP_FLTATR_CTL_NNP" => Ok(Self::CtlNnp),
            "SCMP_FLTATR_CTL_TSYNC" => Ok(Self::CtlTsync),
            "SCMP_FLTATR_API_TSKIP" => Ok(Self::ApiTskip),
            "SCMP_FLTATR_CTL_LOG" => Ok(Self::CtlLog),
            "SCMP_FLTATR_CTL_SSB" => Ok(Self::CtlSsb),
            "SCMP_FLTATR_CTL_OPTIMIZE" => Ok(Self::CtlOptimize),
            "SCMP_FLTATR_API_SYSRAWRC" => Ok(Self::ApiSysRawRc),
            _ => Err(SeccompError::new(ParseError)),
        }
    }
}

/// Represents a comparison operator which can be used in a filter rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScmpCompareOp {
    /// Not equal
    NotEqual,
    /// Less than
    Less,
    /// Less than or equal
    LessOrEqual,
    /// Equal
    Equal,
    /// Greater than or equal
    GreaterEqual,
    /// Greater than
    Greater,
    /// Masked equality
    ///
    /// This works like `Equal` with the exception that the syscall argument is
    /// masked with `mask` via an bitwise AND (i.e. you can check specific bits in the
    /// argument).
    MaskedEqual(#[doc = "mask"] u64),
}

impl ScmpCompareOp {
    const fn to_sys(self) -> scmp_compare {
        match self {
            Self::NotEqual => scmp_compare::SCMP_CMP_NE,
            Self::Less => scmp_compare::SCMP_CMP_LT,
            Self::LessOrEqual => scmp_compare::SCMP_CMP_LE,
            Self::Equal => scmp_compare::SCMP_CMP_EQ,
            Self::GreaterEqual => scmp_compare::SCMP_CMP_GE,
            Self::Greater => scmp_compare::SCMP_CMP_GT,
            Self::MaskedEqual(_) => scmp_compare::SCMP_CMP_MASKED_EQ,
        }
    }
}

impl std::str::FromStr for ScmpCompareOp {
    type Err = SeccompError;

    /// Converts string seccomp comparison operator to `ScmpCompareOp`.
    ///
    /// # Arguments
    ///
    /// * `cmp_op` - A string comparison operator, e.g. `SCMP_CMP_*`.
    ///
    /// See the [seccomp_rule_add(3)] man page for details on valid comparison operator values.
    ///
    /// [seccomp_rule_add(3)]: https://www.man7.org/linux/man-pages/man3/seccomp_rule_add.3.html
    ///
    /// # Errors
    ///
    /// If an invalid comparison operator is specified, an error will be returned.
    fn from_str(cmp_op: &str) -> Result<Self> {
        match cmp_op {
            "SCMP_CMP_NE" => Ok(Self::NotEqual),
            "SCMP_CMP_LT" => Ok(Self::Less),
            "SCMP_CMP_LE" => Ok(Self::LessOrEqual),
            "SCMP_CMP_EQ" => Ok(Self::Equal),
            "SCMP_CMP_GE" => Ok(Self::GreaterEqual),
            "SCMP_CMP_GT" => Ok(Self::Greater),
            "SCMP_CMP_MASKED_EQ" => Ok(Self::MaskedEqual(u64::default())),
            _ => Err(SeccompError::new(ParseError)),
        }
    }
}

/// Represents a rule in a libseccomp filter context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ScmpArgCompare(scmp_arg_cmp);

impl ScmpArgCompare {
    /// Creates and returns a new condition to attach to a filter rule.
    ///
    /// The rule will match if the comparison of argument `arg` (zero-indexed argument
    /// of the syscall) with the value provided by `datum` using the compare operator
    /// provided by `op` is true.
    ///
    /// You can use the [`scmp_cmp!`](crate::scmp_cmp) macro instead of this to create
    /// `ScmpArgCompare` in a more elegant way.
    ///
    /// # Arguments
    ///
    /// * `arg` - The number of the argument
    /// * `op` - A comparison operator
    /// * `datum` - A value to compare to
    #[must_use]
    pub const fn new(arg: u32, op: ScmpCompareOp, datum: u64) -> Self {
        if let ScmpCompareOp::MaskedEqual(mask) = op {
            Self(scmp_arg_cmp {
                arg,
                op: op.to_sys(),
                datum_a: mask,
                datum_b: datum,
            })
        } else {
            Self(scmp_arg_cmp {
                arg,
                op: op.to_sys(),
                datum_a: datum,
                datum_b: 0,
            })
        }
    }
}

impl From<ScmpArgCompare> for scmp_arg_cmp {
    fn from(v: ScmpArgCompare) -> scmp_arg_cmp {
        v.0
    }
}

impl From<&ScmpArgCompare> for scmp_arg_cmp {
    fn from(v: &ScmpArgCompare) -> scmp_arg_cmp {
        v.0
    }
}

#[rustfmt::skip]
#[doc(hidden)]
#[macro_export]
macro_rules! __private_scmp_cmp_arg {
    (arg0) => { 0 };
    (arg1) => { 1 };
    (arg2) => { 2 };
    (arg3) => { 3 };
    (arg4) => { 4 };
    (arg5) => { 5 };
}

/// A macro to create [`ScmpArgCompare`] in a more elegant way.
///
/// ```
/// use libseccomp::{ScmpArgCompare, ScmpCompareOp, scmp_cmp};
///
/// assert_eq!(
///     scmp_cmp!($arg0 != 123),
///     ScmpArgCompare::new(0, ScmpCompareOp::NotEqual, 123),
/// );
/// assert_eq!(
///     scmp_cmp!($arg1 < 123),
///     ScmpArgCompare::new(1, ScmpCompareOp::Less, 123),
/// );
/// assert_eq!(
///     scmp_cmp!($arg2 <= 123),
///     ScmpArgCompare::new(2, ScmpCompareOp::LessOrEqual, 123),
/// );
/// assert_eq!(
///     scmp_cmp!($arg3 == 123),
///     ScmpArgCompare::new(3, ScmpCompareOp::Equal, 123),
/// );
/// assert_eq!(
///     scmp_cmp!($arg4 >= 123),
///     ScmpArgCompare::new(4, ScmpCompareOp::GreaterEqual, 123),
/// );
/// assert_eq!(
///     scmp_cmp!($arg5 > 123),
///     ScmpArgCompare::new(5, ScmpCompareOp::Greater, 123),
/// );
/// assert_eq!(
///     scmp_cmp!($arg0 & 0x0f0 == 123),
///     ScmpArgCompare::new(0, ScmpCompareOp::MaskedEqual(0x0f0), 123),
/// );
/// ```
#[macro_export]
macro_rules! scmp_cmp {
    ($_:tt $arg:tt != $datum:expr) => {
        $crate::ScmpArgCompare::new(
            $crate::__private_scmp_cmp_arg!($arg),
            $crate::ScmpCompareOp::NotEqual,
            $datum,
        )
    };
    ($_:tt $arg:tt < $datum:expr) => {
        $crate::ScmpArgCompare::new(
            $crate::__private_scmp_cmp_arg!($arg),
            $crate::ScmpCompareOp::Less,
            $datum,
        )
    };
    ($_:tt $arg:tt <= $datum:expr) => {
        $crate::ScmpArgCompare::new(
            $crate::__private_scmp_cmp_arg!($arg),
            $crate::ScmpCompareOp::LessOrEqual,
            $datum,
        )
    };
    ($_:tt $arg:tt == $datum:expr) => {
        $crate::ScmpArgCompare::new(
            $crate::__private_scmp_cmp_arg!($arg),
            $crate::ScmpCompareOp::Equal,
            $datum,
        )
    };
    ($_:tt $arg:tt >= $datum:expr) => {
        $crate::ScmpArgCompare::new(
            $crate::__private_scmp_cmp_arg!($arg),
            $crate::ScmpCompareOp::GreaterEqual,
            $datum,
        )
    };
    ($_:tt $arg:tt > $datum:expr) => {
        $crate::ScmpArgCompare::new(
            $crate::__private_scmp_cmp_arg!($arg),
            $crate::ScmpCompareOp::Greater,
            $datum,
        )
    };
    ($_:tt $arg:tt & $mask:tt == $datum:expr) => {
        $crate::ScmpArgCompare::new(
            $crate::__private_scmp_cmp_arg!($arg),
            $crate::ScmpCompareOp::MaskedEqual($mask),
            $datum,
        )
    };
}

/// Represents an action to be taken on a filter rule match in the libseccomp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScmpAction {
    /// Kills the process.
    KillProcess,
    /// Kills the thread.
    KillThread,
    /// Throws a SIGSYS signal.
    Trap,
    /// Triggers a userspace notification.  
    /// NOTE: This action is only usable when the libseccomp API level 6
    /// or higher is supported.
    Notify,
    /// Returns the specified error code.  
    /// NOTE: You can only use integers from 0 to `u16::MAX`.
    Errno(i32),
    /// Notifies a tracing process with the specified value.
    Trace(u16),
    /// Allows the syscall to be executed after the action has been logged.
    Log,
    /// Allows the syscall to be executed.
    Allow,
}

impl ScmpAction {
    fn to_sys(self) -> u32 {
        match self {
            Self::KillProcess => SCMP_ACT_KILL_PROCESS,
            Self::KillThread => SCMP_ACT_KILL_THREAD,
            Self::Trap => SCMP_ACT_TRAP,
            Self::Notify => SCMP_ACT_NOTIFY,
            Self::Errno(x) => SCMP_ACT_ERRNO(x as u16),
            Self::Trace(x) => SCMP_ACT_TRACE(x),
            Self::Log => SCMP_ACT_LOG,
            Self::Allow => SCMP_ACT_ALLOW,
        }
    }

    fn from_sys(val: u32) -> Result<Self> {
        match val & SCMP_ACT_MASK {
            SCMP_ACT_KILL_PROCESS => Ok(Self::KillProcess),
            SCMP_ACT_KILL_THREAD => Ok(Self::KillThread),
            SCMP_ACT_TRAP => Ok(Self::Trap),
            SCMP_ACT_NOTIFY => Ok(Self::Notify),
            SCMP_ACT_ERRNO_MASK => Ok(Self::Errno(val as u16 as i32)),
            SCMP_ACT_TRACE_MASK => Ok(Self::Trace(val as u16)),
            SCMP_ACT_LOG => Ok(Self::Log),
            SCMP_ACT_ALLOW => Ok(Self::Allow),
            _ => Err(SeccompError::new(ParseError)),
        }
    }

    /// Converts string seccomp action to `ScmpAction`.
    ///
    /// # Arguments
    ///
    /// * `action` - A string action, e.g. `SCMP_ACT_*`.
    ///
    /// See the [seccomp_rule_add(3)] man page for details on valid action values.
    ///
    /// [seccomp_rule_add(3)]: https://www.man7.org/linux/man-pages/man3/seccomp_rule_add.3.html
    ///
    /// # Errors
    ///
    /// If an invalid action is specified or a value on `"SCMP_ACT_TRACE"` is not in the
    /// range from 0 to `u16::MAX`, an error will be returned.
    pub fn from_str(action: &str, val: Option<i32>) -> Result<Self> {
        match action {
            "SCMP_ACT_KILL_PROCESS" => Ok(Self::KillProcess),
            "SCMP_ACT_KILL_THREAD" => Ok(Self::KillThread),
            "SCMP_ACT_KILL" => Ok(Self::KillThread),
            "SCMP_ACT_TRAP" => Ok(Self::Trap),
            "SCMP_ACT_NOTIFY" => Ok(Self::Notify),
            "SCMP_ACT_ERRNO" => match val {
                Some(v) => Ok(Self::Errno(v)),
                None => Err(SeccompError::new(ParseError)),
            },
            "SCMP_ACT_TRACE" => match val {
                Some(v) => Ok(Self::Trace(v.try_into()?)),
                None => Err(SeccompError::new(ParseError)),
            },
            "SCMP_ACT_LOG" => Ok(Self::Log),
            "SCMP_ACT_ALLOW" => Ok(Self::Allow),
            _ => Err(SeccompError::new(ParseError)),
        }
    }
}

/// Represents a CPU architecture.
/// Seccomp can restrict syscalls on a per-architecture basis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScmpArch {
    /// The native architecture token
    Native,
    /// The x86 (32-bit) architecture token
    X86,
    /// The x86-64 (64-bit) architecture token
    X8664,
    /// The x32 (32-bit x86_64) architecture token
    X32,
    /// The ARM architecture token
    Arm,
    /// The AARCH64 architecture token
    Aarch64,
    /// The MIPS architecture token
    Mips,
    /// The MIPS (64-bit) architecture token
    Mips64,
    /// The MIPS64N32 architecture token
    Mips64N32,
    /// The MIPSEL architecture token
    Mipsel,
    /// The MIPSEL (64-bit) architecture token
    Mipsel64,
    /// The MIPSEL64N32 architecture token
    Mipsel64N32,
    /// The PowerPC architecture token
    Ppc,
    /// The PowerPC (64-bit) architecture token
    Ppc64,
    /// The PowerPC64LE architecture token
    Ppc64Le,
    /// The S390 architecture token
    S390,
    /// The S390X architecture token
    S390X,
    /// The PA-RISC hppa architecture token
    Parisc,
    /// The PA-RISC (64-bit) hppa architecture token
    Parisc64,
    /// The RISC-V architecture token
    Riscv64,
}

impl ScmpArch {
    fn to_sys(self) -> u32 {
        match self {
            Self::Native => SCMP_ARCH_NATIVE,
            Self::X86 => SCMP_ARCH_X86,
            Self::X8664 => SCMP_ARCH_X86_64,
            Self::X32 => SCMP_ARCH_X32,
            Self::Arm => SCMP_ARCH_ARM,
            Self::Aarch64 => SCMP_ARCH_AARCH64,
            Self::Mips => SCMP_ARCH_MIPS,
            Self::Mips64 => SCMP_ARCH_MIPS64,
            Self::Mips64N32 => SCMP_ARCH_MIPS64N32,
            Self::Mipsel => SCMP_ARCH_MIPSEL,
            Self::Mipsel64 => SCMP_ARCH_MIPSEL64,
            Self::Mipsel64N32 => SCMP_ARCH_MIPSEL64N32,
            Self::Ppc => SCMP_ARCH_PPC,
            Self::Ppc64 => SCMP_ARCH_PPC64,
            Self::Ppc64Le => SCMP_ARCH_PPC64LE,
            Self::S390 => SCMP_ARCH_S390,
            Self::S390X => SCMP_ARCH_S390X,
            Self::Parisc => SCMP_ARCH_PARISC,
            Self::Parisc64 => SCMP_ARCH_PARISC64,
            Self::Riscv64 => SCMP_ARCH_RISCV64,
        }
    }

    fn from_sys(arch: u32) -> Result<Self> {
        match arch {
            SCMP_ARCH_NATIVE => Ok(Self::Native),
            SCMP_ARCH_X86 => Ok(Self::X86),
            SCMP_ARCH_X86_64 => Ok(Self::X8664),
            SCMP_ARCH_X32 => Ok(Self::X32),
            SCMP_ARCH_ARM => Ok(Self::Arm),
            SCMP_ARCH_AARCH64 => Ok(Self::Aarch64),
            SCMP_ARCH_MIPS => Ok(Self::Mips),
            SCMP_ARCH_MIPS64 => Ok(Self::Mips64),
            SCMP_ARCH_MIPS64N32 => Ok(Self::Mips64N32),
            SCMP_ARCH_MIPSEL => Ok(Self::Mipsel),
            SCMP_ARCH_MIPSEL64 => Ok(Self::Mipsel64),
            SCMP_ARCH_MIPSEL64N32 => Ok(Self::Mipsel64N32),
            SCMP_ARCH_PPC => Ok(Self::Ppc),
            SCMP_ARCH_PPC64 => Ok(Self::Ppc64),
            SCMP_ARCH_PPC64LE => Ok(Self::Ppc64Le),
            SCMP_ARCH_S390 => Ok(Self::S390),
            SCMP_ARCH_S390X => Ok(Self::S390X),
            SCMP_ARCH_PARISC => Ok(Self::Parisc),
            SCMP_ARCH_PARISC64 => Ok(Self::Parisc64),
            SCMP_ARCH_RISCV64 => Ok(Self::Riscv64),
            _ => Err(SeccompError::new(ParseError)),
        }
    }

    /// Returns the system's native architecture.
    ///
    /// # Errors
    ///
    /// If this function encounters an issue while getting the native architecture,
    /// an error will be returned.
    pub fn native() -> Result<Self> {
        let ret = unsafe { seccomp_arch_native() };

        match Self::from_sys(ret) {
            Ok(v) => Ok(v),
            Err(_) => Err(SeccompError::new(Common(
                "Could not get native architecture".to_string(),
            ))),
        }
    }
}

impl std::str::FromStr for ScmpArch {
    type Err = SeccompError;

    /// Converts string seccomp architecture to `ScmpArch`.
    ///
    /// # Arguments
    ///
    /// * `arch` - A string architecture, e.g. `SCMP_ARCH_*`.
    ///
    /// See the [seccomp_arch_add(3)] man page for details on valid architecture values.
    ///
    /// [seccomp_arch_add(3)]: https://www.man7.org/linux/man-pages/man3/seccomp_arch_add.3.html
    ///
    /// # Errors
    ///
    /// If an invalid architecture is specified, an error will be returned.
    fn from_str(arch: &str) -> Result<Self> {
        match arch {
            "SCMP_ARCH_NATIVE" => Ok(Self::Native),
            "SCMP_ARCH_X86" => Ok(Self::X86),
            "SCMP_ARCH_X86_64" => Ok(Self::X8664),
            "SCMP_ARCH_X32" => Ok(Self::X32),
            "SCMP_ARCH_ARM" => Ok(Self::Arm),
            "SCMP_ARCH_AARCH64" => Ok(Self::Aarch64),
            "SCMP_ARCH_MIPS" => Ok(Self::Mips),
            "SCMP_ARCH_MIPS64" => Ok(Self::Mips64),
            "SCMP_ARCH_MIPS64N32" => Ok(Self::Mips64N32),
            "SCMP_ARCH_MIPSEL" => Ok(Self::Mipsel),
            "SCMP_ARCH_MIPSEL64" => Ok(Self::Mipsel64),
            "SCMP_ARCH_MIPSEL64N32" => Ok(Self::Mipsel64N32),
            "SCMP_ARCH_PPC" => Ok(Self::Ppc),
            "SCMP_ARCH_PPC64" => Ok(Self::Ppc64),
            "SCMP_ARCH_PPC64LE" => Ok(Self::Ppc64Le),
            "SCMP_ARCH_S390" => Ok(Self::S390),
            "SCMP_ARCH_S390X" => Ok(Self::S390X),
            "SCMP_ARCH_PARISC" => Ok(Self::Parisc),
            "SCMP_ARCH_PARISC64" => Ok(Self::Parisc64),
            "SCMP_ARCH_RISCV64" => Ok(Self::Riscv64),
            _ => Err(SeccompError::new(ParseError)),
        }
    }
}

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
    /// NOTE: This functions is probably not what you want.
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

mod private {
    pub trait Sealed {}

    impl Sealed for super::ScmpSyscall {}
    impl Sealed for i32 {}
}

pub trait Syscall: private::Sealed {
    fn to_syscall_nr(self) -> i32;
}
impl Syscall for ScmpSyscall {
    fn to_syscall_nr(self) -> i32 {
        self.to_sys()
    }
}

impl Syscall for i32 {
    fn to_syscall_nr(self) -> i32 {
        self
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
        let ret = unsafe { seccomp_merge(self.ctx.as_ptr(), src.ctx.as_ptr()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

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
    /// assert!(!ctx.is_arch_present(ScmpArch::Aarch64)?);
    /// ctx.add_arch(ScmpArch::Aarch64)?;
    /// assert!(ctx.is_arch_present(ScmpArch::Aarch64)?);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn is_arch_present(&self, arch: ScmpArch) -> Result<bool> {
        let ret = unsafe { seccomp_arch_exist(self.ctx.as_ptr(), arch.to_sys()) };

        if ret != 0 {
            if ret == -(libc::EEXIST as i32) {
                return Ok(false);
            }
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(true)
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
    pub fn add_rule<S: Syscall>(&mut self, action: ScmpAction, syscall: S) -> Result<()> {
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
    pub fn add_rule_conditional<S: Syscall>(
        &mut self,
        action: ScmpAction,
        syscall: S,
        comparators: &[ScmpArgCompare],
    ) -> Result<()> {
        let ret = unsafe {
            seccomp_rule_add_array(
                self.ctx.as_ptr(),
                action.to_sys(),
                syscall.to_syscall_nr(),
                comparators.len() as u32,
                comparators.as_ptr() as *const scmp_arg_cmp,
            )
        };

        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
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
    pub fn add_rule_exact<S: Syscall>(&mut self, action: ScmpAction, syscall: S) -> Result<()> {
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
    pub fn add_rule_conditional_exact<S: Syscall>(
        &mut self,
        action: ScmpAction,
        syscall: S,
        comparators: &[ScmpArgCompare],
    ) -> Result<()> {
        let ret = unsafe {
            seccomp_rule_add_exact_array(
                self.ctx.as_ptr(),
                action.to_sys(),
                syscall.to_syscall_nr(),
                comparators.len() as u32,
                comparators.as_ptr() as *const scmp_arg_cmp,
            )
        };

        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
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
        let ret = unsafe { seccomp_load(self.ctx.as_ptr()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
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
    pub fn set_syscall_priority<S: Syscall>(&mut self, syscall: S, priority: u8) -> Result<()> {
        let ret = unsafe {
            seccomp_syscall_priority(self.ctx.as_ptr(), syscall.to_syscall_nr(), priority)
        };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
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

        let ret = unsafe { seccomp_attr_get(self.ctx.as_ptr(), attr.to_sys(), &mut attribute) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

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
        let ret = unsafe { seccomp_attr_set(self.ctx.as_ptr(), attr.to_sys(), value) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
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
    /// Filters with the [`ScmpFilterAttr::CtlNnp`] attribute set to on (`state` == `true`) can only
    /// be loaded if the process has the CAP_SYS_ADMIN capability.
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
        let ret = unsafe { seccomp_export_pfc(self.ctx.as_ptr(), fd.as_raw_fd()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
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
        let ret = unsafe { seccomp_export_bpf(self.ctx.as_ptr(), fd.as_raw_fd()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
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
        let ret = unsafe { seccomp_reset(self.ctx.as_ptr(), action.to_sys()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
    }

    /// Gets a raw pointer of a seccomp filter.
    ///
    /// This function return a raw pointer to the [`scmp_filter_ctx`].
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
    let ret = unsafe { seccomp_reset(std::ptr::null_mut(), 0) };
    if ret != 0 {
        return Err(SeccompError::new(Errno(ret)));
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{stdout, Error};
    use std::str::FromStr;

    macro_rules! syscall_assert {
        ($e1: expr, $e2: expr) => {
            let mut errno: i32 = 0;
            if $e1 < 0 {
                errno = -Error::last_os_error().raw_os_error().unwrap()
            }
            assert_eq!(errno, $e2);
        };
    }

    #[test]
    fn test_parse_filter_attr() {
        let test_data = [
            ("SCMP_FLTATR_ACT_DEFAULT", ScmpFilterAttr::ActDefault),
            ("SCMP_FLTATR_ACT_BADARCH", ScmpFilterAttr::ActBadArch),
            ("SCMP_FLTATR_CTL_NNP", ScmpFilterAttr::CtlNnp),
            ("SCMP_FLTATR_CTL_TSYNC", ScmpFilterAttr::CtlTsync),
            ("SCMP_FLTATR_API_TSKIP", ScmpFilterAttr::ApiTskip),
            ("SCMP_FLTATR_CTL_LOG", ScmpFilterAttr::CtlLog),
            ("SCMP_FLTATR_CTL_SSB", ScmpFilterAttr::CtlSsb),
            ("SCMP_FLTATR_CTL_OPTIMIZE", ScmpFilterAttr::CtlOptimize),
            ("SCMP_FLTATR_API_SYSRAWRC", ScmpFilterAttr::ApiSysRawRc),
        ];
        for data in test_data {
            assert_eq!(
                ScmpFilterAttr::from_str(data.0).unwrap().to_sys(),
                data.1.to_sys()
            );
        }
        assert!(ScmpFilterAttr::from_str("SCMP_INVALID_FLAG").is_err());
    }

    #[test]
    fn test_parse_compare_op() {
        let test_data = [
            ("SCMP_CMP_NE", ScmpCompareOp::NotEqual),
            ("SCMP_CMP_LT", ScmpCompareOp::Less),
            ("SCMP_CMP_LE", ScmpCompareOp::LessOrEqual),
            ("SCMP_CMP_EQ", ScmpCompareOp::Equal),
            ("SCMP_CMP_GE", ScmpCompareOp::GreaterEqual),
            ("SCMP_CMP_GT", ScmpCompareOp::Greater),
            (
                "SCMP_CMP_MASKED_EQ",
                ScmpCompareOp::MaskedEqual(u64::default()),
            ),
        ];

        for data in test_data {
            assert_eq!(
                ScmpCompareOp::from_str(data.0).unwrap().to_sys(),
                data.1.to_sys()
            );
        }
        assert!(ScmpCompareOp::from_str("SCMP_INVALID_FLAG").is_err());
    }

    #[test]
    fn test_parse_action() {
        let test_data = [
            ("SCMP_ACT_KILL_PROCESS", ScmpAction::KillProcess),
            ("SCMP_ACT_KILL_THREAD", ScmpAction::KillThread),
            ("SCMP_ACT_KILL", ScmpAction::KillThread),
            ("SCMP_ACT_TRAP", ScmpAction::Trap),
            ("SCMP_ACT_NOTIFY", ScmpAction::Notify),
            ("SCMP_ACT_ERRNO", ScmpAction::Errno(10)),
            ("SCMP_ACT_TRACE", ScmpAction::Trace(10)),
            ("SCMP_ACT_LOG", ScmpAction::Log),
            ("SCMP_ACT_ALLOW", ScmpAction::Allow),
        ];

        for data in test_data {
            if data.0 == "SCMP_ACT_ERRNO" || data.0 == "SCMP_ACT_TRACE" {
                assert_eq!(
                    ScmpAction::from_sys(ScmpAction::from_str(data.0, Some(10)).unwrap().to_sys())
                        .unwrap(),
                    data.1
                );
            } else {
                assert_eq!(
                    ScmpAction::from_sys(ScmpAction::from_str(data.0, None).unwrap().to_sys())
                        .unwrap(),
                    data.1
                );
            }
        }
        assert!(ScmpAction::from_str("SCMP_ACT_ERRNO", None).is_err());
        assert!(ScmpAction::from_str("SCMP_ACT_TRACE", None).is_err());
        assert!(ScmpAction::from_str("SCMP_INVALID_FLAG", None).is_err());
        assert!(ScmpAction::from_sys(0x00010000).is_err());
    }

    #[test]
    fn test_parse_arch() {
        let test_data = [
            ("SCMP_ARCH_NATIVE", ScmpArch::Native),
            ("SCMP_ARCH_X86", ScmpArch::X86),
            ("SCMP_ARCH_X86_64", ScmpArch::X8664),
            ("SCMP_ARCH_X32", ScmpArch::X32),
            ("SCMP_ARCH_ARM", ScmpArch::Arm),
            ("SCMP_ARCH_AARCH64", ScmpArch::Aarch64),
            ("SCMP_ARCH_MIPS", ScmpArch::Mips),
            ("SCMP_ARCH_MIPS64", ScmpArch::Mips64),
            ("SCMP_ARCH_MIPS64N32", ScmpArch::Mips64N32),
            ("SCMP_ARCH_MIPSEL", ScmpArch::Mipsel),
            ("SCMP_ARCH_MIPSEL64", ScmpArch::Mipsel64),
            ("SCMP_ARCH_MIPSEL64N32", ScmpArch::Mipsel64N32),
            ("SCMP_ARCH_PPC", ScmpArch::Ppc),
            ("SCMP_ARCH_PPC64", ScmpArch::Ppc64),
            ("SCMP_ARCH_PPC64LE", ScmpArch::Ppc64Le),
            ("SCMP_ARCH_S390", ScmpArch::S390),
            ("SCMP_ARCH_S390X", ScmpArch::S390X),
            ("SCMP_ARCH_PARISC", ScmpArch::Parisc),
            ("SCMP_ARCH_PARISC64", ScmpArch::Parisc64),
            ("SCMP_ARCH_RISCV64", ScmpArch::Riscv64),
        ];

        for data in test_data {
            assert_eq!(
                ScmpArch::from_sys(ScmpArch::from_str(data.0).unwrap().to_sys()).unwrap(),
                data.1
            );
        }
        assert!(ScmpArch::from_str("SCMP_INVALID_FLAG").is_err());
        assert!(ScmpArch::from_sys(1).is_err());
    }

    #[test]
    fn test_check_version() {
        assert!(check_version(ScmpVersion::from((2, 4, 0))).unwrap());
        assert!(!check_version(ScmpVersion::from((100, 100, 100))).unwrap());
    }

    #[test]
    fn test_check_api() {
        assert!(check_api(3, ScmpVersion::from((2, 4, 0))).unwrap());
        assert!(!check_api(100, ScmpVersion::from((2, 4, 0))).unwrap());
    }

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
    #[allow(deprecated)]
    fn test_get_library_version() {
        let ret = ScmpVersion::current().unwrap();
        assert_eq!(ret, get_library_version().unwrap());
        println!(
            "test_get_library_version: {}.{}.{}",
            ret.major, ret.minor, ret.micro
        );
    }

    #[test]
    #[allow(deprecated)]
    fn test_get_native_arch() {
        let ret = ScmpArch::native().unwrap();
        assert_eq!(ret, get_native_arch().unwrap());
        println!("test_get_native_arch: native arch is {:?}", ret);
    }

    #[test]
    fn test_get_api() {
        let ret = get_api().unwrap();
        println!("test_get_api: Got API level of {}", ret);
    }

    #[test]
    fn test_set_api() {
        let expected_api = 1;
        set_api(expected_api).unwrap();

        let api = get_api().unwrap();
        assert_eq!(expected_api, api);
    }

    #[test]
    fn test_scmpargcompare() {
        assert_eq!(
            ScmpArgCompare::new(0, ScmpCompareOp::NotEqual, 8),
            ScmpArgCompare(scmp_arg_cmp {
                arg: 0,
                op: scmp_compare::SCMP_CMP_NE,
                datum_a: 8,
                datum_b: 0,
            })
        );
        assert_eq!(
            ScmpArgCompare::new(0, ScmpCompareOp::MaskedEqual(0b0010), 2),
            ScmpArgCompare(scmp_arg_cmp {
                arg: 0,
                op: scmp_compare::SCMP_CMP_MASKED_EQ,
                datum_a: 0b0010,
                datum_b: 2,
            })
        );
        assert_eq!(
            scmp_arg_cmp::from(ScmpArgCompare::new(0, ScmpCompareOp::NotEqual, 8)),
            scmp_arg_cmp {
                arg: 0,
                op: scmp_compare::SCMP_CMP_NE,
                datum_a: 8,
                datum_b: 0,
            }
        );
        assert_eq!(
            scmp_arg_cmp::from(&ScmpArgCompare::new(0, ScmpCompareOp::NotEqual, 8)),
            scmp_arg_cmp {
                arg: 0,
                op: scmp_compare::SCMP_CMP_NE,
                datum_a: 8,
                datum_b: 0,
            }
        );
    }

    #[test]
    fn test_set_syscall_priority() {
        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::KillThread).unwrap();
        let syscall = ScmpSyscall::from_name("open").unwrap();
        let priority = 100;

        assert!(ctx.set_syscall_priority(syscall, priority).is_ok());
        assert!(ctx.set_syscall_priority(-1, priority).is_err());
    }

    #[test]
    fn test_filter_attributes() {
        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::KillThread).unwrap();

        // Test for CtlNnp
        ctx.set_ctl_nnp(false).unwrap();
        let ret = ctx.get_ctl_nnp().unwrap();
        assert!(!ret);

        // Test for ActBadArch
        let test_actions = [
            ScmpAction::Trap,
            ScmpAction::Errno(libc::EACCES),
            ScmpAction::Trace(10),
        ];
        for action in test_actions {
            ctx.set_act_badarch(action).unwrap();
            let ret = ctx.get_act_badarch().unwrap();
            assert_eq!(ret, action);
        }

        // Test for ActDefault
        let ret = ctx.get_act_default().unwrap();
        assert_eq!(ret, ScmpAction::KillThread);

        // Test for CtlLog
        if check_api(3, ScmpVersion::from((2, 4, 0))).unwrap() {
            ctx.set_ctl_log(true).unwrap();
            let ret = ctx.get_ctl_log().unwrap();
            assert!(ret);
        } else {
            assert!(ctx.set_ctl_log(true).is_err());
            assert!(ctx.get_ctl_log().is_err());
        }

        // Test for CtlSsb
        if check_api(4, ScmpVersion::from((2, 5, 0))).unwrap() {
            ctx.set_ctl_ssb(true).unwrap();
            let ret = ctx.get_ctl_ssb().unwrap();
            assert!(ret);
        } else {
            assert!(ctx.set_ctl_ssb(true).is_err());
            assert!(ctx.get_ctl_ssb().is_err());
        }

        // Test for CtlOptimize
        let opt_level = 2;
        if check_api(4, ScmpVersion::from((2, 5, 0))).unwrap() {
            ctx.set_ctl_optimize(opt_level).unwrap();
            let ret = ctx.get_ctl_optimize().unwrap();
            assert_eq!(ret, opt_level);
        } else {
            assert!(ctx.set_ctl_optimize(opt_level).is_err());
            assert!(ctx.get_ctl_optimize().is_err());
        }
    }

    #[test]
    fn test_filter_reset() {
        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::KillThread).unwrap();
        ctx.reset(ScmpAction::Allow).unwrap();

        let action = ctx.get_filter_attr(ScmpFilterAttr::ActDefault).unwrap();

        let expected_action: u32 = ScmpAction::Allow.to_sys();

        assert_eq!(expected_action, action);
    }

    #[test]
    fn test_reset_global_state() {
        if check_version(ScmpVersion::from((2, 5, 1))).unwrap() {
            assert!(reset_global_state().is_ok());
        } else {
            assert!(reset_global_state().is_err());
        }
    }

    #[test]
    fn test_get_syscall_name_from_arch() {
        let name = ScmpSyscall::from(5)
            .get_name_by_arch(ScmpArch::Arm)
            .unwrap();

        println!(
            "test_get_syscall_from_name: Got syscall name of 5 on ARM arch as {}",
            name
        );
    }

    #[test]
    fn test_get_syscall_from_name() {
        let num = ScmpSyscall::from_name("open").unwrap().to_sys();
        println!(
            "test_get_syscall_from_name: Got syscall number of open on native arch as {}",
            num
        );

        let num = ScmpSyscall::from_name_by_arch("open", ScmpArch::Arm)
            .unwrap()
            .to_sys();
        println!(
            "test_get_syscall_from_name: Got syscall number of open on ARM arch as {}",
            num
        );
    }

    #[test]
    fn test_arch_functions() {
        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();
        ctx.add_arch(ScmpArch::X86).unwrap();
        let ret = ctx.is_arch_present(ScmpArch::X86).unwrap();
        assert!(ret);

        ctx.remove_arch(ScmpArch::X86).unwrap();
        let ret = ctx.is_arch_present(ScmpArch::X86).unwrap();
        assert!(!ret);
    }

    #[test]
    fn test_merge_filters() {
        let mut ctx1 = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();
        let mut ctx2 = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();
        let native_arch = ScmpArch::native().unwrap();
        let mut prospective_arch = ScmpArch::Aarch64;

        if native_arch == ScmpArch::Aarch64 {
            prospective_arch = ScmpArch::X8664;
        }

        ctx2.add_arch(prospective_arch).unwrap();

        // In order to merge two filters, both filters must have no
        // overlapping architectures.
        // Therefore, need to remove the native arch.
        ctx2.remove_arch(native_arch).unwrap();

        ctx1.merge(ctx2).unwrap();

        let ret = ctx1.is_arch_present(prospective_arch).unwrap();
        assert!(ret);
    }

    #[test]
    fn test_export_functions() {
        let ctx = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();

        assert!(ctx.export_bpf(&mut stdout()).is_ok());
        assert!(ctx.export_bpf(&mut -1).is_err());

        assert!(ctx.export_pfc(&mut stdout()).is_ok());
        assert!(ctx.export_pfc(&mut -1).is_err());
    }

    #[test]
    fn test_rule_add_load() {
        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();
        ctx.add_arch(ScmpArch::Native).unwrap();

        let syscall = ScmpSyscall::from_name("dup3").unwrap();

        ctx.add_rule(ScmpAction::Errno(10), syscall).unwrap();
        ctx.load().unwrap();

        syscall_assert!(unsafe { libc::dup3(0, 100, libc::O_CLOEXEC) }, -10);
    }

    #[test]
    fn test_rule_add_array_load() {
        let mut cmps: Vec<ScmpArgCompare> = Vec::new();
        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();
        ctx.add_arch(ScmpArch::Native).unwrap();

        let syscall = ScmpSyscall::from_name("process_vm_readv").unwrap();

        let cmp1 = ScmpArgCompare::new(0, ScmpCompareOp::Equal, 10);
        let cmp2 = ScmpArgCompare::new(2, ScmpCompareOp::Equal, 20);

        cmps.push(cmp1);
        cmps.push(cmp2);

        ctx.add_rule_conditional(ScmpAction::Errno(111), syscall, &cmps)
            .unwrap();

        ctx.load().unwrap();

        syscall_assert!(
            unsafe { libc::process_vm_readv(10, std::ptr::null(), 0, std::ptr::null(), 0, 0) },
            0
        );
        syscall_assert!(
            unsafe { libc::process_vm_readv(10, std::ptr::null(), 20, std::ptr::null(), 0, 0) },
            -111
        );
    }

    #[test]
    fn test_rule_add_exact_load() {
        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();
        ctx.add_arch(ScmpArch::Native).unwrap();

        let syscall = ScmpSyscall::from_name("dup3").unwrap();

        ctx.add_rule_exact(ScmpAction::Errno(10), syscall).unwrap();
        ctx.load().unwrap();

        syscall_assert!(unsafe { libc::dup3(0, 100, libc::O_CLOEXEC) }, -10);
    }

    #[test]
    fn test_rule_add_exact_array_load() {
        let mut cmps: Vec<ScmpArgCompare> = Vec::new();
        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();
        ctx.add_arch(ScmpArch::Native).unwrap();

        let syscall = ScmpSyscall::from_name("process_vm_readv").unwrap();

        let cmp1 = ScmpArgCompare::new(0, ScmpCompareOp::Equal, 10);
        let cmp2 = ScmpArgCompare::new(2, ScmpCompareOp::Equal, 20);

        cmps.push(cmp1);
        cmps.push(cmp2);

        ctx.add_rule_conditional_exact(ScmpAction::Errno(111), syscall, &cmps)
            .unwrap();

        ctx.load().unwrap();

        syscall_assert!(
            unsafe { libc::process_vm_readv(10, std::ptr::null(), 0, std::ptr::null(), 0, 0) },
            0
        );
        syscall_assert!(
            unsafe { libc::process_vm_readv(10, std::ptr::null(), 20, std::ptr::null(), 0, 0) },
            -111
        );
    }

    #[test]
    fn test_as_ptr() {
        let ctx = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();
        assert_eq!(ctx.as_ptr(), ctx.ctx.as_ptr());
    }
}
