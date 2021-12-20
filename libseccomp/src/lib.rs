// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

//! Native Rust crate for libseccomp library
//!
//! This is a high-level safe API for `libseccomp` on Linux.
//!
//! # Examples
//!
//! ```rust
//! use libseccomp::*;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
//!     let syscall = get_syscall_from_name("getuid", None)?;
//!
//!     filter.add_arch(ScmpArch::X8664)?;
//!     filter.add_rule(ScmpAction::Errno(1), syscall, None)?;
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
//!     let syscall = get_syscall_from_name("dup3", Some(ScmpArch::X8664))?;
//!     let cmp = ScmpArgCompare::new(0, ScmpCompareOp::Equal, 1);
//!
//!     filter.add_arch(ScmpArch::X8664)?;
//!     filter.add_rule(ScmpAction::Errno(libc::EPERM), syscall, Some(&[cmp]))?;
//!     filter.load()?;
//!
//!     Ok(())
//! }
//! ```

pub mod error;
pub mod notify;

use error::ErrorKind::*;
use error::{Result, SeccompError};
use libseccomp_sys::*;
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::os::unix::io::AsRawFd;
use std::ptr::NonNull;

/// ScmpVersion represents the version information of
/// the currently loaded libseccomp library
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScmpVersion {
    pub major: u32,
    pub minor: u32,
    pub micro: u32,
}
impl ScmpVersion {
    /// Returns the version of the currently loaded libseccomp library.
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

/// ScmpFilterArttr represents filter attributes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// A flag to specify if libseccomp should allow filter rules
    /// to be created for the -1 syscall.
    ApiTskip,
    /// A flag to specify if the kernel should log all filter
    /// actions taken except for the ScmpAction::ActAllow action.
    CtlLog,
    /// A flag to disable Speculative Store Bypass mitigations for
    /// this filter.
    CtlSsb,
    /// A flag to specify the optimization level of the seccomp
    /// filter.
    CtlOptimize,
    /// A flag to specify if libseccomp should pass system error
    /// codes back to the caller instead of the default  -ECANCELED.
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

    fn from_str(s: &str) -> Result<Self> {
        match s {
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

/// ScmpCompareOp represents a comparison operator which can be used in a filter rule
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScmpCompareOp {
    /// not equal
    NotEqual,
    /// less than
    Less,
    /// less than or equal
    LessOrEqual,
    /// equal
    Equal,
    /// greater than or equal
    GreaterEqual,
    /// greater than
    Greater,
    /// masked equality
    MaskedEqual(#[doc = "mask"] u64),
}

impl ScmpCompareOp {
    fn to_sys(self) -> scmp_compare {
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

    fn from_str(s: &str) -> Result<Self> {
        match s {
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

/// ScmpArgCompare represents a rule in a libseccomp filter context
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScmpArgCompare {
    /// argument number, starting at 0
    arg: u32,
    /// the comparison op
    op: ScmpCompareOp,
    datum_a: u64,
    datum_b: u64,
}

impl ScmpArgCompare {
    pub const fn new(arg: u32, op: ScmpCompareOp, datum: u64) -> Self {
        if let ScmpCompareOp::MaskedEqual(mask) = op {
            Self {
                arg,
                op,
                datum_a: mask,
                datum_b: datum,
            }
        } else {
            Self {
                arg,
                op,
                datum_a: datum,
                datum_b: 0,
            }
        }
    }
}

impl From<ScmpArgCompare> for scmp_arg_cmp {
    fn from(v: ScmpArgCompare) -> scmp_arg_cmp {
        scmp_arg_cmp {
            arg: v.arg,
            op: v.op.to_sys(),
            datum_a: v.datum_a,
            datum_b: v.datum_b,
        }
    }
}

impl From<&ScmpArgCompare> for scmp_arg_cmp {
    fn from(v: &ScmpArgCompare) -> scmp_arg_cmp {
        scmp_arg_cmp {
            arg: v.arg,
            op: v.op.to_sys(),
            datum_a: v.datum_a,
            datum_b: v.datum_b,
        }
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

/// ScmpAction represents an action to be taken on a filter rule match in libseccomp
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScmpAction {
    /// Kill the process
    KillProcess,
    /// Kill the thread
    KillThread,
    /// Throw a SIGSYS signal
    Trap,
    /// Notifies userspace
    Notify,
    /// Return the specified error code
    /// NOTE: You can only use integers from 0 to `u16::MAX`.
    Errno(i32),
    /// Notify a tracing process with the specified value
    Trace(u16),
    /// Allow the syscall to be executed after the action has been logged
    Log,
    /// Allow the syscall to be executed
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

    /// Convert string seccomp action to ScmpAction
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

/// ScmpArch represents a CPU architecture. Seccomp can restrict syscalls on a
/// per-architecture basis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "SCMP_ARCH_NATIVE" => Ok(Self::Native),
            "SCMP_ARCH_X86" => Ok(Self::X86),
            "SCMP_ARCH_X86_64" => Ok(Self::X8664),
            "SCMP_ARCH_X32" => Ok(Self::X32),
            "SCMP_ARCH_ARM" => Ok(Self::Arm),
            "SCMP_ARCH_AARCH64" => Ok(Self::Aarch64),
            "SCMP_ARCH_MIPS" => Ok(Self::Mips),
            "SCMP_ARCH_MIPS64" => Ok(Self::Mips64),
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

/// ScmpFilterContext represents a filter context in libseccomp.
#[derive(Debug)]
pub struct ScmpFilterContext {
    ctx: NonNull<libc::c_void>,
}

impl ScmpFilterContext {
    /// new_filter creates and returns a new filter context.
    ///
    /// Accepts a default action to be taken for syscalls which match no rules in the filter.
    /// Returns a reference to a valid filter context, or an error if the
    /// filter context could not be created or an invalid default action was given.
    pub fn new_filter(default_action: ScmpAction) -> Result<ScmpFilterContext> {
        let ctx_ptr = unsafe { seccomp_init(default_action.to_sys()) };
        let ctx = NonNull::new(ctx_ptr)
            .ok_or_else(|| SeccompError::new(Common("Could not create new filter".to_string())))?;

        Ok(ScmpFilterContext { ctx })
    }

    /// merge merges two filters.
    /// In order to merge two seccomp filters, both filters must have the same
    /// attribute values and no overlapping architectures.
    /// If successful, the src seccomp filter is released and all internal memory
    /// associated with the filter is freed.
    ///
    /// Accepts a seccomp filter in src that will be merged into the filter this is
    /// called on.
    /// Returns an error if merging the filters failed.
    pub fn merge(&mut self, src: Self) -> Result<()> {
        let ret = unsafe { seccomp_merge(self.ctx.as_ptr(), src.ctx.as_ptr()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        // The src filter is already released.
        std::mem::forget(src);

        Ok(())
    }

    /// is_arch_present checks if an architecture is present in a filter.
    ///
    /// If a filter contains an architecture, it uses its default action for
    /// syscalls which do not match rules in it, and its rules can match syscalls
    /// for that ABI.
    /// If a filter does not contain an architecture, all syscalls made to that
    /// kernel ABI will fail with the filter's default Bad Architecture Action
    /// (by default, killing the proc).
    /// Accepts an architecture constant.
    /// Returns true if the architecture is present in the filter, false otherwise,
    /// and an error on an invalid filter context, architecture constant, or an
    /// issue with the call to libseccomp
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

    /// add_arch adds an architecture to the filter.
    ///
    /// Accepts an architecture constant.
    /// Returns an architecture token, or an error with the call to libseccomp.
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

    /// remove_arch removes an architecture from the filter.
    ///
    /// Accepts an architecture constant.
    /// Returns an error on invalid filter context or architecture token, or an
    /// issue with the call to libseccomp.
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

    /// add_rule adds a single rule for an unconditional or conditional action on a syscall.
    ///
    /// Accepts the number of the syscall the action and the conditions to be taken on the call being made.
    /// If the compartors is None, the function adds a single rule for an unconditional action.
    /// Returns an error if an issue was encountered adding the rule.
    pub fn add_rule(
        &mut self,
        action: ScmpAction,
        syscall: i32,
        comparators: Option<&[ScmpArgCompare]>,
    ) -> Result<()> {
        let ret: i32;

        match comparators {
            Some(cmps) => {
                let arg_cmp: Vec<scmp_arg_cmp> = cmps.iter().map(From::from).collect();
                let arg_cmp_len: u32 = arg_cmp.len().try_into()?;

                ret = unsafe {
                    seccomp_rule_add_array(
                        self.ctx.as_ptr(),
                        action.to_sys(),
                        syscall,
                        arg_cmp_len,
                        arg_cmp.as_ptr(),
                    )
                };
            }
            None => {
                ret = unsafe { seccomp_rule_add(self.ctx.as_ptr(), action.to_sys(), syscall, 0) };
            }
        };

        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
    }

    /// load loads a filter context into the kernel.
    ///
    /// Returns an error if the filter context is invalid or the syscall failed.
    pub fn load(&self) -> Result<()> {
        let ret = unsafe { seccomp_load(self.ctx.as_ptr()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
    }
    /// get_filter_attr gets a raw filter attribute
    pub fn get_filter_attr(&self, attr: ScmpFilterAttr) -> Result<u32> {
        let mut attribute: u32 = 0;

        let ret = unsafe { seccomp_attr_get(self.ctx.as_ptr(), attr.to_sys(), &mut attribute) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(attribute)
    }

    /// get_no_new_privs_bit returns the current state the No New Privileges bit will be set
    /// to on the filter being loaded, or an error if an issue was encountered
    /// retrieving the value.
    pub fn get_no_new_privs_bit(&self) -> Result<bool> {
        let ret = self.get_filter_attr(ScmpFilterAttr::CtlNnp)?;

        Ok(ret != 0)
    }

    /// set_filter_attr sets a raw filter attribute
    pub fn set_filter_attr(&mut self, attr: ScmpFilterAttr, value: u32) -> Result<()> {
        let ret = unsafe { seccomp_attr_set(self.ctx.as_ptr(), attr.to_sys(), value) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
    }

    /// set_no_new_privs_bit sets the state of the No New Privileges bit, which will be
    /// applied on filter load, or an error if an issue was encountered setting the value.
    /// Filters with No New Privileges set to 0 can only be loaded if the process
    /// has the CAP_SYS_ADMIN capability.
    pub fn set_no_new_privs_bit(&mut self, state: bool) -> Result<()> {
        self.set_filter_attr(ScmpFilterAttr::CtlNnp, state.into())
    }

    /// export_pfc outputs PFC-formatted, human-readable dump of a filter context's
    /// rules to a file.
    ///
    /// Accepts file to write to (must be open for writing).
    /// Returns an error if writing to the file fails.
    pub fn export_pfc<T: AsRawFd>(&self, fd: &mut T) -> Result<()> {
        let ret = unsafe { seccomp_export_pfc(self.ctx.as_ptr(), fd.as_raw_fd()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
    }

    /// export_bpf outputs Berkeley Packet Filter-formatted, kernel-readable dump of a
    /// filter context's rules to a file.
    ///
    /// Accepts file to write to (must be open for writing).
    /// Returns an error if writing to the file fails.
    pub fn export_bpf<T: AsRawFd>(&self, fd: &mut T) -> Result<()> {
        let ret = unsafe { seccomp_export_bpf(self.ctx.as_ptr(), fd.as_raw_fd()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
    }

    /// get_notify_fd gets a notification fd of the loaded filter.
    ///
    /// Returns -1 if a notification fd has not yet been created,
    /// and -EINVAL if the filter context is invalid.
    #[cfg(libseccomp_v2_5)]
    pub fn get_notify_fd(&self) -> Result<i32> {
        let ret = unsafe { seccomp_notify_fd(self.ctx.as_ptr()) };
        if ret < 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(ret)
    }

    /// reset resets a filter context, removing all its existing state.
    ///
    /// Accepts a new default action to be taken for syscalls which do not match.
    /// Returns an error if the filter or action provided are invalid.
    pub fn reset(&mut self, action: ScmpAction) -> Result<()> {
        let ret = unsafe { seccomp_reset(self.ctx.as_ptr(), action.to_sys()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
    }

    /// Returns a raw pointer to the [`scmp_filter_ctx`]
    pub fn as_ptr(&self) -> scmp_filter_ctx {
        self.ctx.as_ptr()
    }
}

impl Drop for ScmpFilterContext {
    /// drop releases a filter context, freeing its memory.
    ///
    /// After calling this function, the given filter is no longer valid and cannot be used.
    fn drop(&mut self) {
        unsafe { seccomp_release(self.ctx.as_ptr()) }
    }
}

/// Deprecated alias for [`ScmpVersion::current()`].
#[deprecated(since = "0.2.0", note = "Use ScmpVersion::current().")]
pub fn get_library_version() -> Result<ScmpVersion> {
    ScmpVersion::current()
}

/// Deprecated alias for [`ScmpArch::native()`].
#[deprecated(since = "0.2.0", note = "Use ScmpArch::native()")]
pub fn get_native_arch() -> Result<ScmpArch> {
    ScmpArch::native()
}

/// get_api returns the API level supported by the system.
///
/// Returns a positive int containing the API level, or 0 with an error if the
/// API level could not be detected due to the library being older than v2.4.0.
/// See the seccomp_api_get(3) man page for details on available API levels:
/// <https://github.com/seccomp/libseccomp/blob/main/doc/man/man3/seccomp_api_get.3>
pub fn get_api() -> Result<u32> {
    let ret = unsafe { seccomp_api_get() };
    if ret == 0 {
        return Err(SeccompError::new(Common(
            "API level operations are not supported".to_string(),
        )));
    }

    Ok(ret)
}

/// set_api forcibly sets the API level. General use of this function is strongly
/// discouraged.
///
/// Returns an error if the API level could not be set. An error is always
/// returned if the library is older than v2.4.0
/// See the seccomp_api_get(3) man page for details on available API levels:
/// <https://github.com/seccomp/libseccomp/blob/main/doc/man/man3/seccomp_api_get.3>
pub fn set_api(level: u32) -> Result<()> {
    let ret = unsafe { seccomp_api_set(level) };
    if ret != 0 {
        return Err(SeccompError::new(Common(
            "API level operations are not supported".to_string(),
        )));
    }

    Ok(())
}

/// get_syscall_name_from_arch retrieves the name of a syscall from its number for a given
/// architecture.
///
/// Acts on any syscall number.
/// Accepts a valid architecture constant.
/// Returns either a string containing the name of the syscall, or an error.
/// if the syscall is unrecognized or an issue occurred.
pub fn get_syscall_name_from_arch(arch: ScmpArch, syscall_num: i32) -> Result<String> {
    let ret = unsafe { seccomp_syscall_resolve_num_arch(arch.to_sys(), syscall_num) };
    if ret.is_null() {
        return Err(SeccompError::new(Common(format!(
            "Could not resolve syscall number {}",
            syscall_num
        ))));
    }

    let name = unsafe { CStr::from_ptr(ret) }.to_str()?.to_string();
    unsafe { libc::free(ret as *mut libc::c_void) };

    Ok(name)
}

/// get_syscall_from_name returns the number of a syscall by name for a given
/// architecture's ABI.
///
/// Accepts the name of a syscall and an architecture constant.
/// If arch argument is None, the functions returns the number of a syscall on the kernel's native architecture.
/// Returns the number of the syscall, or an error if an invalid architecture is
/// passed or a syscall with that name was not found.
pub fn get_syscall_from_name(name: &str, arch: Option<ScmpArch>) -> Result<i32> {
    let name_c = CString::new(name)?;
    let syscall: i32;

    match arch {
        Some(arch) => {
            syscall = unsafe { seccomp_syscall_resolve_name_arch(arch.to_sys(), name_c.as_ptr()) };
        }
        None => {
            syscall = unsafe { seccomp_syscall_resolve_name(name_c.as_ptr()) };
        }
    }

    if syscall == __NR_SCMP_ERROR {
        return Err(SeccompError::new(Common(format!(
            "Could not resolve syscall name {}",
            name
        ))));
    }

    Ok(syscall)
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
    fn test_parse() {
        assert_eq!(
            ScmpFilterAttr::from_str("SCMP_FLTATR_ACT_DEFAULT")
                .unwrap()
                .to_sys(),
            ScmpFilterAttr::ActDefault.to_sys()
        );
        assert_eq!(
            ScmpFilterAttr::from_str("SCMP_FLTATR_ACT_BADARCH")
                .unwrap()
                .to_sys(),
            ScmpFilterAttr::ActBadArch.to_sys()
        );
        assert_eq!(
            ScmpFilterAttr::from_str("SCMP_FLTATR_CTL_NNP")
                .unwrap()
                .to_sys(),
            ScmpFilterAttr::CtlNnp.to_sys()
        );
        assert_eq!(
            ScmpFilterAttr::from_str("SCMP_FLTATR_CTL_TSYNC")
                .unwrap()
                .to_sys(),
            ScmpFilterAttr::CtlTsync.to_sys()
        );
        assert_eq!(
            ScmpFilterAttr::from_str("SCMP_FLTATR_API_TSKIP")
                .unwrap()
                .to_sys(),
            ScmpFilterAttr::ApiTskip.to_sys()
        );
        assert_eq!(
            ScmpFilterAttr::from_str("SCMP_FLTATR_CTL_LOG")
                .unwrap()
                .to_sys(),
            ScmpFilterAttr::CtlLog.to_sys()
        );
        assert_eq!(
            ScmpFilterAttr::from_str("SCMP_FLTATR_CTL_SSB")
                .unwrap()
                .to_sys(),
            ScmpFilterAttr::CtlSsb.to_sys()
        );
        assert_eq!(
            ScmpFilterAttr::from_str("SCMP_FLTATR_CTL_OPTIMIZE")
                .unwrap()
                .to_sys(),
            ScmpFilterAttr::CtlOptimize.to_sys()
        );
        assert_eq!(
            ScmpFilterAttr::from_str("SCMP_FLTATR_API_SYSRAWRC")
                .unwrap()
                .to_sys(),
            ScmpFilterAttr::ApiSysRawRc.to_sys()
        );
        assert!(ScmpFilterAttr::from_str("SCMP_INVALID_FLAG").is_err());
        assert_eq!(
            ScmpCompareOp::from_str("SCMP_CMP_NE").unwrap().to_sys(),
            ScmpCompareOp::NotEqual.to_sys()
        );
        assert_eq!(
            ScmpCompareOp::from_str("SCMP_CMP_LT").unwrap().to_sys(),
            ScmpCompareOp::Less.to_sys()
        );
        assert_eq!(
            ScmpCompareOp::from_str("SCMP_CMP_LE").unwrap().to_sys(),
            ScmpCompareOp::LessOrEqual.to_sys()
        );
        assert_eq!(
            ScmpCompareOp::from_str("SCMP_CMP_EQ").unwrap().to_sys(),
            ScmpCompareOp::Equal.to_sys()
        );
        assert_eq!(
            ScmpCompareOp::from_str("SCMP_CMP_GE").unwrap().to_sys(),
            ScmpCompareOp::GreaterEqual.to_sys()
        );
        assert_eq!(
            ScmpCompareOp::from_str("SCMP_CMP_GT").unwrap().to_sys(),
            ScmpCompareOp::Greater.to_sys()
        );
        assert_eq!(
            ScmpCompareOp::from_str("SCMP_CMP_MASKED_EQ")
                .unwrap()
                .to_sys(),
            ScmpCompareOp::MaskedEqual(u64::default()).to_sys()
        );
        assert!(ScmpCompareOp::from_str("SCMP_INVALID_FLAG").is_err());
        assert_eq!(
            ScmpAction::from_str("SCMP_ACT_KILL_PROCESS", None)
                .unwrap()
                .to_sys(),
            ScmpAction::KillProcess.to_sys()
        );
        assert_eq!(
            ScmpAction::from_str("SCMP_ACT_ERRNO", Some(10))
                .unwrap()
                .to_sys(),
            ScmpAction::Errno(10).to_sys()
        );
        assert_eq!(
            ScmpAction::from_str("SCMP_ACT_TRACE", Some(10))
                .unwrap()
                .to_sys(),
            ScmpAction::Trace(10).to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_X86_64").unwrap().to_sys(),
            ScmpArch::X8664.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_X32").unwrap().to_sys(),
            ScmpArch::X32.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_MIPS").unwrap().to_sys(),
            ScmpArch::Mips.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_MIPS64").unwrap().to_sys(),
            ScmpArch::Mips64.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_MIPSEL").unwrap().to_sys(),
            ScmpArch::Mipsel.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_MIPSEL64").unwrap().to_sys(),
            ScmpArch::Mipsel64.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_MIPSEL64N32")
                .unwrap()
                .to_sys(),
            ScmpArch::Mipsel64N32.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_PPC").unwrap().to_sys(),
            ScmpArch::Ppc.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_PPC64").unwrap().to_sys(),
            ScmpArch::Ppc64.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_PPC64LE").unwrap().to_sys(),
            ScmpArch::Ppc64Le.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_S390").unwrap().to_sys(),
            ScmpArch::S390.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_S390X").unwrap().to_sys(),
            ScmpArch::S390X.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_PARISC").unwrap().to_sys(),
            ScmpArch::Parisc.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_PARISC64").unwrap().to_sys(),
            ScmpArch::Parisc64.to_sys()
        );
        assert_eq!(
            ScmpArch::from_str("SCMP_ARCH_RISCV64").unwrap().to_sys(),
            ScmpArch::Riscv64.to_sys()
        );
    }

    #[test]
    fn test_get_library_version() {
        let ret = ScmpVersion::current().unwrap();
        println!(
            "test_get_library_version: {}.{}.{}",
            ret.major, ret.minor, ret.micro
        );
    }

    #[test]
    fn test_get_native_arch() {
        let ret = ScmpArch::native().unwrap();
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
    fn test_filter_attributes() {
        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::KillThread).unwrap();

        ctx.set_no_new_privs_bit(false).unwrap();
        let ret = ctx.get_no_new_privs_bit().unwrap();
        assert!(!ret);
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
    fn test_get_syscall_name_from_arch() {
        let name = get_syscall_name_from_arch(ScmpArch::Arm, 5).unwrap();

        println!(
            "test_get_syscall_from_name: Got syscall name of 5 on ARM arch as {}",
            name
        );
    }

    #[test]
    fn test_get_syscall_from_name() {
        let num = get_syscall_from_name("open", None).unwrap();
        println!(
            "test_get_syscall_from_name: Got syscall number of open on native arch as {}",
            num
        );

        let num = get_syscall_from_name("open", Some(ScmpArch::Arm)).unwrap();
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

        let syscall = get_syscall_from_name("dup3", None).unwrap();

        ctx.add_rule(ScmpAction::Errno(10), syscall, None).unwrap();
        ctx.load().unwrap();

        syscall_assert!(unsafe { libc::dup3(0, 100, libc::O_CLOEXEC) }, -10);
    }

    #[test]
    fn test_rule_add_array_load() {
        let mut cmps: Vec<ScmpArgCompare> = Vec::new();
        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();
        ctx.add_arch(ScmpArch::Native).unwrap();

        let syscall = get_syscall_from_name("process_vm_readv", None).unwrap();

        let cmp1 = ScmpArgCompare::new(0, ScmpCompareOp::Equal, 10);
        let cmp2 = ScmpArgCompare::new(2, ScmpCompareOp::Equal, 20);

        cmps.push(cmp1);
        cmps.push(cmp2);

        ctx.add_rule(ScmpAction::Errno(111), syscall, Some(&cmps))
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

    #[test]
    fn test_scmp_arg_cmp_from_scmpargcompare() {
        // scmp_arg_cmp does not implement PartialEq, that's why we destruct
        // the struct and assert_eq the individual fields.

        let scmp_arg_cmp {
            arg,
            op,
            datum_a,
            datum_b,
        } = <scmp_arg_cmp as From<ScmpArgCompare>>::from(ScmpArgCompare {
            arg: 0,
            op: ScmpCompareOp::Equal,
            datum_a: 1,
            datum_b: 0,
        });
        assert_eq!(arg, 0);
        assert_eq!(op, scmp_compare::SCMP_CMP_EQ);
        assert_eq!(datum_a, 1);
        assert_eq!(datum_b, 0);

        let scmp_arg_cmp {
            arg,
            op,
            datum_a,
            datum_b,
        } = <scmp_arg_cmp as From<&ScmpArgCompare>>::from(&ScmpArgCompare {
            arg: 0,
            op: ScmpCompareOp::Equal,
            datum_a: 1,
            datum_b: 0,
        });
        assert_eq!(arg, 0);
        assert_eq!(op, scmp_compare::SCMP_CMP_EQ);
        assert_eq!(datum_a, 1);
        assert_eq!(datum_b, 0);
    }
}
