// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use std::borrow::Cow;
use std::error::Error;
use std::fmt;

// Errno message
const EACCES: &str = "Setting the attribute with the given value is not allowed";
const ECANCELED: &str = "There was a system failure beyond the control of libseccomp";
const EDOM: &str = "Architecture specific failure";
const EEXIST: &str = "Failure regrading the existance of argument";
const EFAULT: &str = "Internal libseccomp failure";
const EINVAL: &str = "Invalid input to the libseccomp API";
const ENOENT: &str = "No matching entry found";
const ENOMEM: &str = "Unable to allocate enough memory to perform the requested operation";
const EOPNOTSUPP: &str = "The library doesn't support the particular operation";
const ERANGE: &str = "Provided buffer is too small";
const ESRCH: &str = "Unable to load the filter due to thread issues";

// ParseError message
const PARSE_ERROR: &str = "Parse error by invalid argument";

/// The different types of errors that can occur while manipulating libseccomp api.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    Errno(i32),
    Common(String),
    ParseError,
    Source,
}

pub struct SeccompError {
    kind: ErrorKind,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl SeccompError {
    fn msg(&self) -> Cow<'static, str> {
        match &self.kind {
            ErrorKind::Errno(e) => match -(*e) {
                libc::EACCES => EACCES.into(),
                libc::ECANCELED => ECANCELED.into(),
                libc::EDOM => EDOM.into(),
                libc::EEXIST => EEXIST.into(),
                libc::EFAULT => EFAULT.into(),
                libc::EINVAL => EINVAL.into(),
                libc::ENOENT => ENOENT.into(),
                libc::ENOMEM => ENOMEM.into(),
                libc::EOPNOTSUPP => EOPNOTSUPP.into(),
                libc::ERANGE => ERANGE.into(),
                libc::ESRCH => ESRCH.into(),
                errno => format!("Unknown error({})", errno).into(),
            },
            ErrorKind::Common(s) => s.clone().into(),
            ErrorKind::ParseError => PARSE_ERROR.into(),
            ErrorKind::Source => self.source.as_ref().unwrap().to_string().into(),
        }
    }
}

impl fmt::Display for SeccompError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = self.msg();

        match &self.source {
            Some(source) if self.kind != ErrorKind::Source => {
                write!(f, "{} caused by: {}", msg, source)
            }
            Some(_) | None => {
                write!(f, "{}", msg)
            }
        }
    }
}

impl fmt::Debug for SeccompError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Error")
            .field("kind", &self.kind)
            .field("source", &self.source)
            .field("message", &self.msg())
            .finish()
    }
}

impl Error for SeccompError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.source {
            Some(error) => Some(error.as_ref()),
            None => None,
        }
    }
}

/* Does not work without specialization (RFC 1210) or negative trait bounds
impl<T: Error> From<T> for SeccompError {
    fn from(err: T) -> Self {
        Self::with_source(ErrorKind::Source, err)
    }
}
*/

macro_rules! impl_seccomperror_from {
    ($errty:ty) => {
        impl From<$errty> for SeccompError {
            fn from(err: $errty) -> Self {
                Self::with_source(ErrorKind::Source, err)
            }
        }
    };
}
impl_seccomperror_from!(std::ffi::NulError);
impl_seccomperror_from!(std::num::TryFromIntError);
impl_seccomperror_from!(std::str::Utf8Error);

impl SeccompError {
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self { kind, source: None }
    }

    pub(crate) fn with_source<E>(kind: ErrorKind, source: E) -> Self
    where
        E: 'static + Send + Sync + Error,
    {
        Self {
            kind,
            source: Some(Box::new(source)),
        }
    }
}

pub type Result<T> = ::std::result::Result<T, SeccompError>;
