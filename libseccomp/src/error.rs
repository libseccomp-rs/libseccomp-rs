// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use std::error::Error;
use std::fmt;

/// The different types of errors that can occur while manipulating libseccomp api.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    Errno(i32),
    Common(String),
    ParseError,
    Source,
}

#[derive(Debug)]
pub struct SeccompError {
    kind: ErrorKind,
    code: Option<i32>,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl fmt::Display for SeccompError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match &self.kind {
            ErrorKind::Errno(e) => match -(*e) {
                libc::EDOM => "Architecture specific failure",
                libc::EACCES => "Setting the attribute with the given value is not allowed",
                libc::EEXIST => "Failure regrading the existance of argument",
                libc::EINVAL => "Invalid input",
                libc::ENOMEM => "The library was unable to allocate enough memory",
                libc::ECANCELED => "There was a system failure beyond the control of the library",
                libc::EFAULT => "Internal libseccomp failure",
                libc::ESRCH => "Unable to load the filter due to thread issues",
                libc::EOPNOTSUPP => "The library doesn't support the particular operation",
                errno => return write!(f, "Error caused by: errno({})", errno),
            },
            ErrorKind::Common(s) => s,
            ErrorKind::ParseError => "Invalid argument",
            ErrorKind::Source => return self.source.as_ref().unwrap().fmt(f),
        };

        if let Some(source) = &self.source {
            write!(f, "{} caused by: {}", msg, source)
        } else {
            write!(f, "{}", msg)
        }
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
        match kind {
            ErrorKind::Errno(e) => Self {
                kind,
                code: Some(e),
                source: None,
            },
            _ => Self {
                kind,
                code: None,
                source: None,
            },
        }
    }

    pub(crate) fn with_source<E>(kind: ErrorKind, source: E) -> Self
    where
        E: 'static + Send + Sync + Error,
    {
        Self {
            kind,
            code: None,
            source: Some(Box::new(source)),
        }
    }
}

pub type Result<T> = ::std::result::Result<T, SeccompError>;
