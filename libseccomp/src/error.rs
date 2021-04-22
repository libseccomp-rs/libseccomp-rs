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
                libc::EDOM => "Architecture specific failure".to_string(),
                libc::EACCES => {
                    "Setting the attribute with the given value is not allowed".to_string()
                }
                libc::EEXIST => "Failure regrading the existance of argument".to_string(),
                libc::EINVAL => "Invalid input".to_string(),
                libc::ENOMEM => "The library was unable to allocate enough memory".to_string(),
                libc::ECANCELED => {
                    "There was a system failure beyound the control of the library".to_string()
                }
                libc::EFAULT => "Internal libseccomp failure".to_string(),
                libc::ESRCH => "Unable to load the filter due to thread issues".to_string(),
                libc::EOPNOTSUPP => {
                    "The library doesn't support the particular operation".to_string()
                }
                _ => "Other failure".to_string(),
            },
            ErrorKind::Common(s) => s.clone(),
            ErrorKind::ParseError => "Invalid argument".to_string(),
        };

        if let Some(source) = &self.source {
            write!(f, "{} caused by: {:?}", msg, source)
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

    #[allow(dead_code)]
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
