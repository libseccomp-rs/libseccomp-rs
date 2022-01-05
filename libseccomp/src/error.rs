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
const EEXIST: &str = "Failure regrading the existence of argument";
const EFAULT: &str = "Internal libseccomp failure";
const EINVAL: &str = "Invalid input to the libseccomp API";
const ENOENT: &str = "No matching entry found";
const ENOMEM: &str = "Unable to allocate enough memory to perform the requested operation";
const EOPNOTSUPP: &str = "The library doesn't support the particular operation";
const ERANGE: &str = "Provided buffer is too small";
const ESRCH: &str = "Unable to load the filter due to thread issues";

// ParseError message
const PARSE_ERROR: &str = "Parse error by invalid argument";

/// A list specifying different categories of error.
#[derive(Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An error that represents error code on failure of the libseccomp API.
    Errno(i32),
    /// A parse error occurred while trying to convert a value.
    ParseError,
    /// A lower-level error that is caused by an error from a lower-level module.
    Source,
    /// A custom error that does not fall under any other error kind.
    Common(String),
}

/// The error type for libseccomp operations.
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

#[cfg(test)]
mod tests {
    use super::ErrorKind::*;
    use super::*;
    use std::ffi::CString;

    const TEST_ERR_MSG: &str = "test error";
    const TEST_NULL_STR: &str = "f\0oo";
    const NULL_ERR_MSG: &str = "nul byte found in provided data at position: 1";

    #[test]
    fn test_msg() {
        let null_err = CString::new(TEST_NULL_STR).unwrap_err();

        // Errno
        assert_eq!(SeccompError::new(Errno(-libc::EACCES)).msg(), EACCES);
        assert_eq!(SeccompError::new(Errno(-libc::ECANCELED)).msg(), ECANCELED);
        assert_eq!(SeccompError::new(Errno(-libc::EDOM)).msg(), EDOM);
        assert_eq!(SeccompError::new(Errno(-libc::EEXIST)).msg(), EEXIST);
        assert_eq!(SeccompError::new(Errno(-libc::EFAULT)).msg(), EFAULT);
        assert_eq!(SeccompError::new(Errno(-libc::EINVAL)).msg(), EINVAL);
        assert_eq!(SeccompError::new(Errno(-libc::ENOENT)).msg(), ENOENT);
        assert_eq!(SeccompError::new(Errno(-libc::ENOMEM)).msg(), ENOMEM);
        assert_eq!(
            SeccompError::new(Errno(-libc::EOPNOTSUPP)).msg(),
            EOPNOTSUPP
        );
        assert_eq!(SeccompError::new(Errno(-libc::ERANGE)).msg(), ERANGE);
        assert_eq!(SeccompError::new(Errno(-libc::ESRCH)).msg(), ESRCH);
        assert_eq!(
            SeccompError::new(Errno(-libc::EPIPE)).msg(),
            format!("Unknown error({})", libc::EPIPE)
        );

        // Common
        assert_eq!(
            SeccompError::new(Common(TEST_ERR_MSG.to_string())).msg(),
            TEST_ERR_MSG
        );

        // ParseError
        assert_eq!(SeccompError::new(ParseError).msg(), PARSE_ERROR);

        // Source
        assert_eq!(
            SeccompError::with_source(Source, null_err).msg(),
            NULL_ERR_MSG
        );
    }

    #[test]
    fn test_source() {
        let null_err = CString::new(TEST_NULL_STR).unwrap_err();

        assert!(SeccompError::new(Errno(-libc::EACCES)).source().is_none());
        assert!(SeccompError::with_source(Errno(-libc::EACCES), null_err)
            .source()
            .is_some());
    }

    #[test]
    fn test_from() {
        let null_err = CString::new(TEST_NULL_STR).unwrap_err();
        let scmp_err = SeccompError::from(null_err.clone());

        assert_eq!(scmp_err.kind, ErrorKind::Source);
        assert_eq!(scmp_err.source().unwrap().to_string(), null_err.to_string());
    }

    #[test]
    fn test_display() {
        let null_err = CString::new(TEST_NULL_STR).unwrap_err();

        // Errno without source
        assert_eq!(
            format!("{}", SeccompError::new(Errno(-libc::EACCES))),
            EACCES
        );
        // Errno with source
        assert_eq!(
            format!(
                "{}",
                SeccompError::with_source(Errno(-libc::EACCES), null_err.clone())
            ),
            format!("{} caused by: {}", EACCES, NULL_ERR_MSG)
        );

        // Common without source
        assert_eq!(
            format!("{}", SeccompError::new(Common(TEST_ERR_MSG.to_string()))),
            TEST_ERR_MSG
        );
        // Common with source
        assert_eq!(
            format!(
                "{}",
                SeccompError::with_source(Common(TEST_ERR_MSG.to_string()), null_err.clone())
            ),
            format!("{} caused by: {}", TEST_ERR_MSG, NULL_ERR_MSG)
        );

        // Parse without source
        assert_eq!(format!("{}", SeccompError::new(ParseError)), PARSE_ERROR);
        // Parse with source
        assert_eq!(
            format!(
                "{}",
                SeccompError::with_source(ParseError, null_err.clone())
            ),
            format!("{} caused by: {}", PARSE_ERROR, NULL_ERR_MSG)
        );

        // Source
        assert_eq!(
            format!("{}", SeccompError::with_source(ErrorKind::Source, null_err)),
            NULL_ERR_MSG
        )
    }

    #[test]
    fn test_debug() {
        let null_err = CString::new(TEST_NULL_STR).unwrap_err();

        // Errno without source
        assert_eq!(
            format!("{:?}", SeccompError::new(Errno(-libc::EACCES)),),
            format!(
                "Error {{ kind: Errno({}), source: {}, message: \"{}\" }}",
                -libc::EACCES,
                "None",
                EACCES
            )
        );
        // Errno with source
        assert_eq!(
            format!(
                "{:?}",
                SeccompError::with_source(Errno(-libc::EACCES), null_err),
            ),
            format!(
                "Error {{ kind: Errno({}), source: {}, message: \"{}\" }}",
                -libc::EACCES,
                "Some(NulError(1, [102, 0, 111, 111]))",
                EACCES
            )
        );
    }
}
