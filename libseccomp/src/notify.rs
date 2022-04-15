// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use super::cvt;
use crate::api::ensure_supported_api;
use crate::error::ErrorKind::*;
use crate::error::{Result, SeccompError};
use crate::{ScmpArch, ScmpFilterContext, ScmpVersion};
use libseccomp_sys::*;
use std::os::unix::io::RawFd;

fn get_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Checks the libseccomp API level and the libseccomp version for
/// the userspace notification.
///
/// This function succeeds if the libseccomp API level and the libseccomp
/// version being used are equal to or greater than 6 and 2.5.0.
///
/// # Errors
///
/// If both the libseccomp API level and the libseccomp version being used are
/// less than 6 and 2.5.0, an error will be returned.
fn notify_supported() -> Result<()> {
    ensure_supported_api("seccomp notification", 6, ScmpVersion::from((2, 5, 0)))?;

    Ok(())
}

/// Represents a file descriptor used for the userspace notification.
pub type ScmpFd = RawFd;

/// Userspace notification response flag
///
/// Tells the kernel to continue executing the system call that triggered the
/// notification. Must only be used when the notification response's error is 0.
pub const NOTIF_FLAG_CONTINUE: u32 = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

impl ScmpFilterContext {
    /// Gets a file descriptor for the userspace notification associated with the
    /// given filter context.
    ///
    /// Such a file descriptor is only valid after the filter has been loaded
    /// and only when the filter uses the [`crate::ScmpAction::Notify`] action.
    /// The file descriptor can be used to retrieve and respond to notifications
    /// associated with the filter (see [`ScmpNotifReq::receive()`],
    /// [`ScmpNotifResp::respond()`], and [`notify_id_valid()`]).
    ///
    /// This function returns a raw file descriptor for the userspace notification.
    ///
    /// This function corresponds to
    /// [`seccomp_notify_fd`](https://man7.org/linux/man-pages/man3/seccomp_notify_fd.3.html).
    ///
    /// # Errors
    ///
    /// If an issue is encountered getting the file descriptor,
    /// an error will be returned.
    pub fn get_notify_fd(&self) -> Result<ScmpFd> {
        notify_supported()?;

        let ret = unsafe { seccomp_notify_fd(self.as_ptr()) };
        if ret < 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(ret)
    }
}

/// Describes the system call context that triggered a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScmpNotifData {
    /// The syscall number
    pub syscall: i32,
    /// The filter architecture
    pub arch: ScmpArch,
    /// Address of the instruction that triggered a notification
    pub instr_pointer: u64,
    /// Arguments (up to 6) for the syscall
    pub args: [u64; 6],
}

impl ScmpNotifData {
    fn from_sys(data: seccomp_data) -> Result<Self> {
        Ok(Self {
            syscall: data.nr,
            arch: ScmpArch::from_sys(data.arch)?,
            instr_pointer: data.instruction_pointer,
            args: data.args,
        })
    }
}

/// Represents a userspace notification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScmpNotifReq {
    /// Notification ID
    pub id: u64,
    /// Process that triggered the notification event
    pub pid: u32,
    /// Filter flags (see seccomp(2))
    pub flags: u32,
    /// System call context that triggered the notification
    pub data: ScmpNotifData,
}

impl ScmpNotifReq {
    fn from_sys(req: seccomp_notif) -> Result<Self> {
        Ok(Self {
            id: req.id,
            pid: req.pid,
            flags: req.flags,
            data: ScmpNotifData::from_sys(req.data)?,
        })
    }

    /// Retrieves a userspace notification from a filter whose
    /// [`crate::ScmpAction::Notify`] action has triggered.
    ///
    /// The caller is expected to process the notification and return a
    /// response via [`ScmpNotifResp::respond()`]. Each invocation of
    /// this function returns one notification.
    /// As multiple notifications may be pending at any time, this function is
    /// normally called within a polling loop.
    ///
    /// This function returns a userspace notification request.
    ///
    /// This function corresponds to
    /// [`seccomp_notify_receive`](https://man7.org/linux/man-pages/man3/seccomp_notify_receive.3.html).
    ///
    /// # Arguments
    ///
    /// * `fd` - A file descriptor for the userspace notification
    ///
    /// # Errors
    ///
    /// If an issue is encountered getting a notification request,
    /// an error will be returned.
    pub fn receive(fd: ScmpFd) -> Result<Self> {
        notify_supported()?;

        let mut req_ptr: *mut seccomp_notif = std::ptr::null_mut();

        // We only use the request here; the response is unused.
        cvt(unsafe { seccomp_notify_alloc(&mut req_ptr, std::ptr::null_mut()) })?;

        loop {
            let ret = unsafe { seccomp_notify_receive(fd, req_ptr) };
            let errno = get_errno();

            if ret == 0 {
                break;
            } else if errno == libc::EINTR {
                continue;
            } else {
                unsafe { seccomp_notify_free(req_ptr, std::ptr::null_mut()) };
                return Err(SeccompError::new(Errno(ret)));
            }
        }

        // Copy notify request before freeing the memory.
        let req = seccomp_notif {
            id: unsafe { (*req_ptr).id },
            pid: unsafe { (*req_ptr).pid },
            flags: unsafe { (*req_ptr).flags },
            data: unsafe { (*req_ptr).data },
        };

        unsafe { seccomp_notify_free(req_ptr, std::ptr::null_mut()) };

        Self::from_sys(req)
    }
}

/// Represents a userspace notification response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScmpNotifResp {
    /// Notification ID (must match the corresponding `ScmpNotifReq` ID)
    pub id: u64,
    /// Return value for the syscall that created the notification.
    /// Only relevant if the error is 0.
    pub val: i64,
    /// An error code.
    /// Must be 0 if no error occurred, or an error constant from package
    /// syscall (e.g., `libc::EPERM`, etc). In the latter case, it's used
    /// as an error return from the syscall that created the notification.
    pub error: i32,
    /// Userspace notification response flag
    pub flags: u32,
}

impl ScmpNotifResp {
    unsafe fn to_sys(self, resp: *mut seccomp_notif_resp) {
        (*resp).id = self.id;
        (*resp).val = self.val;
        (*resp).error = self.error;
        (*resp).flags = self.flags;
    }

    /// Creates `ScmpNotifResp` from the specified arguments.
    ///
    /// # Arguments
    ///
    /// * `id` - Notification ID
    /// * `val` - Return value for the syscall that created the notification
    /// * `error` - An error code
    /// * `flags` - Userspace notification response flag
    #[must_use]
    pub fn new(id: u64, val: i64, error: i32, flags: u32) -> Self {
        Self {
            id,
            val,
            error,
            flags,
        }
    }

    /// Responds to a userspace notification retrieved via [`ScmpNotifReq::receive()`].
    ///
    /// The response ID must match that of the corresponding notification retrieved
    /// via [`ScmpNotifReq::receive()`].
    ///
    /// This function corresponds to
    /// [`seccomp_notify_respond`](https://man7.org/linux/man-pages/man3/seccomp_notify_respond.3.html).
    ///
    /// # Arguments
    ///
    /// * `fd` - A file descriptor for the userspace notification
    ///
    /// # Errors
    ///
    /// If an issue is encountered responding a notification,
    /// an error will be returned.
    pub fn respond(&self, fd: ScmpFd) -> Result<()> {
        notify_supported()?;

        let mut resp_ptr: *mut seccomp_notif_resp = std::ptr::null_mut();

        // We only use the response here; the request is unused.
        cvt(unsafe { seccomp_notify_alloc(std::ptr::null_mut(), &mut resp_ptr) })?;

        unsafe { self.to_sys(resp_ptr) };

        loop {
            let ret = unsafe { seccomp_notify_respond(fd, resp_ptr) };
            let errno = get_errno();

            if ret == 0 {
                break;
            } else if errno == libc::EINTR {
                continue;
            } else {
                unsafe { seccomp_notify_free(std::ptr::null_mut(), resp_ptr) };
                return Err(SeccompError::new(Errno(ret)));
            }
        }

        unsafe { seccomp_notify_free(std::ptr::null_mut(), resp_ptr) };

        Ok(())
    }
}

/// Checks if a userspace notification is still valid.
///
/// A return value of `Ok` means the notification is still valid.
/// Otherwise the notification is not valid. This can be used to mitigate
/// time-of-check-time-of-use (TOCTOU) attacks as described in [`seccomp_notify_id_valid(2)`].
///
/// [`seccomp_notify_id_valid(2)`]: https://man7.org/linux/man-pages/man3/seccomp_notify_id_valid.3.html
///
/// This function corresponds to
/// [`seccomp_notify_id_valid`](https://man7.org/linux/man-pages/man3/seccomp_notify_id_valid.3.html).
///
/// # Arguments
///
/// * `fd` - A file descriptor for the userspace notification
/// * `id` - Notification ID
///
/// # Errors
///
/// If the notification ID is invalid, an error will be returned.
pub fn notify_id_valid(fd: ScmpFd, id: u64) -> Result<()> {
    notify_supported()?;

    loop {
        let ret = unsafe { seccomp_notify_id_valid(fd, id) };
        let errno = get_errno();

        if ret == 0 {
            break;
        } else if errno == libc::EINTR {
            continue;
        } else {
            return Err(SeccompError::new(Errno(ret)));
        }
    }

    Ok(())
}
