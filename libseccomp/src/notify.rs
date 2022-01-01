// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use crate::error::ErrorKind::*;
use crate::error::{Result, SeccompError};
use crate::{ensure_supported_api, ScmpArch, ScmpFilterContext, ScmpVersion};
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
    /// # Errors
    ///
    /// If an issue is encountered getting the file descriptor,
    /// an error will be returned.
    pub fn get_notify_fd(&self) -> Result<ScmpFd> {
        notify_supported()?;

        let ret = unsafe { seccomp_notify_fd(self.ctx.as_ptr()) };
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
        let ret = unsafe { seccomp_notify_alloc(&mut req_ptr, std::ptr::null_mut()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

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
        let ret = unsafe { seccomp_notify_alloc(std::ptr::null_mut(), &mut resp_ptr) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

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
/// time-of-check-time-of-use (TOCTOU) attacks as described in seccomp_notify_id_valid(2).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScmpAction, ScmpArch, ScmpFilterContext, ScmpSyscall};
    use libc::{dup3, O_CLOEXEC};
    use std::thread;

    macro_rules! skip_if_not_supported {
        () => {
            if notify_supported().is_err() {
                println!("Skip tests for userspace notification");
                return;
            }
        };
    }

    #[derive(Debug)]
    struct TestData {
        syscall: i32,
        args: Vec<u64>,
        arch: ScmpArch,
        resp_val: i64,
        resp_err: i32,
        resp_flags: u32,
        expected_val: i64,
    }

    #[test]
    fn test_user_notification() {
        skip_if_not_supported!();

        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();
        let syscall = ScmpSyscall::from_name("dup3").unwrap().to_sys();
        let arch = ScmpArch::native().unwrap();

        ctx.add_arch(arch).unwrap();
        ctx.add_rule(ScmpAction::Notify, syscall).unwrap();

        let tests = &[
            TestData {
                syscall,
                args: vec![0, 100, O_CLOEXEC as u64],
                arch,
                resp_val: 10,
                resp_err: 0,
                resp_flags: 0,
                expected_val: 10,
            },
            TestData {
                syscall,
                args: vec![0, 100, O_CLOEXEC as u64],
                arch,
                resp_val: 0,
                resp_err: -1,
                resp_flags: 0,
                expected_val: -1,
            },
            TestData {
                syscall,
                args: vec![0, 100, O_CLOEXEC as u64],
                arch,
                resp_val: 0,
                resp_err: 0,
                resp_flags: NOTIF_FLAG_CONTINUE,
                expected_val: 100,
            },
        ];

        ctx.load().unwrap();

        let fd = ctx.get_notify_fd().unwrap();

        let mut handlers = vec![];

        for test in tests.iter() {
            let args: (i32, i32, i32) = (
                test.args[0] as i32,
                test.args[1] as i32,
                test.args[2] as i32,
            );

            handlers.push(thread::spawn(move || unsafe {
                dup3(args.0, args.1, args.2)
            }));

            let req = ScmpNotifReq::receive(fd).unwrap();

            // Checks architecture
            assert_eq!(req.data.arch, test.arch);

            // Checks the number of syscall
            assert_eq!(req.data.syscall, test.syscall);

            // Checks syscall arguments
            for (i, test_val) in test.args.iter().enumerate() {
                assert_eq!(&req.data.args[i], test_val);
            }

            // Checks TOCTOU
            assert!(notify_id_valid(fd, req.id).is_ok());

            let resp = ScmpNotifResp::new(req.id, test.resp_val, test.resp_err, test.resp_flags);
            resp.respond(fd).unwrap();
        }

        // Checks return value
        for (i, handler) in handlers.into_iter().enumerate() {
            let ret_val = handler.join().unwrap();
            assert_eq!(tests[i].expected_val as i32, ret_val);
        }
    }

    #[test]
    fn test_error() {
        skip_if_not_supported!();

        let ctx = ScmpFilterContext::new_filter(ScmpAction::Allow).unwrap();
        let resp = ScmpNotifResp::new(0, 0, 0, 0);

        assert!(ctx.get_notify_fd().is_err());
        assert!(ScmpNotifReq::receive(0).is_err());
        assert!(resp.respond(0).is_err());
        assert!(notify_id_valid(0, 0).is_err());
    }
}
