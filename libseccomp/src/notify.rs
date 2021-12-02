// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

use crate::error::ErrorKind::*;
use crate::error::{Result, SeccompError};
use libseccomp_sys::*;
use std::ptr::NonNull;

pub struct ScmpNotification {
    req: NonNull<seccomp_notif>,
    resp: NonNull<seccomp_notif_resp>,
}

impl ScmpNotification {
    pub fn new() -> Result<Self> {
        let mut req_ptr: *mut seccomp_notif = std::ptr::null_mut();
        let mut resp_ptr: *mut seccomp_notif_resp = std::ptr::null_mut();

        let ret = unsafe { seccomp_notify_alloc(&mut req_ptr, &mut resp_ptr) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        let req = NonNull::new(req_ptr).ok_or_else(|| {
            SeccompError::new(Common(
                "Could not allocate notification request".to_string(),
            ))
        })?;
        let resp = NonNull::new(resp_ptr).ok_or_else(|| {
            SeccompError::new(Common(
                "Could not allocate notification response".to_string(),
            ))
        })?;

        Ok(Self { req, resp })
    }

    pub fn receive(&self, fd: i32) -> Result<()> {
        let ret = unsafe { seccomp_notify_receive(fd, self.req.as_ptr()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
    }

    pub fn respond(&self, fd: i32) -> Result<()> {
        let ret = unsafe { seccomp_notify_respond(fd, self.resp.as_ptr()) };
        if ret != 0 {
            return Err(SeccompError::new(Errno(ret)));
        }

        Ok(())
    }

    pub fn is_id_valid(&self, fd: i32) -> bool {
        let ret = unsafe { seccomp_notify_id_valid(fd, self.req.as_ref().id) };
        if ret != 0 {
            return false;
        }

        true
    }

    pub fn get_req_id(&self) -> u64 {
        unsafe { self.req.as_ref().id }
    }

    pub fn get_req_pid(&self) -> u32 {
        unsafe { self.req.as_ref().pid }
    }

    pub fn get_req_flags(&self) -> u32 {
        unsafe { self.req.as_ref().flags }
    }

    pub fn get_req_args(&self) -> &[u64; 6] {
        unsafe { &self.req.as_ref().data.args }
    }

    pub fn set_resp_id(&mut self, id: u64) {
        unsafe { self.resp.as_mut().id = id };
    }

    pub fn set_resp_val(&mut self, val: i64) {
        unsafe { self.resp.as_mut().val = val };
    }

    pub fn set_resp_error(&mut self, error: i32) {
        unsafe { self.resp.as_mut().error = error };
    }

    pub fn set_resp_flags(&mut self, flags: u32) {
        unsafe { self.resp.as_mut().flags = flags };
    }

    pub fn set_resp_all(&mut self, id: u64, val: i64, error: i32, flags: u32) {
        self.set_resp_id(id);
        self.set_resp_val(val);
        self.set_resp_error(error);
        self.set_resp_flags(flags);
    }
}

impl Drop for ScmpNotification {
    fn drop(&mut self) {
        unsafe { seccomp_notify_free(self.req.as_ptr(), self.resp.as_ptr()) };
    }
}
