// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Copyright 2021 Sony Group Corporation
//

#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)]

/// Manually support SCMP_ACT_ERRNO and SCMP_ACT_TRACE macro
/// because the bindgen cannot expand the macros correctly.
///
/// Return the specified error code
pub fn SCMP_ACT_ERRNO(x: u16) -> u32 {
    0x00050000_u32 | u32::from(x)
}
/// Notify a tracing process with the specified value
pub fn SCMP_ACT_TRACE(x: u16) -> u32 {
    0x7ff00000_u32 | u32::from(x)
}

include!("./libseccomp_bindings.rs");
