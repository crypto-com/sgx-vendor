// Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Unix-specific extensions to general I/O primitives

use sgx_trts::libc;
#[cfg(feature = "untrusted_fs")]
use crate::fs;
#[cfg(not(feature = "untrusted_fs"))]
use crate::untrusted::fs;
use crate::os::raw;
use crate::sys;
use crate::io;
use crate::sys_common::{AsInner, FromInner, IntoInner};

/// Raw file descriptors.
pub type RawFd = raw::c_int;

/// A trait to extract the raw unix file descriptor from an underlying
/// object.
///
/// This is only available on unix platforms and must be imported in order
/// to call the method. Windows platforms have a corresponding `AsRawHandle`
/// and `AsRawSocket` set of traits.
pub trait AsRawFd {
    /// Extracts the raw file descriptor.
    ///
    /// This method does **not** pass ownership of the raw file descriptor
    /// to the caller. The descriptor is only guaranteed to be valid while
    /// the original object has not yet been destroyed.
    fn as_raw_fd(&self) -> RawFd;
}

/// A trait to express the ability to construct an object from a raw file
/// descriptor.
pub trait FromRawFd {
    /// Constructs a new instance of `Self` from the given raw file
    /// descriptor.
    ///
    /// This function **consumes ownership** of the specified file
    /// descriptor. The returned object will take responsibility for closing
    /// it when the object goes out of scope.
    ///
    /// This function is also unsafe as the primitives currently returned
    /// have the contract that they are the sole owner of the file
    /// descriptor they are wrapping. Usage of this function could
    /// accidentally allow violating this contract which can cause memory
    /// unsafety in code that relies on it being true.
    unsafe fn from_raw_fd(fd: RawFd) -> Self;
}

/// A trait to express the ability to consume an object and acquire ownership of
/// its raw file descriptor.
pub trait IntoRawFd {
    /// Consumes this object, returning the raw underlying file descriptor.
    ///
    /// This function **transfers ownership** of the underlying file descriptor
    /// to the caller. Callers are then the unique owners of the file descriptor
    /// and must close the descriptor once it's no longer needed.
    fn into_raw_fd(self) -> RawFd;
}

impl AsRawFd for fs::File {
    fn as_raw_fd(&self) -> RawFd {
        self.as_inner().fd().raw()
    }
}

impl FromRawFd for fs::File {
    unsafe fn from_raw_fd(fd: RawFd) -> fs::File {
        fs::File::from_inner(sys::fs::File::from_inner(fd))
    }
}

impl IntoRawFd for fs::File {
    fn into_raw_fd(self) -> RawFd {
        self.into_inner().into_fd().into_raw()
    }
}

#[cfg(feature = "stdio")]
impl AsRawFd for io::Stdin {
    fn as_raw_fd(&self) -> RawFd { libc::STDIN_FILENO }
}

#[cfg(feature = "stdio")]
impl AsRawFd for io::Stdout {
    fn as_raw_fd(&self) -> RawFd { libc::STDOUT_FILENO }
}

#[cfg(feature = "stdio")]
impl AsRawFd for io::Stderr {
    fn as_raw_fd(&self) -> RawFd { libc::STDERR_FILENO }
}

#[cfg(feature = "stdio")]
impl<'a> AsRawFd for io::StdinLock<'a> {
    fn as_raw_fd(&self) -> RawFd { libc::STDIN_FILENO }
}

#[cfg(feature = "stdio")]
impl<'a> AsRawFd for io::StdoutLock<'a> {
    fn as_raw_fd(&self) -> RawFd { libc::STDOUT_FILENO }
}

#[cfg(feature = "stdio")]
impl<'a> AsRawFd for io::StderrLock<'a> {
    fn as_raw_fd(&self) -> RawFd { libc::STDERR_FILENO }
}
