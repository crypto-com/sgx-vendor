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

use crate::alloc::{AllocErr, LayoutErr, CannotReallocInPlace};
use core::any::TypeId;
use core::cell;
use core::mem::transmute;
use core::num;
use core::array;
use core::fmt::{self, Debug, Display};
use alloc_crate::str;
use alloc_crate::string::{self, String};
use alloc_crate::boxed::Box;
use alloc_crate::borrow::Cow;
use core::char;

/// `Error` is a trait representing the basic expectations for error values,
/// i.e., values of type `E` in [`Result<T, E>`]. Errors must describe
/// themselves through the [`Display`] and [`Debug`] traits, and may provide
/// cause chain information:
///
/// The [`source`] method is generally used when errors cross "abstraction
/// boundaries". If one module must report an error that is caused by an error
/// from a lower-level module, it can allow access to that error via the
/// [`source`] method. This makes it possible for the high-level module to
/// provide its own errors while also revealing some of the implementation for
/// debugging via [`source`] chains.
///
/// [`Result<T, E>`]: ../result/enum.Result.html
/// [`Display`]: ../fmt/trait.Display.html
/// [`Debug`]: ../fmt/trait.Debug.html
/// [`source`]: trait.Error.html#method.source
pub trait Error: Debug + Display {
    /// **This method is soft-deprecated.**
    ///
    /// Although using it won’t cause compilation warning,
    /// new code should use [`Display`] instead
    /// and new `impl`s can omit it.
    ///
    /// To obtain error description as a string, use `to_string()`.
    ///
    /// [`Display`]: ../fmt/trait.Display.html
    ///
    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }

    /// The lower-level cause of this error, if any.
    fn cause(&self) -> Option<&dyn Error> {
        self.source()
    }

    /// The lower-level source of this error, if any.
    fn source(&self) -> Option<&(dyn Error + 'static)> { None }

    /// Get the `TypeId` of `self`
    /// Pending CVE number here
    /// https://github.com/rust-lang/rust/issues/60784
    /// Alex said:
    /// This leaves us, however, with the question of what to do about this
    /// API? Error::type_id has been present since the inception of the Error
    /// trait, all the way back to 1.0.0. It's unstable, however, and is pretty
    /// rare as well to have a manual implementation of the type_id function.
    /// Despite this we would ideally still like a path to stability which
    /// includes safety at some point.
    ///
    /// This tracking issue is intended to serve as a location to discuss this
    /// issue and determine the best way forward to fully removing Error::type_id
    /// (so even nightly users are not affected by this memory safety issue) and
    /// having a stable mechanism for the functionality.
    ///
    /// Yu: Mark as deprecated for compile-time warning
    #[deprecated]
    fn type_id(&self, _: private::Internal) -> TypeId where Self: 'static {
        TypeId::of::<Self>()
    }
}

mod private {
    // This is a hack to prevent `type_id` from being overridden by `Error`
    // implementations, since that can enable unsound downcasting.
    #[derive(Debug)]
    pub struct Internal;
}
impl<'a, E: Error + 'a> From<E> for Box<dyn Error + 'a> {
    /// Converts a type of [`Error`] into a box of dyn [`Error`].
    ///
    fn from(err: E) -> Box<dyn Error + 'a> {
        Box::new(err)
    }
}

impl<'a, E: Error + Send + Sync + 'a> From<E> for Box<dyn Error + Send + Sync + 'a> {
    /// Converts a type of [`Error`] + [`Send`] + [`Sync`] into a box of dyn [`Error`] +
    /// [`Send`] + [`Sync`].
    ///
    fn from(err: E) -> Box<dyn Error + Send + Sync + 'a> {
        Box::new(err)
    }
}

impl From<String> for Box<dyn Error + Send + Sync> {
    /// Converts a [`String`] into a box of dyn [`Error`] + [`Send`] + [`Sync`].
    ///
    fn from(err: String) -> Box<dyn Error + Send + Sync> {
        struct StringError(String);

        impl Error for StringError {
            fn description(&self) -> &str { &self.0 }
        }

        impl Display for StringError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                Display::fmt(&self.0, f)
            }
        }

        // Purposefully skip printing "StringError(..)"
        impl Debug for StringError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                Debug::fmt(&self.0, f)
            }
        }

        Box::new(StringError(err))
    }
}

impl From<String> for Box<dyn Error> {
    /// Converts a [`String`] into a box of dyn [`Error`].
    ///
    fn from(str_err: String) -> Box<dyn Error> {
        let err1: Box<dyn Error + Send + Sync> = From::from(str_err);
        let err2: Box<dyn Error> = err1;
        err2
    }
}

impl<'a> From<&str> for Box<dyn Error + Send + Sync + 'a> {
    /// Converts a [`str`] into a box of dyn [`Error`] + [`Send`] + [`Sync`].
    ///
    fn from(err: &str) -> Box<dyn Error + Send + Sync + 'a> {
        From::from(String::from(err))
    }
}

impl From<&str> for Box<dyn Error> {
    /// Converts a [`str`] into a box of dyn [`Error`].
    ///
    fn from(err: &str) -> Box<dyn Error> {
        From::from(String::from(err))
    }
}

impl<'a, 'b> From<Cow<'b, str>> for Box<dyn Error + Send + Sync + 'a> {
    /// Converts a [`Cow`] into a box of dyn [`Error`] + [`Send`] + [`Sync`].
    ///
    fn from(err: Cow<'b, str>) -> Box<dyn Error + Send + Sync + 'a> {
        From::from(String::from(err))
    }
}

impl<'a> From<Cow<'a, str>> for Box<dyn Error> {
    /// Converts a [`Cow`] into a box of dyn [`Error`].
    ///
    fn from(err: Cow<'a, str>) -> Box<dyn Error> {
        From::from(String::from(err))
    }
}

impl Error for ! {
    fn description(&self) -> &str { *self }
}

impl Error for AllocErr {
    fn description(&self) -> &str {
        "memory allocation failed"
    }
}

impl Error for LayoutErr {
    fn description(&self) -> &str {
        "invalid parameters to Layout::from_size_align"
    }
}

impl Error for CannotReallocInPlace {
    fn description(&self) -> &str {
        CannotReallocInPlace::description(self)
    }
}

impl Error for str::ParseBoolError {
    fn description(&self) -> &str { "failed to parse bool" }
}

impl Error for str::Utf8Error {
    fn description(&self) -> &str {
        "invalid utf-8: corrupt contents"
    }
}

impl Error for num::ParseIntError {
    fn description(&self) -> &str {
        self.__description()
    }
}

impl Error for num::TryFromIntError {
    fn description(&self) -> &str {
        self.__description()
    }
}

impl Error for array::TryFromSliceError {
    fn description(&self) -> &str {
        self.__description()
    }
}

impl Error for num::ParseFloatError {
    fn description(&self) -> &str {
        self.__description()
    }
}

impl Error for string::FromUtf8Error {
    fn description(&self) -> &str {
        "invalid utf-8"
    }
}

impl Error for string::FromUtf16Error {
    fn description(&self) -> &str {
        "invalid utf-16"
    }
}

impl Error for string::ParseError {
    fn description(&self) -> &str {
        match *self {}
    }
}

impl Error for char::DecodeUtf16Error {
    fn description(&self) -> &str {
        "unpaired surrogate found"
    }
}

impl<T: Error> Error for Box<T> {
    fn description(&self) -> &str {
        Error::description(&**self)
    }

    #[allow(deprecated)]
    fn cause(&self) -> Option<&dyn Error> {
        Error::cause(&**self)
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Error::source(&**self)
    }
}

impl Error for fmt::Error {
    fn description(&self) -> &str {
        "an error occurred when formatting an argument"
    }
}

impl Error for cell::BorrowError {
    fn description(&self) -> &str {
        "already mutably borrowed"
    }
}

impl Error for cell::BorrowMutError {
    fn description(&self) -> &str {
        "already borrowed"
    }
}

impl Error for char::CharTryFromError {
    fn description(&self) -> &str {
        "converted integer out of range for `char`"
    }
}

impl Error for char::ParseCharError {
    fn description(&self) -> &str {
        self.__description()
    }
}

// copied from any.rs
impl dyn Error + 'static {
    /// Returns true if the boxed type is the same as `T`
    #[inline]
    pub fn is<T: Error + 'static>(&self) -> bool {
        // Get TypeId of the type this function is instantiated with
        let t = TypeId::of::<T>();

        // Get TypeId of the type in the trait object
        let boxed = self.type_id(private::Internal);

        // Compare both TypeIds on equality
        t == boxed
    }

    /// Returns some reference to the boxed value if it is of type `T`, or
    /// `None` if it isn't.
    #[inline]
    pub fn downcast_ref<T: Error + 'static>(&self) -> Option<&T> {
        if self.is::<T>() {
            unsafe {
                Some(&*(self as *const dyn Error as *const T))
            }
        } else {
            None
        }
    }

    /// Returns some mutable reference to the boxed value if it is of type `T`, or
    /// `None` if it isn't.
    #[inline]
    pub fn downcast_mut<T: Error + 'static>(&mut self) -> Option<&mut T> {
        if self.is::<T>() {
            unsafe {
                Some(&mut *(self as *mut dyn Error as *mut T))
            }
        } else {
            None
        }
    }
}

impl dyn Error + 'static + Send {
    /// Forwards to the method defined on the type `Any`.
    #[inline]
    pub fn is<T: Error + 'static>(&self) -> bool {
        <dyn Error + 'static>::is::<T>(self)
    }

    /// Forwards to the method defined on the type `Any`.
    #[inline]
    pub fn downcast_ref<T: Error + 'static>(&self) -> Option<&T> {
        <dyn Error + 'static>::downcast_ref::<T>(self)
    }

    /// Forwards to the method defined on the type `Any`.
    #[inline]
    pub fn downcast_mut<T: Error + 'static>(&mut self) -> Option<&mut T> {
        <dyn Error + 'static>::downcast_mut::<T>(self)
    }
}

impl dyn Error + 'static + Send + Sync {
    /// Forwards to the method defined on the type `Any`.
    #[inline]
    pub fn is<T: Error + 'static>(&self) -> bool {
        <dyn Error + 'static>::is::<T>(self)
    }

    /// Forwards to the method defined on the type `Any`.
    #[inline]
    pub fn downcast_ref<T: Error + 'static>(&self) -> Option<&T> {
        <dyn Error + 'static>::downcast_ref::<T>(self)
    }

    /// Forwards to the method defined on the type `Any`.
    #[inline]
    pub fn downcast_mut<T: Error + 'static>(&mut self) -> Option<&mut T> {
        <dyn Error + 'static>::downcast_mut::<T>(self)
    }
}

impl dyn Error {
    #[inline]
    /// Attempt to downcast the box to a concrete type.
    pub fn downcast<T: Error + 'static>(self: Box<Self>) -> Result<Box<T>, Box<dyn Error>> {
        if self.is::<T>() {
            unsafe {
                let raw: *mut dyn Error = Box::into_raw(self);
                Ok(Box::from_raw(raw as *mut T))
            }
        } else {
            Err(self)
        }
    }

    /// Returns an iterator starting with the current error and continuing with
    /// recursively calling [`source`].
    ///
    #[inline]
    pub fn iter_chain(&self) -> ErrorIter<'_> {
        ErrorIter {
            current: Some(self),
        }
    }

    /// Returns an iterator starting with the [`source`] of this error
    /// and continuing with recursively calling [`source`].
    ///
    #[inline]
    pub fn iter_sources(&self) -> ErrorIter<'_> {
        ErrorIter {
            current: self.source(),
        }
    }
}

/// An iterator over [`Error`]
///
/// [`Error`]: trait.Error.html
#[derive(Copy, Clone, Debug)]
pub struct ErrorIter<'a> {
    current: Option<&'a (dyn Error + 'static)>,
}

impl<'a> Iterator for ErrorIter<'a> {
    type Item = &'a (dyn Error + 'static);

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current;
        self.current = self.current.and_then(Error::source);
        current
    }
}

impl dyn Error + Send {
    #[inline]
    /// Attempt to downcast the box to a concrete type.
    pub fn downcast<T: Error + 'static>(self: Box<Self>)
                                        -> Result<Box<T>, Box<dyn Error + Send>> {
        let err: Box<dyn Error> = self;
        <dyn Error>::downcast(err).map_err(|s| unsafe {
            // reapply the Send marker
            transmute::<Box<dyn Error>, Box<dyn Error + Send>>(s)
        })
    }
}

impl dyn Error + Send + Sync {
    #[inline]
    /// Attempt to downcast the box to a concrete type.
    pub fn downcast<T: Error + 'static>(self: Box<Self>)
                                        -> Result<Box<T>, Box<Self>> {
        let err: Box<dyn Error> = self;
        <dyn Error>::downcast(err).map_err(|s| unsafe {
            // reapply the Send+Sync marker
            transmute::<Box<dyn Error>, Box<dyn Error + Send + Sync>>(s)
        })
    }
}
