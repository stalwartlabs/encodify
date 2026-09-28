/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use std::mem::MaybeUninit;

/// A growable buffer that encoders append their output to.
///
/// Implemented for `Vec<u8>` and `String`. Encoders only ever append ASCII,
/// so appending to a `String` keeps it valid UTF-8 without a validation pass.
pub trait Buffer: sealed::Sealed {}

impl Buffer for Vec<u8> {}
impl Buffer for String {}

pub(crate) mod sealed {
    use super::SpareCapacity;
    use std::mem::MaybeUninit;

    pub trait Sealed {
        /// The bytes of the buffer.
        ///
        /// # Safety
        ///
        /// Only ASCII may be written to the returned vector.
        unsafe fn ascii_vec(&mut self) -> &mut Vec<u8>;

        /// Appends up to `max_len` ASCII bytes without zero-filling them
        /// first.
        ///
        /// # Safety
        ///
        /// Same contract as [`SpareCapacity::append_with`], and every
        /// committed byte must be ASCII.
        #[inline(always)]
        unsafe fn append_ascii(
            &mut self,
            max_len: usize,
            fill: impl FnOnce(&mut [MaybeUninit<u8>]) -> usize,
        ) -> usize {
            // SAFETY: our caller guarantees every committed byte is ASCII, and
            // bytes past the committed length are never part of the buffer.
            let vec = unsafe { self.ascii_vec() };
            let start = vec.len();
            // SAFETY: our caller upholds the `append_with` contract for `fill`.
            let written = unsafe { vec.append_with(max_len, fill) };
            debug_assert!(vec.get(start..).is_some_and(<[u8]>::is_ascii));
            written
        }

        /// Appends `bytes`, replacing every byte that is not ASCII with `?`,
        /// and returns the number of bytes appended.
        #[inline]
        fn push_ascii(&mut self, bytes: &[u8]) -> usize {
            self.push_ascii_where(bytes, |_| true)
        }

        /// Appends `bytes`, replacing every byte that is not ASCII or that
        /// `keep` rejects with `?`, and returns the number of bytes appended.
        #[inline]
        fn push_ascii_where(&mut self, bytes: &[u8], keep: impl Fn(u8) -> bool) -> usize {
            // SAFETY: the region holds `bytes.len()` slots and all of them are
            // written, each with an ASCII byte or `?`, before returning that
            // length.
            unsafe {
                self.append_ascii(bytes.len(), |dst| {
                    for (slot, &byte) in dst.iter_mut().zip(bytes) {
                        slot.write(if byte.is_ascii() && keep(byte) {
                            byte
                        } else {
                            b'?'
                        });
                    }
                    bytes.len()
                })
            }
        }

        /// Reserves room for at least `additional` more bytes.
        #[inline]
        fn reserve_ascii(&mut self, additional: usize) {
            // SAFETY: reserving capacity writes no bytes.
            unsafe { self.ascii_vec() }.reserve(additional);
        }
    }

    impl Sealed for Vec<u8> {
        #[inline(always)]
        unsafe fn ascii_vec(&mut self) -> &mut Vec<u8> {
            self
        }
    }

    impl Sealed for String {
        #[inline(always)]
        unsafe fn ascii_vec(&mut self) -> &mut Vec<u8> {
            // SAFETY: our caller writes only ASCII, which keeps the string
            // valid UTF-8.
            unsafe { self.as_mut_vec() }
        }
    }
}

pub(crate) trait SpareCapacity {
    /// Appends up to `max_len` bytes without zero-filling them first.
    ///
    /// # Safety
    ///
    /// `fill` receives `max_len` bytes of spare capacity and returns a length
    /// `n`; the first `n` bytes of the region must be initialised when it
    /// returns. The rest of the region may be used as scratch space.
    unsafe fn append_with(
        &mut self,
        max_len: usize,
        fill: impl FnOnce(&mut [MaybeUninit<u8>]) -> usize,
    ) -> usize;
}

impl SpareCapacity for Vec<u8> {
    #[inline(always)]
    unsafe fn append_with(
        &mut self,
        max_len: usize,
        fill: impl FnOnce(&mut [MaybeUninit<u8>]) -> usize,
    ) -> usize {
        self.reserve(max_len);
        let start = self.len();
        let spare = self.spare_capacity_mut();
        let region = match spare.get_mut(..max_len) {
            Some(region) => region,
            None => spare,
        };
        let filled = fill(region);
        debug_assert!(filled <= max_len);
        let written = filled.min(max_len);
        // SAFETY: `reserve` made `region` exactly `max_len` long, and `fill`
        // initialised its first `written` bytes, so they are within capacity.
        unsafe { self.set_len(start + written) };
        written
    }
}

pub(crate) trait Uninit {
    /// Views an initialised slice as a slice the kernels can write into.
    ///
    /// # Safety
    ///
    /// Only initialised values may be written through the returned slice.
    unsafe fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>];
}

impl Uninit for [u8] {
    #[inline(always)]
    unsafe fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        // SAFETY: `MaybeUninit<u8>` has the layout of `u8`, and our caller
        // writes only initialised values, so `self` stays initialised.
        unsafe { &mut *(std::ptr::from_mut(self) as *mut [MaybeUninit<u8>]) }
    }
}

pub(crate) trait Initialized {
    /// The first `len` bytes, or all of them when there are fewer.
    ///
    /// # Safety
    ///
    /// Those bytes must be initialised.
    unsafe fn initialized(&self, len: usize) -> &[u8];
}

impl Initialized for [MaybeUninit<u8>] {
    #[inline(always)]
    unsafe fn initialized(&self, len: usize) -> &[u8] {
        debug_assert!(len <= self.len());
        let len = len.min(self.len());
        // SAFETY: `len` is clamped to the slice, `MaybeUninit<u8>` has the
        // layout of `u8`, and our caller guarantees those bytes are initialised.
        unsafe { std::slice::from_raw_parts(self.as_ptr().cast(), len) }
    }
}
