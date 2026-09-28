/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

#[cfg(encodify_neon)]
mod neon;
#[cfg(encodify_simd)]
mod scalar;
#[cfg(not(encodify_simd))]
mod table;
#[cfg(test)]
mod tests;
#[cfg(encodify_x86)]
mod x86;

use super::{
    LineEnding, Wrap,
    alphabet::{INVALID, Tables},
};
use std::mem::MaybeUninit;

#[derive(Clone, Copy)]
#[cfg_attr(not(encodify_simd), allow(dead_code))]
pub(crate) struct LineShape {
    pub(crate) len: usize,
    pub(crate) ending: Break,
}

const MIN_LINE: usize = 16;
const MAX_LINE: usize = 1024;
const MIN_LINES_INPUT: usize = 512;

impl LineShape {
    /// The line length and line break of `src` when its first two lines are
    /// equal and end the same way, so that the line kernels can decode the run
    /// of equal lines that most likely follows. A space or tab after the
    /// terminator, as in folded header values, is part of the break.
    pub(crate) fn detect(src: &[u8]) -> Option<Self> {
        if src.len() < MIN_LINES_INPUT {
            return None;
        }
        let newline = memchr::memchr(b'\n', src.get(..MAX_LINE).unwrap_or(src))?;
        let len = match src.get(..newline)? {
            [.., b'\r'] => newline - 1,
            _ => newline,
        };
        if len < MIN_LINE || src.len() < 2 * newline + 2 {
            return None;
        }
        let rest = src.get(len..)?;
        let ending = Break::at_start(rest, true).or_else(|| Break::at_start(rest, false))?;
        let shape = LineShape { len, ending };
        (len >= MIN_LINE
            && src
                .get(shape.stride() + len..)
                .is_some_and(|next| ending.starts(next)))
        .then_some(shape)
    }

    /// The shape of the continuation lines of a folded value: the length of
    /// the second line after its leading space or tab, and the fold that ends
    /// it. The first line is usually shorter, as it follows the property name.
    pub(crate) fn detect_folded(src: &[u8]) -> Option<Self> {
        if src.len() < MIN_LINES_INPUT {
            return None;
        }
        let first = memchr::memchr(b'\n', src.get(..MAX_LINE).unwrap_or(src))?;
        let rest = match src.get(first + 1..)? {
            [b' ' | b'\t', rest @ ..] => rest,
            _ => return None,
        };
        let newline = memchr::memchr(b'\n', rest.get(..MAX_LINE).unwrap_or(rest))?;
        let len = match rest.get(..newline)? {
            [.., b'\r'] => newline - 1,
            _ => newline,
        };
        let ending = Break::at_start(rest.get(len..)?, true)?;
        (len >= MIN_LINE && rest.len() >= 2 * len).then_some(LineShape { len, ending })
    }

    pub(crate) const fn stride(self) -> usize {
        self.len + self.ending.len()
    }

    /// Where the folded value at the start of `src` most likely ends. With the
    /// shape of its continuation lines, the lines that follow the shape are
    /// counted by galloping over their breaks; without one, every line break
    /// is checked.
    pub(crate) fn folded_extent(shape: Option<Self>, src: &[u8]) -> usize {
        let Some(shape) = shape else {
            let mut at = 0;
            while let Some(newline) = src.get(at..).and_then(|rest| memchr::memchr(b'\n', rest)) {
                let next = at + newline + 1;
                match src.get(next) {
                    Some(b' ' | b'\t') => at = next + 1,
                    _ => return next,
                }
            }
            return src.len();
        };
        let Some(first) = memchr::memchr(b'\n', src) else {
            return src.len();
        };
        let body = first + 2;
        let full = |line: usize| {
            src.get(body + line * shape.stride() + shape.len..)
                .is_some_and(|rest| shape.ending.starts(rest))
        };
        let mut known = 0;
        let mut step = 1;
        while full(known + step - 1) {
            known += step;
            step *= 2;
        }
        while step > 1 {
            step /= 2;
            if full(known + step - 1) {
                known += step;
            }
        }
        let last = body + known * shape.stride();
        src.get(last..)
            .and_then(|rest| memchr::memchr(b'\n', rest))
            .map_or(src.len(), |newline| last + newline + 1)
    }
}

/// A line break as the line kernels match it: LF or CRLF, followed in folded
/// text by the space or tab that starts the continuation line.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Break {
    bytes: [u8; 3],
    len: u8,
}

#[cfg_attr(not(encodify_simd), allow(dead_code))]
impl Break {
    /// The length of the line break at the start of `src`; with `folded`, only
    /// a break followed by a space or a tab counts, and that byte is part of
    /// it.
    #[inline(always)]
    pub(crate) fn skip(src: &[u8], folded: bool) -> Option<usize> {
        let (terminator, rest) = match src {
            [b'\r', b'\n', rest @ ..] => (2, rest),
            [b'\n', rest @ ..] => (1, rest),
            _ => return None,
        };
        match rest.first() {
            _ if !folded => Some(terminator),
            Some(b' ' | b'\t') => Some(terminator + 1),
            _ => None,
        }
    }

    fn at_start(src: &[u8], folded: bool) -> Option<Break> {
        let len = Break::skip(src, folded)?;
        let mut bytes = [0; 3];
        for (slot, &byte) in bytes.iter_mut().zip(src.iter().take(len)) {
            *slot = byte;
        }
        Some(Break {
            bytes,
            len: len as u8,
        })
    }

    pub(crate) const fn len(self) -> usize {
        self.len as usize
    }

    fn starts(self, src: &[u8]) -> bool {
        src.get(..self.len()) == self.bytes.get(..self.len())
    }

    /// Whether the break starts at `at`.
    ///
    /// # Safety
    ///
    /// `at` must be valid for reading `self.len()` bytes.
    #[inline(always)]
    pub(crate) unsafe fn is_at(self, at: *const u8) -> bool {
        let [first, second, third] = self.bytes;
        // SAFETY: `self.len` is 1, 2 or 3 (from `Break::skip`) and each arm reads
        // exactly that many bytes, which the caller guarantees are readable.
        unsafe {
            match self.len {
                1 => *at == first,
                2 => *at == first && *at.add(1) == second,
                _ => *at == first && *at.add(1) == second && *at.add(2) == third,
            }
        }
    }
}

#[cfg_attr(not(encodify_simd), allow(dead_code))]
impl LineEnding {
    /// Writes the terminator at `at`.
    ///
    /// # Safety
    ///
    /// `at` must be valid for writing `self.len()` bytes.
    #[inline(always)]
    pub(crate) unsafe fn write_at(self, at: *mut u8) {
        // SAFETY: each arm writes exactly `self.len()` bytes (2 for CRLF, 1 for
        // LF), which the caller guarantees are writable; the CRLF store is unaligned.
        unsafe {
            match self {
                LineEnding::CrLf => at.cast::<[u8; 2]>().write_unaligned(*b"\r\n"),
                LineEnding::Lf => at.write(b'\n'),
            }
        }
    }
}

impl Tables {
    #[inline(always)]
    fn decode_quads_simd(&self, src: &[u8], dst: &mut [MaybeUninit<u8>]) -> Option<(usize, usize)> {
        #[cfg(encodify_neon)]
        {
            self.decode_quads_neon(src, dst)
        }
        #[cfg(encodify_x86)]
        {
            let nibbles = self.nibbles.as_ref()?;
            if cfg!(not(encodify_no_avx2)) && std::is_x86_feature_detected!("avx2") {
                // SAFETY: AVX2 was detected at runtime just above; the kernel
                // takes bounds-checked slices and has no other precondition.
                unsafe { nibbles.decode_quads_avx2(src, dst) }
            } else if std::is_x86_feature_detected!("ssse3") {
                // SAFETY: SSSE3 was detected at runtime just above; the kernel
                // takes bounds-checked slices and has no other precondition.
                unsafe { nibbles.decode_quads_ssse3(src, dst) }
            } else {
                None
            }
        }
        #[cfg(not(encodify_simd))]
        {
            let _ = (src, dst);
            None
        }
    }

    #[inline(always)]
    fn encode_groups_simd(&self, src: &[u8], dst: &mut [MaybeUninit<u8>]) -> (usize, usize) {
        #[cfg(encodify_neon)]
        {
            self.encode_groups_neon(src, dst)
        }
        #[cfg(encodify_x86)]
        {
            if cfg!(not(encodify_no_avx2)) && std::is_x86_feature_detected!("avx2") {
                // SAFETY: AVX2 was detected at runtime just above; the kernel
                // takes bounds-checked slices and has no other precondition.
                unsafe { self.encode_groups_avx2(src, dst) }
            } else if std::is_x86_feature_detected!("ssse3") {
                // SAFETY: SSSE3 was detected at runtime just above; the kernel
                // takes bounds-checked slices and has no other precondition.
                unsafe { self.encode_groups_ssse3(src, dst) }
            } else {
                (0, 0)
            }
        }
        #[cfg(not(encodify_simd))]
        {
            let _ = (src, dst);
            (0, 0)
        }
    }

    /// Decodes whole quads from the start of `src` until the first one that
    /// holds a byte outside the alphabet, or until `dst` is full. Returns the
    /// bytes read and written. The SIMD kernels take every input of at least
    /// one vector of quads, stopping at the first invalid quad like the scalar
    /// loop, which handles the shorter ones.
    #[inline(always)]
    pub(crate) fn decode_quads(&self, src: &[u8], dst: &mut [MaybeUninit<u8>]) -> (usize, usize) {
        match self.decode_quads_simd(src, dst) {
            Some(done) => done,
            None if src.len() >= 4 => self.decode_quads_scalar(src, dst),
            None => (0, 0),
        }
    }

    #[inline(always)]
    fn starts_with_quad(&self, src: &[u8]) -> bool {
        src.first_chunk::<4>().is_some_and(|quad| {
            quad.iter()
                .all(|&byte| self.decode[byte as usize] != INVALID)
        })
    }

    /// Encodes whole 3-byte groups from the start of `src` while they fit in
    /// `dst`. Returns the bytes read and written.
    #[inline(always)]
    pub(crate) fn encode_groups(&self, src: &[u8], dst: &mut [MaybeUninit<u8>]) -> (usize, usize) {
        let (read, written) = self.encode_groups_simd(src, dst);
        if read == (src.len() / 3).min(dst.len() / 4) * 3 {
            return (read, written);
        }
        let (more_read, more_written) = self.encode_groups_scalar(
            src.get(read..).unwrap_or_default(),
            dst.get_mut(written..).unwrap_or_default(),
        );
        (read + more_read, written + more_written)
    }

    #[inline]
    fn decode_line_run(
        &self,
        shape: LineShape,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        #[cfg(encodify_neon)]
        {
            self.decode_lines_neon(shape, src, dst)
        }
        #[cfg(encodify_x86)]
        {
            let Some(nibbles) = &self.nibbles else {
                return (0, 0);
            };
            if cfg!(not(encodify_no_avx2)) && std::is_x86_feature_detected!("avx2") {
                // SAFETY: AVX2 was detected at runtime just above; the kernel
                // takes bounds-checked slices and has no other precondition.
                unsafe { nibbles.decode_lines_avx2(shape, src, dst) }
            } else if std::is_x86_feature_detected!("ssse3") {
                // SAFETY: SSSE3 was detected at runtime just above; the kernel
                // takes bounds-checked slices and has no other precondition.
                unsafe { nibbles.decode_lines_ssse3(shape, src, dst) }
            } else {
                (0, 0)
            }
        }
        #[cfg(not(encodify_simd))]
        {
            let _ = (shape, src, dst);
            (0, 0)
        }
    }

    /// Decodes quads, skipping the line breaks between them (only folds when
    /// `folded`), until any other byte that is not a symbol. Runs of lines of
    /// `shape` take the line kernels, from the first line break on when
    /// `mid_line`.
    #[inline]
    pub(crate) fn decode_lines(
        &self,
        shape: Option<LineShape>,
        folded: bool,
        mid_line: bool,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let mut read = 0;
        let mut written = 0;
        let mut line_start = !mid_line;
        loop {
            if let Some(shape) = shape.filter(|_| {
                line_start && self.starts_with_quad(src.get(read..).unwrap_or_default())
            }) {
                let (done, out) = self.decode_line_run(
                    shape,
                    src.get(read..).unwrap_or_default(),
                    dst.get_mut(written..).unwrap_or_default(),
                );
                read += done;
                written += out;
            }
            let rest = src.get(read..).unwrap_or_default();
            let (done, out) = if line_start || self.starts_with_quad(rest) {
                self.decode_quads(rest, dst.get_mut(written..).unwrap_or_default())
            } else {
                (0, 0)
            };
            read += done;
            written += out;
            match Break::skip(src.get(read..).unwrap_or_default(), folded) {
                Some(len) => {
                    read += len;
                    line_start = true;
                }
                None => return (read, written),
            }
        }
    }

    /// Encodes whole lines of `wrap`, each followed by its terminator, while
    /// they fit. Returns the bytes read and written; the caller encodes the
    /// rest.
    #[inline]
    pub(crate) fn encode_lines(
        &self,
        wrap: Wrap,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        debug_assert!(wrap.width.is_multiple_of(4));
        #[cfg(encodify_neon)]
        {
            self.encode_lines_neon(wrap, src, dst)
        }
        #[cfg(encodify_x86)]
        {
            if cfg!(not(encodify_no_avx2)) && std::is_x86_feature_detected!("avx2") {
                // SAFETY: AVX2 was detected at runtime just above;
                // `Base64::wrapped` rounds `wrap.width` to a multiple of 4 (asserted above).
                unsafe { self.encode_lines_avx2(wrap, src, dst) }
            } else if std::is_x86_feature_detected!("ssse3") {
                // SAFETY: SSSE3 was detected at runtime just above;
                // `Base64::wrapped` rounds `wrap.width` to a multiple of 4 (asserted above).
                unsafe { self.encode_lines_ssse3(wrap, src, dst) }
            } else {
                (0, 0)
            }
        }
        #[cfg(not(encodify_simd))]
        {
            let _ = (wrap, src, dst);
            (0, 0)
        }
    }
}
