/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{Base64, Wrap, alphabet::Tables};
use crate::{
    Buffer, Error,
    buffer::{Initialized, Uninit},
};
use std::{io, mem::MaybeUninit};

const WRITER_BUFFER: usize = 4096;

impl Base64 {
    /// Encodes `input` into a new `String`.
    pub fn encode(&self, input: impl AsRef<[u8]>) -> String {
        let input = input.as_ref();
        let mut out = String::with_capacity(self.encoded_len(input.len()));
        self.encode_into_buffer(input, &mut out);
        out
    }

    /// Appends the encoding of `input` to a `Vec<u8>` or `String` and returns
    /// the number of bytes appended.
    pub fn encode_append(&self, input: impl AsRef<[u8]>, out: &mut impl Buffer) -> usize {
        self.encode_into_buffer(input.as_ref(), out)
    }

    /// Encodes `input` into `out` and returns the number of bytes written.
    pub fn encode_slice(&self, input: impl AsRef<[u8]>, out: &mut [u8]) -> Result<usize, Error> {
        self.encode_into_slice(input.as_ref(), out)
    }

    /// Encodes `input` into `out`, typically a stack array, and returns the
    /// encoded text.
    pub fn encode_str<'x>(
        &self,
        input: impl AsRef<[u8]>,
        out: &'x mut [u8],
    ) -> Result<&'x str, Error> {
        let written = self.encode_into_slice(input.as_ref(), out)?;
        let text = out
            .get(..written)
            .ok_or(Error::BufferTooSmall { required: written })?;
        debug_assert!(text.is_ascii());
        // SAFETY: `encode_into_slice` checked `out` holds the whole encoding, so
        // its first `written` bytes are alphabet symbols, `=` or CR/LF (ASCII).
        Ok(unsafe { std::str::from_utf8_unchecked(text) })
    }

    /// Writes the encoding of `input` to `writer` in chunks, without
    /// allocating.
    pub fn encode_to_writer(
        &self,
        input: impl AsRef<[u8]>,
        writer: &mut impl io::Write,
    ) -> io::Result<()> {
        let mut buffer = [MaybeUninit::uninit(); WRITER_BUFFER];
        self.encode_pieces(input.as_ref(), &mut buffer, |piece| writer.write_all(piece))
    }

    /// Encodes `input` at compile time. `N` must be
    /// `self.encoded_len(input.len())`; any other value fails to compile when
    /// used in a `const` item, and panics otherwise.
    ///
    /// ```
    /// use encodify::base64;
    ///
    /// const PROMPT: [u8; base64::STANDARD.encoded_len(9)] =
    ///     base64::STANDARD.encode_const(b"Username:");
    /// assert_eq!(&PROMPT, b"VXNlcm5hbWU6");
    /// ```
    pub const fn encode_const<const N: usize>(&self, input: &[u8]) -> [u8; N] {
        assert!(
            N == self.encoded_len(input.len()),
            "N must equal encoded_len(input.len())"
        );
        let symbols = &self.tables().encode;
        let (width, ending): (usize, &[u8]) = match self.wrap {
            Some(wrap) => (wrap.width, wrap.ending.as_bytes()),
            None => (usize::MAX, b""),
        };
        let mut out = [0u8; N];
        let mut read = 0;
        let mut written = 0;
        let mut column = 0;
        while read < input.len() {
            let remaining = input.len() - read;
            let first = input[read];
            let second = if remaining > 1 { input[read + 1] } else { 0 };
            let third = if remaining > 2 { input[read + 2] } else { 0 };
            let word = ((first as usize) << 16) | ((second as usize) << 8) | third as usize;
            let quad = [
                symbols[(word >> 18) & 0x3f],
                symbols[(word >> 12) & 0x3f],
                if remaining > 1 {
                    symbols[(word >> 6) & 0x3f]
                } else {
                    b'='
                },
                if remaining > 2 {
                    symbols[word & 0x3f]
                } else {
                    b'='
                },
            ];
            let emit = if remaining >= 3 || self.pads() {
                4
            } else {
                remaining + 1
            };
            let mut index = 0;
            while index < emit {
                out[written] = quad[index];
                written += 1;
                index += 1;
            }
            column += emit;
            read += 3;
            if column >= width || (read >= input.len() && !ending.is_empty()) {
                let mut index = 0;
                while index < ending.len() {
                    out[written] = ending[index];
                    written += 1;
                    index += 1;
                }
                column = 0;
            }
        }
        out
    }

    fn encode_into_buffer(&self, input: &[u8], out: &mut impl Buffer) -> usize {
        let len = self.encoded_len(input.len());
        // SAFETY: the region is exactly `encoded_len` long, so `encode_into`
        // writes every byte it counts, and all are alphabet symbols, `=` or CR/LF.
        unsafe { out.append_ascii(len, |dst| self.encode_into(input, dst)) }
    }

    fn encode_into_slice(&self, input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let symbols = input.len().div_ceil(3).saturating_mul(4);
        let bound = match self.wrap {
            Some(wrap) => {
                symbols.saturating_add((symbols / 4 + 1).saturating_mul(wrap.ending.len()))
            }
            None => symbols,
        };
        if out.len() < bound {
            let required = self.encoded_len(input.len());
            if out.len() < required {
                return Err(Error::BufferTooSmall { required });
            }
        }
        // SAFETY: the encoder stores only initialised `u8` values into `out`.
        Ok(self.encode_into(input, unsafe { out.as_uninit() }))
    }

    /// Encodes `input` piece by piece through `buffer`, which must hold at
    /// least four bytes, and hands every piece of output to `sink` in order.
    pub(super) fn encode_pieces<E>(
        &self,
        input: &[u8],
        buffer: &mut [MaybeUninit<u8>],
        mut sink: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let plain = buffer.len() / 4 * 3;
        let lines = self.wrap.map_or(0, |wrap| buffer.len() / wrap.line_out());
        match self.wrap {
            Some(wrap) if lines == 0 => {
                let unwrapped = self.unwrapped();
                for line in input.chunks(wrap.line_in()) {
                    for part in line.chunks(plain) {
                        let written = unwrapped.encode_into(part, buffer);
                        // SAFETY: `part` holds at most `buffer.len() / 4 * 3` bytes, whose
                        // encoding fits in `buffer`, so all `written` bytes were stored.
                        sink(unsafe { buffer.initialized(written) })?;
                    }
                    sink(wrap.ending.as_bytes())?;
                }
            }
            wrap => {
                let piece = wrap.map_or(plain, |wrap| lines * wrap.line_in());
                for part in input.chunks(piece) {
                    let written = self.encode_into(part, buffer);
                    // SAFETY: `part` is at most `plain` bytes or `lines` whole lines, whose
                    // encoding fits in `buffer`, so all `written` bytes were stored.
                    sink(unsafe { buffer.initialized(written) })?;
                }
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub(super) fn encode_into(&self, input: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        match self.wrap {
            None => self.tables().encode_plain(self.pads(), input, dst),
            Some(wrap) => self.tables().encode_wrapped(self.pads(), wrap, input, dst),
        }
    }
}

impl Tables {
    #[inline(always)]
    fn encode_plain(&self, pad: bool, input: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        let (read, written) = self.encode_groups(input, dst);
        written
            + self.encode_tail(
                pad,
                input.get(read..).unwrap_or_default(),
                dst.get_mut(written..).unwrap_or_default(),
            )
    }

    fn encode_wrapped(
        &self,
        pad: bool,
        wrap: Wrap,
        input: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> usize {
        let ending = wrap.ending.as_bytes();
        let line_in = wrap.line_in();
        if input.len() <= line_in {
            let written = self.encode_plain(pad, input, dst);
            if input.is_empty() {
                return 0;
            }
            for (slot, &byte) in dst.iter_mut().skip(written).zip(ending) {
                slot.write(byte);
            }
            debug_assert!(written + ending.len() <= dst.len());
            return written + ending.len();
        }
        let (read, mut written) = if input.len() >= 2 * line_in {
            self.encode_lines_slow(wrap, input, dst)
        } else {
            (0, 0)
        };
        for line in input.get(read..).unwrap_or_default().chunks(line_in) {
            written += self.encode_plain(pad, line, dst.get_mut(written..).unwrap_or_default());
            for (slot, &byte) in dst.iter_mut().skip(written).zip(ending) {
                slot.write(byte);
            }
            written += ending.len();
        }
        debug_assert!(written <= dst.len());
        written
    }

    #[inline(never)]
    fn encode_lines_slow(
        &self,
        wrap: Wrap,
        input: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        self.encode_lines(wrap, input, dst)
    }

    #[inline]
    fn encode_tail(&self, pad: bool, tail: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        let symbols = &self.encode;
        let (quad, len) = match *tail {
            [first] => (
                [
                    symbols[(first >> 2) as usize],
                    symbols[((first & 0x03) << 4) as usize],
                    b'=',
                    b'=',
                ],
                if pad { 4 } else { 2 },
            ),
            [first, second] => (
                [
                    symbols[(first >> 2) as usize],
                    symbols[(((first & 0x03) << 4) | (second >> 4)) as usize],
                    symbols[((second & 0x0f) << 2) as usize],
                    b'=',
                ],
                if pad { 4 } else { 3 },
            ),
            _ => return 0,
        };
        debug_assert!(len <= dst.len());
        for (slot, &byte) in dst.iter_mut().zip(quad.iter().take(len)) {
            slot.write(byte);
        }
        len
    }
}
