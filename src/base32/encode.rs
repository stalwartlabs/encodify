/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{Base32, alphabet::Tables};
use crate::{Buffer, Error, buffer::Uninit};
use std::mem::MaybeUninit;

pub(super) const GROUP: usize = 5;
pub(super) const GROUP_SYMBOLS: usize = 8;
pub(super) const TAIL_SYMBOLS: [usize; GROUP] = [0, 2, 4, 5, 7];
pub(super) const PAD: u8 = b'=';
const PADDING: u64 = u64::from_ne_bytes([PAD; GROUP_SYMBOLS]);

impl Base32 {
    /// Length of the encoding of `input_len` bytes.
    pub const fn encoded_len(&self, input_len: usize) -> usize {
        if self.pads() {
            input_len.div_ceil(GROUP).saturating_mul(GROUP_SYMBOLS)
        } else {
            (input_len / GROUP)
                .saturating_mul(GROUP_SYMBOLS)
                .saturating_add(TAIL_SYMBOLS[input_len % GROUP])
        }
    }

    /// Encodes `input` into a new `String`.
    pub fn encode(&self, input: impl AsRef<[u8]>) -> String {
        self.encode_to_string(input.as_ref())
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
        self.encode_into_str(input.as_ref(), out)
    }

    #[inline]
    fn encode_to_string(&self, input: &[u8]) -> String {
        let mut out = String::with_capacity(self.encoded_len(input.len()));
        self.encode_into_buffer(input, &mut out);
        out
    }

    fn encode_into_buffer(&self, input: &[u8], out: &mut impl Buffer) -> usize {
        let len = self.encoded_len(input.len());
        // SAFETY: `encode_into` returns how many leading bytes it wrote, and
        // writes only alphabet symbols and `=`, which are ASCII.
        unsafe { out.append_ascii(len, |dst| self.encode_into(input, dst)) }
    }

    fn encode_into_slice(&self, input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let required = self.encoded_len(input.len());
        if out.len() < required {
            return Err(Error::BufferTooSmall { required });
        }
        // SAFETY: `encode_into` and the kernels only store initialised bytes.
        Ok(self.encode_into(input, unsafe { out.as_uninit() }))
    }

    fn encode_into_str<'x>(&self, input: &[u8], out: &'x mut [u8]) -> Result<&'x str, Error> {
        let written = self.encode_into_slice(input, out)?;
        let text = out
            .get(..written)
            .ok_or(Error::BufferTooSmall { required: written })?;
        debug_assert!(text.is_ascii());
        // SAFETY: `encode_into_slice` just wrote these `written` bytes, all
        // alphabet symbols or `=`, so they are ASCII and valid UTF-8.
        Ok(unsafe { std::str::from_utf8_unchecked(text) })
    }

    #[inline(always)]
    pub(super) fn encode_into(&self, input: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        let tables = self.tables();
        let (read, written) = tables.encode_groups(input, dst);
        written
            + tables.encode_tail(
                self.pads(),
                input.get(read..).unwrap_or_default(),
                dst.get_mut(written..).unwrap_or_default(),
            )
    }
}

impl Tables {
    #[inline]
    pub(super) fn encode_tail(&self, pad: bool, tail: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        let symbols = TAIL_SYMBOLS.get(tail.len()).copied().unwrap_or_default();
        if symbols == 0 {
            return 0;
        }
        let bits = tail
            .iter()
            .fold(0u64, |bits, &byte| (bits << 8) | byte as u64)
            << (8 * (GROUP - tail.len()));
        let text = u64::from_be_bytes(self.encode_block(bits));
        let (text, len) = if pad {
            let kept = !(u64::MAX >> (8 * symbols));
            ((text & kept) | (PADDING & !kept), GROUP_SYMBOLS)
        } else {
            (text, symbols)
        };
        dst.iter_mut()
            .zip(text.to_be_bytes())
            .take(len)
            .fold(0, |written, (slot, symbol)| {
                slot.write(symbol);
                written + 1
            })
    }
}
