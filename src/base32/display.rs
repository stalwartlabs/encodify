/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{
    Base32,
    encode::{GROUP, GROUP_SYMBOLS},
};
use crate::buffer::Initialized;
use std::{
    fmt::{self, Alignment, Write},
    mem::MaybeUninit,
};

const CHUNK: usize = 128 * GROUP;
const CHUNK_OUT: usize = 128 * GROUP_SYMBOLS;

/// Writes the base32 encoding of a byte slice through [`fmt::Display`],
/// without allocating. Created by [`Base32::display`].
#[derive(Debug, Clone, Copy)]
pub struct Display<'x> {
    engine: Base32,
    input: &'x [u8],
}

impl Base32 {
    /// A [`std::fmt::Display`] adapter that writes the encoding of `input`
    /// without allocating; it honours width, fill and alignment.
    pub fn display<'x>(&self, input: &'x [u8]) -> Display<'x> {
        Display {
            engine: *self,
            input,
        }
    }
}

impl fmt::Display for Display<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.engine.encoded_len(self.input.len());
        let shown = f.precision().map_or(len, |precision| precision.min(len));
        let padding = f.width().map_or(0, |width| width.saturating_sub(shown));
        let (before, after) = match f.align() {
            Some(Alignment::Right) => (padding, 0),
            Some(Alignment::Center) => (padding / 2, padding - padding / 2),
            Some(Alignment::Left) | None => (0, padding),
        };
        let fill = f.fill();
        for _ in 0..before {
            f.write_char(fill)?;
        }
        let mut buffer = [MaybeUninit::uninit(); CHUNK_OUT];
        let mut left = shown;
        for piece in self.input.chunks(CHUNK) {
            if left == 0 {
                break;
            }
            let written = self.engine.encode_into(piece, &mut buffer);
            // SAFETY: `encode_into` initialised the first `written` bytes.
            let text = unsafe { buffer.initialized(written.min(left)) };
            debug_assert!(text.is_ascii());
            // SAFETY: the encoder writes only alphabet symbols and `=`, which
            // are ASCII and so valid UTF-8.
            f.write_str(unsafe { std::str::from_utf8_unchecked(text) })?;
            left -= text.len();
        }
        for _ in 0..after {
            f.write_char(fill)?;
        }
        Ok(())
    }
}
