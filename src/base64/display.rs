/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::Base64;
use std::{
    fmt::{self, Alignment, Write},
    mem::MaybeUninit,
};

const BUFFER: usize = 1024;

/// Writes the base64 encoding of a byte slice through [`fmt::Display`],
/// without allocating. Created by [`Base64::display`].
#[derive(Debug, Clone, Copy)]
pub struct Display<'x> {
    engine: Base64,
    input: &'x [u8],
}

impl Base64 {
    /// A [`std::fmt::Display`] adapter that writes the encoding of `input`
    /// without allocating; it honours width, fill, alignment and precision.
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
        let mut buffer = [MaybeUninit::uninit(); BUFFER];
        let mut left = shown;
        let written = self.engine.encode_pieces(self.input, &mut buffer, |piece| {
            let text = piece.get(..left).unwrap_or(piece);
            debug_assert!(text.is_ascii());
            // SAFETY: pieces hold only alphabet symbols, `=` and CR/LF, and any
            // prefix of ASCII is valid UTF-8.
            f.write_str(unsafe { std::str::from_utf8_unchecked(text) })
                .map_err(Some)?;
            left -= text.len();
            if left == 0 { Err(None) } else { Ok(()) }
        });
        if let Err(Some(err)) = written {
            return Err(err);
        }
        for _ in 0..after {
            f.write_char(fill)?;
        }
        Ok(())
    }
}
