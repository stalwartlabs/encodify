/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::lenient::{Halt, Lenient};
use crate::{
    Error,
    base64::{
        Base64,
        kernel::{Break, LineShape},
    },
    buffer::SpareCapacity,
};

const GROWTH: usize = 4096;

/// Where a folded value ends, as returned by [`Base64::decode_folded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FoldedValue {
    /// Offset of the line break that ends the value, or the input length
    /// when the value runs to the end of the input.
    pub end: usize,
    /// Offset of the byte after that line break, where the next content line
    /// starts.
    pub next: usize,
}

impl Base64 {
    /// Decodes the base64 value at the start of a folded content line
    /// (RFC 5545 section 3.1, RFC 6350 section 3.2) and appends the bytes to
    /// `out`.
    ///
    /// A line break (CRLF or LF) followed by a space or a tab is a fold and is
    /// skipped together with that space or tab; the first line break that is
    /// not a fold ends the value. Inside the value, spaces and tabs are
    /// skipped and `=` completes the pending quantum, as in lenient decoding.
    /// Any other byte is an error, and on error `out` is left unchanged.
    ///
    /// ```
    /// use encodify::base64;
    ///
    /// let card = b"SGVsbG8s\r\n IHdvcmxk\r\n IQ==\r\nEND:VCARD\r\n";
    /// let mut photo = Vec::new();
    /// let value = base64::STANDARD.decode_folded(card, &mut photo)?;
    /// assert_eq!(photo, b"Hello, world!");
    /// assert_eq!(&card[value.next..], b"END:VCARD\r\n");
    /// # Ok::<(), encodify::Error>(())
    /// ```
    pub fn decode_folded(
        &self,
        input: impl AsRef<[u8]>,
        out: &mut Vec<u8>,
    ) -> Result<FoldedValue, Error> {
        self.decode_folded_into(input.as_ref(), out)
    }

    fn decode_folded_into(&self, input: &[u8], out: &mut Vec<u8>) -> Result<FoldedValue, Error> {
        let tables = self.decode_tables();
        let shape = LineShape::detect_folded(input);
        let mut state = Lenient::folded(shape);
        let start = out.len();
        let mut bound = LineShape::folded_extent(shape, input);
        let mut read = 0;
        let halt = loop {
            let rest = input.get(read..).unwrap_or_default();
            let room = self.decoded_len_estimate(bound.saturating_sub(read)) + 3;
            let mut halt = Halt::End;
            let mut consumed = 0;
            // SAFETY: `feed` returns only the bytes it stored, halting with `Full` rather
            // than counting a quantum that does not fit.
            unsafe {
                out.append_with(room, |dst| {
                    let feed = state.feed(tables, rest, dst);
                    consumed = feed.read;
                    halt = feed.halt;
                    feed.written
                })
            };
            read += consumed;
            match halt {
                Halt::Full if bound < input.len() => {
                    bound = (read + 2 * bound.saturating_sub(read).max(GROWTH)).min(input.len());
                }
                other => break other,
            }
        };
        let value = match halt {
            Halt::Byte(byte) => match Break::skip(input.get(read..).unwrap_or_default(), false) {
                Some(len) => FoldedValue {
                    end: read,
                    next: read + len,
                },
                None => {
                    out.truncate(start);
                    return Err(Error::unexpected(byte, read));
                }
            },
            Halt::End => FoldedValue {
                end: input.len(),
                next: input.len(),
            },
            Halt::Full => {
                out.truncate(start);
                return Err(Error::BufferTooSmall {
                    required: self.decoded_len_estimate(input.len()),
                });
            }
        };
        let mut result = Ok(());
        // SAFETY: the region holds 2 bytes, the most a pending quantum flushes, so
        // `finish` stores every byte it counts, and an error commits 0.
        unsafe {
            out.append_with(2, |dst| match state.finish(dst) {
                Ok(written) => written,
                Err(err) => {
                    result = Err(err);
                    0
                }
            })
        };
        result.map(|()| value)
    }
}
