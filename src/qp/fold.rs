/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{Mode, QuotedPrintable, tables::MAX_CONTENT};
use crate::{Buffer, Fold, buffer::Initialized, hex::BLOCK_ROOM};
use std::mem::MaybeUninit;

const BUFFER: usize = 1024;

impl QuotedPrintable {
    /// Encodes `input`, folding it as described by `fold`. `column` is the
    /// current column before the call and is updated to the column after
    /// it, so text written around the value can share it. Every piece of
    /// output, data and separators alike, is handed to `sink` in order,
    /// which lets the value stream into a hasher or a writer.
    ///
    /// A fold is written only before an encoded byte, a literal character or
    /// a `=XX` escape, that would pass `width`, and never inside an escape,
    /// so a value can end exactly at `width`; text written after it must
    /// check `column` and fold first if it does not fit. `BODY` and `BINARY`
    /// break their own lines with soft line breaks and do not use `fold`:
    /// `column` is then the column within the current encoded line.
    ///
    /// ```
    /// use encodify::{Fold, qp};
    ///
    /// let mut value = Vec::new();
    /// let mut column = 70;
    /// qp::DKIM.encode_folded("jörg@example.org", &mut column, Fold::DKIM, |piece| {
    ///     value.extend_from_slice(piece)
    /// });
    /// assert_eq!(value, b"j=C3\r\n\t=B6rg@example.org");
    /// assert_eq!(column, 18);
    /// ```
    pub fn encode_folded(
        &self,
        input: impl AsRef<[u8]>,
        column: &mut usize,
        fold: Fold<'_>,
        mut sink: impl FnMut(&[u8]),
    ) {
        let mut buffer = [MaybeUninit::uninit(); BUFFER];
        let mut rest = input.as_ref();
        match self.mode {
            Mode::Body | Mode::Binary => {
                *column = (*column).min(MAX_CONTENT);
                while !rest.is_empty() {
                    let (read, written) = self.fill_lines(rest, column, &mut buffer);
                    // SAFETY: `fill_lines` counts only bytes it wrote into `buffer`.
                    sink(unsafe { buffer.initialized(written) });
                    rest = rest.get(read..).unwrap_or_default();
                }
            }
            mode => {
                while let Some(&first) = rest.first() {
                    let room = fold.width.saturating_sub(*column).min(BUFFER - BLOCK_ROOM);
                    let (read, written) = mode.words(rest, &mut buffer, room, false);
                    if read > 0 {
                        // SAFETY: `words` counts only bytes it wrote, at most `room`, which is
                        // below `BUFFER`.
                        sink(unsafe { buffer.initialized(written) });
                        *column += written;
                        rest = rest.get(read..).unwrap_or_default();
                    } else if *column > fold.indent {
                        sink(fold.separator);
                        *column = fold.indent;
                    } else {
                        let piece = mode.byte_str(first);
                        sink(piece.as_bytes());
                        *column += piece.len();
                        rest = rest.get(1..).unwrap_or_default();
                    }
                }
            }
        }
    }

    /// Like [`QuotedPrintable::encode_folded`], appending to a `Vec<u8>` or
    /// `String`. The separator must be ASCII. Returns the number of bytes
    /// appended.
    pub fn encode_folded_append(
        &self,
        input: impl AsRef<[u8]>,
        out: &mut impl Buffer,
        column: &mut usize,
        fold: Fold<'_>,
    ) -> usize {
        let mut appended = 0;
        self.encode_folded(input, column, fold, |piece| {
            appended += out.push_ascii(piece)
        });
        appended
    }
}
