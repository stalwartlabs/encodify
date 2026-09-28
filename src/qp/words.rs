/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{
    Mode, QuotedPrintable,
    kernel::{Job, Kernel},
    output::Output,
    tables::{ESCAPED, WordClass},
};
use crate::{
    Buffer,
    hex::{BLOCK_ROOM, EscapeTable},
};
use std::mem::MaybeUninit;

const SLACK: usize = 64;

impl QuotedPrintable {
    /// Appends the encoding of the longest prefix of `text` that ends on a
    /// character boundary and whose encoding is at most `budget` bytes long,
    /// and returns the length of that prefix in bytes. When not even the
    /// first character fits, nothing is appended and the result is zero.
    ///
    /// The encoding of a prefix is what [`QuotedPrintable::encode`] writes
    /// for it on its own, so with `BODY` and `BINARY` a space or tab that
    /// ends the prefix is escaped. RFC 2047 encoded words are the main use:
    /// a word never splits a character.
    ///
    /// ```
    /// use encodify::qp;
    ///
    /// let mut word = String::new();
    /// let taken = qp::Q_TEXT.encode_prefix("Grüße aus Köln", 13, &mut word);
    /// assert_eq!((taken, word.as_str()), (4, "Gr=C3=BC"));
    /// ```
    pub fn encode_prefix(&self, text: &str, budget: usize, out: &mut impl Buffer) -> usize {
        let mut taken = 0;
        // SAFETY: `prefix_into` initialises every byte it counts, and its encoders emit only ASCII
        // (printable literals, `_`, tabs, CRLF and `=XX`).
        unsafe {
            out.append_ascii(self.prefix_room(text.len(), budget), |dst| {
                let (read, written) = self.prefix_into(text, budget, dst);
                taken = read;
                written
            })
        };
        taken
    }

    pub(crate) fn append_word(
        &self,
        head: &[&[u8]],
        text: &str,
        budget: usize,
        tail: &[u8],
        out: &mut impl Buffer,
    ) -> (usize, usize) {
        let head_len: usize = head.iter().map(|piece| piece.len()).sum();
        let room = head_len + self.prefix_room(text.len(), budget) + tail.len();
        let mut taken = 0;
        // SAFETY: `room` fits `head`, the encoded prefix and `tail`, all written contiguously and
        // clamped to `dst`; `put_ascii` maps non-ASCII to `?` and the encoder emits only ASCII.
        let appended = unsafe {
            out.append_ascii(room, |dst| {
                let start = head.iter().fold(0, |at, piece| {
                    dst.put_ascii(at, piece);
                    at + piece.len()
                });
                let (read, written) =
                    self.prefix_into(text, budget, dst.get_mut(start..).unwrap_or_default());
                if read == 0 {
                    return 0;
                }
                taken = read;
                let end = start + written;
                dst.put_ascii(end, tail);
                (end + tail.len()).min(dst.len())
            })
        };
        (taken, appended)
    }

    pub(super) fn prefix_room(&self, len: usize, budget: usize) -> usize {
        match self.mode {
            Mode::Body | Mode::Binary => budget.min(Self::worst_case(len)).saturating_add(SLACK),
            _ => len
                .saturating_mul(ESCAPED)
                .min(budget)
                .saturating_add(BLOCK_ROOM),
        }
    }

    fn prefix_into(
        &self,
        text: &str,
        budget: usize,
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let bytes = text.as_bytes();
        match self.mode {
            Mode::Body | Mode::Binary => {
                let taken = self.line_prefix(text, budget);
                let prefix = bytes.get(..taken).unwrap_or_default();
                let (read, written) = self.fill_lines(prefix, &mut 0, dst);
                debug_assert_eq!(read, taken);
                (taken, written)
            }
            mode => match bytes.len().saturating_mul(ESCAPED) <= budget {
                true => mode.words(bytes, dst, usize::MAX, true),
                false => mode.words(bytes, dst, budget, true),
            },
        }
    }
}

impl Mode {
    pub(super) fn encode_words(self, input: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        let (_, written) = self.words(input, dst, usize::MAX, false);
        written
    }

    #[inline]
    pub(super) fn words(
        self,
        input: &[u8],
        dst: &mut [MaybeUninit<u8>],
        budget: usize,
        chars: bool,
    ) -> (usize, usize) {
        Words {
            table: self.table(),
            class: self.class(),
            input,
            dst,
            budget,
            chars,
        }
        .dispatch()
    }
}

pub(super) struct Words<'x> {
    pub(super) table: &'x EscapeTable,
    pub(super) class: &'x WordClass,
    pub(super) input: &'x [u8],
    pub(super) dst: &'x mut [MaybeUninit<u8>],
    pub(super) budget: usize,
    pub(super) chars: bool,
}

impl Job for Words<'_> {
    type Output = (usize, usize);

    #[inline(always)]
    fn run<K: Kernel>(self) -> (usize, usize) {
        let Words {
            table,
            class,
            input,
            dst,
            budget,
            chars,
        } = self;
        let (read, written) = K::word_blocks(table, class, input, dst, budget);
        match budget {
            usize::MAX => {
                let rest = input.get(read..).unwrap_or_default();
                let tail = table.encode_into(rest, dst.get_mut(written..).unwrap_or_default());
                (input.len(), written + tail)
            }
            _ => table.encode_within(input, (read, written), budget, chars, dst),
        }
    }
}
