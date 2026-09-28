/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{
    Mode, QuotedPrintable,
    count::HighBytes,
    kernel::{Job, Kernel},
    output::Output,
    tables::{BLANK, CLASS, CR, ESCAPED, HARD_BREAK, LF, MAX_CONTENT, PLAIN, QpByte, SOFT_BREAK},
};
use crate::{
    Buffer, Error,
    buffer::{Initialized, Uninit},
};
use std::{io, mem::MaybeUninit};

const SLACK: usize = 64;
const ESTIMATE_MARGIN: usize = 16;
const REST_MARGIN: usize = 8;
const WRITER_CHUNK: usize = 8 * 1024;

impl QuotedPrintable {
    /// Encodes `input` into a new `String`.
    pub fn encode(&self, input: impl AsRef<[u8]>) -> String {
        let input = input.as_ref();
        let mut out = match self.mode {
            Mode::Body | Mode::Binary => String::new(),
            _ => String::with_capacity(input.len().saturating_mul(ESCAPED).saturating_add(1)),
        };
        self.encode_append(input, &mut out);
        out
    }

    /// Appends the encoding of `input` to a `Vec<u8>` or `String` and returns
    /// the number of bytes appended.
    pub fn encode_append(&self, input: impl AsRef<[u8]>, out: &mut impl Buffer) -> usize {
        let input = input.as_ref();
        match self.mode {
            Mode::Body | Mode::Binary => self.append_lines(input, out),
            // SAFETY: `encode_words` initialises every byte it counts, and they are ASCII: literals
            // are printable, spaces may become `_`, everything else becomes `=XX`.
            mode => unsafe {
                out.append_ascii(
                    input.len().saturating_mul(ESCAPED).saturating_add(1),
                    |dst| mode.encode_words(input, dst),
                )
            },
        }
    }

    /// Encodes `input` into `out` and returns the number of bytes written.
    pub fn encode_slice(&self, input: impl AsRef<[u8]>, out: &mut [u8]) -> Result<usize, Error> {
        let input = input.as_ref();
        let written = match self.mode {
            Mode::Body | Mode::Binary => {
                // SAFETY: `fill_lines` only stores byte values into `dst`, never uninitialised
                // ones.
                let (read, written) = self.fill_lines(input, &mut 0, unsafe { out.as_uninit() });
                (read == input.len()).then_some(written)
            }
            mode => (out.len() >= input.len().saturating_mul(ESCAPED)
                || mode.table().encoded_len(input) <= out.len())
            // SAFETY: `encode_words` only stores byte values into `dst`, never uninitialised ones.
            .then(|| mode.encode_words(input, unsafe { out.as_uninit() })),
        };
        written.ok_or_else(|| Error::BufferTooSmall {
            required: self.encoded_len(input),
        })
    }

    /// Writes the encoding of `input` to `writer` in chunks, without
    /// allocating.
    pub fn encode_to_writer(
        &self,
        input: impl AsRef<[u8]>,
        writer: &mut impl io::Write,
    ) -> io::Result<()> {
        let mut buffer = [MaybeUninit::uninit(); WRITER_CHUNK];
        let mut column = 0;
        let mut rest = input.as_ref();
        while !rest.is_empty() {
            let (read, written) = match self.mode {
                Mode::Body | Mode::Binary => self.fill_lines(rest, &mut column, &mut buffer),
                mode => {
                    let take = rest.len().min(WRITER_CHUNK / ESCAPED - 1);
                    let chunk = rest.get(..take).unwrap_or_default();
                    (take, mode.encode_words(chunk, &mut buffer))
                }
            };
            // SAFETY: both arms count only bytes they wrote into `buffer`; word chunks are capped
            // at `WRITER_CHUNK / ESCAPED - 1` input bytes so their worst-case output fits.
            writer.write_all(unsafe { buffer.initialized(written) })?;
            rest = rest.get(read..).unwrap_or_default();
        }
        Ok(())
    }

    pub(super) const fn worst_case(len: usize) -> usize {
        let escaped = len.saturating_mul(ESCAPED);
        escaped
            .saturating_add(escaped / MAX_CONTENT * SOFT_BREAK.len())
            .saturating_add(SLACK)
    }

    pub(super) fn fill_lines(
        &self,
        input: &[u8],
        column: &mut usize,
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        match self.mode {
            Mode::Binary => Lines::<true> { input, column, dst }.dispatch(),
            _ => Lines::<false> { input, column, dst }.dispatch(),
        }
    }

    fn append_lines(&self, input: &[u8], out: &mut impl Buffer) -> usize {
        let mut reserve = Self::estimate(input.len(), HighBytes(input).dispatch());
        let mut column = 0;
        let mut rest = input;
        let mut total = 0;
        while !rest.is_empty() {
            let mut read = 0;
            // SAFETY: `fill_lines` initialises every byte it counts (room is checked per step, or
            // reserved by the span bound), and emits only ASCII: printable bytes, tabs, CRLF and
            // `=XX`.
            let written = unsafe {
                out.append_ascii(reserve, |dst| {
                    let (consumed, written) = self.fill_lines(rest, &mut column, dst);
                    read = consumed;
                    written
                })
            };
            total += written;
            rest = rest.get(read..).unwrap_or_default();
            reserve = Self::estimate_rest(rest.len(), read, written);
        }
        total
    }

    fn estimate(len: usize, high: usize) -> usize {
        let content = len.saturating_add(high.saturating_mul(2));
        content
            .saturating_add(content / ESTIMATE_MARGIN)
            .saturating_add(SLACK)
    }

    fn estimate_rest(len: usize, read: usize, written: usize) -> usize {
        let estimate = len.saturating_mul(written) / read.max(1);
        estimate
            .saturating_add(estimate / REST_MARGIN)
            .saturating_add(SLACK)
            .min(Self::worst_case(len))
    }
}

const STEP_OUTPUT: usize = 4 * MAX_CONTENT;
const EXPANSION: usize = 4;
const MIN_SPAN: usize = 64;

pub(super) struct Lines<'x, const BINARY: bool> {
    pub(super) input: &'x [u8],
    pub(super) column: &'x mut usize,
    pub(super) dst: &'x mut [MaybeUninit<u8>],
}

impl<const BINARY: bool> Job for Lines<'_, BINARY> {
    type Output = (usize, usize);

    #[inline(always)]
    fn run<K: Kernel>(self) -> (usize, usize) {
        let Lines { input, column, dst } = self;
        let capacity = dst.len();
        let mut cursor = Cursor {
            read: 0,
            written: 0,
            column: *column,
        };
        while cursor.read < input.len() {
            let span = (capacity - cursor.written).saturating_sub(STEP_OUTPUT) / EXPANSION;
            if span < MIN_SPAN {
                break;
            }
            let end = input.len().min(cursor.read + span);
            cursor = cursor.steps::<K, BINARY, false>(input, end, dst);
        }
        cursor = cursor.steps::<K, BINARY, true>(input, input.len(), dst);
        *column = cursor.column;
        (cursor.read, cursor.written)
    }
}

#[derive(Clone, Copy)]
struct Cursor {
    read: usize,
    written: usize,
    column: usize,
}

impl Cursor {
    #[inline(always)]
    fn line_ends<const BINARY: bool>(input: &[u8], at: usize) -> bool {
        match input.get(at..) {
            None | Some([]) => true,
            Some([b'\n', ..] | [b'\r', b'\n', ..]) => !BINARY,
            _ => false,
        }
    }

    #[inline(always)]
    fn steps<K: Kernel, const BINARY: bool, const CHECKED: bool>(
        self,
        input: &[u8],
        end: usize,
        dst: &mut [MaybeUninit<u8>],
    ) -> Self {
        let capacity = dst.len();
        let Cursor {
            mut read,
            mut written,
            mut column,
        } = self;
        while read < end {
            let Some(&byte) = input.get(read) else {
                break;
            };
            let class = CLASS[byte as usize];
            if class == PLAIN || (class == BLANK && !Self::line_ends::<BINARY>(input, read + 1)) {
                if column == MAX_CONTENT {
                    if CHECKED && capacity - written <= SOFT_BREAK.len() {
                        break;
                    }
                    dst.put(written, SOFT_BREAK);
                    written += SOFT_BREAK.len();
                    column = 0;
                }
                let max = match CHECKED {
                    true => (MAX_CONTENT - column).min(capacity - written),
                    false => MAX_CONTENT - column,
                };
                if max == 0 {
                    break;
                }
                let rest = input.get(read..).unwrap_or_default();
                let mut count =
                    K::copy_plain(rest, dst.get_mut(written..).unwrap_or_default(), max);
                if count > 1
                    && rest.get(count - 1).is_some_and(|&last| last.is_blank())
                    && Self::line_ends::<BINARY>(input, read + count)
                {
                    count -= 1;
                }
                read += count;
                written += count;
                column += count;
            } else if !BINARY
                && (class == LF || (class == CR && input.get(read + 1) == Some(&b'\n')))
            {
                if CHECKED && capacity - written < HARD_BREAK.len() {
                    break;
                }
                dst.put(written, HARD_BREAK);
                written += HARD_BREAK.len();
                read += if class == LF { 1 } else { 2 };
                column = 0;
            } else {
                let soft = column + ESCAPED > MAX_CONTENT;
                let needed = if soft {
                    SOFT_BREAK.len() + ESCAPED
                } else {
                    ESCAPED
                };
                if CHECKED && capacity - written < needed {
                    break;
                }
                if soft {
                    dst.put(written, SOFT_BREAK);
                    written += SOFT_BREAK.len();
                    column = 0;
                }
                let count = if class == BLANK {
                    dst.put(written, byte.escape());
                    1
                } else {
                    let max = match CHECKED {
                        true => {
                            ((MAX_CONTENT - column) / ESCAPED).min((capacity - written) / ESCAPED)
                        }
                        false => (MAX_CONTENT - column) / ESCAPED,
                    };
                    K::encode_escapes::<BINARY>(
                        input.get(read..).unwrap_or_default(),
                        dst.get_mut(written..).unwrap_or_default(),
                        max,
                    )
                };
                read += count;
                written += ESCAPED * count;
                column += ESCAPED * count;
            }
        }
        Cursor {
            read,
            written,
            column,
        }
    }
}
