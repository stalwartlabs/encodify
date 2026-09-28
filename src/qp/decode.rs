/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{
    Mode, QuotedPrintable,
    kernel::{Job, Kernel, scalar::Swar},
    output::Output,
    tables::QpByte,
};
use crate::{
    Error,
    buffer::{SpareCapacity, Uninit},
    hex::decode_pair,
};
use memchr::{memchr, memchr3};
use std::{borrow::Cow, mem::MaybeUninit};

pub(super) const SLACK: usize = 64;

impl QuotedPrintable {
    /// Decodes `input`, borrowing it when there is nothing to rewrite: no `=`
    /// and, for bodies, no bare CR and no space or tab before a line break or
    /// at the end; for `Q` text, no `_`, CR or LF; for DKIM values, no folding
    /// whitespace.
    pub fn decode<'x>(
        &self,
        input: &'x (impl AsRef<[u8]> + ?Sized),
    ) -> Result<Cow<'x, [u8]>, Error> {
        let input = input.as_ref();
        let Some(verbatim) = self.verbatim_len(input) else {
            return Ok(Cow::Borrowed(input));
        };
        let (verbatim, rest) = input.split_at_checked(verbatim).unwrap_or((&[], input));
        let mut out = Vec::with_capacity(input.len() + SLACK);
        out.extend_from_slice(verbatim);
        self.decode_append(rest, &mut out)
            .map_err(|err| err.shifted(verbatim.len()))?;
        Ok(Cow::Owned(out))
    }

    /// Appends the decoding of `input` to `out` and returns the number of
    /// bytes appended. On error `out` is left unchanged.
    pub fn decode_append(
        &self,
        input: impl AsRef<[u8]>,
        out: &mut Vec<u8>,
    ) -> Result<usize, Error> {
        let input = input.as_ref();
        let mut result = Ok(());
        // SAFETY: decoding never writes more bytes than it reads, so the `input.len() + SLACK`
        // region always has room and `decode_into` initialises every byte it counts; errors
        // count 0.
        let written = unsafe {
            out.append_with(input.len() + SLACK, |dst| {
                match self.decode_into(input, dst) {
                    Ok(written) => written,
                    Err(err) => {
                        result = Err(err);
                        0
                    }
                }
            })
        };
        result.map(|()| written)
    }

    /// Decodes `input` into `out` and returns the number of bytes written.
    /// Never allocates; when `out` is too small, the error reports the
    /// decoded length.
    pub fn decode_slice(&self, input: impl AsRef<[u8]>, out: &mut [u8]) -> Result<usize, Error> {
        // SAFETY: `decode_into` only stores decoded byte values into `dst`, never uninitialised
        // ones.
        let written = self.decode_into(input.as_ref(), unsafe { out.as_uninit() })?;
        match written <= out.len() {
            true => Ok(written),
            false => Err(Error::BufferTooSmall { required: written }),
        }
    }

    /// Decodes one delimited value at the start of `input` and returns the
    /// decoded bytes and the number of input bytes consumed, delimiter
    /// included.
    ///
    /// - `Q_TEXT` and `Q_PHRASE`: the encoded text of an RFC 2047 encoded
    ///   word, up to the `?=` that ends it. A `?` not followed by `=` is
    ///   literal; input without `?=` is truncated.
    /// - `DKIM`: a tag value, up to the `;` that ends it or the end of the
    ///   input.
    /// - `BODY` and `BINARY`: the whole input.
    ///
    /// ```
    /// use encodify::qp;
    ///
    /// # fn main() -> Result<(), encodify::Error> {
    /// let header = b"Keld_J=F8rn_Simonsen?= <keld@dkuug.dk>";
    /// let (name, used) = qp::Q_TEXT.decode_word(header)?;
    /// assert_eq!(name, b"Keld J\xf8rn Simonsen");
    /// assert_eq!(header.get(used..), Some(&b" <keld@dkuug.dk>"[..]));
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode_word(&self, input: impl AsRef<[u8]>) -> Result<(Vec<u8>, usize), Error> {
        let span = self.word_span(input.as_ref());
        let mut out = Vec::with_capacity(span.len() + SLACK);
        let used = self.append_decoded_word(span, &mut out)?;
        Ok((out, used))
    }

    /// Like [`QuotedPrintable::decode_word`], appending the decoded bytes to
    /// `out` and returning the number of input bytes consumed. On error `out`
    /// is left unchanged.
    pub fn decode_word_append(
        &self,
        input: impl AsRef<[u8]>,
        out: &mut Vec<u8>,
    ) -> Result<usize, Error> {
        self.append_decoded_word(self.word_span(input.as_ref()), out)
    }

    fn append_decoded_word(&self, span: &[u8], out: &mut Vec<u8>) -> Result<usize, Error> {
        let mut result = Ok(0);
        // SAFETY: decoding never writes more bytes than it reads, so the `span.len() + SLACK`
        // region always has room and `decode_word_into` initialises every byte it counts; errors
        // count 0.
        unsafe {
            out.append_with(span.len() + SLACK, |dst| {
                match self.decode_word_into(span, dst) {
                    Ok((read, written)) => {
                        result = Ok(read);
                        written
                    }
                    Err(err) => {
                        result = Err(err);
                        0
                    }
                }
            })
        };
        result
    }

    fn word_span<'x>(&self, input: &'x [u8]) -> &'x [u8] {
        let end = match self.mode {
            Mode::QText | Mode::QPhrase => Self::q_word_end(input).map(|at| at + 2),
            Mode::Dkim => memchr(b';', input).map(|at| at + 1),
            Mode::Body | Mode::Binary => None,
        };
        end.and_then(|end| input.get(..end)).unwrap_or(input)
    }

    fn q_word_end(input: &[u8]) -> Option<usize> {
        let mut from = 0;
        loop {
            let at = from + memchr(b'?', input.get(from..)?)?;
            if input.get(at + 1) == Some(&b'=') {
                return Some(at);
            }
            from = at + 1;
        }
    }

    fn decode_into(&self, input: &[u8], dst: &mut [MaybeUninit<u8>]) -> Result<usize, Error> {
        match self.mode {
            Mode::Body | Mode::Binary => Body {
                input,
                dst,
                strict: self.strict,
            }
            .dispatch(),
            Mode::QText | Mode::QPhrase => QPayload {
                input,
                dst,
                word: false,
            }
            .decode()
            .map(|(_, written)| written),
            Mode::Dkim => DkimValue { value: input, dst }.decode(),
        }
    }

    fn decode_word_into(
        &self,
        input: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> Result<(usize, usize), Error> {
        match self.mode {
            Mode::Body | Mode::Binary => self
                .decode_into(input, dst)
                .map(|written| (input.len(), written)),
            Mode::QText | Mode::QPhrase => QPayload {
                input,
                dst,
                word: true,
            }
            .decode(),
            Mode::Dkim => DkimValue {
                value: input.strip_suffix(b";").unwrap_or(input),
                dst,
            }
            .decode()
            .map(|written| (input.len(), written)),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Escape<'x>(pub(super) &'x [u8]);

impl Escape<'_> {
    #[inline(always)]
    pub(super) fn byte(self) -> Option<u8> {
        self.0
            .first_chunk::<2>()
            .and_then(|&[high, low]| decode_pair(high, low))
    }

    pub(super) fn soft_break(self) -> Option<usize> {
        let blanks = self.0.iter().take_while(|&&byte| byte.is_blank()).count();
        match self.0.get(blanks..) {
            Some([]) => Some(blanks),
            Some([b'\n', ..]) => Some(blanks + 1),
            Some([b'\r', b'\n', ..]) => Some(blanks + 2),
            _ => None,
        }
    }

    pub(super) fn body_error(self, offset: usize, total: usize) -> Error {
        let invalid = |offset, byte| Error::InvalidByte { offset, byte };
        match self.0 {
            [high, low, ..] if high.is_ascii_hexdigit() => invalid(offset + 1, *low),
            [first, ..] if first.is_blank() => {
                let blanks = self.0.iter().take_while(|&&byte| byte.is_blank()).count();
                self.0
                    .get(blanks)
                    .map_or(Error::Truncated { offset: total }, |&byte| {
                        invalid(offset + blanks, byte)
                    })
            }
            [high] if high.is_ascii_hexdigit() => Error::Truncated { offset: total },
            [first, ..] => invalid(offset, *first),
            [] => Error::Truncated { offset: total },
        }
    }

    pub(super) fn word_error(self, offset: usize, total: usize) -> Error {
        match self.0 {
            [high, ..] if !high.is_ascii_hexdigit() => Error::InvalidByte {
                offset,
                byte: *high,
            },
            [_, low, ..] => Error::InvalidByte {
                offset: offset + 1,
                byte: *low,
            },
            _ => Error::Truncated { offset: total },
        }
    }
}

pub(super) struct Body<'x> {
    pub(super) input: &'x [u8],
    pub(super) dst: &'x mut [MaybeUninit<u8>],
    pub(super) strict: bool,
}

impl Job for Body<'_> {
    type Output = Result<usize, Error>;

    #[inline(always)]
    fn run<K: Kernel>(self) -> Self::Output {
        let Body { input, dst, strict } = self;
        let mut read = 0;
        let mut written = 0;
        let mut blanks = 0;
        loop {
            let src = input.get(read..).unwrap_or_default();
            let run = match dst.get_mut(written..) {
                Some(rest) if !rest.is_empty() => K::copy_text(src, rest),
                _ => memchr3(b'=', b'\r', b'\n', src).unwrap_or(src.len()),
            };
            if run > 0 {
                let trailing = src
                    .get(..run)
                    .unwrap_or_default()
                    .iter()
                    .rev()
                    .take_while(|&&byte| byte.is_blank())
                    .count();
                blanks = if trailing == run {
                    blanks + trailing
                } else {
                    trailing
                };
                read += run;
                written += run;
            }
            match input.get(read..).unwrap_or_default() {
                [] => return Ok(written - blanks),
                [b'=', after @ ..] => {
                    let escape = Escape(after);
                    if let Some(byte) = escape.byte() {
                        dst.put(written, [byte]);
                        read += 3;
                        written += 1;
                        let (more_read, more_written) = K::decode_escapes(
                            input.get(read..).unwrap_or_default(),
                            dst.get_mut(written..).unwrap_or_default(),
                        );
                        read += more_read;
                        written += more_written;
                    } else if let Some(len) = escape.soft_break() {
                        read += 1 + len;
                    } else if strict {
                        return Err(escape.body_error(read + 1, input.len()));
                    } else {
                        match after.first() {
                            Some(&byte) if byte != b'\r' => {
                                dst.put(written, [b'=', byte]);
                                written += 2;
                            }
                            _ => {
                                dst.put(written, *b"=");
                                written += 1;
                            }
                        }
                        read += 2;
                    }
                    blanks = 0;
                }
                [b'\r', b'\n', ..] => {
                    written -= blanks;
                    dst.put(written, *b"\r\n");
                    written += 2;
                    read += 2;
                    blanks = 0;
                }
                [b'\n', ..] => {
                    written -= blanks;
                    dst.put(written, *b"\n");
                    written += 1;
                    read += 1;
                    blanks = 0;
                }
                [b'\r', ..] => read += 1,
                [byte, ..] => {
                    dst.put(written, [*byte]);
                    blanks = if byte.is_blank() { blanks + 1 } else { 0 };
                    written += 1;
                    read += 1;
                }
            }
        }
    }
}

const Q_PLAIN: u8 = 0;
const Q_SPECIAL: u8 = 1;

static Q_CLASS: [u8; 256] = {
    let mut table = [Q_PLAIN; 256];
    let mut byte = 0;
    while byte < 256 {
        if matches!(byte as u8, b'=' | b'?' | b'\r' | b'\n') {
            table[byte] = Q_SPECIAL;
        }
        byte += 1;
    }
    table
};

struct QPayload<'x> {
    input: &'x [u8],
    dst: &'x mut [MaybeUninit<u8>],
    word: bool,
}

impl QPayload<'_> {
    fn decode(self) -> Result<(usize, usize), Error> {
        let QPayload { input, dst, word } = self;
        let mut read = 0;
        let mut written = 0;
        loop {
            let literal = input
                .get(read..)
                .unwrap_or_default()
                .split(|&byte| Q_CLASS[byte as usize] != Q_PLAIN)
                .next()
                .unwrap_or_default();
            dst.put_q_text(written, literal);
            read += literal.len();
            written += literal.len();
            match input.get(read..).unwrap_or_default() {
                [] if word => {
                    return Err(Error::Truncated {
                        offset: input.len(),
                    });
                }
                [] => return Ok((read, written)),
                [b'?', b'=', ..] if word => return Ok((read + 2, written)),
                [b'=', after @ ..] => {
                    let escape = Escape(after);
                    let byte = escape
                        .byte()
                        .ok_or_else(|| escape.word_error(read + 1, input.len()))?;
                    dst.put(written, [byte]);
                    read += 3;
                    written += 1;
                    let (more_read, more_written) = Swar::decode_escapes(
                        input.get(read..).unwrap_or_default(),
                        dst.get_mut(written..).unwrap_or_default(),
                    );
                    read += more_read;
                    written += more_written;
                }
                [b'\r', ..] => read += 1,
                [b'\n', after @ ..] => {
                    read += 1 + after.iter().take_while(|&&byte| byte.is_blank()).count();
                }
                [byte, ..] => {
                    dst.put(written, [*byte]);
                    read += 1;
                    written += 1;
                }
            }
        }
    }
}

pub(super) const DKIM_SAFE: u8 = 0;
pub(super) const DKIM_FWS: u8 = 1;
pub(super) const DKIM_EQUALS: u8 = 2;
const DKIM_INVALID: u8 = 3;

pub(super) static DKIM_CLASS: [u8; 256] = {
    let mut table = [DKIM_INVALID; 256];
    let mut byte = 0;
    while byte < 256 {
        table[byte] = match byte as u8 {
            b' ' | b'\t' | b'\r' | b'\n' => DKIM_FWS,
            b'=' => DKIM_EQUALS,
            0x21..=0x3a | 0x3c | 0x3e..=0x7e | 0x80..=0xff => DKIM_SAFE,
            _ => DKIM_INVALID,
        };
        byte += 1;
    }
    table
};

pub(super) struct DkimValue<'x> {
    value: &'x [u8],
    dst: &'x mut [MaybeUninit<u8>],
}

impl DkimValue<'_> {
    fn decode(self) -> Result<usize, Error> {
        let DkimValue { value, dst } = self;
        let mut read = 0;
        let mut written = 0;
        while let Some(&byte) = value.get(read) {
            match DKIM_CLASS[byte as usize] {
                DKIM_SAFE => {
                    let run = Swar::copy_dkim_safe(
                        value.get(read..).unwrap_or_default(),
                        dst.get_mut(written..).unwrap_or_default(),
                    )
                    .max(1);
                    read += run;
                    written += run;
                }
                DKIM_FWS => read += 1,
                DKIM_EQUALS => {
                    let (run_read, run_written) = Swar::decode_escapes(
                        value.get(read..).unwrap_or_default(),
                        dst.get_mut(written..).unwrap_or_default(),
                    );
                    if run_written > 0 {
                        read += run_read;
                        written += run_written;
                        continue;
                    }
                    let (decoded, next) = Self::folded_escape(value, read)?;
                    dst.put(written, [decoded]);
                    read = next;
                    written += 1;
                }
                _ => return Err(Error::InvalidByte { offset: read, byte }),
            }
        }
        Ok(written)
    }

    pub(super) fn folded_escape(value: &[u8], equals: usize) -> Result<(u8, usize), Error> {
        let mut digits = value
            .iter()
            .enumerate()
            .skip(equals + 1)
            .filter(|&(_, &byte)| DKIM_CLASS[byte as usize] != DKIM_FWS);
        match (digits.next(), digits.next()) {
            (Some((at, &high)), _) if !high.is_ascii_hexdigit() => Err(Error::InvalidByte {
                offset: at,
                byte: high,
            }),
            (Some((_, &high)), Some((at, &low))) => decode_pair(high, low)
                .map(|decoded| (decoded, at + 1))
                .ok_or(Error::InvalidByte {
                    offset: at,
                    byte: low,
                }),
            _ => Err(Error::Truncated {
                offset: value.len(),
            }),
        }
    }
}
