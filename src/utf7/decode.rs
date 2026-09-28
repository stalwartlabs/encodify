/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{REPLACEMENT, SHIFT_END, Utf7};
use crate::{
    Error,
    base64::alphabet::{self, INVALID},
    buffer::sealed::Sealed,
    error::ToStr,
};
use memchr::memchr;
use std::slice;

impl Utf7 {
    pub(super) fn decodes_to_itself(&self, bytes: &[u8]) -> bool {
        if self.lenient {
            bytes
                .iter()
                .fold(true, |same, &byte| same & byte.is_ascii() & (byte != b'&'))
        } else {
            self.is_all_direct(bytes)
        }
    }

    /// Decodes `input` into a new `String`.
    pub fn decode(&self, input: impl AsRef<[u8]>) -> Result<String, Error> {
        let input = input.as_ref();
        let mut out = String::with_capacity(input.len() + input.len() / 8);
        self.append_decoded(input, &mut out)?;
        Ok(out)
    }

    /// Appends the decoding of `input` to `out` and returns the number of bytes
    /// appended. On error `out` is left unchanged.
    pub fn decode_append(&self, input: impl AsRef<[u8]>, out: &mut String) -> Result<usize, Error> {
        self.append_decoded(input.as_ref(), out)
    }

    fn append_decoded(&self, input: &[u8], out: &mut String) -> Result<usize, Error> {
        if self.imap && self.decodes_to_itself(input) {
            debug_assert!(input.is_ascii());
            #[allow(unsafe_code)]
            // SAFETY: `decodes_to_itself` accepted only ASCII bytes, which are
            // valid UTF-8.
            out.push_str(unsafe { str::from_utf8_unchecked(input) });
            return Ok(input.len());
        }
        let start = out.len();
        let result = if self.imap {
            self.decode_imap(input, out)
        } else {
            self.decode_mail(input, out, OnError::Fail)
        };
        match result {
            Ok(()) => Ok(out.len() - start),
            Err(err) => {
                out.truncate(start);
                Err(err)
            }
        }
    }

    /// Decodes `input` replacing every ill-formed sequence with U+FFFD, in
    /// the syntax of the engine: `&` shifts for [`IMAP`](super::IMAP), `+`
    /// shifts for [`MAIL`](super::MAIL). This is the behaviour expected from
    /// a MIME charset decoder.
    pub fn decode_lossy(&self, input: impl AsRef<[u8]>) -> String {
        let input = input.as_ref();
        let mut out = String::with_capacity(input.len());
        if self.imap {
            self.decode_imap_lossy(input, &mut out);
        } else if self.decode_mail(input, &mut out, OnError::Replace).is_err() {
            out.push(REPLACEMENT);
        }
        out
    }

    fn decode_imap_lossy(&self, input: &[u8], out: &mut String) {
        let mut rest = input;
        while !rest.is_empty() {
            let direct_len = if self.lenient {
                memchr(b'&', rest).unwrap_or(rest.len())
            } else {
                self.direct_len(rest)
            };
            let (direct, tail) = rest.split_at(direct_len);
            out.push_str(&String::from_utf8_lossy(direct));
            rest = match tail {
                [] => tail,
                [b'&', SHIFT_END, after @ ..] => {
                    out.push('&');
                    after
                }
                [b'&'] if self.lenient => {
                    out.push('&');
                    &[]
                }
                [b'&', shifted @ ..] => self.decode_imap_shift_lossy(shifted, out),
                [_, after @ ..] => {
                    out.push(REPLACEMENT);
                    after
                }
            };
        }
    }

    fn decode_imap_shift_lossy<'x>(&self, shifted: &'x [u8], out: &mut String) -> &'x [u8] {
        let decode = &self.tables().decode;
        let symbols_len = shifted
            .iter()
            .take_while(|&&byte| decode[byte as usize] != INVALID)
            .count();
        let (symbols, after) = shifted.split_at(symbols_len);
        let (closed, rest) = match after {
            [SHIFT_END, rest @ ..] => (true, rest),
            _ => (self.lenient && after.is_empty(), after),
        };
        let units = Units::new(symbols, decode);
        let mut well_formed =
            closed && !symbols.is_empty() && (self.lenient || units.is_canonical());
        for ch in char::decode_utf16(units) {
            let ch = ch.unwrap_or(REPLACEMENT);
            well_formed &= self.lenient || !matches!(ch, ' '..='~');
            out.push(ch);
        }
        if !well_formed {
            out.push(REPLACEMENT);
        }
        rest
    }

    #[inline(never)]
    fn decode_imap(&self, input: &[u8], out: &mut String) -> Result<(), Error> {
        if self.lenient && !input.is_ascii() {
            self.decode_imap_raw(input, out)
        } else {
            self.decode_imap_into(input, out)
        }
    }

    #[cold]
    fn decode_imap_raw(&self, input: &[u8], out: &mut String) -> Result<(), Error> {
        input.to_str()?;
        let mut raw = Vec::with_capacity(input.len());
        self.decode_imap_into(input, &mut raw)?;
        out.push_str(raw.to_str()?);
        Ok(())
    }

    fn decode_imap_into(&self, input: &[u8], out: &mut impl Decoded) -> Result<(), Error> {
        let mut rest = input;
        let mut last_shift_end = None;
        loop {
            let direct_len = if self.lenient {
                memchr(b'&', rest).unwrap_or(rest.len())
            } else {
                self.direct_len(rest)
            };
            let (direct, tail) = rest.split_at(direct_len);
            out.push_direct(direct);
            let offset = input.len() - tail.len();
            rest = match tail {
                [] => return Ok(()),
                [b'&', SHIFT_END, after @ ..] => {
                    out.push_direct(b"&");
                    after
                }
                [b'&'] if self.lenient => {
                    out.push_direct(b"&");
                    &[]
                }
                [b'&'] => return Err(Error::Truncated { offset: offset + 1 }),
                [b'&', shifted @ ..] => {
                    if !self.lenient && last_shift_end == Some(offset) {
                        return Err(Error::NonCanonical { offset });
                    }
                    let after = self.decode_imap_shift(shifted, offset + 1, out)?;
                    last_shift_end = Some(input.len() - after.len());
                    after
                }
                &[byte, ..] => return Err(Error::InvalidByte { offset, byte }),
            };
        }
    }

    fn decode_imap_shift<'x>(
        &self,
        shifted: &'x [u8],
        start: usize,
        out: &mut impl Decoded,
    ) -> Result<&'x [u8], Error> {
        let decode = &self.tables().decode;
        let symbols_len = shifted
            .iter()
            .take_while(|&&byte| decode[byte as usize] != INVALID)
            .count();
        let (symbols, after) = shifted.split_at(symbols_len);
        let end = start + symbols_len;
        let rest = match after {
            [SHIFT_END, rest @ ..] => rest,
            [] if self.lenient => after,
            [] => return Err(Error::Truncated { offset: end }),
            &[byte, ..] => return Err(Error::InvalidByte { offset: end, byte }),
        };
        let units = Units::new(symbols, decode);
        if !self.lenient && !units.is_canonical() {
            return Err(Error::NonCanonical {
                offset: start + symbols_len.saturating_sub(1),
            });
        }
        let mut encodes_printable = false;
        for ch in char::decode_utf16(units) {
            let ch = ch.map_err(|_| Error::InvalidUtf16 { offset: start })?;
            encodes_printable |= matches!(ch, ' '..='~');
            out.push_char(ch);
        }
        if !self.lenient && encodes_printable {
            return Err(Error::NonCanonical { offset: start });
        }
        Ok(rest)
    }

    #[inline(never)]
    fn decode_mail(&self, input: &[u8], out: &mut String, on_error: OnError) -> Result<(), Error> {
        let mut rest = input;
        loop {
            let direct_len = rest
                .iter()
                .position(|&byte| byte == b'+' || !byte.is_ascii())
                .unwrap_or(rest.len());
            let (direct, tail) = rest.split_at(direct_len);
            out.push_ascii(direct);
            let offset = input.len() - tail.len();
            rest = match tail {
                [] => return Ok(()),
                [b'+', shifted @ ..] => {
                    self.decode_mail_shift(shifted, offset + 1, out, on_error)?
                }
                [byte, after @ ..] => {
                    on_error.handle(
                        Error::InvalidByte {
                            offset,
                            byte: *byte,
                        },
                        out,
                    )?;
                    after
                }
            };
        }
    }

    fn decode_mail_shift<'x>(
        &self,
        shifted: &'x [u8],
        start: usize,
        out: &mut String,
        on_error: OnError,
    ) -> Result<&'x [u8], Error> {
        let symbols_len = shifted
            .iter()
            .take_while(|&&byte| alphabet::STANDARD.decode[byte as usize] != INVALID)
            .count();
        let (symbols, after) = shifted.split_at(symbols_len);
        let end = start + symbols_len;
        let rest = after.strip_prefix(&[SHIFT_END]).unwrap_or(after);
        if symbols.is_empty() {
            match after.first() {
                Some(&SHIFT_END) => out.push('+'),
                Some(&byte) => on_error.handle(Error::InvalidByte { offset: end, byte }, out)?,
                None => on_error.handle(Error::Truncated { offset: end }, out)?,
            }
            return Ok(rest);
        }
        let units = Units::new(symbols, &self.tables().decode);
        let canonical = self.lenient || units.is_canonical();
        if !canonical && on_error == OnError::Fail {
            return Err(Error::NonCanonical { offset: end - 1 });
        }
        for ch in char::decode_utf16(units) {
            match ch {
                Ok(ch) => out.push(ch),
                Err(_) => on_error.handle(Error::InvalidUtf16 { offset: start }, out)?,
            }
        }
        if !canonical {
            out.push(REPLACEMENT);
        }
        Ok(rest)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OnError {
    Fail,
    Replace,
}

impl OnError {
    fn handle(self, error: Error, out: &mut String) -> Result<(), Error> {
        match self {
            OnError::Fail => Err(error),
            OnError::Replace => {
                out.push(REPLACEMENT);
                Ok(())
            }
        }
    }
}

struct Units<'x> {
    symbols: slice::Iter<'x, u8>,
    decode: &'static [u8; 256],
    word: u32,
    bits: u32,
}

impl<'x> Units<'x> {
    fn new(symbols: &'x [u8], decode: &'static [u8; 256]) -> Self {
        Units {
            symbols: symbols.iter(),
            decode,
            word: 0,
            bits: 0,
        }
    }

    fn is_canonical(&self) -> bool {
        let symbols = self.symbols.as_slice();
        let leftover = symbols.len() % 8 * 6 % 16;
        match symbols.last() {
            _ if leftover == 0 => true,
            Some(&last) if leftover < 6 => {
                u32::from(self.decode[last as usize]) & ((1 << leftover) - 1) == 0
            }
            _ => false,
        }
    }
}

impl Iterator for Units<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        for &symbol in self.symbols.by_ref() {
            self.word = (self.word << 6) | u32::from(self.decode[symbol as usize]);
            self.bits += 6;
            if self.bits >= 16 {
                self.bits -= 16;
                let unit = (self.word >> self.bits) as u16;
                self.word &= (1 << self.bits) - 1;
                return Some(unit);
            }
        }
        None
    }
}

trait Decoded {
    fn push_direct(&mut self, bytes: &[u8]);
    fn push_char(&mut self, ch: char);
}

impl Decoded for String {
    fn push_direct(&mut self, bytes: &[u8]) {
        debug_assert!(bytes.is_ascii());
        self.push_ascii(bytes);
    }

    fn push_char(&mut self, ch: char) {
        self.push(ch);
    }
}

impl Decoded for Vec<u8> {
    fn push_direct(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }

    fn push_char(&mut self, ch: char) {
        self.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
    }
}
