/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Hexadecimal escapes shared by quoted-printable (`=XX`), percent-encoding
//! (`%XX`) and xtext (`+XX`).
//!
//! [`decode_pair`] is the primitive every decoder in the crate uses. The
//! [`HexEscape`] engines apply a whole scheme: bytes outside the scheme's
//! safe set are written as a marker followed by two uppercase hexadecimal
//! digits, and decoding turns every marker and the two digits after it back
//! into a byte.
//!
//! ```
//! use encodify::hex;
//! use std::borrow::Cow;
//!
//! # fn main() -> Result<(), encodify::Error> {
//! assert_eq!(hex::PERCENT.encode("naïve.txt"), "na%C3%AFve.txt");
//! assert_eq!(hex::PERCENT.decode("na%c3%afve.txt")?, "naïve.txt".as_bytes());
//!
//! assert_eq!(
//!     hex::XTEXT.encode("rfc822;a+b@example.org"),
//!     "rfc822;a+2Bb@example.org"
//! );
//! assert!(matches!(
//!     hex::XTEXT.decode("rfc822;user@example.org")?,
//!     Cow::Borrowed(_)
//! ));
//! # Ok(())
//! # }
//! ```

#![allow(unsafe_code)]

use crate::{Buffer, Error};
use std::{borrow::Cow, mem::MaybeUninit};

const INVALID: u8 = 0xff;

static HEX: [u8; 256] = {
    let mut table = [INVALID; 256];
    let mut byte = 0;
    while byte < 256 {
        table[byte] = match byte as u8 {
            digit @ b'0'..=b'9' => digit - b'0',
            upper @ b'A'..=b'F' => upper - b'A' + 10,
            lower @ b'a'..=b'f' => lower - b'a' + 10,
            _ => INVALID,
        };
        byte += 1;
    }
    table
};

/// Decodes two hexadecimal digits (either case) into a byte.
#[inline(always)]
pub const fn decode_pair(high: u8, low: u8) -> Option<u8> {
    let high = HEX[high as usize];
    let low = HEX[low as usize];
    if (high | low) & 0xf0 == 0 {
        Some((high << 4) | low)
    } else {
        None
    }
}

const UPPER: &[u8; 16] = b"0123456789ABCDEF";
const ENTRY_LEN: usize = 3;
const LEN_SHIFT: usize = 8 * ENTRY_LEN;
const ESCAPED: usize = 3;
pub(crate) const BLOCK: usize = 16;
pub(crate) const BLOCK_ROOM: usize = ESCAPED * BLOCK + 1;
#[cfg(encodify_simd)]
pub(crate) const SPARSE_ESCAPES: usize = 4;
#[cfg(encodify_simd)]
pub(crate) const SPARSE_LEN: usize = BLOCK + (ESCAPED - 1) * SPARSE_ESCAPES;

pub(crate) struct EscapeTable {
    entries: [[u8; 4]; 256],
}

impl EscapeTable {
    pub(crate) const fn escaped(marker: u8, byte: u8) -> [u8; 4] {
        [
            marker,
            UPPER[(byte >> 4) as usize],
            UPPER[(byte & 0x0f) as usize],
            ESCAPED as u8,
        ]
    }

    pub(crate) const fn new(marker: u8, safe: &[bool; 256]) -> Self {
        let mut entries = [[0u8; 4]; 256];
        let mut byte = 0;
        while byte < 256 {
            entries[byte] = if safe[byte] {
                [byte as u8, 0, 0, 1]
            } else {
                Self::escaped(marker, byte as u8)
            };
            byte += 1;
        }
        EscapeTable { entries }
    }

    #[inline(always)]
    const fn is_continuation(byte: u8) -> bool {
        (byte as i8) < -0x40
    }

    pub(crate) const fn with(mut self, byte: u8, literal: u8) -> Self {
        self.entries[byte as usize] = [literal, 0, 0, 1];
        self
    }

    #[inline(always)]
    pub(crate) fn word(&self, byte: u8) -> u32 {
        u32::from_le_bytes(self.entries[byte as usize])
    }

    pub(crate) const fn byte_len(&self, byte: u8) -> usize {
        self.entries[byte as usize][ENTRY_LEN] as usize
    }

    pub(crate) const fn strs(&'static self) -> [&'static str; 256] {
        let mut strs = [""; 256];
        let mut byte = 0;
        while byte < 256 {
            let entry = &self.entries[byte];
            let (text, _) = entry.as_slice().split_at(entry[ENTRY_LEN] as usize);
            strs[byte] = match std::str::from_utf8(text) {
                Ok(text) => text,
                Err(_) => "",
            };
            byte += 1;
        }
        strs
    }

    #[inline(always)]
    pub(crate) fn encode_block(
        &self,
        block: &[u8; BLOCK],
        window: &mut [MaybeUninit<u8>; BLOCK_ROOM],
    ) -> usize {
        block.iter().fold(0, |written, &byte| {
            let word = self.word(byte);
            if let Some(slot) = window
                .get_mut(written..)
                .and_then(|rest| rest.first_chunk_mut::<4>())
            {
                *slot = word.to_le_bytes().map(MaybeUninit::new);
            }
            written + (word >> LEN_SHIFT) as usize
        })
    }

    #[inline(always)]
    pub(crate) fn encode_blocks(
        &self,
        input: &[u8],
        dst: &mut [MaybeUninit<u8>],
        budget: usize,
    ) -> (usize, usize) {
        let (blocks, _) = input.as_chunks::<BLOCK>();
        let mut read = 0;
        let mut written = 0;
        for block in blocks {
            let Some(window) = dst
                .get_mut(written..)
                .and_then(|rest| rest.first_chunk_mut::<BLOCK_ROOM>())
            else {
                break;
            };
            let len = self.encode_block(block, window);
            if len > budget - written {
                break;
            }
            written += len;
            read += BLOCK;
        }
        (read, written)
    }

    #[inline(always)]
    pub(crate) fn encode_into(&self, input: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        let (read, written) = self.encode_blocks(input, dst, usize::MAX);
        written
            + self.encode_tail(
                input.get(read..).unwrap_or_default(),
                dst.get_mut(written..).unwrap_or_default(),
            )
    }

    #[inline(always)]
    fn encode_tail(&self, input: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        let written = input.iter().fold(0, |written, &byte| {
            let word = self.word(byte);
            let len = (word >> LEN_SHIFT) as usize;
            Self::put(word, len, dst.get_mut(written..).unwrap_or_default());
            written + len
        });
        debug_assert!(written <= dst.len());
        written
    }

    #[inline(always)]
    pub(crate) fn encode_within(
        &self,
        input: &[u8],
        start: (usize, usize),
        budget: usize,
        chars: bool,
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let (mut read, mut written) = start;
        let budget = budget.min(dst.len());
        let mut mark = match chars {
            true => self.char_start(input, start),
            false => start,
        };
        for &byte in input.get(read..).unwrap_or_default() {
            if chars && !Self::is_continuation(byte) {
                mark = (read, written);
            }
            let word = self.word(byte);
            let len = (word >> LEN_SHIFT) as usize;
            if len > budget - written {
                return match chars {
                    true => mark,
                    false => (read, written),
                };
            }
            Self::put(word, len, dst.get_mut(written..).unwrap_or_default());
            read += 1;
            written += len;
        }
        (read, written)
    }

    fn char_start(&self, input: &[u8], (read, written): (usize, usize)) -> (usize, usize) {
        if !input
            .get(read)
            .is_some_and(|&byte| Self::is_continuation(byte))
        {
            return (read, written);
        }
        let before = input.get(..read).unwrap_or_default();
        let lead = before
            .iter()
            .rposition(|&byte| !Self::is_continuation(byte))
            .unwrap_or_default();
        let split = before.get(lead..).unwrap_or_default();
        (lead, written.saturating_sub(self.encoded_len(split)))
    }

    #[inline(always)]
    fn put(word: u32, len: usize, dst: &mut [MaybeUninit<u8>]) {
        match dst.first_chunk_mut::<4>() {
            Some(slot) => *slot = word.to_le_bytes().map(MaybeUninit::new),
            None => {
                for (slot, byte) in dst.iter_mut().zip(word.to_le_bytes().into_iter().take(len)) {
                    slot.write(byte);
                }
            }
        }
    }

    #[inline(always)]
    pub(crate) fn encoded_len(&self, input: &[u8]) -> usize {
        input.iter().map(|&byte| self.byte_len(byte)).sum()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Scheme {
    Percent,
    Xtext,
}

impl Scheme {
    const fn marker(self) -> u8 {
        match self {
            Scheme::Percent => b'%',
            Scheme::Xtext => b'+',
        }
    }

    const fn safe_set(self) -> [bool; 256] {
        let mut set = [false; 256];
        let mut byte = 0;
        while byte < 128 {
            let ch = byte as u8;
            set[byte] = match self {
                Scheme::Percent => {
                    ch.is_ascii_alphanumeric()
                        || matches!(
                            ch,
                            b'!' | b'#'
                                | b'$'
                                | b'&'
                                | b'+'
                                | b'-'
                                | b'.'
                                | b'^'
                                | b'_'
                                | b'`'
                                | b'{'
                                | b'|'
                                | b'}'
                                | b'~'
                        )
                }
                Scheme::Xtext => matches!(ch, b'!'..=b'~') && ch != b'+' && ch != b'=',
            };
            byte += 1;
        }
        set
    }

    const fn table(self) -> EscapeTable {
        EscapeTable::new(self.marker(), &self.safe_set())
    }
}

const PERCENT_ESCAPES: EscapeTable = Scheme::Percent.table();
const XTEXT_ESCAPES: EscapeTable = Scheme::Xtext.table();
static PERCENT_TABLE: EscapeTable = PERCENT_ESCAPES;
static XTEXT_TABLE: EscapeTable = XTEXT_ESCAPES;
static PERCENT_STRS: [&str; 256] = PERCENT_TABLE.strs();
static XTEXT_STRS: [&str; 256] = XTEXT_TABLE.strs();

/// A hexadecimal escaping scheme: a marker byte followed by two hexadecimal
/// digits stands for any byte outside the scheme's safe set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HexEscape {
    scheme: Scheme,
}

/// Percent-encoding (`%XX`). Encoding keeps the RFC 2231 `attribute-char`
/// set (letters, digits and ``! # $ & + - . ^ _ ` { | } ~``) and escapes
/// every other byte, as RFC 2231 extended parameter values require. It is
/// not a URI component encoder: RFC 3986 reserves some of those characters.
/// Decoding accepts any literal byte, so URIs and `mailto:` URLs decode too;
/// `+` is not a space.
pub const PERCENT: HexEscape = HexEscape {
    scheme: Scheme::Percent,
};

/// SMTP xtext (RFC 3461, `+XX`), used by the `ENVID` and `ORCPT`
/// parameters. Encoding keeps the printable ASCII characters other than `+`
/// and `=`.
pub const XTEXT: HexEscape = HexEscape {
    scheme: Scheme::Xtext,
};

impl HexEscape {
    /// The byte that introduces an escape.
    pub const fn marker(&self) -> u8 {
        self.scheme.marker()
    }

    #[inline(always)]
    fn table(&self) -> &'static EscapeTable {
        match self.scheme {
            Scheme::Percent => &PERCENT_TABLE,
            Scheme::Xtext => &XTEXT_TABLE,
        }
    }

    /// Length of the encoding of `byte`: 1 or 3.
    pub const fn encoded_byte_len(&self, byte: u8) -> usize {
        match self.scheme {
            Scheme::Percent => PERCENT_ESCAPES.byte_len(byte),
            Scheme::Xtext => XTEXT_ESCAPES.byte_len(byte),
        }
    }

    /// The encoding of `byte`: the byte itself or its escape.
    pub fn encode_byte(&self, byte: u8) -> &'static str {
        match self.scheme {
            Scheme::Percent => PERCENT_STRS[byte as usize],
            Scheme::Xtext => XTEXT_STRS[byte as usize],
        }
    }

    /// Length of the encoding of `input`.
    pub fn encoded_len(&self, input: impl AsRef<[u8]>) -> usize {
        self.table().encoded_len(input.as_ref())
    }

    /// Encodes `input` into a new `String`.
    pub fn encode(&self, input: impl AsRef<[u8]>) -> String {
        let input = input.as_ref();
        let mut out = String::with_capacity(input.len().saturating_mul(ESCAPED).saturating_add(1));
        self.encode_append(input, &mut out);
        out
    }

    /// Appends the encoding of `input` to a `Vec<u8>` or `String` and returns
    /// the number of bytes appended.
    pub fn encode_append(&self, input: impl AsRef<[u8]>, out: &mut impl Buffer) -> usize {
        let input = input.as_ref();
        // SAFETY: at most 3 bytes per input byte fit in the region, `encode_into`
        // returns the count it wrote, and every committed byte is a safe-set
        // ASCII byte, the marker or an uppercase hex digit.
        unsafe {
            out.append_ascii(
                input.len().saturating_mul(ESCAPED).saturating_add(1),
                |dst| self.encode_into(input, dst),
            )
        }
    }

    fn encode_into(&self, input: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        self.table().encode_into(input, dst)
    }

    /// Decodes `input`, borrowing it when it contains no escape. Hex digits
    /// may be in either case; a marker that is not followed by two of them
    /// is an error.
    pub fn decode<'x>(
        &self,
        input: &'x (impl AsRef<[u8]> + ?Sized),
    ) -> Result<Cow<'x, [u8]>, Error> {
        let input = input.as_ref();
        if !input.contains(&self.marker()) {
            return Ok(Cow::Borrowed(input));
        }
        let mut out = Vec::with_capacity(input.len());
        self.decode_into(input, &mut out)?;
        Ok(Cow::Owned(out))
    }

    /// Appends the decoding of `input` to `out` and returns the number of
    /// bytes appended. On error `out` is left unchanged.
    pub fn decode_append(
        &self,
        input: impl AsRef<[u8]>,
        out: &mut Vec<u8>,
    ) -> Result<usize, Error> {
        let start = out.len();
        let input = input.as_ref();
        out.reserve(input.len());
        match self.decode_into(input, out) {
            Ok(()) => Ok(out.len() - start),
            Err(err) => {
                out.truncate(start);
                Err(err)
            }
        }
    }

    fn decode_into(&self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let marker = self.marker();
        let mut read = 0;
        loop {
            let literal = input
                .get(read..)
                .unwrap_or_default()
                .split(|&byte| byte == marker)
                .next()
                .unwrap_or_default();
            out.extend_from_slice(literal);
            read += literal.len();
            loop {
                let byte = match input.get(read..).unwrap_or_default() {
                    [] => return Ok(()),
                    [_, high, low, ..] => decode_pair(*high, *low)
                        .ok_or_else(|| Self::invalid_escape(read, *high, *low))?,
                    [_, high] if !high.is_ascii_hexdigit() => {
                        return Err(Error::InvalidByte {
                            offset: read + 1,
                            byte: *high,
                        });
                    }
                    _ => {
                        return Err(Error::Truncated {
                            offset: input.len(),
                        });
                    }
                };
                out.push(byte);
                read += ESCAPED;
                if input.get(read) != Some(&marker) {
                    break;
                }
            }
        }
    }

    const fn invalid_escape(marker_at: usize, high: u8, low: u8) -> Error {
        match high.is_ascii_hexdigit() {
            false => Error::InvalidByte {
                offset: marker_at + 1,
                byte: high,
            },
            true => Error::InvalidByte {
                offset: marker_at + 2,
                byte: low,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PERCENT, XTEXT, decode_pair};
    use crate::{
        Error,
        qp::tests::reference::{Digits, Failure, Hex},
        test_rng::XorShift,
    };
    use std::borrow::Cow;

    #[test]
    fn decodes_every_pair() {
        for byte in 0..=u8::MAX {
            let upper = format!("{byte:02X}");
            let lower = format!("{byte:02x}");
            for text in [upper, lower] {
                let [high, low] = text.as_bytes() else {
                    panic!("two digits");
                };
                assert_eq!(decode_pair(*high, *low), Some(byte));
            }
        }
        assert_eq!(decode_pair(b'G', b'0'), None);
        assert_eq!(decode_pair(b'0', b' '), None);
        for high in 0..=u8::MAX {
            for low in 0..=u8::MAX {
                assert_eq!(decode_pair(high, low), Digits::pair(high, low));
            }
        }
    }

    #[test]
    fn encodes_every_byte_like_the_reference() {
        for (engine, safe) in [
            (PERCENT, Hex::is_attribute_char as fn(u8) -> bool),
            (XTEXT, Hex::is_xchar),
        ] {
            let all: Vec<u8> = (0..=u8::MAX).collect();
            let expected = Hex::encode(&all, engine.marker(), safe);
            assert_eq!(engine.encode(&all).as_bytes(), expected);
            assert_eq!(engine.encoded_len(&all), expected.len());
            for byte in 0..=u8::MAX {
                let single = Hex::encode(&[byte], engine.marker(), safe);
                assert_eq!(engine.encode_byte(byte).as_bytes(), single);
                assert_eq!(engine.encoded_byte_len(byte), single.len());
            }
        }
    }

    #[test]
    fn matches_the_reference_on_random_input() {
        let mut rng = XorShift::new(0x4e58);
        let alphabet = b"%+=09afAFgG \x00\xff;.";
        for round in 0..20_000 {
            let len = rng.below(if round % 16 == 0 { 300 } else { 24 });
            let input: Vec<u8> = match round % 2 {
                0 => (0..len).map(|_| *rng.pick(alphabet)).collect(),
                _ => rng.bytes(len),
            };
            for engine in [PERCENT, XTEXT] {
                let encoded = engine.encode(&input);
                assert_eq!(engine.decode(&encoded).as_deref(), Ok(input.as_slice()));
                let expected = Hex::decode(&input, engine.marker());
                let actual = engine.decode(&input);
                assert_eq!(
                    actual.as_deref().map_err(|&err| Failure::from(err)),
                    expected.as_deref().map_err(|&err| err),
                    "{:?}",
                    String::from_utf8_lossy(&input)
                );
                let mut appended = b"prefix".to_vec();
                match engine.decode_append(&input, &mut appended) {
                    Ok(written) => {
                        assert_eq!(appended.get(6..), expected.as_deref().ok());
                        assert_eq!(appended.len(), 6 + written);
                    }
                    Err(_) => assert_eq!(appended, b"prefix"),
                }
            }
        }
    }

    #[test]
    fn borrows_when_nothing_is_escaped() {
        let input = "rfc822;user@example.org";
        assert!(matches!(XTEXT.decode(input), Ok(Cow::Borrowed(text)) if text == input.as_bytes()));
        assert!(matches!(
            PERCENT.decode("plain"),
            Ok(Cow::Borrowed(b"plain"))
        ));
        assert!(matches!(XTEXT.decode("a+2Bb"), Ok(Cow::Owned(text)) if text == b"a+b"));
    }

    #[test]
    fn reports_malformed_escapes() {
        for (input, error) in [
            ("%", Error::Truncated { offset: 1 }),
            ("ab%4", Error::Truncated { offset: 4 }),
            (
                "%G1",
                Error::InvalidByte {
                    offset: 1,
                    byte: b'G',
                },
            ),
            (
                "%4G",
                Error::InvalidByte {
                    offset: 2,
                    byte: b'G',
                },
            ),
            (
                "%%41",
                Error::InvalidByte {
                    offset: 1,
                    byte: b'%',
                },
            ),
            (
                "%4%41",
                Error::InvalidByte {
                    offset: 2,
                    byte: b'%',
                },
            ),
            ("x%41%2", Error::Truncated { offset: 6 }),
        ] {
            assert_eq!(PERCENT.decode(input), Err(error), "{input}");
        }
        assert_eq!(XTEXT.decode("a+2"), Err(Error::Truncated { offset: 3 }));
    }

    #[test]
    fn rfc_examples() {
        assert_eq!(
            PERCENT
                .decode("This%20is%20%2A%2A%2Afun%2A%2A%2A")
                .as_deref(),
            Ok(&b"This is ***fun***"[..])
        );
        assert_eq!(
            PERCENT.encode("This is ***fun***"),
            "This%20is%20%2A%2A%2Afun%2A%2A%2A"
        );
        assert_eq!(XTEXT.encode("Joe+Smith=x"), "Joe+2BSmith+3Dx");
        assert_eq!(
            XTEXT.decode("Joe+2BSmith+3dx").as_deref(),
            Ok(&b"Joe+Smith=x"[..])
        );
    }
}
