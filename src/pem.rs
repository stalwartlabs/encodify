/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! PEM textual encoding (RFC 7468) and OpenPGP ASCII armor (RFC 9580
//! section 6.2).
//!
//! Parsing is lax, as RFC 7468 recommends: text around the blocks is
//! ignored, every kind of whitespace and line ending is accepted inside the
//! base64, armor headers are skipped and an OpenPGP CRC24 line never causes a
//! rejection. Encoding follows the strict format: 64 columns and no headers.
//!
//! ```
//! use encodify::pem;
//!
//! let text = pem::STANDARD.encode("PUBLIC KEY", b"key bytes");
//! assert_eq!(text, "-----BEGIN PUBLIC KEY-----\na2V5IGJ5dGVz\n-----END PUBLIC KEY-----\n");
//!
//! let block = pem::STANDARD.decode(&text)?;
//! assert_eq!(block.label, "PUBLIC KEY");
//! assert_eq!(block.contents, b"key bytes");
//! # Ok::<(), encodify::Error>(())
//! ```

use crate::{
    Buffer, Error,
    base64::{self, LineEnding},
    error::ToStr,
};
use memchr::{memchr2, memmem};
use std::ops::Range;

const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"-----END ";
const DASHES: &[u8] = b"-----";
const LINE_WIDTH: usize = 64;

/// PEM encoder and decoder. Decoding accepts any line ending; the engine's
/// line ending is used when encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pem {
    ending: LineEnding,
}

/// PEM with LF line endings.
pub const STANDARD: Pem = Pem {
    ending: LineEnding::Lf,
};

/// One decoded block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block<'x> {
    /// The label of the `-----BEGIN` line, such as `PRIVATE KEY`.
    pub label: &'x str,
    /// The label of the `-----END` line. RFC 7468 requires it to match
    /// `label` and lets parsers ignore a mismatch; checking it is left to
    /// the caller.
    pub end_label: &'x str,
    /// The raw armor headers (`Key: Value` lines) when present, as found in
    /// legacy encrypted PEM keys and OpenPGP armor.
    pub headers: &'x [u8],
    /// The decoded contents.
    pub contents: Vec<u8>,
    /// Byte range of the whole block in the input, from `-----BEGIN` to the
    /// end of the `-----END` line.
    pub span: Range<usize>,
}

impl Pem {
    /// Returns this engine with a different line ending for encoding.
    pub const fn with_ending(mut self, ending: LineEnding) -> Self {
        self.ending = ending;
        self
    }

    const fn body(&self) -> base64::Base64 {
        base64::STANDARD.wrapped(LINE_WIDTH, self.ending)
    }

    /// Length of the encoding of `data_len` bytes under a label of
    /// `label_len` bytes.
    pub const fn encoded_len(&self, label_len: usize, data_len: usize) -> usize {
        let ending = self.ending.as_bytes().len();
        let frame = BEGIN.len() + END.len() + 2 * DASHES.len() + 2 * label_len + 2 * ending;
        frame + self.body().encoded_len(data_len)
    }

    /// Encodes `data` into a new `String`.
    pub fn encode(&self, label: &str, data: impl AsRef<[u8]>) -> String {
        let data = data.as_ref();
        let mut out = String::with_capacity(self.encoded_len(label.len(), data.len()));
        self.append_encoded(label, data, &mut out);
        out
    }

    /// Appends the encoding of `data` to `out` and returns the number of bytes
    /// appended. `label` must be printable ASCII; other characters are
    /// replaced by `?`.
    pub fn encode_append(
        &self,
        label: &str,
        data: impl AsRef<[u8]>,
        out: &mut impl Buffer,
    ) -> usize {
        self.append_encoded(label, data.as_ref(), out)
    }

    fn append_encoded(&self, label: &str, data: &[u8], out: &mut impl Buffer) -> usize {
        out.reserve_ascii(self.encoded_len(label.len(), data.len()));
        let begin = self.push_boundary(BEGIN, label, out);
        let body = self.body().encode_append(data, out);
        begin + body + self.push_boundary(END, label, out)
    }

    fn push_boundary(&self, marker: &[u8], label: &str, out: &mut impl Buffer) -> usize {
        out.push_ascii(marker)
            + out.push_ascii_where(label.as_bytes(), |byte| !byte.is_ascii_control())
            + out.push_ascii(DASHES)
            + out.push_ascii(self.ending.as_bytes())
    }

    /// Decodes the first block of `input`.
    pub fn decode<'x>(&self, input: &'x (impl AsRef<[u8]> + ?Sized)) -> Result<Block<'x>, Error> {
        self.blocks(input).next().unwrap_or(Err(Error::NotFound))
    }

    /// Iterates over every block of `input`.
    pub fn blocks<'x>(&self, input: &'x (impl AsRef<[u8]> + ?Sized)) -> Blocks<'x> {
        Blocks {
            input: input.as_ref(),
            offset: 0,
        }
    }
}

impl<'x> Block<'x> {
    fn end_of(input: &[u8], begin: usize) -> usize {
        let mut cursor = Cursor {
            input,
            position: begin + BEGIN.len(),
        };
        match cursor.take_until(END) {
            Some(_) => {
                cursor.next_line();
                cursor.position
            }
            None => input.len(),
        }
    }

    fn parse(input: &'x [u8], begin: usize) -> Result<Self, Error> {
        let label_start = begin + BEGIN.len();
        let mut cursor = Cursor {
            input,
            position: label_start,
        };
        let label = cursor
            .label()?
            .to_str()
            .map_err(|err| err.shifted(label_start))?;
        cursor.next_line();
        let headers = cursor.headers();
        let body_start = cursor.position;
        let body = cursor.take_until(END).ok_or(Error::Truncated {
            offset: input.len(),
        })?;
        let contents = base64::LENIENT
            .decode(strip_checksum(body))
            .map_err(|err| err.shifted(body_start))?;
        let end_start = cursor.position;
        let end_label = cursor
            .label()?
            .to_str()
            .map_err(|err| err.shifted(end_start))?;
        cursor.next_line();
        Ok(Block {
            label,
            end_label,
            headers,
            contents,
            span: begin..cursor.position,
        })
    }
}

/// Iterator over the blocks of a PEM input. Created by [`Pem::blocks`].
#[derive(Debug, Clone)]
pub struct Blocks<'x> {
    input: &'x [u8],
    offset: usize,
}

impl<'x> Iterator for Blocks<'x> {
    type Item = Result<Block<'x>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let begin = self.offset + memmem::find(self.input.get(self.offset..)?, BEGIN)?;
        let result = Block::parse(self.input, begin);
        self.offset = match &result {
            Ok(block) => block.span.end,
            Err(_) => Block::end_of(self.input, begin),
        };
        Some(result)
    }
}

#[derive(Clone, Copy)]
struct Cursor<'x> {
    input: &'x [u8],
    position: usize,
}

impl<'x> Cursor<'x> {
    fn rest(self) -> &'x [u8] {
        self.input.get(self.position..).unwrap_or_default()
    }

    fn line_end(self) -> usize {
        memchr2(b'\n', b'\r', self.rest()).map_or(self.input.len(), |len| self.position + len)
    }

    fn line(self) -> &'x [u8] {
        self.input
            .get(self.position..self.line_end())
            .unwrap_or_default()
    }

    fn next_line(&mut self) {
        let end = self.line_end();
        self.position = match self.input.get(end..) {
            Some([b'\r', b'\n', ..]) => end + 2,
            Some([_, ..]) => end + 1,
            _ => end,
        };
    }

    fn take_until(&mut self, needle: &[u8]) -> Option<&'x [u8]> {
        let rest = self.rest();
        let len = memmem::find(rest, needle)?;
        self.position += len + needle.len();
        rest.get(..len)
    }

    fn label(self) -> Result<&'x [u8], Error> {
        let line = self.line();
        memmem::find(line, DASHES)
            .and_then(|len| line.get(..len))
            .ok_or_else(|| Error::Truncated {
                offset: self.line_end(),
            })
    }

    fn headers(&mut self) -> &'x [u8] {
        let start = self.position;
        while self.line().contains(&b':') && self.line_end() < self.input.len() {
            self.next_line();
        }
        let end = self.position;
        if end > start && self.line().iter().all(u8::is_ascii_whitespace) {
            self.next_line();
        }
        self.input.get(start..end).unwrap_or_default()
    }
}

fn strip_checksum(body: &[u8]) -> &[u8] {
    let trimmed = body.trim_ascii_end();
    let last_line = trimmed
        .rsplit(|&byte| byte == b'\n' || byte == b'\r')
        .next()
        .unwrap_or_default();
    match last_line.trim_ascii_start() {
        [b'=', checksum @ ..]
            if checksum.len() == 4
                && checksum
                    .iter()
                    .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/') =>
        {
            trimmed
                .get(..trimmed.len() - last_line.len())
                .unwrap_or_default()
        }
        _ => body,
    }
}

#[cfg(test)]
mod tests {
    use super::STANDARD;
    use crate::{Error, base64::LineEnding, test_rng::XorShift};

    #[test]
    fn round_trips_with_64_columns() {
        let mut rng = XorShift::new(11);
        for len in [0, 1, 47, 48, 49, 96, 1000] {
            let data = rng.bytes(len);
            for pem in [STANDARD, STANDARD.with_ending(LineEnding::CrLf)] {
                let text = pem.encode("PRIVATE KEY", &data);
                assert_eq!(text.len(), pem.encoded_len(11, len));
                assert!(
                    text.lines()
                        .all(|line| line.len() <= 64 || line.starts_with("-----"))
                );
                let block = pem.decode(&text).expect("valid pem");
                assert_eq!(block.label, "PRIVATE KEY");
                assert_eq!(block.contents, data);
                assert_eq!(block.span, 0..text.len());
            }
        }
    }

    #[test]
    fn parses_several_blocks_with_surrounding_text() {
        let input = concat!(
            "Subject: keys\n\n",
            "-----BEGIN CERTIFICATE-----\r\n",
            "  YWJj\r\n",
            "  ZGVm\r\n",
            "-----END CERTIFICATE-----\r\n",
            "junk between\n",
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "Proc-Type: 4,ENCRYPTED\n",
            "DEK-Info: AES-128-CBC,00\n",
            "\n",
            "aGVsbG8=\n",
            "-----END RSA PRIVATE KEY-----"
        );
        let blocks = STANDARD
            .blocks(input)
            .collect::<Result<Vec<_>, _>>()
            .expect("valid blocks");
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[0].contents, b"abcdef");
        assert_eq!(
            &input[blocks[0].span.clone()],
            concat!(
                "-----BEGIN CERTIFICATE-----\r\n",
                "  YWJj\r\n",
                "  ZGVm\r\n",
                "-----END CERTIFICATE-----\r\n"
            )
        );
        assert_eq!(blocks[1].label, "RSA PRIVATE KEY");
        assert_eq!(
            blocks[1].headers,
            b"Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n"
        );
        assert_eq!(blocks[1].contents, b"hello");
    }

    #[test]
    fn skips_openpgp_armor_headers_and_checksum() {
        let input = concat!(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
            "Comment: test key\n",
            "\n",
            "aGVsbG8gd29y\n",
            "bGQ=\n",
            "=njUN\n",
            "-----END PGP PUBLIC KEY BLOCK-----\n"
        );
        let block = STANDARD.decode(input).expect("valid armor");
        assert_eq!(block.label, "PGP PUBLIC KEY BLOCK");
        assert_eq!(block.headers, b"Comment: test key\n");
        assert_eq!(block.contents, b"hello world");
    }

    #[test]
    fn strips_indented_checksum_lines() {
        let input = concat!(
            "-----BEGIN PGP MESSAGE-----\n",
            "\n",
            "  aGVsbG8gd29y\n",
            "  bGQ=\n",
            "  =njUN\n",
            "-----END PGP MESSAGE-----\n"
        );
        assert_eq!(
            STANDARD.decode(input).map(|block| block.contents),
            Ok(b"hello world".to_vec())
        );
    }

    #[test]
    fn headers_end_at_the_first_data_line() {
        let input = concat!(
            "-----BEGIN X-----\n",
            "Proc-Type: 4,ENCRYPTED\n",
            "YWJj\n",
            "-----END X-----\n",
            "-----BEGIN Y-----\n",
            "ZGVm\n",
            "-----END Y-----\n"
        );
        let blocks = STANDARD
            .blocks(input)
            .collect::<Result<Vec<_>, _>>()
            .expect("valid blocks");
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].headers, b"Proc-Type: 4,ENCRYPTED\n");
        assert_eq!(blocks[0].contents, b"abc");
        assert_eq!(blocks[1].label, "Y");
        assert_eq!(blocks[1].contents, b"def");
    }

    #[test]
    fn iteration_continues_after_a_malformed_block() {
        let input = concat!(
            "-----BEGIN A-----\n",
            "YW*j\n",
            "-----END A-----\n",
            "-----BEGIN B-----\n",
            "YWJj\n",
            "-----END C-----\n"
        );
        let mut blocks = STANDARD.blocks(input);
        assert!(matches!(blocks.next(), Some(Err(_))));
        let block = blocks.next().and_then(Result::ok).expect("second block");
        assert_eq!((block.label, block.end_label), ("B", "C"));
        assert_eq!(block.contents, b"abc");
        assert!(blocks.next().is_none());
    }

    #[test]
    fn encoding_sanitizes_labels_and_reserves_the_exact_length() {
        let text = STANDARD.encode("A-----\n-----END A-----\nX", b"abc");
        assert_eq!(text.lines().count(), 3);
        let block = STANDARD.decode(&text).expect("valid pem");
        assert_eq!((block.label, block.contents.as_slice()), ("A", &b"abc"[..]));
        let data = XorShift::new(12).bytes(1 << 20);
        let mut out = Vec::new();
        let written = STANDARD.encode_append("DATA", &data, &mut out);
        assert_eq!((out.len(), out.capacity()), (written, written));
    }

    #[test]
    fn reports_missing_and_broken_blocks() {
        assert_eq!(STANDARD.decode("no pem here"), Err(Error::NotFound));
        assert_eq!(
            STANDARD.decode("-----BEGIN X-----\nYWJj\n"),
            Err(Error::Truncated { offset: 23 })
        );
        assert_eq!(
            STANDARD.decode("-----BEGIN X-----\nYW*j\n-----END X-----\n"),
            Err(Error::InvalidByte {
                offset: 20,
                byte: b'*'
            })
        );
    }
}
