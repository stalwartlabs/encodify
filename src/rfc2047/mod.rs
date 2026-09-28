/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Encoding and decoding of RFC 2047 encoded words.
//!
//! [`WordEncoder`] writes header text as encoded words: [`B`], [`Q_TEXT`]
//! and [`Q_PHRASE`] split it at character boundaries into words of at most
//! [`MAX_WORD_LEN`] characters, and [`WordEncoder::encode_payload`] gives
//! header folders the payload that fits a budget.
//!
//! Decoding has two layers. [`EncodedWord`] parses and decodes a single
//! `=?charset?encoding?text?=` token; structured header parsers (address
//! phrases, comments, parameters) call it on the tokens they have already
//! delimited, as RFC 2047 section 6.1 requires. [`decode_text`] decodes a
//! whole unstructured field body (`Subject`, `Comments`, extension fields):
//! it unfolds the value, decodes every encoded word, drops the whitespace
//! between adjacent encoded words (section 6.2) and joins adjacent words in
//! the same charset before converting them, so a character split across two
//! words by a sloppy encoder still decodes.
//!
//! ```
//! use encodify::rfc2047;
//!
//! let subject = rfc2047::decode_text(
//!     b"Re: =?utf-8?q?caf=C3?= =?utf-8?q?=A9?= menu",
//!     rfc2047::utf8_charset,
//! );
//! assert_eq!(subject, "Re: café menu");
//! ```

use crate::{Error, base64, qp};
mod encode;

pub use encode::{B, MAX_WORD_LEN, Q_PHRASE, Q_TEXT, WordEncoder};

use memchr::{memchr_iter, memchr3};
use simdutf8::basic::from_utf8;
use std::borrow::Cow;

/// The encoding of an encoded word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WordEncoding {
    /// `B`: base64.
    Base64,
    /// `Q`: the quoted-printable variant of RFC 2047 section 4.2.
    Q,
}

/// An encoded word located in a header, not yet decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedWord<'x> {
    /// The charset name as written, without the RFC 2231 language suffix.
    pub charset: &'x [u8],
    /// The RFC 2231 section 5 language tag, when present.
    pub language: Option<&'x [u8]>,
    pub encoding: WordEncoding,
    /// The encoded text between the third `?` and the final `?=`.
    pub payload: &'x [u8],
}

const MAX_WORD: usize = 998;
const TERMINATOR: &[u8] = b"?=";

impl<'x> EncodedWord<'x> {
    /// Parses the encoded word at the start of `input`. Returns the word and
    /// the number of bytes it spans, or `None` when `input` does not start
    /// with a well-formed encoded word.
    pub fn parse(input: &'x [u8]) -> Option<(Self, usize)> {
        Self::parse_with(input, |payload| {
            Self::find_terminator(payload.get(..MAX_WORD + 1).unwrap_or(payload))
        })
    }

    fn parse_with(
        input: &'x [u8],
        payload_len: impl FnOnce(&'x [u8]) -> Option<usize>,
    ) -> Option<(Self, usize)> {
        let rest = input.strip_prefix(b"=?")?;
        let charset_len = rest.iter().take(MAX_WORD).position(|&byte| byte == b'?')?;
        let (charset, rest) = rest.split_at(charset_len);
        if charset.iter().any(|&byte| byte <= b' ' || byte >= 0x7f) {
            return None;
        }
        let mut charset_parts = charset.splitn(2, |&byte| byte == b'*');
        let charset = charset_parts.next().unwrap_or_default();
        let language = charset_parts.next();
        if charset.is_empty() {
            return None;
        }
        let (encoding, rest) = match rest {
            [b'?', b'b' | b'B', b'?', rest @ ..] => (WordEncoding::Base64, rest),
            [b'?', b'q' | b'Q', b'?', rest @ ..] => (WordEncoding::Q, rest),
            _ => return None,
        };
        let payload_len = payload_len(rest)?;
        let payload = rest.get(..payload_len)?;
        let consumed = input.len() - rest.len() + payload_len + TERMINATOR.len();
        Some((
            EncodedWord {
                charset,
                language,
                encoding,
                payload,
            },
            consumed,
        ))
    }

    /// Decodes the payload into a new `Vec<u8>` (the bytes are still in the
    /// word's charset).
    pub fn decode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(self.payload.len());
        self.decode_append(&mut out)?;
        Ok(out)
    }

    /// Appends the decoded payload to `out`. On error `out` is unchanged.
    pub fn decode_append(&self, out: &mut Vec<u8>) -> Result<usize, Error> {
        match self.encoding {
            WordEncoding::Base64 => base64::LENIENT.decode_append(self.payload, out),
            WordEncoding::Q => qp::Q_TEXT.decode_append(self.payload, out),
        }
    }

    #[inline]
    fn find_terminator(text: &[u8]) -> Option<usize> {
        memchr_iter(b'?', text).find(|&at| text.get(at + 1) == Some(&b'='))
    }
}

/// Charset conversion that treats every charset as UTF-8, replacing invalid
/// sequences. Suitable for tests and for callers that only expect UTF-8.
pub fn utf8_charset(_charset: &[u8], bytes: &[u8], out: &mut String) {
    out.push_utf8_lossy(bytes);
}

/// Decodes an unstructured header field body.
///
/// Folding whitespace (a run of whitespace containing a line break) becomes
/// a single space, leading and trailing whitespace is removed, encoded words
/// are decoded and the whitespace between two encoded words is dropped.
/// Adjacent encoded words in the same charset are joined before
/// `decode_charset` converts them. Text that is not an encoded word is taken
/// as UTF-8, replacing invalid sequences. The result borrows from `input`
/// when nothing had to change.
pub fn decode_text<'x>(
    input: &'x [u8],
    decode_charset: impl FnMut(&[u8], &[u8], &mut String),
) -> Cow<'x, str> {
    let input = input.trim_fws();
    if let Some(text) = input.verbatim() {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(input.len());
    TextDecoder::new(input, decode_charset, &mut Vec::new(), &mut out).decode();
    Cow::Owned(out)
}

/// Like [`decode_text`], appending the decoded text to `out`. Returns the
/// number of bytes appended.
pub fn decode_text_append(
    input: &[u8],
    decode_charset: impl FnMut(&[u8], &[u8], &mut String),
    out: &mut String,
) -> usize {
    decode_text_append_with(input, decode_charset, &mut Vec::new(), out)
}

/// Like [`decode_text_append`], collecting the bytes of encoded words in
/// `scratch` instead of a buffer of its own, so that decoding many fields
/// with the same `scratch` does not allocate once it has grown. `scratch` is
/// cleared first and keeps its capacity.
pub fn decode_text_append_with(
    input: &[u8],
    decode_charset: impl FnMut(&[u8], &[u8], &mut String),
    scratch: &mut Vec<u8>,
    out: &mut String,
) -> usize {
    let start = out.len();
    let input = input.trim_fws();
    scratch.clear();
    match input.verbatim() {
        Some(text) => out.push_str(text),
        None => {
            out.reserve(input.len());
            TextDecoder::new(input, decode_charset, scratch, out).decode();
        }
    }
    out.len() - start
}

struct TextDecoder<'x, 'o, F> {
    input: &'x [u8],
    rest: &'x [u8],
    out: &'o mut String,
    pending: &'o mut Vec<u8>,
    pending_charset: Option<&'x [u8]>,
    decode_charset: F,
    no_terminator_after: usize,
    terminator_cache: Option<(usize, Option<usize>)>,
    last_was_word: bool,
    next_word: Option<(EncodedWord<'x>, usize)>,
    skipped_space: Option<&'x [u8]>,
}

impl<'x, 'o, F: FnMut(&[u8], &[u8], &mut String)> TextDecoder<'x, 'o, F> {
    fn new(
        input: &'x [u8],
        decode_charset: F,
        pending: &'o mut Vec<u8>,
        out: &'o mut String,
    ) -> Self {
        TextDecoder {
            input,
            rest: input,
            out,
            pending,
            pending_charset: None,
            decode_charset,
            no_terminator_after: usize::MAX,
            terminator_cache: None,
            last_was_word: false,
            next_word: None,
            skipped_space: None,
        }
    }

    fn decode(mut self) {
        while let Some(&byte) = self.rest.first() {
            if byte.is_fws() {
                self.whitespace();
            } else if byte != b'=' || !self.encoded_word() {
                self.text();
            }
        }
        self.flush();
    }

    fn whitespace(&mut self) {
        let len = self.rest.iter().take_while(|byte| byte.is_fws()).count();
        let (space, rest) = self.rest.split_at(len);
        self.rest = rest;
        if self.last_was_word && rest.starts_with(b"=?") {
            self.next_word = self.parse_cached(rest);
            if self.next_word.is_some() {
                self.skipped_space = Some(space);
                return;
            }
        }
        self.push_space(space);
    }

    fn push_space(&mut self, space: &[u8]) {
        self.flush();
        if space.iter().any(|&byte| byte == b'\n' || byte == b'\r') {
            self.out.push(' ');
        } else {
            self.out.push_utf8_lossy(space);
        }
        self.last_was_word = false;
    }

    fn encoded_word(&mut self) -> bool {
        let skipped_space = self.skipped_space.take();
        let decoded = self.decode_word();
        if !decoded && let Some(space) = skipped_space {
            self.push_space(space);
        }
        decoded
    }

    fn decode_word(&mut self) -> bool {
        let next_word = self.next_word.take();
        let offset = self.input.len() - self.rest.len();
        if self.rest.get(1) != Some(&b'?') || offset >= self.no_terminator_after {
            return false;
        }
        let parsed = match next_word {
            Some(word) => Some(word),
            None => self.parse_cached(self.rest),
        };
        let Some((word, consumed)) = parsed else {
            if self.next_terminator(offset + 2).is_none() {
                self.no_terminator_after = offset;
            }
            return false;
        };
        if !self
            .pending_charset
            .is_some_and(|charset| charset.eq_ignore_ascii_case(word.charset))
        {
            self.flush();
        }
        if word.decode_append(self.pending).is_err() {
            return false;
        }
        self.pending_charset = Some(word.charset);
        self.last_was_word = true;
        self.rest = self.rest.get(consumed..).unwrap_or_default();
        true
    }

    fn parse_cached(&mut self, rest: &'x [u8]) -> Option<(EncodedWord<'x>, usize)> {
        EncodedWord::parse_with(rest, |payload| {
            let start = self.input.len() - payload.len();
            let end = self.next_terminator(start)?;
            (end - start < MAX_WORD).then_some(end - start)
        })
    }

    fn next_terminator(&mut self, from: usize) -> Option<usize> {
        if let Some((cached_from, found)) = self.terminator_cache {
            if from >= cached_from && found.is_none_or(|at| at >= from) {
                return found;
            }
            if from < cached_from {
                let gap = self
                    .input
                    .get(from..(cached_from + 1).min(self.input.len()))
                    .unwrap_or_default();
                return EncodedWord::find_terminator(gap)
                    .map(|position| from + position)
                    .or(found);
            }
        }
        let found = EncodedWord::find_terminator(self.input.get(from..).unwrap_or_default())
            .map(|position| from + position);
        self.terminator_cache = Some((from, found));
        found
    }

    fn text(&mut self) {
        self.flush();
        self.last_was_word = false;
        let tail = self.rest.get(1..).unwrap_or_default();
        let end = memchr3(b'=', b'\r', b'\n', tail).map_or(self.rest.len(), |at| at + 1);
        let run = self.rest.get(..end).unwrap_or(self.rest);
        let len = match self.rest.get(end) {
            Some(b'\r' | b'\n') => {
                run.len() - run.iter().rev().take_while(|byte| byte.is_fws()).count()
            }
            _ => run.len(),
        };
        let (text, rest) = self.rest.split_at(len);
        self.out.push_utf8_lossy(text);
        self.rest = rest;
    }

    #[inline]
    fn flush(&mut self) {
        if let Some(charset) = self.pending_charset.take() {
            (self.decode_charset)(charset, self.pending, self.out);
            self.pending.clear();
        }
    }
}

trait Fws {
    fn is_fws(&self) -> bool;
}

impl Fws for u8 {
    #[inline(always)]
    fn is_fws(&self) -> bool {
        matches!(self, b' ' | b'\t' | b'\r' | b'\n')
    }
}

trait HeaderText {
    fn trim_fws(&self) -> &Self;
    fn verbatim(&self) -> Option<&str>;
}

impl HeaderText for [u8] {
    fn verbatim(&self) -> Option<&str> {
        if memchr3(b'\n', b'\r', b'=', self).is_some() {
            return None;
        }
        from_utf8(self).ok()
    }

    fn trim_fws(&self) -> &[u8] {
        let mut text = self;
        while let [first, rest @ ..] = text
            && first.is_fws()
        {
            text = rest;
        }
        while let [rest @ .., last] = text
            && last.is_fws()
        {
            text = rest;
        }
        text
    }
}

trait PushUtf8Lossy {
    fn push_utf8_lossy(&mut self, bytes: &[u8]);
}

impl PushUtf8Lossy for String {
    fn push_utf8_lossy(&mut self, bytes: &[u8]) {
        match from_utf8(bytes) {
            Ok(text) => self.push_str(text),
            Err(_) => {
                for chunk in bytes.utf8_chunks() {
                    self.push_str(chunk.valid());
                    if !chunk.invalid().is_empty() {
                        self.push(char::REPLACEMENT_CHARACTER);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EncodedWord, WordEncoding, decode_text, decode_text_append, decode_text_append_with,
        utf8_charset,
    };
    use crate::{Error, qp};
    use std::borrow::Cow;

    fn latin1(charset: &[u8], bytes: &[u8], out: &mut String) {
        if charset.eq_ignore_ascii_case(b"iso-8859-1") {
            out.extend(bytes.iter().map(|&byte| byte as char));
        } else {
            utf8_charset(charset, bytes, out);
        }
    }

    #[test]
    fn parses_encoded_words() {
        let (word, consumed) =
            EncodedWord::parse(b"=?ISO-8859-1*es?Q?Keld_J=F8rn?= tail").expect("valid word");
        assert_eq!(consumed, 31);
        assert_eq!(word.charset, b"ISO-8859-1");
        assert_eq!(word.language, Some(&b"es"[..]));
        assert_eq!(word.encoding, WordEncoding::Q);
        assert_eq!(word.decode().as_deref(), Ok(&b"Keld J\xf8rn"[..]));
        let (word, _) = EncodedWord::parse(b"=?utf-8?b?w6HDqcOtw7PDug==?=").expect("valid");
        assert_eq!(word.decode().as_deref(), Ok("áéíóú".as_bytes()));
        for invalid in [
            &b"=?utf-8?x?abc?="[..],
            b"=??q?abc?=",
            b"=?utf-8?q?abc",
            b"?utf-8?q?a?=",
            b"=?*en?q?a?=",
        ] {
            assert_eq!(EncodedWord::parse(invalid), None, "{invalid:?}");
        }
        let (word, _) = EncodedWord::parse(b"=?utf-8?q?=ZZ?=").expect("parses");
        assert!(word.decode().is_err());
        for (payload, error) in [
            (&b"=4"[..], Error::Truncated { offset: 2 }),
            (
                b"a=G1",
                Error::InvalidByte {
                    offset: 2,
                    byte: b'G',
                },
            ),
        ] {
            let word = EncodedWord {
                charset: b"utf-8",
                language: None,
                encoding: WordEncoding::Q,
                payload,
            };
            assert_eq!(
                word.decode(),
                qp::Q_TEXT.decode(payload).map(Cow::into_owned)
            );
            assert_eq!(word.decode(), Err(error));
        }
    }

    #[test]
    fn decodes_unstructured_text() {
        for (input, expected) in [
            (&b"plain subject"[..], "plain subject"),
            (b"  padded  ", "padded"),
            (b"folded\r\n line", "folded line"),
            (b"folded \r\n\t line", "folded line"),
            (
                b"=?iso-8859-1?q?this=20is=20some=20text?=",
                "this is some text",
            ),
            (b"=?ISO-8859-1?Q?a?= b", "a b"),
            (b"=?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?=", "ab"),
            (b"=?ISO-8859-1?Q?a?=\r\n =?ISO-8859-1?Q?b?=", "ab"),
            (b"=?ISO-8859-1?Q?a_?= =?ISO-8859-1?Q?_b?=", "a  b"),
            (
                b"x =?iso-8859-1?q?Olle_J=E4rnefors?= y",
                "x Olle Järnefors y",
            ),
            (b"=?utf-8?q?caf=C3?= =?UTF-8?q?=A9?=", "café"),
            (b"=?utf-8?b?w6k=?= =?iso-8859-1?q?=E9?=", "éé"),
            (b"broken =?utf-8?q?no end", "broken =?utf-8?q?no end"),
            (b"=?utf-8?q?bad=ZZ?= ok", "=?utf-8?q?bad=ZZ?= ok"),
            (b"=?utf-8?q?a?= =?utf-8?q?=ZZ?=", "a =?utf-8?q?=ZZ?="),
            (b"=?iso-8859-1?q?this is some text?=", "this is some text"),
            (b"=?iso-8859-1?q?tab\there?= x", "tab\there x"),
            (b"=?utf-8?q?fol\r\n ded?=", "folded"),
            (b"=?utf-8?q?a?=\r\n =?utf-8?b?*?=", "a =?utf-8?b?*?="),
            (b"a =?=?=?=?=? b", "a =?=?=?=?=? b"),
            (b"caf\xc3\xa9 raw", "café raw"),
            (b"text  \r\n next", "text next"),
            (b"a \t b =?utf-8?q?c?= d", "a \t b c d"),
            (b"a=b c=?d", "a=b c=?d"),
            (b"one\r\n two \t\r\n three", "one two three"),
            (b"caf\xc3 \xa9\r\n x", "caf\u{fffd} \u{fffd} x"),
            (b"=?utf-8?q?a_b_c?= and_d", "a b c and_d"),
        ] {
            assert_eq!(
                decode_text(input, latin1),
                expected,
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn decode_text_append_appends() {
        let mut out = String::from("Subject: ");
        assert_eq!(decode_text_append(b"  plain  ", utf8_charset, &mut out), 5);
        assert_eq!(
            decode_text_append(b" =?utf-8?q?caf=C3=A9?= menu", utf8_charset, &mut out),
            10
        );
        assert_eq!(out, "Subject: plaincafé menu");
    }

    #[test]
    fn decode_text_append_with_reuses_scratch() {
        let mut scratch = b"left over".to_vec();
        let mut out = String::new();
        for input in [
            &b"=?utf-8?q?caf=C3=A9?= =?utf-8?b?w6k=?= menu"[..],
            b"plain",
            b"=?iso-8859-1?q?Olle_J=E4rnefors?=\r\n =?utf-8?q?=ZZ?=",
            b"x =?utf-8?q?y?= z",
        ] {
            let mut expected = String::from("> ");
            decode_text_append(input, latin1, &mut expected);
            out.clear();
            out.push_str("> ");
            let appended = decode_text_append_with(input, latin1, &mut scratch, &mut out);
            assert_eq!(out, expected, "{:?}", String::from_utf8_lossy(input));
            assert_eq!(appended, out.len() - 2);
        }
    }

    #[test]
    fn unterminated_words_stay_linear() {
        let mut input = b"=?a?q?x".repeat(20_000);
        input.extend_from_slice(b"?=");
        let decoded = decode_text(&input, utf8_charset);
        let text = String::from_utf8_lossy(&input);
        let expected = format!("{}x", text.strip_suffix("=?a?q?x?=").unwrap_or_default());
        assert_eq!(decoded, expected);
    }

    #[test]
    fn borrows_when_nothing_changes() {
        assert!(matches!(
            decode_text(b"Hello world", utf8_charset),
            Cow::Borrowed("Hello world")
        ));
    }
}
