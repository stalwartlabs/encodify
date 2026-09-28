/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::WordEncoding;
use crate::{
    Buffer, Fold, base64,
    qp::{self, QuotedPrintable},
};

/// The longest encoded word, delimiters included (RFC 2047 section 2).
pub const MAX_WORD_LEN: usize = 75;

const DELIMITERS: usize = "=?".len() + "?X?".len() + "?=".len();
const WORD_END: &[u8] = b"?=";

/// Writes header text as RFC 2047 encoded words, `=?charset?X?payload?=`.
///
/// A word never splits a character (section 5, rule 3) and is at most
/// [`MAX_WORD_LEN`] characters long. Engines are `Copy` and cheap to pass
/// around; the constants in this module are engines.
///
/// ```
/// use encodify::{Fold, rfc2047};
///
/// let mut header = String::from("Subject: ");
/// let mut column = header.len();
/// rfc2047::Q_TEXT.encode_words("utf-8", "Grüße aus Köln", &mut column, Fold::HEADER, &mut header);
/// assert_eq!(header, "Subject: =?utf-8?Q?Gr=C3=BC=C3=9Fe_aus_K=C3=B6ln?=");
///
/// let value = header.strip_prefix("Subject: ").unwrap_or_default();
/// let text = rfc2047::decode_text(value.as_bytes(), rfc2047::utf8_charset);
/// assert_eq!(text, "Grüße aus Köln");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WordEncoder {
    encoding: WordEncoding,
    q: QuotedPrintable,
}

/// "B" encoded words, whose payload is base64.
pub const B: WordEncoder = WordEncoder {
    encoding: WordEncoding::Base64,
    q: qp::Q_TEXT,
};

/// "Q" encoded words for unstructured text such as `Subject`.
pub const Q_TEXT: WordEncoder = WordEncoder {
    encoding: WordEncoding::Q,
    q: qp::Q_TEXT,
};

/// "Q" encoded words inside a phrase, such as a display name (RFC 2047
/// section 5, rule 3).
pub const Q_PHRASE: WordEncoder = WordEncoder {
    encoding: WordEncoding::Q,
    q: qp::Q_PHRASE,
};

impl WordEncoder {
    /// The letter that names the encoding inside a word: `B` or `Q`.
    pub const fn letter(&self) -> u8 {
        match self.encoding {
            WordEncoding::Base64 => b'B',
            WordEncoding::Q => b'Q',
        }
    }

    /// Length of the payload of `text` encoded as a single word, without the
    /// `=?charset?X?` and `?=` delimiters.
    pub fn payload_len(&self, text: impl AsRef<[u8]>) -> usize {
        let text = text.as_ref();
        match self.encoding {
            WordEncoding::Base64 => base64::STANDARD.encoded_len(text.len()),
            WordEncoding::Q => self.q.encoded_len(text),
        }
    }

    /// Appends the payload of the longest prefix of `text` that ends on a
    /// character boundary and whose payload is at most `budget` characters
    /// long. Returns the length of that prefix in bytes, which is zero when
    /// not even the first character fits.
    pub fn encode_payload(&self, text: &str, budget: usize, out: &mut impl Buffer) -> usize {
        match self.encoding {
            WordEncoding::Base64 => {
                let taken = Self::base64_prefix(text, budget);
                let chunk = text.as_bytes().get(..taken).unwrap_or_default();
                base64::STANDARD.encode_append(chunk, out);
                taken
            }
            WordEncoding::Q => self.q.encode_prefix(text, budget, out),
        }
    }

    /// Appends `text` as encoded words in `charset` and returns the number of
    /// bytes appended. `column` is the current column before the call and is
    /// updated to the column after it. Words follow each other on a line,
    /// separated by a space, while they fit in `fold.width` columns; the next
    /// word then starts a new line after `fold.separator`. A word takes as
    /// much of the text as fits on its line, and a line that cannot hold even
    /// one character is folded first. Decoders drop the space between two
    /// encoded words, so the text reads back unchanged.
    pub fn encode_words(
        &self,
        charset: &str,
        text: &str,
        column: &mut usize,
        fold: Fold<'_>,
        out: &mut impl Buffer,
    ) -> usize {
        let overhead = DELIMITERS + charset.len();
        let budget_at = |start: usize| {
            fold.width
                .saturating_sub(start)
                .min(MAX_WORD_LEN)
                .saturating_sub(overhead)
        };
        let mut appended = 0;
        let mut rest = text;
        let mut gap: &[u8] = b"";
        let mut start = *column;
        let mut folded = false;
        let mut first = self.first_cost(rest);
        while !rest.is_empty() {
            let budget = budget_at(start);
            if first > budget && !folded && start > fold.indent {
                gap = fold.separator;
                start = fold.indent;
                folded = true;
                continue;
            }
            let word = Word {
                gap,
                charset: charset.as_bytes(),
                text: rest,
                budget: budget.max(first),
            };
            let (taken, written) = self.append_word(word, out);
            appended += written;
            *column = start + written - gap.len();
            rest = rest.get(taken..).unwrap_or_default();
            if rest.is_empty() {
                break;
            }
            first = self.first_cost(rest);
            folded = first > budget_at(*column + 1);
            (gap, start) = match folded {
                true => (fold.separator, fold.indent),
                false => (&b" "[..], *column + 1),
            };
        }
        appended
    }

    fn append_word(&self, word: Word<'_>, out: &mut impl Buffer) -> (usize, usize) {
        let letter = [b'?', self.letter(), b'?'];
        let head = [word.gap, b"=?", word.charset, &letter];
        match self.encoding {
            WordEncoding::Q => self
                .q
                .append_word(&head, word.text, word.budget, WORD_END, out),
            WordEncoding::Base64 => {
                let taken = Self::base64_prefix(word.text, word.budget);
                let chunk = word.text.as_bytes().get(..taken).unwrap_or_default();
                let written = head
                    .iter()
                    .map(|piece| out.push_ascii(piece))
                    .sum::<usize>()
                    + base64::STANDARD.encode_append(chunk, out)
                    + out.push_ascii(WORD_END);
                (taken, written)
            }
        }
    }

    fn first_cost(&self, text: &str) -> usize {
        let bytes = text.as_bytes();
        let len = match bytes.first() {
            None => 0,
            Some(&lead) if lead < 0x80 => 1,
            Some(&lead) => lead.leading_ones() as usize,
        };
        match self.encoding {
            WordEncoding::Base64 => base64::STANDARD.encoded_len(len),
            WordEncoding::Q => bytes
                .iter()
                .take(len)
                .map(|&byte| self.q.encoded_byte_len(byte))
                .sum(),
        }
    }

    fn base64_prefix(text: &str, budget: usize) -> usize {
        let mut taken = (budget / 4 * 3).min(text.len());
        while !text.is_char_boundary(taken) {
            taken -= 1;
        }
        taken
    }
}

#[derive(Clone, Copy)]
struct Word<'x> {
    gap: &'x [u8],
    charset: &'x [u8],
    text: &'x str,
    budget: usize,
}

#[cfg(test)]
mod tests {
    use super::{B, MAX_WORD_LEN, Q_PHRASE, Q_TEXT, WordEncoder};
    use crate::{
        Fold, base64,
        rfc2047::{decode_text, utf8_charset},
        test_rng::XorShift,
    };

    const SAMPLES: [&str; 8] = [
        "Hello",
        "Grüße aus Köln, schöne Grüße!",
        "Привет, как дела? Это тестовое письмо с довольно длинной темой.",
        "【重要】来週の会議についてのお知らせと資料の共有をお願いします",
        "emoji 🦀🦀🦀 and =?not-a-word?= _under_ score",
        "a",
        "ÿ",
        "x y z = ? _ \t tab",
    ];

    fn check(encoder: WordEncoder, text: &str, start: usize, fold: Fold<'_>) {
        let mut out = String::from_iter(std::iter::repeat_n('x', start));
        let mut column = start;
        let appended = encoder.encode_words("utf-8", text, &mut column, fold, &mut out);
        assert_eq!(appended, out.len() - start, "{text}");
        let value = out.get(start..).unwrap_or_default();
        let lines: Vec<&str> = out.split("\r\n").collect();
        assert!(
            lines.iter().all(|line| line.len() <= fold.width.max(start)),
            "{out:?}"
        );
        assert_eq!(lines.last().map_or(0, |line| line.len()), column, "{out:?}");
        for word in value
            .split([' ', '\r', '\n'])
            .filter(|word| !word.is_empty())
        {
            assert!(word.len() <= MAX_WORD_LEN, "{word}");
            assert!(
                word.starts_with("=?utf-8?") && word.ends_with("?="),
                "{word}"
            );
        }
        assert_eq!(
            decode_text(value.as_bytes(), utf8_charset),
            text.trim(),
            "{out:?}"
        );
    }

    #[test]
    fn words_decode_back_to_the_text() {
        for encoder in [B, Q_TEXT, Q_PHRASE] {
            for text in SAMPLES {
                for start in [0, 9, 30, 60, 75, 80] {
                    check(encoder, text, start, Fold::HEADER);
                }
            }
        }
    }

    #[test]
    fn random_text_round_trips() {
        let mut rng = XorShift::new(51);
        let alphabet: Vec<char> = "aZ09 _=?\t.éßПр日本🦀".chars().collect();
        for _ in 0..300 {
            let len = rng.below(120);
            let text: String = (0..len).map(|_| *rng.pick(&alphabet)).collect();
            let text = text.trim().to_string();
            for encoder in [B, Q_TEXT, Q_PHRASE] {
                check(encoder, &text, rng.below(70), Fold::HEADER);
            }
        }
    }

    fn reference_words(
        encoder: WordEncoder,
        charset: &str,
        text: &str,
        column: &mut usize,
        fold: Fold<'_>,
    ) -> String {
        let letter = char::from(encoder.letter());
        let overhead = 7 + charset.len();
        let prefix_len = |text: &str, budget: usize| -> usize {
            if letter == 'B' {
                let mut taken = (budget / 4 * 3).min(text.len());
                while !text.is_char_boundary(taken) {
                    taken -= 1;
                }
                return taken;
            }
            let mut used = 0;
            let mut taken = 0;
            for ch in text.chars() {
                let cost = encoder.payload_len(ch.to_string());
                if used + cost > budget {
                    break;
                }
                used += cost;
                taken += ch.len_utf8();
            }
            taken
        };
        let mut out = String::new();
        let mut rest = text;
        while !rest.is_empty() {
            let room = fold.width.saturating_sub(*column).min(MAX_WORD_LEN);
            let mut taken = prefix_len(rest, room.saturating_sub(overhead));
            if taken == 0 && *column > fold.indent {
                out.push_str(std::str::from_utf8(fold.separator).unwrap_or_default());
                *column = fold.indent;
                continue;
            }
            if taken == 0 {
                taken = rest.chars().next().map_or(rest.len(), char::len_utf8);
            }
            let (chunk, tail) = rest.split_at(taken);
            let payload = match letter {
                'B' => base64::STANDARD.encode(chunk),
                _ => encoder.q.encode(chunk),
            };
            let word = format!("=?{charset}?{letter}?{payload}?=");
            *column += word.len();
            out.push_str(&word);
            rest = tail;
            if rest.is_empty() {
                break;
            }
            let first = rest.chars().next().map_or(0, char::len_utf8);
            let next = overhead + encoder.payload_len(rest.get(..first).unwrap_or_default());
            if *column + 1 + next <= fold.width {
                out.push(' ');
                *column += 1;
            } else {
                out.push_str(std::str::from_utf8(fold.separator).unwrap_or_default());
                *column = fold.indent;
            }
        }
        out
    }

    #[test]
    fn words_match_the_greedy_reference() {
        let mut rng = XorShift::new(52);
        let alphabet: Vec<char> = "aZ09 _=?\t.éßПр日本🦀".chars().collect();
        for round in 0..600 {
            let len = rng.below(if round % 4 == 0 { 200 } else { 40 });
            let text: String = (0..len).map(|_| *rng.pick(&alphabet)).collect();
            for encoder in [B, Q_TEXT, Q_PHRASE] {
                for charset in ["utf-8", "us-ascii", "iso-8859-15"] {
                    for fold in [Fold::HEADER, Fold::new(40, b"\n\t", 1)] {
                        let start = rng.below(80);
                        let mut expected_column = start;
                        let expected =
                            reference_words(encoder, charset, &text, &mut expected_column, fold);
                        let mut column = start;
                        let mut out = String::new();
                        encoder.encode_words(charset, &text, &mut column, fold, &mut out);
                        assert_eq!(out, expected, "{encoder:?} {charset} {start} {text:?}");
                        assert_eq!(column, expected_column);
                    }
                }
            }
        }
    }

    #[test]
    fn long_charsets_never_fold_after_a_space() {
        let charset = "x".repeat(66);
        for encoder in [B, Q_TEXT, Q_PHRASE] {
            for start in [0, 10, 40] {
                let mut column = start;
                let mut out = String::new();
                encoder.encode_words(&charset, "abc déf ghi", &mut column, Fold::HEADER, &mut out);
                assert!(!out.contains(" \r\n"), "{encoder:?} {start} {out:?}");
                assert_eq!(
                    decode_text(out.as_bytes(), utf8_charset),
                    "abc déf ghi",
                    "{out:?}"
                );
            }
        }
    }

    #[test]
    fn payload_prefixes_respect_the_budget() {
        let text = "Grüße 日本";
        for encoder in [B, Q_TEXT, Q_PHRASE] {
            for budget in 0..40 {
                let mut out = String::new();
                let taken = encoder.encode_payload(text, budget, &mut out);
                assert!(text.is_char_boundary(taken));
                assert!(out.len() <= budget, "{budget} {out}");
                assert_eq!(encoder.payload_len(&text[..taken]), out.len());
            }
        }
        let mut out = String::new();
        assert_eq!(B.encode_payload("日本", 3, &mut out), 0);
        assert_eq!(B.encode_payload("日本", 4, &mut out), 3);
        assert_eq!(out, "5pel");
    }
}
