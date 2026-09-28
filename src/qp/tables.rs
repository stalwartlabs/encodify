/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::Mode;
use crate::hex::EscapeTable;

pub(super) const MAX_CONTENT: usize = 75;
pub(super) const ESCAPED: usize = 3;
pub(super) const SOFT_BREAK: [u8; 3] = *b"=\r\n";
pub(super) const HARD_BREAK: [u8; 2] = *b"\r\n";

pub(super) const PLAIN: u8 = 0;
pub(super) const BLANK: u8 = 1;
pub(super) const ESCAPE: u8 = 2;
pub(super) const CR: u8 = 3;
pub(super) const LF: u8 = 4;

pub(super) static CLASS: [u8; 256] = {
    let mut table = [ESCAPE; 256];
    let mut byte = 0;
    while byte < 256 {
        table[byte] = match byte as u8 {
            b' ' | b'\t' => BLANK,
            b'\r' => CR,
            b'\n' => LF,
            b'=' => ESCAPE,
            0x21..=0x7e => PLAIN,
            _ => ESCAPE,
        };
        byte += 1;
    }
    table
};

pub(super) static ESCAPE_WORDS: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut byte = 0;
    while byte < 256 {
        let [equals, high, low, _] = EscapeTable::escaped(b'=', byte as u8);
        table[byte] = u32::from_le_bytes([equals, high, low, 0]);
        byte += 1;
    }
    table
};

pub(super) trait QpByte: Copy {
    /// Whether the byte is a space or a tab.
    fn is_blank(self) -> bool;

    /// Whether the line encoders write the byte as `=XX`; CR and LF too when
    /// `BINARY`.
    fn needs_escape<const BINARY: bool>(self) -> bool;

    /// The `=XX` escape of the byte.
    fn escape(self) -> [u8; 3];
}

impl QpByte for u8 {
    #[inline(always)]
    fn is_blank(self) -> bool {
        matches!(self, b' ' | b'\t')
    }

    #[inline(always)]
    fn needs_escape<const BINARY: bool>(self) -> bool {
        match CLASS[self as usize] {
            ESCAPE => true,
            CR | LF => BINARY,
            _ => false,
        }
    }

    #[inline(always)]
    fn escape(self) -> [u8; 3] {
        let [equals, high, low, _] = ESCAPE_WORDS[self as usize].to_le_bytes();
        [equals, high, low]
    }
}

#[cfg_attr(not(encodify_simd), allow(dead_code))]
pub(crate) struct WordClass {
    pub(crate) low: [u8; 16],
    pub(crate) high: [u8; 16],
}

const LINE: EscapeTable = Mode::Body.escapes();
const Q_TEXT: EscapeTable = Mode::QText.escapes();
const Q_PHRASE: EscapeTable = Mode::QPhrase.escapes();
const DKIM: EscapeTable = Mode::Dkim.escapes();

static LINE_TABLE: EscapeTable = LINE;
static Q_TEXT_TABLE: EscapeTable = Q_TEXT;
static Q_PHRASE_TABLE: EscapeTable = Q_PHRASE;
static DKIM_TABLE: EscapeTable = DKIM;

static LINE_STRS: [&str; 256] = LINE_TABLE.strs();
static Q_TEXT_STRS: [&str; 256] = Q_TEXT_TABLE.strs();
static Q_PHRASE_STRS: [&str; 256] = Q_PHRASE_TABLE.strs();
static DKIM_STRS: [&str; 256] = DKIM_TABLE.strs();

static Q_TEXT_CLASS: WordClass = Mode::QText.word_class();
static Q_PHRASE_CLASS: WordClass = Mode::QPhrase.word_class();
static DKIM_CLASS: WordClass = Mode::Dkim.word_class();

impl Mode {
    const fn safe_set(self) -> [bool; 256] {
        let mut set = [false; 256];
        let mut byte = 0;
        while byte < 256 {
            let ch = byte as u8;
            set[byte] = match self {
                Mode::Body | Mode::Binary => matches!(ch, b'\t' | b' '..=b'<' | b'>'..=b'~'),
                Mode::QText => matches!(ch, b' '..=b'~') && !matches!(ch, b'=' | b'?' | b'_'),
                Mode::QPhrase => matches!(
                    ch,
                    b' ' | b'A'..=b'Z'
                        | b'a'..=b'z'
                        | b'0'..=b'9'
                        | b'!'
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                ),
                Mode::Dkim => matches!(ch, 0x21..=0x3a | 0x3c | 0x3e..=0x7b | 0x7d | 0x7e),
            };
            byte += 1;
        }
        set
    }

    const fn escapes(self) -> EscapeTable {
        let table = EscapeTable::new(b'=', &self.safe_set());
        match self {
            Mode::QText | Mode::QPhrase => table.with(b' ', b'_'),
            _ => table,
        }
    }

    const fn word_class(self) -> WordClass {
        let set = self.safe_set();
        let mut low = [0u8; 16];
        let mut high = [0u8; 16];
        let mut row = 2;
        while row < 8 {
            let bit = 1 << (row - 2);
            high[row] = bit;
            let mut column = 0;
            while column < 16 {
                if set[row * 16 + column] {
                    low[column] |= bit;
                }
                column += 1;
            }
            row += 1;
        }
        WordClass { low, high }
    }

    pub(super) const fn byte_len(self, byte: u8) -> usize {
        match self {
            Mode::Body | Mode::Binary => LINE.byte_len(byte),
            Mode::QText => Q_TEXT.byte_len(byte),
            Mode::QPhrase => Q_PHRASE.byte_len(byte),
            Mode::Dkim => DKIM.byte_len(byte),
        }
    }

    pub(super) fn byte_str(self, byte: u8) -> &'static str {
        match self {
            Mode::Body | Mode::Binary => LINE_STRS[byte as usize],
            Mode::QText => Q_TEXT_STRS[byte as usize],
            Mode::QPhrase => Q_PHRASE_STRS[byte as usize],
            Mode::Dkim => DKIM_STRS[byte as usize],
        }
    }

    pub(super) fn table(self) -> &'static EscapeTable {
        match self {
            Mode::QPhrase => &Q_PHRASE_TABLE,
            Mode::Dkim => &DKIM_TABLE,
            _ => &Q_TEXT_TABLE,
        }
    }

    pub(super) fn class(self) -> &'static WordClass {
        match self {
            Mode::QPhrase => &Q_PHRASE_CLASS,
            Mode::Dkim => &DKIM_CLASS,
            _ => &Q_TEXT_CLASS,
        }
    }
}
