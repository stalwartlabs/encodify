/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

pub(crate) const INVALID: u8 = 0xff;

const STANDARD_SYMBOLS: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE_SYMBOLS: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const IMAP_SYMBOLS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

pub(crate) const FLAGS_BASE: u8 = b'+';
pub(crate) const FLAGS_LEN: usize = 80;
pub(crate) const FLAG_VALID: u8 = 0x80;
#[cfg(not(encodify_simd))]
pub(crate) const TRIPLE_BITS: u32 = 24;
#[cfg(not(encodify_simd))]
const TRIPLE_INVALID: u32 = u32::MAX;

pub(crate) struct Tables {
    pub(crate) encode: [u8; 64],
    pub(crate) decode: [u8; 256],
    #[cfg_attr(not(encodify_neon), allow(dead_code))]
    pub(crate) flags: [u8; FLAGS_LEN],
    #[cfg_attr(not(encodify_x86), allow(dead_code))]
    pub(crate) nibbles: Option<Nibbles>,
    #[cfg_attr(not(encodify_x86), allow(dead_code))]
    pub(crate) offsets: [u8; 16],
    #[cfg(not(encodify_simd))]
    pub(crate) pairs: [u16; 4096],
    #[cfg(not(encodify_simd))]
    pub(crate) triples: [[u32; 256]; 4],
}

#[cfg_attr(not(encodify_x86), allow(dead_code))]
pub(crate) struct Nibbles {
    pub(crate) low: [u8; 16],
    pub(crate) high: [u8; 16],
    pub(crate) roll: [u8; 16],
    pub(crate) special: u8,
}

impl Tables {
    const fn new(symbols: &[&[u8; 64]], nibbles: Option<Nibbles>) -> Self {
        let decode = Self::decode_table(symbols);
        Tables {
            encode: *symbols[0],
            decode,
            flags: Self::flags(&decode),
            nibbles,
            offsets: Self::offsets(symbols[0][62], symbols[0][63]),
            #[cfg(not(encodify_simd))]
            pairs: Self::pairs(symbols[0]),
            #[cfg(not(encodify_simd))]
            triples: Self::triples(&decode),
        }
    }

    #[cfg(not(encodify_simd))]
    const fn pairs(symbols: &[u8; 64]) -> [u16; 4096] {
        let mut table = [0; 4096];
        let mut value = 0;
        while value < table.len() {
            table[value] = u16::from_le_bytes([symbols[value >> 6], symbols[value & 0x3f]]);
            value += 1;
        }
        table
    }

    #[cfg(not(encodify_simd))]
    const fn triples(decode: &[u8; 256]) -> [[u32; 256]; 4] {
        let mut table = [[TRIPLE_INVALID; 256]; 4];
        let mut byte = 0;
        while byte < decode.len() {
            if decode[byte] != INVALID {
                let sextet = decode[byte] as u32;
                table[0][byte] = sextet << 2;
                table[1][byte] = sextet >> 4 | (sextet & 0x0f) << 12;
                table[2][byte] = (sextet >> 2) << 8 | (sextet & 0x03) << 22;
                table[3][byte] = sextet << 16;
            }
            byte += 1;
        }
        table
    }

    const fn decode_table(symbols: &[&[u8; 64]]) -> [u8; 256] {
        let mut table = [INVALID; 256];
        let mut set = 0;
        while set < symbols.len() {
            let mut value = 0;
            while value < 64 {
                table[symbols[set][value] as usize] = value as u8;
                value += 1;
            }
            set += 1;
        }
        table
    }

    const fn flags(decode: &[u8; 256]) -> [u8; FLAGS_LEN] {
        let mut table = [0; FLAGS_LEN];
        let mut index = 0;
        while index < FLAGS_LEN {
            let value = decode[FLAGS_BASE as usize + index];
            if value != INVALID {
                table[index] = value | FLAG_VALID;
            }
            index += 1;
        }
        table
    }

    const fn offsets(sixty_two: u8, sixty_three: u8) -> [u8; 16] {
        let digits = b'0'.wrapping_sub(52);
        [
            b'A',
            b'a'.wrapping_sub(26),
            digits,
            digits,
            digits,
            digits,
            digits,
            digits,
            digits,
            digits,
            digits,
            digits,
            sixty_two.wrapping_sub(62),
            sixty_three.wrapping_sub(63),
            0,
            0,
        ]
    }
}

impl Nibbles {
    const REJECT: u8 = 0x10;

    const fn new(low: [u8; 16], high: [u8; 8], sixty_two: u8, special: u8) -> Self {
        let rolls = [
            0,
            0,
            62u8.wrapping_sub(sixty_two),
            b'0'.wrapping_neg().wrapping_add(52),
            b'A'.wrapping_neg(),
            b'A'.wrapping_neg(),
            b'a'.wrapping_neg().wrapping_add(26),
            b'a'.wrapping_neg().wrapping_add(26),
        ];
        let mut nibbles = Nibbles {
            low,
            high: [Self::REJECT; 16],
            roll: [0; 16],
            special,
        };
        let mut nibble = 0;
        while nibble < high.len() {
            nibbles.high[2 * nibble] = high[nibble];
            nibbles.roll[2 * nibble] = rolls[nibble];
            nibble += 1;
        }
        if special != 0 {
            nibbles.roll[2 * (special >> 4) as usize - 1] = 63u8.wrapping_sub(special);
        }
        nibbles
    }
}

pub(crate) static STANDARD: Tables = Tables::new(
    &[STANDARD_SYMBOLS],
    Some(Nibbles::new(
        [
            0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x13, 0x1a, 0x1b, 0x1b,
            0x1b, 0x1a,
        ],
        [0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08],
        b'+',
        b'/',
    )),
);

pub(crate) static URL_SAFE: Tables = Tables::new(
    &[URL_SAFE_SYMBOLS],
    Some(Nibbles::new(
        [
            0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x13, 0x3b, 0x3b, 0x3a,
            0x3b, 0x33,
        ],
        [0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x20],
        b'-',
        b'_',
    )),
);

pub(crate) static IMAP: Tables = Tables::new(
    &[IMAP_SYMBOLS],
    Some(Nibbles::new(
        [
            0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x13, 0x1a, 0x1a, 0x1b,
            0x1b, 0x1b,
        ],
        [0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08],
        b'+',
        0,
    )),
);

pub(crate) static ANY: Tables = Tables::new(&[STANDARD_SYMBOLS, URL_SAFE_SYMBOLS], None);

#[cfg(test)]
mod tests {
    use super::*;

    fn shuffle(table: &[u8; 16], index: u8) -> u8 {
        if index & 0x80 != 0 {
            0
        } else {
            table[(index & 0x0f) as usize]
        }
    }

    fn nibble_decode(nibbles: &Nibbles, byte: u8) -> Option<u8> {
        let index = (byte >> 3) & 0x1e;
        let low = !shuffle(&nibbles.low.map(|entry| !entry), byte);
        if low & shuffle(&nibbles.high, index) != 0 {
            return None;
        }
        let special = if byte == nibbles.special { u8::MAX } else { 0 };
        Some(byte.wrapping_add(shuffle(&nibbles.roll, index.wrapping_add(special))))
    }

    fn translate(tables: &Tables, sextet: u8) -> u8 {
        let mut class = sextet.saturating_sub(51);
        if sextet > 25 {
            class += 1;
        }
        sextet.wrapping_add(tables.offsets[class as usize])
    }

    #[test]
    fn simd_constants_match_the_scalar_tables() {
        assert!(ANY.nibbles.is_none());
        for tables in [&STANDARD, &URL_SAFE, &IMAP] {
            let nibbles = tables.nibbles.as_ref().expect("single alphabet");
            for byte in 0..=u8::MAX {
                let expected = tables.decode[byte as usize];
                let expected = (expected != INVALID).then_some(expected);
                assert_eq!(nibble_decode(nibbles, byte), expected, "byte {byte:#04x}");
            }
            for sextet in 0..64 {
                assert_eq!(translate(tables, sextet), tables.encode[sextet as usize]);
            }
        }
    }

    #[test]
    fn flag_tables_cover_every_symbol() {
        for tables in [&STANDARD, &URL_SAFE, &IMAP, &ANY] {
            for byte in 0..=u8::MAX {
                let expected = tables.decode[byte as usize];
                let flag = byte
                    .checked_sub(FLAGS_BASE)
                    .and_then(|index| tables.flags.get(index as usize))
                    .copied()
                    .unwrap_or(0);
                if expected == INVALID {
                    assert_eq!(flag & FLAG_VALID, 0, "byte {byte:#04x}");
                } else {
                    assert_eq!(flag, expected | FLAG_VALID, "byte {byte:#04x}");
                }
            }
        }
    }

    #[test]
    fn any_alphabet_accepts_both_symbol_pairs() {
        for (symbol, value) in [(b'+', 62), (b'-', 62), (b'/', 63), (b'_', 63)] {
            assert_eq!(ANY.decode[symbol as usize], value);
        }
    }
}
