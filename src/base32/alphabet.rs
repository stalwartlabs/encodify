/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

pub(crate) const INVALID: u8 = 0xff;
#[cfg(not(encodify_simd))]
pub(crate) const HALF_INVALID: u32 = 1 << 31;

const STANDARD_SYMBOLS: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STALWART_SYMBOLS: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz792013";
#[cfg(encodify_x86)]
const LETTERS: usize = 26;

#[cfg(any(test, encodify_simd))]
pub(crate) use nibble::Nibbles;

pub(crate) struct Tables {
    pub(crate) encode: [u8; 32],
    pub(crate) pairs: [[u8; 2]; 1024],
    pub(crate) decode: [u8; 256],
    #[cfg(any(test, encodify_simd))]
    pub(crate) nibbles: Nibbles,
    #[cfg(encodify_x86)]
    pub(crate) offsets: [u8; 16],
    #[cfg(not(encodify_simd))]
    pub(crate) halves: [[u32; 256]; 4],
}

pub(crate) static STANDARD: Tables = Tables::new(STANDARD_SYMBOLS);
pub(crate) static STALWART: Tables = Tables::new(STALWART_SYMBOLS);

impl Tables {
    const fn new(symbols: &[u8; 32]) -> Self {
        let decode = Self::decode_table(symbols);
        Tables {
            encode: *symbols,
            pairs: Self::pair_table(symbols),
            decode,
            #[cfg(any(test, encodify_simd))]
            nibbles: Nibbles::new(symbols),
            #[cfg(encodify_x86)]
            offsets: Self::offsets(symbols),
            #[cfg(not(encodify_simd))]
            halves: Self::halves(&decode),
        }
    }

    #[cfg(not(encodify_simd))]
    const fn halves(decode: &[u8; 256]) -> [[u32; 256]; 4] {
        let mut table = [[HALF_INVALID; 256]; 4];
        let mut byte = 0;
        while byte < decode.len() {
            if decode[byte] != INVALID {
                let value = decode[byte] as u32;
                table[0][byte] = value << 15;
                table[1][byte] = value << 10;
                table[2][byte] = value << 5;
                table[3][byte] = value;
            }
            byte += 1;
        }
        table
    }

    const fn decode_table(symbols: &[u8; 32]) -> [u8; 256] {
        let mut table = [INVALID; 256];
        let mut value = 0;
        while value < 32 {
            assert!(symbols[value] < 0x80, "symbols must be ASCII");
            assert!(
                table[symbols[value] as usize] == INVALID,
                "symbols must be distinct"
            );
            table[symbols[value] as usize] = value as u8;
            value += 1;
        }
        table
    }

    const fn pair_table(symbols: &[u8; 32]) -> [[u8; 2]; 1024] {
        let mut table = [[0u8; 2]; 1024];
        let mut index = 0;
        while index < 1024 {
            table[index] = [symbols[index >> 5], symbols[index & 31]];
            index += 1;
        }
        table
    }

    #[cfg(encodify_x86)]
    const fn offsets(symbols: &[u8; 32]) -> [u8; 16] {
        let mut offsets = [0u8; 16];
        let mut value = 0;
        while value < LETTERS {
            assert!(
                symbols[value] == symbols[0] + value as u8,
                "the first 26 symbols must be consecutive"
            );
            value += 1;
        }
        offsets[0] = symbols[0];
        let mut class = 1;
        while class < 32 - LETTERS + 1 {
            let value = LETTERS - 1 + class;
            offsets[class] = symbols[value].wrapping_sub(value as u8);
            class += 1;
        }
        offsets
    }
}

#[cfg(any(test, encodify_simd))]
mod nibble {
    use super::{INVALID, Tables};

    const OTHER_CLASS: u8 = 0x80;

    pub(crate) struct Nibbles {
        pub(crate) low_mask: [u8; 16],
        pub(crate) high_mask: [u8; 16],
        pub(crate) low_value: [u8; 16],
        pub(crate) roll: u8,
    }

    impl Nibbles {
        pub(super) const fn new(symbols: &[u8; 32]) -> Self {
            let decode = Tables::decode_table(symbols);
            let mut nibbles = Nibbles {
                low_mask: [OTHER_CLASS; 16],
                high_mask: [OTHER_CLASS; 16],
                low_value: [INVALID; 16],
                roll: 0u8.wrapping_sub(symbols[0]),
            };
            let mut class = 1u8;
            let mut listed = None;
            let mut high = 0;
            while high < 8 {
                if Self::has_symbol(&decode, high) {
                    assert!(class < OTHER_CLASS, "too many symbol classes");
                    nibbles.high_mask[high] = class;
                    let mut low = 0;
                    while low < 16 {
                        if decode[high << 4 | low] == INVALID {
                            nibbles.low_mask[low] |= class;
                        }
                        low += 1;
                    }
                    if !Self::follows_roll(&decode, high, nibbles.roll) {
                        assert!(
                            listed.is_none(),
                            "at most one class may be listed by low nibble"
                        );
                        listed = Some(high);
                    }
                    class <<= 1;
                }
                high += 1;
            }
            if let Some(high) = listed {
                let mut low = 0;
                while low < 16 {
                    nibbles.low_value[low] = decode[high << 4 | low];
                    low += 1;
                }
            }
            let mut byte = 0;
            while byte < 0x80 {
                let value = decode[byte];
                if value != INVALID {
                    let rolled = (byte as u8).wrapping_add(nibbles.roll);
                    let listed = nibbles.low_value[byte & 0x0f];
                    let resolved = if rolled < listed { rolled } else { listed };
                    assert!(resolved == value, "nibble lookup must resolve every symbol");
                }
                byte += 1;
            }
            nibbles
        }

        const fn has_symbol(decode: &[u8; 256], high: usize) -> bool {
            let mut low = 0;
            while low < 16 {
                if decode[high << 4 | low] != INVALID {
                    return true;
                }
                low += 1;
            }
            false
        }

        const fn follows_roll(decode: &[u8; 256], high: usize, roll: u8) -> bool {
            let mut low = 0;
            while low < 16 {
                let byte = (high << 4 | low) as u8;
                let value = decode[byte as usize];
                if value != INVALID && value != byte.wrapping_add(roll) {
                    return false;
                }
                low += 1;
            }
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Tables {
        fn nibble_decode(&self, byte: u8) -> Option<u8> {
            let nibbles = &self.nibbles;
            let high = (byte >> 4) as usize;
            let low = (byte & 0x0f) as usize;
            if nibbles.low_mask[low] & nibbles.high_mask[high] != 0 {
                return None;
            }
            Some(nibbles.low_value[low].min(byte.wrapping_add(nibbles.roll)))
        }

        #[cfg(encodify_x86)]
        fn translate(&self, value: u8) -> u8 {
            value.wrapping_add(self.offsets[value.saturating_sub(25) as usize])
        }
    }

    #[test]
    fn simd_constants_match_the_scalar_tables() {
        for tables in [&STANDARD, &STALWART] {
            for byte in 0..=u8::MAX {
                let expected = tables.decode[byte as usize];
                let expected = (expected != INVALID).then_some(expected);
                assert_eq!(tables.nibble_decode(byte), expected, "byte {byte:#04x}");
            }
            for value in 0..32u8 {
                #[cfg(encodify_x86)]
                assert_eq!(tables.translate(value), tables.encode[value as usize]);
                assert_eq!(tables.decode[tables.encode[value as usize] as usize], value);
            }
        }
    }

    #[test]
    fn stalwart_alphabet_is_lowercase_only() {
        for byte in b'A'..=b'Z' {
            assert_eq!(STALWART.decode[byte as usize], INVALID);
        }
        for byte in b'a'..=b'z' {
            assert_eq!(STANDARD.decode[byte as usize], INVALID);
        }
    }
}
