/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::super::alphabet::{Nibbles, Tables};
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use std::mem::MaybeUninit;

const ENCODE_STEP: usize = 10;
const ENCODE_STEP_OUT: usize = 16;
const ENCODE_LOAD: usize = 16;
const DECODE_STEP: usize = 16;
const DECODE_STEP_OUT: usize = 10;
const DECODE_STORE: usize = 16;

const GATHER_FIRST: [u8; 16] = [1, 0, 1, 0, 2, 1, 2, 1, 3, 2, 4, 3, 4, 3, 5, 4];
const GATHER_SECOND: [u8; 16] = [6, 5, 6, 5, 7, 6, 7, 6, 8, 7, 9, 8, 9, 8, 10, 9];
const SHIFT_MULTIPLIERS: [u16; 8] = [1, 1 << 5, 1 << 2, 1 << 7, 1 << 4, 1 << 1, 1 << 6, 1 << 3];
const EXTRACT: [u8; 16] = [
    4, 3, 2, 1, 0, 12, 11, 10, 9, 8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
];
const MERGE_PAIRS: i16 = 0x0120;
const MERGE_QUADS: i32 = 0x0001_0400;
const SYMBOL_SHIFT: i32 = 11;
const LOW_NIBBLE: i8 = 0x0f;
const LAST_LETTER: i8 = 25;

trait Load {
    fn load(&self) -> __m128i;
}

impl Load for [u8; 16] {
    #[inline(always)]
    fn load(&self) -> __m128i {
        // SAFETY: the `encodify_x86` cfg guarantees SSE2, and the unaligned load
        // reads exactly the 16 bytes of `self`.
        unsafe { _mm_loadu_si128(self.as_ptr().cast()) }
    }
}

impl Load for [u16; 8] {
    #[inline(always)]
    fn load(&self) -> __m128i {
        // SAFETY: the `encodify_x86` cfg guarantees SSE2, and the unaligned load
        // reads exactly the 16 bytes of `self`.
        unsafe { _mm_loadu_si128(self.as_ptr().cast()) }
    }
}

struct Spread {
    first: __m128i,
    second: __m128i,
    multipliers: __m128i,
    offsets: __m128i,
    letters: __m128i,
}

impl Spread {
    #[inline]
    #[target_feature(enable = "ssse3")]
    fn new(tables: &Tables) -> Self {
        Spread {
            first: GATHER_FIRST.load(),
            second: GATHER_SECOND.load(),
            multipliers: SHIFT_MULTIPLIERS.load(),
            offsets: tables.offsets.load(),
            letters: _mm_set1_epi8(LAST_LETTER),
        }
    }

    #[inline]
    #[target_feature(enable = "ssse3")]
    fn encode(&self, bytes: __m128i) -> __m128i {
        let first = _mm_srli_epi16::<SYMBOL_SHIFT>(_mm_mullo_epi16(
            _mm_shuffle_epi8(bytes, self.first),
            self.multipliers,
        ));
        let second = _mm_srli_epi16::<SYMBOL_SHIFT>(_mm_mullo_epi16(
            _mm_shuffle_epi8(bytes, self.second),
            self.multipliers,
        ));
        let values = _mm_packus_epi16(first, second);
        _mm_add_epi8(
            values,
            _mm_shuffle_epi8(self.offsets, _mm_subs_epu8(values, self.letters)),
        )
    }
}

struct Lookup {
    low_mask: __m128i,
    high_mask: __m128i,
    low_value: __m128i,
    roll: __m128i,
    low_nibble: __m128i,
    pairs: __m128i,
    quads: __m128i,
    extract: __m128i,
}

impl Lookup {
    #[inline]
    #[target_feature(enable = "ssse3")]
    fn new(nibbles: &Nibbles) -> Self {
        Lookup {
            low_mask: nibbles.low_mask.load(),
            high_mask: nibbles.high_mask.load(),
            low_value: nibbles.low_value.load(),
            roll: _mm_set1_epi8(nibbles.roll as i8),
            low_nibble: _mm_set1_epi8(LOW_NIBBLE),
            pairs: _mm_set1_epi16(MERGE_PAIRS),
            quads: _mm_set1_epi32(MERGE_QUADS),
            extract: EXTRACT.load(),
        }
    }

    #[inline]
    #[target_feature(enable = "ssse3")]
    fn decode(&self, chars: __m128i) -> Option<__m128i> {
        let low = _mm_and_si128(chars, self.low_nibble);
        let high = _mm_and_si128(_mm_srli_epi16::<4>(chars), self.low_nibble);
        let bad = _mm_and_si128(
            _mm_shuffle_epi8(self.low_mask, low),
            _mm_shuffle_epi8(self.high_mask, high),
        );
        if _mm_movemask_epi8(_mm_cmpeq_epi8(bad, _mm_setzero_si128())) != 0xffff {
            return None;
        }
        let values = _mm_min_epu8(
            _mm_shuffle_epi8(self.low_value, low),
            _mm_add_epi8(chars, self.roll),
        );
        let quads = _mm_madd_epi16(_mm_maddubs_epi16(values, self.pairs), self.quads);
        let words = _mm_or_si128(_mm_slli_epi64::<20>(quads), _mm_srli_epi64::<32>(quads));
        Some(_mm_shuffle_epi8(words, self.extract))
    }
}

impl Tables {
    #[target_feature(enable = "ssse3")]
    pub(super) fn encode_groups_ssse3(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let spread = Spread::new(self);
        let src_len = src.len();
        let dst_len = dst.len();
        let src = src.as_ptr();
        let dst = dst.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        // SAFETY: the loop guard keeps the unaligned 16-byte load within `src`
        // and the unaligned 16-byte store within `dst`.
        unsafe {
            while read + ENCODE_LOAD <= src_len && written + ENCODE_STEP_OUT <= dst_len {
                let bytes = _mm_loadu_si128(src.add(read).cast());
                _mm_storeu_si128(dst.add(written).cast(), spread.encode(bytes));
                read += ENCODE_STEP;
                written += ENCODE_STEP_OUT;
            }
        }
        (read, written)
    }

    #[target_feature(enable = "ssse3")]
    pub(super) fn decode_groups_ssse3(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let lookup = Lookup::new(&self.nibbles);
        let src_len = src.len();
        let dst_len = dst.len();
        let src = src.as_ptr();
        let dst = dst.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        // SAFETY: the loop guard keeps the unaligned 16-byte load within `src`
        // and the unaligned 16-byte store within `dst`.
        unsafe {
            while read + DECODE_STEP <= src_len && written + DECODE_STORE <= dst_len {
                let Some(bytes) = lookup.decode(_mm_loadu_si128(src.add(read).cast())) else {
                    break;
                };
                _mm_storeu_si128(dst.add(written).cast(), bytes);
                read += DECODE_STEP;
                written += DECODE_STEP_OUT;
            }
        }
        (read, written)
    }
}
