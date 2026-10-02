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
const ENCODE_GROUP: usize = 10;
const ENCODE_STEP_WIDE: usize = 20;
const ENCODE_STEP_OUT_WIDE: usize = 32;
const ENCODE_LOAD_WIDE: usize = 26;
const DECODE_STEP_WIDE: usize = 32;
const DECODE_STEP_OUT_WIDE: usize = 20;
const DECODE_STORE_WIDE: usize = 26;
const DECODE_GROUP_OUT: usize = 10;

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

#[inline]
#[target_feature(enable = "avx2")]
fn broadcast(table: &impl Load) -> __m256i {
    _mm256_broadcastsi128_si256(table.load())
}

struct SpreadWide {
    first: __m256i,
    second: __m256i,
    multipliers: __m256i,
    offsets: __m256i,
    letters: __m256i,
}

impl SpreadWide {
    #[inline]
    #[target_feature(enable = "avx2")]
    fn new(tables: &Tables) -> Self {
        SpreadWide {
            first: broadcast(&GATHER_FIRST),
            second: broadcast(&GATHER_SECOND),
            multipliers: broadcast(&SHIFT_MULTIPLIERS),
            offsets: broadcast(&tables.offsets),
            letters: _mm256_set1_epi8(LAST_LETTER),
        }
    }

    /// The 32 symbols of the two 10-byte groups held one per 128-bit lane.
    ///
    /// Every step is per-lane, including `_mm256_packus_epi16`, so each lane
    /// yields the 16 symbols of its own group and the two land in order.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn encode(&self, bytes: __m256i) -> __m256i {
        let first = _mm256_srli_epi16::<SYMBOL_SHIFT>(_mm256_mullo_epi16(
            _mm256_shuffle_epi8(bytes, self.first),
            self.multipliers,
        ));
        let second = _mm256_srli_epi16::<SYMBOL_SHIFT>(_mm256_mullo_epi16(
            _mm256_shuffle_epi8(bytes, self.second),
            self.multipliers,
        ));
        let values = _mm256_packus_epi16(first, second);
        _mm256_add_epi8(
            values,
            _mm256_shuffle_epi8(self.offsets, _mm256_subs_epu8(values, self.letters)),
        )
    }
}

struct LookupWide {
    low_mask: __m256i,
    high_mask: __m256i,
    low_value: __m256i,
    roll: __m256i,
    low_nibble: __m256i,
    pairs: __m256i,
    quads: __m256i,
    extract: __m256i,
}

impl LookupWide {
    #[inline]
    #[target_feature(enable = "avx2")]
    fn new(nibbles: &Nibbles) -> Self {
        LookupWide {
            low_mask: broadcast(&nibbles.low_mask),
            high_mask: broadcast(&nibbles.high_mask),
            low_value: broadcast(&nibbles.low_value),
            roll: _mm256_set1_epi8(nibbles.roll as i8),
            low_nibble: _mm256_set1_epi8(LOW_NIBBLE),
            pairs: _mm256_set1_epi16(MERGE_PAIRS),
            quads: _mm256_set1_epi32(MERGE_QUADS),
            extract: broadcast(&EXTRACT),
        }
    }

    /// The 20 bytes of the two 16-symbol groups, each in the low 10 bytes of
    /// its own 128-bit lane, or `None` when any symbol is not in the alphabet.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn decode(&self, chars: __m256i) -> Option<__m256i> {
        let low = _mm256_and_si256(chars, self.low_nibble);
        let high = _mm256_and_si256(_mm256_srli_epi16::<4>(chars), self.low_nibble);
        let bad = _mm256_and_si256(
            _mm256_shuffle_epi8(self.low_mask, low),
            _mm256_shuffle_epi8(self.high_mask, high),
        );
        if _mm256_movemask_epi8(_mm256_cmpeq_epi8(bad, _mm256_setzero_si256())) as u32 != u32::MAX {
            return None;
        }
        let values = _mm256_min_epu8(
            _mm256_shuffle_epi8(self.low_value, low),
            _mm256_add_epi8(chars, self.roll),
        );
        let quads = _mm256_madd_epi16(_mm256_maddubs_epi16(values, self.pairs), self.quads);
        let words = _mm256_or_si256(
            _mm256_slli_epi64::<20>(quads),
            _mm256_srli_epi64::<32>(quads),
        );
        Some(_mm256_shuffle_epi8(words, self.extract))
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

    #[target_feature(enable = "avx2")]
    pub(super) fn encode_groups_avx2(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let spread = SpreadWide::new(self);
        let src_len = src.len();
        let dst_len = dst.len();
        let src_ptr = src.as_ptr();
        let dst_ptr = dst.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        // SAFETY: the loop guard keeps both unaligned 16-byte loads within
        // `src`, the second starting `ENCODE_GROUP` bytes into the step and so
        // ending at `read + ENCODE_LOAD_WIDE`, and keeps the unaligned 32-byte
        // store within `dst`.
        unsafe {
            while read + ENCODE_LOAD_WIDE <= src_len && written + ENCODE_STEP_OUT_WIDE <= dst_len {
                let bytes = _mm256_inserti128_si256::<1>(
                    _mm256_castsi128_si256(_mm_loadu_si128(src_ptr.add(read).cast())),
                    _mm_loadu_si128(src_ptr.add(read + ENCODE_GROUP).cast()),
                );
                _mm256_storeu_si256(dst_ptr.add(written).cast(), spread.encode(bytes));
                read += ENCODE_STEP_WIDE;
                written += ENCODE_STEP_OUT_WIDE;
            }
        }
        let (more_read, more_written) = self.encode_groups_ssse3(
            src.get(read..).unwrap_or_default(),
            dst.get_mut(written..).unwrap_or_default(),
        );
        (read + more_read, written + more_written)
    }

    #[target_feature(enable = "avx2")]
    pub(super) fn decode_groups_avx2(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let lookup = LookupWide::new(&self.nibbles);
        let src_len = src.len();
        let dst_len = dst.len();
        let src_ptr = src.as_ptr();
        let dst_ptr = dst.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        // SAFETY: the loop guard keeps the unaligned 32-byte load within `src`.
        // Each lane holds its 10 bytes in its low half, so the two unaligned
        // 16-byte stores place them at `written` and `written + DECODE_GROUP_OUT`
        // and the second ends at `written + DECODE_STORE_WIDE`, which the guard
        // keeps within `dst`; the 6 bytes they write past the 20 decoded ones are
        // uninitialised scratch that the return value excludes.
        unsafe {
            while read + DECODE_STEP_WIDE <= src_len && written + DECODE_STORE_WIDE <= dst_len {
                let Some(bytes) = lookup.decode(_mm256_loadu_si256(src_ptr.add(read).cast()))
                else {
                    break;
                };
                _mm_storeu_si128(dst_ptr.add(written).cast(), _mm256_castsi256_si128(bytes));
                _mm_storeu_si128(
                    dst_ptr.add(written + DECODE_GROUP_OUT).cast(),
                    _mm256_extracti128_si256::<1>(bytes),
                );
                read += DECODE_STEP_WIDE;
                written += DECODE_STEP_OUT_WIDE;
            }
        }
        let (more_read, more_written) = self.decode_groups_ssse3(
            src.get(read..).unwrap_or_default(),
            dst.get_mut(written..).unwrap_or_default(),
        );
        (read + more_read, written + more_written)
    }
}
