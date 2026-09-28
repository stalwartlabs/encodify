/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{
    super::{
        Wrap,
        alphabet::{Nibbles, Tables},
    },
    LineShape,
};
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use std::{array, hint::black_box, mem::MaybeUninit};

const PACK_LANE: [i8; 16] = [2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1];
const SPREAD_LANE: [i8; 16] = [1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10];
const SPREAD_AFTER_LEAD: [i8; 16] = [5, 4, 6, 5, 8, 7, 9, 8, 11, 10, 12, 11, 14, 13, 15, 14];
const LEAD: usize = 4;
const STORE_SLACK: usize = 4;
const DECODE_UNROLL: usize = 4;
const ENCODE_UNROLL: usize = 8;
const HIGH_INDEX_SHIFT: i32 = 3;
const HIGH_INDEX_MASK: i8 = 0x1e;
const MERGE_PAIRS: i32 = 0x0140_0140;
const MERGE_QUADS: i32 = 0x0001_1000;
const ALIGN_MUL: i32 = 0x0010_0001;
const ALIGN_SHIFT: i32 = 10;
const FIELD_MASK: i32 = 0x003f_03f0;
const FIELD_MUL: i32 = 0x0100_0010;

trait Lanes {
    fn lanes(&self) -> __m128i;
}

impl Lanes for [u8; 16] {
    #[inline(always)]
    fn lanes(&self) -> __m128i {
        // SAFETY: `self` is 16 readable bytes and the load is unaligned; SSE2 is
        // statically enabled wherever `encodify_x86` is set (build.rs).
        unsafe { _mm_loadu_si128(self.as_ptr().cast()) }
    }
}

impl Lanes for [i8; 16] {
    #[inline(always)]
    fn lanes(&self) -> __m128i {
        // SAFETY: `self` is 16 readable bytes and the load is unaligned; SSE2 is
        // statically enabled wherever `encodify_x86` is set (build.rs).
        unsafe { _mm_loadu_si128(self.as_ptr().cast()) }
    }
}

#[derive(Clone, Copy)]
struct Valid(u32);

impl Valid {
    #[inline(always)]
    fn stop(self, start: usize) -> (usize, usize) {
        let quads = start / 4 + (!self.0).trailing_zeros() as usize / 4;
        (quads * 4, quads * 3)
    }
}

#[derive(Clone, Copy)]
struct Ssse3Decoder {
    low: __m128i,
    high: __m128i,
    roll: __m128i,
    special: __m128i,
    pack: __m128i,
    high_index: __m128i,
    merge_pairs: __m128i,
    merge_quads: __m128i,
}

impl Ssse3Decoder {
    const BLOCK: usize = 16;
    const VALID: u32 = 0xffff;

    #[inline]
    #[target_feature(enable = "ssse3")]
    fn load(nibbles: &Nibbles) -> Self {
        Ssse3Decoder {
            low: _mm_xor_si128(nibbles.low.lanes(), _mm_set1_epi8(-1)),
            high: nibbles.high.lanes(),
            roll: nibbles.roll.lanes(),
            special: _mm_set1_epi8(nibbles.special as i8),
            pack: PACK_LANE.lanes(),
            high_index: _mm_set1_epi8(HIGH_INDEX_MASK),
            merge_pairs: _mm_set1_epi32(MERGE_PAIRS),
            merge_quads: _mm_set1_epi32(MERGE_QUADS),
        }
    }

    #[inline]
    #[target_feature(enable = "ssse3")]
    fn decode(self, chars: __m128i) -> (__m128i, __m128i) {
        let high = _mm_and_si128(_mm_srli_epi32::<HIGH_INDEX_SHIFT>(chars), self.high_index);
        let bad = _mm_andnot_si128(
            _mm_shuffle_epi8(self.low, chars),
            _mm_shuffle_epi8(self.high, high),
        );
        let special = _mm_cmpeq_epi8(chars, self.special);
        let sextets = _mm_add_epi8(
            chars,
            _mm_shuffle_epi8(self.roll, _mm_add_epi8(high, special)),
        );
        let merged = _mm_madd_epi16(
            _mm_maddubs_epi16(sextets, self.merge_pairs),
            self.merge_quads,
        );
        (_mm_shuffle_epi8(merged, self.pack), bad)
    }

    #[inline]
    #[target_feature(enable = "ssse3")]
    fn valid(bad: __m128i) -> Valid {
        Valid(_mm_movemask_epi8(_mm_cmpeq_epi8(bad, _mm_setzero_si128())) as u32)
    }

    /// Decodes the 16 characters at `src` into exactly 12 bytes at `dst`.
    ///
    /// # Safety
    ///
    /// The CPU must support SSSE3, `src` must be valid for reading 16 bytes and `dst` for
    /// writing 12 bytes.
    #[inline]
    #[target_feature(enable = "ssse3")]
    unsafe fn decode_exact(self, src: *const u8, dst: *mut u8) -> Valid {
        // SAFETY: callers pass `src` readable for 16 bytes and `dst` writable for
        // the 12 stored here (8 + 4, unaligned); SSSE3 is enabled on this fn.
        unsafe {
            let (bytes, bad) = self.decode(_mm_loadu_si128(src.cast()));
            _mm_storel_epi64(dst.cast(), bytes);
            dst.add(8)
                .cast::<i32>()
                .write_unaligned(_mm_cvtsi128_si32(_mm_srli_si128::<8>(bytes)));
            Self::valid(bad)
        }
    }

    /// Decodes the 16 characters at `src` with one 16-byte store at `dst`; returns bad lanes.
    ///
    /// # Safety
    ///
    /// The CPU must support SSSE3, `src` must be valid for reading 16 bytes and `dst` for
    /// writing 16 bytes (12 decoded plus `STORE_SLACK`).
    #[inline]
    #[target_feature(enable = "ssse3")]
    unsafe fn decode_wide(self, src: *const u8, dst: *mut u8) -> __m128i {
        // SAFETY: callers pass `src` readable for 16 bytes and `dst` writable for
        // 16 (12 decoded plus `STORE_SLACK`); SSSE3 is enabled on this fn.
        unsafe {
            let (bytes, bad) = self.decode(_mm_loadu_si128(src.cast()));
            _mm_storeu_si128(dst.cast(), bytes);
            bad
        }
    }

    /// Rescans `start..end` block by block and returns where decoding stops.
    ///
    /// # Safety
    ///
    /// The CPU must support SSSE3, `src` must be valid for reading `end` bytes, and
    /// `end - start` must be a multiple of 16.
    #[cold]
    #[inline(never)]
    #[target_feature(enable = "ssse3")]
    unsafe fn first_bad(self, src: *const u8, start: usize, end: usize) -> (usize, usize) {
        let mut at = start;
        while at < end {
            // SAFETY: callers pass `start..end` as whole 16-byte blocks inside the
            // readable input, so `at + 16 <= end`; SSSE3 is enabled on this fn.
            let (_, bad) = self.decode(unsafe { _mm_loadu_si128(src.add(at).cast()) });
            let valid = Self::valid(bad);
            if valid.0 != Self::VALID {
                return valid.stop(at);
            }
            at += Self::BLOCK;
        }
        (end, end / 4 * 3)
    }
}

#[derive(Clone, Copy)]
struct Avx2Decoder {
    low: __m256i,
    high: __m256i,
    roll: __m256i,
    special: __m256i,
    pack: __m256i,
    compact: __m256i,
    high_index: __m256i,
    merge_pairs: __m256i,
    merge_quads: __m256i,
}

impl Avx2Decoder {
    const BLOCK: usize = 32;
    const VALID: u32 = u32::MAX;

    #[inline]
    #[target_feature(enable = "avx2")]
    fn load(nibbles: &Nibbles) -> Self {
        Avx2Decoder {
            low: _mm256_broadcastsi128_si256(_mm_xor_si128(nibbles.low.lanes(), _mm_set1_epi8(-1))),
            high: _mm256_broadcastsi128_si256(nibbles.high.lanes()),
            roll: _mm256_broadcastsi128_si256(nibbles.roll.lanes()),
            special: _mm256_set1_epi8(nibbles.special as i8),
            pack: _mm256_broadcastsi128_si256(PACK_LANE.lanes()),
            compact: _mm256_setr_epi32(0, 1, 2, 4, 5, 6, 7, 7),
            high_index: _mm256_set1_epi8(HIGH_INDEX_MASK),
            merge_pairs: _mm256_set1_epi32(MERGE_PAIRS),
            merge_quads: _mm256_set1_epi32(MERGE_QUADS),
        }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn decode(self, chars: __m256i) -> (__m256i, __m256i) {
        let high = _mm256_and_si256(
            _mm256_srli_epi32::<HIGH_INDEX_SHIFT>(chars),
            self.high_index,
        );
        let bad = _mm256_andnot_si256(
            _mm256_shuffle_epi8(self.low, chars),
            _mm256_shuffle_epi8(self.high, high),
        );
        let special = _mm256_cmpeq_epi8(chars, self.special);
        let sextets = _mm256_add_epi8(
            chars,
            _mm256_shuffle_epi8(self.roll, _mm256_add_epi8(high, special)),
        );
        let merged = _mm256_madd_epi16(
            _mm256_maddubs_epi16(sextets, self.merge_pairs),
            self.merge_quads,
        );
        (_mm256_shuffle_epi8(merged, self.pack), bad)
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn valid(bad: __m256i) -> Valid {
        Valid(_mm256_movemask_epi8(_mm256_cmpeq_epi8(bad, _mm256_setzero_si256())) as u32)
    }

    /// Decodes the 32 characters at `src` into exactly 24 bytes at `dst`.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2, `src` must be valid for reading 32 bytes and `dst` for
    /// writing 24 bytes.
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn decode_exact(self, src: *const u8, dst: *mut u8) -> Valid {
        // SAFETY: callers pass `src` readable for 32 bytes and `dst` writable for
        // the 24 stored here (16 + 8, unaligned); AVX2 is enabled on this fn.
        unsafe {
            let (bytes, bad) = self.decode(_mm256_loadu_si256(src.cast()));
            let bytes = _mm256_permutevar8x32_epi32(bytes, self.compact);
            _mm_storeu_si128(dst.cast(), _mm256_castsi256_si128(bytes));
            _mm_storel_epi64(dst.add(16).cast(), _mm256_extracti128_si256::<1>(bytes));
            Self::valid(bad)
        }
    }

    /// Decodes the 32 characters at `src` with two overlapping stores at `dst`; returns bad lanes.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2, `src` must be valid for reading 32 bytes and `dst` for
    /// writing 28 bytes (24 decoded plus `STORE_SLACK`).
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn decode_wide(self, src: *const u8, dst: *mut u8) -> __m256i {
        // SAFETY: callers pass `src` readable for 32 bytes and `dst` writable for
        // 28 (24 decoded plus `STORE_SLACK`); AVX2 is enabled on this fn.
        unsafe {
            let (bytes, bad) = self.decode(_mm256_loadu_si256(src.cast()));
            _mm_storeu_si128(dst.cast(), _mm256_castsi256_si128(bytes));
            _mm_storeu_si128(dst.add(12).cast(), _mm256_extracti128_si256::<1>(bytes));
            bad
        }
    }

    /// Rescans `start..end` block by block and returns where decoding stops.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2, `src` must be valid for reading `end` bytes, and
    /// `end - start` must be a multiple of 32.
    #[cold]
    #[inline(never)]
    #[target_feature(enable = "avx2")]
    unsafe fn first_bad(self, src: *const u8, start: usize, end: usize) -> (usize, usize) {
        let mut at = start;
        while at < end {
            // SAFETY: callers pass `start..end` as whole 32-byte blocks inside the
            // readable input, so `at + 32 <= end`; AVX2 is enabled on this fn.
            let (_, bad) = self.decode(unsafe { _mm256_loadu_si256(src.add(at).cast()) });
            let valid = Self::valid(bad);
            if valid.0 != Self::VALID {
                return valid.stop(at);
            }
            at += Self::BLOCK;
        }
        (end, end / 4 * 3)
    }
}

#[derive(Clone, Copy)]
struct Ssse3Encoder {
    offsets: __m128i,
    spread: __m128i,
    align_mul: __m128i,
    field_mask: __m128i,
    field_mul: __m128i,
    fifty_one: __m128i,
    twenty_five: __m128i,
}

impl Ssse3Encoder {
    #[inline]
    #[target_feature(enable = "ssse3")]
    fn load(tables: &Tables, spread: &[i8; 16]) -> Self {
        Ssse3Encoder {
            offsets: tables.offsets.lanes(),
            spread: spread.lanes(),
            align_mul: black_box(_mm_set1_epi32(ALIGN_MUL)),
            field_mask: _mm_set1_epi32(FIELD_MASK),
            field_mul: black_box(_mm_set1_epi32(FIELD_MUL)),
            fifty_one: _mm_set1_epi8(51),
            twenty_five: _mm_set1_epi8(25),
        }
    }

    #[inline]
    fn with_spread(self, spread: &[i8; 16]) -> Self {
        Ssse3Encoder {
            spread: spread.lanes(),
            ..self
        }
    }

    #[inline]
    #[target_feature(enable = "ssse3")]
    fn encode(self, bytes: __m128i) -> __m128i {
        let lanes = _mm_shuffle_epi8(bytes, self.spread);
        let aligned = _mm_srli_epi16::<ALIGN_SHIFT>(_mm_mullo_epi16(lanes, self.align_mul));
        let fields = _mm_mullo_epi16(_mm_and_si128(lanes, self.field_mask), self.field_mul);
        let indices = _mm_or_si128(aligned, fields);
        let class = _mm_sub_epi8(
            _mm_subs_epu8(indices, self.fifty_one),
            _mm_cmpgt_epi8(indices, self.twenty_five),
        );
        _mm_add_epi8(indices, _mm_shuffle_epi8(self.offsets, class))
    }

    /// Loads the 12 bytes at `src` into the low lanes of a vector.
    ///
    /// # Safety
    ///
    /// The CPU must support SSSE3 and `src` must be valid for reading 12 bytes.
    #[inline]
    #[target_feature(enable = "ssse3")]
    unsafe fn load12(src: *const u8) -> __m128i {
        // SAFETY: callers pass `src` readable for 12 bytes, exactly what the 8-byte
        // and 4-byte unaligned loads cover; SSSE3 is enabled on this fn.
        unsafe {
            let low = _mm_loadl_epi64(src.cast());
            let high = _mm_cvtsi32_si128(src.add(8).cast::<i32>().read_unaligned());
            _mm_unpacklo_epi64(low, high)
        }
    }
}

#[derive(Clone, Copy)]
struct Avx2Encoder {
    offsets: __m256i,
    spread: __m256i,
    align_mul: __m256i,
    field_mask: __m256i,
    field_mul: __m256i,
    fifty_one: __m256i,
    twenty_five: __m256i,
}

impl Avx2Encoder {
    #[inline]
    #[target_feature(enable = "avx2")]
    fn load(tables: &Tables, first: &[i8; 16], second: &[i8; 16]) -> Self {
        Avx2Encoder {
            offsets: _mm256_broadcastsi128_si256(tables.offsets.lanes()),
            spread: _mm256_setr_m128i(first.lanes(), second.lanes()),
            align_mul: black_box(_mm256_set1_epi32(ALIGN_MUL)),
            field_mask: _mm256_set1_epi32(FIELD_MASK),
            field_mul: black_box(_mm256_set1_epi32(FIELD_MUL)),
            fifty_one: _mm256_set1_epi8(51),
            twenty_five: _mm256_set1_epi8(25),
        }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn with_spread(self, first: &[i8; 16], second: &[i8; 16]) -> Self {
        Avx2Encoder {
            spread: _mm256_setr_m128i(first.lanes(), second.lanes()),
            ..self
        }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    fn encode(self, bytes: __m256i) -> __m256i {
        let lanes = _mm256_shuffle_epi8(bytes, self.spread);
        let aligned = _mm256_srli_epi16::<ALIGN_SHIFT>(_mm256_mullo_epi16(lanes, self.align_mul));
        let fields = _mm256_mullo_epi16(_mm256_and_si256(lanes, self.field_mask), self.field_mul);
        let indices = _mm256_or_si256(aligned, fields);
        let class = _mm256_sub_epi8(
            _mm256_subs_epu8(indices, self.fifty_one),
            _mm256_cmpgt_epi8(indices, self.twenty_five),
        );
        _mm256_add_epi8(indices, _mm256_shuffle_epi8(self.offsets, class))
    }

    /// Loads 16 bytes at `src` into the low lane and 16 bytes at `src + second` into the high one.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2 and `src` must be valid for reading `second + 16` bytes.
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn load_pair(src: *const u8, second: usize) -> __m256i {
        // SAFETY: callers pass `src` readable for `second + 16` bytes, covering both
        // unaligned 16-byte loads; AVX2 is enabled on this fn.
        unsafe {
            _mm256_inserti128_si256::<1>(
                _mm256_castsi128_si256(_mm_loadu_si128(src.cast())),
                _mm_loadu_si128(src.add(second).cast()),
            )
        }
    }
}

impl Nibbles {
    /// Decodes whole quads of `src` into `dst` up to the first invalid one; `None` below one block.
    ///
    /// # Safety
    ///
    /// The caller must have verified at runtime that the CPU supports SSSE3.
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn decode_quads_ssse3(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> Option<(usize, usize)> {
        const BLOCK: usize = Ssse3Decoder::BLOCK;
        const GROUP: usize = DECODE_UNROLL * BLOCK;
        let chars = (src.len() / 4).min(dst.len() / 3) * 4;
        if chars < BLOCK {
            return None;
        }
        let dst_len = dst.len();
        let src = src.as_ptr();
        let dst = dst.as_mut_ptr().cast::<u8>();
        // SAFETY: `chars <= src.len()` and `chars / 4 * 3 <= dst_len`; the group loop
        // also reserves `STORE_SLACK` for `decode_wide`, and `chars >= BLOCK` keeps the
        // final overlapping block in bounds. SSSE3 is enabled on this fn.
        unsafe {
            let decoder = Ssse3Decoder::load(self);
            let mut read = 0;
            while read + GROUP <= chars && (read + GROUP) / 4 * 3 + STORE_SLACK <= dst_len {
                let mut bad = _mm_setzero_si128();
                for block in 0..DECODE_UNROLL {
                    let at = read + block * BLOCK;
                    bad = _mm_or_si128(bad, decoder.decode_wide(src.add(at), dst.add(at / 4 * 3)));
                }
                if Ssse3Decoder::valid(bad).0 != Ssse3Decoder::VALID {
                    return Some(decoder.first_bad(src, read, read + GROUP));
                }
                read += GROUP;
            }
            while read + BLOCK <= chars {
                let valid = decoder.decode_exact(src.add(read), dst.add(read / 4 * 3));
                if valid.0 != Ssse3Decoder::VALID {
                    return Some(valid.stop(read));
                }
                read += BLOCK;
            }
            if read < chars {
                let last = chars - BLOCK;
                let valid = decoder.decode_exact(src.add(last), dst.add(last / 4 * 3));
                if valid.0 != Ssse3Decoder::VALID {
                    return Some(valid.stop(last));
                }
            }
        }
        Some((chars, chars / 4 * 3))
    }

    /// Decodes whole quads of `src` into `dst` up to the first invalid one; `None` below one block.
    ///
    /// # Safety
    ///
    /// The caller must have verified at runtime that the CPU supports AVX2.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn decode_quads_avx2(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> Option<(usize, usize)> {
        const BLOCK: usize = Avx2Decoder::BLOCK;
        const GROUP: usize = DECODE_UNROLL * BLOCK;
        let chars = (src.len() / 4).min(dst.len() / 3) * 4;
        if chars < BLOCK {
            // SAFETY: the `avx2` feature enabled on this fn implies SSSE3.
            return unsafe { self.decode_quads_ssse3(src, dst) };
        }
        let dst_len = dst.len();
        let src = src.as_ptr();
        let dst = dst.as_mut_ptr().cast::<u8>();
        // SAFETY: `chars <= src.len()` and `chars / 4 * 3 <= dst_len`; the group loop
        // also reserves `STORE_SLACK` for `decode_wide`, and `chars >= BLOCK` keeps the
        // final overlapping block in bounds. AVX2 is enabled on this fn.
        unsafe {
            let decoder = Avx2Decoder::load(self);
            let mut read = 0;
            while read + GROUP <= chars && (read + GROUP) / 4 * 3 + STORE_SLACK <= dst_len {
                let mut bad = _mm256_setzero_si256();
                for block in 0..DECODE_UNROLL {
                    let at = read + block * BLOCK;
                    bad =
                        _mm256_or_si256(bad, decoder.decode_wide(src.add(at), dst.add(at / 4 * 3)));
                }
                if _mm256_testz_si256(bad, bad) == 0 {
                    return Some(decoder.first_bad(src, read, read + GROUP));
                }
                read += GROUP;
            }
            while read + BLOCK <= chars {
                let valid = decoder.decode_exact(src.add(read), dst.add(read / 4 * 3));
                if valid.0 != Avx2Decoder::VALID {
                    return Some(valid.stop(read));
                }
                read += BLOCK;
            }
            if read < chars {
                let last = chars - BLOCK;
                let valid = decoder.decode_exact(src.add(last), dst.add(last / 4 * 3));
                if valid.0 != Avx2Decoder::VALID {
                    return Some(valid.stop(last));
                }
            }
        }
        Some((chars, chars / 4 * 3))
    }

    /// Decodes whole lines of `shape` from `src` into `dst` until one does not match or decode.
    ///
    /// # Safety
    ///
    /// The caller must have verified at runtime that the CPU supports AVX2.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn decode_lines_avx2(
        &self,
        shape: LineShape,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        const BLOCK: usize = Avx2Decoder::BLOCK;
        if shape.len < BLOCK || !shape.len.is_multiple_of(4) {
            return (0, 0);
        }
        let stride = shape.stride();
        let line_out = shape.len / 4 * 3;
        let last = shape.len - BLOCK;
        let src_len = src.len();
        let dst_len = dst.len();
        let src_ptr = src.as_ptr();
        let dst_ptr = dst.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        // SAFETY: each line is checked for `stride` readable bytes (so `is_at` and the
        // blocks up to `shape.len` stay in bounds) and `line_out + STORE_SLACK` writable
        // bytes, which the last `decode_wide` ends exactly on. AVX2 is enabled on this fn.
        unsafe {
            let decoder = Avx2Decoder::load(self);
            while read + stride <= src_len
                && written + line_out + STORE_SLACK <= dst_len
                && shape.ending.is_at(src_ptr.add(read + shape.len))
            {
                let line = src_ptr.add(read);
                let out = dst_ptr.add(written);
                let mut bad = _mm256_setzero_si256();
                let mut at = 0;
                while at < last {
                    bad = _mm256_or_si256(
                        bad,
                        decoder.decode_wide(line.add(at), out.add(at / 4 * 3)),
                    );
                    at += BLOCK;
                }
                bad = _mm256_or_si256(
                    bad,
                    decoder.decode_wide(line.add(last), out.add(last / 4 * 3)),
                );
                if _mm256_testz_si256(bad, bad) == 0 {
                    break;
                }
                read += stride;
                written += line_out;
            }
        }
        (read, written)
    }

    /// Decodes whole lines of `shape` from `src` into `dst` until one does not match or decode.
    ///
    /// # Safety
    ///
    /// The caller must have verified at runtime that the CPU supports SSSE3.
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn decode_lines_ssse3(
        &self,
        shape: LineShape,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        const BLOCK: usize = Ssse3Decoder::BLOCK;
        if shape.len < BLOCK || !shape.len.is_multiple_of(4) {
            return (0, 0);
        }
        let stride = shape.stride();
        let line_out = shape.len / 4 * 3;
        let last = shape.len - BLOCK;
        let src_len = src.len();
        let dst_len = dst.len();
        let src_ptr = src.as_ptr();
        let dst_ptr = dst.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        // SAFETY: each line is checked for `stride` readable bytes (so `is_at` and the
        // blocks up to `shape.len` stay in bounds) and `line_out + STORE_SLACK` writable
        // bytes, which the last `decode_wide` ends exactly on. SSSE3 is enabled on this fn.
        unsafe {
            let decoder = Ssse3Decoder::load(self);
            while read + stride <= src_len
                && written + line_out + STORE_SLACK <= dst_len
                && shape.ending.is_at(src_ptr.add(read + shape.len))
            {
                let line = src_ptr.add(read);
                let out = dst_ptr.add(written);
                let mut bad = _mm_setzero_si128();
                let mut at = 0;
                while at < last {
                    bad = _mm_or_si128(bad, decoder.decode_wide(line.add(at), out.add(at / 4 * 3)));
                    at += BLOCK;
                }
                bad = _mm_or_si128(
                    bad,
                    decoder.decode_wide(line.add(last), out.add(last / 4 * 3)),
                );
                if Ssse3Decoder::valid(bad).0 != Ssse3Decoder::VALID {
                    break;
                }
                read += stride;
                written += line_out;
            }
        }
        (read, written)
    }
}

impl Tables {
    /// Encodes the whole 3-byte groups of `src` that fit in `dst`, returning `(read, written)`.
    ///
    /// # Safety
    ///
    /// The caller must have verified at runtime that the CPU supports SSSE3.
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn encode_groups_ssse3(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        const BLOCK: usize = 12;
        const UNROLL: usize = 4;
        let groups = (src.len() / 3).min(dst.len() / 4);
        let bytes = groups * 3;
        if bytes < BLOCK {
            return (0, 0);
        }
        let src = src.as_ptr();
        let dst = dst.as_mut_ptr().cast::<u8>();
        // SAFETY: `bytes <= src.len()` and `bytes / 3 * 4 <= dst.len()`; every load ends
        // by `read + BLOCK <= bytes` (reading from `read - LEAD` only once `read >= BLOCK`),
        // every store by `(read + BLOCK) / 3 * 4`, and `bytes >= BLOCK`. SSSE3 is enabled.
        unsafe {
            let exact = Ssse3Encoder::load(self, &SPREAD_LANE);
            let steady = exact.with_spread(&SPREAD_AFTER_LEAD);
            _mm_storeu_si128(dst.cast(), exact.encode(Ssse3Encoder::load12(src)));
            let mut read = BLOCK;
            while read + UNROLL * BLOCK <= bytes {
                let chunks: [__m128i; UNROLL] = array::from_fn(|block| {
                    _mm_loadu_si128(src.add(read + block * BLOCK - LEAD).cast())
                });
                for (block, chunk) in chunks.into_iter().enumerate() {
                    let out = dst.add((read + block * BLOCK) / 3 * 4);
                    _mm_storeu_si128(out.cast(), steady.encode(chunk));
                }
                read += UNROLL * BLOCK;
            }
            while read + BLOCK <= bytes {
                let chunk = _mm_loadu_si128(src.add(read - LEAD).cast());
                _mm_storeu_si128(dst.add(read / 3 * 4).cast(), steady.encode(chunk));
                read += BLOCK;
            }
            if read < bytes {
                let last = bytes - BLOCK;
                let chars = exact.encode(Ssse3Encoder::load12(src.add(last)));
                _mm_storeu_si128(dst.add(last / 3 * 4).cast(), chars);
            }
        }
        (bytes, groups * 4)
    }

    /// Encodes the whole 3-byte groups of `src` that fit in `dst`, returning `(read, written)`.
    ///
    /// # Safety
    ///
    /// The caller must have verified at runtime that the CPU supports AVX2.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn encode_groups_avx2(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        const ROUND: usize = 24;
        const LOAD: usize = 32;
        let groups = (src.len() / 3).min(dst.len() / 4);
        let bytes = groups * 3;
        if bytes < ROUND {
            // SAFETY: the `avx2` feature enabled on this fn implies SSSE3.
            return unsafe { self.encode_groups_ssse3(src, dst) };
        }
        let src = src.as_ptr();
        let dst = dst.as_mut_ptr().cast::<u8>();
        // SAFETY: `bytes <= src.len()` and `bytes / 3 * 4 <= dst.len()`; the steady loops
        // check `read + ROUND + LEAD <= bytes` for their 32-byte loads from `read - LEAD`,
        // and the tail clamps `at <= bytes - ROUND`. AVX2 is enabled on this fn.
        unsafe {
            let tail = Avx2Encoder::load(self, &SPREAD_LANE, &SPREAD_AFTER_LEAD);
            let mut read = 0;
            if bytes >= LOAD {
                let steady = tail.with_spread(&SPREAD_AFTER_LEAD, &SPREAD_LANE);
                let first = _mm256_permutevar8x32_epi32(
                    _mm256_loadu_si256(src.cast()),
                    _mm256_setr_epi32(0, 0, 1, 2, 3, 4, 5, 6),
                );
                _mm256_storeu_si256(dst.cast(), steady.encode(first));
                read = ROUND;
                while read + ENCODE_UNROLL * ROUND + LEAD <= bytes {
                    let chunks: [__m256i; ENCODE_UNROLL] = array::from_fn(|round| {
                        _mm256_loadu_si256(src.add(read + round * ROUND - LEAD).cast())
                    });
                    for (round, chunk) in chunks.into_iter().enumerate() {
                        let out = dst.add((read + round * ROUND) / 3 * 4);
                        _mm256_storeu_si256(out.cast(), steady.encode(chunk));
                    }
                    read += ENCODE_UNROLL * ROUND;
                }
                while read + ROUND + LEAD <= bytes {
                    let chunk = _mm256_loadu_si256(src.add(read - LEAD).cast());
                    _mm256_storeu_si256(dst.add(read / 3 * 4).cast(), steady.encode(chunk));
                    read += ROUND;
                }
            }
            while read < bytes {
                let at = read.min(bytes - ROUND);
                let chars = tail.encode(Avx2Encoder::load_pair(src.add(at), ROUND / 2 - LEAD));
                _mm256_storeu_si256(dst.add(at / 3 * 4).cast(), chars);
                read = at + ROUND;
            }
        }
        (bytes, groups * 4)
    }

    /// Encodes whole lines of `wrap` from `src` into `dst`, each followed by its ending.
    ///
    /// # Safety
    ///
    /// The caller must have verified at runtime that the CPU supports AVX2, and `wrap.width` must
    /// be a multiple of 4.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn encode_lines_avx2(
        &self,
        wrap: Wrap,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        const LOAD: usize = 28;
        const BLOCK: usize = 24;
        let line_in = wrap.line_in();
        if line_in < BLOCK {
            return (0, 0);
        }
        let line_out = wrap.line_out();
        let last = line_in - BLOCK;
        let src_len = src.len();
        let dst_len = dst.len();
        let src_ptr = src.as_ptr();
        let dst_ptr = dst.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        // SAFETY: each line checks `last + LOAD` readable bytes (the last `load_pair` ends
        // there) and `line_out` writable ones; the last store ends at `width` (a multiple
        // of 4), where `write_at` fills the ending. AVX2 is enabled on this fn.
        unsafe {
            let encoder = Avx2Encoder::load(self, &SPREAD_LANE, &SPREAD_LANE);
            let block = |at: *const u8, out: *mut u8| {
                let chars = encoder.encode(Avx2Encoder::load_pair(at, BLOCK / 2));
                _mm256_storeu_si256(out.cast(), chars);
            };
            while read + last + LOAD <= src_len && written + line_out <= dst_len {
                let line = src_ptr.add(read);
                let out = dst_ptr.add(written);
                let mut at = 0;
                while at < last {
                    block(line.add(at), out.add(at / 3 * 4));
                    at += BLOCK;
                }
                block(line.add(last), out.add(last / 3 * 4));
                wrap.ending.write_at(out.add(wrap.width));
                read += line_in;
                written += line_out;
            }
        }
        (read, written)
    }

    /// Encodes whole lines of `wrap` from `src` into `dst`, each followed by its ending.
    ///
    /// # Safety
    ///
    /// The caller must have verified at runtime that the CPU supports SSSE3, and `wrap.width` must
    /// be a multiple of 4.
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn encode_lines_ssse3(
        &self,
        wrap: Wrap,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        const LOAD: usize = 16;
        const BLOCK: usize = 12;
        let line_in = wrap.line_in();
        if line_in < BLOCK {
            return (0, 0);
        }
        let line_out = wrap.line_out();
        let last = line_in - BLOCK;
        let src_len = src.len();
        let dst_len = dst.len();
        let src_ptr = src.as_ptr();
        let dst_ptr = dst.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        // SAFETY: each line checks `last + LOAD` readable bytes (the last 16-byte load ends
        // there) and `line_out` writable ones; the last store ends at `width` (a multiple
        // of 4), where `write_at` fills the ending. SSSE3 is enabled on this fn.
        unsafe {
            let encoder = Ssse3Encoder::load(self, &SPREAD_LANE);
            let block = |at: *const u8, out: *mut u8| {
                _mm_storeu_si128(out.cast(), encoder.encode(_mm_loadu_si128(at.cast())));
            };
            while read + last + LOAD <= src_len && written + line_out <= dst_len {
                let line = src_ptr.add(read);
                let out = dst_ptr.add(written);
                let mut at = 0;
                while at < last {
                    block(line.add(at), out.add(at / 3 * 4));
                    at += BLOCK;
                }
                block(line.add(last), out.add(last / 3 * 4));
                wrap.ending.write_at(out.add(wrap.width));
                read += line_in;
                written += line_out;
            }
        }
        (read, written)
    }
}
