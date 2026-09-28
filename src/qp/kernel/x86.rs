/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{
    super::tables::WordClass, Job, Kernel, LineMasks, PLAIN_PROLOGUE, TEXT_PROLOGUE, scalar::Swar,
};
use crate::hex::{BLOCK_ROOM, EscapeTable, SPARSE_ESCAPES, SPARSE_LEN};
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use std::mem::MaybeUninit;

const NARROW: usize = 16;
const WIDE: usize = 32;
const GRANULE: usize = 64;

pub(crate) struct Sse2;

impl Sse2 {
    /// Bitmask of the lanes of `chunk` holding `=`, `\r` or `\n`.
    ///
    /// # Safety
    ///
    /// The CPU must support SSE2, which the `encodify_x86` cfg guarantees; nothing else applies.
    #[inline(always)]
    unsafe fn text_stops(chunk: __m128i) -> u32 {
        // SAFETY: SSE2 is statically enabled under `encodify_x86`, and these intrinsics
        // only touch registers.
        unsafe {
            let stops = _mm_or_si128(
                _mm_or_si128(
                    _mm_cmpeq_epi8(chunk, _mm_set1_epi8(b'=' as i8)),
                    _mm_cmpeq_epi8(chunk, _mm_set1_epi8(b'\r' as i8)),
                ),
                _mm_cmpeq_epi8(chunk, _mm_set1_epi8(b'\n' as i8)),
            );
            _mm_movemask_epi8(stops) as u32
        }
    }

    /// Bitmask of the lanes of `chunk` that stop a plain copy: controls other than tab,
    /// `=`, DEL and bytes of 0x80 or above.
    ///
    /// # Safety
    ///
    /// The CPU must support SSE2, which the `encodify_x86` cfg guarantees; nothing else applies.
    #[inline(always)]
    unsafe fn plain_stops(chunk: __m128i) -> u32 {
        // SAFETY: SSE2 is statically enabled under `encodify_x86`, and these intrinsics
        // only touch registers.
        unsafe {
            let printable = _mm_andnot_si128(
                _mm_or_si128(
                    _mm_cmpeq_epi8(chunk, _mm_set1_epi8(0x7f)),
                    _mm_cmpeq_epi8(chunk, _mm_set1_epi8(b'=' as i8)),
                ),
                _mm_cmpgt_epi8(chunk, _mm_set1_epi8(0x1f)),
            );
            let plain = _mm_or_si128(printable, _mm_cmpeq_epi8(chunk, _mm_set1_epi8(b'\t' as i8)));
            !(_mm_movemask_epi8(plain) as u32) & 0xffff
        }
    }

    #[inline(always)]
    fn copy_text_from(src: &[u8], dst: &mut [MaybeUninit<u8>], mut done: usize) -> usize {
        let len = src.len().min(dst.len());
        while done + NARROW <= len {
            // SAFETY: the loop guard keeps `done + NARROW <= len`, and `len` bounds both
            // slices, so the 16-byte load and store stay in bounds; SSE2 is static.
            let hits = unsafe {
                let chunk = _mm_loadu_si128(src.as_ptr().add(done).cast());
                _mm_storeu_si128(dst.as_mut_ptr().add(done).cast(), chunk);
                Self::text_stops(chunk)
            };
            if hits != 0 {
                return done + hits.trailing_zeros() as usize;
            }
            done += NARROW;
        }
        done + Swar::copy_text(
            src.get(done..).unwrap_or_default(),
            dst.get_mut(done..).unwrap_or_default(),
        )
    }

    #[inline(always)]
    fn copy_plain_from(
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        limit: usize,
        mut done: usize,
    ) -> usize {
        while done < limit && done + NARROW <= src.len() && done + NARROW <= dst.len() {
            // SAFETY: the loop guard checks `done + NARROW` against both `src.len()` and
            // `dst.len()`, so the 16-byte load and store stay in bounds; SSE2 is static.
            let hits = unsafe {
                let chunk = _mm_loadu_si128(src.as_ptr().add(done).cast());
                _mm_storeu_si128(dst.as_mut_ptr().add(done).cast(), chunk);
                Self::plain_stops(chunk)
            };
            if hits != 0 {
                return (done + hits.trailing_zeros() as usize).min(limit);
            }
            done += NARROW;
        }
        if done >= limit {
            return limit;
        }
        done + Swar::copy_plain(
            src.get(done..).unwrap_or_default(),
            dst.get_mut(done..).unwrap_or_default(),
            limit - done,
        )
    }

    /// Bitmask of the lanes of `chunk` holding `\r` or `\n`.
    ///
    /// # Safety
    ///
    /// The CPU must support SSE2, which the `encodify_x86` cfg guarantees; nothing else applies.
    #[inline(always)]
    unsafe fn breaks(chunk: __m128i) -> u32 {
        // SAFETY: SSE2 is statically enabled under `encodify_x86`, and these intrinsics
        // only touch registers.
        unsafe {
            _mm_movemask_epi8(_mm_or_si128(
                _mm_cmpeq_epi8(chunk, _mm_set1_epi8(b'\r' as i8)),
                _mm_cmpeq_epi8(chunk, _mm_set1_epi8(b'\n' as i8)),
            )) as u32
        }
    }

    /// Counts of the bytes of `chunk` with the high bit set, one per 64-bit lane.
    ///
    /// # Safety
    ///
    /// The CPU must support SSE2, which the `encodify_x86` cfg guarantees; nothing else applies.
    #[inline(always)]
    unsafe fn high_lanes(chunk: __m128i) -> __m128i {
        // SAFETY: SSE2 is statically enabled under `encodify_x86`, and these intrinsics
        // only touch registers.
        unsafe {
            _mm_sad_epu8(
                _mm_and_si128(_mm_srli_epi16::<7>(chunk), _mm_set1_epi8(1)),
                _mm_setzero_si128(),
            )
        }
    }

    /// Sum of the two 64-bit lanes of `lanes`.
    ///
    /// # Safety
    ///
    /// The CPU must support SSE2, which the `encodify_x86` cfg guarantees; nothing else applies.
    #[inline(always)]
    unsafe fn lane_sum(lanes: __m128i) -> usize {
        let mut sums = [0u64; 2];
        // SAFETY: `sums` is `[u64; 2]`, exactly the 16 bytes stored; SSE2 is static.
        unsafe { _mm_storeu_si128(sums.as_mut_ptr().cast(), lanes) };
        sums.iter().map(|&sum| sum as usize).sum()
    }
}

impl Kernel for Sse2 {
    const GRANULE: usize = GRANULE;
    const LANE_BITS: u32 = 1;
    const LANE_FLAGS: u64 = u64::MAX;

    #[inline(always)]
    fn copy_text(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        if let Some(count) = Swar::probe_text(src, dst) {
            return count;
        }
        match Swar::copy_text_words::<TEXT_PROLOGUE>(src, dst) {
            Ok(count) => count,
            Err(done) => Self::copy_text_from(src, dst, done),
        }
    }

    #[inline(always)]
    fn decode_escapes(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> (usize, usize) {
        Swar::decode_escapes(src, dst)
    }

    #[inline(always)]
    fn copy_plain(src: &[u8], dst: &mut [MaybeUninit<u8>], max: usize) -> usize {
        let limit = src.len().min(max);
        if let Some(count) = Swar::probe_plain(src, dst, limit) {
            return count;
        }
        match Swar::copy_plain_words::<PLAIN_PROLOGUE>(src, dst, limit) {
            Ok(count) => count,
            Err(done) => Self::copy_plain_from(src, dst, limit, done),
        }
    }

    #[inline(always)]
    fn encode_escapes<const BINARY: bool>(
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        max: usize,
    ) -> usize {
        Swar::encode_escapes::<BINARY>(src, dst, max)
    }

    #[inline(always)]
    fn line_masks<const BINARY: bool>(block: &[u8]) -> LineMasks {
        let Some(block) = block.first_chunk::<GRANULE>() else {
            return LineMasks::default();
        };
        // SAFETY: `block` is a `&[u8; GRANULE]`, so the four 16-byte loads at
        // `index * NARROW` cover exactly its 64 bytes; SSE2 is static.
        unsafe {
            let chunks = [0, 1, 2, 3]
                .map(|index| _mm_loadu_si128(block.as_ptr().add(index * NARROW).cast()));
            let combine = |masks: [u32; 4]| {
                masks
                    .iter()
                    .rev()
                    .fold(0u64, |bits, &mask| (bits << NARROW) | u64::from(mask))
            };
            let stops = combine(chunks.map(|chunk| Self::plain_stops(chunk)));
            let escapes = match BINARY {
                true => stops,
                false if stops == 0 => 0,
                false => stops & !combine(chunks.map(|chunk| Self::breaks(chunk))),
            };
            LineMasks { stops, escapes }
        }
    }

    #[inline(always)]
    fn scan_lines<const BINARY: bool>(
        input: &[u8],
        visit: impl FnMut(usize, LineMasks) -> bool,
    ) -> Option<usize> {
        LineMasks::scan::<GRANULE>(input, |block| Self::line_masks::<BINARY>(block), visit)
    }

    #[inline(always)]
    fn high_bytes(src: &[u8]) -> usize {
        let (blocks, tail) = src.as_chunks::<NARROW>();
        // SAFETY: each `block` is a `&[u8; NARROW]`, so every 16-byte load is in
        // bounds; the helpers need only SSE2, which is static.
        let high = unsafe {
            Self::lane_sum(blocks.iter().fold(_mm_setzero_si128(), |lanes, block| {
                _mm_add_epi64(
                    lanes,
                    Self::high_lanes(_mm_loadu_si128(block.as_ptr().cast())),
                )
            }))
        };
        high + tail.iter().filter(|&&byte| byte >= 0x80).count()
    }

    #[inline(always)]
    fn word_blocks(
        table: &EscapeTable,
        _: &WordClass,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        budget: usize,
    ) -> (usize, usize) {
        table.encode_blocks(src, dst, budget)
    }

    #[inline(always)]
    fn word_len(table: &EscapeTable, _: &WordClass, src: &[u8]) -> usize {
        table.encoded_len(src)
    }
}

pub(crate) struct Avx2;

impl Avx2 {
    /// Runs `job` with the AVX2 kernel, compiled with AVX2 enabled.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn run<J: Job>(job: J) -> J::Output {
        job.run::<Avx2>()
    }

    /// Bitmask of the lanes of `chunk` holding `=`, `\r` or `\n`.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2, as `Avx2::run` requires.
    #[inline(always)]
    unsafe fn text_stops(chunk: __m256i) -> u32 {
        // SAFETY: callers only reach this from `Avx2::run`, whose contract guarantees
        // AVX2, and these intrinsics only touch registers.
        unsafe {
            let stops = _mm256_or_si256(
                _mm256_or_si256(
                    _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8(b'=' as i8)),
                    _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8(b'\r' as i8)),
                ),
                _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8(b'\n' as i8)),
            );
            _mm256_movemask_epi8(stops) as u32
        }
    }

    /// Bitmask of the lanes of `chunk` that stop a plain copy: controls other than tab,
    /// `=`, DEL and bytes of 0x80 or above.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2, as `Avx2::run` requires.
    #[inline(always)]
    unsafe fn plain_stops(chunk: __m256i) -> u32 {
        // SAFETY: callers only reach this from `Avx2::run`, whose contract guarantees
        // AVX2, and these intrinsics only touch registers.
        unsafe {
            let printable = _mm256_andnot_si256(
                _mm256_or_si256(
                    _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8(0x7f)),
                    _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8(b'=' as i8)),
                ),
                _mm256_cmpgt_epi8(chunk, _mm256_set1_epi8(0x1f)),
            );
            let plain = _mm256_or_si256(
                printable,
                _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8(b'\t' as i8)),
            );
            !(_mm256_movemask_epi8(plain) as u32)
        }
    }

    /// Bitmask of the lanes of `chunk` holding `\r` or `\n`.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2, as `Avx2::run` requires.
    #[inline(always)]
    unsafe fn breaks(chunk: __m256i) -> u32 {
        // SAFETY: callers only reach this from `Avx2::run`, whose contract guarantees
        // AVX2, and these intrinsics only touch registers.
        unsafe {
            _mm256_movemask_epi8(_mm256_or_si256(
                _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8(b'\r' as i8)),
                _mm256_cmpeq_epi8(chunk, _mm256_set1_epi8(b'\n' as i8)),
            )) as u32
        }
    }

    /// Loads the low and high nibble tables of `class`.
    ///
    /// # Safety
    ///
    /// The CPU must support SSE2, which the `encodify_x86` cfg guarantees; unlike the other
    /// `Avx2` helpers it needs no AVX2.
    #[inline(always)]
    unsafe fn class_tables(class: &WordClass) -> (__m128i, __m128i) {
        // SAFETY: `low` and `high` are `[u8; 16]`, so each 16-byte load fits; SSE2 is static.
        unsafe {
            (
                _mm_loadu_si128(class.low.as_ptr().cast()),
                _mm_loadu_si128(class.high.as_ptr().cast()),
            )
        }
    }

    /// Mask of the lanes of `chunk` that the nibble tables `low` and `high` mark for
    /// escaping.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2 (implying the SSSE3 `pshufb`), as `Avx2::run` requires.
    #[inline(always)]
    unsafe fn word_escapes(low: __m128i, high: __m128i, chunk: __m128i) -> __m128i {
        // SAFETY: callers only reach this from `Avx2::run`, whose AVX2 guarantee implies
        // the SSSE3 `pshufb`; the intrinsics only touch registers.
        unsafe {
            let nibble = _mm_set1_epi8(0x0f);
            let rows = _mm_shuffle_epi8(high, _mm_and_si128(_mm_srli_epi16::<4>(chunk), nibble));
            let columns = _mm_shuffle_epi8(low, _mm_and_si128(chunk, nibble));
            _mm_cmpeq_epi8(_mm_and_si128(rows, columns), _mm_setzero_si128())
        }
    }

    /// Sum of the four 64-bit lanes of `lanes`.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2 (implying the AVX store), as `Avx2::run` requires.
    #[inline(always)]
    unsafe fn lane_sum(lanes: __m256i) -> usize {
        let mut sums = [0u64; 4];
        // SAFETY: `sums` is `[u64; 4]`, exactly the 32 bytes stored; AVX is implied by
        // the AVX2 guarantee of `Avx2::run`, the only way callers reach this.
        unsafe { _mm256_storeu_si256(sums.as_mut_ptr().cast(), lanes) };
        sums.iter().map(|&sum| sum as usize).sum()
    }

    /// Encodes the 16-byte `block` into `window`, returning the number of bytes written.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2 (implying SSSE3 and SSE4.1), as `Avx2::run` requires; the
    /// array types of `block` and `window` bound every memory access.
    #[inline(always)]
    unsafe fn word_block(
        table: &EscapeTable,
        (low, high): (__m128i, __m128i),
        block: &[u8; NARROW],
        window: &mut [MaybeUninit<u8>; BLOCK_ROOM],
    ) -> usize {
        // SAFETY: AVX2 (so SSSE3 and SSE4.1) holds via `Avx2::run`. `block` is 16 bytes;
        // with at most `SPARSE_ESCAPES` (4) escapes the furthest write ends at
        // 16 + 2 * 4 + 16 = 40, within the `BLOCK_ROOM` (49) bytes of `window`.
        unsafe {
            let chunk = _mm_loadu_si128(block.as_ptr().cast());
            let spaces = _mm_cmpeq_epi8(chunk, _mm_set1_epi8(b' ' as i8));
            let out = _mm_blendv_epi8(chunk, _mm_set1_epi8(b'_' as i8), spaces);
            let mut escapes = _mm_movemask_epi8(Self::word_escapes(low, high, chunk)) as u32;
            if escapes == 0 {
                _mm_storeu_si128(window.as_mut_ptr().cast(), out);
                return NARROW;
            }
            if escapes.count_ones() as usize > SPARSE_ESCAPES {
                return table.encode_block(block, window);
            }
            let mut from = 0;
            let mut written = 0;
            while escapes != 0 {
                let at = escapes.trailing_zeros() as usize;
                escapes &= escapes - 1;
                Self::put_run(out, from, window.as_mut_ptr().add(written));
                written += at - from;
                let word = block.get(at).map_or(0, |&byte| table.word(byte));
                window
                    .as_mut_ptr()
                    .add(written)
                    .cast::<[u8; 4]>()
                    .write_unaligned(word.to_le_bytes());
                written += 3;
                from = at + 1;
            }
            Self::put_run(out, from, window.as_mut_ptr().add(written));
            written + NARROW - from
        }
    }

    /// Shifts `out` down by `from` lanes and stores all 16 lanes at `dst`.
    ///
    /// # Safety
    ///
    /// `dst` must be valid for writing 16 bytes, and the CPU must support AVX2 (implying
    /// SSSE3), as `Avx2::run` requires.
    #[inline(always)]
    unsafe fn put_run(out: __m128i, from: usize, dst: *mut MaybeUninit<u8>) {
        // SAFETY: `IOTA` is 16 bytes, the caller provides 16 writable bytes at `dst`,
        // and SSSE3 is implied by the AVX2 guarantee of `Avx2::run`.
        unsafe {
            let indices = _mm_add_epi8(
                _mm_loadu_si128(IOTA.as_ptr().cast()),
                _mm_set1_epi8(from as i8),
            );
            _mm_storeu_si128(dst.cast(), _mm_shuffle_epi8(out, indices));
        }
    }
}

const IOTA: [u8; NARROW] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

impl Kernel for Avx2 {
    const GRANULE: usize = GRANULE;
    const LANE_BITS: u32 = 1;
    const LANE_FLAGS: u64 = u64::MAX;

    #[inline(always)]
    fn copy_text(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        if let Some(count) = Swar::probe_text(src, dst) {
            return count;
        }
        let mut done = match Swar::copy_text_words::<TEXT_PROLOGUE>(src, dst) {
            Ok(count) => return count,
            Err(done) => done,
        };
        let len = src.len().min(dst.len());
        while done + WIDE <= len {
            // SAFETY: `done + WIDE <= len` and `len` bounds both slices, so the 32-byte load
            // and store stay in bounds; `Kernel for Avx2` only runs inside `Avx2::run`.
            let hits = unsafe {
                let chunk = _mm256_loadu_si256(src.as_ptr().add(done).cast());
                _mm256_storeu_si256(dst.as_mut_ptr().add(done).cast(), chunk);
                Self::text_stops(chunk)
            };
            if hits != 0 {
                return done + hits.trailing_zeros() as usize;
            }
            done += WIDE;
        }
        Sse2::copy_text_from(src, dst, done)
    }

    #[inline(always)]
    fn decode_escapes(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> (usize, usize) {
        Swar::decode_escapes(src, dst)
    }

    #[inline(always)]
    fn copy_plain(src: &[u8], dst: &mut [MaybeUninit<u8>], max: usize) -> usize {
        let limit = src.len().min(max);
        if let Some(count) = Swar::probe_plain(src, dst, limit) {
            return count;
        }
        let mut done = match Swar::copy_plain_words::<PLAIN_PROLOGUE>(src, dst, limit) {
            Ok(count) => return count,
            Err(done) => done,
        };
        while done < limit && done + WIDE <= src.len() && done + WIDE <= dst.len() {
            // SAFETY: the guard checks `done + WIDE` against both slice lengths, so the 32-byte
            // load and store stay in bounds; AVX2 holds as only `Avx2::run` runs this.
            let hits = unsafe {
                let chunk = _mm256_loadu_si256(src.as_ptr().add(done).cast());
                _mm256_storeu_si256(dst.as_mut_ptr().add(done).cast(), chunk);
                Self::plain_stops(chunk)
            };
            if hits != 0 {
                return (done + hits.trailing_zeros() as usize).min(limit);
            }
            done += WIDE;
        }
        Sse2::copy_plain_from(src, dst, limit, done)
    }

    #[inline(always)]
    fn encode_escapes<const BINARY: bool>(
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        max: usize,
    ) -> usize {
        Swar::encode_escapes::<BINARY>(src, dst, max)
    }

    #[inline(always)]
    fn line_masks<const BINARY: bool>(block: &[u8]) -> LineMasks {
        let Some(block) = block.first_chunk::<GRANULE>() else {
            return LineMasks::default();
        };
        // SAFETY: `block` is a `&[u8; GRANULE]`, so the 32-byte loads at 0 and `WIDE`
        // cover its 64 bytes; AVX2 holds as only `Avx2::run` runs this kernel.
        unsafe {
            let low = _mm256_loadu_si256(block.as_ptr().cast());
            let high = _mm256_loadu_si256(block.as_ptr().add(WIDE).cast());
            let combine = |low: u32, high: u32| u64::from(low) | (u64::from(high) << WIDE);
            let stops = combine(Self::plain_stops(low), Self::plain_stops(high));
            let escapes = match BINARY {
                true => stops,
                false if stops == 0 => 0,
                false => stops & !combine(Self::breaks(low), Self::breaks(high)),
            };
            LineMasks { stops, escapes }
        }
    }

    #[inline(always)]
    fn scan_lines<const BINARY: bool>(
        input: &[u8],
        visit: impl FnMut(usize, LineMasks) -> bool,
    ) -> Option<usize> {
        LineMasks::scan::<GRANULE>(input, |block| Self::line_masks::<BINARY>(block), visit)
    }

    #[inline(always)]
    fn high_bytes(src: &[u8]) -> usize {
        let (blocks, tail) = src.as_chunks::<WIDE>();
        // SAFETY: each `block` is a `&[u8; WIDE]`, so every 32-byte load is in bounds;
        // AVX2 holds as only `Avx2::run` runs this kernel.
        let high = unsafe {
            Self::lane_sum(blocks.iter().fold(_mm256_setzero_si256(), |lanes, block| {
                let chunk = _mm256_loadu_si256(block.as_ptr().cast());
                let ones = _mm256_and_si256(_mm256_srli_epi16::<7>(chunk), _mm256_set1_epi8(1));
                _mm256_add_epi64(lanes, _mm256_sad_epu8(ones, _mm256_setzero_si256()))
            }))
        };
        high + Sse2::high_bytes(tail)
    }

    #[inline(always)]
    fn word_blocks(
        table: &EscapeTable,
        class: &WordClass,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        budget: usize,
    ) -> (usize, usize) {
        let (blocks, _) = src.as_chunks::<NARROW>();
        // SAFETY: `class_tables` loads two `[u8; 16]` arrays and needs only static SSE2.
        let (low, high) = unsafe { Self::class_tables(class) };
        let mut read = 0;
        let mut written = 0;
        let mut vector = true;
        for block in blocks {
            let Some(window) = dst
                .get_mut(written..)
                .and_then(|rest| rest.first_chunk_mut::<BLOCK_ROOM>())
            else {
                break;
            };
            let len = match vector {
                // SAFETY: `window` has `BLOCK_ROOM` bytes and `block` has 16, as `word_block`
                // needs; AVX2 holds as only `Avx2::run` runs this kernel.
                true => unsafe { Self::word_block(table, (low, high), block, window) },
                false => table.encode_block(block, window),
            };
            if len > budget - written {
                break;
            }
            vector = len <= SPARSE_LEN;
            written += len;
            read += NARROW;
        }
        (read, written)
    }

    #[inline(always)]
    fn word_len(table: &EscapeTable, class: &WordClass, src: &[u8]) -> usize {
        let (blocks, tail) = src.as_chunks::<NARROW>();
        // SAFETY: the class tables are 16 bytes and each `block` is a `&[u8; NARROW]`;
        // AVX2 (so SSSE3) holds as only `Avx2::run` runs this kernel.
        let escapes = unsafe {
            let (low, high) = Self::class_tables(class);
            Sse2::lane_sum(blocks.iter().fold(_mm_setzero_si128(), |lanes, block| {
                let chunk = _mm_loadu_si128(block.as_ptr().cast());
                let ones = _mm_and_si128(Self::word_escapes(low, high, chunk), _mm_set1_epi8(1));
                _mm_add_epi64(lanes, _mm_sad_epu8(ones, _mm_setzero_si128()))
            }))
        };
        src.len() - tail.len() + 2 * escapes + table.encoded_len(tail)
    }
}
