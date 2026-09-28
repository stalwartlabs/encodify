/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{
    super::tables::WordClass, Kernel, LineMasks, PLAIN_PROLOGUE, TEXT_PROLOGUE, scalar::Swar,
};
use crate::hex::{BLOCK_ROOM, EscapeTable, SPARSE_ESCAPES, SPARSE_LEN};
use core::arch::aarch64::*;
use std::mem::MaybeUninit;

const BLOCK: usize = 16;

pub(crate) struct Neon;

impl Neon {
    /// Packs a byte mask into a `u64`, four bits per lane.
    ///
    /// # Safety
    ///
    /// The CPU must support NEON; builds with `encodify_neon` guarantee it.
    #[inline(always)]
    unsafe fn lanes(mask: uint8x16_t) -> u64 {
        // SAFETY: register-only NEON intrinsics; NEON is enabled at compile time (`encodify_neon`).
        unsafe {
            vget_lane_u64::<0>(vreinterpret_u64_u8(vshrn_n_u16::<4>(vreinterpretq_u16_u8(
                mask,
            ))))
        }
    }

    #[inline(always)]
    fn first_lane(hits: u64) -> usize {
        (hits.trailing_zeros() / 4) as usize
    }

    /// Packs the four masks of a `vld4q_u8` load into one bit per source byte.
    ///
    /// # Safety
    ///
    /// The CPU must support NEON; builds with `encodify_neon` guarantee it.
    #[inline(always)]
    unsafe fn bits([first, second, third, fourth]: [uint8x16_t; 4]) -> u64 {
        // SAFETY: register-only NEON intrinsics; NEON is enabled at compile time (`encodify_neon`).
        unsafe {
            let low = vsriq_n_u8::<1>(second, first);
            let high = vsriq_n_u8::<1>(fourth, third);
            let quads = vsriq_n_u8::<2>(high, low);
            let doubled = vsriq_n_u8::<4>(quads, quads);
            vget_lane_u64::<0>(vreinterpret_u64_u8(vshrn_n_u16::<4>(vreinterpretq_u16_u8(
                doubled,
            ))))
        }
    }

    /// Marks the lanes of `chunk` holding `=`, CR or LF.
    ///
    /// # Safety
    ///
    /// The CPU must support NEON; builds with `encodify_neon` guarantee it.
    #[inline(always)]
    unsafe fn text_stops(chunk: uint8x16_t) -> uint8x16_t {
        // SAFETY: register-only NEON intrinsics; NEON is enabled at compile time (`encodify_neon`).
        unsafe {
            vorrq_u8(
                vorrq_u8(
                    vceqq_u8(chunk, vdupq_n_u8(b'=')),
                    vceqq_u8(chunk, vdupq_n_u8(b'\r')),
                ),
                vceqq_u8(chunk, vdupq_n_u8(b'\n')),
            )
        }
    }

    /// Marks the lanes of `chunk` copied as is: printable ASCII other than `=`, and tab.
    ///
    /// # Safety
    ///
    /// The CPU must support NEON; builds with `encodify_neon` guarantee it.
    #[inline(always)]
    unsafe fn plain(chunk: uint8x16_t) -> uint8x16_t {
        // SAFETY: register-only NEON intrinsics; NEON is enabled at compile time (`encodify_neon`).
        unsafe {
            let printable = vcltq_u8(vsubq_u8(chunk, vdupq_n_u8(b' ')), vdupq_n_u8(0x5f));
            let equals = vceqq_u8(chunk, vdupq_n_u8(b'='));
            let tab = vceqq_u8(chunk, vdupq_n_u8(b'\t'));
            vorrq_u8(vbicq_u8(printable, equals), tab)
        }
    }

    /// Marks the lanes of `chunk` that `plain` rejects.
    ///
    /// # Safety
    ///
    /// The CPU must support NEON; builds with `encodify_neon` guarantee it.
    #[inline(always)]
    unsafe fn plain_stops(chunk: uint8x16_t) -> uint8x16_t {
        // SAFETY: register-only NEON intrinsics; NEON is enabled at compile time (`encodify_neon`).
        unsafe { vmvnq_u8(Self::plain(chunk)) }
    }

    /// Marks the lanes of `chunk` that the nibble tables `low` and `high` keep literal.
    ///
    /// # Safety
    ///
    /// The CPU must support NEON; builds with `encodify_neon` guarantee it.
    #[inline(always)]
    unsafe fn word_literals(low: uint8x16_t, high: uint8x16_t, chunk: uint8x16_t) -> uint8x16_t {
        // SAFETY: register-only NEON intrinsics; NEON is enabled at compile time (`encodify_neon`).
        unsafe {
            vtstq_u8(
                vqtbl1q_u8(low, vandq_u8(chunk, vdupq_n_u8(0x0f))),
                vqtbl1q_u8(high, vshrq_n_u8::<4>(chunk)),
            )
        }
    }

    /// Loads the low and high nibble tables of `class`.
    ///
    /// # Safety
    ///
    /// The CPU must support NEON; builds with `encodify_neon` guarantee it.
    #[inline(always)]
    unsafe fn class_tables(class: &WordClass) -> (uint8x16_t, uint8x16_t) {
        // SAFETY: `low` and `high` are `[u8; 16]`, so each 16-byte load stays in bounds; NEON is
        // enabled at compile time (`encodify_neon`).
        unsafe { (vld1q_u8(class.low.as_ptr()), vld1q_u8(class.high.as_ptr())) }
    }

    /// Encodes `block` into `window` as encoded-word text, returning the bytes written.
    ///
    /// # Safety
    ///
    /// The CPU must support NEON; builds with `encodify_neon` guarantee it.
    /// The fixed-size `block` and `window` bound every load and store.
    #[inline(always)]
    unsafe fn word_block(
        table: &EscapeTable,
        (low, high): (uint8x16_t, uint8x16_t),
        block: &[u8; BLOCK],
        window: &mut [MaybeUninit<u8>; BLOCK_ROOM],
    ) -> usize {
        // SAFETY: `block` is 16 bytes; at most `SPARSE_ESCAPES` (4) escapes reach the loop, so
        // `written <= 15 + 2 * 4 + 1` and every 16-byte run and 4-byte word store ends by byte 40
        // of the `BLOCK_ROOM` (49) byte window. NEON is enabled at compile time (`encodify_neon`).
        unsafe {
            let chunk = vld1q_u8(block.as_ptr());
            let literals = Self::word_literals(low, high, chunk);
            let spaces = vceqq_u8(chunk, vdupq_n_u8(b' '));
            let out = vbslq_u8(spaces, vdupq_n_u8(b'_'), chunk);
            let mut escapes = !Self::lanes(literals) & LANE_ONES;
            if escapes == 0 {
                vst1q_u8(window.as_mut_ptr().cast(), out);
                return BLOCK;
            }
            if escapes.count_ones() as usize > SPARSE_ESCAPES {
                return table.encode_block(block, window);
            }
            let mut from = 0;
            let mut written = 0;
            while escapes != 0 {
                let at = (escapes.trailing_zeros() / 4) as usize;
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
            written + BLOCK - from
        }
    }

    /// Stores the lanes of `out` from `from` onward at `dst`, zero-filled to 16 bytes.
    ///
    /// # Safety
    ///
    /// `dst` must be valid for writing 16 bytes, and the CPU must support NEON;
    /// builds with `encodify_neon` guarantee the latter.
    #[inline(always)]
    unsafe fn put_run(out: uint8x16_t, from: usize, dst: *mut MaybeUninit<u8>) {
        // SAFETY: `IOTA` is 16 bytes; the caller (`word_block`) gives a `dst` with 16 writable
        // bytes, and out-of-range table indices just yield 0. NEON is enabled (`encodify_neon`).
        unsafe {
            let indices = vaddq_u8(vld1q_u8(IOTA.as_ptr()), vdupq_n_u8(from as u8));
            vst1q_u8(dst.cast(), vqtbl1q_u8(out, indices));
        }
    }
}

const LANE_ONES: u64 = 0x1111_1111_1111_1111;
const GRANULE: usize = 4 * BLOCK;
const IOTA: [u8; BLOCK] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

impl Kernel for Neon {
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
        while done + BLOCK <= len {
            // SAFETY: `done + BLOCK <= len`, the shorter of `src` and `dst`, so the 16-byte load
            // and store stay in bounds. NEON is enabled at compile time (`encodify_neon`).
            let hits = unsafe {
                let chunk = vld1q_u8(src.as_ptr().add(done));
                vst1q_u8(dst.as_mut_ptr().add(done).cast(), chunk);
                Self::lanes(Self::text_stops(chunk))
            };
            if hits != 0 {
                return done + Self::first_lane(hits);
            }
            done += BLOCK;
        }
        done + Swar::copy_text(
            src.get(done..).unwrap_or_default(),
            dst.get_mut(done..).unwrap_or_default(),
        )
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
        while done < limit && done + BLOCK <= src.len() && done + BLOCK <= dst.len() {
            // SAFETY: the loop condition keeps `done + BLOCK` within both `src` and `dst`, so the
            // 16-byte load and store stay in bounds. NEON is enabled at compile time
            // (`encodify_neon`).
            let hits = unsafe {
                let chunk = vld1q_u8(src.as_ptr().add(done));
                vst1q_u8(dst.as_mut_ptr().add(done).cast(), chunk);
                Self::lanes(Self::plain_stops(chunk))
            };
            if hits != 0 {
                return (done + Self::first_lane(hits)).min(limit);
            }
            done += BLOCK;
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
        // SAFETY: `block` is a `[u8; GRANULE]` (64 bytes), exactly what `vld4q_u8` reads. NEON is
        // enabled at compile time (`encodify_neon`).
        unsafe {
            let uint8x16x4_t(first, second, third, fourth) = vld4q_u8(block.as_ptr());
            let chunks = [first, second, third, fourth];
            let plain = chunks.map(|chunk| Self::plain(chunk));
            let stops = !Self::bits(plain);
            let escapes = match BINARY {
                true => stops,
                false if stops == 0 => 0,
                false => {
                    let kept = [0, 1, 2, 3].map(|index| {
                        let chunk = chunks[index];
                        let breaks = vorrq_u8(
                            vceqq_u8(chunk, vdupq_n_u8(b'\r')),
                            vceqq_u8(chunk, vdupq_n_u8(b'\n')),
                        );
                        vorrq_u8(plain[index], breaks)
                    });
                    !Self::bits(kept)
                }
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
        let (blocks, tail) = src.as_chunks::<BLOCK>();
        let high: usize = blocks
            .chunks(u8::MAX as usize)
            // SAFETY: each load reads one 16-byte block from `as_chunks`. NEON is enabled at
            // compile time (`encodify_neon`).
            .map(|group| unsafe {
                let lanes = group.iter().fold(vdupq_n_u8(0), |lanes, block| {
                    vsraq_n_u8::<7>(lanes, vld1q_u8(block.as_ptr()))
                });
                usize::from(vaddlvq_u8(lanes))
            })
            .sum();
        high + tail.iter().filter(|&&byte| byte >= 0x80).count()
    }

    #[inline(always)]
    fn word_blocks(
        table: &EscapeTable,
        class: &WordClass,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        budget: usize,
    ) -> (usize, usize) {
        let (blocks, _) = src.as_chunks::<BLOCK>();
        // SAFETY: `class_tables` only loads the two 16-byte tables of `class`. NEON is enabled at
        // compile time (`encodify_neon`).
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
                // SAFETY: `block` and `window` are fixed-size arrays of the sizes `word_block`
                // stores within. NEON is enabled at compile time (`encodify_neon`).
                true => unsafe { Self::word_block(table, (low, high), block, window) },
                false => table.encode_block(block, window),
            };
            if len > budget - written {
                break;
            }
            vector = len <= SPARSE_LEN;
            written += len;
            read += BLOCK;
        }
        (read, written)
    }

    #[inline(always)]
    fn word_len(table: &EscapeTable, class: &WordClass, src: &[u8]) -> usize {
        let (blocks, tail) = src.as_chunks::<BLOCK>();
        // SAFETY: `class_tables` only loads the two 16-byte tables of `class`. NEON is enabled at
        // compile time (`encodify_neon`).
        let (low, high) = unsafe { Self::class_tables(class) };
        let literals: usize = blocks
            .chunks(u8::MAX as usize)
            // SAFETY: each load reads one 16-byte block from `as_chunks`. NEON is enabled at
            // compile time (`encodify_neon`).
            .map(|group| unsafe {
                let lanes = group.iter().fold(vdupq_n_u8(0), |lanes, block| {
                    vsubq_u8(
                        lanes,
                        Self::word_literals(low, high, vld1q_u8(block.as_ptr())),
                    )
                });
                usize::from(vaddlvq_u8(lanes))
            })
            .sum();
        let block_len = src.len() - tail.len();
        block_len + 2 * (block_len - literals) + table.encoded_len(tail)
    }
}
