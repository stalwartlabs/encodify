/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{
    super::{
        Wrap,
        alphabet::{FLAG_VALID, FLAGS_BASE, Tables},
    },
    LineShape,
};
use core::arch::aarch64::*;
use std::mem::MaybeUninit;

const DECODE_BLOCK: usize = 64;
const DECODE_BLOCK_OUT: usize = 48;
const DECODE_BLOCK_TAIL: usize = 48;
const DECODE_QUARTER: usize = 16;
const ENCODE_BLOCK: usize = 48;
const ENCODE_BLOCK_OUT: usize = 64;
const ENCODE_BLOCK_TAIL: usize = 36;
const ENCODE_QUARTER: usize = 12;
const STAGE: usize = 2048;
const ENCODE_STAGE: usize = 2048;
const COPY: usize = 16;

const PACK_LANES: [u8; 16] = [2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, 3, 7, 11, 15];
const QUARTER_HIGH_INDEX: [u8; 16] = [0, 0, 1, 2, 3, 3, 4, 5, 6, 6, 7, 8, 9, 9, 10, 11];
const QUARTER_HIGH_SHIFT: [i8; 16] = [-2, 4, 2, 0, -2, 4, 2, 0, -2, 4, 2, 0, -2, 4, 2, 0];
const QUARTER_LOW_INDEX: [u8; 16] = [
    0xff, 1, 2, 0xff, 0xff, 4, 5, 0xff, 0xff, 7, 8, 0xff, 0xff, 10, 11, 0xff,
];
const QUARTER_LOW_SHIFT: [i8; 16] = [0, -4, -6, 0, 0, -4, -6, 0, 0, -4, -6, 0, 0, -4, -6, 0];

#[derive(Clone, Copy)]
struct Validity(uint8x16_t);

impl Validity {
    /// Lane-wise AND of the two validity masks.
    ///
    /// # Safety
    ///
    /// NEON must be available.
    #[inline(always)]
    unsafe fn and(self, other: Validity) -> Validity {
        // SAFETY: NEON is guaranteed by the `encodify_neon` cfg; register-only intrinsics.
        unsafe { Validity(vandq_u8(self.0, other.0)) }
    }

    /// Whether every lane is at least `FLAG_VALID`.
    ///
    /// # Safety
    ///
    /// NEON must be available.
    #[inline(always)]
    unsafe fn is_valid(self) -> bool {
        // SAFETY: NEON is guaranteed by the `encodify_neon` cfg; register-only intrinsics.
        unsafe { vminvq_u8(self.0) >= FLAG_VALID }
    }

    /// Index of the first lane below `FLAG_VALID`, or 16 when there is none.
    ///
    /// # Safety
    ///
    /// NEON must be available.
    #[inline(always)]
    unsafe fn first_bad_lane(self) -> usize {
        // SAFETY: NEON is guaranteed by the `encodify_neon` cfg; register-only intrinsics.
        unsafe {
            let mask = vcltq_u8(self.0, vdupq_n_u8(FLAG_VALID));
            let bits = vget_lane_u64::<0>(vreinterpret_u64_u8(vshrn_n_u16::<4>(
                vreinterpretq_u16_u8(mask),
            )));
            (bits.trailing_zeros() / 4) as usize
        }
    }

    /// The `(read, written)` counts up to the first invalid quad of the block at `start`.
    ///
    /// # Safety
    ///
    /// NEON must be available.
    #[inline(always)]
    unsafe fn block_stop(self, start: usize) -> (usize, usize) {
        // SAFETY: `first_bad_lane` only reads a register; NEON is guaranteed by `encodify_neon`.
        let quads = start / 4 + unsafe { self.first_bad_lane() };
        (quads * 4, quads * 3)
    }

    /// The `(read, written)` counts up to the first invalid quad of the quarter at `start`.
    ///
    /// # Safety
    ///
    /// NEON must be available.
    #[inline(always)]
    unsafe fn quarter_stop(self, start: usize) -> (usize, usize) {
        // SAFETY: `first_bad_lane` only reads a register; NEON is guaranteed by `encodify_neon`.
        let quads = start / 4 + unsafe { self.first_bad_lane() } / 4;
        (quads * 4, quads * 3)
    }
}

#[derive(Clone, Copy)]
struct Flags {
    low: uint8x16x4_t,
    high: uint8x16_t,
}

impl Flags {
    /// Loads the 80-byte flag table into registers.
    ///
    /// # Safety
    ///
    /// NEON must be available.
    #[inline(always)]
    unsafe fn load(tables: &Tables) -> Flags {
        // SAFETY: `tables.flags` is `[u8; FLAGS_LEN]` with `FLAGS_LEN == 80`, so the 64-byte
        // load at 0 and the 16-byte load at 64 stay in bounds.
        unsafe {
            Flags {
                low: vld1q_u8_x4(tables.flags.as_ptr()),
                high: vld1q_u8(tables.flags.as_ptr().add(64)),
            }
        }
    }

    /// Looks up the flag byte of each character lane.
    ///
    /// # Safety
    ///
    /// NEON must be available.
    #[inline(always)]
    unsafe fn lookup(self, chars: uint8x16_t) -> uint8x16_t {
        // SAFETY: NEON is guaranteed by the `encodify_neon` cfg; register-only intrinsics.
        unsafe {
            let index = vsubq_u8(chars, vdupq_n_u8(FLAGS_BASE));
            vqtbx1q_u8(
                vqtbl4q_u8(self.low, index),
                self.high,
                vsubq_u8(index, vdupq_n_u8(64)),
            )
        }
    }

    /// Decodes 64 characters at `src` into 48 bytes at `dst`, one validity lane per quad.
    ///
    /// # Safety
    ///
    /// `src` must be valid for reading 64 bytes and `dst` for writing 48 bytes.
    #[inline(always)]
    unsafe fn decode_block(self, src: *const u8, dst: *mut u8) -> Validity {
        // SAFETY: callers pass 64 readable bytes at `src` and 48 writable bytes at `dst`,
        // exactly what `vld4q_u8` and `vst3q_u8` access.
        unsafe {
            let chars = vld4q_u8(src);
            let a = self.lookup(chars.0);
            let b = self.lookup(chars.1);
            let c = self.lookup(chars.2);
            let d = self.lookup(chars.3);
            let first = vsliq_n_u8::<2>(vshrq_n_u8::<4>(b), a);
            let second = vsliq_n_u8::<4>(vshrq_n_u8::<2>(c), b);
            let third = vsliq_n_u8::<6>(d, c);
            vst3q_u8(dst, uint8x16x3_t(first, second, third));
            Validity(vandq_u8(vandq_u8(a, b), vandq_u8(c, d)))
        }
    }

    /// Decodes 16 characters at `src` into 12 bytes at `dst`, `pack` holding `PACK_LANES`.
    ///
    /// # Safety
    ///
    /// `src` must be valid for reading 16 bytes and `dst` for writing 12 bytes.
    #[inline(always)]
    unsafe fn decode_quarter(self, pack: uint8x16_t, src: *const u8, dst: *mut u8) -> Validity {
        // SAFETY: callers pass 16 readable bytes at `src` and 12 writable bytes at `dst`: one
        // 16-byte load, then an 8-byte and a 4-byte store.
        unsafe {
            let sextets = self.lookup(vld1q_u8(src));
            let pairs = vreinterpretq_u16_u8(sextets);
            let pairs = vsliq_n_u16::<6>(vshrq_n_u16::<8>(pairs), pairs);
            let quads = vreinterpretq_u32_u16(pairs);
            let quads = vsliq_n_u32::<12>(vshrq_n_u32::<16>(quads), quads);
            let bytes = vqtbl1q_u8(vreinterpretq_u8_u32(quads), pack);
            vst1_u8(dst, vget_low_u8(bytes));
            dst.add(8)
                .cast::<u32>()
                .write_unaligned(vgetq_lane_u32::<2>(vreinterpretq_u32_u8(bytes)));
            Validity(sextets)
        }
    }

    /// Decodes `src[read..chars]` 16 characters at a time, the last quarter overlapping
    /// the previous one; `None` when every quad is valid.
    ///
    /// # Safety
    ///
    /// `read` and `chars` must be multiples of 4 with `chars >= 16`; `src` must be valid
    /// for reading `chars` bytes and `dst` for writing `chars / 4 * 3` bytes.
    #[inline(always)]
    unsafe fn decode_quarters(
        self,
        src: *const u8,
        mut read: usize,
        chars: usize,
        dst: *mut u8,
    ) -> Option<(usize, usize)> {
        // SAFETY: `PACK_LANES` is 16 bytes; `read` and `chars` are multiples of 4, `chars >= 16`,
        // so each quarter at `at` (with `at + 16 <= chars`) stays within the caller's `chars`
        // readable and `chars / 4 * 3` writable bytes, the tail one included.
        unsafe {
            let pack = vld1q_u8(PACK_LANES.as_ptr());
            while read + DECODE_QUARTER <= chars {
                let all = self.decode_quarter(pack, src.add(read), dst.add(read / 4 * 3));
                if !all.is_valid() {
                    return Some(all.quarter_stop(read));
                }
                read += DECODE_QUARTER;
            }
            if read < chars {
                let last = chars - DECODE_QUARTER;
                let all = self.decode_quarter(pack, src.add(last), dst.add(last / 4 * 3));
                if !all.is_valid() {
                    return Some(all.quarter_stop(last));
                }
            }
            None
        }
    }

    /// Decodes the `chars` characters at `src` into `dst`, returning the `(read, written)`
    /// counts up to the first invalid quad; `(0, 0)` below 16 characters.
    ///
    /// # Safety
    ///
    /// `chars` must be a multiple of 4; `src` must be valid for reading `chars` bytes and
    /// `dst` for writing `chars / 4 * 3` bytes.
    #[inline(always)]
    unsafe fn decode_exact(self, src: *const u8, chars: usize, dst: *mut u8) -> (usize, usize) {
        // SAFETY: callers pass `chars` (a multiple of 4) readable bytes at `src` and
        // `chars / 4 * 3` writable at `dst`; every block starts at a multiple of 4 and ends
        // at or before `chars` (the tail at `chars - DECODE_BLOCK` needs `chars >= 64`).
        unsafe {
            if chars < DECODE_QUARTER {
                return (0, 0);
            } else if chars >= DECODE_BLOCK {
                let mut read = 0;
                while read + 2 * DECODE_BLOCK <= chars {
                    let out = dst.add(read / 4 * 3);
                    let first = self.decode_block(src.add(read), out);
                    let second =
                        self.decode_block(src.add(read + DECODE_BLOCK), out.add(DECODE_BLOCK_OUT));
                    if !first.and(second).is_valid() {
                        return if !first.is_valid() {
                            first.block_stop(read)
                        } else {
                            second.block_stop(read + DECODE_BLOCK)
                        };
                    }
                    read += 2 * DECODE_BLOCK;
                }
                if read + DECODE_BLOCK <= chars {
                    let all = self.decode_block(src.add(read), dst.add(read / 4 * 3));
                    if !all.is_valid() {
                        return all.block_stop(read);
                    }
                    read += DECODE_BLOCK;
                }
                if chars - read >= DECODE_BLOCK_TAIL {
                    let last = chars - DECODE_BLOCK;
                    let all = self.decode_block(src.add(last), dst.add(last / 4 * 3));
                    if !all.is_valid() {
                        return all.block_stop(last);
                    }
                } else if read < chars
                    && let Some(stop) = self.decode_quarters(src, read, chars, dst)
                {
                    return stop;
                }
            } else if let Some(stop) = self.decode_quarters(src, 0, chars, dst) {
                return stop;
            }
            (chars, chars / 4 * 3)
        }
    }
}

#[derive(Clone, Copy)]
struct Symbols(uint8x16x4_t);

impl Symbols {
    /// Loads the 64-byte encode table into registers.
    ///
    /// # Safety
    ///
    /// NEON must be available.
    #[inline(always)]
    unsafe fn load(tables: &Tables) -> Symbols {
        // SAFETY: `tables.encode` is `[u8; 64]`, exactly one `vld1q_u8_x4` load.
        unsafe { Symbols(vld1q_u8_x4(tables.encode.as_ptr())) }
    }

    /// Splits deinterleaved 3-byte groups into their four sextets.
    ///
    /// # Safety
    ///
    /// NEON must be available.
    #[inline(always)]
    unsafe fn split_sextets(bytes: uint8x16x3_t) -> uint8x16x4_t {
        // SAFETY: NEON is guaranteed by the `encodify_neon` cfg; register-only intrinsics.
        unsafe {
            let mask = vdupq_n_u8(0x3f);
            uint8x16x4_t(
                vshrq_n_u8::<2>(bytes.0),
                vandq_u8(vsliq_n_u8::<4>(vshrq_n_u8::<4>(bytes.1), bytes.0), mask),
                vandq_u8(vsliq_n_u8::<2>(vshrq_n_u8::<6>(bytes.2), bytes.1), mask),
                vandq_u8(bytes.2, mask),
            )
        }
    }

    /// Encodes 12 bytes at `src` into 16 characters at `dst`.
    ///
    /// # Safety
    ///
    /// `src` must be valid for reading 12 bytes and `dst` for writing 16 bytes.
    #[inline(always)]
    unsafe fn encode_quarter(self, src: *const u8, dst: *mut u8) {
        // SAFETY: callers pass 12 readable bytes at `src` (8-byte load plus 4-byte read at 8)
        // and 16 writable at `dst`; the index and shift tables are 16 bytes each.
        unsafe {
            let low = vld1_u8(src);
            let high = vcreate_u8(u64::from(src.add(8).cast::<u32>().read_unaligned()));
            let bytes = vcombine_u8(low, high);
            let upper = vshlq_u8(
                vqtbl1q_u8(bytes, vld1q_u8(QUARTER_HIGH_INDEX.as_ptr())),
                vld1q_s8(QUARTER_HIGH_SHIFT.as_ptr()),
            );
            let lower = vshlq_u8(
                vqtbl1q_u8(bytes, vld1q_u8(QUARTER_LOW_INDEX.as_ptr())),
                vld1q_s8(QUARTER_LOW_SHIFT.as_ptr()),
            );
            let sextets = vandq_u8(vorrq_u8(upper, lower), vdupq_n_u8(0x3f));
            vst1q_u8(dst, vqtbl4q_u8(self.0, sextets));
        }
    }

    /// Encodes 48 bytes at `src` into 64 characters at `dst`.
    ///
    /// # Safety
    ///
    /// `src` must be valid for reading 48 bytes and `dst` for writing 64 bytes.
    #[inline(always)]
    unsafe fn encode_block(self, src: *const u8, dst: *mut u8) {
        // SAFETY: callers pass 48 readable bytes at `src` and 64 writable bytes at `dst`,
        // exactly what `vld3q_u8` and `vst4q_u8` access.
        unsafe {
            let sextets = Self::split_sextets(vld3q_u8(src));
            vst4q_u8(
                dst,
                uint8x16x4_t(
                    vqtbl4q_u8(self.0, sextets.0),
                    vqtbl4q_u8(self.0, sextets.1),
                    vqtbl4q_u8(self.0, sextets.2),
                    vqtbl4q_u8(self.0, sextets.3),
                ),
            );
        }
    }

    /// Encodes `src[read..bytes]` 12 bytes at a time, the last quarter overlapping the
    /// previous one.
    ///
    /// # Safety
    ///
    /// `read` and `bytes` must be multiples of 3 with `bytes >= 12`; `src` must be valid
    /// for reading `bytes` bytes and `dst` for writing `bytes / 3 * 4` bytes.
    #[inline(always)]
    unsafe fn encode_quarters(self, src: *const u8, mut read: usize, bytes: usize, dst: *mut u8) {
        // SAFETY: `read` and `bytes` are multiples of 3 and `bytes >= 12`, so each quarter at `at`
        // (with `at + 12 <= bytes`) stays within the caller's `bytes` readable and
        // `bytes / 3 * 4` writable bytes, the tail one included.
        unsafe {
            while read + ENCODE_QUARTER <= bytes {
                self.encode_quarter(src.add(read), dst.add(read / 3 * 4));
                read += ENCODE_QUARTER;
            }
            if read < bytes {
                let last = bytes - ENCODE_QUARTER;
                self.encode_quarter(src.add(last), dst.add(last / 3 * 4));
            }
        }
    }

    /// Encodes the `bytes` bytes at `src` into `dst`; writes nothing below 12 bytes.
    ///
    /// # Safety
    ///
    /// `bytes` must be a multiple of 3; `src` must be valid for reading `bytes` bytes and
    /// `dst` for writing `bytes / 3 * 4` bytes.
    #[inline(always)]
    unsafe fn encode_exact(self, src: *const u8, bytes: usize, dst: *mut u8) {
        // SAFETY: callers pass `bytes` (a multiple of 3) readable at `src` and `bytes / 3 * 4`
        // writable at `dst`; every block ends at or before `bytes`, the tail block at
        // `bytes - ENCODE_BLOCK` needing `bytes >= 48` and the quarters `bytes >= 12`.
        unsafe {
            if bytes >= ENCODE_BLOCK {
                let mut read = 0;
                while read + 2 * ENCODE_BLOCK <= bytes {
                    let out = dst.add(read / 3 * 4);
                    self.encode_block(src.add(read), out);
                    self.encode_block(src.add(read + ENCODE_BLOCK), out.add(ENCODE_BLOCK_OUT));
                    read += 2 * ENCODE_BLOCK;
                }
                if read + ENCODE_BLOCK <= bytes {
                    self.encode_block(src.add(read), dst.add(read / 3 * 4));
                    read += ENCODE_BLOCK;
                }
                if bytes - read >= ENCODE_BLOCK_TAIL {
                    let last = bytes - ENCODE_BLOCK;
                    self.encode_block(src.add(last), dst.add(last / 3 * 4));
                } else if read < bytes {
                    self.encode_quarters(src, read, bytes, dst);
                }
            } else if bytes >= ENCODE_QUARTER {
                self.encode_quarters(src, 0, bytes, dst);
            }
        }
    }
}

impl LineShape {
    const fn batch_lines(self) -> usize {
        let shift = if self.len.trailing_zeros() < 6 {
            self.len.trailing_zeros()
        } else {
            6
        };
        let unit = DECODE_BLOCK >> shift;
        let per_stage = STAGE / self.len;
        if per_stage >= unit {
            per_stage / unit * unit
        } else {
            per_stage
        }
    }
}

impl Wrap {
    const fn batch_lines(self) -> usize {
        let quads = self.width / 4;
        let shift = if quads.trailing_zeros() < 4 {
            quads.trailing_zeros()
        } else {
            4
        };
        let unit = (ENCODE_BLOCK / 3) >> shift;
        let per_stage = ENCODE_STAGE / self.width;
        if per_stage >= unit {
            per_stage / unit * unit
        } else if per_stage == 0 {
            1
        } else {
            per_stage
        }
    }
}

/// Copies `width` bytes from `from` to `to` with overlapping unaligned accesses.
///
/// # Safety
///
/// `from` must be valid for reading `width` bytes and `to` for writing `width` bytes.
#[inline(always)]
unsafe fn copy_line(from: *const u8, to: *mut u8, width: usize) {
    // SAFETY: callers pass `width` readable bytes at `from` and `width` writable at `to`;
    // below `COPY` the 8/4/2/1-byte pieces sum to `width`, above it every 16-byte
    // access is guarded by the `width` or `rest` checks, the last one at `width - COPY`.
    unsafe {
        if width < COPY {
            let mut at = 0;
            if width & 8 != 0 {
                to.cast::<u64>()
                    .write_unaligned(from.cast::<u64>().read_unaligned());
                at = 8;
            }
            if width & 4 != 0 {
                to.add(at)
                    .cast::<u32>()
                    .write_unaligned(from.add(at).cast::<u32>().read_unaligned());
                at += 4;
            }
            if width & 2 != 0 {
                to.add(at)
                    .cast::<u16>()
                    .write_unaligned(from.add(at).cast::<u16>().read_unaligned());
                at += 2;
            }
            if width & 1 != 0 {
                to.add(at).write(from.add(at).read());
            }
        } else if width < 4 * COPY {
            vst1q_u8(to, vld1q_u8(from));
            if width > 2 * COPY {
                vst1q_u8(to.add(COPY), vld1q_u8(from.add(COPY)));
            }
            if width > 3 * COPY {
                vst1q_u8(to.add(2 * COPY), vld1q_u8(from.add(2 * COPY)));
            }
            vst1q_u8(to.add(width - COPY), vld1q_u8(from.add(width - COPY)));
        } else {
            let mut at = 0;
            while at + 4 * COPY <= width {
                vst1q_u8_x4(to.add(at), vld1q_u8_x4(from.add(at)));
                at += 4 * COPY;
            }
            let rest = width - at;
            if rest > COPY {
                vst1q_u8(to.add(at), vld1q_u8(from.add(at)));
            }
            if rest > 2 * COPY {
                vst1q_u8(to.add(at + COPY), vld1q_u8(from.add(at + COPY)));
            }
            if rest > 3 * COPY {
                vst1q_u8(to.add(at + 2 * COPY), vld1q_u8(from.add(at + 2 * COPY)));
            }
            if rest > 0 {
                vst1q_u8(to.add(width - COPY), vld1q_u8(from.add(width - COPY)));
            }
        }
    }
}

impl Tables {
    #[inline(always)]
    pub(super) fn decode_quads_neon(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> Option<(usize, usize)> {
        let chars = (src.len() / 4).min(dst.len() / 3) * 4;
        if chars < DECODE_QUARTER {
            return None;
        }
        let src = src.as_ptr();
        let dst = dst.as_mut_ptr().cast::<u8>();
        // SAFETY: `chars` is a multiple of 4 with `chars <= src.len()` and
        // `chars / 4 * 3 <= dst.len()`, as `decode_exact` needs; `Flags::load` reads a fixed table.
        Some(unsafe { Flags::load(self).decode_exact(src, chars, dst) })
    }

    #[inline]
    pub(super) fn decode_lines_neon(
        &self,
        shape: LineShape,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        debug_assert!(shape.len <= STAGE);
        if shape.len < DECODE_QUARTER {
            return (0, 0);
        }
        // SAFETY: `src.len() >= shape.stride()` is checked first, so the `ending.len()`
        // bytes that `is_at` reads at `shape.len` are in bounds.
        let at_line_start = src.len() >= shape.stride()
            && unsafe { shape.ending.is_at(src.as_ptr().add(shape.len)) };
        if !at_line_start || !shape.len.is_multiple_of(4) {
            self.decode_lines_compact_neon(shape, src, dst)
        } else if shape.len.is_multiple_of(DECODE_BLOCK) {
            self.decode_lines_direct_neon(shape, src, dst)
        } else {
            self.decode_lines_batched_neon(shape, src, dst)
        }
    }

    #[inline(never)]
    fn decode_lines_direct_neon(
        &self,
        shape: LineShape,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let stride = shape.stride();
        let line_out = shape.len / 4 * 3;
        let blocks = shape.len / DECODE_BLOCK;
        let src_len = src.len();
        let dst_len = dst.len();
        let src_ptr = src.as_ptr();
        let dst_ptr = dst.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        // SAFETY: `shape.len` is a multiple of `DECODE_BLOCK`, so the blocks cover exactly
        // `line[..len]` and `out[..line_out]`; the loop condition checks `read + stride <= src_len`
        // before `is_at` reads the break at `read + len`, and `written + line_out <= dst_len`.
        unsafe {
            let flags = Flags::load(self);
            while read + stride <= src_len
                && written + line_out <= dst_len
                && shape.ending.is_at(src_ptr.add(read + shape.len))
            {
                let line = src_ptr.add(read);
                let out = dst_ptr.add(written);
                let mut all = Validity(vdupq_n_u8(u8::MAX));
                for block in 0..blocks {
                    all = all.and(flags.decode_block(
                        line.add(block * DECODE_BLOCK),
                        out.add(block * DECODE_BLOCK_OUT),
                    ));
                }
                if !all.is_valid() {
                    break;
                }
                read += stride;
                written += line_out;
            }
        }
        (read, written)
    }

    #[inline(never)]
    fn decode_lines_batched_neon(
        &self,
        shape: LineShape,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let len = shape.len;
        let stride = shape.stride();
        let line_out = len / 4 * 3;
        let batch = shape.batch_lines().max(1);
        let src_len = src.len();
        let dst_len = dst.len();
        let src_ptr = src.as_ptr();
        let dst_ptr = dst.as_mut_ptr().cast::<u8>();
        let mut stage = [MaybeUninit::<u8>::uninit(); STAGE];
        let stage_ptr = stage.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        let mut limit = 1;
        // SAFETY: `len <= STAGE`: `LineShape::detect` and `detect_folded` keep it below
        // `MAX_LINE`, as `decode_lines_neon` asserts; `lines <= batch <= STAGE / len` keeps
        // the staged copies in `stage`; `available` bounds the line reads by `src_len` and
        // the decoded output by `dst_len`.
        unsafe {
            let flags = Flags::load(self);
            loop {
                let available = ((src_len - read) / stride)
                    .min((dst_len - written) / line_out)
                    .min(limit);
                let mut lines = 0;
                while lines < available {
                    let line = src_ptr.add(read + lines * stride);
                    if !shape.ending.is_at(line.add(len)) {
                        break;
                    }
                    copy_line(line, stage_ptr.add(lines * len), len);
                    lines += 1;
                }
                if lines == 0 {
                    return (read, written);
                }
                let chars = lines * len;
                let (done, out) = flags.decode_exact(stage_ptr, chars, dst_ptr.add(written));
                written += out;
                if done < chars {
                    return (read + done / len * stride + done % len, written);
                }
                read += lines * stride;
                if lines < limit {
                    return (read, written);
                }
                limit = batch;
            }
        }
    }

    #[inline(never)]
    fn decode_lines_compact_neon(
        &self,
        shape: LineShape,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let len = shape.len;
        let stride = shape.stride();
        let gap = shape.ending.len();
        let unit_shift = 6 - len.trailing_zeros().min(6);
        let per_stage = STAGE / len;
        let src_len = src.len();
        // SAFETY: `src_len >= stride` is checked first, so the `ending.len()` bytes
        // that `is_at` reads at `len` are in bounds.
        let at_line_start =
            src_len >= stride && unsafe { shape.ending.is_at(src.as_ptr().add(len)) };
        let head = if at_line_start {
            Some(len)
        } else {
            memchr::memchr2(b'\r', b'\n', src.get(..len + 1).unwrap_or(src))
        };
        let Some(mut head) = head else {
            return (0, 0);
        };
        let dst_len = dst.len();
        let src_ptr = src.as_ptr();
        let dst_ptr = dst.as_mut_ptr().cast::<u8>();
        let mut stage = [MaybeUninit::<u8>::uninit(); STAGE];
        let stage_ptr = stage.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        let mut probe = true;
        // SAFETY: `len <= STAGE`: `LineShape::detect` and `detect_folded` keep it below
        // `MAX_LINE`, as `decode_lines_neon` asserts; `head <= len` and `most` keep
        // `staged <= STAGE` and `chars <= room`, and each line is read only after
        // `first + (lines + 1) * stride <= src_len`.
        unsafe {
            let flags = Flags::load(self);
            loop {
                let room = (dst_len - written) / 3 * 4;
                if read + head + gap > src_len
                    || head > room.min(STAGE)
                    || !shape.ending.is_at(src_ptr.add(read + head))
                {
                    return (read, written);
                }
                let first = read + head + gap;
                let mut most = if room >= STAGE {
                    per_stage - usize::from(head > 0)
                } else {
                    (room - head) / len
                };
                if probe {
                    most = most.min(1);
                    probe = false;
                } else if head == 0 || head == len {
                    let whole = usize::from(head > 0);
                    let aligned = (most + whole) >> unit_shift << unit_shift;
                    if aligned > 0 {
                        most = aligned - whole;
                    }
                }
                if head > 0 {
                    copy_line(src_ptr.add(read), stage_ptr, head);
                }
                let mut lines = 0;
                while lines < most && first + (lines + 1) * stride <= src_len {
                    let line = src_ptr.add(first + lines * stride);
                    if !shape.ending.is_at(line.add(len)) {
                        break;
                    }
                    copy_line(line, stage_ptr.add(head + lines * len), len);
                    lines += 1;
                }
                let staged = head + lines * len;
                let chars = staged / 4 * 4;
                if chars == 0 {
                    return (read, written);
                }
                let (done, out) = flags.decode_exact(stage_ptr, chars, dst_ptr.add(written));
                written += out;
                if done < chars {
                    let position = match done.checked_sub(head) {
                        Some(past) if past > 0 => first + past / len * stride + past % len,
                        _ => read + done,
                    };
                    return (position, written);
                }
                let end = if lines > 0 {
                    first + (lines - 1) * stride + len
                } else {
                    read + head
                };
                head = staged - chars;
                read = end - head;
            }
        }
    }

    #[inline(always)]
    pub(super) fn encode_groups_neon(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let groups = (src.len() / 3).min(dst.len() / 4);
        let bytes = groups * 3;
        if bytes < ENCODE_QUARTER {
            return (0, 0);
        }
        let src = src.as_ptr();
        let dst = dst.as_mut_ptr().cast::<u8>();
        // SAFETY: `bytes = groups * 3 <= src.len()` and `groups * 4 <= dst.len()`, as
        // `encode_exact` needs; `Symbols::load` reads the fixed 64-byte table.
        unsafe { Symbols::load(self).encode_exact(src, bytes, dst) };
        (bytes, groups * 4)
    }

    #[inline]
    pub(super) fn encode_lines_neon(
        &self,
        wrap: Wrap,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        if wrap.width < COPY || wrap.line_in() < ENCODE_QUARTER {
            (0, 0)
        } else if wrap.line_in().is_multiple_of(ENCODE_BLOCK) {
            self.encode_lines_direct_neon(wrap, src, dst)
        } else {
            self.encode_lines_staged_neon(wrap, src, dst)
        }
    }

    #[inline(never)]
    fn encode_lines_direct_neon(
        &self,
        wrap: Wrap,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let line_in = wrap.line_in();
        let line_out = wrap.line_out();
        let blocks = line_in / ENCODE_BLOCK;
        let src_len = src.len();
        let dst_len = dst.len();
        let src = src.as_ptr();
        let dst = dst.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        // SAFETY: `line_in` is a multiple of `ENCODE_BLOCK`, so the blocks read `line[..line_in]`
        // and write `line_in / 3 * 4 <= width` bytes, the break fills `out[width..line_out]`;
        // the loop keeps `read + line_in <= src_len` and `written + line_out <= dst_len`.
        unsafe {
            let symbols = Symbols::load(self);
            while read + line_in <= src_len && written + line_out <= dst_len {
                let line = src.add(read);
                let out = dst.add(written);
                for block in 0..blocks {
                    symbols.encode_block(
                        line.add(block * ENCODE_BLOCK),
                        out.add(block * ENCODE_BLOCK_OUT),
                    );
                }
                wrap.ending.write_at(out.add(wrap.width));
                read += line_in;
                written += line_out;
            }
        }
        (read, written)
    }

    #[inline(never)]
    fn encode_lines_staged_neon(
        &self,
        wrap: Wrap,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let width = wrap.width;
        let line_in = wrap.line_in();
        let line_out = wrap.line_out();
        if src.len() < 2 * line_in {
            return (0, 0);
        }
        let batch = wrap.batch_lines();
        if batch * width > ENCODE_STAGE {
            return (0, 0);
        }
        let src_len = src.len();
        let dst_len = dst.len();
        let src = src.as_ptr();
        let dst = dst.as_mut_ptr().cast::<u8>();
        let mut stage = [MaybeUninit::<u8>::uninit(); ENCODE_STAGE];
        let stage = stage.as_mut_ptr().cast::<u8>();
        let mut read = 0;
        let mut written = 0;
        // SAFETY: `lines <= batch`, `batch * width <= ENCODE_STAGE` and `width % 4 == 0`
        // (`Base64::wrapped`), so `encode_exact` fills `stage[..lines * width]` from in-bounds
        // `src`; line copies and breaks end at `written + lines * line_out <= dst_len`.
        unsafe {
            let symbols = Symbols::load(self);
            loop {
                let lines = ((src_len - read) / line_in)
                    .min((dst_len - written) / line_out)
                    .min(batch);
                if lines == 0 {
                    return (read, written);
                }
                symbols.encode_exact(src.add(read), lines * line_in, stage);
                for line in 0..lines {
                    let to = dst.add(written + line * line_out);
                    copy_line(stage.add(line * width), to, width);
                    wrap.ending.write_at(to.add(width));
                }
                read += lines * line_in;
                written += lines * line_out;
            }
        }
    }
}
