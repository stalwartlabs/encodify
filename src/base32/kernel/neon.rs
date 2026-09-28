/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::super::alphabet::{Nibbles, Tables};
use core::arch::aarch64::*;
use std::mem::MaybeUninit;

const ENCODE_STEP: usize = 10;
const ENCODE_STEP_OUT: usize = 16;
const ENCODE_LOAD: usize = 16;
const ENCODE_BLOCK: usize = 4 * ENCODE_STEP;
const ENCODE_BLOCK_OUT: usize = 4 * ENCODE_STEP_OUT;
const ENCODE_BLOCK_LOAD: usize = 3 * ENCODE_STEP + ENCODE_LOAD;
const DECODE_STEP: usize = 16;
const DECODE_STEP_OUT: usize = 10;
const DECODE_STORE: usize = 16;
const DECODE_BLOCK: usize = 4 * DECODE_STEP;
const DECODE_BLOCK_OUT: usize = 4 * DECODE_STEP_OUT;
const DECODE_BLOCK_STORE: usize = 3 * DECODE_STEP_OUT + DECODE_STORE;

const GATHER_FIRST: [u8; 16] = [1, 0, 1, 0, 2, 1, 2, 1, 3, 2, 4, 3, 4, 3, 5, 4];
const GATHER_SECOND: [u8; 16] = [6, 5, 6, 5, 7, 6, 7, 6, 8, 7, 9, 8, 9, 8, 10, 9];
const GROUP_SHIFTS: [i16; 8] = [-11, -6, -9, -4, -7, -10, -5, -8];
const EXTRACT: [u8; 16] = [
    4, 3, 2, 1, 0, 12, 11, 10, 9, 8, 255, 255, 255, 255, 255, 255,
];
const NUMERAL_GATHER_HIGH: [u8; 16] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 7, 0xff, 6, 7, 6, 7, 5, 6, 5, 6,
];
const NUMERAL_GATHER_LOW: [u8; 16] = [4, 5, 3, 4, 3, 4, 2, 3, 1, 2, 1, 2, 0, 1, 0, 1];
const NUMERAL_SHIFTS_HIGH: [i16; 8] = [0, 0, 0, -4, -7, -2, -5, 0];
const NUMERAL_SHIFTS_LOW: [i16; 8] = [-3, -6, -1, -4, -7, -2, -5, 0];
const LANES: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const SYMBOL_MASK: u8 = 0x1f;
const LOW_NIBBLE: u8 = 0x0f;

trait Load {
    type Vector;

    fn load(&self) -> Self::Vector;
}

impl Load for [u8; 16] {
    type Vector = uint8x16_t;

    #[inline(always)]
    fn load(&self) -> uint8x16_t {
        // SAFETY: the `encodify_neon` cfg guarantees NEON, and the load reads
        // exactly the 16 bytes of `self`.
        unsafe { vld1q_u8(self.as_ptr()) }
    }
}

impl Load for [u8; 32] {
    type Vector = uint8x16x2_t;

    #[inline(always)]
    fn load(&self) -> uint8x16x2_t {
        // SAFETY: the `encodify_neon` cfg guarantees NEON, and the load reads
        // exactly the 32 bytes of `self`.
        unsafe { vld1q_u8_x2(self.as_ptr()) }
    }
}

impl Load for [i16; 8] {
    type Vector = int16x8_t;

    #[inline(always)]
    fn load(&self) -> int16x8_t {
        // SAFETY: the `encodify_neon` cfg guarantees NEON, and the load reads
        // exactly the eight `i16` lanes of `self`.
        unsafe { vld1q_s16(self.as_ptr()) }
    }
}

struct Spread {
    symbols: uint8x16x2_t,
    first: uint8x16_t,
    second: uint8x16_t,
    shifts: int16x8_t,
    mask: uint8x16_t,
}

impl Spread {
    #[inline]
    #[target_feature(enable = "neon")]
    fn new(tables: &Tables) -> Self {
        Spread {
            symbols: tables.encode.load(),
            first: GATHER_FIRST.load(),
            second: GATHER_SECOND.load(),
            shifts: GROUP_SHIFTS.load(),
            mask: vdupq_n_u8(SYMBOL_MASK),
        }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn encode(&self, bytes: uint8x16_t) -> uint8x16_t {
        let first = vshlq_u16(
            vreinterpretq_u16_u8(vqtbl1q_u8(bytes, self.first)),
            self.shifts,
        );
        let second = vshlq_u16(
            vreinterpretq_u16_u8(vqtbl1q_u8(bytes, self.second)),
            self.shifts,
        );
        let values = vandq_u8(
            vuzp1q_u8(vreinterpretq_u8_u16(first), vreinterpretq_u8_u16(second)),
            self.mask,
        );
        vqtbl2q_u8(self.symbols, values)
    }
}

struct Lookup {
    low_mask: uint8x16_t,
    high_mask: uint8x16_t,
    low_value: uint8x16_t,
    roll: uint8x16_t,
    low_nibble: uint8x16_t,
    extract: uint8x16_t,
}

impl Lookup {
    #[inline]
    #[target_feature(enable = "neon")]
    fn new(nibbles: &Nibbles) -> Self {
        Lookup {
            low_mask: nibbles.low_mask.load(),
            high_mask: nibbles.high_mask.load(),
            low_value: nibbles.low_value.load(),
            roll: vdupq_n_u8(nibbles.roll),
            low_nibble: vdupq_n_u8(LOW_NIBBLE),
            extract: EXTRACT.load(),
        }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn values(&self, chars: uint8x16_t, bad: &mut uint8x16_t) -> uint8x16_t {
        let low = vandq_u8(chars, self.low_nibble);
        let high = vshrq_n_u8::<4>(chars);
        *bad = vorrq_u8(
            *bad,
            vandq_u8(
                vqtbl1q_u8(self.low_mask, low),
                vqtbl1q_u8(self.high_mask, high),
            ),
        );
        vminq_u8(vqtbl1q_u8(self.low_value, low), vaddq_u8(chars, self.roll))
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn pack(&self, values: uint8x16_t) -> uint8x16_t {
        let pairs = vreinterpretq_u16_u8(values);
        let pairs = vsliq_n_u16::<5>(vshrq_n_u16::<8>(pairs), pairs);
        let quads = vreinterpretq_u32_u16(pairs);
        let quads = vsliq_n_u32::<10>(vshrq_n_u32::<16>(quads), quads);
        let words = vreinterpretq_u64_u32(quads);
        let words = vsliq_n_u64::<20>(vshrq_n_u64::<32>(words), words);
        vqtbl1q_u8(vreinterpretq_u8_u64(words), self.extract)
    }
}

#[derive(Clone, Copy)]
struct Numeral(uint8x16_t);

impl Numeral {
    #[inline]
    #[target_feature(enable = "neon")]
    fn shifted(self, start: usize) -> Self {
        let lanes = vaddq_u8(LANES.load(), vdupq_n_u8(start as u8));
        Numeral(vqtbl1q_u8(self.0, lanes))
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        // SAFETY: the store writes exactly the 16 bytes of `out`.
        unsafe { vst1q_u8(out.as_mut_ptr(), self.0) };
        out
    }
}

impl Tables {
    #[target_feature(enable = "neon")]
    pub(super) fn encode_groups_neon(
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
        // SAFETY: the loop guards keep every access in bounds: the block reads
        // `src[read..read + 46]` and writes `dst[written..written + 64]`, the
        // step reads 16 and writes 16; `u8` stores into `MaybeUninit<u8>` are valid.
        unsafe {
            while read + ENCODE_BLOCK_LOAD <= src_len && written + ENCODE_BLOCK_OUT <= dst_len {
                let from = src.add(read);
                let symbols = uint8x16x4_t(
                    spread.encode(vld1q_u8(from)),
                    spread.encode(vld1q_u8(from.add(ENCODE_STEP))),
                    spread.encode(vld1q_u8(from.add(2 * ENCODE_STEP))),
                    spread.encode(vld1q_u8(from.add(3 * ENCODE_STEP))),
                );
                vst1q_u8_x4(dst.add(written), symbols);
                read += ENCODE_BLOCK;
                written += ENCODE_BLOCK_OUT;
            }
            while read + ENCODE_LOAD <= src_len && written + ENCODE_STEP_OUT <= dst_len {
                vst1q_u8(dst.add(written), spread.encode(vld1q_u8(src.add(read))));
                read += ENCODE_STEP;
                written += ENCODE_STEP_OUT;
            }
        }
        (read, written)
    }

    #[target_feature(enable = "neon")]
    pub(super) fn decode_groups_neon(
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
        // SAFETY: the loop guards keep every access in bounds: the block reads
        // `src[read..read + 64]` and writes `dst[written..written + 46]`, the
        // step reads 16 and writes 16; `u8` stores into `MaybeUninit<u8>` are valid.
        unsafe {
            while read + DECODE_BLOCK <= src_len && written + DECODE_BLOCK_STORE <= dst_len {
                let chars = vld1q_u8_x4(src.add(read));
                let mut bad = vdupq_n_u8(0);
                let first = lookup.values(chars.0, &mut bad);
                let second = lookup.values(chars.1, &mut bad);
                let third = lookup.values(chars.2, &mut bad);
                let fourth = lookup.values(chars.3, &mut bad);
                if vmaxvq_u8(bad) != 0 {
                    return (read, written);
                }
                let to = dst.add(written);
                vst1q_u8(to, lookup.pack(first));
                vst1q_u8(to.add(DECODE_STEP_OUT), lookup.pack(second));
                vst1q_u8(to.add(2 * DECODE_STEP_OUT), lookup.pack(third));
                vst1q_u8(to.add(3 * DECODE_STEP_OUT), lookup.pack(fourth));
                read += DECODE_BLOCK;
                written += DECODE_BLOCK_OUT;
            }
            while read + DECODE_STEP <= src_len && written + DECODE_STORE <= dst_len {
                let mut bad = vdupq_n_u8(0);
                let values = lookup.values(vld1q_u8(src.add(read)), &mut bad);
                if vmaxvq_u8(bad) != 0 {
                    return (read, written);
                }
                vst1q_u8(dst.add(written), lookup.pack(values));
                read += DECODE_STEP;
                written += DECODE_STEP_OUT;
            }
        }
        (read, written)
    }

    #[inline]
    #[target_feature(enable = "neon")]
    pub(super) fn numeral_neon(&self, value: u64) -> [u8; 16] {
        self.numeral_lanes(value).to_bytes()
    }

    #[inline]
    #[target_feature(enable = "neon")]
    pub(super) fn numeral_left_neon(&self, value: u64, start: usize) -> [u8; 16] {
        self.numeral_lanes(value).shifted(start).to_bytes()
    }

    #[inline]
    #[target_feature(enable = "neon")]
    pub(super) fn parse_numeral_neon(&self, high: u64, low: u64) -> Option<u64> {
        let chars = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(low), vcreate_u64(high)));
        let mut bad = vdupq_n_u8(0);
        let values = Lookup::new(&self.nibbles).values(chars, &mut bad);
        if vmaxvq_u8(bad) != 0 {
            return None;
        }
        let pairs = vreinterpretq_u16_u8(values);
        let pairs = vsliq_n_u16::<5>(pairs, vshrq_n_u16::<8>(pairs));
        let quads = vreinterpretq_u32_u16(pairs);
        let quads = vsliq_n_u32::<10>(quads, vshrq_n_u32::<16>(quads));
        let words = vreinterpretq_u64_u32(quads);
        let words = vsliq_n_u64::<20>(words, vshrq_n_u64::<32>(words));
        let low = vgetq_lane_u64::<0>(words);
        let high = vgetq_lane_u64::<1>(words);
        (high >> 24 == 0).then_some((high << 40) | low)
    }

    #[inline]
    #[target_feature(enable = "neon")]
    fn numeral_lanes(&self, value: u64) -> Numeral {
        let source = vreinterpretq_u8_u64(vdupq_n_u64(value));
        let high = vshlq_u16(
            vreinterpretq_u16_u8(vqtbl1q_u8(source, NUMERAL_GATHER_HIGH.load())),
            NUMERAL_SHIFTS_HIGH.load(),
        );
        let low = vshlq_u16(
            vreinterpretq_u16_u8(vqtbl1q_u8(source, NUMERAL_GATHER_LOW.load())),
            NUMERAL_SHIFTS_LOW.load(),
        );
        let values = vandq_u8(
            vuzp1q_u8(vreinterpretq_u8_u16(high), vreinterpretq_u8_u16(low)),
            vdupq_n_u8(SYMBOL_MASK),
        );
        Numeral(vqtbl2q_u8(self.encode.load(), values))
    }
}
