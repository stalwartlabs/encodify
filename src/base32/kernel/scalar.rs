/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::super::alphabet::Tables;
use std::mem::MaybeUninit;

pub(crate) const NUMERAL_SYMBOLS: usize = 13;
const PAIR_BITS: u64 = 0x3ff;
const INVALID_BITS: u64 = 0xe0e0_e0e0_e0e0_e0e0;

impl Tables {
    #[inline(always)]
    pub(crate) fn encode_block(&self, bits: u64) -> [u8; 8] {
        let pair = |shift: u32| self.pairs[((bits >> shift) & PAIR_BITS) as usize];
        let [a, b] = pair(30);
        let [c, d] = pair(20);
        let [e, f] = pair(10);
        let [g, h] = pair(0);
        [a, b, c, d, e, f, g, h]
    }

    #[inline(always)]
    pub(crate) fn decode_block(&self, group: &[u8; 8]) -> Option<u64> {
        let [a, b, c, d, e, f, g, h] = group.map(|byte| self.decode[byte as usize] as u64);
        ((a | b | c | d | e | f | g | h) & INVALID_BITS & 0xff == 0).then_some(
            (a << 35) | (b << 30) | (c << 25) | (d << 20) | (e << 15) | (f << 10) | (g << 5) | h,
        )
    }

    #[cfg(any(test, not(encodify_neon)))]
    #[inline(always)]
    pub(super) fn numeral_scalar(&self, value: u64) -> [u8; 16] {
        let mut out = [0u8; 16];
        let (head, tail) = out.split_at_mut(4);
        if let Some(first) = head.last_mut() {
            *first = self.encode[(value >> 60) as usize];
        }
        let (pairs, _) = tail.as_chunks_mut::<2>();
        for (pair, shift) in pairs.iter_mut().zip((0..6).rev()) {
            *pair = self.pairs[((value >> (10 * shift)) & PAIR_BITS) as usize];
        }
        out
    }

    #[cfg(any(test, not(encodify_neon)))]
    #[inline(always)]
    pub(super) fn parse_numeral_scalar(&self, input: &[u8]) -> Option<u64> {
        use super::super::alphabet::INVALID;
        const TOP_SYMBOL_MAX: u8 = 0x0f;
        let (&first, _) = input.split_first()?;
        if input.len() > NUMERAL_SYMBOLS
            || (input.len() == NUMERAL_SYMBOLS && self.decode[first as usize] > TOP_SYMBOL_MAX)
        {
            return None;
        }
        let mut value = 0u64;
        for &byte in input {
            let digit = self.decode[byte as usize];
            if digit == INVALID {
                return None;
            }
            value = (value << 5) | digit as u64;
        }
        Some(value)
    }

    #[inline]
    pub(super) fn encode_groups_scalar(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let (groups, _) = src.as_chunks::<5>();
        let (blocks, _) = dst.as_chunks_mut::<8>();
        let mut count = 0;
        for (&[a, b, c, d, e], block) in groups.iter().zip(blocks.iter_mut()) {
            let bits = u64::from_be_bytes([0, 0, 0, a, b, c, d, e]);
            *block = self.encode_block(bits).map(MaybeUninit::new);
            count += 1;
        }
        (count * 5, count * 8)
    }

    #[cfg(encodify_simd)]
    #[inline]
    pub(super) fn decode_groups_scalar(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let (groups, _) = src.as_chunks::<8>();
        let (blocks, _) = dst.as_chunks_mut::<5>();
        let mut count = 0;
        for (group, block) in groups.iter().zip(blocks.iter_mut()) {
            let Some(bits) = self.decode_block(group) else {
                break;
            };
            let [_, _, _, a, b, c, d, e] = bits.to_be_bytes();
            *block = [a, b, c, d, e].map(MaybeUninit::new);
            count += 1;
        }
        (count * 8, count * 5)
    }

    #[cfg(not(encodify_simd))]
    #[inline(always)]
    fn half(&self, &[a, b, c, d]: &[u8; 4]) -> u32 {
        let [first, second, third, fourth] = &self.halves;
        first[a as usize] | second[b as usize] | third[c as usize] | fourth[d as usize]
    }

    #[cfg(not(encodify_simd))]
    #[inline]
    pub(super) fn decode_groups_scalar(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        use super::super::alphabet::HALF_INVALID;
        let (groups, _) = src.as_chunks::<8>();
        let (blocks, _) = dst.as_chunks_mut::<5>();
        let mut count = 0;
        for (group, block) in groups.iter().zip(blocks.iter_mut()) {
            let (quads, _) = group.as_chunks::<4>();
            let mut halves = [0; 2];
            for (half, quad) in halves.iter_mut().zip(quads) {
                *half = self.half(quad);
            }
            let [first, second] = halves;
            if (first | second) & HALF_INVALID != 0 {
                break;
            }
            let bits = u64::from(first) << 20 | u64::from(second);
            let [_, _, _, a, b, c, d, e] = bits.to_be_bytes();
            *block = [a, b, c, d, e].map(MaybeUninit::new);
            count += 1;
        }
        (count * 8, count * 5)
    }
}
