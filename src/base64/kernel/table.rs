/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::super::alphabet::{TRIPLE_BITS, Tables};
use std::mem::MaybeUninit;

const PAIR_BITS: u32 = 12;
const PAIR_MASK: u64 = (1 << PAIR_BITS) - 1;
const BLOCK_CHARS: usize = 16;
const BLOCK_BYTES: usize = 12;
#[cfg(target_pointer_width = "64")]
const GROUP_BYTES: usize = 24;
#[cfg(target_pointer_width = "64")]
const GROUP_CHARS: usize = 32;

impl Tables {
    #[inline(always)]
    fn triple(&self, &[a, b, c, d]: &[u8; 4]) -> u32 {
        let [first, second, third, fourth] = &self.triples;
        first[a as usize] | second[b as usize] | third[c as usize] | fourth[d as usize]
    }

    #[inline(always)]
    fn pair(&self, word: u64, shift: u32) -> u64 {
        u64::from(self.pairs[(word >> shift & PAIR_MASK) as usize])
    }

    #[cfg(target_pointer_width = "64")]
    #[inline(always)]
    fn sextets(&self, word: u64) -> [u8; 8] {
        (self.pair(word, 52)
            | self.pair(word, 40) << 16
            | self.pair(word, 28) << 32
            | self.pair(word, 16) << 48)
            .to_le_bytes()
    }

    #[inline]
    pub(super) fn decode_quads_scalar(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let mut read = 0;
        let mut written = 0;
        let (blocks, _) = src.as_chunks::<BLOCK_CHARS>();
        let (outs, _) = dst.as_chunks_mut::<BLOCK_BYTES>();
        for (block, out) in blocks.iter().zip(outs) {
            let (quads, _) = block.as_chunks::<4>();
            let mut triples = [0; BLOCK_CHARS / 4];
            for (triple, quad) in triples.iter_mut().zip(quads) {
                *triple = self.triple(quad);
            }
            let [first, second, third, fourth] = triples;
            if (first | second | third | fourth) >> TRIPLE_BITS != 0 {
                break;
            }
            let words = [first, second, third, third >> 16 | fourth << 8];
            for (word, at) in words.into_iter().zip([0, 3, 6, 8]) {
                if let Some(slot) = out
                    .get_mut(at..)
                    .and_then(<[MaybeUninit<u8>]>::first_chunk_mut::<4>)
                {
                    *slot = word.to_le_bytes().map(MaybeUninit::new);
                }
            }
            read += BLOCK_CHARS;
            written += BLOCK_BYTES;
        }
        let (quads, _) = src.get(read..).unwrap_or_default().as_chunks::<4>();
        let (outs, _) = dst
            .get_mut(written..)
            .unwrap_or_default()
            .as_chunks_mut::<3>();
        for (quad, out) in quads.iter().zip(outs) {
            let triple = self.triple(quad);
            if triple >> TRIPLE_BITS != 0 {
                break;
            }
            let [first, second, third, _] = triple.to_le_bytes();
            *out = [first, second, third].map(MaybeUninit::new);
            read += 4;
            written += 3;
        }
        (read, written)
    }

    #[inline]
    pub(super) fn encode_groups_scalar(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let mut read = 0;
        let mut written = 0;
        #[cfg(target_pointer_width = "64")]
        {
            let (groups, _) = src.as_chunks::<GROUP_BYTES>();
            let (outs, _) = dst.as_chunks_mut::<GROUP_CHARS>();
            for (group, out) in groups.iter().zip(outs) {
                let (octets, _) = out.as_chunks_mut::<8>();
                let words = [0, 6, 12, 16].map(|start| {
                    group
                        .get(start..)
                        .and_then(<[u8]>::first_chunk::<8>)
                        .map_or(0, |bytes| u64::from_be_bytes(*bytes))
                });
                let [first, second, third, fourth] = words;
                for (octet, word) in octets.iter_mut().zip([first, second, third, fourth << 16]) {
                    *octet = self.sextets(word).map(MaybeUninit::new);
                }
                read += GROUP_BYTES;
                written += GROUP_CHARS;
            }
        }
        let (groups, _) = src.get(read..).unwrap_or_default().as_chunks::<3>();
        let (quads, _) = dst
            .get_mut(written..)
            .unwrap_or_default()
            .as_chunks_mut::<4>();
        for (&[first, second, third], quad) in groups.iter().zip(quads) {
            let word = u64::from(u32::from_be_bytes([0, first, second, third]));
            let chars = self.pair(word, PAIR_BITS) | self.pair(word, 0) << 16;
            *quad = (chars as u32).to_le_bytes().map(MaybeUninit::new);
            read += 3;
            written += 4;
        }
        (read, written)
    }
}
