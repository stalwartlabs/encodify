/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::super::alphabet::Tables;
use std::mem::MaybeUninit;

const SEXTET_OVERFLOW: u8 = 0xc0;

impl Tables {
    #[inline]
    pub(super) fn decode_quads_scalar(
        &self,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> (usize, usize) {
        let decode = &self.decode;
        let mut read = 0;
        let mut written = 0;
        let (octets, _) = src.as_chunks::<8>();
        let (sextets, _) = dst.as_chunks_mut::<6>();
        for (octet, out) in octets.iter().zip(sextets.iter_mut()) {
            let [a, b, c, d, e, f, g, h] = octet.map(|byte| decode[byte as usize] as u64);
            if (a | b | c | d | e | f | g | h) & SEXTET_OVERFLOW as u64 != 0 {
                break;
            }
            let word = (a << 42)
                | (b << 36)
                | (c << 30)
                | (d << 24)
                | (e << 18)
                | (f << 12)
                | (g << 6)
                | h;
            let [_, _, first, second, third, fourth, fifth, sixth] = word.to_be_bytes();
            *out = [first, second, third, fourth, fifth, sixth].map(MaybeUninit::new);
            read += 8;
            written += 6;
        }
        let (quads, _) = src.get(read..).unwrap_or_default().as_chunks::<4>();
        let (triples, _) = dst
            .get_mut(written..)
            .unwrap_or_default()
            .as_chunks_mut::<3>();
        for (quad, triple) in quads.iter().zip(triples.iter_mut()) {
            let [a, b, c, d] = quad.map(|byte| decode[byte as usize]);
            if (a | b | c | d) & SEXTET_OVERFLOW != 0 {
                break;
            }
            let word = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | d as u32;
            let [_, first, second, third] = word.to_be_bytes();
            *triple = [first, second, third].map(MaybeUninit::new);
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
        let encode = &self.encode;
        let mut read = 0;
        let mut written = 0;
        let (sextets, _) = src.as_chunks::<6>();
        let (octets, _) = dst.as_chunks_mut::<8>();
        for (&[a, b, c, d, e, f], out) in sextets.iter().zip(octets.iter_mut()) {
            let word = u64::from_be_bytes([0, 0, a, b, c, d, e, f]);
            *out = [42, 36, 30, 24, 18, 12, 6, 0]
                .map(|shift| MaybeUninit::new(encode[((word >> shift) & 0x3f) as usize]));
            read += 6;
            written += 8;
        }
        let (groups, _) = src.get(read..).unwrap_or_default().as_chunks::<3>();
        let (quads, _) = dst
            .get_mut(written..)
            .unwrap_or_default()
            .as_chunks_mut::<4>();
        for (&[first, second, third], quad) in groups.iter().zip(quads.iter_mut()) {
            let word = ((first as usize) << 16) | ((second as usize) << 8) | third as usize;
            *quad = [18, 12, 6, 0].map(|shift| MaybeUninit::new(encode[(word >> shift) & 0x3f]));
            read += 3;
            written += 4;
        }
        (read, written)
    }
}
