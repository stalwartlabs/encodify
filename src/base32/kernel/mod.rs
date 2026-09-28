/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

#[cfg(encodify_neon)]
mod neon;
pub(crate) mod scalar;
#[cfg(encodify_x86)]
mod x86;

use super::alphabet::Tables;
use std::mem::MaybeUninit;

const SIMD_MIN_INPUT: usize = 16;

impl Tables {
    #[inline]
    pub(crate) fn encode_groups(&self, src: &[u8], dst: &mut [MaybeUninit<u8>]) -> (usize, usize) {
        let (read, written) = self.encode_groups_simd(src, dst);
        let (more_read, more_written) = self.encode_groups_scalar(
            src.get(read..).unwrap_or_default(),
            dst.get_mut(written..).unwrap_or_default(),
        );
        (read + more_read, written + more_written)
    }

    #[inline]
    pub(crate) fn decode_groups(&self, src: &[u8], dst: &mut [MaybeUninit<u8>]) -> (usize, usize) {
        let (read, written) = self.decode_groups_simd(src, dst);
        let (more_read, more_written) = self.decode_groups_scalar(
            src.get(read..).unwrap_or_default(),
            dst.get_mut(written..).unwrap_or_default(),
        );
        (read + more_read, written + more_written)
    }

    #[inline(always)]
    pub(crate) fn numeral(&self, value: u64) -> [u8; 16] {
        #[cfg(encodify_neon)]
        {
            // SAFETY: the `encodify_neon` cfg guarantees NEON is enabled at
            // compile time; the kernel has no other precondition.
            unsafe { self.numeral_neon(value) }
        }
        #[cfg(not(encodify_neon))]
        {
            self.numeral_scalar(value)
        }
    }

    #[inline(always)]
    pub(crate) fn numeral_left(&self, value: u64, start: usize) -> [u8; 16] {
        #[cfg(encodify_neon)]
        {
            // SAFETY: the `encodify_neon` cfg guarantees NEON is enabled at
            // compile time; the kernel has no other precondition.
            unsafe { self.numeral_left_neon(value, start) }
        }
        #[cfg(not(encodify_neon))]
        {
            (u128::from_be_bytes(self.numeral_scalar(value)) << (8 * start)).to_be_bytes()
        }
    }

    #[inline(always)]
    pub(crate) fn parse_numeral(&self, input: &[u8]) -> Option<u64> {
        #[cfg(encodify_neon)]
        {
            if input.len().wrapping_sub(1) >= scalar::NUMERAL_SYMBOLS {
                return None;
            }
            let (high, low) = self.numeral_text_lanes(input);
            // SAFETY: the `encodify_neon` cfg guarantees NEON is enabled at
            // compile time; the kernel takes plain integers and reads no memory.
            unsafe { self.parse_numeral_neon(high, low) }
        }
        #[cfg(not(encodify_neon))]
        {
            self.parse_numeral_scalar(input)
        }
    }

    #[cfg(encodify_neon)]
    #[inline(always)]
    fn numeral_text_lanes(&self, input: &[u8]) -> (u64, u64) {
        let len = input.len();
        let zero = u64::from_ne_bytes([self.encode[0]; 8]);
        if let (Some(head), Some(tail)) = (input.first_chunk::<8>(), input.last_chunk::<8>()) {
            let lanes = ((u64::from_be_bytes(*head) as u128) << (8 * (len - 8)))
                | u64::from_be_bytes(*tail) as u128
                | (u128::from_ne_bytes([self.encode[0]; 16]) << (8 * len));
            ((lanes >> 64) as u64, lanes as u64)
        } else {
            let text = if let (Some(head), Some(tail)) =
                (input.first_chunk::<4>(), input.last_chunk::<4>())
            {
                ((u32::from_be_bytes(*head) as u64) << (8 * (len - 4)))
                    | u32::from_be_bytes(*tail) as u64
            } else {
                input.iter().fold(0, |acc, &byte| (acc << 8) | byte as u64)
            };
            (zero, text | (zero << (8 * len)))
        }
    }

    #[inline]
    fn encode_groups_simd(&self, src: &[u8], dst: &mut [MaybeUninit<u8>]) -> (usize, usize) {
        if src.len() < SIMD_MIN_INPUT {
            return (0, 0);
        }
        #[cfg(encodify_neon)]
        {
            // SAFETY: the `encodify_neon` cfg guarantees NEON is enabled at
            // compile time; the kernel bounds its loads and stores by the slices.
            unsafe { self.encode_groups_neon(src, dst) }
        }
        #[cfg(encodify_x86)]
        {
            if std::is_x86_feature_detected!("ssse3") {
                // SAFETY: SSSE3 was detected at runtime just above; the kernel
                // bounds its loads and stores by the slices.
                unsafe { self.encode_groups_ssse3(src, dst) }
            } else {
                (0, 0)
            }
        }
        #[cfg(not(encodify_simd))]
        {
            let _ = dst;
            (0, 0)
        }
    }

    #[inline]
    fn decode_groups_simd(&self, src: &[u8], dst: &mut [MaybeUninit<u8>]) -> (usize, usize) {
        if src.len() < SIMD_MIN_INPUT {
            return (0, 0);
        }
        #[cfg(encodify_neon)]
        {
            // SAFETY: the `encodify_neon` cfg guarantees NEON is enabled at
            // compile time; the kernel bounds its loads and stores by the slices.
            unsafe { self.decode_groups_neon(src, dst) }
        }
        #[cfg(encodify_x86)]
        {
            if std::is_x86_feature_detected!("ssse3") {
                // SAFETY: SSSE3 was detected at runtime just above; the kernel
                // bounds its loads and stores by the slices.
                unsafe { self.decode_groups_ssse3(src, dst) }
            } else {
                (0, 0)
            }
        }
        #[cfg(not(encodify_simd))]
        {
            let _ = dst;
            (0, 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::alphabet::{STALWART, STANDARD, Tables};
    use crate::test_rng::XorShift;
    use std::mem::MaybeUninit;

    type Groups = fn(&Tables, &[u8], &mut [MaybeUninit<u8>]) -> (usize, usize);

    #[derive(Clone, Copy)]
    struct Kernel(Groups);

    impl Kernel {
        fn run(self, tables: &Tables, src: &[u8], out_len: usize) -> (usize, Vec<u8>) {
            let mut dst = vec![MaybeUninit::new(0u8); out_len];
            let (read, written) = (self.0)(tables, src, &mut dst);
            let out = dst
                .iter()
                .take(written)
                // SAFETY: `dst` was created fully initialised with zeros.
                .map(|byte| unsafe { byte.assume_init() })
                .collect();
            (read, out)
        }
    }

    struct Level {
        name: &'static str,
        encode: Kernel,
        decode: Kernel,
    }

    impl Level {
        fn available() -> Vec<Level> {
            #[cfg_attr(not(encodify_simd), allow(unused_mut))]
            let mut levels = Vec::new();
            #[cfg(encodify_neon)]
            levels.push(Level {
                name: "neon",
                // SAFETY: the `encodify_neon` cfg guarantees NEON at compile time.
                encode: Kernel(|tables, src, dst| unsafe { tables.encode_groups_neon(src, dst) }),
                // SAFETY: the `encodify_neon` cfg guarantees NEON at compile time.
                decode: Kernel(|tables, src, dst| unsafe { tables.decode_groups_neon(src, dst) }),
            });
            #[cfg(encodify_x86)]
            if std::is_x86_feature_detected!("ssse3") {
                levels.push(Level {
                    name: "ssse3",
                    // SAFETY: SSSE3 was detected at runtime before this level is listed.
                    encode: Kernel(|tables, src, dst| unsafe {
                        tables.encode_groups_ssse3(src, dst)
                    }),
                    // SAFETY: SSSE3 was detected at runtime before this level is listed.
                    decode: Kernel(|tables, src, dst| unsafe {
                        tables.decode_groups_ssse3(src, dst)
                    }),
                });
            }
            levels
        }
    }

    #[test]
    fn every_simd_level_matches_the_scalar_kernels() {
        let mut rng = XorShift::new(21);
        let levels = Level::available();
        let scalar = Kernel(Tables::encode_groups_scalar);
        for len in (0..400).chain([1024, 4095, 4096, 4097, 20_000]) {
            let input = rng.bytes(len);
            for tables in [&STANDARD, &STALWART] {
                let (_, encoded) = scalar.run(tables, &input, len * 2);
                for level in &levels {
                    let name = level.name;
                    for slack in [0, 7, 64] {
                        let (read, out) = level.encode.run(tables, &input, len / 5 * 8 + slack);
                        assert_eq!(read % 5, 0, "{name} {len}");
                        assert_eq!(out.len(), read / 5 * 8, "{name} {len}");
                        assert_eq!(Some(&out[..]), encoded.get(..out.len()), "{name} {len}");
                        let (read, out) = level.decode.run(tables, &encoded, len / 5 * 5 + slack);
                        assert_eq!(read % 8, 0, "{name} {len}");
                        assert_eq!(out.len(), read / 8 * 5, "{name} {len}");
                        assert_eq!(Some(&out[..]), input.get(..out.len()), "{name} {len}");
                    }
                    if !encoded.is_empty() {
                        let mut corrupt = encoded.clone();
                        let at = rng.below(corrupt.len());
                        if let Some(byte) = corrupt.get_mut(at) {
                            *byte = *rng.pick(b"=!\x00\xff8");
                        }
                        let (read, out) = level.decode.run(tables, &corrupt, len * 2);
                        assert!(read <= at / 8 * 8, "{name} {len} {at} {read}");
                        assert_eq!(Some(&out[..]), input.get(..out.len()), "{name} {len}");
                    }
                }
            }
        }
    }

    #[test]
    fn numeral_kernels_match_the_scalar_kernels() {
        let mut rng = XorShift::new(22);
        let values: Vec<u64> = (0..64)
            .flat_map(|bits| [(1u64 << bits) - 1, 1 << bits])
            .chain([u64::MAX])
            .chain((0..5000).map(|_| rng.next() >> rng.below(64)))
            .collect();
        for tables in [&STANDARD, &STALWART] {
            for &value in &values {
                let expected = tables.numeral_scalar(value);
                let numeral = tables.numeral(value);
                assert_eq!(numeral.get(3..), expected.get(3..), "{value}");
                for start in 3..16 {
                    let shifted = (u128::from_be_bytes(expected) << (8 * start)).to_be_bytes();
                    let left = tables.numeral_left(value, start);
                    assert_eq!(
                        left.get(..16 - start),
                        shifted.get(..16 - start),
                        "{value} {start}"
                    );
                }
                let count = ((u64::BITS + 4 - (value | 1).leading_zeros()) / 5) as usize;
                let text = expected.get(16 - count..).unwrap_or_default();
                assert_eq!(tables.parse_numeral(text), Some(value), "{value}");
                assert_eq!(tables.parse_numeral_scalar(text), Some(value));
            }
            for _ in 0..20_000 {
                let len = rng.below(16);
                let text: Vec<u8> = (0..len)
                    .map(|_| {
                        if rng.below(8) == 0 {
                            *rng.pick(b"=!\x00\xffAa9")
                        } else {
                            *rng.pick(&tables.encode)
                        }
                    })
                    .collect();
                assert_eq!(
                    tables.parse_numeral(&text),
                    tables.parse_numeral_scalar(&text),
                    "{text:?}"
                );
            }
        }
    }
}
