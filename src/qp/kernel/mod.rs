/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

#[cfg(encodify_neon)]
pub(crate) mod neon;
pub(crate) mod scalar;
#[cfg(encodify_x86)]
pub(crate) mod x86;

use super::tables::WordClass;
use crate::hex::EscapeTable;
use std::mem::MaybeUninit;

#[cfg(encodify_simd)]
const PLAIN_PROLOGUE: usize = 3;
#[cfg(encodify_simd)]
const TEXT_PROLOGUE: usize = 3;

pub(crate) trait Kernel {
    const GRANULE: usize;
    const LANE_BITS: u32;
    const LANE_FLAGS: u64;

    fn copy_text(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize;

    fn decode_escapes(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> (usize, usize);

    fn copy_plain(src: &[u8], dst: &mut [MaybeUninit<u8>], max: usize) -> usize;

    fn encode_escapes<const BINARY: bool>(
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        max: usize,
    ) -> usize;

    fn line_masks<const BINARY: bool>(block: &[u8]) -> LineMasks;

    fn scan_lines<const BINARY: bool>(
        input: &[u8],
        visit: impl FnMut(usize, LineMasks) -> bool,
    ) -> Option<usize>;

    fn high_bytes(src: &[u8]) -> usize;

    fn word_blocks(
        table: &EscapeTable,
        class: &WordClass,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        budget: usize,
    ) -> (usize, usize);

    fn word_len(table: &EscapeTable, class: &WordClass, src: &[u8]) -> usize;
}

#[derive(Clone, Copy, Default)]
pub(crate) struct LineMasks {
    pub(crate) stops: u64,
    pub(crate) escapes: u64,
}

impl LineMasks {
    #[inline(always)]
    fn scan<const N: usize>(
        input: &[u8],
        masks: impl Fn(&[u8; N]) -> LineMasks,
        mut visit: impl FnMut(usize, LineMasks) -> bool,
    ) -> Option<usize> {
        let (granules, _) = input.as_chunks::<N>();
        for (index, granule) in granules.iter().enumerate() {
            let found = masks(granule);
            if found.stops != 0 && !visit(index * N, found) {
                return None;
            }
        }
        Some(granules.len() * N)
    }
}

pub(crate) trait Job: Sized {
    type Output;

    fn run<K: Kernel>(self) -> Self::Output;

    #[inline]
    fn dispatch(self) -> Self::Output {
        #[cfg(encodify_neon)]
        {
            self.run::<neon::Neon>()
        }
        #[cfg(encodify_x86)]
        {
            if cfg!(not(encodify_no_avx2)) && std::is_x86_feature_detected!("avx2") {
                // SAFETY: AVX2 was detected at runtime in the condition just above.
                unsafe { x86::Avx2::run(self) }
            } else {
                self.run::<x86::Sse2>()
            }
        }
        #[cfg(not(encodify_simd))]
        {
            self.run::<scalar::Swar>()
        }
    }
}
