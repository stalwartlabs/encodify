/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

pub(crate) struct XorShift(u64);

impl XorShift {
    pub(crate) fn new(seed: u64) -> Self {
        XorShift(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub(crate) fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }

    pub(crate) fn pick<'x, T>(&mut self, items: &'x [T]) -> &'x T {
        &items[self.below(items.len())]
    }
}

const MIRI_DIVISOR: usize = if cfg!(miri) { 64 } else { 1 };
const LENGTH_STEP: usize = if cfg!(miri) { 11 } else { 1 };

pub(crate) const fn scaled(count: usize) -> usize {
    count.div_ceil(MIRI_DIVISOR)
}

pub(crate) fn lengths(end: usize) -> impl Iterator<Item = usize> {
    (0..end).step_by(LENGTH_STEP)
}
