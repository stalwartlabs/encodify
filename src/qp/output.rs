/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::mem::MaybeUninit;

pub(super) trait Output {
    fn put<const N: usize>(&mut self, at: usize, bytes: [u8; N]);

    fn put_ascii(&mut self, at: usize, bytes: &[u8]);

    fn put_q_text(&mut self, at: usize, bytes: &[u8]);
}

impl Output for [MaybeUninit<u8>] {
    #[inline(always)]
    fn put<const N: usize>(&mut self, at: usize, bytes: [u8; N]) {
        if let Some(slot) = self
            .get_mut(at..)
            .and_then(|rest| rest.first_chunk_mut::<N>())
        {
            *slot = bytes.map(MaybeUninit::new);
        }
    }

    #[inline(always)]
    fn put_ascii(&mut self, at: usize, bytes: &[u8]) {
        for (slot, &byte) in self.get_mut(at..).unwrap_or_default().iter_mut().zip(bytes) {
            slot.write(if byte.is_ascii() { byte } else { b'?' });
        }
    }

    #[inline(always)]
    fn put_q_text(&mut self, at: usize, bytes: &[u8]) {
        for (slot, &byte) in self.get_mut(at..).unwrap_or_default().iter_mut().zip(bytes) {
            slot.write(if byte == b'_' { b' ' } else { byte });
        }
    }
}
