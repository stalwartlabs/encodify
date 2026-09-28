/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    super::tables::{ESCAPE_WORDS, QpByte, WordClass},
    Kernel, LineMasks,
};
use crate::hex::{EscapeTable, decode_pair};
use std::mem::MaybeUninit;

pub(crate) const WORD: usize = 8;
const ESCAPE: usize = 3;

#[derive(Clone, Copy)]
struct Word(u64);

impl Word {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGHS: u64 = 0x8080_8080_8080_8080;
    const LOW7: u64 = 0x7f7f_7f7f_7f7f_7f7f;

    #[inline(always)]
    const fn load(bytes: &[u8; WORD]) -> Self {
        Word(u64::from_le_bytes(*bytes))
    }

    #[inline(always)]
    const fn zero_lanes(value: u64) -> u64 {
        !(((value & Self::LOW7).wrapping_add(Self::LOW7)) | value) & Self::HIGHS
    }

    #[inline(always)]
    const fn equal(self, byte: u8) -> u64 {
        Self::zero_lanes(self.0 ^ (Self::ONES * byte as u64))
    }

    #[inline(always)]
    const fn below(self, bound: u8) -> u64 {
        !((self.0 & Self::LOW7).wrapping_add(Self::ONES * (0x80 - bound) as u64))
            & !self.0
            & Self::HIGHS
    }

    #[inline(always)]
    const fn high(self) -> u64 {
        (((self.0 & Self::LOW7).wrapping_add(Self::ONES)) | self.0) & Self::HIGHS
    }

    #[inline(always)]
    const fn text_stops(self) -> u64 {
        self.equal(b'=') | self.equal(b'\r') | self.equal(b'\n')
    }

    #[inline(always)]
    const fn plain_stops(self) -> u64 {
        self.high() | self.equal(b'=') | (self.below(0x20) & !self.equal(b'\t'))
    }

    #[inline(always)]
    const fn dkim_stops(self) -> u64 {
        self.below(0x21) | self.equal(b';') | self.equal(b'=') | self.equal(0x7f)
    }

    #[inline(always)]
    const fn first_lane(hits: u64) -> usize {
        (hits.trailing_zeros() / 8) as usize
    }

    #[inline(always)]
    const fn high_lanes(self) -> u64 {
        (self.0 >> 7) & Self::ONES
    }

    #[inline(always)]
    const fn lane_sum(lanes: u64) -> usize {
        const PAIRS: u64 = 0x00ff_00ff_00ff_00ff;
        const SHORTS: u64 = 0x0001_0001_0001_0001;
        let pairs = (lanes & PAIRS) + ((lanes >> 8) & PAIRS);
        (pairs.wrapping_mul(SHORTS) >> 48) as usize
    }
}

pub(crate) struct Swar;

impl Swar {
    #[inline(always)]
    const fn is_text_stop(byte: u8) -> bool {
        matches!(byte, b'=' | b'\r' | b'\n')
    }

    #[inline(always)]
    const fn is_plain(byte: u8) -> bool {
        matches!(byte, b'\t' | b' '..=b'<' | b'>'..=b'~')
    }

    #[inline(always)]
    const fn is_dkim_safe(byte: u8) -> bool {
        matches!(byte, 0x21..=0x3a | 0x3c | 0x3e..=0x7e | 0x80..=0xff)
    }

    #[inline(always)]
    pub(crate) fn copy_dkim_safe(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        let mut done = 0;
        let (words, _) = src.as_chunks::<WORD>();
        let (slots, _) = dst.as_chunks_mut::<WORD>();
        for (word, slot) in words.iter().zip(slots.iter_mut()) {
            *slot = word.map(MaybeUninit::new);
            let hits = Word::load(word).dkim_stops();
            if hits != 0 {
                return done + Word::first_lane(hits);
            }
            done += WORD;
        }
        let tail = src.get(done..).unwrap_or_default();
        for (slot, &byte) in dst.get_mut(done..).unwrap_or_default().iter_mut().zip(tail) {
            if !Self::is_dkim_safe(byte) {
                break;
            }
            slot.write(byte);
            done += 1;
        }
        done
    }

    #[inline(always)]
    pub(crate) fn probe_text(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> Option<usize> {
        match src {
            [] => Some(0),
            [first, ..] if Self::is_text_stop(*first) => Some(0),
            [first, rest @ ..] if rest.first().is_none_or(|&next| Self::is_text_stop(next)) => {
                dst.first_mut().map(|slot| {
                    slot.write(*first);
                    1
                })
            }
            _ => None,
        }
    }

    #[inline(always)]
    pub(crate) fn probe_plain(
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        limit: usize,
    ) -> Option<usize> {
        match src {
            [first, ..] if limit == 0 || !Self::is_plain(*first) => Some(0),
            [first, rest @ ..]
                if limit == 1 || rest.first().is_none_or(|&next| !Self::is_plain(next)) =>
            {
                dst.first_mut().map(|slot| {
                    slot.write(*first);
                    1
                })
            }
            [] => Some(0),
            _ => None,
        }
    }

    #[cfg(encodify_simd)]
    #[inline(always)]
    pub(crate) fn copy_text_words<const WORDS: usize>(
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> Result<usize, usize> {
        let (words, _) = src.as_chunks::<WORD>();
        let (slots, _) = dst.as_chunks_mut::<WORD>();
        let mut done = 0;
        for (word, slot) in words.iter().zip(slots.iter_mut()).take(WORDS) {
            *slot = word.map(MaybeUninit::new);
            let hits = Word::load(word).text_stops();
            if hits != 0 {
                return Ok(done + Word::first_lane(hits));
            }
            done += WORD;
        }
        match done == WORDS * WORD {
            true => Err(done),
            false => Ok(done + Self::copy_text_tail(src, dst, done)),
        }
    }

    #[cfg(encodify_simd)]
    #[inline(always)]
    pub(crate) fn copy_plain_words<const WORDS: usize>(
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        limit: usize,
    ) -> Result<usize, usize> {
        let (words, _) = src.get(..limit).unwrap_or(src).as_chunks::<WORD>();
        let (slots, _) = dst.as_chunks_mut::<WORD>();
        let mut done = 0;
        for (word, slot) in words.iter().zip(slots.iter_mut()).take(WORDS) {
            *slot = word.map(MaybeUninit::new);
            let hits = Word::load(word).plain_stops();
            if hits != 0 {
                return Ok(done + Word::first_lane(hits));
            }
            done += WORD;
        }
        match done == WORDS * WORD {
            true => Err(done),
            false => Ok(done + Self::copy_plain_tail(src, dst, done, limit)),
        }
    }

    #[inline(always)]
    fn copy_text_run(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        let mut done = 0;
        let (words, _) = src.as_chunks::<WORD>();
        let (slots, _) = dst.as_chunks_mut::<WORD>();
        for (word, slot) in words.iter().zip(slots.iter_mut()) {
            *slot = word.map(MaybeUninit::new);
            let hits = Word::load(word).text_stops();
            if hits != 0 {
                return done + Word::first_lane(hits);
            }
            done += WORD;
        }
        done + Self::copy_text_tail(src, dst, done)
    }

    #[inline(always)]
    fn copy_text_tail(src: &[u8], dst: &mut [MaybeUninit<u8>], from: usize) -> usize {
        let tail = src.get(from..).unwrap_or_default();
        let mut copied = 0;
        for (slot, &byte) in dst.get_mut(from..).unwrap_or_default().iter_mut().zip(tail) {
            if Self::is_text_stop(byte) {
                break;
            }
            slot.write(byte);
            copied += 1;
        }
        copied
    }

    #[inline(always)]
    fn copy_plain_run(src: &[u8], dst: &mut [MaybeUninit<u8>], limit: usize) -> usize {
        let mut done = 0;
        let (words, _) = src.get(..limit).unwrap_or_default().as_chunks::<WORD>();
        let (slots, _) = dst.as_chunks_mut::<WORD>();
        for (word, slot) in words.iter().zip(slots.iter_mut()) {
            *slot = word.map(MaybeUninit::new);
            let hits = Word::load(word).plain_stops();
            if hits != 0 {
                return done + Word::first_lane(hits);
            }
            done += WORD;
        }
        done + Self::copy_plain_tail(src, dst, done, limit)
    }

    #[inline(always)]
    fn copy_plain_tail(
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        from: usize,
        limit: usize,
    ) -> usize {
        let tail = src.get(from..limit).unwrap_or_default();
        let mut copied = 0;
        for (slot, &byte) in dst.get_mut(from..).unwrap_or_default().iter_mut().zip(tail) {
            if !Self::is_plain(byte) {
                break;
            }
            slot.write(byte);
            copied += 1;
        }
        copied
    }
}

impl Kernel for Swar {
    const GRANULE: usize = WORD;
    const LANE_BITS: u32 = u8::BITS;
    const LANE_FLAGS: u64 = Word::HIGHS;

    #[inline(always)]
    fn copy_text(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> usize {
        Self::probe_text(src, dst).unwrap_or_else(|| Self::copy_text_run(src, dst))
    }

    #[inline(always)]
    fn decode_escapes(src: &[u8], dst: &mut [MaybeUninit<u8>]) -> (usize, usize) {
        let (escapes, _) = src.as_chunks::<ESCAPE>();
        let mut written = 0;
        for (escape, slot) in escapes.iter().zip(dst.iter_mut()) {
            let [b'=', high, low] = *escape else {
                break;
            };
            let Some(byte) = decode_pair(high, low) else {
                break;
            };
            slot.write(byte);
            written += 1;
        }
        (ESCAPE * written, written)
    }

    #[inline(always)]
    fn copy_plain(src: &[u8], dst: &mut [MaybeUninit<u8>], max: usize) -> usize {
        let limit = src.len().min(max);
        Self::probe_plain(src, dst, limit).unwrap_or_else(|| Self::copy_plain_run(src, dst, limit))
    }

    #[inline(always)]
    fn encode_escapes<const BINARY: bool>(
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        max: usize,
    ) -> usize {
        let mut count = 0;
        for (index, &byte) in src.iter().enumerate().take(max) {
            if index > 0 && !byte.needs_escape::<BINARY>() {
                break;
            }
            let [equals, high, low, spare] = ESCAPE_WORDS[byte as usize].to_le_bytes();
            let at = 3 * index;
            match dst
                .get_mut(at..)
                .and_then(|rest| rest.first_chunk_mut::<4>())
            {
                Some(slot) => *slot = [equals, high, low, spare].map(MaybeUninit::new),
                None => match dst
                    .get_mut(at..)
                    .and_then(|rest| rest.first_chunk_mut::<3>())
                {
                    Some(slot) => *slot = [equals, high, low].map(MaybeUninit::new),
                    None => break,
                },
            }
            count += 1;
        }
        count
    }

    #[inline(always)]
    fn line_masks<const BINARY: bool>(block: &[u8]) -> LineMasks {
        let Some(word) = block.first_chunk::<WORD>() else {
            return LineMasks::default();
        };
        let word = Word::load(word);
        let stops = word.plain_stops();
        let escapes = match BINARY {
            true => stops,
            false => stops & !(word.equal(b'\r') | word.equal(b'\n')),
        };
        LineMasks { stops, escapes }
    }

    #[inline(always)]
    fn scan_lines<const BINARY: bool>(
        input: &[u8],
        visit: impl FnMut(usize, LineMasks) -> bool,
    ) -> Option<usize> {
        LineMasks::scan::<WORD>(input, |block| Self::line_masks::<BINARY>(block), visit)
    }

    #[inline(always)]
    fn high_bytes(src: &[u8]) -> usize {
        let (words, tail) = src.as_chunks::<WORD>();
        let high: usize = words
            .chunks(u8::MAX as usize)
            .map(|group| {
                Word::lane_sum(
                    group
                        .iter()
                        .fold(0, |lanes, word| lanes + Word::load(word).high_lanes()),
                )
            })
            .sum();
        high + tail.iter().filter(|&&byte| byte >= 0x80).count()
    }

    #[inline(always)]
    fn word_blocks(
        table: &EscapeTable,
        _: &WordClass,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
        budget: usize,
    ) -> (usize, usize) {
        table.encode_blocks(src, dst, budget)
    }

    #[inline(always)]
    fn word_len(table: &EscapeTable, _: &WordClass, src: &[u8]) -> usize {
        table.encoded_len(src)
    }
}
