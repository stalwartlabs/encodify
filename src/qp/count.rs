/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    Mode, QuotedPrintable,
    kernel::{Job, Kernel, LineMasks},
    tables::{ESCAPED, HARD_BREAK, MAX_CONTENT, QpByte, SOFT_BREAK, WordClass},
};
use crate::hex::EscapeTable;

const PER_LINE: usize = MAX_CONTENT / ESCAPED;
const WORD_CHUNK: usize = 1024;
const SAMPLE: usize = 1024;
const MIN_SAMPLED: usize = 2 * SAMPLE;
const FILLER: u8 = b'x';
const MAX_GRANULE: usize = 64;

impl QuotedPrintable {
    /// Exact length of the encoding of `input`.
    pub fn encoded_len(&self, input: impl AsRef<[u8]>) -> usize {
        self.count(input.as_ref(), usize::MAX).unwrap_or(usize::MAX)
    }

    /// Exact length of the encoding of `input` when it is at most `limit`,
    /// or `None` as soon as the encoding is known to be longer. Useful to
    /// choose between quoted-printable and base64 without scanning the whole
    /// input.
    pub fn encoded_len_within(&self, input: impl AsRef<[u8]>, limit: usize) -> Option<usize> {
        self.count(input.as_ref(), limit)
    }

    pub(super) fn line_prefix(&self, text: &str, budget: usize) -> usize {
        match self.mode {
            Mode::Binary => Tally::longest_prefix::<true>(text, budget),
            _ => Tally::longest_prefix::<false>(text, budget),
        }
    }

    pub(super) fn count(&self, input: &[u8], limit: usize) -> Option<usize> {
        if input.len() > limit {
            return None;
        }
        match self.mode {
            Mode::Body => Count::<false> { input, limit }.dispatch(),
            Mode::Binary => Count::<true> { input, limit }.dispatch(),
            mode => WordCount {
                table: mode.table(),
                class: mode.class(),
                input,
                limit,
            }
            .dispatch(),
        }
    }
}

pub(super) struct HighBytes<'x>(pub(super) &'x [u8]);

impl Job for HighBytes<'_> {
    type Output = usize;

    #[inline(always)]
    fn run<K: Kernel>(self) -> usize {
        K::high_bytes(self.0)
    }
}

pub(super) struct WordCount<'x> {
    pub(super) table: &'x EscapeTable,
    pub(super) class: &'x WordClass,
    pub(super) input: &'x [u8],
    pub(super) limit: usize,
}

impl Job for WordCount<'_> {
    type Output = Option<usize>;

    #[inline(always)]
    fn run<K: Kernel>(self) -> Option<usize> {
        let WordCount {
            table,
            class,
            input,
            limit,
        } = self;
        let mut total = 0u64;
        let mut remaining = input.len();
        for chunk in input.chunks(WORD_CHUNK) {
            total += K::word_len(table, class, chunk) as u64;
            remaining -= chunk.len();
            if total + remaining as u64 > limit as u64 {
                return None;
            }
        }
        usize::try_from(total).ok()
    }
}

pub(super) struct Count<'x, const BINARY: bool> {
    pub(super) input: &'x [u8],
    pub(super) limit: usize,
}

impl<const BINARY: bool> Job for Count<'_, BINARY> {
    type Output = Option<usize>;

    #[inline(always)]
    fn run<K: Kernel>(self) -> Option<usize> {
        let Count { input, limit } = self;
        if Self::exceeds_by_high_bytes::<K>(input, limit) {
            return None;
        }
        let mut tally = Tally::default();
        let base = K::scan_lines::<BINARY>(input, |base, masks| {
            tally.scan::<K, BINARY>(input, base, masks);
            tally.total + (input.len() - tally.read) as u64 <= limit as u64
        })?;
        let tail = input.get(base..).unwrap_or_default();
        if !tail.is_empty() {
            let mut padded = [FILLER; MAX_GRANULE];
            for (slot, &byte) in padded.iter_mut().zip(tail) {
                *slot = byte;
            }
            let block = padded.get(..K::GRANULE).unwrap_or_default();
            tally.scan::<K, BINARY>(input, base, K::line_masks::<BINARY>(block));
        }
        tally.line_end(input, input.len());
        usize::try_from(tally.total)
            .ok()
            .filter(|&total| total <= limit)
    }
}

impl<const BINARY: bool> Count<'_, BINARY> {
    #[inline(always)]
    fn exceeds_by_high_bytes<K: Kernel>(input: &[u8], limit: usize) -> bool {
        let len = input.len();
        if len < MIN_SAMPLED || limit >= len.saturating_mul(ESCAPED) {
            return false;
        }
        let mut high = 0;
        let mut scanned = 0;
        for chunk in input.chunks(SAMPLE) {
            high += K::high_bytes(chunk);
            scanned += chunk.len();
            let bound = len as u64 + 2 * high as u64;
            if bound > limit as u64 {
                return true;
            }
            let projected = len as u128 + 2 * high as u128 * len as u128 / scanned as u128;
            if projected <= limit as u128 {
                return false;
            }
        }
        false
    }
}

#[derive(Clone, Copy, Default)]
struct Tally {
    total: u64,
    column: usize,
    read: usize,
}

impl Tally {
    #[inline(always)]
    fn plain(&mut self, count: usize) {
        let end = self.column + count;
        if end <= 2 * MAX_CONTENT {
            let wrapped = usize::from(end > MAX_CONTENT);
            self.column = end - MAX_CONTENT * wrapped;
            self.total += (count + SOFT_BREAK.len() * wrapped) as u64;
        } else {
            let (column, added) = Self::long_plain(self.column, count);
            self.column = column;
            self.total += added;
        }
    }

    #[cold]
    #[inline(never)]
    fn long_plain(column: usize, count: usize) -> (usize, u64) {
        let last = column + count - 1;
        let added = count as u64 + (SOFT_BREAK.len() * (last / MAX_CONTENT)) as u64;
        (last % MAX_CONTENT + 1, added)
    }

    #[inline(always)]
    fn escapes(&mut self, count: usize) {
        let end = self.column + ESCAPED * count;
        if end <= MAX_CONTENT {
            self.column = end;
            self.total += (ESCAPED * count) as u64;
        } else {
            let (column, added) = Self::wrapped_escapes(self.column, count);
            self.column = column;
            self.total += added;
        }
    }

    #[inline(never)]
    fn wrapped_escapes(column: usize, count: usize) -> (usize, u64) {
        let fit = (MAX_CONTENT - column) / ESCAPED;
        let wrapped = count - fit - 1;
        let added = ESCAPED * count + SOFT_BREAK.len() * (1 + wrapped / PER_LINE);
        (ESCAPED * (wrapped % PER_LINE + 1), added as u64)
    }

    #[inline(always)]
    fn line_end(&mut self, input: &[u8], at: usize) {
        let run = at - self.read;
        match input.get(at.wrapping_sub(1)) {
            Some(&byte) if run > 0 && byte.is_blank() => {
                self.plain(run - 1);
                self.escapes(1);
            }
            _ => self.plain(run),
        }
    }

    #[inline(always)]
    fn hard_break(&mut self, input: &[u8], at: usize, len: usize) {
        self.line_end(input, at);
        self.total += HARD_BREAK.len() as u64;
        self.column = 0;
        self.read = at + len;
    }

    fn ending(mut self, input: &[u8], at: usize) -> u64 {
        self.line_end(input, at);
        self.total
    }

    fn longest_prefix<const BINARY: bool>(source: &str, budget: usize) -> usize {
        let text = source.as_bytes();
        let budget = budget as u64;
        let mut tally = Tally::default();
        let mut best = 0;
        let mut at = 0;
        while let Some(&byte) = text.get(at) {
            if source.is_char_boundary(at) && tally.ending(text, at) <= budget {
                best = at;
            }
            if tally.total + (at - tally.read) as u64 > budget {
                return best;
            }
            match (byte, text.get(at + 1)) {
                (b'\n', _) if !BINARY => tally.hard_break(text, at, 1),
                (b'\r', Some(b'\n')) if !BINARY => {
                    let mut bare = tally;
                    bare.plain(at - tally.read);
                    bare.escapes(1);
                    if bare.total <= budget {
                        best = at + 1;
                    }
                    tally.hard_break(text, at, 2);
                }
                _ if byte.needs_escape::<BINARY>() || (!BINARY && byte == b'\r') => {
                    tally.plain(at - tally.read);
                    tally.escapes(1);
                    tally.read = at + 1;
                }
                _ => {}
            }
            at = tally.read.max(at + 1);
        }
        match tally.ending(text, text.len()) <= budget {
            true => text.len(),
            false => best,
        }
    }

    #[inline(always)]
    fn scan<K: Kernel, const BINARY: bool>(&mut self, input: &[u8], base: usize, masks: LineMasks) {
        let escapes = masks.escapes & K::LANE_FLAGS;
        let starts = escapes & !(escapes << K::LANE_BITS);
        let mut events = match BINARY {
            true => starts,
            false => starts | (masks.stops & K::LANE_FLAGS & !escapes),
        };
        if self.read > base {
            let offset = self.read - base;
            events &= match offset < K::GRANULE {
                true => u64::MAX << (offset as u32 * K::LANE_BITS),
                false => 0,
            };
        }
        while events != 0 {
            let first = events & events.wrapping_neg();
            let lane = (first.trailing_zeros() / K::LANE_BITS) as usize;
            let at = base + lane;
            events ^= first;
            if BINARY || escapes & first != 0 {
                let rest = (!escapes & K::LANE_FLAGS) >> (lane as u32 * K::LANE_BITS);
                let run = ((rest.trailing_zeros() / K::LANE_BITS) as usize).min(K::GRANULE - lane);
                self.plain(at - self.read);
                self.escapes(run);
                self.read = at + run;
            } else {
                match input.get(at..) {
                    Some([b'\r', b'\n', ..]) => {
                        self.hard_break(input, at, 2);
                        if lane + 1 < K::GRANULE {
                            events &= events.wrapping_sub(1);
                        }
                    }
                    Some([b'\n', ..]) => self.hard_break(input, at, 1),
                    _ => {
                        self.plain(at - self.read);
                        self.escapes(1);
                        self.read = at + 1;
                    }
                }
            }
        }
    }
}
