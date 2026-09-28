/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{SHIFT_END, Utf7};
use crate::Buffer;
use std::mem::MaybeUninit;

const BOUNDED_CAPACITY_LEN: usize = 64;

impl Utf7 {
    fn split_direct<'x>(&self, text: &'x str) -> (&'x str, &'x str) {
        let bytes = text.as_bytes();
        if self.imap && self.is_all_direct(bytes) {
            (text, "")
        } else {
            text.split_at(self.direct_len(bytes))
        }
    }

    #[inline(always)]
    fn shifted_len(&self, bytes: &[u8]) -> usize {
        bytes
            .iter()
            .position(|&byte| byte == self.shift() || self.is_direct(byte))
            .unwrap_or(bytes.len())
    }

    pub(super) const fn max_encoded_len(text_len: usize) -> usize {
        text_len.saturating_mul(7).div_ceil(2).saturating_add(1)
    }

    fn capacity(&self, direct: &str, rest: &str) -> usize {
        direct.len()
            + match rest.len() {
                0 => 0,
                len if len <= BOUNDED_CAPACITY_LEN => Self::max_encoded_len(len),
                _ => self.encoded_len(rest),
            }
    }

    /// Encodes `text`.
    pub fn encode(&self, text: &str) -> String {
        let (direct, rest) = self.split_direct(text);
        if rest.is_empty() {
            return direct.to_owned();
        }
        let mut out = String::new();
        self.append_encoded(direct, rest, &mut out);
        out
    }

    /// Appends the encoding of `text` to `out` and returns the number of bytes
    /// appended.
    pub fn encode_append(&self, text: &str, out: &mut impl Buffer) -> usize {
        let (direct, rest) = self.split_direct(text);
        self.append_encoded(direct, rest, out)
    }

    fn append_encoded(&self, direct: &str, rest: &str, out: &mut impl Buffer) -> usize {
        #[allow(unsafe_code)]
        // SAFETY: `SliceWriter::len` counts only slots it wrote, and every byte
        // is ASCII: direct characters, the shift byte, `-` or base64 symbols.
        unsafe {
            out.append_ascii(self.capacity(direct, rest), |dst| {
                let mut writer = SliceWriter { dst, len: 0 };
                writer.extend(direct.as_bytes());
                self.encode_into(rest, &mut writer);
                writer.len
            })
        }
    }

    /// Length of the encoding of `text`.
    pub fn encoded_len(&self, text: &str) -> usize {
        let mut counter = Counter(0);
        self.encode_into(text, &mut counter);
        counter.0
    }

    fn encode_into(&self, text: &str, sink: &mut impl Sink) {
        let shift = self.shift();
        let mut rest = text;
        loop {
            let (direct, tail) = rest.split_at(self.direct_len(rest.as_bytes()));
            sink.extend(direct.as_bytes());
            rest = match tail.as_bytes() {
                [] => break,
                [first, ..] if *first == shift => {
                    sink.extend(&[shift, SHIFT_END]);
                    tail.split_at(1).1
                }
                _ => {
                    let (run, tail) = tail.split_at(self.shifted_len(tail.as_bytes()));
                    self.encode_run(run, sink);
                    tail
                }
            };
        }
    }

    fn encode_run(&self, run: &str, sink: &mut impl Sink) {
        let symbols = &self.tables().encode;
        sink.push(self.shift());
        let mut units = run.encode_utf16().map(u64::from);
        while let Some(first) = units.next() {
            let second = units.next();
            let third = units.next();
            let group = first << 32 | second.unwrap_or(0) << 16 | third.unwrap_or(0);
            let encoded = [42, 36, 30, 24, 18, 12, 6, 0]
                .map(|shift| symbols[(group >> shift & 0x3f) as usize]);
            let len = match (second, third) {
                (None, _) => 3,
                (_, None) => 6,
                _ => 8,
            };
            sink.extend(encoded.get(..len).unwrap_or_default());
        }
        sink.push(SHIFT_END);
    }
}

trait Sink {
    fn push(&mut self, byte: u8);
    fn extend(&mut self, bytes: &[u8]);
}

struct Counter(usize);

impl Sink for Counter {
    fn push(&mut self, _: u8) {
        self.0 += 1;
    }

    fn extend(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }
}

struct SliceWriter<'x> {
    dst: &'x mut [MaybeUninit<u8>],
    len: usize,
}

impl Sink for SliceWriter<'_> {
    fn push(&mut self, byte: u8) {
        if let Some(slot) = self.dst.get_mut(self.len) {
            slot.write(byte);
            self.len += 1;
        }
    }

    fn extend(&mut self, bytes: &[u8]) {
        if let Some(slots) = self.dst.get_mut(self.len..) {
            for (slot, &byte) in slots.iter_mut().zip(bytes) {
                slot.write(byte);
            }
        }
        self.len = (self.len + bytes.len()).min(self.dst.len());
    }
}
