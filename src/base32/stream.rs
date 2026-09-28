/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{
    Base32,
    alphabet::{INVALID, Tables},
    encode::{GROUP, GROUP_SYMBOLS, TAIL_SYMBOLS},
};
use crate::Buffer;
use std::{fmt, io, iter::FusedIterator, mem::MaybeUninit, slice};

const BYTE_BITS: u32 = 8;
const SYMBOL_BITS: u32 = 5;
const GROUP_BITS: u32 = 40;

impl Base32 {
    /// Starts a streaming encoder that appends to `out`, which may already
    /// hold a prefix; see [`Encoder`].
    pub fn encoder<'x, B: Buffer>(&self, out: &'x mut B) -> Encoder<'x, B> {
        Encoder {
            out,
            tables: self.tables(),
            pad: self.pads(),
            pending: 0,
            count: 0,
        }
    }

    /// Starts a streaming decoder over `input`; see [`Decoder`].
    pub fn decoder<'x>(&self, input: &'x (impl AsRef<[u8]> + ?Sized)) -> Decoder<'x> {
        Decoder::new(*self, input.as_ref())
    }

    /// Starts a streaming decoder over the bytes that `input` has not yielded
    /// yet, for text that starts with a raw prefix the caller has already
    /// read.
    pub fn decoder_from_iter<'x>(&self, input: slice::Iter<'x, u8>) -> Decoder<'x> {
        Decoder::new(*self, input.as_slice())
    }
}

/// Streaming encoder that appends base32 to a `Vec<u8>` or `String`.
/// Created by [`Base32::encoder`].
///
/// The buffer may already hold text, such as a prefix written before the
/// encoded bytes. Input is encoded in groups of 5 bytes; the last partial
/// group, and the padding if the engine pads, is written by
/// [`Encoder::finish`] or when the encoder is dropped. Writes never fail.
///
/// ```
/// use encodify::base32;
/// use std::io::Write;
///
/// let mut key = String::from("app_");
/// let mut encoder = base32::STALWART.encoder(&mut key);
/// encoder.push(&[0x00, 0x00, 0x00, 0x2a]);
/// encoder.write_all(b"secret")?;
/// encoder.finish();
/// assert_eq!(key, "app_aaaaakttmvrxezlu");
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct Encoder<'x, B: Buffer> {
    out: &'x mut B,
    tables: &'static Tables,
    pad: bool,
    pending: u64,
    count: usize,
}

impl<B: Buffer> Encoder<'_, B> {
    /// Encodes `input`: the infallible form of [`io::Write::write_all`].
    #[inline]
    pub fn push(&mut self, input: &[u8]) {
        if self.count + input.len() < GROUP {
            for &byte in input {
                self.pending = (self.pending << BYTE_BITS) | byte as u64;
            }
            self.count += input.len();
        } else {
            self.push_groups(input);
        }
    }

    /// Writes the last partial group and the padding.
    pub fn finish(mut self) {
        self.flush_tail();
    }

    fn push_groups(&mut self, input: &[u8]) {
        let (head, input) = input
            .split_at_checked((GROUP - self.count) % GROUP)
            .unwrap_or((input, &[]));
        if self.count > 0 {
            for &byte in head {
                self.pending = (self.pending << BYTE_BITS) | byte as u64;
            }
            let block = self.tables.encode_block(self.pending);
            // SAFETY: the closure either commits nothing or writes and commits
            // all 8 slots, each an alphabet symbol (ASCII).
            unsafe {
                self.out.append_ascii(GROUP_SYMBOLS, |dst| {
                    let Some(slots) = dst.first_chunk_mut::<GROUP_SYMBOLS>() else {
                        return 0;
                    };
                    *slots = block.map(MaybeUninit::new);
                    GROUP_SYMBOLS
                })
            };
        }
        let (groups, tail) = input.as_chunks::<GROUP>();
        let groups = groups.as_flattened();
        if !groups.is_empty() {
            let len = groups.len() / GROUP * GROUP_SYMBOLS;
            let tables = self.tables;
            // SAFETY: `encode_groups` returns how many leading bytes it wrote,
            // all alphabet symbols (ASCII).
            unsafe {
                self.out
                    .append_ascii(len, |dst| tables.encode_groups(groups, dst).1)
            };
        }
        self.pending = tail
            .iter()
            .fold(0, |pending, &byte| (pending << BYTE_BITS) | byte as u64);
        self.count = tail.len();
    }

    fn flush_tail(&mut self) {
        if self.count == 0 {
            return;
        }
        let bytes = self.pending.to_be_bytes();
        let tail = bytes.get(bytes.len() - self.count..).unwrap_or_default();
        let (tables, pad) = (self.tables, self.pad);
        let len = if pad {
            GROUP_SYMBOLS
        } else {
            TAIL_SYMBOLS.get(self.count).copied().unwrap_or_default()
        };
        // SAFETY: `encode_tail` returns how many leading bytes it wrote, all
        // alphabet symbols or `=` (ASCII).
        unsafe {
            self.out
                .append_ascii(len, |dst| tables.encode_tail(pad, tail, dst))
        };
        self.pending = 0;
        self.count = 0;
    }
}

impl<B: Buffer> io::Write for Encoder<'_, B> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.push(buf);
        Ok(buf.len())
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.push(buf);
        Ok(())
    }

    /// Does nothing: the last partial group can only be written by
    /// [`Encoder::finish`], since more bytes may follow.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<B: Buffer> Drop for Encoder<'_, B> {
    fn drop(&mut self) {
        self.flush_tail();
    }
}

impl<B: Buffer> fmt::Debug for Encoder<'_, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encoder")
            .field("pad", &self.pad)
            .field("pending", &self.count)
            .finish_non_exhaustive()
    }
}

/// Streaming decoder that yields the bytes encoded in a base32 string.
/// Created by [`Base32::decoder`] and [`Base32::decoder_from_iter`].
///
/// Decoding stops silently at the end of the input or at the first byte that
/// is not a symbol of the engine's alphabet (`=` included), and the unused
/// bits of the last symbol are not checked: a trailing symbol that does not
/// complete a byte is ignored. [`Decoder::remaining`] returns the input that
/// follows the decoded symbols.
///
/// ```
/// use encodify::base32;
///
/// let mut decoder = base32::STALWART.decoder("mfrgg.rest");
/// assert_eq!(decoder.by_ref().collect::<Vec<_>>(), b"abc");
/// assert_eq!(decoder.remaining(), b".rest");
/// ```
#[derive(Debug, Clone)]
pub struct Decoder<'x> {
    engine: Base32,
    input: &'x [u8],
    position: usize,
    bits: u64,
    count: u32,
}

impl<'x> Decoder<'x> {
    fn new(engine: Base32, input: &'x [u8]) -> Self {
        Decoder {
            engine,
            input,
            position: 0,
            bits: 0,
            count: 0,
        }
    }

    /// The input from the first symbol that has not contributed to a decoded
    /// byte. After the decoder has returned `None`, this is any trailing
    /// symbols too few to complete a byte, then the byte that stopped it and
    /// everything after it.
    pub fn remaining(&self) -> &'x [u8] {
        self.input
            .get(
                self.position
                    .saturating_sub((self.count / SYMBOL_BITS) as usize)..,
            )
            .unwrap_or_default()
    }
}

impl Iterator for Decoder<'_> {
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<u8> {
        if self.count < BYTE_BITS {
            let (bits, symbols) =
                self.engine
                    .tables()
                    .read_symbols(self.input, self.position, self.bits, self.count);
            self.bits = bits;
            self.position += symbols;
            self.count += SYMBOL_BITS * symbols as u32;
            if self.count < BYTE_BITS {
                return None;
            }
        }
        self.count -= BYTE_BITS;
        Some((self.bits >> self.count) as u8)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let symbols = self.input.len().saturating_sub(self.position);
        let bits = self.count as usize + symbols * SYMBOL_BITS as usize;
        (0, Some(bits / BYTE_BITS as usize))
    }
}

impl FusedIterator for Decoder<'_> {}

impl Tables {
    #[inline(never)]
    fn read_symbols(&self, input: &[u8], position: usize, bits: u64, count: u32) -> (u64, usize) {
        let rest = input.get(position..).unwrap_or_default();
        if let Some(block) = rest
            .first_chunk::<GROUP_SYMBOLS>()
            .and_then(|group| self.decode_block(group))
        {
            return ((bits << GROUP_BITS) | block, GROUP_SYMBOLS);
        }
        let mut bits = bits;
        let mut count = count;
        let mut symbols = 0;
        for &byte in rest {
            let value = self.decode[byte as usize];
            if value == INVALID || count >= BYTE_BITS {
                break;
            }
            bits = (bits << SYMBOL_BITS) | value as u64;
            count += SYMBOL_BITS;
            symbols += 1;
        }
        (bits, symbols)
    }
}
