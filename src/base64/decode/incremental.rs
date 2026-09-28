/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::lenient::Quantum;
use crate::{
    base64::{Base64, alphabet::INVALID},
    buffer::SpareCapacity,
};

const CHUNK: usize = 4096;

/// Incremental lenient decoder for input that arrives in pieces or that the
/// caller tokenizes itself.
///
/// [`Decoder::decode_symbols`] consumes alphabet symbols only and hands every
/// other byte back to the caller, who decides whether it is whitespace to
/// skip, padding ([`Decoder::pad`]) or the end of the value. For folded
/// iCalendar and vCard values, [`Base64::decode_folded`] is much faster than
/// feeding the decoder one line at a time.
#[derive(Debug, Clone, Copy)]
pub struct Decoder {
    engine: Base64,
    quantum: Quantum,
}

impl Base64 {
    /// Starts an incremental decoder; see [`Decoder`].
    pub fn decoder(&self) -> Decoder {
        Decoder {
            engine: *self,
            quantum: Quantum::default(),
        }
    }
}

impl Decoder {
    /// Decodes the leading alphabet symbols of `input` into `out` and returns
    /// how many bytes were consumed. Decoding stops at the first byte that is
    /// not a symbol of the engine's alphabet.
    pub fn decode_symbols(&mut self, input: &[u8], out: &mut Vec<u8>) -> usize {
        let tables = self.engine.decode_tables();
        let mut consumed = 0;
        loop {
            let rest = input.get(consumed..).unwrap_or_default();
            let chunk = rest.get(..CHUNK).unwrap_or(rest);
            let mut read = 0;
            // SAFETY: up to 3 pending plus `chunk.len()` symbols decode to at most
            // `chunk.len() / 4 * 3 + 3` bytes, so the region fits every byte that
            // `push` and `decode_quads` count, and all of them are stored.
            unsafe {
                out.append_with(chunk.len() / 4 * 3 + 3, |dst| {
                    let mut written = 0;
                    loop {
                        if self.quantum.is_empty() {
                            let (done, out) = tables.decode_quads(
                                chunk.get(read..).unwrap_or_default(),
                                dst.get_mut(written..).unwrap_or_default(),
                            );
                            read += done;
                            written += out;
                        }
                        let Some(&byte) = chunk.get(read) else {
                            break;
                        };
                        let value = tables.decode[byte as usize];
                        if value == INVALID {
                            break;
                        }
                        written += self.quantum.push(value, dst, written);
                        read += 1;
                    }
                    written
                })
            };
            consumed += read;
            if read < CHUNK {
                return consumed;
            }
        }
    }

    /// Handles a `=`: completes the pending quantum and starts a new one.
    pub fn pad(&mut self, out: &mut Vec<u8>) {
        // SAFETY: the region holds 2 bytes, the most `flush` writes, so it stores every
        // byte it counts.
        unsafe { out.append_with(2, |dst| self.quantum.flush(dst)) };
    }

    /// Completes the pending quantum, as at the end of the input.
    pub fn finish(mut self, out: &mut Vec<u8>) {
        self.pad(out);
    }

    /// Whether the decoder is between quanta.
    pub fn is_aligned(&self) -> bool {
        self.quantum.is_empty()
    }
}
