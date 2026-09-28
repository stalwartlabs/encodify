/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{
    Base32, Padding,
    alphabet::{INVALID, Tables},
    encode::{GROUP, GROUP_SYMBOLS, PAD},
};
use crate::{
    Error,
    buffer::{SpareCapacity, Uninit},
};
use std::mem::MaybeUninit;

const TAIL_BYTES: [usize; GROUP_SYMBOLS] = [0, 0, 1, 1, 2, 3, 3, 4];

struct Layout {
    full: usize,
    body: usize,
    output: usize,
}

impl Layout {
    fn new(input: &[u8]) -> Self {
        let padding = input.iter().rev().take_while(|&&byte| byte == PAD).count();
        let body = input.len() - padding;
        let tail = body % GROUP_SYMBOLS;
        let full = body - tail;
        Layout {
            full,
            body,
            output: full / GROUP_SYMBOLS * GROUP + TAIL_BYTES[tail],
        }
    }
}

struct Tail {
    bits: u64,
    len: usize,
}

impl Tail {
    fn bytes(&self) -> impl Iterator<Item = u8> {
        let bits = self.bits;
        (0..self.len)
            .rev()
            .map(move |index| (bits >> (8 * index)) as u8)
    }
}

impl Base32 {
    /// Upper bound of the decoded length of `input_len` bytes of input.
    pub const fn decoded_len_estimate(&self, input_len: usize) -> usize {
        input_len.div_ceil(GROUP_SYMBOLS).saturating_mul(GROUP)
    }

    /// Decodes `input` into a new `Vec<u8>`.
    pub fn decode(&self, input: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        self.decode_to_vec(input.as_ref())
    }

    /// Appends the decoding of `input` to `out` and returns the number of
    /// bytes appended. On error `out` is left unchanged.
    pub fn decode_append(
        &self,
        input: impl AsRef<[u8]>,
        out: &mut Vec<u8>,
    ) -> Result<usize, Error> {
        self.decode_into_vec(input.as_ref(), out)
    }

    /// Decodes `input` into `out` and returns the number of bytes written.
    pub fn decode_slice(&self, input: impl AsRef<[u8]>, out: &mut [u8]) -> Result<usize, Error> {
        self.decode_into_slice(input.as_ref(), out)
    }

    #[inline]
    fn decode_to_vec(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.decode_into_vec(input, &mut out)?;
        Ok(out)
    }

    fn decode_into_vec(&self, input: &[u8], out: &mut Vec<u8>) -> Result<usize, Error> {
        let layout = Layout::new(input);
        let mut result = Ok(());
        // SAFETY: `decode_into` returns how many leading bytes of `dst` it
        // wrote, and the error path returns 0.
        let written = unsafe {
            out.append_with(layout.output, |dst| {
                match self.decode_into(input, &layout, dst) {
                    Ok(written) => written,
                    Err(err) => {
                        result = Err(err);
                        0
                    }
                }
            })
        };
        result.map(|()| written)
    }

    fn decode_into_slice(&self, input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        // SAFETY: `decode_into` and the kernels only store initialised bytes.
        self.decode_into(input, &Layout::new(input), unsafe { out.as_uninit() })
    }

    fn decode_into(
        &self,
        input: &[u8],
        layout: &Layout,
        dst: &mut [MaybeUninit<u8>],
    ) -> Result<usize, Error> {
        let tables = self.tables();
        let groups = input.get(..layout.full).unwrap_or_default();
        if dst.len() < layout.output {
            if let Some(err) = tables.find_invalid(groups, 0) {
                return Err(err);
            }
            self.strict_tail(input, layout)?;
            return Err(Error::BufferTooSmall {
                required: layout.output,
            });
        }
        let dst = dst.get_mut(..layout.output).unwrap_or_default();
        let (read, written) = tables.decode_groups(groups, dst);
        if read < groups.len() {
            return Err(tables
                .find_invalid(groups, read)
                .unwrap_or(Error::Truncated { offset: read }));
        }
        let tail = self.strict_tail(input, layout)?;
        let region = dst.get_mut(written..).unwrap_or_default();
        Ok(region
            .iter_mut()
            .zip(tail.bytes())
            .fold(written, |written, (slot, byte)| {
                slot.write(byte);
                written + 1
            }))
    }

    fn strict_tail(&self, input: &[u8], layout: &Layout) -> Result<Tail, Error> {
        let tables = self.tables();
        let tail = input.get(layout.full..layout.body).unwrap_or_default();
        let bits = (layout.full..)
            .zip(tail)
            .try_fold(0u64, |bits, (offset, &byte)| {
                tables
                    .symbol(byte, offset)
                    .map(|value| (bits << 5) | value as u64)
            })?;
        let len = match tail.len() {
            0 => 0,
            2 => 1,
            4 => 2,
            5 => 3,
            7 => 4,
            _ => {
                return Err(Error::Truncated {
                    offset: layout.body,
                });
            }
        };
        let padding = input.len() - layout.body;
        let expected = if len == 0 {
            0
        } else {
            GROUP_SYMBOLS - tail.len()
        };
        let padding_ok = match self.padding {
            Padding::Required => padding == expected,
            Padding::Omitted => padding == 0,
            Padding::Optional => padding == 0 || padding == expected,
        };
        if !padding_ok {
            return Err(Error::InvalidPadding {
                offset: layout.body,
            });
        }
        let spare = tail.len() * 5 - len * 8;
        if bits & ((1 << spare) - 1) != 0 {
            return Err(Error::NonCanonical {
                offset: layout.body - 1,
            });
        }
        Ok(Tail {
            bits: bits >> spare,
            len,
        })
    }
}

impl Tables {
    #[inline(always)]
    fn symbol(&self, byte: u8, offset: usize) -> Result<u8, Error> {
        match self.decode[byte as usize] {
            INVALID => Err(Error::unexpected(byte, offset)),
            value => Ok(value),
        }
    }

    fn find_invalid(&self, input: &[u8], from: usize) -> Option<Error> {
        input
            .iter()
            .enumerate()
            .skip(from)
            .find(|(_, byte)| self.decode[**byte as usize] == INVALID)
            .map(|(offset, &byte)| Error::unexpected(byte, offset))
    }
}
