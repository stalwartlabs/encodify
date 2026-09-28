/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{CHUNK, CHUNK_OUT};
use crate::{
    Error,
    base64::{
        Base64, Padding,
        alphabet::{INVALID, Tables},
    },
};
use std::mem::MaybeUninit;

const SEXTET_OVERFLOW: u8 = 0xc0;

pub(super) struct Layout {
    pub(super) full: usize,
    tail: usize,
    body: usize,
    output: usize,
}

impl Layout {
    pub(super) fn of(input: &[u8]) -> Self {
        let padding = input.iter().rev().take_while(|&&byte| byte == b'=').count();
        let body = input.len() - padding;
        let tail = body % 4;
        let full = body - tail;
        let output = full / 4 * 3
            + match tail {
                2 => 1,
                3 => 2,
                _ => 0,
            };
        Layout {
            full,
            tail,
            body,
            output,
        }
    }
}

impl Padding {
    #[inline(always)]
    const fn accepts(self, padding: usize, expected: usize) -> bool {
        match self {
            Padding::Required => padding == expected,
            Padding::Omitted => padding == 0,
            Padding::Optional => padding == 0 || padding == expected,
        }
    }
}

impl Base64 {
    #[inline(always)]
    pub(super) fn decode_strict(
        &self,
        input: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> Result<usize, Error> {
        match self.decode_strict_fast(input, dst) {
            Some(written) => Ok(written),
            None => Err(self.strict_error(input)),
        }
    }

    #[inline(always)]
    fn decode_strict_fast(&self, input: &[u8], dst: &mut [MaybeUninit<u8>]) -> Option<usize> {
        let padding = match input {
            [.., b'=', b'='] => 2,
            [.., b'='] => 1,
            _ => 0,
        };
        let body = input.len() - padding;
        let tail = body % 4;
        let expected = match tail {
            0 => 0,
            2 => 2,
            3 => 1,
            _ => return None,
        };
        let full = body - tail;
        let output = full / 4 * 3 + tail * 3 / 4;
        if !self.padding.accepts(padding, expected) {
            return None;
        }
        let dst = dst.get_mut(..output)?;
        let tables = self.decode_tables();
        let (read, written) = tables.decode_quads(input.get(..full)?, dst);
        if read < full {
            return None;
        }
        let decode = &tables.decode;
        match *input.get(full..body)? {
            [] => {}
            [first, second] => {
                let (first, second) = (decode[first as usize], decode[second as usize]);
                if (first | second) & SEXTET_OVERFLOW != 0 || second & 0x0f != 0 {
                    return None;
                }
                dst.get_mut(written)?.write((first << 2) | (second >> 4));
            }
            [first, second, third] => {
                let (first, second, third) = (
                    decode[first as usize],
                    decode[second as usize],
                    decode[third as usize],
                );
                if (first | second | third) & SEXTET_OVERFLOW != 0 || third & 0x03 != 0 {
                    return None;
                }
                let [low, high] = dst.get_mut(written..written + 2)? else {
                    return None;
                };
                low.write((first << 2) | (second >> 4));
                high.write((second << 4) | (third >> 2));
            }
            _ => return None,
        }
        Some(output)
    }

    #[cold]
    #[inline(never)]
    fn strict_error(&self, input: &[u8]) -> Error {
        match self.check_strict(input) {
            Err(err) => err,
            Ok(required) => Error::BufferTooSmall { required },
        }
    }

    pub(super) fn check_strict(&self, input: &[u8]) -> Result<usize, Error> {
        let layout = Layout::of(input);
        let tables = self.decode_tables();
        let mut scratch = [MaybeUninit::uninit(); CHUNK_OUT];
        let quads = input.get(..layout.full).unwrap_or_default();
        let mut offset = 0;
        for chunk in quads.chunks(CHUNK) {
            let (read, _) = tables.decode_quads(chunk, &mut scratch);
            if read < chunk.len() {
                return Err(tables.first_invalid(chunk, read).shifted(offset));
            }
            offset += chunk.len();
        }
        self.strict_tail(input, &layout)?;
        Ok(layout.output)
    }

    pub(super) fn strict_tail(&self, input: &[u8], layout: &Layout) -> Result<Tail, Error> {
        let decode = &self.decode_tables().decode;
        let tail = input.get(layout.full..layout.body).unwrap_or_default();
        let mut word = 0u32;
        for (offset, &byte) in (layout.full..).zip(tail) {
            let value = decode[byte as usize];
            if value == INVALID {
                return Err(Error::unexpected(byte, offset));
            }
            word = (word << 6) | value as u32;
        }
        let expected = match layout.tail {
            0 => 0,
            1 => {
                return Err(Error::Truncated {
                    offset: layout.body,
                });
            }
            2 => 2,
            _ => 1,
        };
        if !self.padding.accepts(input.len() - layout.body, expected) {
            return Err(Error::InvalidPadding {
                offset: layout.body,
            });
        }
        let (bytes, spare_bits) = match layout.tail {
            2 => (Tail::one((word >> 4) as u8), word & 0x0f),
            3 => (
                Tail::two((word >> 10) as u8, (word >> 2) as u8),
                word & 0x03,
            ),
            _ => (Tail::default(), 0),
        };
        if spare_bits != 0 {
            return Err(Error::NonCanonical {
                offset: layout.body - 1,
            });
        }
        Ok(bytes)
    }
}

impl Tables {
    pub(super) fn first_invalid(&self, input: &[u8], from: usize) -> Error {
        let invalid = input
            .iter()
            .enumerate()
            .skip(from)
            .find(|(_, byte)| self.decode[**byte as usize] == INVALID)
            .map(|(offset, &byte)| Error::unexpected(byte, offset));
        debug_assert!(invalid.is_some(), "kernel stopped before a valid quad");
        invalid.unwrap_or(Error::Truncated { offset: from })
    }
}

#[derive(Default)]
pub(super) struct Tail {
    bytes: [u8; 2],
    len: usize,
}

impl Tail {
    fn one(first: u8) -> Self {
        Tail {
            bytes: [first, 0],
            len: 1,
        }
    }

    fn two(first: u8, second: u8) -> Self {
        Tail {
            bytes: [first, second],
            len: 2,
        }
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}
