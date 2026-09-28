/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use super::{
    Base32,
    alphabet::{INVALID, Tables},
    kernel::scalar::NUMERAL_SYMBOLS,
};
use crate::{Buffer, Error};
use std::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    mem::MaybeUninit,
    ops::Deref,
};

const TEXT_LEN: usize = 16;

/// The base32 numeral of a `u64`, stored inline. Created by
/// [`Base32::encode_u64`]; it dereferences to `str`.
#[derive(Clone, Copy)]
pub struct U64Text {
    bytes: [u8; TEXT_LEN],
    start: u8,
}

impl Base32 {
    /// Encodes `value` as a base32 numeral of 1 to 13 symbols, without
    /// allocating.
    #[inline]
    pub fn encode_u64(&self, value: u64) -> U64Text {
        U64Text::new(self.tables(), value)
    }

    /// Appends the base32 numeral of `value` to a `Vec<u8>` or `String` and
    /// returns the number of bytes appended.
    #[inline]
    pub fn encode_u64_append(&self, value: u64, out: &mut impl Buffer) -> usize {
        self.tables().append_numeral(value, out)
    }

    /// Parses a base32 numeral written by [`Base32::encode_u64`]. Leading zero
    /// symbols are accepted. The empty string is [`Error::Truncated`], more
    /// than 13 symbols or a value above `u64::MAX` is [`Error::Overflow`], and
    /// a byte outside the alphabet is [`Error::InvalidByte`].
    #[inline]
    pub fn decode_u64(&self, input: impl AsRef<[u8]>) -> Result<u64, Error> {
        self.tables().decode_numeral(input.as_ref())
    }
}

impl Tables {
    #[inline(always)]
    fn append_numeral(&self, value: u64, out: &mut impl Buffer) -> usize {
        let count = U64Text::symbol_count(value);
        let symbols = self.numeral_left(value, TEXT_LEN - count);
        // SAFETY: the closure writes all 16 slots before committing `count`
        // (at most 13) of them, and `symbols` holds only alphabet symbols and
        // zero fill, all ASCII.
        unsafe {
            out.append_ascii(TEXT_LEN, |dst| {
                let Some(slots) = dst.first_chunk_mut::<TEXT_LEN>() else {
                    return 0;
                };
                *slots = symbols.map(MaybeUninit::new);
                count
            })
        }
    }

    #[inline(always)]
    fn decode_numeral(&self, input: &[u8]) -> Result<u64, Error> {
        self.parse_numeral(input)
            .ok_or_else(|| self.numeral_error(input))
    }

    #[cold]
    fn numeral_error(&self, input: &[u8]) -> Error {
        if input.is_empty() {
            Error::Truncated { offset: 0 }
        } else if input.len() > NUMERAL_SYMBOLS {
            Error::Overflow
        } else {
            input
                .iter()
                .enumerate()
                .find(|(_, byte)| self.decode[**byte as usize] == INVALID)
                .map_or(Error::Overflow, |(offset, &byte)| Error::InvalidByte {
                    offset,
                    byte,
                })
        }
    }
}

impl U64Text {
    #[inline(always)]
    fn symbol_count(value: u64) -> usize {
        ((u64::BITS + 4 - (value | 1).leading_zeros()) / 5) as usize
    }

    #[inline(always)]
    fn new(tables: &Tables, value: u64) -> Self {
        U64Text {
            bytes: tables.numeral(value),
            start: (TEXT_LEN - Self::symbol_count(value)) as u8,
        }
    }

    /// The numeral as bytes.
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(self.start as usize..).unwrap_or_default()
    }

    /// The numeral as a string slice.
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        let bytes = self.as_bytes();
        debug_assert!(bytes.is_ascii());
        // SAFETY: `Tables::numeral` fills `bytes` with alphabet symbols and
        // zero bytes, all ASCII and so valid UTF-8.
        unsafe { std::str::from_utf8_unchecked(bytes) }
    }
}

impl Deref for U64Text {
    type Target = str;

    #[inline(always)]
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for U64Text {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for U64Text {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for U64Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl fmt::Debug for U64Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl PartialEq for U64Text {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for U64Text {}

impl PartialOrd for U64Text {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U64Text {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl Hash for U64Text {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}
