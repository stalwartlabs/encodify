/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::fmt;

/// Error returned by the decoders and by the encoders that write into a
/// caller-provided slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// A byte that is not valid at this position.
    InvalidByte { offset: usize, byte: u8 },
    /// The input ends in the middle of a quantum, an escape or a shift.
    Truncated { offset: usize },
    /// Padding is missing, misplaced or not allowed by the engine.
    InvalidPadding { offset: usize },
    /// The unused bits of the last symbol are not zero, so the input is not
    /// the canonical encoding of any byte string.
    NonCanonical { offset: usize },
    /// The decoded bytes are not valid UTF-8.
    InvalidUtf8 { offset: usize },
    /// The decoded UTF-16 contains an unpaired surrogate.
    InvalidUtf16 { offset: usize },
    /// The decoded value does not fit in the target integer.
    Overflow,
    /// The output slice is too short; `required` bytes are needed.
    BufferTooSmall { required: usize },
    /// The input contains no encoded block.
    NotFound,
}

impl Error {
    pub(crate) fn shifted(self, by: usize) -> Self {
        match self {
            Error::InvalidByte { offset, byte } => Error::InvalidByte {
                offset: offset + by,
                byte,
            },
            Error::Truncated { offset } => Error::Truncated {
                offset: offset + by,
            },
            Error::InvalidPadding { offset } => Error::InvalidPadding {
                offset: offset + by,
            },
            Error::NonCanonical { offset } => Error::NonCanonical {
                offset: offset + by,
            },
            Error::InvalidUtf8 { offset } => Error::InvalidUtf8 {
                offset: offset + by,
            },
            Error::InvalidUtf16 { offset } => Error::InvalidUtf16 {
                offset: offset + by,
            },
            other => other,
        }
    }

    /// The error for an `unexpected` byte: [`Error::InvalidPadding`] for a
    /// misplaced `=`, [`Error::InvalidByte`] for anything else.
    pub(crate) const fn unexpected(byte: u8, offset: usize) -> Self {
        if byte == b'=' {
            Error::InvalidPadding { offset }
        } else {
            Error::InvalidByte { offset, byte }
        }
    }

    /// Offset in the input where the problem was found, when there is one.
    pub fn offset(&self) -> Option<usize> {
        match *self {
            Error::InvalidByte { offset, .. }
            | Error::Truncated { offset }
            | Error::InvalidPadding { offset }
            | Error::NonCanonical { offset }
            | Error::InvalidUtf8 { offset }
            | Error::InvalidUtf16 { offset } => Some(offset),
            Error::Overflow | Error::BufferTooSmall { .. } | Error::NotFound => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::InvalidByte { offset, byte } => {
                write!(f, "invalid byte 0x{byte:02x} at offset {offset}")
            }
            Error::Truncated { offset } => write!(f, "input truncated at offset {offset}"),
            Error::InvalidPadding { offset } => write!(f, "invalid padding at offset {offset}"),
            Error::NonCanonical { offset } => {
                write!(f, "non-canonical encoding at offset {offset}")
            }
            Error::InvalidUtf8 { offset } => write!(f, "invalid UTF-8 at offset {offset}"),
            Error::InvalidUtf16 { offset } => write!(f, "invalid UTF-16 at offset {offset}"),
            Error::Overflow => f.write_str("value overflows the target integer"),
            Error::BufferTooSmall { required } => {
                write!(f, "output buffer too small, {required} bytes required")
            }
            Error::NotFound => f.write_str("no encoded block found"),
        }
    }
}

impl std::error::Error for Error {}

pub(crate) trait ToStr {
    /// Validates the bytes as UTF-8.
    fn to_str(&self) -> Result<&str, Error>;
}

impl ToStr for [u8] {
    #[inline]
    fn to_str(&self) -> Result<&str, Error> {
        simdutf8::compat::from_utf8(self).map_err(|err| Error::InvalidUtf8 {
            offset: err.valid_up_to(),
        })
    }
}
