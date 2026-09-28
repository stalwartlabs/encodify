/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Base32 (RFC 4648 section 6) and the Stalwart base32 alphabet.
//!
//! Every operation is a method on a [`Base32`] engine:
//!
//! ```
//! use encodify::base32;
//!
//! assert_eq!(base32::STANDARD.encode(b"foobar"), "MZXW6YTBOI======");
//! assert_eq!(base32::STANDARD_NO_PAD.encode(b"foobar"), "MZXW6YTBOI");
//! assert_eq!(base32::STANDARD.decode("MZXW6YTBOI======"), Ok(b"foobar".to_vec()));
//!
//! let id = base32::STALWART.encode_u64(20080258862541);
//! assert_eq!(&*id, "singleton");
//! assert_eq!(base32::STALWART.decode_u64("singleton"), Ok(20080258862541));
//! ```
//!
//! # Decoding rules
//!
//! The one-shot decoders ([`Base32::decode`], [`Base32::decode_append`],
//! [`Base32::decode_slice`]) are strict: a byte outside the engine's alphabet
//! is an error (RFC 4648 section 3.3), padding must be exactly what the
//! encoder writes (or absent, depending on the engine's [`Padding`]), a final
//! group of 1, 3 or 6 symbols is an invalid length and the unused bits of the
//! last symbol must be zero, so every byte string has exactly one accepted
//! encoding.
//!
//! Decoding is case-sensitive. [`STANDARD`] and [`STANDARD_NO_PAD`] accept only
//! the uppercase symbols of RFC 4648 table 3, and [`STALWART`] only its
//! lowercase ones. Accepting both cases would give every value many
//! encodings; RFC 6541 (ATPS) labels, which the DNS compares without regard to
//! case, are only ever encoded.
//!
//! The streaming [`Decoder`] is lenient instead: it stops at the first byte
//! that is not a symbol and does not check the trailing bits, so that a
//! caller can read LEB128 fields out of a base32 string that is followed by
//! other text.
//!
//! # Integers
//!
//! [`Base32::encode_u64`] and [`Base32::decode_u64`] write a `u64` as a
//! positional numeral: the first symbol carries the top 4 bits and the next
//! twelve carry 5 bits each, leading zero symbols are dropped, and zero is a
//! single zero symbol. This is the format of Stalwart's JMAP ids.

mod alphabet;
mod decode;
mod display;
mod encode;
mod kernel;
mod numeric;
mod stream;
#[cfg(test)]
mod tests;

pub use display::Display;
pub use numeric::U64Text;
pub use stream::{Decoder, Encoder};

use alphabet::Tables;

/// The base32 alphabets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alphabet {
    /// `A-Z 2-7` (RFC 4648 section 6).
    Standard,
    /// `a-z 7 9 2 0 1 3`, the alphabet of Stalwart ids, blob ids, states and
    /// storage keys.
    Stalwart,
}

/// How an engine writes and checks `=` padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Padding {
    /// Encoders pad to a multiple of 8 symbols; decoders require canonical
    /// padding.
    Required,
    /// Encoders do not pad; decoders reject `=`.
    Omitted,
    /// Encoders pad; decoders accept input with or without canonical
    /// padding.
    Optional,
}

/// A base32 configuration: alphabet and padding. Engines are `Copy` and cheap
/// to pass around; all the constants in this module are engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Base32 {
    alphabet: Alphabet,
    padding: Padding,
}

/// RFC 4648 alphabet, padded.
pub const STANDARD: Base32 = Base32::new(Alphabet::Standard);

/// RFC 4648 alphabet without padding, as used by RFC 6541 (ATPS) query
/// labels.
pub const STANDARD_NO_PAD: Base32 = STANDARD.with_padding(Padding::Omitted);

/// Stalwart alphabet, never padded.
pub const STALWART: Base32 = Base32::new(Alphabet::Stalwart).with_padding(Padding::Omitted);

impl Base32 {
    /// A padded engine for `alphabet`.
    pub const fn new(alphabet: Alphabet) -> Self {
        Base32 {
            alphabet,
            padding: Padding::Required,
        }
    }

    /// Returns this engine with a different padding policy.
    pub const fn with_padding(mut self, padding: Padding) -> Self {
        self.padding = padding;
        self
    }

    pub const fn alphabet(&self) -> Alphabet {
        self.alphabet
    }

    pub const fn padding(&self) -> Padding {
        self.padding
    }

    #[inline(always)]
    pub(crate) const fn tables(&self) -> &'static Tables {
        match self.alphabet {
            Alphabet::Standard => &alphabet::STANDARD,
            Alphabet::Stalwart => &alphabet::STALWART,
        }
    }

    #[inline(always)]
    pub(crate) const fn pads(&self) -> bool {
        !matches!(self.padding, Padding::Omitted)
    }
}
