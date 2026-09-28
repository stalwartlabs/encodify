/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Base64 (RFC 4648 sections 4 and 5, RFC 2045 section 6.8).
//!
//! Every operation is a method on a [`Base64`] engine. The engines below
//! cover the variants used across the mail stack, and new ones can be built
//! in `const` context from them:
//!
//! ```
//! use encodify::base64::{self, Padding, LineEnding};
//!
//! let token = base64::URL_SAFE_NO_PAD.encode(b"\x01\x02\x03\x04");
//! assert_eq!(token, "AQIDBA");
//! assert_eq!(base64::URL_SAFE_NO_PAD.decode(&token)?, b"\x01\x02\x03\x04");
//!
//! let body = base64::MIME.decode("SGVs\r\nbG8=\r\n")?;
//! assert_eq!(body, b"Hello");
//!
//! const PUSH_KEYS: base64::Base64 = base64::URL_SAFE.with_padding(Padding::Optional);
//! assert_eq!(PUSH_KEYS.decode("AQIDBA==")?, PUSH_KEYS.decode("AQIDBA")?);
//!
//! const PEM_BODY: base64::Base64 = base64::STANDARD.wrapped(64, LineEnding::Lf);
//! assert!(PEM_BODY.encode([0u8; 60]).ends_with('\n'));
//! # Ok::<(), encodify::Error>(())
//! ```

pub(crate) mod alphabet;
mod decode;
mod display;
mod encode;
mod fold;
mod kernel;
#[cfg(test)]
mod tests;

pub use crate::Fold;
pub use decode::{Decoder, FoldedValue};
pub use display::Display;

use alphabet::Tables;

/// The two RFC 4648 alphabets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alphabet {
    /// `A-Z a-z 0-9 + /` (RFC 4648 section 4).
    Standard,
    /// `A-Z a-z 0-9 - _` (RFC 4648 section 5).
    UrlSafe,
}

/// How an engine writes and checks `=` padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Padding {
    /// Encoders pad; strict decoders require canonical padding.
    Required,
    /// Encoders do not pad; strict decoders reject `=`.
    Omitted,
    /// Encoders pad; strict decoders accept input with or without padding.
    Optional,
}

/// Line terminator written by wrapping engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LineEnding {
    Lf,
    CrLf,
}

impl LineEnding {
    pub(crate) const fn as_bytes(self) -> &'static [u8] {
        match self {
            LineEnding::Lf => b"\n",
            LineEnding::CrLf => b"\r\n",
        }
    }

    pub(crate) const fn len(self) -> usize {
        self.as_bytes().len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Wrap {
    pub(crate) width: usize,
    pub(crate) ending: LineEnding,
}

impl Wrap {
    pub(crate) const fn line_in(self) -> usize {
        self.width / 4 * 3
    }

    pub(crate) const fn line_out(self) -> usize {
        self.width + self.ending.len()
    }
}

/// A base64 configuration: alphabet, padding, decoding strictness and line
/// wrapping. Engines are `Copy` and cheap to pass around; all the constants in
/// this module are engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Base64 {
    alphabet: Alphabet,
    padding: Padding,
    lenient: bool,
    any_alphabet: bool,
    wrap: Option<Wrap>,
}

/// Standard alphabet, padded. Decoding is strict: canonical padding, zero
/// trailing bits, no whitespace.
pub const STANDARD: Base64 = Base64::new(Alphabet::Standard);

/// Standard alphabet without padding. Decoding rejects `=`.
pub const STANDARD_NO_PAD: Base64 = STANDARD.with_padding(Padding::Omitted);

/// URL-safe alphabet, padded. Decoding is strict.
pub const URL_SAFE: Base64 = Base64::new(Alphabet::UrlSafe);

/// URL-safe alphabet without padding: the form used by JWT, JWS, OAuth tokens
/// and Web Push. Decoding is strict, so every byte string has exactly one
/// accepted encoding.
pub const URL_SAFE_NO_PAD: Base64 = URL_SAFE.with_padding(Padding::Omitted);

/// Standard alphabet with lenient decoding, for SASL, HTTP Basic, DKIM tags
/// and other text that may carry whitespace: see [`Base64::lenient`].
pub const LENIENT: Base64 = STANDARD.lenient();

/// MIME `Content-Transfer-Encoding: base64` (RFC 2045): lenient decoding,
/// and encoding wrapped at 76 columns with CRLF after every line.
pub const MIME: Base64 = LENIENT.wrapped(76, LineEnding::CrLf);

impl Base64 {
    /// A padded engine with strict decoding and no line wrapping.
    pub const fn new(alphabet: Alphabet) -> Self {
        Base64 {
            alphabet,
            padding: Padding::Required,
            lenient: false,
            any_alphabet: false,
            wrap: None,
        }
    }

    /// Returns this engine with a different padding policy.
    pub const fn with_padding(mut self, padding: Padding) -> Self {
        self.padding = padding;
        self
    }

    /// Returns this engine with lenient decoding: ASCII whitespace (SP, HT,
    /// CR, LF, VT, FF) is skipped, `=` ends the current quantum and decoding
    /// goes on after it, a single symbol left over before `=` or at the end is
    /// dropped and trailing bits are not checked. Any other byte is an error.
    pub const fn lenient(mut self) -> Self {
        self.lenient = true;
        self
    }

    /// Returns this engine accepting both `+ /` and `- _` when decoding.
    pub const fn any_alphabet(mut self) -> Self {
        self.any_alphabet = true;
        self
    }

    /// Returns this engine with encoded lines of `width` symbols, each one
    /// (the last included) followed by `ending`. `width` is rounded down to a
    /// multiple of 4, with a minimum of 4.
    pub const fn wrapped(mut self, width: usize, ending: LineEnding) -> Self {
        let width = if width < 4 { 4 } else { width & !3 };
        self.wrap = Some(Wrap { width, ending });
        self
    }

    /// Returns this engine without line wrapping.
    pub const fn unwrapped(mut self) -> Self {
        self.wrap = None;
        self
    }

    pub const fn alphabet(&self) -> Alphabet {
        self.alphabet
    }

    pub const fn padding(&self) -> Padding {
        self.padding
    }

    pub const fn is_lenient(&self) -> bool {
        self.lenient
    }

    #[inline(always)]
    pub(crate) const fn tables(&self) -> &'static Tables {
        match self.alphabet {
            Alphabet::Standard => &alphabet::STANDARD,
            Alphabet::UrlSafe => &alphabet::URL_SAFE,
        }
    }

    #[inline(always)]
    pub(crate) const fn decode_tables(&self) -> &'static Tables {
        if self.any_alphabet {
            &alphabet::ANY
        } else {
            self.tables()
        }
    }

    #[inline(always)]
    pub(crate) const fn pads(&self) -> bool {
        !matches!(self.padding, Padding::Omitted)
    }

    /// Length of the encoding of `input_len` bytes, line breaks included.
    pub const fn encoded_len(&self, input_len: usize) -> usize {
        let symbols = if self.pads() {
            input_len.div_ceil(3).saturating_mul(4)
        } else {
            (input_len / 3).saturating_mul(4)
                + match input_len % 3 {
                    0 => 0,
                    1 => 2,
                    _ => 3,
                }
        };
        match self.wrap {
            Some(wrap) => symbols.saturating_add(
                symbols
                    .div_ceil(wrap.width)
                    .saturating_mul(wrap.ending.len()),
            ),
            None => symbols,
        }
    }

    /// Upper bound of the decoded length of `input_len` bytes of input.
    pub const fn decoded_len_estimate(&self, input_len: usize) -> usize {
        input_len.div_ceil(4).saturating_mul(3)
    }
}
