/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Quoted-printable (RFC 2045 section 6.7), the "Q" encoding of RFC 2047
//! encoded words and dkim-quoted-printable (RFC 6376 section 2.11).
//!
//! Every operation is a method on a [`QuotedPrintable`] engine:
//!
//! ```
//! use encodify::qp;
//!
//! # fn main() -> Result<(), encodify::Error> {
//! let body = qp::BODY.encode("Grüße,\nJürgen\n");
//! assert_eq!(body, "Gr=C3=BC=C3=9Fe,\r\nJ=C3=BCrgen\r\n");
//! assert_eq!(qp::BODY.decode(&body)?, "Grüße,\r\nJürgen\r\n".as_bytes());
//!
//! assert_eq!(qp::Q_PHRASE.encode("Keld Jørn"), "Keld_J=C3=B8rn");
//! let (name, used) = qp::Q_TEXT.decode_word("Andr=E9?= Pirard")?;
//! assert_eq!((name.as_slice(), used), (&b"Andr\xe9"[..], 9));
//!
//! assert_eq!(qp::DKIM.encode("a=b; c"), "a=3Db=3B=20c");
//! assert_eq!(qp::DKIM.decode("a=3Db=3B\r\n\t=20c")?, &b"a=b; c"[..]);
//! # Ok(())
//! # }
//! ```
//!
//! Decoding of `BODY` and `BINARY` is lenient by default, as RFC 2045
//! recommends for robust implementations; [`QuotedPrintable::strict`] turns
//! malformed escapes into errors.

mod count;
mod decode;
mod encode;
mod fold;
mod kernel;
mod output;
mod scan;
mod tables;
#[cfg(test)]
pub(crate) mod tests;
mod words;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Mode {
    Body,
    Binary,
    QText,
    QPhrase,
    Dkim,
}

/// A quoted-printable configuration. Engines are `Copy` and cheap to pass
/// around; all the constants in this module are engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuotedPrintable {
    mode: Mode,
    strict: bool,
}

/// Text bodies (`Content-Transfer-Encoding: quoted-printable`).
///
/// Encoding turns LF and CRLF into CRLF hard line breaks, inserts `=` soft
/// breaks so that no line exceeds 76 characters, never splits an escape,
/// and escapes `=`, bytes from 0x7F up, control characters other than TAB,
/// and a space or tab that would end a line.
///
/// Decoding keeps CRLF and bare LF line breaks as they are, drops bare CR,
/// joins soft breaks (`=`, optional spaces or tabs, then a line break or the
/// end of the input), deletes the spaces and tabs that end a line, accepts
/// lowercase hex digits and keeps a malformed escape (`=` and the byte after
/// it) literally.
pub const BODY: QuotedPrintable = QuotedPrintable {
    mode: Mode::Body,
    strict: false,
};

/// Binary content such as attachments: like [`BODY`] except that encoding
/// escapes CR and LF too, so the output has soft line breaks only.
pub const BINARY: QuotedPrintable = QuotedPrintable {
    mode: Mode::Binary,
    strict: false,
};

/// RFC 2047 "Q" encoding for unstructured header text such as `Subject`:
/// a space becomes `_`, and `=`, `?`, `_`, control characters and bytes from
/// 0x7F up are escaped.
///
/// Decoding turns `_` into a space and `=XX` escapes (either case) into
/// bytes and rejects any other `=`. Spaces and tabs, which RFC 2047 does
/// not allow in an encoded word but some encoders leave in, are kept; CR,
/// and LF with the spaces and tabs after it, are dropped as left over from
/// folding.
pub const Q_TEXT: QuotedPrintable = QuotedPrintable {
    mode: Mode::QText,
    strict: true,
};

/// RFC 2047 "Q" encoding for words in a phrase, such as display names
/// (section 5, rule 3): only letters, digits and `! * + - /` stay literal, a
/// space becomes `_` and every other byte is escaped. Decoding is the same
/// as [`Q_TEXT`].
pub const Q_PHRASE: QuotedPrintable = QuotedPrintable {
    mode: Mode::QPhrase,
    strict: true,
};

/// dkim-quoted-printable (RFC 6376 section 2.11), used by the DKIM `i=`,
/// `z=` and ARC tags.
///
/// Encoding escapes every byte outside `dkim-safe-char`, including `=`, `;`,
/// spaces and 8-bit bytes, and `|`, which separates the items of `z=` (RFC
/// 6376 section 3.5). It does not wrap lines: callers fold between escapes,
/// or use [`QuotedPrintable::encode_folded`]. Decoding removes folding
/// whitespace, accepts lowercase hex digits, `|` and 8-bit bytes (RFC 8616)
/// and rejects anything else that is not `dkim-safe-char` or a complete
/// escape.
pub const DKIM: QuotedPrintable = QuotedPrintable {
    mode: Mode::Dkim,
    strict: true,
};

impl QuotedPrintable {
    /// Returns this engine with strict decoding: a `=` that starts neither
    /// an escape nor a soft line break is an error that reports its offset.
    /// The `Q_*` and `DKIM` engines are always strict.
    pub const fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Whether malformed escapes are errors.
    pub const fn is_strict(&self) -> bool {
        self.strict
    }

    /// Length of the encoding of `byte` on its own: 1 when it stays literal
    /// (or becomes `_`), 3 when it is escaped. Line breaks and line-final
    /// white space, which depend on the surrounding bytes, are not taken into
    /// account.
    ///
    /// ```
    /// use encodify::qp;
    ///
    /// const PHRASE_LEN: [u8; 256] = {
    ///     let mut table = [0; 256];
    ///     let mut byte = 0;
    ///     while byte < 256 {
    ///         table[byte] = qp::Q_PHRASE.encoded_byte_len(byte as u8) as u8;
    ///         byte += 1;
    ///     }
    ///     table
    /// };
    /// assert_eq!(PHRASE_LEN[b'a' as usize], 1);
    /// assert_eq!(PHRASE_LEN[b'.' as usize], 3);
    /// ```
    pub const fn encoded_byte_len(&self, byte: u8) -> usize {
        self.mode.byte_len(byte)
    }

    /// The encoding of `byte` on its own, with the same caveat as
    /// [`QuotedPrintable::encoded_byte_len`].
    pub fn encode_byte(&self, byte: u8) -> &'static str {
        self.mode.byte_str(byte)
    }
}
