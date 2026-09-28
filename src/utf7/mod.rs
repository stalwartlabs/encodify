/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! UTF-7 (RFC 2152) and the modified UTF-7 of IMAP mailbox names (RFC 3501
//! section 5.1.3).
//!
//! ```
//! use encodify::utf7;
//!
//! assert_eq!(utf7::IMAP.encode("~peter/mail/台北/日本語"), "~peter/mail/&U,BTFw-/&ZeVnLIqe-");
//! assert_eq!(utf7::IMAP.decode("&ZeVnLIqe-")?, "日本語");
//! assert!(utf7::IMAP.decode("Hello, World&ACE-").is_err());
//! assert_eq!(utf7::IMAP.lenient().decode("Hello, World&ACE-")?, "Hello, World!");
//! assert_eq!(utf7::MAIL.decode_lossy(b"Hi Mom -+Jjo--!"), "Hi Mom -\u{263a}-!");
//! # Ok::<(), encodify::Error>(())
//! ```

mod decode;
mod encode;
#[cfg(test)]
mod tests;

use crate::base64::alphabet::{self, Tables};

/// A UTF-7 variant: the IMAP modified form or the RFC 2152 form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Utf7 {
    imap: bool,
    lenient: bool,
}

/// IMAP modified UTF-7 (RFC 3501 section 5.1.3): `&` shifts, `,` replaces
/// `/`, every shift ends with `-`. Decoding is strict, as RFC 3501 asks of
/// servers for names given to CREATE; see [`Utf7::lenient`] for the other
/// commands.
pub const IMAP: Utf7 = Utf7 {
    imap: true,
    lenient: false,
};

/// UTF-7 as defined by RFC 2152, the `utf-7` charset of MIME messages.
pub const MAIL: Utf7 = Utf7 {
    imap: false,
    lenient: false,
};

const SHIFT_END: u8 = b'-';
const REPLACEMENT: char = char::REPLACEMENT_CHARACTER;

static MAIL_DIRECT: ByteSet = ByteSet::new(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \t\r\n'(),-./:?!\"#$%&*;<=>@[]^_`{|}",
);

impl Utf7 {
    /// Returns this variant with lenient decoding. For IMAP names: leftover
    /// bits are not checked, a missing final `-` is accepted, a trailing lone
    /// `&` is literal, encoded printable ASCII is accepted and text outside a
    /// shift passes through unchanged. For RFC 2152 text: leftover bits are
    /// not checked.
    pub const fn lenient(mut self) -> Self {
        self.lenient = true;
        self
    }

    #[inline(always)]
    const fn shift(&self) -> u8 {
        if self.imap { b'&' } else { b'+' }
    }

    #[inline(always)]
    fn tables(&self) -> &'static Tables {
        if self.imap {
            &alphabet::IMAP
        } else {
            &alphabet::STANDARD
        }
    }

    #[inline(always)]
    fn is_direct(&self, byte: u8) -> bool {
        if self.imap {
            matches!(byte, b' '..=b'~') && byte != b'&'
        } else {
            MAIL_DIRECT.contains(byte)
        }
    }

    #[inline(always)]
    fn direct_len(&self, bytes: &[u8]) -> usize {
        bytes
            .iter()
            .position(|&byte| !self.is_direct(byte))
            .unwrap_or(bytes.len())
    }

    fn is_all_direct(&self, bytes: &[u8]) -> bool {
        bytes
            .iter()
            .fold(true, |direct, &byte| direct & self.is_direct(byte))
    }
}

struct ByteSet([bool; 256]);

impl ByteSet {
    const fn new(members: &[u8]) -> Self {
        let mut set = [false; 256];
        let mut index = 0;
        while index < members.len() {
            set[members[index] as usize] = true;
            index += 1;
        }
        ByteSet(set)
    }

    #[inline(always)]
    fn contains(&self, byte: u8) -> bool {
        self.0[byte as usize]
    }
}
