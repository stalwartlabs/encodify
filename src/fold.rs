/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

/// How encoded text embedded in a header or a content line is folded.
///
/// Before the text would push the line past `width` columns, `separator` is
/// written and the column restarts at `indent`, the number of columns the
/// separator's trailing whitespace occupies on the new line. With a
/// `granularity` of 4, base64 lines only break between 4-symbol groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fold<'x> {
    pub width: usize,
    pub separator: &'x [u8],
    pub indent: usize,
    pub granularity: usize,
}

impl<'x> Fold<'x> {
    /// DKIM and ARC `b=` and `bh=` values (RFC 6376): 76 columns, folded
    /// anywhere with CRLF TAB.
    pub const DKIM: Fold<'static> = Fold {
        width: 76,
        separator: b"\r\n\t",
        indent: 1,
        granularity: 1,
    };

    /// Header fields that hold RFC 2047 encoded words: lines of at most 76
    /// characters (RFC 2047 section 2), folded with CRLF SPACE.
    pub const HEADER: Fold<'static> = Fold {
        width: 76,
        separator: b"\r\n ",
        indent: 1,
        granularity: 1,
    };

    /// iCalendar and vCard content lines (RFC 5545, RFC 6350): 75 octets,
    /// folded anywhere with CRLF SPACE.
    pub const CONTENT_LINE: Fold<'static> = Fold {
        width: 75,
        separator: b"\r\n ",
        indent: 1,
        granularity: 1,
    };

    pub const fn new(width: usize, separator: &'x [u8], indent: usize) -> Self {
        Fold {
            width,
            separator,
            indent,
            granularity: 1,
        }
    }

    /// Returns this configuration breaking lines only between groups of
    /// `granularity` symbols.
    pub const fn with_granularity(mut self, granularity: usize) -> Self {
        self.granularity = if granularity == 0 { 1 } else { granularity };
        self
    }
}
