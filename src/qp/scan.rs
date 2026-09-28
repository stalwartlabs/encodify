/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    Mode, QuotedPrintable,
    decode::{Body, DKIM_CLASS, DKIM_EQUALS, DKIM_FWS, DKIM_SAFE, DkimValue, Escape, SLACK},
    kernel::{Job, Kernel},
    tables::QpByte,
};
use crate::Error;
use memchr::{memchr, memchr3_iter, memrchr};
use std::mem::MaybeUninit;

const CHUNK: usize = 4096;

impl QuotedPrintable {
    /// Validates `input` and returns its exact decoded length without
    /// allocating. Fails exactly when [`QuotedPrintable::decode`] fails.
    ///
    /// ```
    /// use encodify::qp;
    ///
    /// # fn main() -> Result<(), encodify::Error> {
    /// assert_eq!(qp::BODY.decoded_len("Gr=C3=BC=C3=9Fe \r\nJ=\r\n=C3=BCrgen")?, 16);
    /// # Ok(())
    /// # }
    /// ```
    pub fn decoded_len(&self, input: impl AsRef<[u8]>) -> Result<usize, Error> {
        let input = input.as_ref();
        match self.mode {
            Mode::Body | Mode::Binary => BodyScan(input).decoded_len(self.strict),
            Mode::QText | Mode::QPhrase => QScan(input).decoded_len(),
            Mode::Dkim => DkimScan(input).decoded_len(),
        }
    }

    /// `None` when `input` has nothing to rewrite, so that it decodes to
    /// itself. Otherwise the length of a prefix with nothing to rewrite, after
    /// which decoding starts afresh.
    pub(super) fn verbatim_len(&self, input: &[u8]) -> Option<usize> {
        match self.mode {
            Mode::Body | Mode::Binary => BodyScan(input).verbatim_len(),
            Mode::QText | Mode::QPhrase => QScan(input).verbatim_len(),
            Mode::Dkim => DkimScan(input).verbatim_len(),
        }
    }
}

struct BodyScan<'x>(&'x [u8]);

impl BodyScan<'_> {
    fn decoded_len(self, strict: bool) -> Result<usize, Error> {
        let mut scratch = [MaybeUninit::uninit(); CHUNK + SLACK];
        let mut rest = self.0;
        let mut offset = 0;
        let mut total = 0;
        while !rest.is_empty() {
            let (chunk, after) = rest
                .split_at_checked(Self::chunk_len(rest))
                .unwrap_or((rest, &[]));
            total += Body {
                input: chunk,
                dst: &mut scratch,
                strict,
            }
            .dispatch()
            .map_err(|err| err.shifted(offset))?;
            offset += chunk.len();
            rest = after;
        }
        Ok(total)
    }

    fn chunk_len(rest: &[u8]) -> usize {
        let Some(window) = rest.get(..CHUNK) else {
            return rest.len();
        };
        memrchr(b'\n', window)
            .map(|at| at + 1)
            .or_else(|| {
                memchr(b'\n', rest.get(CHUNK..).unwrap_or_default()).map(|at| CHUNK + at + 1)
            })
            .unwrap_or(rest.len())
    }

    fn verbatim_len(self) -> Option<usize> {
        Verbatim(self.0).dispatch()
    }
}

struct Verbatim<'x>(&'x [u8]);

impl Job for Verbatim<'_> {
    type Output = Option<usize>;

    #[inline(always)]
    fn run<K: Kernel>(self) -> Option<usize> {
        let input = self.0;
        let mut scratch = [MaybeUninit::uninit(); CHUNK];
        let mut read = 0;
        let mut line = 0;
        loop {
            let run = K::copy_text(input.get(read..).unwrap_or_default(), &mut scratch);
            read += run;
            let blank_before = read
                .checked_sub(1)
                .and_then(|before| input.get(before))
                .is_some_and(|byte| byte.is_blank());
            match input.get(read..).unwrap_or_default() {
                [] => return blank_before.then_some(line),
                [b'\n', ..] if !blank_before => {
                    read += 1;
                    line = read;
                }
                [b'\r', b'\n', ..] if !blank_before => {
                    read += 2;
                    line = read;
                }
                [b'=' | b'\r' | b'\n', ..] => return Some(line),
                _ => read += usize::from(run == 0),
            }
        }
    }
}

struct QScan<'x>(&'x [u8]);

impl QScan<'_> {
    fn decoded_len(self) -> Result<usize, Error> {
        let input = self.0;
        let mut read = 0;
        let mut written = 0;
        for at in memchr3_iter(b'=', b'\r', b'\n', input) {
            if at < read {
                continue;
            }
            written += at - read;
            read = at;
            match input.get(at..).unwrap_or_default() {
                [b'=', after @ ..] => {
                    let escape = Escape(after);
                    escape
                        .byte()
                        .ok_or_else(|| escape.word_error(at + 1, input.len()))?;
                    read += 3;
                    written += 1;
                }
                [b'\n', after @ ..] => {
                    read += 1 + after.iter().take_while(|&&byte| byte.is_blank()).count();
                }
                _ => read += 1,
            }
        }
        Ok(written + input.len().saturating_sub(read))
    }

    fn verbatim_len(self) -> Option<usize> {
        self.0
            .iter()
            .position(|&byte| matches!(byte, b'_' | b'=' | b'\r' | b'\n'))
    }
}

struct DkimScan<'x>(&'x [u8]);

impl DkimScan<'_> {
    fn decoded_len(self) -> Result<usize, Error> {
        let value = self.0;
        let mut read = 0;
        let mut written = 0;
        while let Some(&byte) = value.get(read) {
            match DKIM_CLASS[byte as usize] {
                DKIM_SAFE => {
                    read += 1;
                    written += 1;
                }
                DKIM_FWS => read += 1,
                DKIM_EQUALS => {
                    let (_, next) = DkimValue::folded_escape(value, read)?;
                    read = next;
                    written += 1;
                }
                _ => return Err(Error::InvalidByte { offset: read, byte }),
            }
        }
        Ok(written)
    }

    fn verbatim_len(self) -> Option<usize> {
        self.0
            .iter()
            .position(|&byte| DKIM_CLASS[byte as usize] != DKIM_SAFE)
    }
}
