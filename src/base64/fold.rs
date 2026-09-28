/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::Base64;
use crate::{Buffer, Fold};
use std::{convert::Infallible, mem::MaybeUninit};

const BUFFER: usize = 1024;

impl Base64 {
    /// Encodes `input` without line wrapping, folding it as described by
    /// `fold`. `column` is the current column before the call and is updated
    /// to the column after it, so text written around the value can share it.
    /// Every piece of output, data and separators alike, is handed to `sink`
    /// in order, which lets the value stream into a hasher or a writer.
    ///
    /// A fold is written only before a symbol that would pass `width`, so a
    /// value can end exactly at `width`; text written after it must check
    /// `column` and fold first if it does not fit.
    pub fn encode_folded(
        &self,
        input: impl AsRef<[u8]>,
        column: &mut usize,
        fold: Fold<'_>,
        mut sink: impl FnMut(&[u8]),
    ) {
        let input = input.as_ref();
        let engine = self.unwrapped();
        let mut folder = Folder {
            fold,
            granularity: fold.granularity.max(1),
            total: engine.encoded_len(input.len()),
            position: 0,
        };
        let mut buffer = [MaybeUninit::uninit(); BUFFER];
        let Ok(()) = engine.encode_pieces(input, &mut buffer, |mut rest| {
            while !rest.is_empty() {
                let run = folder.next_run(column, &mut sink).clamp(1, rest.len());
                let (head, tail) = rest.split_at(run);
                sink(head);
                *column += run;
                folder.position += run;
                rest = tail;
            }
            Ok::<(), Infallible>(())
        });
    }

    /// Encodes `input` without line wrapping and hands the output to `sink`
    /// in chunks of at most a few kilobytes, without allocating. Useful for
    /// sinks that are neither `io::Write` nor `fmt::Write`, such as hashers.
    pub fn encode_chunks(&self, input: impl AsRef<[u8]>, mut sink: impl FnMut(&[u8])) {
        let mut buffer = [MaybeUninit::uninit(); BUFFER];
        let Ok(()) = self
            .unwrapped()
            .encode_pieces(input.as_ref(), &mut buffer, |piece| {
                sink(piece);
                Ok::<(), Infallible>(())
            });
    }

    /// Like [`Base64::encode_folded`], appending to a `Vec<u8>` or `String`.
    /// The separator must be ASCII. Returns the number of bytes appended.
    pub fn encode_folded_append(
        &self,
        input: impl AsRef<[u8]>,
        out: &mut impl Buffer,
        column: &mut usize,
        fold: Fold<'_>,
    ) -> usize {
        let mut appended = 0;
        self.encode_folded(input, column, fold, |piece| {
            appended += out.push_ascii(piece)
        });
        appended
    }
}

struct Folder<'x> {
    fold: Fold<'x>,
    granularity: usize,
    total: usize,
    position: usize,
}

impl Folder<'_> {
    fn next_run(&self, column: &mut usize, sink: &mut impl FnMut(&[u8])) -> usize {
        let Folder {
            fold,
            granularity,
            total,
            position,
        } = *self;
        let left = total.saturating_sub(position);
        let into_group = position % granularity;
        let committed = if into_group == 0 {
            let group = granularity.min(left);
            if *column + group > fold.width && *column > fold.indent {
                sink(fold.separator);
                *column = fold.indent;
            }
            group
        } else {
            (granularity - into_group).min(left)
        };
        let Some(space) = fold.width.checked_sub(*column + committed) else {
            return committed;
        };
        let whole = space / granularity * granularity;
        let last = granularity.min(left.saturating_sub(committed + whole));
        let run = if whole + last <= space {
            committed + whole + last
        } else {
            committed + whole
        };
        run.min(left)
    }
}

#[cfg(test)]
mod tests {
    use super::Fold;
    use crate::{
        base64::{STANDARD, STANDARD_NO_PAD},
        test_rng::XorShift,
    };

    fn reference(encoded: &[u8], column: &mut usize, fold: Fold<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        for group in encoded.chunks(fold.granularity) {
            if *column + group.len() > fold.width && *column > fold.indent {
                out.extend_from_slice(fold.separator);
                *column = fold.indent;
            }
            out.extend_from_slice(group);
            *column += group.len();
        }
        out
    }

    #[test]
    fn folds_like_the_reference() {
        let mut rng = XorShift::new(31);
        for fold in [
            Fold::DKIM,
            Fold::CONTENT_LINE,
            Fold::DKIM.with_granularity(4),
            Fold::new(76, b"\r\n\t", 1).with_granularity(4),
            Fold::new(22, b"\r\n ", 0).with_granularity(6),
            Fold::new(20, b"\n", 2).with_granularity(3),
            Fold::new(3, b"\n", 1).with_granularity(4),
            Fold::new(76, b" ", 1),
            Fold::new(10, b"\n", 0),
            Fold::new(0, b"\n", 0),
        ] {
            for len in [0, 1, 2, 3, 30, 57, 256, 1000, 3000] {
                for start in [0, 1, 10, 40, 74, 75, 76, 80] {
                    for engine in [STANDARD, STANDARD_NO_PAD] {
                        let input = rng.bytes(len);
                        let encoded = engine.encode(&input);
                        let mut expected_column = start;
                        let expected = reference(encoded.as_bytes(), &mut expected_column, fold);
                        let mut column = start;
                        let mut out = Vec::new();
                        engine.encode_folded(&input, &mut column, fold, |piece| {
                            out.extend_from_slice(piece)
                        });
                        assert_eq!(
                            String::from_utf8_lossy(&out),
                            String::from_utf8_lossy(&expected),
                            "{fold:?} {len} {start}"
                        );
                        assert_eq!(column, expected_column, "{fold:?} {len} {start}");
                        let mut appended = String::new();
                        let mut column = start;
                        engine.encode_folded_append(&input, &mut appended, &mut column, fold);
                        assert_eq!(appended.as_bytes(), expected);
                    }
                }
            }
        }
    }

    #[test]
    fn chunked_encoding_matches_one_shot() {
        let mut rng = XorShift::new(32);
        for len in [0, 1, 767, 768, 769, 5000] {
            let input = rng.bytes(len);
            let mut out = Vec::new();
            STANDARD.encode_chunks(&input, |piece| out.extend_from_slice(piece));
            assert_eq!(out, STANDARD.encode(&input).as_bytes());
        }
    }

    #[test]
    fn lines_never_exceed_the_width() {
        let input = [0x5au8; 500];
        let mut column = 70;
        let mut out = Vec::new();
        STANDARD.encode_folded(input, &mut column, Fold::CONTENT_LINE, |piece| {
            out.extend_from_slice(piece)
        });
        let text = String::from_utf8(out).expect("ascii");
        let mut lines = text.split("\r\n");
        assert_eq!(lines.next().map(str::len), Some(5));
        assert!(lines.all(|line| line.len() <= 75 && line.starts_with(' ')));
    }
}
