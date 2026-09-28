/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    Check, Inputs, Shown,
    reference::{self, Dkim, Q},
};
use crate::{
    Fold,
    buffer::SpareCapacity,
    qp::{
        BINARY, BODY, DKIM, Mode, Q_PHRASE, Q_TEXT, QuotedPrintable,
        count::{Count, WordCount},
        kernel::{Job, Kernel},
        words::Words,
    },
    test_rng::XorShift,
};

const ENGINES: [QuotedPrintable; 5] = [BODY, BINARY, Q_TEXT, Q_PHRASE, DKIM];
const WORD_MODES: [Mode; 3] = [Mode::QText, Mode::QPhrase, Mode::Dkim];
const TEXT_PIECES: &[&str] = &[
    "a",
    "Z",
    "0",
    " ",
    "\t",
    "=",
    "?",
    "_",
    ";",
    "\r\n",
    "\n",
    "\r",
    "é",
    "ß",
    "日",
    "🦀",
    "\u{7f}",
    "\u{1b}",
    "  ",
    "word",
    "longer words here",
];

trait Texts {
    fn text(&mut self, pieces: usize) -> String;
}

impl Texts for XorShift {
    fn text(&mut self, pieces: usize) -> String {
        (0..pieces).map(|_| *self.pick(TEXT_PIECES)).collect()
    }
}

fn expected_len(mode: Mode, input: &[u8]) -> usize {
    match mode {
        Mode::Body => reference::Body::encode(input).len(),
        Mode::Binary => reference::Binary::encode(input).len(),
        Mode::QText => Q::encode(input, false).len(),
        Mode::QPhrase => Q::encode(input, true).len(),
        Mode::Dkim => Dkim::encode(input).len(),
    }
}

struct Counts(Vec<Vec<u8>>);

impl Counts {
    fn count_with<K: Kernel>(mode: Mode, input: &[u8], limit: usize) -> Option<usize> {
        match mode {
            Mode::Body => Count::<false> { input, limit }.run::<K>(),
            Mode::Binary => Count::<true> { input, limit }.run::<K>(),
            mode => WordCount {
                table: mode.table(),
                class: mode.class(),
                input,
                limit,
            }
            .run::<K>(),
        }
    }
}

impl Check for Counts {
    fn check<K: Kernel>(&self, kernel: &'static str) {
        for (index, input) in self.0.iter().enumerate() {
            let high = input.iter().filter(|&&byte| byte >= 0x80).count();
            for mode in [
                Mode::Body,
                Mode::Binary,
                Mode::QText,
                Mode::QPhrase,
                Mode::Dkim,
            ] {
                let expected = expected_len(mode, input);
                let context = || format!("{kernel} {mode:?} {}", input.shown());
                let limits = [
                    usize::MAX,
                    expected,
                    expected.saturating_sub(1),
                    (input.len() + 2 * high).saturating_sub(1),
                    input.len(),
                    input.len() + index % 97,
                    expected / 2,
                ];
                for limit in limits {
                    assert_eq!(
                        Self::count_with::<K>(mode, input, limit),
                        (expected <= limit).then_some(expected),
                        "limit {limit} {}",
                        context()
                    );
                }
            }
        }
    }
}

#[test]
fn every_kernel_counts_like_the_reference() {
    let mut rng = XorShift::new(0xc0de);
    let mut samples: Vec<Vec<u8>> = (0..1_500)
        .map(|round| {
            let len = rng.lengths(round);
            rng.raw_input(len)
        })
        .collect();
    for len in [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 200] {
        for filler in [&b"a"[..], b" ", b"\xe9", b"=", b"\r\n", b"a\r"] {
            samples.push(filler.iter().copied().cycle().take(len).collect());
        }
    }
    for len in [2_048, 3_000, 9_000] {
        samples.push(rng.raw_input(len));
        samples.push(rng.bytes(len));
        let mut mixed = rng.raw_input(len / 2);
        mixed.extend(rng.bytes(len / 2));
        samples.push(mixed);
        let mut late = vec![b'a'; len / 2];
        late.extend(rng.bytes(len / 2));
        samples.push(late);
    }
    Counts(samples).every_kernel();
}

struct Prefixes(Vec<(String, usize)>);

impl Prefixes {
    fn longest(mode: Mode, text: &str, budget: usize, chars: bool) -> (usize, usize) {
        let bytes = text.as_bytes();
        (0..=bytes.len())
            .filter(|&at| !chars || text.is_char_boundary(at))
            .map(|at| (at, expected_len(mode, bytes.get(..at).unwrap_or_default())))
            .take_while(|&(_, len)| len <= budget)
            .last()
            .unwrap_or((0, 0))
    }
}

impl Check for Prefixes {
    fn check<K: Kernel>(&self, kernel: &'static str) {
        for (text, budget) in &self.0 {
            for mode in WORD_MODES {
                for chars in [false, true] {
                    let expected = Self::longest(mode, text, *budget, chars);
                    let mut out = Vec::new();
                    let mut read = 0;
                    // SAFETY: `Words::run` counts only bytes it wrote, at most `budget`, which is
                    // below the `budget + 64` region.
                    unsafe {
                        out.append_with(budget + 64, |dst| {
                            let (taken, written) = Words {
                                table: mode.table(),
                                class: mode.class(),
                                input: text.as_bytes(),
                                dst,
                                budget: *budget,
                                chars,
                            }
                            .run::<K>();
                            read = taken;
                            written
                        })
                    };
                    let context = || format!("{kernel} {mode:?} {chars} {budget} {text:?}");
                    assert_eq!((read, out.len()), expected, "{}", context());
                    let prefix = text.as_bytes().get(..read).unwrap_or_default();
                    let reference = match mode {
                        Mode::QText => Q::encode(prefix, false),
                        Mode::QPhrase => Q::encode(prefix, true),
                        _ => Dkim::encode(prefix),
                    };
                    assert_eq!(out, reference, "{}", context());
                }
            }
        }
    }
}

#[test]
fn every_kernel_encodes_word_prefixes() {
    let mut rng = XorShift::new(0x9ef1);
    let samples = (0..600)
        .map(|round| {
            let pieces = rng.below(if round % 5 == 0 { 40 } else { 12 });
            (rng.text(pieces), rng.below(90))
        })
        .collect();
    Prefixes(samples).every_kernel();
}

#[test]
fn encode_prefix_takes_the_longest_fitting_prefix() {
    let mut rng = XorShift::new(0x51fe);
    for round in 0..1_500 {
        let pieces = rng.below(if round % 7 == 0 { 30 } else { 10 });
        let text = rng.text(pieces);
        let budget = rng.below(if round % 3 == 0 { 400 } else { 60 });
        for engine in ENGINES {
            let mut out = String::from("x");
            let taken = engine.encode_prefix(&text, budget, &mut out);
            let context = || format!("{engine:?} {budget} {text:?}");
            assert!(text.is_char_boundary(taken), "{}", context());
            let prefix = text.get(..taken).unwrap_or_default();
            assert_eq!(
                out.get(1..),
                Some(engine.encode(prefix).as_str()),
                "{}",
                context()
            );
            assert!(out.len() - 1 <= budget, "{}", context());
            let longer_fits = (taken + 1..=text.len())
                .filter(|&at| text.is_char_boundary(at))
                .any(|at| engine.encoded_len(text.get(..at).unwrap_or_default()) <= budget);
            assert!(!longer_fits, "{}", context());
        }
    }
}

fn folded_reference(
    engine: QuotedPrintable,
    input: &[u8],
    column: &mut usize,
    fold: Fold<'_>,
) -> Vec<u8> {
    let mut out = Vec::new();
    for &byte in input {
        let piece = engine.encode_byte(byte);
        if *column + piece.len() > fold.width && *column > fold.indent {
            out.extend_from_slice(fold.separator);
            *column = fold.indent;
        }
        out.extend_from_slice(piece.as_bytes());
        *column += piece.len();
    }
    out
}

#[test]
fn word_engines_fold_between_escapes() {
    let mut rng = XorShift::new(0xf01d);
    for fold in [
        Fold::DKIM,
        Fold::HEADER,
        Fold::new(10, b"\n", 0),
        Fold::new(4, b" ", 2),
        Fold::new(2, b"\r\n ", 1),
        Fold::new(3000, b"\r\n", 0),
    ] {
        for round in 0..300 {
            let len = rng.lengths(round);
            let input = match round % 3 {
                0 => rng.raw_input(len),
                1 => rng.bytes(len),
                _ => rng.text(len / 4).into_bytes(),
            };
            for engine in [Q_TEXT, Q_PHRASE, DKIM] {
                for start in [0, 1, 40, 75, 76, 80] {
                    let mut expected_column = start;
                    let expected = folded_reference(engine, &input, &mut expected_column, fold);
                    let mut column = start;
                    let mut out = Vec::new();
                    engine.encode_folded(&input, &mut column, fold, |piece| {
                        out.extend_from_slice(piece)
                    });
                    let context = || format!("{engine:?} {fold:?} {start} {}", input.shown());
                    assert_eq!(out, expected, "{}", context());
                    assert_eq!(column, expected_column, "{}", context());
                    let mut appended = String::from("x");
                    let mut column = start;
                    let len = engine.encode_folded_append(&input, &mut appended, &mut column, fold);
                    assert_eq!(appended.as_bytes().get(1..), Some(expected.as_slice()));
                    assert_eq!(len, expected.len());
                }
            }
        }
    }
}

#[test]
fn line_engines_fold_with_soft_breaks() {
    let mut rng = XorShift::new(0xb0d1);
    for round in 0..600 {
        let len = rng.lengths(round);
        let input = rng.raw_input(len);
        for (engine, encode) in [
            (BODY, reference::Body::encode as fn(&[u8]) -> Vec<u8>),
            (BINARY, reference::Binary::encode),
        ] {
            for start in [0, 1, 30, 74, 75, 90] {
                let lead = start.min(75);
                let mut padded = vec![b'a'; lead];
                padded.extend_from_slice(&input);
                let expected = encode(&padded);
                let mut column = start;
                let mut out = b"a".repeat(lead);
                engine.encode_folded(&input, &mut column, Fold::HEADER, |piece| {
                    out.extend_from_slice(piece)
                });
                let context = || format!("{engine:?} {start} {}", input.shown());
                assert_eq!(out, expected, "{}", context());
                let last_line = expected
                    .rsplit(|&byte| byte == b'\n')
                    .next()
                    .unwrap_or_default();
                assert_eq!(column, last_line.len(), "{}", context());
            }
        }
    }
}
