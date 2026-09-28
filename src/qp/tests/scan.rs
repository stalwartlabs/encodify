/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Inputs, Shown};
use crate::{
    Error,
    qp::{BINARY, BODY, DKIM, Q_PHRASE, Q_TEXT, QuotedPrintable},
    test_rng::XorShift,
};
use std::borrow::Cow;

const ENGINES: [QuotedPrintable; 7] = [
    BODY,
    BINARY,
    BODY.strict(),
    BINARY.strict(),
    Q_TEXT,
    Q_PHRASE,
    DKIM,
];
const ALPHABET: &[u8] = b"=\r\n \tA3_?;z\x7f\xc3";
const EXHAUSTIVE_LEN: u32 = 4;

trait Scanned {
    fn check_scans(&self, engine: QuotedPrintable);
}

impl Scanned for [u8] {
    fn check_scans(&self, engine: QuotedPrintable) {
        let mut reference = Vec::new();
        let expected = engine
            .decode_append(self, &mut reference)
            .map(|_| reference);
        let context = || format!("{engine:?} {}", self.shown());
        assert_eq!(
            engine.decoded_len(self),
            expected.as_ref().map(Vec::len).map_err(|&err| err),
            "{}",
            context()
        );
        let decoded = engine.decode(self);
        assert_eq!(decoded.as_deref(), expected.as_deref(), "{}", context());
        if !self.contains(&b'=') && expected.as_deref() == Ok(self) {
            assert!(
                matches!(decoded, Ok(Cow::Borrowed(_))),
                "{} is not borrowed",
                context()
            );
        }
        if let Ok(bytes) = &expected
            && !bytes.is_empty()
        {
            let mut short = vec![0; bytes.len() / 2];
            assert_eq!(
                engine.decode_slice(self, &mut short),
                Err(Error::BufferTooSmall {
                    required: bytes.len()
                }),
                "{}",
                context()
            );
        }
    }
}

#[test]
fn scans_agree_with_decoding_on_every_short_input() {
    let symbols = ALPHABET.len();
    for len in 0..=EXHAUSTIVE_LEN {
        for index in 0..symbols.pow(len) {
            let input: Vec<u8> = (0..len)
                .scan(index, |rest, _| {
                    let symbol = ALPHABET[*rest % symbols];
                    *rest /= symbols;
                    Some(symbol)
                })
                .collect();
            for engine in ENGINES {
                input.check_scans(engine);
            }
        }
    }
}

#[test]
fn scans_agree_with_decoding_on_random_input() {
    let mut rng = XorShift::new(0x5ca7);
    for round in 0..3000 {
        let len = rng.lengths(round);
        let input = match round % 2 {
            0 => rng.qp_input(len),
            _ => rng.raw_input(len),
        };
        for engine in ENGINES {
            input.check_scans(engine);
        }
    }
}

#[test]
fn decoding_borrows_what_it_does_not_change() {
    assert!(matches!(
        BODY.decode("Hello,\r\nworld.\n"),
        Ok(Cow::Borrowed(_))
    ));
    assert!(matches!(Q_TEXT.decode("Hello world"), Ok(Cow::Borrowed(_))));
    assert!(matches!(DKIM.decode("@example.com"), Ok(Cow::Borrowed(_))));
    assert_eq!(
        BODY.decode("line one\r\nline two \r\n").as_deref(),
        Ok(&b"line one\r\nline two\r\n"[..])
    );
    assert_eq!(
        BODY.strict().decode("fine\r\nbad =ZZ"),
        Err(Error::InvalidByte {
            offset: 11,
            byte: b'Z'
        })
    );
}

#[test]
fn decoded_len_counts_without_decoding() {
    assert_eq!(
        BODY.decoded_len("Gr=C3=BC=C3=9Fe \r\nJ=\r\n=C3=BCrgen"),
        Ok(16)
    );
    assert_eq!(Q_TEXT.decoded_len("Andr=E9_Pirard"), Ok(12));
    assert_eq!(DKIM.decoded_len("a=3Db=3B\r\n\t=20c"), Ok(6));
    assert_eq!(
        Q_TEXT.decoded_len("a=4"),
        Err(Error::Truncated { offset: 3 })
    );
    assert_eq!(
        BODY.strict().decoded_len("fine\r\nbad =ZZ"),
        Err(Error::InvalidByte {
            offset: 11,
            byte: b'Z'
        })
    );
}

#[test]
fn scans_agree_with_decoding_across_chunks() {
    const BODIES: [QuotedPrintable; 4] = [BODY, BINARY, BODY.strict(), BINARY.strict()];
    let mut rng = XorShift::new(0xc4a7);
    for round in 0..48 {
        let target = 9_000 + rng.below(4_000);
        let mut input = Vec::with_capacity(target + 3_000);
        while input.len() < target {
            let len = rng.below(if round % 3 == 1 { 3_000 } else { 120 });
            let piece = match round % 3 {
                0 => rng.qp_input(len),
                1 => rng.raw_input(len),
                _ => {
                    let mut line = rng.qp_input(len);
                    line.extend_from_slice(b"\r\n");
                    line
                }
            };
            input.extend_from_slice(&piece);
        }
        for engine in BODIES {
            input.check_scans(engine);
        }
    }
    for (fill, tail) in [
        (4_095, &b"\r\nnext =ZZ"[..]),
        (4_094, b" \r\n=41"),
        (4_096, b"=\r\nabc"),
        (4_096, b" \n"),
        (5_000, b"\n=4"),
        (8_191, b"=\n \t\r\n"),
        (8_192, b""),
        (10_000, b" "),
        (10_000, b"=41"),
        (12_000, b"\r"),
    ] {
        let mut input = vec![b'a'; fill];
        input.extend_from_slice(tail);
        for engine in BODIES {
            input.check_scans(engine);
        }
    }
    for line_end in 4_088usize..4_104 {
        for (snippet, tail) in [
            (&b"=\r\n"[..], &b"x =41 \r\n"[..]),
            (b"= \r\n", b"=ZZ\r\n"),
            (b"=4\n", b"y\t\n=4"),
            (b" \r\n", b" \r z"),
        ] {
            let mut input = vec![b'a'; line_end.saturating_sub(snippet.len())];
            input.extend_from_slice(snippet);
            input.extend_from_slice(tail);
            for engine in BODIES {
                input.check_scans(engine);
            }
        }
    }
    for len in [4_159, 4_161, 8_193, 70_000] {
        for ending in [&b"=4"[..], b"=", b" ", b"=ZZ"] {
            let mut input = vec![b'b'; len];
            input.extend_from_slice(ending);
            for engine in BODIES {
                input.check_scans(engine);
            }
        }
    }
}
