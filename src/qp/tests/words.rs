/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    Check, Inputs, Shown,
    reference::{Digits, Dkim, Failure, Q},
};
use crate::{
    Error,
    buffer::SpareCapacity,
    qp::{
        BINARY, BODY, DKIM, Mode, Q_PHRASE, Q_TEXT, QuotedPrintable,
        kernel::{Job, Kernel},
        words::Words,
    },
    test_rng::XorShift,
};
use std::borrow::Cow;

type Encoder = fn(&[u8]) -> Vec<u8>;

const WORD_ENGINES: [(QuotedPrintable, Encoder); 3] = [
    (Q_TEXT, |input| Q::encode(input, false)),
    (Q_PHRASE, |input| Q::encode(input, true)),
    (DKIM, Dkim::encode),
];

struct WordSamples(Vec<Vec<u8>>);

impl Check for WordSamples {
    fn check<K: Kernel>(&self, kernel: &'static str) {
        for input in &self.0 {
            for (mode, expected) in [
                (Mode::QText, Q::encode(input, false)),
                (Mode::QPhrase, Q::encode(input, true)),
                (Mode::Dkim, Dkim::encode(input)),
            ] {
                let mut out = Vec::new();
                // SAFETY: `Words::run` counts only bytes it wrote; `input.len() * 3 + 1` holds the
                // worst case of three bytes per input byte.
                unsafe {
                    out.append_with(input.len() * 3 + 1, |dst| {
                        Words {
                            table: mode.table(),
                            class: mode.class(),
                            input,
                            dst,
                            budget: usize::MAX,
                            chars: false,
                        }
                        .run::<K>()
                        .1
                    })
                };
                assert_eq!(out, expected, "{kernel} {mode:?} {}", input.shown());
            }
        }
    }
}

#[test]
fn every_kernel_encodes_words() {
    let mut rng = XorShift::new(0x3a7d);
    let alphabet = b"abcdefghij KLMNOP0123456789!*+-/=?_;.:<>~\t";
    let samples = (0..3_000)
        .map(|round| {
            let len = rng.lengths(round);
            match round % 3 {
                0 => (0..len).map(|_| *rng.pick(alphabet)).collect(),
                1 => rng.raw_input(len),
                _ => rng.bytes(len),
            }
        })
        .collect();
    WordSamples(samples).every_kernel();
}

#[test]
fn encodes_words_like_the_reference() {
    let mut rng = XorShift::new(0x9e70);
    for round in 0..6_000 {
        let len = rng.lengths(round);
        let input = match round % 2 {
            0 => rng.raw_input(len),
            _ => rng.bytes(len),
        };
        for (engine, encode) in WORD_ENGINES {
            let expected = encode(&input);
            let context = || format!("{engine:?} {}", input.shown());
            assert_eq!(engine.encode(&input).as_bytes(), expected, "{}", context());
            let mut appended = String::from("prefix");
            assert_eq!(engine.encode_append(&input, &mut appended), expected.len());
            assert_eq!(appended.as_bytes().get(6..), Some(expected.as_slice()));
            let mut exact = vec![0u8; expected.len()];
            assert_eq!(engine.encode_slice(&input, &mut exact), Ok(expected.len()));
            assert_eq!(exact, expected);
            if let Some(short) = expected.len().checked_sub(1) {
                assert_eq!(
                    engine.encode_slice(&input, &mut vec![0u8; short]),
                    Err(Error::BufferTooSmall {
                        required: expected.len()
                    })
                );
                assert_eq!(engine.encoded_len_within(&input, short), None);
            }
            let mut written = Vec::new();
            engine
                .encode_to_writer(&input, &mut written)
                .expect("vec writer");
            assert_eq!(written, expected);
            assert_eq!(engine.encoded_len(&input), expected.len());
            assert_eq!(
                engine.encoded_len_within(&input, expected.len()),
                Some(expected.len())
            );
            assert_eq!(
                engine.decode(&expected).as_deref(),
                Ok(input.as_slice()),
                "{}",
                context()
            );
        }
    }
}

#[test]
fn encodes_large_words() {
    let mut rng = XorShift::new(0x1a7e);
    let input = rng.bytes(40_000);
    for (engine, encode) in WORD_ENGINES {
        let expected = encode(&input);
        let mut written = Vec::new();
        engine
            .encode_to_writer(&input, &mut written)
            .expect("vec writer");
        assert!(written == expected);
        assert!(engine.encode(&input).as_bytes() == expected);
    }
}

#[test]
fn encodes_every_byte_on_its_own() {
    for byte in 0..=u8::MAX {
        let line = match byte {
            b'\t' | b' ' | b'!'..=b'<' | b'>'..=b'~' => vec![byte],
            _ => Digits::escape(b'=', byte).to_vec(),
        };
        for (engine, expected) in [
            (BODY, line.clone()),
            (BINARY, line.clone()),
            (Q_TEXT, Q::encode(&[byte], false)),
            (Q_PHRASE, Q::encode(&[byte], true)),
            (DKIM, Dkim::encode(&[byte])),
        ] {
            assert_eq!(
                engine.encode_byte(byte).as_bytes(),
                expected,
                "{engine:?} {byte}"
            );
            assert_eq!(
                engine.encoded_byte_len(byte),
                expected.len(),
                "{engine:?} {byte}"
            );
        }
    }
}

#[test]
fn decodes_q_like_the_reference() {
    let mut rng = XorShift::new(0x7707);
    for round in 0..8_000 {
        let len = rng.lengths(round);
        let input = rng.qp_input(len);
        for engine in [Q_TEXT, Q_PHRASE] {
            let context = || input.shown();
            let expected = Q::decode(&input, false).map(|(decoded, _)| decoded);
            assert_eq!(
                engine
                    .decode(&input)
                    .map(Cow::into_owned)
                    .map_err(Failure::from),
                expected,
                "{}",
                context()
            );
            let expected = Q::decode(&input, true);
            assert_eq!(
                engine.decode_word(&input).map_err(Failure::from),
                expected,
                "{}",
                context()
            );
            let mut appended = b"prefix".to_vec();
            match engine.decode_word_append(&input, &mut appended) {
                Ok(used) => {
                    assert_eq!(Some(used), expected.as_ref().ok().map(|(_, used)| *used));
                    assert_eq!(
                        appended.get(6..),
                        expected
                            .as_ref()
                            .ok()
                            .map(|(decoded, _)| decoded.as_slice())
                    );
                }
                Err(_) => assert_eq!(appended, b"prefix"),
            }
        }
    }
}

#[test]
fn rfc2047_examples() {
    for (word, expected) in [
        (&b"Keith_Moore?="[..], &b"Keith Moore"[..]),
        (b"Keld_J=F8rn_Simonsen?=", b"Keld J\xf8rn Simonsen"),
        (b"Andr=E9?=", b"Andr\xe9"),
        (b"Olle_J=E4rnefors?=", b"Olle J\xe4rnefors"),
        (b"Patrik_F=E4ltstr=F6m?=", b"Patrik F\xe4ltstr\xf6m"),
        (b"a?=", b"a"),
        (b"a_b?=", b"a b"),
        (b"_b?=", b" b"),
        (b"?=", b""),
    ] {
        assert_eq!(
            Q_TEXT.decode_word(word),
            Ok((expected.to_vec(), word.len()))
        );
        let payload = word.strip_suffix(b"?=").unwrap_or(word);
        assert_eq!(Q_PHRASE.encode(expected).as_bytes(), payload);
        assert_eq!(Q_TEXT.encode(expected).as_bytes(), payload);
    }
    assert_eq!(Q_TEXT.encode("hello ? world ?"), "hello_=3F_world_=3F");
    assert_eq!(Q_PHRASE.encode("O'Brien (Jr.)"), "O=27Brien_=28Jr=2E=29");
    assert_eq!(Q_TEXT.encode("O'Brien (Jr.)"), "O'Brien_(Jr.)");
    assert_eq!(Q_TEXT.encode("tab\there\x01"), "tab=09here=01");
}

#[test]
fn q_word_edge_cases() {
    for (word, expected) in [
        (&b"abc"[..], Err(Error::Truncated { offset: 3 })),
        (
            b"=4?=",
            Err(Error::InvalidByte {
                offset: 2,
                byte: b'?',
            }),
        ),
        (
            b"=G1?=",
            Err(Error::InvalidByte {
                offset: 1,
                byte: b'G',
            }),
        ),
        (b"ab=", Err(Error::Truncated { offset: 3 })),
        (b"ab=4", Err(Error::Truncated { offset: 4 })),
        (
            b"this=20is=20\r\n  some=20text?=",
            Ok((&b"this is some text"[..], 29)),
        ),
        (b"a b\tc?= rest", Ok((b"a b\tc", 7))),
        (b"????=", Ok((b"???", 5))),
        (b"=3F=3D?=", Ok((b"?=", 8))),
    ] {
        assert_eq!(
            Q_TEXT.decode_word(word),
            expected.map(|(decoded, used)| (decoded.to_vec(), used)),
            "{}",
            word.shown()
        );
    }
}

#[test]
fn decodes_dkim_like_the_reference() {
    let mut rng = XorShift::new(0xd41);
    for round in 0..8_000 {
        let len = rng.lengths(round);
        let input = match round % 3 {
            0 => rng.qp_input(len),
            1 => DKIM.encode(rng.bytes(len)).into_bytes(),
            _ => {
                let raw = rng.raw_input(len);
                let mut text = DKIM.encode(raw).into_bytes();
                for _ in 0..rng.below(4) {
                    let at = rng.below(text.len() + 1);
                    text.insert(at, *rng.pick(b" \t\r\n;=|"));
                }
                text
            }
        };
        let context = || input.shown();
        let expected = Dkim::decode(&input);
        assert_eq!(
            DKIM.decode(&input)
                .map(Cow::into_owned)
                .map_err(Failure::from),
            expected,
            "{}",
            context()
        );
        let value = input.split(|&byte| byte == b';').next().unwrap_or_default();
        let expected =
            Dkim::decode(value).map(|decoded| (decoded, (value.len() + 1).min(input.len())));
        assert_eq!(
            DKIM.decode_word(&input).map_err(Failure::from),
            expected,
            "{}",
            context()
        );
    }
}

#[test]
fn rfc6376_examples() {
    let copied = concat!(
        "From:foo@eng.example.net|To:joe@example.com|\r\n",
        "\tSubject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700"
    );
    assert_eq!(
        DKIM.decode(copied).as_deref(),
        Ok(
            &b"From:foo@eng.example.net|To:joe@example.com|Subject:demo run|Date:July 5, 2005 3:44:08 PM -0700"
                [..]
        )
    );
    assert_eq!(DKIM.encode("demo run"), "demo=20run");
    assert_eq!(
        DKIM.encode("a=b;c d\r\n\u{e9}"),
        "a=3Db=3Bc=20d=0D=0A=C3=A9"
    );
    assert_eq!(
        DKIM.decode_word("@eng.example.net; s=brisbane"),
        Ok((b"@eng.example.net".to_vec(), 17))
    );
    assert_eq!(
        DKIM.decode("a;b"),
        Err(Error::InvalidByte {
            offset: 1,
            byte: b';'
        })
    );
    assert_eq!(DKIM.decode("=4 1=4\r\n\t2").as_deref(), Ok(&b"AB"[..]));
    assert_eq!(DKIM.encode("From:a|To:b"), "From:a=7CTo:b");
    assert_eq!(DKIM.encode_byte(b'|'), "=7C");
    assert_eq!(DKIM.encoded_byte_len(b'|'), 3);
    assert_eq!(
        DKIM.decode("From:a=7CTo:b|x").as_deref(),
        Ok(&b"From:a|To:b|x"[..])
    );
    assert_eq!(
        DKIM.decode("caf\u{e9}").as_deref(),
        Ok("caf\u{e9}".as_bytes())
    );
    assert_eq!(
        DKIM.decode("a\x7f"),
        Err(Error::InvalidByte {
            offset: 1,
            byte: 0x7f
        })
    );
}
