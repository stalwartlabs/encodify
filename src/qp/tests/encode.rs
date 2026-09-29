/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    Check, Inputs, Shown,
    reference::{self, Wrapping},
};
use crate::{
    Error,
    buffer::SpareCapacity,
    qp::{
        BINARY, BODY, QuotedPrintable,
        count::Count,
        encode::Lines,
        kernel::{Job, Kernel},
    },
    test_rng::{XorShift, lengths, scaled},
};

const MIN_ROOM: usize = 6;

struct Samples(Vec<Vec<u8>>);

impl Samples {
    fn encode_with<K: Kernel, const BINARY: bool>(input: &[u8], room: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut column = 0;
        let mut rest = input;
        while !rest.is_empty() {
            let mut read = 0;
            // SAFETY: `Lines::run` counts only bytes it wrote into `dst` (room is checked per step,
            // or reserved by the span bound).
            unsafe {
                out.append_with(room, |dst| {
                    let (consumed, written) = Lines::<BINARY> {
                        input: rest,
                        column: &mut column,
                        dst,
                    }
                    .run::<K>();
                    read = consumed;
                    written
                })
            };
            assert!(read > 0, "no progress with {room} bytes of room");
            rest = rest.get(read..).unwrap_or_default();
        }
        out
    }

    fn count_with<K: Kernel, const BINARY: bool>(input: &[u8], limit: usize) -> Option<usize> {
        Count::<BINARY> { input, limit }.run::<K>()
    }

    fn check_mode<K: Kernel, const BINARY: bool>(&self, kernel: &'static str) {
        for (index, input) in self.0.iter().enumerate() {
            let expected = match BINARY {
                true => reference::Binary::encode(input),
                false => reference::Body::encode(input),
            };
            let context = || format!("{kernel} binary={BINARY} {}", input.shown());
            assert_eq!(
                Self::encode_with::<K, BINARY>(input, 4 * input.len() + 64),
                expected,
                "{}",
                context()
            );
            for room in [MIN_ROOM + index % 90, 500 + index % 900] {
                assert_eq!(
                    Self::encode_with::<K, BINARY>(input, room),
                    expected,
                    "room {room} {}",
                    context()
                );
            }
            assert_eq!(
                Self::count_with::<K, BINARY>(input, usize::MAX),
                Some(expected.len()),
                "{}",
                context()
            );
            assert_eq!(
                Self::count_with::<K, BINARY>(input, expected.len()),
                Some(expected.len())
            );
            if let Some(short) = expected.len().checked_sub(1) {
                assert_eq!(
                    Self::count_with::<K, BINARY>(input, short),
                    None,
                    "{}",
                    context()
                );
            }
        }
    }
}

impl Check for Samples {
    fn check<K: Kernel>(&self, kernel: &'static str) {
        self.check_mode::<K, false>(kernel);
        self.check_mode::<K, true>(kernel);
    }
}

#[test]
fn every_kernel_encodes_like_the_reference() {
    let mut rng = XorShift::new(0xe4c0);
    let samples = (0..scaled(3_000))
        .map(|round| {
            let len = rng.lengths(round);
            rng.raw_input(len)
        })
        .collect();
    Samples(samples).every_kernel();
}

#[test]
fn every_kernel_handles_line_boundaries() {
    let mut samples = Vec::new();
    for len in lengths(160) {
        for tail in [
            &b""[..],
            b" ",
            b"\t",
            b"=",
            b"\xc3\xa9",
            b" \r\n",
            b"\n",
            b"\r",
            b"  x",
        ] {
            let mut input = vec![b'a'; len];
            input.extend_from_slice(tail);
            samples.push(input.clone());
            input.extend_from_slice(b"more");
            samples.push(input);
            let mut dense = vec![0xe9; len / 2];
            dense.extend_from_slice(tail);
            samples.push(dense);
        }
    }
    Samples(samples).every_kernel();
}

trait Decoded {
    fn decoded_form(&self, input: &[u8]) -> Vec<u8>;
}

impl Decoded for QuotedPrintable {
    fn decoded_form(&self, input: &[u8]) -> Vec<u8> {
        if *self == BINARY {
            return input.to_vec();
        }
        let mut out = Vec::with_capacity(input.len() * 2);
        let mut previous = 0;
        for &byte in input {
            if byte == b'\n' && previous != b'\r' {
                out.push(b'\r');
            }
            out.push(byte);
            previous = byte;
        }
        out
    }
}

#[test]
fn encodes_through_every_sink() {
    let mut rng = XorShift::new(0x51c4);
    for round in 0..scaled(2_000) {
        let len = rng.lengths(round);
        let input = rng.raw_input(len);
        for (engine, expected) in [
            (BODY, reference::Body::encode(&input)),
            (BINARY, reference::Binary::encode(&input)),
        ] {
            let context = || input.shown();
            Wrapping::check(&expected).unwrap_or_else(|err| panic!("{err} {}", context()));
            assert_eq!(engine.encode(&input).as_bytes(), expected, "{}", context());
            let mut appended = b"prefix".to_vec();
            assert_eq!(engine.encode_append(&input, &mut appended), expected.len());
            assert_eq!(appended.get(6..), Some(expected.as_slice()));
            let mut text = String::from("prefix");
            assert_eq!(engine.encode_append(&input, &mut text), expected.len());
            assert_eq!(text.as_bytes().get(6..), Some(expected.as_slice()));
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
            assert_eq!(written, expected, "{}", context());
            assert_eq!(engine.encoded_len(&input), expected.len());
            assert_eq!(
                engine.encoded_len_within(&input, expected.len()),
                Some(expected.len())
            );
            assert_eq!(
                engine.decode(&expected).as_deref(),
                Ok(engine.decoded_form(&input).as_slice()),
                "{}",
                context()
            );
        }
    }
}

#[test]
fn encodes_large_inputs() {
    let mut rng = XorShift::new(0x1a46e);
    for len in [70_000, 300_000] {
        let latin: Vec<u8> = rng.raw_input(len);
        let mixed: Vec<u8> = latin
            .iter()
            .take(len / 2)
            .copied()
            .chain(rng.bytes(len / 2))
            .collect();
        for input in [latin, mixed, rng.bytes(len)] {
            for (engine, expected) in [
                (BODY, reference::Body::encode(&input)),
                (BINARY, reference::Binary::encode(&input)),
            ] {
                assert!(engine.encode(&input).as_bytes() == expected);
                let mut appended = vec![b'x'; 3];
                engine.encode_append(&input, &mut appended);
                assert!(appended.get(3..) == Some(expected.as_slice()));
                let mut written = Vec::new();
                engine
                    .encode_to_writer(&input, &mut written)
                    .expect("vec writer");
                assert!(written == expected);
                assert_eq!(engine.encoded_len(&input), expected.len());
                assert_eq!(engine.encoded_len_within(&input, expected.len() / 2), None);
            }
        }
    }
}

#[test]
fn mail_builder_vectors() {
    for (input, body, binary) in [
        ("hello world", "hello world", "hello world"),
        ("hello_world", "hello_world", "hello_world"),
        ("hello ? world ?", "hello ? world ?", "hello ? world ?"),
        (
            "hello = world =",
            "hello =3D world =3D",
            "hello =3D world =3D",
        ),
        ("hello\nworld\n", "hello\r\nworld\r\n", "hello=0Aworld=0A"),
        (
            "hello   \nworld   \r\n   ",
            "hello  =20\r\nworld  =20\r\n  =20",
            "hello   =0Aworld   =0D=0A  =20",
        ),
        (
            "hello   \nworld   \n",
            "hello  =20\r\nworld  =20\r\n",
            "hello   =0Aworld   =0A",
        ),
        (
            "áéíóú",
            "=C3=A1=C3=A9=C3=AD=C3=B3=C3=BA",
            "=C3=A1=C3=A9=C3=AD=C3=B3=C3=BA",
        ),
        (
            "안녕하세요 세계",
            "=EC=95=88=EB=85=95=ED=95=98=EC=84=B8=EC=9A=94 =EC=84=B8=EA=B3=84",
            "=EC=95=88=EB=85=95=ED=95=98=EC=84=B8=EC=9A=94 =EC=84=B8=EA=B3=84",
        ),
    ] {
        assert_eq!(BODY.encode(input), body, "{input:?}");
        assert_eq!(BINARY.encode(input), binary, "{input:?}");
    }
    let spaces = " ".repeat(100);
    let expected = " ".repeat(75) + "=\r\n" + &" ".repeat(24) + "=20";
    assert_eq!(BODY.encode(&spaces), expected);
    assert_eq!(BINARY.encode(&spaces), expected);
    let accents = BODY.encode("é".repeat(100));
    assert_eq!(accents.len(), 8 * 75 + 7 * 3);
    assert!(accents.starts_with(&"=C3=A9".repeat(12)));
    assert!(accents.ends_with(&"=C3=A9".repeat(12)));
}

#[test]
fn rfc2045_rules() {
    let text = "Now's the time for all folk to come to the aid of their country.";
    assert_eq!(BODY.encode(text), text);
    assert_eq!(BODY.encode("tab\tand space \r\n"), "tab\tand space=20\r\n");
    assert_eq!(
        BODY.encode("bell\x07 del\x7f nul\x00"),
        "bell=07 del=7F nul=00"
    );
    assert_eq!(BODY.encode("bare\rcr\r\n"), "bare=0Dcr\r\n");
    assert_eq!(BINARY.encode("a\r\nb"), "a=0D=0Ab");
    assert_eq!(BODY.encode(""), "");
    assert_eq!(BODY.encode("\n"), "\r\n");
    assert_eq!(BODY.encode(" "), "=20");
}
