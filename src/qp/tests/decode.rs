/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    Check, Inputs, Shown,
    reference::{self, Failure},
};
use crate::{
    Error,
    buffer::SpareCapacity,
    qp::{
        BINARY, BODY,
        decode::Body,
        kernel::{Job, Kernel},
    },
    test_rng::XorShift,
};

struct Samples(Vec<Vec<u8>>);

impl Samples {
    fn decode_with<K: Kernel>(input: &[u8], strict: bool) -> Result<Vec<u8>, Failure> {
        let mut out = Vec::new();
        let mut result = Ok(());
        // SAFETY: `Body::run` never writes more bytes than it reads, so the `input.len() + 64`
        // region has room and it initialises every byte it counts; errors count 0.
        unsafe {
            out.append_with(input.len() + 64, |dst| {
                match (Body { input, dst, strict }).run::<K>() {
                    Ok(written) => written,
                    Err(err) => {
                        result = Err(Failure::from(err));
                        0
                    }
                }
            })
        };
        result.map(|()| out)
    }
}

impl Check for Samples {
    fn check<K: Kernel>(&self, kernel: &'static str) {
        for input in &self.0 {
            for strict in [false, true] {
                assert_eq!(
                    Self::decode_with::<K>(input, strict),
                    reference::Body::decode(input, strict),
                    "{kernel} strict={strict} {}",
                    input.shown()
                );
            }
        }
    }
}

#[test]
fn every_kernel_decodes_like_the_reference() {
    let mut rng = XorShift::new(0x5157);
    let samples = (0..6_000)
        .map(|round| {
            let len = rng.lengths(round);
            rng.qp_input(len)
        })
        .collect();
    Samples(samples).every_kernel();
}

#[test]
fn every_kernel_handles_block_boundaries() {
    let mut samples = Vec::new();
    for len in 0..70 {
        for special in [
            &b"="[..],
            b"=\r\n",
            b"=41",
            b"\r\n",
            b"\n",
            b"\r",
            b" \r\n",
            b"=4",
        ] {
            let mut input = vec![b'x'; len];
            input.extend_from_slice(special);
            input.extend_from_slice(b"tail text that is long enough for a vector");
            samples.push(input.clone());
            input.truncate(len + special.len());
            samples.push(input);
        }
    }
    Samples(samples).every_kernel();
}

#[test]
fn decodes_through_every_sink() {
    let mut rng = XorShift::new(0xdec0);
    for round in 0..4_000 {
        let len = rng.lengths(round);
        let input = rng.qp_input(len);
        for engine in [BODY, BINARY, BODY.strict()] {
            let expected = reference::Body::decode(&input, engine.is_strict());
            let actual = engine.decode(&input);
            assert_eq!(
                actual.as_deref().map_err(|&err| Failure::from(err)),
                expected.as_deref().map_err(|&err| err),
                "{}",
                input.shown()
            );
            let mut appended = b"prefix".to_vec();
            match engine.decode_append(&input, &mut appended) {
                Ok(written) => {
                    assert_eq!(appended.get(6..), expected.as_deref().ok());
                    assert_eq!(written, appended.len() - 6);
                }
                Err(_) => assert_eq!(appended, b"prefix"),
            }
            let Ok(expected) = expected else {
                continue;
            };
            let mut exact = vec![0u8; expected.len()];
            assert_eq!(engine.decode_slice(&input, &mut exact), Ok(expected.len()));
            assert_eq!(exact, expected);
            let mut roomy = vec![0u8; input.len() + 3];
            assert_eq!(engine.decode_slice(&input, &mut roomy), Ok(expected.len()));
            assert_eq!(roomy.get(..expected.len()), Some(expected.as_slice()));
            if let Some(short) = expected.len().checked_sub(1) {
                assert_eq!(
                    engine.decode_slice(&input, &mut vec![0u8; short]),
                    Err(Error::BufferTooSmall {
                        required: expected.len()
                    })
                );
            }
            assert_eq!(engine.decode_word(&input), Ok((expected, input.len())));
        }
    }
}

#[test]
fn rfc2045_soft_breaks() {
    let encoded = "Now's the time =\r\nfor all folk to come=\r\n to the aid of their country.";
    assert_eq!(
        BODY.decode(encoded).as_deref(),
        Ok(&b"Now's the time for all folk to come to the aid of their country."[..])
    );
    assert_eq!(
        BODY.decode(concat!(
            "hello  \r\nbar=\r\n\r\nfoo\t=\r\nbar\r\nfoo\t \t= \r\n=62\r\nfoo = \t\r\n",
            "bar\r\nfoo =\r\n=62\r\nfoo  \r\nbar=\r\n\r\nfoo_bar\r\n"
        ))
        .as_deref(),
        Ok(
            &b"hello\r\nbar\r\nfoo\tbar\r\nfoo\t \tb\r\nfoo bar\r\nfoo b\r\nfoo\r\nbar\r\nfoo_bar\r\n"
                [..]
        )
    );
}

#[test]
fn keeps_line_breaks_and_drops_bare_cr() {
    for (input, expected) in [
        (&b"a\nb\r\nc\n"[..], &b"a\nb\r\nc\n"[..]),
        (b"a\r\nb\nc", b"a\r\nb\nc"),
        (b"a\rb\r", b"ab"),
        (b"a \r\n", b"a\r\n"),
        (b"a \t", b"a"),
        (b"a=20", b"a "),
        (b"a=20 \t\r\n", b"a \r\n"),
        (b"a \r \r\n", b"a\r\n"),
        (b"a \rb", b"a b"),
        (b"a =\r\n\r\n", b"a \r\n"),
        (b"a=\n\nb", b"a\nb"),
        (b"=\r\n", b""),
        (b"\n\n", b"\n\n"),
    ] {
        assert_eq!(
            BODY.decode(input).as_deref(),
            Ok(expected),
            "{}",
            input.shown()
        );
    }
}

#[test]
fn lenient_decoding_keeps_malformed_escapes() {
    for (input, expected) in [
        (&b"=4G"[..], &b"=4G"[..]),
        (b"==41", b"==41"),
        (b"=4=41", b"=4A"),
        (b"a=\rb", b"a=b"),
        (b"=4", b"=4"),
        (b"=", b""),
        (b"a =  ", b"a "),
        (b"= x", b"= x"),
        (b"=\xc3\xa9", b"=\xc3\xa9"),
        (b"=41=4a=4A", b"AJJ"),
        (b"=4\r\n", b"=4\r\n"),
    ] {
        assert_eq!(
            BODY.decode(input).as_deref(),
            Ok(expected),
            "{}",
            input.shown()
        );
    }
}

#[test]
fn strict_errors_point_at_the_offending_byte() {
    let strict = BODY.strict();
    for (input, error) in [
        (
            &b"ab=4G"[..],
            Error::InvalidByte {
                offset: 4,
                byte: b'G',
            },
        ),
        (
            b"ab=G4",
            Error::InvalidByte {
                offset: 3,
                byte: b'G',
            },
        ),
        (
            b"==41",
            Error::InvalidByte {
                offset: 1,
                byte: b'=',
            },
        ),
        (b"ab=4", Error::Truncated { offset: 4 }),
        (
            b"a= x",
            Error::InvalidByte {
                offset: 3,
                byte: b'x',
            },
        ),
        (
            b"a=\rb",
            Error::InvalidByte {
                offset: 2,
                byte: b'\r',
            },
        ),
        (
            b"a=4\r\n",
            Error::InvalidByte {
                offset: 3,
                byte: b'\r',
            },
        ),
    ] {
        assert_eq!(strict.decode(input), Err(error), "{}", input.shown());
    }
    assert_eq!(strict.decode("a= \t").as_deref(), Ok(&b"a"[..]));
    assert_eq!(
        strict.decode("caf=C3=A9 =\r\n").as_deref(),
        Ok("café ".as_bytes())
    );
}
