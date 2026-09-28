/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    Alphabet, Base64, LENIENT, LineEnding, MIME, Padding, STANDARD, STANDARD_NO_PAD, URL_SAFE,
    URL_SAFE_NO_PAD,
    alphabet::{self, INVALID},
};
use crate::{Error, test_rng::XorShift};
use ::base64::{
    Engine as _,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};

fn reference_engine(engine: &Base64) -> GeneralPurpose {
    let alphabet = match engine.alphabet() {
        Alphabet::Standard => &::base64::alphabet::STANDARD,
        Alphabet::UrlSafe => &::base64::alphabet::URL_SAFE,
    };
    let (encode_padding, mode) = match engine.padding() {
        Padding::Required => (true, DecodePaddingMode::RequireCanonical),
        Padding::Omitted => (false, DecodePaddingMode::RequireNone),
        Padding::Optional => (true, DecodePaddingMode::Indifferent),
    };
    GeneralPurpose::new(
        alphabet,
        GeneralPurposeConfig::new()
            .with_encode_padding(encode_padding)
            .with_decode_padding_mode(mode),
    )
}

fn reference_lenient(engine: &Base64, input: &[u8]) -> Result<Vec<u8>, usize> {
    let table = &engine.decode_tables().decode;
    let mut out = Vec::new();
    let mut word = 0u32;
    let mut pending = 0;
    let flush = |out: &mut Vec<u8>, word: u32, pending: u8| match pending {
        2 => out.push((word >> 4) as u8),
        3 => out.extend_from_slice(&[(word >> 10) as u8, (word >> 2) as u8]),
        _ => {}
    };
    for (offset, &byte) in input.iter().enumerate() {
        let value = table[byte as usize];
        if value != INVALID {
            word = (word << 6) | value as u32;
            pending += 1;
            if pending == 4 {
                out.extend_from_slice(&word.to_be_bytes()[1..]);
                word = 0;
                pending = 0;
            }
        } else if byte == b'=' {
            flush(&mut out, word, pending);
            word = 0;
            pending = 0;
        } else if !matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c) {
            return Err(offset);
        }
    }
    flush(&mut out, word, pending);
    Ok(out)
}

fn reference_wrapped(encoded: &str, width: usize, ending: &str) -> String {
    let mut out = String::new();
    for line in encoded.as_bytes().chunks(width) {
        out.push_str(std::str::from_utf8(line).expect("ascii"));
        out.push_str(ending);
    }
    out
}

const STRICT_ENGINES: [Base64; 6] = [
    STANDARD,
    STANDARD_NO_PAD,
    URL_SAFE,
    URL_SAFE_NO_PAD,
    STANDARD.with_padding(Padding::Optional),
    URL_SAFE.with_padding(Padding::Optional),
];

#[test]
fn encodes_like_the_base64_crate_for_every_length() {
    let mut rng = XorShift::new(1);
    for len in 0..700 {
        let input = rng.bytes(len);
        for engine in STRICT_ENGINES {
            let expected = reference_engine(&engine).encode(&input);
            assert_eq!(engine.encode(&input), expected, "{engine:?} {len}");
            assert_eq!(engine.encoded_len(len), expected.len());
            let mut appended = b"prefix".to_vec();
            assert_eq!(engine.encode_append(&input, &mut appended), expected.len());
            assert_eq!(&appended[6..], expected.as_bytes());
            let mut exact = vec![0u8; expected.len()];
            assert_eq!(engine.encode_slice(&input, &mut exact), Ok(expected.len()));
            assert_eq!(exact, expected.as_bytes());
            if !expected.is_empty() {
                let mut short = vec![0u8; expected.len() - 1];
                assert_eq!(
                    engine.encode_slice(&input, &mut short),
                    Err(Error::BufferTooSmall {
                        required: expected.len()
                    })
                );
            }
            let mut written = Vec::new();
            engine
                .encode_to_writer(&input, &mut written)
                .expect("vec writer");
            assert_eq!(written, expected.as_bytes());
            assert_eq!(engine.display(&input).to_string(), expected);
        }
    }
}

#[test]
fn encodes_large_inputs_through_every_sink() {
    let mut rng = XorShift::new(2);
    for len in [4095, 4096, 4097, 65_536 + 7, 1 << 20] {
        let input = rng.bytes(len);
        let expected = reference_engine(&STANDARD).encode(&input);
        assert_eq!(STANDARD.encode(&input), expected);
        let mut written = Vec::new();
        STANDARD
            .encode_to_writer(&input, &mut written)
            .expect("vec writer");
        assert_eq!(written, expected.as_bytes());
        assert_eq!(STANDARD.display(&input).to_string(), expected);
        let wrapped = reference_wrapped(&expected, 76, "\r\n");
        assert_eq!(MIME.encode(&input), wrapped);
        let mut written = Vec::new();
        MIME.encode_to_writer(&input, &mut written)
            .expect("vec writer");
        assert_eq!(written, wrapped.as_bytes());
        assert_eq!(MIME.display(&input).to_string(), wrapped);
    }
}

#[test]
fn wraps_lines_with_the_requested_width_and_ending() {
    let mut rng = XorShift::new(3);
    for (width, ending, text) in [
        (76, LineEnding::CrLf, "\r\n"),
        (64, LineEnding::Lf, "\n"),
        (4, LineEnding::Lf, "\n"),
        (72, LineEnding::CrLf, "\r\n"),
    ] {
        let engine = STANDARD.wrapped(width, ending);
        for len in 0..400 {
            let input = rng.bytes(len);
            let expected = reference_wrapped(&STANDARD.encode(&input), width, text);
            assert_eq!(engine.encode(&input), expected, "{width} {len}");
            assert_eq!(engine.encoded_len(len), expected.len(), "{width} {len}");
        }
    }
}

#[test]
fn decodes_strict_engines_like_the_base64_crate() {
    let mut rng = XorShift::new(4);
    let noise = b"=\r\n \t-_+/.\x00\xffA";
    for round in 0..40_000 {
        let len = rng.below(if round % 10 == 0 { 400 } else { 40 });
        let input = rng.bytes(len);
        for engine in STRICT_ENGINES {
            let mut text = reference_engine(&engine).encode(&input).into_bytes();
            if round % 3 != 0 && !text.is_empty() {
                for _ in 0..1 + rng.below(2) {
                    let at = rng.below(text.len() + 1);
                    match rng.below(3) {
                        0 => text.insert(at, *rng.pick(noise)),
                        1 if at < text.len() => {
                            text.remove(at);
                        }
                        _ if at < text.len() => text[at] = *rng.pick(noise),
                        _ => {}
                    }
                }
            }
            let padding = text.iter().rev().take_while(|&&byte| byte == b'=').count();
            let partial_padding = padding > 0 && (text.len() - padding) % 4 + padding != 4;
            let expected = reference_engine(&engine)
                .decode(&text)
                .ok()
                .filter(|_| !partial_padding);
            let actual = engine.decode(&text);
            assert_eq!(
                actual.as_ref().ok(),
                expected.as_ref(),
                "{engine:?} {:?} {actual:?}",
                String::from_utf8_lossy(&text)
            );
            assert_eq!(
                engine.decoded_len(&text).ok(),
                expected.as_ref().map(Vec::len),
                "{engine:?} {:?}",
                String::from_utf8_lossy(&text)
            );
            let mut in_place = text.clone();
            assert_eq!(
                engine
                    .decode_in_place(&mut in_place)
                    .ok()
                    .map(|out| out.to_vec()),
                expected
            );
        }
    }
}

#[test]
fn strict_errors_point_at_the_offending_byte() {
    for (engine, input, error) in [
        (
            STANDARD,
            &b"QUJD*EVG"[..],
            Error::InvalidByte {
                offset: 4,
                byte: b'*',
            },
        ),
        (STANDARD, b"QQ==QUJD", Error::InvalidPadding { offset: 2 }),
        (STANDARD, b"QUJDR", Error::Truncated { offset: 5 }),
        (STANDARD, b"QQ", Error::InvalidPadding { offset: 2 }),
        (STANDARD, b"QR==", Error::NonCanonical { offset: 1 }),
        (
            STANDARD_NO_PAD,
            b"QQ==",
            Error::InvalidPadding { offset: 2 },
        ),
        (
            URL_SAFE_NO_PAD,
            b"AB+/",
            Error::InvalidByte {
                offset: 2,
                byte: b'+',
            },
        ),
        (
            STANDARD,
            b"QUJD\r\nQUJD",
            Error::InvalidByte {
                offset: 4,
                byte: b'\r',
            },
        ),
    ] {
        assert_eq!(engine.decode(input), Err(error), "{input:?}");
        assert_eq!(engine.decoded_len(input), Err(error), "{input:?}");
    }
}

fn lenient_samples(rng: &mut XorShift, count: usize) -> Vec<Vec<u8>> {
    let pieces: &[&[u8]] = &[
        b"=",
        b"==",
        b" ",
        b"\t",
        b"\r\n",
        b"\n",
        b"\r\n\t",
        b"\x0b",
        b"\x0c",
        b"-",
        b"_",
        b"\\",
        b"\xff",
        b"\xc3\xa9",
        b":",
        b";",
        b",",
        b".",
        b"\x00",
    ];
    let mut samples = Vec::with_capacity(count);
    for round in 0..count {
        let len = rng.below(match round % 10 {
            0 => 3000,
            1..=3 => 300,
            _ => 40,
        });
        let raw = rng.bytes(len);
        let encoded = STANDARD.encode(&raw).into_bytes();
        let mut text = match round % 4 {
            0 => encoded,
            1 => reference_wrapped(std::str::from_utf8(&encoded).expect("ascii"), 76, "\r\n")
                .into_bytes(),
            2 => reference_wrapped(
                std::str::from_utf8(&encoded).expect("ascii"),
                4 * (1 + rng.below(30)),
                "\n",
            )
            .into_bytes(),
            _ => encoded
                .chunks(1 + rng.below(90))
                .flat_map(|line| line.iter().copied().chain(*b"\r\n "))
                .collect(),
        };
        let density = 1 + rng.below(200);
        let mut noisy: Vec<u8> = Vec::with_capacity(text.len() + 16);
        for byte in text.drain(..) {
            if rng.below(density) == 0 {
                let piece = rng.pick(pieces);
                noisy.extend_from_slice(piece);
            }
            noisy.push(byte);
        }
        samples.push(noisy);
    }
    samples
}

#[test]
fn lenient_decoding_follows_the_reference_rules() {
    let mut rng = XorShift::new(5);
    for text in lenient_samples(&mut rng, 20_000) {
        let expected = reference_lenient(&LENIENT, &text);
        let actual = LENIENT.decode(&text);
        match (&expected, &actual) {
            (Ok(expected), Ok(actual)) => assert_eq!(actual, expected),
            (Err(offset), Err(error)) => assert_eq!(error.offset(), Some(*offset)),
            _ => panic!(
                "{:?} expected {expected:?} got {actual:?}",
                String::from_utf8_lossy(&text)
            ),
        }
        assert_eq!(
            LENIENT.decoded_len(&text).ok(),
            expected.as_ref().ok().map(Vec::len)
        );
        let mut in_place = text.clone();
        assert_eq!(
            LENIENT
                .decode_in_place(&mut in_place)
                .ok()
                .map(|out| out.to_vec()),
            expected.clone().ok()
        );
        if let Ok(expected) = &expected {
            let mut exact = vec![0u8; expected.len()];
            assert_eq!(LENIENT.decode_slice(&text, &mut exact), Ok(expected.len()));
            assert_eq!(&exact, expected);
            if !expected.is_empty() {
                let mut short = vec![0u8; expected.len() - 1];
                assert_eq!(
                    LENIENT.decode_slice(&text, &mut short),
                    Err(Error::BufferTooSmall {
                        required: expected.len()
                    })
                );
            }
        }
    }
}

#[test]
fn lenient_decoding_edge_cases() {
    for (input, expected) in [
        (&b""[..], Some(&b""[..])),
        (b"=", Some(b"")),
        (b"QUJDRA", Some(b"ABCD")),
        (b"QUI", Some(b"AB")),
        (b"QQ", Some(b"A")),
        (b"Q", Some(b"")),
        (b"QUJDQ=", Some(b"ABC")),
        (b"QQ==QUJD", Some(b"AABC")),
        (b"/9", Some(b"\xff")),
        (b"QU\xff", None),
        (b"QU*", None),
        (b" Q U J D \r\n\t\x0b\x0c", Some(b"ABC")),
    ] {
        assert_eq!(LENIENT.decode(input).ok().as_deref(), expected, "{input:?}");
    }
}

#[test]
fn slice_decoding_stays_within_its_output() {
    const SENTINEL: u8 = 0xa5;
    let mut rng = XorShift::new(47);
    for len in (0..300).chain([1000, 4096, 4099]) {
        let data = rng.bytes(len);
        for engine in [STANDARD, URL_SAFE_NO_PAD, MIME, LENIENT] {
            let text = engine.encode(&data);
            let mut out = vec![SENTINEL; len + 64];
            assert_eq!(
                engine.decode_slice(&text, &mut out),
                Ok(len),
                "{engine:?} {len}"
            );
            assert_eq!(out[..len], data[..], "{engine:?} {len}");
            let untouched = if engine.is_lenient() {
                engine.decoded_len_estimate(text.len())
            } else {
                len
            };
            assert!(
                out.iter().skip(untouched).all(|&byte| byte == SENTINEL),
                "{engine:?} {len}"
            );
        }
    }
}

#[test]
fn in_place_decoding_reports_the_same_errors() {
    for input in [
        &b"QU*DQ"[..],
        b"QU*DQQ",
        b"QU*DQQ=",
        b"Q=QUJD==",
        b"QUJDRA=x",
        b"QUJDRB==",
    ] {
        let mut buffer = input.to_vec();
        assert_eq!(
            STANDARD
                .decode_in_place(&mut buffer)
                .map(|out| out.to_vec()),
            STANDARD.decode(input),
            "{:?}",
            String::from_utf8_lossy(input)
        );
    }
}

#[test]
fn decode_until_stops_at_the_delimiter() {
    let tag = b"dGVzdA==\r\n\t; bh=abc";
    assert_eq!(LENIENT.decode_until(tag, b';'), Ok((b"test".to_vec(), 11)));
    assert_eq!(
        LENIENT.decode_until(b"dGVzdA", b';'),
        Ok((b"test".to_vec(), 6))
    );
    assert_eq!(
        LENIENT.decode_until(b"dGV*zdA;", b';'),
        Err(Error::InvalidByte {
            offset: 3,
            byte: b'*'
        })
    );
    assert_eq!(
        STANDARD.decode_until(b"dGVzdA==;x", b';'),
        Ok((b"test".to_vec(), 8))
    );
    assert_eq!(
        LENIENT.decode_until(b"AHVzZXIAcGFzcw==\r\nQUIT\r\n", b'\r'),
        Ok((b"\0user\0pass".to_vec(), 16))
    );
    for stop in *b" A=" {
        let input = b"QUJD REVG=QUJD";
        let end = input
            .iter()
            .position(|&byte| byte == stop)
            .unwrap_or(input.len());
        assert_eq!(
            LENIENT.decode_until(input, stop),
            LENIENT.decode(&input[..end]).map(|bytes| (bytes, end))
        );
    }
}

#[test]
fn decode_prefix_leaves_the_boundary_to_the_caller() {
    let body = b"SGVsbG8g\r\nV29ybGQ=\r\n--boundary--\r\n";
    let mut out = b"x".to_vec();
    let consumed = MIME.decode_prefix(body, &mut out);
    assert_eq!(&body[consumed..], b"--boundary--\r\n");
    assert_eq!(out, b"xHello World");

    let mut message = b"SGVsbG8=\r\n--boundary\r\n".to_vec();
    message.resize(message.len() + (1 << 20), b'x');
    let mut out = Vec::new();
    assert_eq!(MIME.decode_prefix(&message, &mut out), 10);
    assert_eq!(out, b"Hello");
    assert!(out.capacity() < 4096, "{}", out.capacity());
    let (value, end) = LENIENT.decode_until(&message, b'-').expect("valid prefix");
    assert_eq!((value.as_slice(), end), (&b"Hello"[..], 10));
    assert!(value.capacity() < 4096, "{}", value.capacity());

    let text = STANDARD.encode(vec![0x42; 100_000]);
    let mut long = text.clone().into_bytes();
    long.extend_from_slice(b"\r\n--boundary");
    let mut out = Vec::new();
    assert_eq!(MIME.decode_prefix(&long, &mut out), text.len() + 2);
    assert_eq!(out, vec![0x42; 100_000]);
}

#[test]
fn folded_values_reserve_what_they_decode() {
    let encoded = STANDARD.encode(vec![0x33; 3000]);
    let (first, mut rest) = encoded.as_bytes().split_at(58);
    let mut card = first.to_vec();
    let mut line = 0;
    while !rest.is_empty() {
        let width = if line == 3 { 70 } else { 74 };
        let (head, tail) = rest.split_at(width.min(rest.len()));
        card.extend_from_slice(b"\r\n ");
        card.extend_from_slice(head);
        rest = tail;
        line += 1;
    }
    card.extend_from_slice(b"\r\nEND:VCARD\r\n");
    card.resize(card.len() + (1 << 20), b'x');
    let mut out = Vec::new();
    let value = STANDARD
        .decode_folded(&card, &mut out)
        .expect("valid value");
    assert_eq!(&card[value.next..value.next + 9], b"END:VCARD");
    assert_eq!(out, vec![0x33; 3000]);
    assert!(out.capacity() < 64 * 1024, "{}", out.capacity());
}

#[test]
fn incremental_decoder_matches_one_shot_decoding() {
    let mut rng = XorShift::new(6);
    for text in lenient_samples(&mut rng, 3000) {
        let Ok(expected) = reference_lenient(&LENIENT, &text) else {
            continue;
        };
        let mut decoder = LENIENT.decoder();
        let mut out = Vec::new();
        let mut rest = &text[..];
        while !rest.is_empty() {
            let split = rng.below(rest.len() + 1);
            let (mut piece, tail) = rest.split_at(split);
            rest = tail;
            while !piece.is_empty() {
                let consumed = decoder.decode_symbols(piece, &mut out);
                piece = &piece[consumed..];
                if let Some((&byte, tail)) = piece.split_first() {
                    if byte == b'=' {
                        decoder.pad(&mut out);
                    }
                    piece = tail;
                }
            }
        }
        decoder.finish(&mut out);
        assert_eq!(out, expected, "{:?}", String::from_utf8_lossy(&text));
    }
}

#[test]
fn any_alphabet_accepts_both_symbol_pairs() {
    let engine = URL_SAFE_NO_PAD
        .any_alphabet()
        .with_padding(Padding::Optional);
    for input in ["-_-_", "+/+/", "-/+_"] {
        assert_eq!(engine.decode(input), Ok(vec![0xfb, 0xff, 0xbf]));
    }
    assert_eq!(engine.decode("-_-_-A=="), Ok(vec![0xfb, 0xff, 0xbf, 0xf8]));
    let data: Vec<u8> = (0..=u8::MAX).cycle().take(3000).collect();
    for text in [URL_SAFE.encode(&data), STANDARD.encode(&data)] {
        assert_eq!(engine.decode(&text), Ok(data.clone()));
        assert_eq!(STANDARD.any_alphabet().decode(&text), Ok(data.clone()));
        let mut in_place = text.clone().into_bytes();
        assert_eq!(
            engine
                .decode_in_place(&mut in_place)
                .map(|out| out.to_vec()),
            Ok(data.clone())
        );
    }
}

#[test]
fn const_encoding_matches_runtime_encoding() {
    const PROMPT: [u8; STANDARD.encoded_len(9)] = STANDARD.encode_const(b"Username:");
    assert_eq!(&PROMPT, b"VXNlcm5hbWU6");
    const NO_PAD: [u8; URL_SAFE_NO_PAD.encoded_len(4)] =
        URL_SAFE_NO_PAD.encode_const(&[0xfb, 0xff, 0xbf, 0xff]);
    assert_eq!(&NO_PAD, b"-_-__w");
    let mut rng = XorShift::new(7);
    for len in 0..200 {
        let input = rng.bytes(len);
        let wrapped = MIME.encode(&input);
        let mut out = vec![0u8; wrapped.len()];
        let copy: [u8; 400] = {
            let mut buffer = [0u8; 400];
            buffer[..len].copy_from_slice(&input);
            buffer
        };
        assert_eq!(runtime_const(&copy[..len], &mut out), wrapped.as_bytes());
    }
}

fn runtime_const<'x>(input: &[u8], out: &'x mut [u8]) -> &'x [u8] {
    macro_rules! with_len {
        ($($n:literal),*) => {
            match out.len() {
                $($n => { out.copy_from_slice(&MIME.encode_const::<$n>(input)); })*
                _ => {}
            }
        };
    }
    with_len!(
        0, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48,
        50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94,
        96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 130,
        132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166,
        168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 192, 194, 196, 198, 200, 202,
        204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238,
        240, 242, 244, 246, 248, 250, 252, 254, 256, 258, 260, 262, 264, 266, 268, 270, 272, 274,
        276, 278, 280, 282
    );
    out
}

#[test]
fn display_honours_width_fill_and_precision() {
    let engine = STANDARD;
    assert_eq!(format!("{:>10}", engine.display(b"hi!")), "      aGkh");
    assert_eq!(format!("{:*<10}", engine.display(b"hi!")), "aGkh******");
    assert_eq!(format!("{:^8}", engine.display(b"hi!")), "  aGkh  ");
    assert_eq!(format!("{:.2}", engine.display(b"hi!")), "aG");
    assert_eq!(format!("base64:{}", engine.display(b"hi!")), "base64:aGkh");
}

#[test]
fn encode_str_uses_the_caller_buffer() {
    let mut buffer = [0u8; 44];
    assert_eq!(
        STANDARD.encode_str([0u8; 32], &mut buffer),
        Ok("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    );
    let mut small = [0u8; 4];
    assert_eq!(
        STANDARD.encode_str([0u8; 32], &mut small),
        Err(Error::BufferTooSmall { required: 44 })
    );
}

#[test]
fn decode_to_string_checks_utf8() {
    assert_eq!(LENIENT.decode_to_string("w6k="), Ok("é".to_string()));
    assert_eq!(
        LENIENT.decode_to_string("/w=="),
        Err(Error::InvalidUtf8 { offset: 0 })
    );
}

#[test]
fn simd_tables_are_consistent() {
    for tables in [&alphabet::STANDARD, &alphabet::URL_SAFE] {
        for (value, &symbol) in tables.encode.iter().enumerate() {
            assert_eq!(tables.decode[symbol as usize], value as u8);
        }
    }
}

fn reference_folded(input: &[u8]) -> Result<(Vec<u8>, usize, usize), usize> {
    let mut symbols = Vec::new();
    let mut out = Vec::new();
    let mut offset = 0;
    let (end, next) = loop {
        let Some(&byte) = input.get(offset) else {
            break (input.len(), input.len());
        };
        let rest = input.get(offset..).unwrap_or_default();
        let terminator = match rest {
            [b'\r', b'\n', ..] => Some(2),
            [b'\n', ..] => Some(1),
            _ => None,
        };
        if let Some(terminator) = terminator {
            match rest.get(terminator) {
                Some(b' ' | b'\t') => {
                    offset += terminator + 1;
                    continue;
                }
                _ => break (offset, offset + terminator),
            }
        }
        match byte {
            b' ' | b'\t' => {}
            b'=' => {
                out.extend(reference_flush(&symbols));
                symbols.clear();
            }
            _ if alphabet::STANDARD.decode[byte as usize] != INVALID => {
                symbols.push(alphabet::STANDARD.decode[byte as usize]);
                if symbols.len() == 4 {
                    out.extend(reference_flush(&symbols));
                    symbols.clear();
                }
            }
            _ => return Err(offset),
        }
        offset += 1;
    };
    out.extend(reference_flush(&symbols));
    Ok((out, end, next))
}

fn reference_flush(symbols: &[u8]) -> Vec<u8> {
    let word = symbols
        .iter()
        .fold(0u32, |word, &value| (word << 6) | value as u32)
        << (6 * (4 - symbols.len()) as u32);
    let bytes = word.to_be_bytes();
    let take = match symbols.len() {
        4 => 3,
        3 => 2,
        2 => 1,
        _ => 0,
    };
    bytes.get(1..1 + take).unwrap_or_default().to_vec()
}

fn folded_value(
    rng: &mut XorShift,
    raw: &[u8],
    first: usize,
    width: usize,
    fold: &[u8],
) -> Vec<u8> {
    let encoded = STANDARD.encode(raw);
    let mut text = Vec::new();
    let mut rest = encoded.as_bytes();
    let (head, tail) = rest.split_at(first.min(rest.len()));
    text.extend_from_slice(head);
    rest = tail;
    while !rest.is_empty() {
        let (line, tail) = rest.split_at(width.min(rest.len()));
        text.extend_from_slice(fold);
        if rng.below(8) == 0 {
            text.push(b' ');
        }
        text.extend_from_slice(line);
        rest = tail;
    }
    text
}

#[test]
fn folded_values_decode_like_the_reference() {
    let mut rng = XorShift::new(41);
    for len in [0, 1, 2, 3, 10, 57, 100, 500, 1000, 4000, 20000] {
        for (first, width) in [
            (58, 74),
            (60, 72),
            (17, 74),
            (74, 74),
            (40, 75),
            (10, 16),
            (3, 5),
        ] {
            for fold in [&b"\r\n "[..], b"\r\n\t", b"\n ", b"\n\t"] {
                for trailer in [&b"\r\nEND:VCARD\r\n"[..], b"\nX-A:b\n", b""] {
                    let raw = rng.bytes(len);
                    let mut input = folded_value(&mut rng, &raw, first, width, fold);
                    input.extend_from_slice(trailer);
                    let expected = reference_folded(&input);
                    let mut out = b"prefix".to_vec();
                    let result = STANDARD.decode_folded(&input, &mut out);
                    let (bytes, end, next) = expected.clone().expect("valid input");
                    assert_eq!(bytes, raw, "{len} {first} {width} {fold:?}");
                    let value = result.expect("valid input");
                    assert_eq!(
                        out.get(6..),
                        Some(&raw[..]),
                        "{len} {first} {width} {fold:?}"
                    );
                    assert_eq!(
                        (value.end, value.next),
                        (end, next),
                        "{len} {first} {width}"
                    );
                }
            }
        }
    }
}

#[test]
fn folded_values_reject_what_the_reference_rejects() {
    let mut rng = XorShift::new(42);
    let raw = rng.bytes(2000);
    let clean = folded_value(&mut rng, &raw, 58, 74, b"\r\n ");
    for _ in 0..500 {
        let mut input = clean.clone();
        let position = rng.below(input.len());
        input[position] = *rng.pick(b"=\r\n \t*:-_.A0\x00\xff");
        input.extend_from_slice(b"\r\nEND:VCARD\r\n");
        let expected = reference_folded(&input);
        let mut out = b"prefix".to_vec();
        let result = STANDARD.decode_folded(&input, &mut out);
        match expected {
            Ok((bytes, end, next)) => {
                let value = result.expect("the reference accepts it");
                assert_eq!(out.get(6..), Some(&bytes[..]), "{position}");
                assert_eq!((value.end, value.next), (end, next), "{position}");
            }
            Err(offset) => {
                assert_eq!(
                    result.map_err(|err| err.offset()),
                    Err(Some(offset)),
                    "{position}"
                );
                assert_eq!(out, b"prefix");
            }
        }
    }
}

#[test]
fn lenient_decode_until_matches_the_reference() {
    let mut rng = XorShift::new(43);
    for stop in *b";?\" A=" {
        for len in [0, 1, 5, 30, 64, 100, 400] {
            for _ in 0..40 {
                let input: Vec<u8> = (0..len)
                    .map(|_| *rng.pick(b"QUJDREVGR0hJSktM+/=  \r\n;?\"*"))
                    .collect();
                let end = input
                    .iter()
                    .position(|&byte| byte == stop)
                    .unwrap_or(input.len());
                let expected = reference_lenient(&LENIENT, &input[..end]).map(|bytes| (bytes, end));
                let actual = LENIENT
                    .decode_until(&input, stop)
                    .map_err(|err| err.offset().unwrap_or(usize::MAX));
                assert_eq!(
                    actual,
                    expected,
                    "{stop} {:?}",
                    String::from_utf8_lossy(&input)
                );
            }
        }
    }
}
