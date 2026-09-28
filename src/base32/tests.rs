/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Alphabet, Base32, Padding, STALWART, STANDARD, STANDARD_NO_PAD};
use crate::{Error, test_rng::XorShift};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io::Write,
};

const ENGINES: [Base32; 6] = [
    STANDARD,
    STANDARD_NO_PAD,
    STALWART,
    STANDARD.with_padding(Padding::Optional),
    Base32::new(Alphabet::Stalwart),
    Base32::new(Alphabet::Stalwart).with_padding(Padding::Optional),
];

impl Base32 {
    fn symbols(&self) -> &'static [u8; 32] {
        match self.alphabet() {
            Alphabet::Standard => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
            Alphabet::Stalwart => b"abcdefghijklmnopqrstuvwxyz792013",
        }
    }

    fn reference_encode(&self, input: &[u8]) -> String {
        let symbols = self.symbols();
        let mut out = String::new();
        let mut acc = 0u64;
        let mut bits = 0;
        for &byte in input {
            acc = (acc << 8) | byte as u64;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(symbols[((acc >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(symbols[((acc << (5 - bits)) & 31) as usize] as char);
        }
        if self.padding() != Padding::Omitted {
            while !out.len().is_multiple_of(8) {
                out.push('=');
            }
        }
        out
    }

    fn reference_decode(&self, input: &[u8]) -> Option<Vec<u8>> {
        let symbols = self.symbols();
        let padding = input.iter().rev().take_while(|&&byte| byte == b'=').count();
        let (body, _) = input.split_at(input.len() - padding);
        let tail = body.len() % 8;
        if matches!(tail, 1 | 3 | 6) {
            return None;
        }
        let expected = if tail == 0 { 0 } else { 8 - tail };
        let padding_ok = match self.padding() {
            Padding::Required => padding == expected,
            Padding::Omitted => padding == 0,
            Padding::Optional => padding == 0 || padding == expected,
        };
        if !padding_ok {
            return None;
        }
        let mut out = Vec::new();
        let mut acc = 0u64;
        let mut bits = 0;
        for &byte in body {
            let value = symbols.iter().position(|&symbol| symbol == byte)?;
            acc = (acc << 5) | value as u64;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        (acc & ((1 << bits) - 1) == 0).then_some(out)
    }

    fn reference_numeral(&self, value: u64) -> String {
        let symbols = self.symbols();
        let mut digits = Vec::new();
        let mut rest = value;
        loop {
            digits.push(symbols[(rest & 31) as usize]);
            rest >>= 5;
            if rest == 0 {
                break;
            }
        }
        digits.iter().rev().map(|&symbol| symbol as char).collect()
    }
}

struct Sha1 {
    state: [u32; 5],
}

impl Sha1 {
    fn digest(message: &[u8]) -> [u8; 20] {
        let mut padded = message.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&(message.len() as u64 * 8).to_be_bytes());
        let mut sha1 = Sha1 {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
            ],
        };
        let (blocks, _) = padded.as_chunks::<64>();
        for block in blocks {
            sha1.compress(block);
        }
        sha1.finish()
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let (words, _) = block.as_chunks::<4>();
        let mut schedule: Vec<u32> = words.iter().map(|&word| u32::from_be_bytes(word)).collect();
        while let Some(&[w16, _, w14, _, _, _, _, _, w8, _, _, _, _, w3, _, _]) =
            schedule.last_chunk::<16>()
        {
            if schedule.len() == 80 {
                break;
            }
            schedule.push((w3 ^ w8 ^ w14 ^ w16).rotate_left(1));
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (round, &word) in schedule.iter().enumerate() {
            let (mix, constant) = match round {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(mix)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (word, add) in self.state.iter_mut().zip([a, b, c, d, e]) {
            *word = word.wrapping_add(add);
        }
    }

    fn finish(self) -> [u8; 20] {
        let mut digest = [0u8; 20];
        let (words, _) = digest.as_chunks_mut::<4>();
        for (bytes, word) in words.iter_mut().zip(self.state) {
            *bytes = word.to_be_bytes();
        }
        digest
    }
}

#[test]
fn rfc4648_test_vectors() {
    for (input, padded) in [
        ("", ""),
        ("f", "MY======"),
        ("fo", "MZXQ===="),
        ("foo", "MZXW6==="),
        ("foob", "MZXW6YQ="),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI======"),
    ] {
        let unpadded = padded.trim_end_matches('=');
        assert_eq!(STANDARD.encode(input), padded);
        assert_eq!(STANDARD_NO_PAD.encode(input), unpadded);
        assert_eq!(STANDARD.decode(padded), Ok(input.as_bytes().to_vec()));
        assert_eq!(
            STANDARD_NO_PAD.decode(unpadded),
            Ok(input.as_bytes().to_vec())
        );
    }
}

#[test]
fn rfc6541_atps_labels() {
    assert_eq!(
        STANDARD_NO_PAD.encode(Sha1::digest(b"abc")),
        STANDARD_NO_PAD.encode([
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
        ])
    );
    for (domain, label) in [
        ("one.example.net", "QSP4I4D24CRHOPDZ3O3ZIU2KSGS3X6Z6"),
        ("two.example.net", "ZTZGRRV3F45A4U6HLDKBF3ZCOW4V2AJX"),
    ] {
        let digest = Sha1::digest(domain.as_bytes());
        assert_eq!(STANDARD_NO_PAD.encode(digest), label);
        let mut buffer = [0u8; 32];
        assert_eq!(STANDARD_NO_PAD.encode_str(digest, &mut buffer), Ok(label));
        assert_eq!(STANDARD_NO_PAD.decode(label), Ok(digest.to_vec()));
        let mut query = String::new();
        STANDARD_NO_PAD.encode_append(digest, &mut query);
        query.push_str("._atps.example.com");
        assert_eq!(query, format!("{label}._atps.example.com"));
    }
}

#[test]
fn stalwart_id_golden_vectors() {
    for (value, text) in [
        (0, "a"),
        (1, "b"),
        (31, "3"),
        (32, "ba"),
        (33, "bb"),
        (1023, "33"),
        (1024, "baa"),
        ((1 << 60) - 1, "333333333333"),
        (1 << 60, "baaaaaaaaaaaa"),
        (1 << 63, "iaaaaaaaaaaaa"),
        (u64::MAX - 1, "p333333333331"),
        (u64::MAX, "p333333333333"),
        (20080258862541, "singleton"),
        ((1000 << 32) | 5000, "d0aaaae2i"),
    ] {
        assert_eq!(&*STALWART.encode_u64(value), text);
        assert_eq!(STALWART.encode_u64(value).to_string(), text);
        let mut appended = b"id:".to_vec();
        assert_eq!(STALWART.encode_u64_append(value, &mut appended), text.len());
        assert_eq!(appended, format!("id:{text}").as_bytes());
        let mut string = String::from("id:");
        STALWART.encode_u64_append(value, &mut string);
        assert_eq!(string, format!("id:{text}"));
        assert_eq!(STALWART.decode_u64(text), Ok(value));
    }
}

#[test]
fn u64_numerals_round_trip() {
    let mut rng = XorShift::new(11);
    let random = (0..20_000u32).map(|round| rng.next().checked_shr(round % 65).unwrap_or(0));
    let values: Vec<u64> = (0..64)
        .flat_map(|bits| [(1u64 << bits) - 1, 1 << bits, (1 << bits) + 1])
        .chain([u64::MAX - 1, u64::MAX])
        .chain(random)
        .collect();
    for engine in ENGINES {
        for &value in &values {
            let expected = engine.reference_numeral(value);
            let text = engine.encode_u64(value);
            assert_eq!(&*text, expected, "{engine:?} {value}");
            assert_eq!(text.as_bytes(), expected.as_bytes());
            let mut appended = Vec::new();
            assert_eq!(
                engine.encode_u64_append(value, &mut appended),
                expected.len()
            );
            assert_eq!(appended, expected.as_bytes());
            assert_eq!(
                engine.decode_u64(&*text),
                Ok(value),
                "{engine:?} {expected}"
            );
            let zero = engine.symbols()[0] as char;
            let padded: String = std::iter::repeat_n(zero, 13 - expected.len())
                .chain(expected.chars())
                .collect();
            assert_eq!(engine.decode_u64(&padded), Ok(value), "{padded}");
        }
    }
}

#[test]
fn u64_numerals_reject_invalid_text() {
    for (text, error) in [
        ("", Error::Truncated { offset: 0 }),
        ("aaaaaaaaaaaaab", Error::Overflow),
        ("p3333333333333", Error::Overflow),
        ("q333333333333", Error::Overflow),
        ("3aaaaaaaaaaaa", Error::Overflow),
        (
            "ab!",
            Error::InvalidByte {
                offset: 2,
                byte: b'!',
            },
        ),
        (
            "B",
            Error::InvalidByte {
                offset: 0,
                byte: b'B',
            },
        ),
        (
            "aaZ",
            Error::InvalidByte {
                offset: 2,
                byte: b'Z',
            },
        ),
        (
            "=",
            Error::InvalidByte {
                offset: 0,
                byte: b'=',
            },
        ),
        (
            "a\u{e9}",
            Error::InvalidByte {
                offset: 1,
                byte: 0xc3,
            },
        ),
        (
            "abcdefghij4lm",
            Error::InvalidByte {
                offset: 10,
                byte: b'4',
            },
        ),
    ] {
        assert_eq!(STALWART.decode_u64(text), Err(error), "{text:?}");
    }
    assert_eq!(STALWART.decode_u64("aaaaaaaaaaaab"), Ok(1));
    assert_eq!(STALWART.decode_u64("p333333333333"), Ok(u64::MAX));
    assert_eq!(STANDARD.decode_u64("P777777777777"), Ok(u64::MAX));
    assert_eq!(
        STANDARD.decode_u64("b"),
        Err(Error::InvalidByte {
            offset: 0,
            byte: b'b'
        })
    );
    let mut rng = XorShift::new(12);
    for _ in 0..20_000 {
        let len = rng.below(16);
        let text: Vec<u8> = (0..len)
            .map(|_| *rng.pick(b"abcdefghijklmnopqrstuvwxyz792013AZ4=\x00\xff"))
            .collect();
        let expected = (1..=13).contains(&len).then(|| {
            text.iter().try_fold(0u64, |value, &byte| {
                let digit = STALWART
                    .symbols()
                    .iter()
                    .position(|&symbol| symbol == byte)?;
                value.checked_mul(32)?.checked_add(digit as u64)
            })
        });
        assert_eq!(
            STALWART.decode_u64(&text).ok(),
            expected.flatten(),
            "{:?}",
            String::from_utf8_lossy(&text)
        );
    }
}

#[test]
fn u64_text_behaves_like_str() {
    let text = STALWART.encode_u64(33);
    assert_eq!(text.len(), 2);
    assert_eq!(text.as_str(), "bb");
    assert_eq!(AsRef::<[u8]>::as_ref(&text), b"bb");
    assert_eq!(AsRef::<str>::as_ref(&text), "bb");
    assert_eq!(
        format!("{text:>4}|{text:<4}|{text:^6}|{text:.1}"),
        "  bb|bb  |  bb  |b"
    );
    assert_eq!(format!("{text:?}"), "\"bb\"");
    assert_eq!(text, STALWART.encode_u64(33));
    assert_ne!(text, STALWART.encode_u64(34));
    assert!(STALWART.encode_u64(33) < STALWART.encode_u64(34));
    let mut hashed = DefaultHasher::new();
    text.hash(&mut hashed);
    let mut expected = DefaultHasher::new();
    "bb".hash(&mut expected);
    assert_eq!(hashed.finish(), expected.finish());
}

#[test]
fn encodes_and_decodes_every_length_through_every_sink() {
    let mut rng = XorShift::new(13);
    for len in 0..200 {
        let input = rng.bytes(len);
        for engine in ENGINES {
            let expected = engine.reference_encode(&input);
            assert_eq!(engine.encode(&input), expected, "{engine:?} {len}");
            assert_eq!(engine.encoded_len(len), expected.len());
            assert!(engine.decoded_len_estimate(expected.len()) >= len);

            let mut appended = b"prefix".to_vec();
            assert_eq!(engine.encode_append(&input, &mut appended), expected.len());
            assert_eq!(appended.strip_prefix(b"prefix"), Some(expected.as_bytes()));
            let mut string = String::from("prefix");
            engine.encode_append(&input, &mut string);
            assert_eq!(string, format!("prefix{expected}"));

            let mut exact = vec![0u8; expected.len()];
            assert_eq!(engine.encode_slice(&input, &mut exact), Ok(expected.len()));
            assert_eq!(exact, expected.as_bytes());
            let mut larger = vec![b'#'; expected.len() + 40];
            assert_eq!(
                engine.encode_str(&input, &mut larger),
                Ok(expected.as_str())
            );
            assert!(larger.iter().skip(expected.len()).all(|&byte| byte == b'#'));
            if let Some(short) = expected.len().checked_sub(1) {
                let mut short = vec![0u8; short];
                assert_eq!(
                    engine.encode_slice(&input, &mut short),
                    Err(Error::BufferTooSmall {
                        required: expected.len()
                    })
                );
            }
            assert_eq!(engine.display(&input).to_string(), expected);

            assert_eq!(
                engine.decode(&expected),
                Ok(input.clone()),
                "{engine:?} {expected}"
            );
            let mut decoded = b"prefix".to_vec();
            assert_eq!(engine.decode_append(&expected, &mut decoded), Ok(len));
            assert_eq!(decoded.strip_prefix(b"prefix"), Some(&input[..]));
            let mut exact = vec![0u8; len];
            assert_eq!(engine.decode_slice(&expected, &mut exact), Ok(len));
            assert_eq!(exact, input);
            let mut larger = vec![b'#'; len + 40];
            assert_eq!(engine.decode_slice(&expected, &mut larger), Ok(len));
            assert!(
                larger.iter().skip(len).all(|&byte| byte == b'#'),
                "{engine:?} {len}"
            );
            if let Some(short) = len.checked_sub(1) {
                let mut short = vec![0u8; short];
                assert_eq!(
                    engine.decode_slice(&expected, &mut short),
                    Err(Error::BufferTooSmall { required: len })
                );
            }

            let mut streamed = String::from("prefix");
            let mut encoder = engine.encoder(&mut streamed);
            let mut rest = &input[..];
            while !rest.is_empty() {
                let (piece, tail) = rest.split_at(1 + rng.below(rest.len().min(12)));
                if rng.below(2) == 0 {
                    encoder.push(piece);
                } else {
                    encoder.write_all(piece).expect("in-memory encoder");
                }
                rest = tail;
            }
            encoder.finish();
            assert_eq!(streamed, format!("prefix{expected}"), "{engine:?} {len}");

            let mut decoder = engine.decoder(&expected);
            assert_eq!(decoder.by_ref().collect::<Vec<_>>(), input);
            assert!(decoder.remaining().iter().all(|&byte| byte == b'='));
            assert_eq!(decoder.next(), None);
        }
    }
}

#[test]
fn encoded_len_saturates() {
    for engine in ENGINES {
        for len in [usize::MAX, usize::MAX - 1, usize::MAX - 5] {
            assert_eq!(engine.encoded_len(len), usize::MAX, "{engine:?} {len}");
        }
    }
}

#[test]
fn large_inputs_use_the_bulk_kernels() {
    let mut rng = XorShift::new(14);
    for len in [4095, 4096, 4097, 65_536 + 3] {
        let input = rng.bytes(len);
        for engine in ENGINES {
            let expected = engine.reference_encode(&input);
            assert_eq!(engine.encode(&input), expected);
            assert_eq!(engine.display(&input).to_string(), expected);
            assert_eq!(engine.decode(&expected), Ok(input.clone()));
            assert_eq!(engine.decoder(&expected).collect::<Vec<_>>(), input);
            let mut streamed = Vec::new();
            let mut encoder = engine.encoder(&mut streamed);
            let (head, tail) = input.split_at(7);
            encoder.push(head);
            encoder.push(tail);
            drop(encoder);
            assert_eq!(streamed, expected.as_bytes());
        }
    }
}

#[test]
fn strict_decoding_matches_the_reference() {
    let mut rng = XorShift::new(15);
    let noise = b"=AZaz2790!\r\n \x00\xffMmYy";
    for round in 0..30_000 {
        let len = rng.below(if round % 10 == 0 { 300 } else { 30 });
        let input = rng.bytes(len);
        for engine in ENGINES {
            let mut text = engine.reference_encode(&input).into_bytes();
            if round % 3 != 0 {
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
            let expected = engine.reference_decode(&text);
            assert_eq!(
                engine.decode(&text).ok(),
                expected,
                "{engine:?} {:?}",
                String::from_utf8_lossy(&text)
            );
            let mut out = vec![0u8; text.len()];
            assert_eq!(
                engine.decode_slice(&text, &mut out).ok(),
                expected.as_ref().map(Vec::len)
            );
        }
    }
}

#[test]
fn strict_errors_point_at_the_offending_byte() {
    for (engine, input, error) in [
        (
            STANDARD,
            &b"MZXW6*TB"[..],
            Error::InvalidByte {
                offset: 5,
                byte: b'*',
            },
        ),
        (
            STANDARD,
            b"MZXW6YTBOI======MY======",
            Error::InvalidPadding { offset: 10 },
        ),
        (STANDARD, b"MY=====", Error::InvalidPadding { offset: 2 }),
        (STANDARD, b"MY", Error::InvalidPadding { offset: 2 }),
        (
            STANDARD,
            b"MZXW6YTB========",
            Error::InvalidPadding { offset: 8 },
        ),
        (STANDARD, b"M=======", Error::Truncated { offset: 1 }),
        (STANDARD, b"MZX=====", Error::Truncated { offset: 3 }),
        (STANDARD, b"MZXW6Y==", Error::Truncated { offset: 6 }),
        (STANDARD, b"MZ======", Error::NonCanonical { offset: 1 }),
        (
            STANDARD,
            b"my======",
            Error::InvalidByte {
                offset: 0,
                byte: b'm',
            },
        ),
        (
            STANDARD_NO_PAD,
            b"MY======",
            Error::InvalidPadding { offset: 2 },
        ),
        (
            STANDARD_NO_PAD,
            b"MZXW6YTBOJ",
            Error::NonCanonical { offset: 9 },
        ),
        (
            STALWART,
            b"mzxw6ytb",
            Error::InvalidByte {
                offset: 4,
                byte: b'6',
            },
        ),
        (
            STALWART,
            b"mfRgg",
            Error::InvalidByte {
                offset: 2,
                byte: b'R',
            },
        ),
        (STALWART, b"mfrgg=", Error::InvalidPadding { offset: 5 }),
        (STALWART, b"mfrgh", Error::NonCanonical { offset: 4 }),
    ] {
        assert_eq!(engine.decode(input), Err(error), "{input:?}");
        let mut out = [0u8; 64];
        assert_eq!(
            engine.decode_slice(input, &mut out),
            Err(error),
            "{input:?}"
        );
        let mut appended = b"keep".to_vec();
        assert_eq!(engine.decode_append(input, &mut appended), Err(error));
        assert_eq!(appended, b"keep");
    }
    let optional = STANDARD.with_padding(Padding::Optional);
    assert_eq!(optional.decode("MY"), Ok(b"f".to_vec()));
    assert_eq!(optional.decode("MY======"), Ok(b"f".to_vec()));
    assert_eq!(
        optional.decode("MY===="),
        Err(Error::InvalidPadding { offset: 2 })
    );
}

#[test]
fn stream_decoder_stops_at_the_first_non_symbol() {
    let mut decoder = STALWART.decoder("mfrgg.rest");
    assert_eq!(decoder.by_ref().collect::<Vec<_>>(), b"abc");
    assert_eq!(decoder.remaining(), b".rest");

    let mut decoder = STALWART.decoder("mfrggb");
    assert_eq!(decoder.by_ref().collect::<Vec<_>>(), b"abc");
    assert_eq!(decoder.remaining(), b"b");

    assert_eq!(STALWART.decoder("mfrgh").collect::<Vec<_>>(), b"abc");
    assert_eq!(STALWART.decoder("b").collect::<Vec<_>>(), b"");

    let mut decoder = STALWART.decoder("mfRgg");
    assert_eq!(decoder.by_ref().collect::<Vec<_>>(), b"a");
    assert_eq!(decoder.remaining(), b"Rgg");
    assert_eq!(decoder.next(), None);

    let mut iter = b"smfrgg".iter();
    assert_eq!(iter.next(), Some(&b's'));
    assert_eq!(STALWART.decoder_from_iter(iter).collect::<Vec<_>>(), b"abc");

    let mut decoder = STANDARD.decoder("MZXW6===");
    assert_eq!(decoder.by_ref().collect::<Vec<_>>(), b"foo");
    assert_eq!(decoder.remaining(), b"===");
}

#[test]
fn stream_decoder_reports_the_remaining_input_while_reading() {
    let mut rng = XorShift::new(16);
    for _ in 0..2_000 {
        let len = rng.below(40);
        let input = rng.bytes(len);
        let encoded = STALWART.encode(&input);
        let text = format!("{encoded}.{}", rng.below(1000));
        let mut decoder = STALWART.decoder(&text);
        let mut consumed = 0;
        while let Some(byte) = decoder.next() {
            assert_eq!(Some(&byte), input.get(consumed));
            consumed += 1;
            let bits = consumed * 8;
            let used = bits.div_ceil(5);
            assert_eq!(Some(decoder.remaining()), text.as_bytes().get(used..));
        }
        assert_eq!(consumed, input.len());
        assert!(decoder.remaining().starts_with(b"."));
        let (low, high) = STALWART.decoder(&text).size_hint();
        assert_eq!(low, 0);
        assert!(high.is_some_and(|high| high >= input.len()));
    }
}

#[test]
fn stream_encoder_flushes_on_drop_and_keeps_the_prefix() {
    let mut out = String::from("s");
    {
        let mut encoder = STALWART.encoder(&mut out);
        encoder.push(b"a");
        encoder.push(b"b");
        encoder.push(b"c");
    }
    assert_eq!(out, "smfrgg");

    let mut out = Vec::new();
    let mut encoder = STANDARD.encoder(&mut out);
    assert_eq!(encoder.write(b"foob").ok(), Some(4));
    assert!(encoder.flush().is_ok());
    encoder.push(b"ar");
    encoder.finish();
    assert_eq!(out, b"MZXW6YTBOI======");

    let mut out = Vec::new();
    STANDARD.encoder(&mut out).finish();
    assert!(out.is_empty());
}
