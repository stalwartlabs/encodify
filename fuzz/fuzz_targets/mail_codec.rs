/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![no_main]

use libfuzzer_sys::fuzz_target;
use encodify::{
    Error, Fold,
    base32::{self, Base32},
    base64::{self, Base64, LineEnding, Padding},
    hex, pem, qp, rfc2047, utf7,
};
use std::{borrow::Cow, cell::RefCell};

thread_local! {
    static SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    match selector % 12 {
        0 => Base64Case(input).round_trip(),
        1 => Base64Case(input).decode_any(),
        2 => Base64Case(input).folded(),
        3 => Base64Case(input).incremental(),
        4 => Base32Case(input).check(),
        5 => QpCase(input).round_trip(),
        6 => QpCase(input).decode_any(),
        7 => TextCase(input).rfc2047(),
        8 => TextCase(input).hex(),
        9 => TextCase(input).utf7(),
        10 => TextCase(input).pem(),
        _ => Base64Case(input).fold(),
    }
});

const SENTINEL: u8 = 0xa5;

const BASE64_ENGINES: [Base64; 9] = [
    base64::STANDARD,
    base64::STANDARD_NO_PAD,
    base64::URL_SAFE,
    base64::URL_SAFE_NO_PAD,
    base64::URL_SAFE.with_padding(Padding::Optional),
    base64::STANDARD.any_alphabet(),
    base64::LENIENT,
    base64::MIME,
    base64::LENIENT.wrapped(64, LineEnding::Lf),
];

struct Base64Case<'x>(&'x [u8]);

impl Base64Case<'_> {
    fn round_trip(&self) {
        let input = self.0;
        for engine in BASE64_ENGINES {
            let encoded = engine.encode(input);
            assert_eq!(encoded.len(), engine.encoded_len(input.len()));
            let unwrapped = engine.unwrapped().encode(input);
            let decoder = if engine.is_lenient() {
                engine
            } else {
                engine.unwrapped()
            };
            let source = if engine.is_lenient() {
                &encoded
            } else {
                &unwrapped
            };
            assert_eq!(decoder.decode(source).as_deref(), Ok(input));
            assert_eq!(decoder.decoded_len(source), Ok(input.len()));
            let mut exact = vec![0; encoded.len()];
            assert_eq!(engine.encode_slice(input, &mut exact), Ok(encoded.len()));
            assert_eq!(exact, encoded.as_bytes());
            if let Some(short) = exact.get_mut(..encoded.len().saturating_sub(1))
                && !encoded.is_empty()
            {
                assert_eq!(
                    engine.encode_slice(input, short),
                    Err(Error::BufferTooSmall {
                        required: encoded.len()
                    })
                );
            }
            let mut appended = String::from("prefix");
            assert_eq!(engine.encode_append(input, &mut appended), encoded.len());
            assert_eq!(appended.get(6..), Some(encoded.as_str()));
            let mut written = Vec::new();
            engine
                .encode_to_writer(input, &mut written)
                .expect("in-memory writer");
            assert_eq!(written, encoded.as_bytes());
            assert_eq!(engine.display(input).to_string(), encoded);
            let shown = format!("{:.7}", engine.display(input));
            assert_eq!(
                shown,
                encoded.get(..7.min(encoded.len())).unwrap_or(&encoded)
            );
            let mut decoded = vec![0; input.len()];
            assert_eq!(decoder.decode_slice(source, &mut decoded), Ok(input.len()));
            assert_eq!(decoded, input);
            let mut in_place = source.as_bytes().to_vec();
            assert_eq!(decoder.decode_in_place(&mut in_place).as_deref(), Ok(input));
        }
    }

    fn decode_any(&self) {
        let input = self.0;
        for engine in BASE64_ENGINES {
            let decoded = engine.decode(input);
            match &decoded {
                Ok(bytes) => {
                    assert_eq!(engine.decoded_len(input), Ok(bytes.len()));
                    let mut exact = vec![0; bytes.len()];
                    assert_eq!(engine.decode_slice(input, &mut exact), Ok(bytes.len()));
                    assert_eq!(&exact, bytes);
                    let mut roomy = vec![SENTINEL; bytes.len() + 64];
                    assert_eq!(engine.decode_slice(input, &mut roomy), Ok(bytes.len()));
                    let untouched = if engine.is_lenient() {
                        engine.decoded_len_estimate(input.len())
                    } else {
                        bytes.len()
                    };
                    assert!(roomy.iter().skip(untouched).all(|&byte| byte == SENTINEL));
                    if !bytes.is_empty() {
                        let mut short = vec![0; bytes.len() - 1];
                        assert_eq!(
                            engine.decode_slice(input, &mut short),
                            Err(Error::BufferTooSmall {
                                required: bytes.len()
                            })
                        );
                    }
                    let strict = !engine.is_lenient() && engine.padding() != Padding::Optional;
                    if strict && engine == engine.unwrapped() {
                        let canonical = engine.encode(bytes);
                        if engine != base64::STANDARD.any_alphabet() {
                            assert_eq!(canonical.as_bytes(), input);
                        }
                    }
                }
                Err(err) => {
                    assert_eq!(engine.decoded_len(input), Err(*err));
                }
            }
            let mut in_place = input.to_vec();
            assert_eq!(
                engine
                    .decode_in_place(&mut in_place)
                    .map(|bytes| bytes.to_vec()),
                decoded.clone()
            );
            let mut appended = b"prefix".to_vec();
            match engine.decode_append(input, &mut appended) {
                Ok(_) => assert_eq!(appended.get(6..), decoded.as_deref().ok()),
                Err(err) => {
                    assert_eq!(Err(err), decoded.clone().map(|bytes| bytes.len()));
                    assert_eq!(appended, b"prefix");
                }
            }
            if engine.is_lenient() {
                assert_eq!(decoded, reference_lenient(&engine, input));
                let (prefix, until) = match engine.decode_until(input, b';') {
                    Ok((bytes, consumed)) => (bytes, consumed),
                    Err(_) => continue,
                };
                let head = input.get(..until).unwrap_or_default();
                assert_eq!(engine.decode(head).as_ref(), Ok(&prefix));
            }
            let mut prefix = Vec::new();
            let consumed = base64::LENIENT.decode_prefix(input, &mut prefix);
            let head = input.get(..consumed).unwrap_or_default();
            assert_eq!(base64::LENIENT.decode(head), Ok(prefix));
        }
    }

    fn folded(&self) {
        let input = self.0;
        let mut out = b"prefix".to_vec();
        let result = base64::STANDARD.decode_folded(input, &mut out);
        match reference_folded(input) {
            Ok((bytes, end, next)) => {
                let value = result.expect("the reference accepts it");
                assert_eq!((value.end, value.next), (end, next));
                assert_eq!(out.get(6..), Some(&bytes[..]));
            }
            Err(offset) => {
                assert_eq!(result.map_err(|err| err.offset()), Err(Some(offset)));
                assert_eq!(out, b"prefix");
            }
        }
    }

    fn incremental(&self) {
        let (splits, input) = self.0.split_at(self.0.len().min(4));
        let symbols: Vec<u8> = input
            .iter()
            .copied()
            .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
            .collect();
        let mut decoder = base64::STANDARD.decoder();
        let mut out = Vec::new();
        let mut rest = &symbols[..];
        for &split in splits {
            let (head, tail) = rest.split_at((split as usize).min(rest.len()));
            assert_eq!(decoder.decode_symbols(head, &mut out), head.len());
            rest = tail;
        }
        assert_eq!(decoder.decode_symbols(rest, &mut out), rest.len());
        decoder.finish(&mut out);
        assert_eq!(Ok(out), base64::LENIENT.decode(&symbols));
    }

    fn fold(&self) {
        let (&[width, column, granularity], input) = self
            .0
            .split_first_chunk::<3>()
            .unwrap_or((&[0, 0, 0], self.0));
        let fold = Fold::new(4 + width as usize % 90, b"\r\n\t", 1)
            .with_granularity(1 + granularity as usize % 4);
        let start = column as usize % 100;
        let mut out = Vec::new();
        let mut column = start;
        base64::STANDARD.encode_folded(input, &mut column, fold, |piece| {
            out.extend_from_slice(piece)
        });
        let unfolded: Vec<u8> = out
            .iter()
            .copied()
            .filter(|byte| !matches!(byte, b'\r' | b'\n' | b'\t'))
            .collect();
        assert_eq!(unfolded, base64::STANDARD.encode(input).as_bytes());
        let text = String::from_utf8(out).expect("ascii");
        let mut lines = text.split("\r\n");
        if let Some(first) = lines.next() {
            assert!(start + first.len() <= fold.width.max(start + fold.granularity));
        }
        for line in lines {
            assert!(line.len() <= fold.width.max(fold.indent + fold.granularity));
        }
    }
}

fn reference_lenient(engine: &Base64, input: &[u8]) -> Result<Vec<u8>, Error> {
    let urls = engine.alphabet() == base64::Alphabet::UrlSafe;
    let value = |byte: u8| -> Option<u32> {
        Some(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' if !urls => 62,
            b'/' if !urls => 63,
            b'-' if urls => 62,
            b'_' if urls => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::new();
    let mut word = 0u32;
    let mut pending = 0;
    let flush = |out: &mut Vec<u8>, word: u32, pending: u8| match pending {
        2 => out.push((word >> 4) as u8),
        3 => out.extend_from_slice(&[(word >> 10) as u8, (word >> 2) as u8]),
        _ => {}
    };
    for (offset, &byte) in input.iter().enumerate() {
        if let Some(sextet) = value(byte) {
            word = (word << 6) | sextet;
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
            return Err(Error::InvalidByte { offset, byte });
        }
    }
    flush(&mut out, word, pending);
    Ok(out)
}

fn reference_folded(input: &[u8]) -> Result<(Vec<u8>, usize, usize), usize> {
    let mut clean = Vec::new();
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
            b'=' | b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => clean.push(byte),
            _ => return Err(offset),
        }
        offset += 1;
    };
    let bytes = reference_lenient(&base64::LENIENT, &clean).map_err(|_| usize::MAX)?;
    Ok((bytes, end, next))
}

const BASE32_ENGINES: [Base32; 4] = [
    base32::STANDARD,
    base32::STANDARD_NO_PAD,
    base32::STANDARD.with_padding(base32::Padding::Optional),
    base32::STALWART,
];

struct Base32Case<'x>(&'x [u8]);

impl Base32Case<'_> {
    fn check(&self) {
        let input = self.0;
        for engine in BASE32_ENGINES {
            let encoded = engine.encode(input);
            assert_eq!(encoded.len(), engine.encoded_len(input.len()));
            assert_eq!(engine.decode(&encoded).as_deref(), Ok(input));
            let mut exact = vec![0; encoded.len()];
            assert_eq!(engine.encode_slice(input, &mut exact), Ok(encoded.len()));
            assert_eq!(exact, encoded.as_bytes());
            assert_eq!(engine.display(input).to_string(), encoded);
            let mut streamed = String::new();
            let mut encoder = engine.encoder(&mut streamed);
            for piece in input.chunks(1 + input.first().copied().unwrap_or(0) as usize % 7) {
                encoder.push(piece);
            }
            encoder.finish();
            assert_eq!(streamed, encoded);
            let read: Vec<u8> = engine.decoder(&encoded).collect();
            assert_eq!(read, input);
            if let Ok(bytes) = engine.decode(input)
                && engine.padding() != base32::Padding::Optional
            {
                assert_eq!(engine.encode(&bytes).as_bytes(), input);
            }
            let mut appended = b"prefix".to_vec();
            if engine.decode_append(input, &mut appended).is_err() {
                assert_eq!(appended, b"prefix");
            }
        }
        if let Some(value) = input
            .first_chunk::<8>()
            .map(|bytes| u64::from_le_bytes(*bytes))
        {
            let text = base32::STALWART.encode_u64(value);
            assert_eq!(base32::STALWART.decode_u64(&*text), Ok(value));
            let mut appended = String::from("x");
            base32::STALWART.encode_u64_append(value, &mut appended);
            assert_eq!(appended.get(1..), Some(&*text));
        }
        if let Ok(value) = base32::STALWART.decode_u64(input) {
            let text = base32::STALWART.encode_u64(value);
            let zeros = input.iter().take_while(|&&byte| byte == b'a').count();
            let trimmed = input
                .get(zeros.min(input.len().saturating_sub(1))..)
                .unwrap_or_default();
            assert_eq!(text.as_bytes(), trimmed);
        }
    }
}

const QP_ENGINES: [qp::QuotedPrintable; 5] =
    [qp::BODY, qp::BINARY, qp::Q_TEXT, qp::Q_PHRASE, qp::DKIM];
const TILED_LEN: usize = 9000;

struct QpCase<'x>(&'x [u8]);

impl QpCase<'_> {
    fn round_trip(&self) {
        let input = self.0;
        for engine in QP_ENGINES {
            let encoded = engine.encode(input);
            assert_eq!(engine.encoded_len(input), encoded.len());
            let limit = input.first().copied().unwrap_or(0) as usize * 8;
            assert_eq!(
                engine.encoded_len_within(input, limit),
                (encoded.len() <= limit).then_some(encoded.len())
            );
            let expected: Cow<'_, [u8]> = if engine == qp::BODY {
                Cow::Owned(normalize_breaks(input))
            } else {
                Cow::Borrowed(input)
            };
            assert_eq!(engine.decode(&encoded).as_deref(), Ok(&*expected));
            let mut exact = vec![0; encoded.len()];
            assert_eq!(engine.encode_slice(input, &mut exact), Ok(encoded.len()));
            assert_eq!(exact, encoded.as_bytes());
            if engine == qp::BODY || engine == qp::BINARY {
                for line in encoded.split("\r\n") {
                    assert!(line.len() <= 76, "{line}");
                    assert!(!line.ends_with([' ', '\t']), "{line}");
                }
            }
        }
    }

    fn decode_any(&self) {
        let input = self.0;
        Self::decode_scans(input);
        if !input.is_empty() && input.len() < TILED_LEN {
            Self::decode_scans(&input.repeat(TILED_LEN / input.len() + 1));
        }
        for engine in QP_ENGINES {
            let lenient = engine.decode(input);
            let strict = engine.strict().decode(input);
            if let Ok(bytes) = &strict {
                assert_eq!(lenient.as_ref(), Ok(bytes));
            }
            let mut appended = b"prefix".to_vec();
            if engine.decode_append(input, &mut appended).is_err() {
                assert_eq!(appended, b"prefix");
            }
            if let Ok((bytes, consumed)) = engine.decode_word(input) {
                assert!(consumed <= input.len());
                let _ = bytes;
            }
        }
    }

    fn decode_scans(input: &[u8]) {
        for engine in QP_ENGINES
            .into_iter()
            .flat_map(|engine| [engine, engine.strict()])
        {
            let decoded = engine.decode(input);
            let mut reference = Vec::new();
            let expected = engine
                .decode_append(input, &mut reference)
                .map(|_| reference);
            assert_eq!(decoded.as_deref(), expected.as_deref());
            assert_eq!(
                engine.decoded_len(input),
                expected.as_ref().map(Vec::len).map_err(|&err| err)
            );
            if !input.contains(&b'=') && expected.as_deref() == Ok(input) {
                assert!(matches!(decoded, Ok(Cow::Borrowed(_))));
            }
            if let Ok(bytes) = &expected
                && !bytes.is_empty()
            {
                let mut short = vec![0; bytes.len() / 2];
                assert_eq!(
                    engine.decode_slice(input, &mut short),
                    Err(Error::BufferTooSmall {
                        required: bytes.len()
                    })
                );
            }
        }
    }
}

fn normalize_breaks(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 8);
    let mut rest = input;
    while let Some((&byte, tail)) = rest.split_first() {
        match (byte, tail.first()) {
            (b'\r', Some(b'\n')) => {
                out.extend_from_slice(b"\r\n");
                rest = tail.get(1..).unwrap_or_default();
                continue;
            }
            (b'\n', _) => out.extend_from_slice(b"\r\n"),
            _ => out.push(byte),
        }
        rest = tail;
    }
    out
}

struct TextCase<'x>(&'x [u8]);

impl TextCase<'_> {
    fn rfc2047(&self) {
        let input = self.0;
        let decoded = rfc2047::decode_text(input, rfc2047::utf8_charset);
        assert!(std::str::from_utf8(decoded.as_bytes()).is_ok());
        let mut appended = String::from("prefix");
        let len = SCRATCH.with_borrow_mut(|scratch| {
            rfc2047::decode_text_append_with(input, rfc2047::utf8_charset, scratch, &mut appended)
        });
        assert_eq!(appended.get(6..), Some(&*decoded));
        assert_eq!(len, decoded.len());
        if let Some((word, consumed)) = rfc2047::EncodedWord::parse(input) {
            assert!(consumed <= input.len());
            let _ = word.decode();
        }
        let (&[width, column], text) = input.split_first_chunk::<2>().unwrap_or((&[0, 0], input));
        let text = String::from_utf8_lossy(text);
        let fold = Fold::new(20 + width as usize % 80, b"\r\n ", 1);
        for encoder in [rfc2047::B, rfc2047::Q_TEXT, rfc2047::Q_PHRASE] {
            let start = column as usize % 90;
            let mut out = String::new();
            let mut column = start;
            let appended = encoder.encode_words("utf-8", &text, &mut column, fold, &mut out);
            assert_eq!(appended, out.len());
            for word in out.split([' ', '\r', '\n']).filter(|word| !word.is_empty()) {
                assert!(word.len() <= rfc2047::MAX_WORD_LEN, "{word}");
            }
            assert_eq!(
                rfc2047::decode_text(out.as_bytes(), rfc2047::utf8_charset),
                text
            );
        }
    }

    fn hex(&self) {
        let input = self.0;
        for escape in [hex::PERCENT, hex::XTEXT] {
            let encoded = escape.encode(input);
            assert_eq!(escape.decode(&encoded).as_deref(), Ok(input));
            if let Ok(decoded) = escape.decode(input)
                && let Cow::Borrowed(borrowed) = decoded
            {
                assert_eq!(borrowed, input);
            }
        }
    }

    fn utf7(&self) {
        let input = self.0;
        let text = String::from_utf8_lossy(input);
        for engine in [utf7::IMAP, utf7::MAIL] {
            let encoded = engine.encode(&text);
            assert_eq!(engine.encoded_len(&text), encoded.len());
            assert_eq!(engine.decode(&encoded).as_deref(), Ok(&*text));
            assert_eq!(engine.decode_lossy(&encoded), text);
            let _ = engine.lenient().decode(input);
            let _ = engine.decode_lossy(input);
            let mut appended = String::from("prefix");
            if engine.decode_append(input, &mut appended).is_err() {
                assert_eq!(appended, "prefix");
            }
        }
        if let Ok(decoded) = utf7::IMAP.decode(input) {
            assert_eq!(utf7::IMAP.encode(&decoded).as_bytes(), input);
        }
    }

    fn pem(&self) {
        let input = self.0;
        let mut previous_end = 0;
        for block in pem::STANDARD.blocks(input).flatten() {
            assert!(previous_end <= block.span.start);
            assert!(block.span.start < block.span.end && block.span.end <= input.len());
            previous_end = block.span.end;
        }
        let label = "TEST KEY";
        for engine in [pem::STANDARD, pem::STANDARD.with_ending(LineEnding::CrLf)] {
            let encoded = engine.encode(label, input);
            assert_eq!(encoded.len(), engine.encoded_len(label.len(), input.len()));
            let block = engine.decode(&encoded).expect("round trip");
            assert_eq!(block.label, label);
            assert_eq!(block.contents, input);
            assert_eq!(block.span, 0..encoded.len());
        }
    }
}
