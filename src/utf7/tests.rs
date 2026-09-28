/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{IMAP, MAIL, Utf7};
use crate::{Error, test_rng::XorShift};

#[test]
fn lossy_decoding_follows_the_engine_syntax() {
    for name in [
        "INBOX",
        "Entwürfe",
        "Отправленные",
        "送信済み",
        "A&B",
        "~peter/mail/台北/日本語",
    ] {
        let encoded = IMAP.encode(name);
        assert_eq!(IMAP.decode_lossy(&encoded), name);
        assert_eq!(
            IMAP.decode_lossy(&encoded),
            IMAP.decode(&encoded).expect("valid")
        );
    }
    assert_eq!(IMAP.decode_lossy("&ZeVnLIqe-&&-"), "日本語\u{fffd}&");
    assert_eq!(IMAP.decode_lossy(b"a\xffb"), "a\u{fffd}b");
    assert_eq!(IMAP.decode_lossy("1+1"), "1+1");
    assert_eq!(MAIL.decode_lossy("1+-1"), "1+1");
    assert_eq!(MAIL.decode_lossy("A+ImIDkQ."), "A\u{2262}\u{391}.");
}

#[test]
fn imap_lossy_decoding_flags_ill_formed_shifts() {
    for (input, expected) in [
        ("x&A-y", "x\u{fffd}y"),
        ("&AKN-", "£\u{fffd}"),
        ("x&AKM y", "x£\u{fffd} y"),
        ("&AKM", "£\u{fffd}"),
        ("&ACY-", "&\u{fffd}"),
        ("a&", "a\u{fffd}"),
        ("a\u{1}b", "a\u{fffd}b"),
    ] {
        assert_eq!(IMAP.decode_lossy(input), expected, "{input:?}");
    }
    for (input, expected) in [
        ("x&A-y", "xy"),
        ("&AKN-", "£"),
        ("&AKM", "£"),
        ("&ACY-", "&"),
        ("a&", "a&"),
        ("Entwürfe", "Entwürfe"),
    ] {
        assert_eq!(IMAP.lenient().decode_lossy(input), expected, "{input:?}");
        if !expected.contains('\u{fffd}') {
            assert_eq!(IMAP.lenient().decode(input).as_deref(), Ok(expected));
        }
    }
    assert_eq!(
        IMAP.lenient().decode_lossy(b"\xc3&AA-\xa9"),
        "\u{fffd}\u{fffd}"
    );
}

#[test]
fn imap_strict_rejects_an_encoded_ampersand() {
    for input in ["&ACY-", "&AKMAJg-"] {
        assert!(IMAP.decode(input).is_err(), "{input:?}");
    }
    assert_eq!(IMAP.lenient().decode("&AKMAJg-").as_deref(), Ok("£&"));
    assert_eq!(IMAP.encode("£&"), "&AKM-&-");
}

#[test]
fn lenient_imap_validates_raw_utf8_in_the_input() {
    assert_eq!(
        IMAP.lenient().decode(b"&ZeVnLIqe-\xff"),
        Err(Error::InvalidUtf8 { offset: 10 })
    );
    assert!(IMAP.lenient().decode(b"\xc3&AA-\xa9").is_err());
}

#[test]
fn encoding_long_text_reserves_the_exact_length() {
    let text = format!("é{}", "a".repeat(1000));
    for engine in [IMAP, MAIL] {
        let encoded = engine.encode(&text);
        assert_eq!(encoded.capacity(), encoded.len(), "{engine:?}");
        let mut appended = Vec::new();
        engine.encode_append(&text, &mut appended);
        assert_eq!(appended.capacity(), appended.len(), "{engine:?}");
    }
}

const ROUND_TRIPS: &[(&str, &str)] = &[
    ("~peter/mail/&U,BTFw-/&ZeVnLIqe-", "~peter/mail/台北/日本語"),
    ("&U,BTF2XlZyyKng-", "台北日本語"),
    ("Hi Mom -&Jjo--!", "Hi Mom -☺-!"),
    ("&ZeVnLIqe-", "日本語"),
    ("Item 3 is &AKM-1.", "Item 3 is £1."),
    ("Plus minus &- -&- &--", "Plus minus & -& &-"),
    ("&VMhUyNg93gQ-", "哈哈😄"),
    ("Entw&APw-rfe", "Entwürfe"),
    ("&BB4EQgQ,BEAEMAQyBDsENQQ9BD0ESwQ1-", "Отправленные"),
    ("INBOX", "INBOX"),
    ("", ""),
];

#[test]
fn imap_round_trips() {
    for (encoded, decoded) in ROUND_TRIPS {
        assert_eq!(IMAP.encode(decoded), *encoded, "{decoded:?}");
        assert_eq!(IMAP.decode(encoded).as_deref(), Ok(*decoded), "{encoded:?}");
        assert_eq!(
            IMAP.lenient().decode(encoded).as_deref(),
            Ok(*decoded),
            "{encoded:?}"
        );
    }
}

#[test]
fn imap_strict_rejects_what_rfc_3501_forbids() {
    for (input, error) in [
        ("&ZeVnLIqe", Error::Truncated { offset: 9 }),
        ("Hello, World&ACE-", Error::NonCanonical { offset: 13 }),
        ("&AKM-&AKM-", Error::NonCanonical { offset: 5 }),
        (
            "a\u{e9}b",
            Error::InvalidByte {
                offset: 1,
                byte: 0xc3,
            },
        ),
        (
            "tab\there",
            Error::InvalidByte {
                offset: 3,
                byte: b'\t',
            },
        ),
        ("&", Error::Truncated { offset: 1 }),
        ("&AKN-", Error::NonCanonical { offset: 3 }),
        ("&2D0-", Error::InvalidUtf16 { offset: 1 }),
        (
            "&Z!-",
            Error::InvalidByte {
                offset: 2,
                byte: b'!',
            },
        ),
    ] {
        assert_eq!(IMAP.decode(input), Err(error), "{input:?}");
    }
}

#[test]
fn imap_lenient_matches_imap_proto_without_truncation() {
    let lenient = IMAP.lenient();
    for (input, expected) in [
        ("Hello, World&ACE-", Some("Hello, World!")),
        ("&ZeVnLIqe", Some("日本語")),
        ("Test-ąęć-Test", Some("Test-ąęć-Test")),
        ("a\u{1f604}b", Some("a\u{1f604}b")),
        ("trailing &", Some("trailing &")),
        (
            "&APw-ber ihre mi&AN8-liche Lage&ADs- &ACI-wir",
            Some("über ihre mißliche Lage; \"wir"),
        ),
        ("&Z!-", None),
        ("&2D0-", None),
    ] {
        assert_eq!(lenient.decode(input).ok().as_deref(), expected, "{input:?}");
    }
}

#[test]
fn identity_check_matches_the_byte_classes() {
    let mut rng = XorShift::new(7);
    for len in 0..40 {
        for _ in 0..200 {
            let mut bytes: Vec<u8> = (0..len).map(|_| b' ' + rng.below(95) as u8).collect();
            if len > 0 && rng.below(2) == 0 {
                let at = rng.below(len);
                bytes[at] = *rng.pick(&[0x00, 0x1f, b'&', 0x7f, 0x80, 0xff, b' ', b'~']);
            }
            let printable = bytes
                .iter()
                .all(|&byte| (b' '..=b'~').contains(&byte) && byte != b'&');
            let ascii = bytes.iter().all(|&byte| byte.is_ascii() && byte != b'&');
            assert_eq!(IMAP.is_all_direct(&bytes), printable, "{bytes:?}");
            assert_eq!(IMAP.lenient().is_all_direct(&bytes), printable, "{bytes:?}");
            assert_eq!(IMAP.decodes_to_itself(&bytes), printable, "{bytes:?}");
            assert_eq!(IMAP.lenient().decodes_to_itself(&bytes), ascii, "{bytes:?}");
        }
    }
}

#[test]
fn encodings_fit_the_reserved_length() {
    for text in [
        "\x01",
        "\x01\x01",
        "\x01&\x01",
        "\x01+\x01",
        "\x01&\x01\x01&\x01",
        "&&&&",
        "++++",
        "\x01a\x01a\x01",
        "\u{1f604}&\u{e9}",
        "\u{e9}\u{7f}~\\\u{1f604}\x00",
    ] {
        for engine in [IMAP, MAIL] {
            let len = engine.encoded_len(text);
            assert!(len <= Utf7::max_encoded_len(text.len()), "{text:?}");
            assert_eq!(engine.encode(text).len(), len, "{text:?}");
        }
    }
    let worst = "\x01&".repeat(40) + "\x01";
    assert_eq!(IMAP.encoded_len(&worst), Utf7::max_encoded_len(worst.len()));
}

#[test]
fn rfc_2152_decoding() {
    for (input, expected) in [
        (&b"Hi Mom -+Jjo--!"[..], "Hi Mom -\u{263a}-!"),
        (b"A+ImIDkQ.", "A\u{2262}\u{391}."),
        (b"+ZeVnLIqe-", "\u{65e5}\u{672c}\u{8a9e}"),
        (b"Item 3 is +AKM-1.", "Item 3 is \u{a3}1."),
        (b"1 +- 1 = 2", "1 + 1 = 2"),
        (b"+AKM", "\u{a3}"),
    ] {
        assert_eq!(MAIL.decode(input).as_deref(), Ok(expected), "{input:?}");
        assert_eq!(MAIL.decode_lossy(input), expected, "{input:?}");
    }
    assert_eq!(MAIL.decode_lossy(b"+!x"), "\u{fffd}!x");
    assert_eq!(MAIL.decode_lossy(b"+AKN-"), "\u{a3}\u{fffd}");
    assert_eq!(MAIL.decode_lossy(b"caf\xe9"), "caf\u{fffd}");
    assert!(MAIL.decode(b"+!x").is_err());
    assert_eq!(MAIL.encode("1 + 1 = 2 \u{263a}"), "1 +- 1 = 2 +Jjo-");
    assert_eq!(
        MAIL.decode(MAIL.encode("\u{1f604} and ~")).as_deref(),
        Ok("\u{1f604} and ~")
    );
}
