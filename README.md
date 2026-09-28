# encodify

[![crates.io](https://img.shields.io/crates/v/encodify)](https://crates.io/crates/encodify)
[![build](https://github.com/stalwartlabs/encodify/actions/workflows/rust.yml/badge.svg)](https://github.com/stalwartlabs/encodify/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/encodify)](https://docs.rs/encodify)
[![msrv](https://img.shields.io/crates/msrv/encodify)](https://crates.io/crates/encodify)
[![crates.io](https://img.shields.io/crates/l/encodify)](http://www.apache.org/licenses/LICENSE-2.0)

_encodify_ is a fast **Base64, Base32, Quoted-Printable, RFC 2047, UTF-7 and PEM encoding and decoding library** written in Rust. It implements the binary-to-text encodings used across the Internet mail protocol stack:
- the MIME content transfer encodings (_RFC 2045_) and MIME encoded words (_RFC 2047_);
- the Base32 and Base64 alphabets of _RFC 4648_;
- UTF-7 (_RFC 2152_) and the modified Base64 of IMAP mailbox names (_RFC 3501_);
- dkim-quoted-printable (_RFC 6376_), percent and xtext escapes (_RFC 2231_, _RFC 3461_);
- the textual encoding of PEM (_RFC 7468_).

## Features

- **Base64**:
  - Standard (`+/`) and URL-safe (`-_`) alphabets, with required, omitted or optional padding, and decoders that accept both alphabets.
  - Strict decoding that accepts exactly one encoding per value, and lenient decoding that skips whitespace and tolerates missing or misplaced padding as found in real-world e-mail.
  - MIME bodies: 76-column CRLF wrapping and line-aware decoding.
  - Folded values:
    - `b=` values in DKIM signatures;
    - iCalendar and vCard content lines, folded when encoding and unfolded when decoding;
    - values that end at a delimiter.
  - Incremental decoding for tokenizers, streaming to `io::Write`, `fmt::Display`, and compile-time encoding.
- **Base32**:
  - _RFC 4648_ alphabet with or without padding, and the Stalwart alphabet used by ids, blob ids and storage keys.
  - `u64` numerals as used by JMAP ids, streaming encoders and decoders, `fmt::Display`.
- **Quoted-Printable**:
  - Body and attachment encoding with soft line breaks (_RFC 2045_), and lenient or strict decoding that borrows the input when there is nothing to rewrite.
  - "Q" encoding for header encoded words, in text and phrase contexts (_RFC 2047_).
  - dkim-quoted-printable (_RFC 6376_).
  - Exact encoded lengths with early exit, to choose between quoted-printable and base64 without encoding twice, and exact decoded lengths without decoding.
- **RFC 2047 encoded words**:
  - Encoding of header text into `B` or `Q` words that never split a character, with folding.
  - Decoding of single encoded words for structured fields, and of whole unstructured field bodies with charset conversion supplied by the caller.
- **Escapes**: percent (_RFC 2231_) and xtext (_RFC 3461_) encoding and decoding, borrowing when nothing is escaped.
- **UTF-7**: IMAP modified UTF-7 mailbox names (strict or lenient) and _RFC 2152_ UTF-7 for MIME bodies.
- **PEM**: armored blocks with labels, headers and checksums.
- **Performance and safety**:
  - SIMD kernels for NEON (aarch64) and SSSE3/AVX2 (x86 and x86_64, detected at runtime), with fast portable fallbacks on every other target, including 32-bit ARM, RISC-V and `wasm32`.
  - Output appended to caller-owned buffers or written into slices, without zero-filling or hidden reallocations.
  - Two dependencies: [memchr](https://crates.io/crates/memchr) and [simdutf8](https://crates.io/crates/simdutf8).

## Usage

Every operation is a method on an engine constant, so the configuration is visible at the call site:

```rust
use encodify::{Fold, base32, base64, qp, rfc2047, utf7};

# fn main() -> Result<(), encodify::Error> {
// Base64: strict and lenient decoding, MIME wrapping, URL-safe tokens.
assert_eq!(base64::STANDARD.encode(b"Hello"), "SGVsbG8=");
assert_eq!(base64::MIME.decode("SGVs\r\nbG8=\r\n")?, b"Hello");
assert_eq!(base64::URL_SAFE_NO_PAD.encode([0xfb, 0xff]), "-_8");

// Encoding into an existing buffer never zero-fills it first.
let mut header = String::from("Authorization: Basic ");
base64::STANDARD.encode_append("user:secret", &mut header);
assert_eq!(header, "Authorization: Basic dXNlcjpzZWNyZXQ=");

// Folded iCalendar/vCard values decode in one call.
let card = b"SGVsbG8s\r\n IHdvcmxk\r\n IQ==\r\nEND:VCARD\r\n";
let mut photo = Vec::new();
let value = base64::STANDARD.decode_folded(card, &mut photo)?;
assert_eq!(photo, b"Hello, world!");
assert_eq!(&card[value.next..], b"END:VCARD\r\n");

// Base32 JMAP ids and RFC 4648 text.
assert_eq!(&*base32::STALWART.encode_u64(20080258862541), "singleton");
assert_eq!(base32::STANDARD.encode(b"foobar"), "MZXW6YTBOI======");

// Quoted-printable bodies and dkim-quoted-printable tags.
assert_eq!(qp::BODY.encode("Grüße,\nJürgen\n"), "Gr=C3=BC=C3=9Fe,\r\nJ=C3=BCrgen\r\n");
assert_eq!(qp::DKIM.decode("a=3Db=3B\r\n\t=20c")?, &b"a=b; c"[..]);

// RFC 2047 encoded words, both ways.
let mut subject = String::from("Subject: ");
let mut column = subject.len();
rfc2047::Q_TEXT.encode_words("utf-8", "Grüße aus Köln", &mut column, Fold::HEADER, &mut subject);
assert_eq!(subject, "Subject: =?utf-8?Q?Gr=C3=BC=C3=9Fe_aus_K=C3=B6ln?=");
let decoded = rfc2047::decode_text(b"=?utf-8?B?0J/RgNC40LLQtdGC?=", rfc2047::utf8_charset);
assert_eq!(decoded, "Привет");

// IMAP mailbox names.
assert_eq!(utf7::IMAP.encode("Entwürfe"), "Entw&APw-rfe");
assert_eq!(utf7::IMAP.decode("Entw&APw-rfe")?, "Entwürfe");
# Ok(())
# }
```

## Performance

Throughput measured with [criterion](https://crates.io/crates/criterion) on the same inputs for every crate (`cargo bench --bench codec`). Encoders are measured in bytes of input per second and decoders in bytes of output per second, in GB/s (10^9 bytes). The factor in parentheses is how many times faster encodify is than the crate on that row, or the crate named next to it: `3.0x` means three times the throughput, and a value below `1.0x` means encodify is slower. The base64 and base32 benchmarks write into caller-provided buffers (the `base32` crate always allocates); the quoted-printable benchmarks return a new buffer for both crates.

The crates compared are [base64](https://crates.io/crates/base64), [base64-simd](https://crates.io/crates/base64-simd), [base64-turbo](https://crates.io/crates/base64-turbo), [data-encoding](https://crates.io/crates/data-encoding), [simdutf](https://crates.io/crates/simdutf), [base32](https://crates.io/crates/base32), [fast32](https://crates.io/crates/fast32) and [quoted_printable](https://crates.io/crates/quoted_printable).

At 64 KiB, against the fastest other crate for each operation:

| Operation | Apple M5 Max (NEON) | AMD EPYC Zen 2 (AVX2) |
|---|---|---|
| Base64 encode | 25.7 GB/s (1.0x simdutf) | 19.2 GB/s (1.0x base64-turbo) |
| Base64 decode | 18.1 GB/s (1.2x simdutf) | 15.0 GB/s (1.0x base64-turbo) |
| Base64 MIME encode (76 columns, CRLF) | 21.3 GB/s (1.5x simdutf) | 10.7 GB/s (1.1x simdutf) |
| Base64 MIME decode (76 columns, CRLF) | 14.1 GB/s (1.4x simdutf) | 8.6 GB/s (1.7x simdutf) |
| Base32 encode | 24.2 GB/s (6.5x data-encoding) | 7.2 GB/s (4.8x data-encoding) |
| Base32 decode | 10.6 GB/s (3.1x data-encoding) | 5.0 GB/s (3.9x data-encoding) |
| Quoted-printable encode, Latin text | 6.1 GB/s (5.1x quoted_printable) | 2.0 GB/s (5.8x quoted_printable) |
| Quoted-printable decode, Latin text | 5.3 GB/s (7.8x quoted_printable) | 2.2 GB/s (9.0x quoted_printable) |

<details>
<summary>Apple M5 Max (NEON): every size and crate</summary>

#### Base64 encode

| Implementation | 32 B | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|
| **encodify** | 6.58 GB/s | 25.15 GB/s | 25.73 GB/s | 25.65 GB/s |
| base64 | 3.90 GB/s (1.7x) | 5.12 GB/s (4.9x) | 5.04 GB/s (5.1x) | 5.02 GB/s (5.1x) |
| base64-simd | 6.65 GB/s (1.0x) | 13.07 GB/s (1.9x) | 12.83 GB/s (2.0x) | 12.82 GB/s (2.0x) |
| base64-turbo | 5.30 GB/s (1.2x) | 11.93 GB/s (2.1x) | 12.09 GB/s (2.1x) | 12.08 GB/s (2.1x) |
| data-encoding | 2.40 GB/s (2.7x) | 4.37 GB/s (5.8x) | 4.43 GB/s (5.8x) | 4.41 GB/s (5.8x) |
| simdutf | 6.52 GB/s (1.0x) | 25.78 GB/s (1.0x) | 25.95 GB/s (1.0x) | 25.96 GB/s (1.0x) |

#### Base64 decode

| Implementation | 32 B | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|
| **encodify** | 6.08 GB/s | 17.70 GB/s | 18.12 GB/s | 18.12 GB/s |
| base64 | 2.65 GB/s (2.3x) | 4.65 GB/s (3.8x) | 4.63 GB/s (3.9x) | 4.65 GB/s (3.9x) |
| base64-simd | 7.73 GB/s (0.8x) | 9.72 GB/s (1.8x) | 9.59 GB/s (1.9x) | 9.59 GB/s (1.9x) |
| base64-turbo | 4.57 GB/s (1.3x) | 6.88 GB/s (2.6x) | 6.89 GB/s (2.6x) | 6.89 GB/s (2.6x) |
| data-encoding | 1.99 GB/s (3.1x) | 4.16 GB/s (4.3x) | 4.42 GB/s (4.1x) | 4.42 GB/s (4.1x) |
| simdutf | 2.02 GB/s (3.0x) | 14.57 GB/s (1.2x) | 15.38 GB/s (1.2x) | 15.42 GB/s (1.2x) |

#### Base64 MIME encode (76 columns, CRLF)

| Implementation | 32 B | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|
| **encodify** | 4.50 GB/s | 18.21 GB/s | 21.27 GB/s | 21.52 GB/s |
| data-encoding | 1.84 GB/s (2.4x) | 3.88 GB/s (4.7x) | 4.05 GB/s (5.3x) | 4.05 GB/s (5.3x) |
| simdutf (LF only) | 5.75 GB/s (0.8x) | 13.17 GB/s (1.4x) | 14.35 GB/s (1.5x) | 14.69 GB/s (1.5x) |

#### Base64 MIME decode (76 columns, CRLF)

| Implementation | 32 B | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|
| **encodify** | 3.48 GB/s | 10.82 GB/s | 14.08 GB/s | 14.06 GB/s |
| base64 (strip + decode) | 0.95 GB/s (3.7x) | 1.04 GB/s (10.4x) | 1.04 GB/s (13.6x) | 1.03 GB/s (13.6x) |
| base64-simd (forgiving) | 2.70 GB/s (1.3x) | 1.75 GB/s (6.2x) | 1.64 GB/s (8.6x) | 1.63 GB/s (8.6x) |
| data-encoding | 1.87 GB/s (1.9x) | 2.64 GB/s (4.1x) | 2.70 GB/s (5.2x) | 2.69 GB/s (5.2x) |
| simdutf | 2.00 GB/s (1.7x) | 8.23 GB/s (1.3x) | 10.08 GB/s (1.4x) | 10.13 GB/s (1.4x) |

#### Base32 encode

| Implementation | 32 B | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|
| **encodify** | 3.89 GB/s | 24.67 GB/s | 24.25 GB/s | 24.25 GB/s |
| base32 (allocates) | 0.46 GB/s (8.5x) | 1.55 GB/s (15.9x) | 1.64 GB/s (14.8x) | 1.27 GB/s (19.1x) |
| data-encoding | 2.16 GB/s (1.8x) | 3.73 GB/s (6.6x) | 3.75 GB/s (6.5x) | 3.71 GB/s (6.5x) |
| fast32 | 2.86 GB/s (1.4x) | 3.53 GB/s (7.0x) | 3.55 GB/s (6.8x) | 3.51 GB/s (6.9x) |

#### Base32 decode

| Implementation | 32 B | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|
| **encodify** | 2.86 GB/s | 10.63 GB/s | 10.61 GB/s | 10.62 GB/s |
| base32 (allocates) | 0.76 GB/s (3.8x) | 1.45 GB/s (7.3x) | 1.52 GB/s (7.0x) | 1.51 GB/s (7.0x) |
| data-encoding | 1.74 GB/s (1.6x) | 3.33 GB/s (3.2x) | 3.42 GB/s (3.1x) | 3.46 GB/s (3.1x) |
| fast32 | 2.18 GB/s (1.3x) | 2.82 GB/s (3.8x) | 2.87 GB/s (3.7x) | 2.84 GB/s (3.7x) |

#### Base32 `u64` numerals (per id)

| Implementation | append | decode | encode |
|---|---:|---:|---:|
| **encodify** | 0.77 ns | 1.66 ns | 0.70 ns |
| fast32 | 2.04 ns (2.6x) | 1.90 ns (1.1x) |  |
| fast32 (allocates) |  |  | 20.53 ns (29.3x) |

#### Quoted-printable encode, Latin text

| Implementation | 4 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|
| **encodify** | 5.97 GB/s | 6.13 GB/s | 6.21 GB/s |
| quoted_printable | 1.16 GB/s (5.2x) | 1.20 GB/s (5.1x) | 1.20 GB/s (5.2x) |

#### Quoted-printable encode, Cyrillic text (mostly escaped)

| Implementation | 4 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|
| **encodify** | 1.21 GB/s | 1.16 GB/s | 1.23 GB/s |
| quoted_printable | 0.28 GB/s (4.3x) | 0.29 GB/s (4.1x) | 0.28 GB/s (4.3x) |

#### Quoted-printable decode, Latin text

| Implementation | 4 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|
| **encodify** | 5.35 GB/s | 5.29 GB/s | 5.39 GB/s |
| quoted_printable | 0.64 GB/s (8.4x) | 0.68 GB/s (7.8x) | 0.70 GB/s (7.7x) |

#### Quoted-printable decode, Cyrillic text (mostly escaped)

| Implementation | 4 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|
| **encodify** | 1.37 GB/s | 1.38 GB/s | 1.37 GB/s |
| quoted_printable | 0.27 GB/s (5.1x) | 0.28 GB/s (4.9x) | 0.28 GB/s (4.9x) |

</details>

<details>
<summary>AMD EPYC, Zen 2 (AVX2): every size and crate</summary>

A 4-vCPU virtual machine; the other SIMD crates use their AVX2 code as well.

#### Base64 encode

| Implementation | 32 B | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|
| **encodify** | 1.88 GB/s | 16.47 GB/s | 19.17 GB/s | 17.95 GB/s |
| base64 | 1.18 GB/s (1.6x) | 1.73 GB/s (9.5x) | 1.74 GB/s (11.0x) | 1.83 GB/s (9.8x) |
| base64-simd | 2.06 GB/s (0.9x) | 7.93 GB/s (2.1x) | 8.31 GB/s (2.3x) | 7.90 GB/s (2.3x) |
| base64-turbo | 2.20 GB/s (0.9x) | 14.59 GB/s (1.1x) | 19.91 GB/s (1.0x) | 18.72 GB/s (1.0x) |
| data-encoding | 0.83 GB/s (2.3x) | 1.78 GB/s (9.3x) | 1.77 GB/s (10.8x) | 1.76 GB/s (10.2x) |
| simdutf | 1.99 GB/s (0.9x) | 10.96 GB/s (1.5x) | 13.96 GB/s (1.4x) | 13.12 GB/s (1.4x) |

#### Base64 decode

| Implementation | 32 B | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|
| **encodify** | 1.63 GB/s | 11.54 GB/s | 14.97 GB/s | 14.07 GB/s |
| base64 | 0.75 GB/s (2.2x) | 1.57 GB/s (7.3x) | 1.56 GB/s (9.6x) | 1.63 GB/s (8.6x) |
| base64-simd | 2.35 GB/s (0.7x) | 4.99 GB/s (2.3x) | 5.09 GB/s (2.9x) | 5.20 GB/s (2.7x) |
| base64-turbo | 1.59 GB/s (1.0x) | 11.03 GB/s (1.0x) | 15.64 GB/s (1.0x) | 13.83 GB/s (1.0x) |
| data-encoding | 0.64 GB/s (2.6x) | 1.60 GB/s (7.2x) | 1.63 GB/s (9.2x) | 1.65 GB/s (8.6x) |
| simdutf | 0.56 GB/s (2.9x) | 6.74 GB/s (1.7x) | 11.23 GB/s (1.3x) | 9.71 GB/s (1.4x) |

#### Base64 MIME encode (76 columns, CRLF)

| Implementation | 32 B | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|
| **encodify** | 1.36 GB/s | 7.95 GB/s | 10.72 GB/s | 10.56 GB/s |
| data-encoding | 0.68 GB/s (2.0x) | 1.38 GB/s (5.8x) | 1.36 GB/s (7.9x) | 1.44 GB/s (7.3x) |
| simdutf (LF only) | 1.40 GB/s (1.0x) | 7.32 GB/s (1.1x) | 9.50 GB/s (1.1x) | 8.59 GB/s (1.2x) |

#### Base64 MIME decode (76 columns, CRLF)

| Implementation | 32 B | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|
| **encodify** | 1.02 GB/s | 5.82 GB/s | 8.61 GB/s | 8.37 GB/s |
| base64 (strip + decode) | 0.32 GB/s (3.2x) | 0.39 GB/s (14.9x) | 0.39 GB/s (22.3x) | 0.39 GB/s (21.6x) |
| base64-simd (forgiving) | 1.02 GB/s (1.0x) | 0.79 GB/s (7.3x) | 0.87 GB/s (9.9x) | 0.82 GB/s (10.3x) |
| data-encoding | 0.59 GB/s (1.7x) | 0.89 GB/s (6.5x) | 0.91 GB/s (9.4x) | 0.89 GB/s (9.4x) |
| simdutf | 0.55 GB/s (1.9x) | 3.75 GB/s (1.6x) | 5.20 GB/s (1.7x) | 5.23 GB/s (1.6x) |

#### Base32 encode

| Implementation | 32 B | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|
| **encodify** | 1.26 GB/s | 6.49 GB/s | 7.21 GB/s | 6.70 GB/s |
| base32 (allocates) | 0.18 GB/s (7.0x) | 0.35 GB/s (18.5x) | 0.36 GB/s (20.0x) | 0.36 GB/s (18.6x) |
| data-encoding | 0.75 GB/s (1.7x) | 1.43 GB/s (4.5x) | 1.51 GB/s (4.8x) | 1.49 GB/s (4.5x) |
| fast32 | 0.98 GB/s (1.3x) | 1.18 GB/s (5.5x) | 1.20 GB/s (6.0x) | 1.17 GB/s (5.7x) |

#### Base32 decode

| Implementation | 32 B | 1 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|
| **encodify** | 0.90 GB/s | 4.27 GB/s | 5.03 GB/s | 4.81 GB/s |
| base32 (allocates) | 0.34 GB/s (2.6x) | 0.46 GB/s (9.2x) | 0.46 GB/s (11.0x) | 0.45 GB/s (10.8x) |
| data-encoding | 0.49 GB/s (1.8x) | 1.18 GB/s (3.6x) | 1.29 GB/s (3.9x) | 1.32 GB/s (3.7x) |
| fast32 | 0.70 GB/s (1.3x) | 0.92 GB/s (4.6x) | 0.94 GB/s (5.4x) | 0.93 GB/s (5.2x) |

#### Base32 `u64` numerals (per id)

| Implementation | append | decode | encode |
|---|---:|---:|---:|
| **encodify** | 9.78 ns | 5.55 ns | 4.43 ns |
| fast32 | 13.73 ns (1.4x) | 12.53 ns (2.3x) |  |
| fast32 (allocates) |  |  | 24.55 ns (5.5x) |

#### Quoted-printable encode, Latin text

| Implementation | 4 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|
| **encodify** | 2.05 GB/s | 2.00 GB/s | 1.76 GB/s |
| quoted_printable | 0.39 GB/s (5.2x) | 0.35 GB/s (5.8x) | 0.39 GB/s (4.5x) |

#### Quoted-printable encode, Cyrillic text (mostly escaped)

| Implementation | 4 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|
| **encodify** | 0.41 GB/s | 0.46 GB/s | 0.45 GB/s |
| quoted_printable | 0.11 GB/s (3.9x) | 0.11 GB/s (4.4x) | 0.10 GB/s (4.6x) |

#### Quoted-printable decode, Latin text

| Implementation | 4 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|
| **encodify** | 2.17 GB/s | 2.24 GB/s | 2.29 GB/s |
| quoted_printable | 0.22 GB/s (9.7x) | 0.25 GB/s (9.0x) | 0.24 GB/s (9.5x) |

#### Quoted-printable decode, Cyrillic text (mostly escaped)

| Implementation | 4 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|
| **encodify** | 0.49 GB/s | 0.51 GB/s | 0.48 GB/s |
| quoted_printable | 0.09 GB/s (5.4x) | 0.09 GB/s (5.8x) | 0.09 GB/s (5.2x) |

</details>

### SSSE3

x86 CPUs without AVX2 use the SSSE3 kernels, measured on the same EPYC with `--cfg encodify_no_avx2`. The other SIMD crates cannot be restricted to SSSE3 in the same way, so the factors are against the fastest portable crate.

| Operation | 32 B | 1 KiB | 4 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|---:|
| Base64 encode | 1.76 GB/s (1.5x base64) | 8.58 GB/s (5.1x base64) |  | 9.92 GB/s (5.5x data-encoding) | 9.83 GB/s (5.5x data-encoding) |
| Base64 decode | 1.60 GB/s (1.9x base64) | 7.45 GB/s (4.6x base64) |  | 8.30 GB/s (5.0x base64) | 8.25 GB/s (5.0x base64) |
| Base64 MIME encode (76 columns, CRLF) | 1.37 GB/s (2.1x data-encoding) | 6.35 GB/s (4.3x data-encoding) |  | 7.78 GB/s (5.5x data-encoding) | 7.17 GB/s (4.9x data-encoding) |
| Base64 MIME decode (76 columns, CRLF) | 0.97 GB/s (1.6x data-encoding) | 4.42 GB/s (5.2x data-encoding) |  | 6.15 GB/s (6.7x data-encoding) | 6.19 GB/s (7.0x data-encoding) |
| Base32 encode | 1.23 GB/s (1.3x fast32) | 5.93 GB/s (4.0x data-encoding) |  | 7.19 GB/s (4.8x data-encoding) | 6.81 GB/s (4.6x data-encoding) |
| Base32 decode | 0.92 GB/s (1.3x fast32) | 3.83 GB/s (3.2x data-encoding) |  | 4.66 GB/s (4.0x data-encoding) | 4.65 GB/s (4.2x data-encoding) |
| Quoted-printable encode, Latin text |  |  | 1.87 GB/s (5.1x quoted_printable) | 1.98 GB/s (5.4x quoted_printable) | 1.97 GB/s (5.5x quoted_printable) |
| Quoted-printable decode, Latin text |  |  | 2.24 GB/s (9.8x quoted_printable) | 2.21 GB/s (9.1x quoted_printable) | 2.30 GB/s (9.4x quoted_printable) |

### Portable fallbacks

Targets without NEON, SSSE3 or AVX2 (32-bit ARM, RISC-V, PowerPC, s390x, `wasm32` and others) use portable code: table-driven base64 (two symbols per 12-bit lookup when encoding, four pre-shifted tables when decoding), table-driven base32 and SWAR quoted-printable. Measured with `--cfg encodify_scalar`, which forces these fallbacks, against the fastest portable crate.

Apple M5 Max:

| Operation | 32 B | 1 KiB | 4 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|---:|
| Base64 encode | 5.38 GB/s (1.4x base64) | 12.94 GB/s (2.5x base64) |  | 13.63 GB/s (2.7x base64) | 13.45 GB/s (2.7x base64) |
| Base64 decode | 3.11 GB/s (1.2x base64) | 4.68 GB/s (1.0x base64) |  | 4.66 GB/s (1.0x base64) | 4.65 GB/s (1.0x base64) |
| Base64 MIME encode (76 columns, CRLF) | 3.90 GB/s (2.1x data-encoding) | 7.04 GB/s (1.8x data-encoding) |  | 7.28 GB/s (1.8x data-encoding) | 7.50 GB/s (1.9x data-encoding) |
| Base64 MIME decode (76 columns, CRLF) | 2.42 GB/s (1.3x data-encoding) | 3.48 GB/s (1.3x data-encoding) |  | 3.54 GB/s (1.3x data-encoding) | 3.55 GB/s (1.3x data-encoding) |
| Base32 encode | 3.18 GB/s (1.1x fast32) | 4.39 GB/s (1.2x data-encoding) |  | 4.45 GB/s (1.2x data-encoding) | 4.50 GB/s (1.2x data-encoding) |
| Base32 decode | 2.53 GB/s (1.1x fast32) | 3.85 GB/s (1.2x data-encoding) |  | 3.74 GB/s (1.1x data-encoding) | 3.88 GB/s (1.1x data-encoding) |
| Quoted-printable encode, Latin text |  |  | 5.30 GB/s (4.6x quoted_printable) | 5.36 GB/s (4.5x quoted_printable) | 5.45 GB/s (4.5x quoted_printable) |
| Quoted-printable decode, Latin text |  |  | 4.71 GB/s (7.0x quoted_printable) | 4.74 GB/s (6.7x quoted_printable) | 4.75 GB/s (6.6x quoted_printable) |

AMD EPYC, Zen 2:

| Operation | 32 B | 1 KiB | 4 KiB | 64 KiB | 1 MiB |
|---|---:|---:|---:|---:|---:|
| Base64 encode | 1.54 GB/s (1.3x base64) | 3.68 GB/s (2.1x data-encoding) |  | 3.67 GB/s (2.0x base64) | 3.65 GB/s (2.1x data-encoding) |
| Base64 decode | 1.16 GB/s (1.4x base64) | 2.17 GB/s (1.4x base64) |  | 2.22 GB/s (1.4x data-encoding) | 2.30 GB/s (1.4x base64) |
| Base64 MIME encode (76 columns, CRLF) | 1.11 GB/s (1.7x data-encoding) | 2.15 GB/s (1.5x data-encoding) |  | 2.11 GB/s (1.4x data-encoding) | 2.11 GB/s (1.5x data-encoding) |
| Base64 MIME decode (76 columns, CRLF) | 0.97 GB/s (1.6x data-encoding) | 1.49 GB/s (1.7x data-encoding) |  | 1.52 GB/s (2.1x data-encoding) | 1.48 GB/s (1.8x data-encoding) |
| Base32 encode | 1.04 GB/s (1.2x fast32) | 1.56 GB/s (1.1x data-encoding) |  | 1.70 GB/s (1.2x data-encoding) | 1.62 GB/s (1.1x data-encoding) |
| Base32 decode | 0.88 GB/s (1.4x fast32) | 1.65 GB/s (1.3x data-encoding) |  | 1.80 GB/s (1.4x data-encoding) | 1.74 GB/s (1.4x data-encoding) |
| Quoted-printable encode, Latin text |  |  | 1.61 GB/s (4.3x quoted_printable) | 1.57 GB/s (4.4x quoted_printable) | 1.59 GB/s (4.2x quoted_printable) |
| Quoted-printable decode, Latin text |  |  | 1.73 GB/s (7.8x quoted_printable) | 1.75 GB/s (7.4x quoted_printable) | 1.75 GB/s (7.4x quoted_printable) |

## Portability

The minimum supported Rust version is 1.89. SIMD kernels are chosen at compile time on aarch64 (NEON) and at runtime on x86 and x86_64 (SSSE3 and AVX2, when SSE2 is part of the target baseline). Every other target, including 32-bit ARM (where NEON is not stable in Rust), RISC-V, PowerPC, s390x and `wasm32`, uses portable fallbacks that match or beat the fastest portable crates. Building with `RUSTFLAGS="--cfg encodify_scalar"` forces the fallbacks everywhere, and `--cfg encodify_no_avx2` limits x86 to the SSSE3 kernels; this is how both are tested and measured.

## Testing, Fuzzing & Benchmarking

To run the testsuite:

```bash
 $ cargo test
```

including the portable fallbacks and, on Apple Silicon, the x86 kernels under Rosetta:

```bash
 $ RUSTFLAGS="--cfg encodify_scalar" cargo test --target-dir target/scalar
 $ cargo test --target x86_64-apple-darwin
 $ ROSETTA_ADVERTISE_AVX=1 cargo test --target x86_64-apple-darwin
```

To fuzz the library with `cargo-fuzz`:

```bash
 $ cargo +nightly fuzz run encodify
```

including the portable fallbacks and, on Apple Silicon, the x86 kernels under Rosetta (without AddressSanitizer):

```bash
 $ RUSTFLAGS="--cfg encodify_scalar" cargo +nightly fuzz run --target-dir target/fuzz-scalar encodify
 $ ROSETTA_ADVERTISE_AVX=1 cargo fuzz run --target x86_64-apple-darwin --sanitizer none encodify
```

and, to run the benchmarks against other crates (Rust 1.93 or later, because of `base64-turbo`), with the SIMD kernels, the SSSE3 kernels and the portable fallbacks:

```bash
 $ cargo bench --bench codec
 $ RUSTFLAGS="--cfg encodify_no_avx2" CARGO_TARGET_DIR=target/ssse3 cargo bench --bench codec
 $ RUSTFLAGS="--cfg encodify_scalar" CARGO_TARGET_DIR=target/scalar cargo bench --bench codec
```

## Conformed RFCs

- [RFC 4648 - The Base16, Base32, and Base64 Data Encodings](https://datatracker.ietf.org/doc/html/rfc4648)
- [RFC 2045 - Multipurpose Internet Mail Extensions (MIME) Part One: Format of Internet Message Bodies](https://datatracker.ietf.org/doc/html/rfc2045)
- [RFC 2047 - MIME (Multipurpose Internet Mail Extensions) Part Three: Message Header Extensions for Non-ASCII Text](https://datatracker.ietf.org/doc/html/rfc2047)
- [RFC 2152 - UTF-7 - A Mail-Safe Transformation Format of Unicode](https://datatracker.ietf.org/doc/html/rfc2152)
- [RFC 2231 - MIME Parameter Value and Encoded Word Extensions](https://datatracker.ietf.org/doc/html/rfc2231)
- [RFC 3461 - SMTP Service Extension for Delivery Status Notifications (xtext)](https://datatracker.ietf.org/doc/html/rfc3461)
- [RFC 3501 - Internet Message Access Protocol - Version 4rev1 (Section 5.1.3)](https://datatracker.ietf.org/doc/html/rfc3501#section-5.1.3)
- [RFC 5545 - Internet Calendaring and Scheduling Core Object Specification (Section 3.1)](https://datatracker.ietf.org/doc/html/rfc5545#section-3.1)
- [RFC 6350 - vCard Format Specification (Section 3.2)](https://datatracker.ietf.org/doc/html/rfc6350#section-3.2)
- [RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures](https://datatracker.ietf.org/doc/html/rfc6376)
- [RFC 7468 - Textual Encodings of PKIX, PKCS, and CMS Structures](https://datatracker.ietf.org/doc/html/rfc7468)
- [RFC 9051 - Internet Message Access Protocol (IMAP) - Version 4rev2 (Appendix A.1)](https://datatracker.ietf.org/doc/html/rfc9051#appendix-A.1)

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt) or <https://www.apache.org/licenses/LICENSE-2.0>)
 * MIT license ([LICENSES/MIT.txt](LICENSES/MIT.txt) or <https://opensource.org/licenses/MIT>)

at your option.
