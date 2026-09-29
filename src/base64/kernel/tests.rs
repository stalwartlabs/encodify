/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Break, LineShape};
use crate::{
    base64::{
        LineEnding, Wrap,
        alphabet::{self, Tables},
    },
    test_rng::{XorShift, lengths},
};
use std::mem::MaybeUninit;

type DecodeKernel = fn(&Tables, &[u8], &mut [MaybeUninit<u8>]) -> (usize, usize);
type LinesKernel = fn(&Tables, LineShape, &[u8], &mut [MaybeUninit<u8>]) -> (usize, usize);
type EncodeKernel = fn(&Tables, &[u8], &mut [MaybeUninit<u8>]) -> (usize, usize);
type EncodeLinesKernel = fn(&Tables, Wrap, &[u8], &mut [MaybeUninit<u8>]) -> (usize, usize);

const GUARD: u8 = 0xa5;

fn decode_kernels() -> Vec<(&'static str, DecodeKernel)> {
    #[cfg_attr(not(encodify_simd), allow(unused_mut))]
    let mut kernels: Vec<(&'static str, DecodeKernel)> = vec![
        ("scalar", Tables::decode_quads_scalar),
        ("dispatch", Tables::decode_quads),
    ];
    #[cfg(encodify_neon)]
    kernels.push(("neon", |t, s, d| {
        t.decode_quads_neon(s, d).unwrap_or((0, 0))
    }));
    #[cfg(encodify_x86)]
    {
        if std::is_x86_feature_detected!("ssse3") {
            // SAFETY: SSSE3 was detected at runtime just above; the kernel only takes slices.
            kernels.push(("ssse3", |t, s, d| unsafe {
                t.nibbles
                    .as_ref()
                    .and_then(|nibbles| nibbles.decode_quads_ssse3(s, d))
                    .unwrap_or((0, 0))
            }));
        }
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 was detected at runtime just above; the kernel only takes slices.
            kernels.push(("avx2", |t, s, d| unsafe {
                t.nibbles
                    .as_ref()
                    .and_then(|nibbles| nibbles.decode_quads_avx2(s, d))
                    .unwrap_or((0, 0))
            }));
        }
    }
    kernels
}

#[allow(clippy::vec_init_then_push)]
fn lines_kernels() -> Vec<(&'static str, LinesKernel)> {
    #[cfg_attr(not(encodify_simd), allow(unused_mut))]
    let mut kernels: Vec<(&'static str, LinesKernel)> = Vec::new();
    #[cfg(encodify_neon)]
    kernels.push(("neon", Tables::decode_lines_neon));
    #[cfg(encodify_x86)]
    {
        if std::is_x86_feature_detected!("ssse3") {
            // SAFETY: SSSE3 was detected at runtime just above; the kernel only takes slices.
            kernels.push(("ssse3", |t, shape, s, d| unsafe {
                t.nibbles
                    .as_ref()
                    .map_or((0, 0), |nibbles| nibbles.decode_lines_ssse3(shape, s, d))
            }));
        }
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 was detected at runtime just above; the kernel only takes slices.
            kernels.push(("avx2", |t, shape, s, d| unsafe {
                t.nibbles
                    .as_ref()
                    .map_or((0, 0), |nibbles| nibbles.decode_lines_avx2(shape, s, d))
            }));
        }
    }
    kernels
}

fn encode_kernels() -> Vec<(&'static str, EncodeKernel)> {
    #[cfg_attr(not(encodify_simd), allow(unused_mut))]
    let mut kernels: Vec<(&'static str, EncodeKernel)> = vec![
        ("scalar", Tables::encode_groups_scalar),
        ("dispatch", Tables::encode_groups),
    ];
    #[cfg(encodify_neon)]
    kernels.push(("neon", Tables::encode_groups_neon));
    #[cfg(encodify_x86)]
    {
        if std::is_x86_feature_detected!("ssse3") {
            // SAFETY: SSSE3 was detected at runtime just above; the kernel only takes slices.
            kernels.push(("ssse3", |t, s, d| unsafe { t.encode_groups_ssse3(s, d) }));
        }
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 was detected at runtime just above; the kernel only takes slices.
            kernels.push(("avx2", |t, s, d| unsafe { t.encode_groups_avx2(s, d) }));
        }
    }
    kernels
}

#[allow(clippy::vec_init_then_push)]
fn encode_lines_kernels() -> Vec<(&'static str, EncodeLinesKernel)> {
    #[cfg_attr(not(encodify_simd), allow(unused_mut))]
    let mut kernels: Vec<(&'static str, EncodeLinesKernel)> = Vec::new();
    #[cfg(encodify_neon)]
    kernels.push(("neon", Tables::encode_lines_neon));
    #[cfg(encodify_x86)]
    {
        if std::is_x86_feature_detected!("ssse3") {
            // SAFETY: SSSE3 was detected at runtime just above; the kernel only takes slices.
            kernels.push(("ssse3", |t, w, s, d| unsafe {
                t.encode_lines_ssse3(w, s, d)
            }));
        }
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 was detected at runtime just above; the kernel only takes slices.
            kernels.push(("avx2", |t, w, s, d| unsafe { t.encode_lines_avx2(w, s, d) }));
        }
    }
    kernels
}

fn run(
    capacity: usize,
    kernel: impl FnOnce(&mut [MaybeUninit<u8>]) -> (usize, usize),
) -> ((usize, usize), Vec<u8>) {
    let mut buffer = vec![MaybeUninit::new(GUARD); capacity + 64];
    let (region, guard) = buffer.split_at_mut(capacity);
    let result = kernel(region);
    assert!(
        guard
            .iter()
            // SAFETY: the whole buffer was created as `MaybeUninit::new(GUARD)`.
            .all(|byte| unsafe { byte.assume_init() } == GUARD),
        "kernel wrote past the end of its output"
    );
    let bytes = region
        .iter()
        .take(result.1)
        // SAFETY: the whole buffer was created as `MaybeUninit::new(GUARD)` and
        // kernels only store initialised bytes into it.
        .map(|byte| unsafe { byte.assume_init() })
        .collect();
    (result, bytes)
}

const ALL_TABLES: [&Tables; 4] = [
    &alphabet::STANDARD,
    &alphabet::URL_SAFE,
    &alphabet::IMAP,
    &alphabet::ANY,
];

#[test]
fn decode_kernels_agree_with_scalar() {
    let mut rng = XorShift::new(21);
    for tables in ALL_TABLES {
        for len in lengths(300).chain([511, 512, 513, 4096, 4099]) {
            let text: Vec<u8> = (0..len).map(|_| *rng.pick(&tables.encode)).collect();
            for room in [len / 4 * 3, len / 4 * 3 + 7, len] {
                let (expected, expected_bytes) =
                    run(room, |dst| tables.decode_quads_scalar(&text, dst));
                for (name, kernel) in decode_kernels() {
                    let ((read, written), bytes) = run(room, |dst| kernel(tables, &text, dst));
                    assert_eq!(read % 4, 0, "{name} {len}");
                    assert_eq!(written, read / 4 * 3, "{name} {len}");
                    assert!(read <= expected.0, "{name} {len}");
                    assert_eq!(bytes, expected_bytes[..written], "{name} {len}");
                    if name == "dispatch" {
                        assert_eq!((read, written), expected, "{name} {len} {room}");
                    }
                }
            }
        }
    }
}

#[test]
fn decode_kernels_stop_at_the_first_invalid_quad() {
    let mut rng = XorShift::new(22);
    for tables in ALL_TABLES {
        let text: Vec<u8> = (0..160).map(|_| *rng.pick(&tables.encode)).collect();
        for position in 0..text.len() {
            for bad in [b'=', b'\r', b'\n', b' ', 0x00, 0x80, 0xff, b'*', b'.', b'~'] {
                if tables.decode[bad as usize] != alphabet::INVALID {
                    continue;
                }
                let mut input = text.clone();
                input[position] = bad;
                let stop = position / 4 * 4;
                for (name, kernel) in decode_kernels() {
                    let ((read, written), bytes) =
                        run(input.len(), |dst| kernel(tables, &input, dst));
                    assert!(read <= stop, "{name} {position} {bad}");
                    if name == "dispatch" || name == "scalar" {
                        assert_eq!(read, stop, "{name} {position} {bad}");
                    }
                    let (_, expected) =
                        run(input.len(), |dst| tables.decode_quads_scalar(&input, dst));
                    assert_eq!(bytes, expected[..written], "{name} {position} {bad}");
                }
            }
        }
    }
}

#[test]
fn line_kernels_decode_whole_lines_only() {
    let mut rng = XorShift::new(23);
    for tables in ALL_TABLES {
        for (len, ending) in [
            (76, &b"\r\n"[..]),
            (76, b"\n"),
            (64, b"\n"),
            (72, b"\r\n"),
            (60, b"\n"),
            (32, b"\r\n"),
            (16, b"\n"),
            (132, b"\r\n"),
            (74, b"\r\n "),
            (74, b"\n\t"),
            (75, b"\r\n "),
            (58, b"\r\n"),
            (17, b"\n "),
        ] {
            let shape = LineShape {
                len,
                ending: Break::at_start(ending, ending.ends_with(b" ") || ending.ends_with(b"\t"))
                    .expect("valid break"),
            };
            for lines in [1, 2, 5, 17] {
                let mut input = Vec::new();
                let mut bodies = Vec::new();
                for _ in 0..lines {
                    let line: Vec<u8> = (0..len).map(|_| *rng.pick(&tables.encode)).collect();
                    bodies.extend_from_slice(&line);
                    input.extend_from_slice(&line);
                    input.extend_from_slice(ending);
                }
                let mut decoded = vec![MaybeUninit::uninit(); bodies.len()];
                let (_, total) = tables.decode_quads_scalar(&bodies, &mut decoded);
                let expected: Vec<u8> = decoded
                    .iter()
                    .take(total)
                    // SAFETY: the scalar kernel initialised the first `total` bytes it
                    // reported as written.
                    .map(|byte| unsafe { byte.assume_init() })
                    .collect();
                let tail_len = rng.below(len);
                input.extend((0..tail_len).map(|_| *rng.pick(&tables.encode)));
                for (name, kernel) in lines_kernels() {
                    let ((read, written), bytes) = run(expected.len() + 64, |dst| {
                        kernel(tables, shape, &input, dst)
                    });
                    let symbols = input
                        .iter()
                        .take(read)
                        .filter(|&&byte| tables.decode[byte as usize] != alphabet::INVALID)
                        .count();
                    assert_eq!(symbols % 4, 0, "{name} {len} {lines}");
                    assert_eq!(written, symbols / 4 * 3, "{name} {len} {lines}");
                    assert_eq!(bytes, expected[..written], "{name} {len} {lines}");
                    if len >= 32 && len % 4 == 0 && (name == "neon" || tables.nibbles.is_some()) {
                        assert_eq!(written, lines * len / 4 * 3, "{name} {len} {lines}");
                    }
                    if name == "neon" {
                        assert_eq!(written, lines * len / 4 * 3, "{name} {len} {lines}");
                    }
                }
                for start in [1, 2, 3, len / 2, len - 1] {
                    let mut decoded = vec![MaybeUninit::uninit(); bodies.len()];
                    let (_, total) = tables
                        .decode_quads_scalar(bodies.get(start..).unwrap_or_default(), &mut decoded);
                    let expected: Vec<u8> = decoded
                        .iter()
                        .take(total)
                        // SAFETY: the scalar kernel initialised the first `total` bytes
                        // it reported as written.
                        .map(|byte| unsafe { byte.assume_init() })
                        .collect();
                    let input = input.get(start..).unwrap_or_default();
                    for (name, kernel) in lines_kernels() {
                        let ((read, written), bytes) =
                            run(expected.len() + 64, |dst| kernel(tables, shape, input, dst));
                        let symbols = input
                            .iter()
                            .take(read)
                            .filter(|&&byte| tables.decode[byte as usize] != alphabet::INVALID)
                            .count();
                        assert_eq!(written, symbols / 4 * 3, "{name} {len} {lines} {start}");
                        assert_eq!(bytes, expected[..written], "{name} {len} {lines} {start}");
                        if name == "neon" && lines * len - start >= 16 {
                            assert_eq!(
                                written,
                                (lines * len - start) / 4 * 3,
                                "{name} {len} {lines} {start}"
                            );
                        }
                    }
                }
                let bad = shape.stride() + len / 2;
                let mut broken = input.clone();
                if let Some(byte) = broken.get_mut(bad) {
                    *byte = b'*';
                }
                for (name, kernel) in lines_kernels() {
                    let ((read, written), bytes) = run(expected.len() + 64, |dst| {
                        kernel(tables, shape, &broken, dst)
                    });
                    let symbols = broken
                        .iter()
                        .take(read)
                        .filter(|&&byte| tables.decode[byte as usize] != alphabet::INVALID)
                        .count();
                    assert!(read <= bad, "{name} {len} {lines}");
                    assert_eq!(written, symbols / 4 * 3, "{name} {len} {lines}");
                    assert_eq!(bytes, expected[..written], "{name} {len} {lines}");
                }
            }
        }
    }
}

#[test]
fn encode_kernels_agree_with_scalar() {
    let mut rng = XorShift::new(24);
    for tables in ALL_TABLES {
        for len in lengths(300).chain([511, 512, 513, 4096, 4099]) {
            let input = rng.bytes(len);
            for room in [len / 3 * 4, len / 3 * 4 + 5, len * 2] {
                let (expected, expected_bytes) =
                    run(room, |dst| tables.encode_groups_scalar(&input, dst));
                for (name, kernel) in encode_kernels() {
                    let ((read, written), bytes) = run(room, |dst| kernel(tables, &input, dst));
                    assert_eq!(read % 3, 0, "{name} {len}");
                    assert_eq!(written, read / 3 * 4, "{name} {len}");
                    assert!(read <= expected.0, "{name} {len}");
                    assert_eq!(bytes, expected_bytes[..written], "{name} {len}");
                    if name == "dispatch" {
                        assert_eq!((read, written), expected, "{name} {len} {room}");
                    }
                }
            }
        }
    }
}

#[test]
fn encode_line_kernels_match_the_reference() {
    let mut rng = XorShift::new(25);
    for tables in ALL_TABLES {
        for (width, ending) in [
            (76, LineEnding::CrLf),
            (64, LineEnding::Lf),
            (72, LineEnding::CrLf),
            (32, LineEnding::Lf),
            (16, LineEnding::Lf),
        ] {
            let wrap = Wrap { width, ending };
            let line_in = wrap.line_in();
            for lines in [0, 1, 2, 7] {
                let extra = rng.below(line_in);
                let input = rng.bytes(line_in * lines + extra);
                let mut expected = Vec::new();
                for line in input.chunks_exact(line_in) {
                    let mut encoded = vec![MaybeUninit::uninit(); width];
                    let (_, written) = tables.encode_groups_scalar(line, &mut encoded);
                    expected.extend(
                        encoded
                            .iter()
                            .take(written)
                            // SAFETY: the scalar kernel initialised the first
                            // `written` bytes it reported.
                            .map(|byte| unsafe { byte.assume_init() }),
                    );
                    expected.extend_from_slice(ending.as_bytes());
                }
                for (name, kernel) in encode_lines_kernels() {
                    let ((read, written), bytes) =
                        run(expected.len(), |dst| kernel(tables, wrap, &input, dst));
                    assert_eq!(read % line_in, 0, "{name} {width} {lines}");
                    let done = read / line_in;
                    assert_eq!(written, done * (width + ending.len()), "{name} {width}");
                    assert_eq!(bytes, expected[..written], "{name} {width} {lines}");
                }
            }
        }
    }
}
