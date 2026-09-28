/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

use base64::Engine as _;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
    measurement::WallTime,
};
use std::{fmt::Display, hint::black_box};

const SIZES: [usize; 4] = [32, 1024, 64 * 1024, 1024 * 1024];
const SEED: u64 = 0x9e37_79b9_7f4a_7c15;
const IDS: usize = 1024;

fast32::make_base32_alpha!(
    FAST32_STALWART,
    FAST32_STALWART_DECODE,
    b"abcdefghijklmnopqrstuvwxyz792013"
);

fn sample(len: usize) -> Vec<u8> {
    let mut state = SEED;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn ids() -> Vec<u64> {
    let mut state = SEED;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    (0..IDS)
        .map(|_| {
            let bits = (next() % 65) as u32;
            next().checked_shr(u64::BITS - bits).unwrap_or(0)
        })
        .collect()
}

fn wrap(encoded: &str, width: usize) -> Vec<u8> {
    encoded
        .as_bytes()
        .chunks(width)
        .flat_map(|line| line.iter().copied().chain(*b"\r\n"))
        .collect()
}

fn bench<I: ?Sized, P: Display>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    parameter: P,
    input: &I,
    mut f: impl FnMut(&I),
) {
    group.bench_with_input(BenchmarkId::new(name, parameter), input, |b, input| {
        b.iter(|| f(black_box(input)))
    });
}

fn base64_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("base64_encode");
    for len in SIZES {
        let input = sample(len);
        let mut out = vec![0u8; len * 2 + 64];
        group.throughput(Throughput::Bytes(len as u64));
        bench(&mut group, "encodify", len, &input[..], |input| {
            black_box(encodify::base64::STANDARD.encode_slice(input, &mut out)).ok();
        });
        bench(&mut group, "base64", len, &input[..], |input| {
            black_box(base64::engine::general_purpose::STANDARD.encode_slice(input, &mut out)).ok();
        });
        bench(&mut group, "base64-simd", len, &input[..], |input| {
            black_box(base64_simd::STANDARD.encode(input, base64_simd::Out::from_slice(&mut out)));
        });
        bench(&mut group, "base64-turbo", len, &input[..], |input| {
            black_box(base64_turbo::STANDARD.encode_slice(input, &mut out)).ok();
        });
        bench(&mut group, "data-encoding", len, &input[..], |input| {
            let encoded = data_encoding::BASE64.encode_len(input.len());
            data_encoding::BASE64.encode_mut(input, &mut out[..encoded]);
            black_box(&out);
        });
        bench(&mut group, "simdutf", len, &input[..], |input| {
            // SAFETY: `input` and `out` are separate non-empty buffers, and `out` holds
            // `len * 2 + 64` bytes, more than the `len.div_ceil(3) * 4` written.
            black_box(unsafe {
                simdutf::binary_to_base64(
                    input.as_ptr(),
                    input.len(),
                    out.as_mut_ptr(),
                    simdutf::Base64Options::Default,
                )
            });
        });
    }
    group.finish();
}

fn base64_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("base64_decode");
    for len in SIZES {
        let encoded = encodify::base64::STANDARD.encode(sample(len));
        let input = encoded.as_bytes();
        let mut out = vec![0u8; len + 64];
        group.throughput(Throughput::Bytes(len as u64));
        bench(&mut group, "encodify", len, input, |input| {
            black_box(encodify::base64::STANDARD.decode_slice(input, &mut out)).ok();
        });
        bench(&mut group, "base64", len, input, |input| {
            black_box(base64::engine::general_purpose::STANDARD.decode_slice(input, &mut out)).ok();
        });
        bench(&mut group, "base64-simd", len, input, |input| {
            black_box(base64_simd::STANDARD.decode(input, base64_simd::Out::from_slice(&mut out)))
                .ok();
        });
        bench(&mut group, "base64-turbo", len, input, |input| {
            black_box(base64_turbo::STANDARD.decode_slice(input, &mut out)).ok();
        });
        bench(&mut group, "data-encoding", len, input, |input| {
            if let Ok(decoded) = data_encoding::BASE64.decode_len(input.len()) {
                black_box(data_encoding::BASE64.decode_mut(input, &mut out[..decoded])).ok();
            }
        });
        bench(&mut group, "simdutf", len, input, |input| {
            // SAFETY: `input` and `out` are separate non-empty buffers, and `out` holds
            // `len + 64` bytes, more than the `len` bytes `input` can decode to.
            black_box(unsafe {
                simdutf::base64_to_binary(
                    input.as_ptr(),
                    input.len(),
                    out.as_mut_ptr(),
                    simdutf::Base64Options::Default,
                    simdutf::LastChunkHandlingOptions::Strict,
                )
            });
        });
    }
    group.finish();
}

fn base64_mime_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("base64_mime_encode");
    for len in SIZES {
        let input = sample(len);
        let mut out = vec![0u8; len * 2 + 64];
        group.throughput(Throughput::Bytes(len as u64));
        bench(&mut group, "encodify", len, &input[..], |input| {
            black_box(encodify::base64::MIME.encode_slice(input, &mut out)).ok();
        });
        bench(&mut group, "data-encoding", len, &input[..], |input| {
            let encoded = data_encoding::BASE64_MIME.encode_len(input.len());
            data_encoding::BASE64_MIME.encode_mut(input, &mut out[..encoded]);
            black_box(&out);
        });
        bench(&mut group, "simdutf (LF only)", len, &input[..], |input| {
            // SAFETY: `input` and `out` are separate non-empty buffers, and `out` holds
            // `len * 2 + 64` bytes, more than the symbols plus one LF per 76 of them.
            black_box(unsafe {
                simdutf::binary_to_base64_with_lines(
                    input.as_ptr(),
                    input.len(),
                    out.as_mut_ptr(),
                    76,
                    simdutf::Base64Options::Default,
                )
            });
        });
    }
    group.finish();
}

fn base64_mime_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("base64_mime_decode");
    for len in SIZES {
        let wrapped = wrap(&encodify::base64::STANDARD.encode(sample(len)), 76);
        let mut out = vec![0u8; wrapped.len()];
        let mut scratch = Vec::with_capacity(wrapped.len());
        group.throughput(Throughput::Bytes(len as u64));
        bench(&mut group, "encodify", len, &wrapped[..], |input| {
            black_box(encodify::base64::MIME.decode_slice(input, &mut out)).ok();
        });
        bench(&mut group, "data-encoding", len, &wrapped[..], |input| {
            if let Ok(decoded) = data_encoding::BASE64_MIME.decode_len(input.len()) {
                black_box(data_encoding::BASE64_MIME.decode_mut(input, &mut out[..decoded])).ok();
            }
        });
        bench(
            &mut group,
            "base64-simd (forgiving)",
            len,
            &wrapped[..],
            |input| {
                black_box(base64_simd::forgiving_decode(
                    input,
                    base64_simd::Out::from_slice(&mut out),
                ))
                .ok();
            },
        );
        bench(&mut group, "simdutf", len, &wrapped[..], |input| {
            // SAFETY: `input` and `out` are separate non-empty buffers, and `out` is as
            // long as `input`, which decodes to at most three quarters of that.
            black_box(unsafe {
                simdutf::base64_to_binary(
                    input.as_ptr(),
                    input.len(),
                    out.as_mut_ptr(),
                    simdutf::Base64Options::Default,
                    simdutf::LastChunkHandlingOptions::Loose,
                )
            });
        });
        bench(
            &mut group,
            "base64 (strip + decode)",
            len,
            &wrapped[..],
            |input| {
                scratch.clear();
                scratch.extend(
                    input
                        .iter()
                        .copied()
                        .filter(|byte| !byte.is_ascii_whitespace()),
                );
                black_box(
                    base64::engine::general_purpose::STANDARD.decode_slice(&scratch, &mut out),
                )
                .ok();
            },
        );
    }
    group.finish();
}

fn base32_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("base32_encode");
    for len in SIZES {
        let input = sample(len);
        let mut out = vec![0u8; len * 2 + 64];
        let mut vec_out = Vec::with_capacity(len * 2 + 64);
        group.throughput(Throughput::Bytes(len as u64));
        bench(&mut group, "encodify", len, &input[..], |input| {
            black_box(encodify::base32::STANDARD.encode_slice(input, &mut out)).ok();
        });
        bench(&mut group, "data-encoding", len, &input[..], |input| {
            let encoded = data_encoding::BASE32.encode_len(input.len());
            data_encoding::BASE32.encode_mut(input, &mut out[..encoded]);
            black_box(&out);
        });
        bench(&mut group, "fast32", len, &input[..], |input| {
            vec_out.clear();
            fast32::base32::RFC4648.encode_into(input, &mut vec_out);
            black_box(&vec_out);
        });
        bench(&mut group, "base32 (allocates)", len, &input[..], |input| {
            black_box(base32::encode(
                base32::Alphabet::Rfc4648 { padding: true },
                input,
            ));
        });
    }
    group.finish();
}

fn base32_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("base32_decode");
    for len in SIZES {
        let encoded = encodify::base32::STANDARD.encode(sample(len));
        let input = encoded.as_bytes();
        let mut out = vec![0u8; len + 64];
        let mut vec_out = Vec::with_capacity(len + 64);
        group.throughput(Throughput::Bytes(len as u64));
        bench(&mut group, "encodify", len, input, |input| {
            black_box(encodify::base32::STANDARD.decode_slice(input, &mut out)).ok();
        });
        bench(&mut group, "data-encoding", len, input, |input| {
            if let Ok(decoded) = data_encoding::BASE32.decode_len(input.len()) {
                black_box(data_encoding::BASE32.decode_mut(input, &mut out[..decoded])).ok();
            }
        });
        bench(&mut group, "fast32", len, input, |input| {
            vec_out.clear();
            black_box(fast32::base32::RFC4648.decode_into(input, &mut vec_out)).ok();
        });
        bench(
            &mut group,
            "base32 (allocates)",
            len,
            &encoded[..],
            |input| {
                black_box(base32::decode(
                    base32::Alphabet::Rfc4648 { padding: true },
                    input,
                ));
            },
        );
    }
    group.finish();
}

fn base32_u64(c: &mut Criterion) {
    let mut group = c.benchmark_group("base32_u64");
    let ids = ids();
    let texts: Vec<String> = ids
        .iter()
        .map(|&id| encodify::base32::STALWART.encode_u64(id).to_string())
        .collect();
    let mut out = Vec::with_capacity(IDS * 16);
    group.throughput(Throughput::Elements(IDS as u64));
    bench(&mut group, "encodify", "encode", &ids[..], |ids| {
        ids.iter().for_each(|&id| {
            black_box(encodify::base32::STALWART.encode_u64(black_box(id)));
        });
    });
    bench(
        &mut group,
        "fast32 (allocates)",
        "encode",
        &ids[..],
        |ids| {
            ids.iter().for_each(|&id| {
                black_box(FAST32_STALWART.encode_u64(black_box(id)));
            });
        },
    );
    bench(&mut group, "encodify", "append", &ids[..], |ids| {
        out.clear();
        ids.iter().for_each(|&id| {
            encodify::base32::STALWART.encode_u64_append(black_box(id), &mut out);
        });
        black_box(&out);
    });
    bench(&mut group, "fast32", "append", &ids[..], |ids| {
        out.clear();
        ids.iter().for_each(|&id| {
            FAST32_STALWART.encode_u64_into(black_box(id), &mut out);
        });
        black_box(&out);
    });
    bench(&mut group, "encodify", "decode", &texts[..], |texts| {
        texts.iter().for_each(|text| {
            black_box(encodify::base32::STALWART.decode_u64(black_box(text))).ok();
        });
    });
    bench(&mut group, "fast32", "decode", &texts[..], |texts| {
        texts.iter().for_each(|text| {
            black_box(FAST32_STALWART.decode_u64(black_box(text.as_bytes()))).ok();
        });
    });
    group.finish();
}

fn text(kind: &str, len: usize) -> Vec<u8> {
    let sentence: &str = match kind {
        "latin" => {
            "Please find attached the quarterly report for the München office, as discussed \
             last week. Let me know if the figures for Zürich need another review before \
             Friday. "
        }
        _ => "Привет, как дела? Это тестовое письмо с длинной темой. ",
    };
    sentence
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(len)
        .collect()
}

fn qp_encode(c: &mut Criterion) {
    for kind in ["latin", "dense"] {
        let mut group = c.benchmark_group(format!("qp_encode_{kind}"));
        for len in [4096, 64 * 1024, 1024 * 1024] {
            let input = text(kind, len);
            group.throughput(Throughput::Bytes(len as u64));
            bench(&mut group, "encodify", len, &input[..], |input| {
                black_box(encodify::qp::BODY.encode(input));
            });
            bench(&mut group, "quoted_printable", len, &input[..], |input| {
                black_box(quoted_printable::encode(input));
            });
        }
        group.finish();
    }
}

fn qp_decode(c: &mut Criterion) {
    for kind in ["latin", "dense"] {
        let mut group = c.benchmark_group(format!("qp_decode_{kind}"));
        for len in [4096, 64 * 1024, 1024 * 1024] {
            let encoded = encodify::qp::BODY.encode(text(kind, len));
            let input = encoded.as_bytes();
            group.throughput(Throughput::Bytes(len as u64));
            bench(&mut group, "encodify", len, input, |input| {
                black_box(encodify::qp::BODY.decode(input)).ok();
            });
            bench(&mut group, "quoted_printable", len, input, |input| {
                black_box(quoted_printable::decode(
                    input,
                    quoted_printable::ParseMode::Robust,
                ))
                .ok();
            });
        }
        group.finish();
    }
}

criterion_group!(
    benches,
    base64_encode,
    base64_decode,
    base64_mime_encode,
    base64_mime_decode,
    base32_encode,
    base32_decode,
    base32_u64,
    qp_encode,
    qp_decode
);
criterion_main!(benches);
