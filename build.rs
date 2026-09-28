/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::env;

fn main() {
    for name in [
        "encodify_scalar",
        "encodify_no_avx2",
        "encodify_neon",
        "encodify_x86",
        "encodify_simd",
    ] {
        println!("cargo::rustc-check-cfg=cfg({name})");
    }
    println!("cargo::rerun-if-changed=build.rs");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let features = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let scalar = env::var_os("CARGO_CFG_encodify_SCALAR").is_some();
    let has = |wanted: &str| features.split(',').any(|feature| feature == wanted);
    let neon = !scalar && arch == "aarch64" && has("neon");
    let x86 = !scalar && matches!(arch.as_str(), "x86" | "x86_64") && has("sse2");
    for (enabled, name) in [
        (neon, "encodify_neon"),
        (x86, "encodify_x86"),
        (neon || x86, "encodify_simd"),
    ] {
        if enabled {
            println!("cargo::rustc-cfg={name}");
        }
    }
}
