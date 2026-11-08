/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Picks x86 SIMD kernels at run time with `std`, else from compile-time target features.

/// Whether the AVX2 kernels may run.
#[inline]
pub(crate) fn avx2() -> bool {
    #[cfg(feature = "std")]
    let available = std::is_x86_feature_detected!("avx2");
    #[cfg(not(feature = "std"))]
    let available = cfg!(target_feature = "avx2");
    cfg!(not(encodify_no_avx2)) && available
}

/// Whether the SSSE3 kernels may run.
#[inline]
pub(crate) fn ssse3() -> bool {
    #[cfg(feature = "std")]
    let available = std::is_x86_feature_detected!("ssse3");
    #[cfg(not(feature = "std"))]
    let available = cfg!(target_feature = "ssse3");
    available
}
