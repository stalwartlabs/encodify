/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */
#![doc = include_str!("../README.md")]

pub mod base32;
pub mod base64;
mod buffer;
mod error;
mod fold;
pub mod hex;
pub mod pem;
pub mod qp;
pub mod rfc2047;
pub mod utf7;

pub use buffer::Buffer;
pub use error::Error;
pub use fold::Fold;

#[cfg(test)]
mod test_rng;
