/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

mod decode;
mod encode;
mod prefix;
pub(crate) mod reference;
mod scan;
mod words;

use super::kernel::{Job, Kernel, scalar::Swar};
use crate::{Error, test_rng::XorShift};
use reference::Failure;

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidByte { offset, byte } => Failure::InvalidByte { offset, byte },
            Error::Truncated { offset } => Failure::Truncated { offset },
            other => panic!("unexpected error {other:?}"),
        }
    }
}

pub(super) trait Shown {
    fn shown(&self) -> String;
}

impl Shown for [u8] {
    fn shown(&self) -> String {
        format!("{:?}", String::from_utf8_lossy(self))
    }
}

pub(super) trait Check: Sized {
    fn check<K: Kernel>(&self, kernel: &'static str);

    fn every_kernel(&self) {
        CheckJob(self, "swar").run::<Swar>();
        #[cfg(encodify_neon)]
        CheckJob(self, "neon").run::<super::kernel::neon::Neon>();
        #[cfg(encodify_x86)]
        {
            CheckJob(self, "sse2").run::<super::kernel::x86::Sse2>();
            if std::is_x86_feature_detected!("avx2") {
                // SAFETY: AVX2 was detected at runtime just above.
                unsafe { super::kernel::x86::Avx2::run(CheckJob(self, "avx2")) };
            }
        }
    }
}

struct CheckJob<'x, C: Check>(&'x C, &'static str);

impl<C: Check> Job for CheckJob<'_, C> {
    type Output = ();

    fn run<K: Kernel>(self) {
        self.0.check::<K>(self.1)
    }
}

const LETTERS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,;:!?-_()<>@/'\"";
const HEX_DIGITS: &[u8] = b"0123456789ABCDEFabcdef";

pub(super) trait Inputs {
    fn lengths(&mut self, round: usize) -> usize;

    fn run_of(&mut self, out: &mut Vec<u8>, alphabet: &[u8], len: usize);

    fn qp_input(&mut self, len: usize) -> Vec<u8>;

    fn raw_input(&mut self, len: usize) -> Vec<u8>;
}

impl Inputs for XorShift {
    fn lengths(&mut self, round: usize) -> usize {
        match round % 8 {
            0 => self.below(400),
            1 => 12 + self.below(40),
            2 => 60 + self.below(40),
            _ => self.below(24),
        }
    }

    fn run_of(&mut self, out: &mut Vec<u8>, alphabet: &[u8], len: usize) {
        for _ in 0..len {
            out.push(*self.pick(alphabet));
        }
    }

    fn qp_input(&mut self, len: usize) -> Vec<u8> {
        const PIECES: &[&[u8]] = &[
            b"=\r\n", b"=\n", b"= \r\n", b"=\t \n", b"=", b"\r\n", b"\n", b"\r", b" ", b"\t",
            b"  \r\n", b" \t\n", b"=G", b"==", b"=4", b"=4G", b"=\r", b"= x", b"=\r=", b" \r\r\n",
            b"=20", b"=09", b"=3D", b"=3d", b"_", b"?=", b"?",
        ];
        let dense = self.below(4) == 0;
        let mut out = Vec::with_capacity(len + 64);
        while out.len() < len {
            match self.below(if dense { 8 } else { 24 }) {
                0 => {
                    let piece = self.pick(PIECES);
                    out.extend_from_slice(piece);
                }
                1 => {
                    out.push(b'=');
                    self.run_of(&mut out, HEX_DIGITS, 2);
                }
                2 => {
                    for _ in 0..self.below(40) {
                        out.push(b'=');
                        self.run_of(&mut out, HEX_DIGITS, 2);
                    }
                }
                3 => out.push(self.next() as u8),
                4 => {
                    let run = self.below(100);
                    self.run_of(&mut out, LETTERS, run);
                }
                _ => out.push(*self.pick(LETTERS)),
            }
        }
        out
    }

    fn raw_input(&mut self, len: usize) -> Vec<u8> {
        const PIECES: &[&[u8]] = &[
            b"\r\n",
            b"\n",
            b"\r",
            b" ",
            b"\t",
            b" \r\n",
            b"\t\n",
            b"  ",
            b"=",
            b"\x00",
            b"\x1b",
            b"\x7f",
            b"\xc3\xa9",
            b"\xe4\xbc\x9a",
            b"\xff",
            b" \r",
            b"\r\r\n",
            b"?",
            b"_",
            b";",
        ];
        let dense = self.below(4) == 0;
        let mut out = Vec::with_capacity(len + 64);
        while out.len() < len {
            match self.below(if dense { 6 } else { 20 }) {
                0 => {
                    let piece = self.pick(PIECES);
                    out.extend_from_slice(piece);
                }
                1 => {
                    for _ in 0..self.below(40) {
                        out.push(0x80 | self.next() as u8);
                    }
                }
                2 => out.push(self.next() as u8),
                3 => {
                    let run = 60 + self.below(120);
                    self.run_of(&mut out, LETTERS, run);
                }
                4 => {
                    let run = self.below(8);
                    self.run_of(&mut out, b" \t", run);
                }
                _ => out.push(*self.pick(LETTERS)),
            }
        }
        if self.below(8) == 0 {
            out.push(*self.pick(b" \t"));
        }
        out
    }
}

#[test]
fn every_kernel_runs() {
    struct Names(std::cell::RefCell<Vec<&'static str>>);
    impl Check for Names {
        fn check<K: Kernel>(&self, kernel: &'static str) {
            self.0.borrow_mut().push(kernel);
        }
    }
    let names = Names(Default::default());
    names.every_kernel();
    let names = names.0.into_inner();
    assert!(names.contains(&"swar"));
    #[cfg(encodify_neon)]
    assert!(names.contains(&"neon"));
    #[cfg(encodify_x86)]
    {
        assert!(names.contains(&"sse2"));
        assert_eq!(
            names.contains(&"avx2"),
            std::is_x86_feature_detected!("avx2")
        );
    }
}
