/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{
    Error,
    base64::{
        alphabet::{INVALID, Tables},
        kernel::{Break, LineShape},
    },
};
use std::mem::MaybeUninit;

pub(super) enum Halt {
    End,
    Byte(u8),
    Full,
}

pub(super) struct Feed {
    pub(super) read: usize,
    pub(super) written: usize,
    pub(super) halt: Halt,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Quantum {
    word: u32,
    pending: u8,
}

impl Quantum {
    #[inline(always)]
    pub(super) fn is_empty(&self) -> bool {
        self.pending == 0
    }

    #[inline(always)]
    pub(super) fn is_full(&self) -> bool {
        self.pending == 3
    }

    #[inline(always)]
    pub(super) fn push(&mut self, value: u8, dst: &mut [MaybeUninit<u8>], at: usize) -> usize {
        self.word = (self.word << 6) | value as u32;
        self.pending += 1;
        if self.pending < 4 {
            return 0;
        }
        debug_assert!(at + 3 <= dst.len());
        let [_, first, second, third] = self.word.to_be_bytes();
        if let Some([a, b, c]) = dst.get_mut(at..at + 3) {
            a.write(first);
            b.write(second);
            c.write(third);
        }
        self.word = 0;
        self.pending = 0;
        3
    }

    pub(super) fn flush(&mut self, dst: &mut [MaybeUninit<u8>]) -> usize {
        debug_assert!(self.flushed_len() <= dst.len());
        let written = match self.pending {
            2 => {
                if let Some(slot) = dst.first_mut() {
                    slot.write((self.word >> 4) as u8);
                }
                1
            }
            3 => {
                if let Some([first, second]) = dst.first_chunk_mut::<2>() {
                    first.write((self.word >> 10) as u8);
                    second.write((self.word >> 2) as u8);
                }
                2
            }
            _ => 0,
        };
        self.word = 0;
        self.pending = 0;
        written
    }

    pub(super) fn flushed_len(&self) -> usize {
        self.pending.saturating_sub(1) as usize
    }
}

#[derive(Default, Clone, Copy)]
pub(super) struct Lenient {
    quantum: Quantum,
    shape: Option<Option<LineShape>>,
    folded: bool,
}

impl Lenient {
    pub(super) fn with_shape(shape: Option<LineShape>) -> Self {
        Lenient {
            quantum: Quantum::default(),
            shape: Some(shape),
            folded: false,
        }
    }

    pub(super) fn folded(shape: Option<LineShape>) -> Self {
        Lenient {
            quantum: Quantum::default(),
            shape: Some(shape),
            folded: true,
        }
    }

    #[inline(always)]
    pub(super) const fn is_space(byte: u8) -> bool {
        matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c)
    }

    pub(super) fn feed(
        &mut self,
        tables: &Tables,
        src: &[u8],
        dst: &mut [MaybeUninit<u8>],
    ) -> Feed {
        let mut read = 0;
        let mut written = 0;
        let mut mid_line = false;
        let shape = *self.shape.get_or_insert_with(|| LineShape::detect(src));
        loop {
            if self.quantum.is_empty() {
                let (done, out) = tables.decode_lines(
                    shape,
                    self.folded,
                    mid_line,
                    src.get(read..).unwrap_or_default(),
                    dst.get_mut(written..).unwrap_or_default(),
                );
                read += done;
                written += out;
                mid_line = true;
            }
            let Some(&byte) = src.get(read) else {
                return Feed {
                    read,
                    written,
                    halt: Halt::End,
                };
            };
            let value = tables.decode[byte as usize];
            if value != INVALID {
                if self.quantum.is_full() && dst.len() < written + 3 {
                    return Feed {
                        read,
                        written,
                        halt: Halt::Full,
                    };
                }
                written += self.quantum.push(value, dst, written);
            } else if byte == b'=' {
                if dst.len() < written + self.quantum.flushed_len() {
                    return Feed {
                        read,
                        written,
                        halt: Halt::Full,
                    };
                }
                written += self
                    .quantum
                    .flush(dst.get_mut(written..).unwrap_or_default());
            } else if self.folded && !matches!(byte, b' ' | b'\t') {
                match Break::skip(src.get(read..).unwrap_or_default(), true) {
                    Some(len) => {
                        read += len;
                        mid_line = false;
                        continue;
                    }
                    None => {
                        return Feed {
                            read,
                            written,
                            halt: Halt::Byte(byte),
                        };
                    }
                }
            } else if !self.folded && !Self::is_space(byte) {
                return Feed {
                    read,
                    written,
                    halt: Halt::Byte(byte),
                };
            }
            mid_line &= byte != b'\n';
            read += 1;
        }
    }

    pub(super) fn finish(&mut self, dst: &mut [MaybeUninit<u8>]) -> Result<usize, Error> {
        let needed = self.quantum.flushed_len();
        if dst.len() < needed {
            return Err(Error::BufferTooSmall { required: needed });
        }
        Ok(self.quantum.flush(dst))
    }
}
