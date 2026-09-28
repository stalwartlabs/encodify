/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(unsafe_code)]

mod folded;
mod incremental;
mod lenient;
mod strict;

pub use folded::FoldedValue;
pub use incremental::Decoder;

use super::{
    Base64,
    alphabet::{INVALID, Tables},
    kernel::LineShape,
};
use crate::{
    Error,
    buffer::{SpareCapacity, Uninit},
    error::ToStr,
};
use lenient::{Halt, Lenient};
use std::mem::MaybeUninit;
use strict::Layout;

const CHUNK: usize = 4096;
const CHUNK_OUT: usize = CHUNK / 4 * 3 + 3;
const PREFIX_WINDOW: usize = 4096;
const PREFIX_GROWTH: usize = 8;

impl Base64 {
    /// Decodes `input` into a new `Vec<u8>`.
    pub fn decode(&self, input: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        let input = input.as_ref();
        let mut out = Vec::with_capacity(self.decoded_len_estimate(input.len()));
        self.decode_into_vec(input, &mut out)?;
        Ok(out)
    }

    /// Appends the decoding of `input` to `out` and returns the number of
    /// bytes appended. On error `out` is left unchanged.
    pub fn decode_append(
        &self,
        input: impl AsRef<[u8]>,
        out: &mut Vec<u8>,
    ) -> Result<usize, Error> {
        self.decode_into_vec(input.as_ref(), out)
    }

    /// Decodes `input` into `out` and returns the number of bytes written.
    /// Strict engines leave the rest of `out` untouched. Lenient engines, whose
    /// output length is only known at the end, may also overwrite the bytes
    /// after it, up to [`Base64::decoded_len_estimate`] of the input length.
    pub fn decode_slice(&self, input: impl AsRef<[u8]>, out: &mut [u8]) -> Result<usize, Error> {
        self.decode_into_slice(input.as_ref(), out)
    }

    /// Decodes `buffer` in place and returns the decoded prefix of it.
    pub fn decode_in_place<'x>(&self, buffer: &'x mut [u8]) -> Result<&'x mut [u8], Error> {
        let written = self.decode_within(buffer)?;
        buffer
            .get_mut(..written)
            .ok_or(Error::BufferTooSmall { required: written })
    }

    /// Decodes `input` and checks that the result is UTF-8.
    pub fn decode_to_string(&self, input: impl AsRef<[u8]>) -> Result<String, Error> {
        let bytes = self.decode(input)?;
        bytes.to_str()?;
        // SAFETY: `to_str` just validated `bytes` as UTF-8.
        Ok(unsafe { String::from_utf8_unchecked(bytes) })
    }

    /// Validates `input` and returns its exact decoded length without
    /// allocating.
    pub fn decoded_len(&self, input: impl AsRef<[u8]>) -> Result<usize, Error> {
        self.measure_decoded(input.as_ref())
    }

    /// Decodes `input` up to the first `stop` byte, which is not consumed.
    /// Returns the decoded bytes and the number of input bytes consumed, which
    /// is the position of `stop` or the input length. Any other byte that the
    /// engine does not accept is an error.
    pub fn decode_until(
        &self,
        input: impl AsRef<[u8]>,
        stop: u8,
    ) -> Result<(Vec<u8>, usize), Error> {
        let mut out = Vec::new();
        let consumed = self.decode_until_into(input.as_ref(), stop, &mut out)?;
        Ok((out, consumed))
    }

    /// Decodes the longest prefix of `input` made of alphabet symbols, ASCII
    /// whitespace and `=`, with lenient rules, appending the bytes to `out`.
    /// Returns the number of input bytes consumed; decoding stops at the first
    /// other byte, which is left for the caller (a MIME boundary, a quote, a
    /// delimiter).
    pub fn decode_prefix(&self, input: impl AsRef<[u8]>, out: &mut Vec<u8>) -> usize {
        self.decode_prefix_into(input.as_ref(), out)
    }

    fn decode_into_vec(&self, input: &[u8], out: &mut Vec<u8>) -> Result<usize, Error> {
        let mut result = Ok(());
        let max_len = self.decoded_len_estimate(input.len());
        // SAFETY: the decoders count only bytes they stored, stopping or erroring when
        // the region is full, and an error commits 0 bytes.
        let written = unsafe {
            out.append_with(max_len, |dst| match self.decode_into(input, dst) {
                Ok(written) => written,
                Err(err) => {
                    result = Err(err);
                    0
                }
            })
        };
        result.map(|()| written)
    }

    fn decode_into_slice(&self, input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        // SAFETY: the decoders store only initialised `u8` values into `out`.
        self.decode_into(input, unsafe { out.as_uninit() })
    }

    #[inline(always)]
    fn decode_into(&self, input: &[u8], dst: &mut [MaybeUninit<u8>]) -> Result<usize, Error> {
        if !self.lenient {
            return self.decode_strict(input, dst);
        }
        let bound = self.decoded_len_estimate(input.len()).min(dst.len());
        let dst = dst.get_mut(..bound).unwrap_or_default();
        let tables = self.decode_tables();
        let shape = LineShape::detect(input);
        let (read, written) = tables.decode_lines(shape, false, false, input, dst);
        let rest = input.get(read..).unwrap_or_default();
        match tables.lenient_tail(rest, dst.get_mut(written..).unwrap_or_default()) {
            Some(extra) => Ok(written + extra),
            None => self.decode_lenient_slow(input, dst, read, written, shape),
        }
    }

    #[inline(never)]
    fn decode_lenient_slow(
        &self,
        input: &[u8],
        dst: &mut [MaybeUninit<u8>],
        read: usize,
        written: usize,
        shape: Option<LineShape>,
    ) -> Result<usize, Error> {
        let mut state = Lenient::with_shape(shape);
        let rest = dst.get_mut(written..).unwrap_or_default();
        let feed = state.feed(
            self.decode_tables(),
            input.get(read..).unwrap_or_default(),
            rest,
        );
        let result = match feed.halt {
            Halt::End => state
                .finish(rest.get_mut(feed.written..).unwrap_or_default())
                .map(|extra| written + feed.written + extra),
            Halt::Byte(byte) => Err(Error::unexpected(byte, read + feed.read)),
            Halt::Full => Err(Error::BufferTooSmall { required: 0 }),
        };
        match result {
            Err(Error::BufferTooSmall { .. }) => Err(Error::BufferTooSmall {
                required: self.measure_decoded(input)?,
            }),
            other => other,
        }
    }

    fn measure_decoded(&self, input: &[u8]) -> Result<usize, Error> {
        if !self.lenient {
            return self.check_strict(input);
        }
        let tables = self.decode_tables();
        let mut state = Lenient::default();
        let mut scratch = [MaybeUninit::uninit(); CHUNK_OUT];
        let mut total = 0;
        let mut offset = 0;
        for chunk in input.chunks(CHUNK) {
            let feed = state.feed(tables, chunk, &mut scratch);
            if let Halt::Byte(byte) = feed.halt {
                return Err(Error::unexpected(byte, offset + feed.read));
            }
            total += feed.written;
            offset += chunk.len();
        }
        Ok(total + state.finish(&mut scratch)?)
    }

    fn decode_within(&self, buffer: &mut [u8]) -> Result<usize, Error> {
        let tables = self.decode_tables();
        let mut scratch = Scratch([0; CHUNK]);
        let mut written = 0;
        if self.lenient {
            let mut state = Lenient::default();
            for read in (0..buffer.len()).step_by(CHUNK) {
                let chunk = scratch.copy_of(buffer, read, buffer.len());
                let dst = buffer.get_mut(written..).unwrap_or_default();
                // SAFETY: `feed` stores only initialised `u8` values into `dst`.
                let feed = state.feed(tables, chunk, unsafe { dst.as_uninit() });
                if let Halt::Byte(byte) = feed.halt {
                    return Err(Error::unexpected(byte, read + feed.read));
                }
                written += feed.written;
            }
            let dst = buffer.get_mut(written..).unwrap_or_default();
            // SAFETY: `finish` stores only initialised `u8` values into `dst`.
            return Ok(written + state.finish(unsafe { dst.as_uninit() })?);
        }
        let layout = Layout::of(buffer);
        for read in (0..layout.full).step_by(CHUNK) {
            let chunk = scratch.copy_of(buffer, read, layout.full);
            let dst = buffer.get_mut(written..).unwrap_or_default();
            // SAFETY: `decode_quads` stores only initialised `u8` values into `dst`.
            let (done, out) = tables.decode_quads(chunk, unsafe { dst.as_uninit() });
            if done < chunk.len() {
                return Err(tables.first_invalid(chunk, done).shifted(read));
            }
            written += out;
        }
        let tail = self.strict_tail(buffer, &layout)?;
        let dst = buffer.get_mut(written..).unwrap_or_default();
        for (slot, &byte) in dst.iter_mut().zip(tail.as_slice()) {
            *slot = byte;
        }
        Ok(written + tail.as_slice().len())
    }

    fn decode_until_into(&self, input: &[u8], stop: u8, out: &mut Vec<u8>) -> Result<usize, Error> {
        let end = memchr::memchr(stop, input).unwrap_or(input.len());
        self.decode_into_vec(input.get(..end).unwrap_or_default(), out)?;
        Ok(end)
    }

    fn decode_prefix_into(&self, input: &[u8], out: &mut Vec<u8>) -> usize {
        let tables = self.decode_tables();
        let mut state = Lenient::default();
        let mut read = 0;
        let mut window = PREFIX_WINDOW;
        loop {
            let rest = input.get(read..).unwrap_or_default();
            let chunk = rest.get(..window).unwrap_or(rest);
            let mut halt = Halt::End;
            // SAFETY: `feed` returns only the bytes it stored, halting with `Full` rather
            // than counting a quantum that does not fit.
            unsafe {
                out.append_with(self.decoded_len_estimate(chunk.len()), |dst| {
                    let feed = state.feed(tables, chunk, dst);
                    read += feed.read;
                    halt = feed.halt;
                    feed.written
                })
            };
            match halt {
                Halt::End if chunk.len() < rest.len() => {
                    window = window.saturating_mul(PREFIX_GROWTH);
                }
                Halt::Full => {}
                _ => break,
            }
        }
        // SAFETY: the region holds 2 bytes, the most a pending quantum flushes, so
        // `finish` stores every byte it counts, and an error commits 0.
        unsafe { out.append_with(2, |dst| state.finish(dst).unwrap_or(0)) };
        read
    }
}

impl Tables {
    #[inline(always)]
    fn lenient_tail(&self, rest: &[u8], dst: &mut [MaybeUninit<u8>]) -> Option<usize> {
        let decode = &self.decode;
        let symbols = rest
            .iter()
            .take_while(|&&byte| decode[byte as usize] != INVALID)
            .count();
        let (tail, after) = rest.split_at_checked(symbols)?;
        if !after
            .iter()
            .all(|&byte| byte == b'=' || Lenient::is_space(byte))
        {
            return None;
        }
        let word = tail.iter().fold(0u32, |word, &byte| {
            (word << 6) | decode[byte as usize] as u32
        });
        match symbols {
            0 | 1 => Some(0),
            2 => {
                dst.first_mut()?.write((word >> 4) as u8);
                Some(1)
            }
            3 => {
                let [low, high] = dst.first_chunk_mut::<2>()?;
                low.write((word >> 10) as u8);
                high.write((word >> 2) as u8);
                Some(2)
            }
            _ => None,
        }
    }
}

struct Scratch([u8; CHUNK]);

impl Scratch {
    fn copy_of(&mut self, buffer: &[u8], from: usize, end: usize) -> &[u8] {
        let source = buffer.get(from..end.min(from + CHUNK)).unwrap_or_default();
        let (chunk, _) = self.0.split_at_mut(source.len());
        chunk.copy_from_slice(source);
        chunk
    }
}
