/*
 * SPDX-FileCopyrightText: 2026 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![allow(dead_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    InvalidByte { offset: usize, byte: u8 },
    Truncated { offset: usize },
}

const MAX_CONTENT: usize = 75;
const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

pub struct Digits;

impl Digits {
    pub fn value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    pub fn pair(high: u8, low: u8) -> Option<u8> {
        Some((Self::value(high)? << 4) | Self::value(low)?)
    }

    pub fn escape(marker: u8, byte: u8) -> [u8; 3] {
        [
            marker,
            UPPER_HEX[usize::from(byte >> 4)],
            UPPER_HEX[usize::from(byte & 0x0f)],
        ]
    }

    pub fn is_blank(byte: u8) -> bool {
        matches!(byte, b' ' | b'\t')
    }
}

pub struct Body;

impl Body {
    fn soft_break_len(after: &[u8]) -> Option<usize> {
        let blanks = after
            .iter()
            .take_while(|&&byte| Digits::is_blank(byte))
            .count();
        match after.get(blanks..) {
            Some([]) => Some(blanks),
            Some([b'\n', ..]) => Some(blanks + 1),
            Some([b'\r', b'\n', ..]) => Some(blanks + 2),
            _ => None,
        }
    }

    fn escape_failure(after: &[u8], offset: usize, total: usize) -> Failure {
        match after {
            [high, low, ..] if Digits::value(*high).is_some() => Failure::InvalidByte {
                offset: offset + 1,
                byte: *low,
            },
            [high] if Digits::value(*high).is_some() => Failure::Truncated { offset: total },
            [first, ..] if Digits::is_blank(*first) => {
                let blanks = after
                    .iter()
                    .take_while(|&&byte| Digits::is_blank(byte))
                    .count();
                match after.get(blanks) {
                    Some(&byte) => Failure::InvalidByte {
                        offset: offset + blanks,
                        byte,
                    },
                    None => Failure::Truncated { offset: total },
                }
            }
            [first, ..] => Failure::InvalidByte {
                offset,
                byte: *first,
            },
            [] => Failure::Truncated { offset: total },
        }
    }

    fn trim(out: &mut Vec<u8>, keep: usize) {
        while out.len() > keep && out.last().is_some_and(|&byte| Digits::is_blank(byte)) {
            out.pop();
        }
    }

    pub fn decode(input: &[u8], strict: bool) -> Result<Vec<u8>, Failure> {
        let mut out = Vec::with_capacity(input.len());
        let mut keep = 0;
        let mut at = 0;
        loop {
            match input.get(at..).unwrap_or_default() {
                [] => {
                    Self::trim(&mut out, keep);
                    return Ok(out);
                }
                [b'=', after @ ..] => {
                    if let Some(byte) = after
                        .first_chunk::<2>()
                        .and_then(|&[high, low]| Digits::pair(high, low))
                    {
                        out.push(byte);
                        keep = out.len();
                        at += 3;
                    } else if let Some(len) = Self::soft_break_len(after) {
                        keep = out.len();
                        at += 1 + len;
                    } else if strict {
                        return Err(Self::escape_failure(after, at + 1, input.len()));
                    } else {
                        out.push(b'=');
                        if let Some(&byte) = after.first().filter(|&&byte| byte != b'\r') {
                            out.push(byte);
                        }
                        keep = out.len();
                        at += 2;
                    }
                }
                [b'\r', b'\n', ..] => {
                    Self::trim(&mut out, keep);
                    out.extend_from_slice(b"\r\n");
                    keep = out.len();
                    at += 2;
                }
                [b'\n', ..] => {
                    Self::trim(&mut out, keep);
                    out.push(b'\n');
                    keep = out.len();
                    at += 1;
                }
                [b'\r', ..] => at += 1,
                [byte, ..] => {
                    out.push(*byte);
                    at += 1;
                }
            }
        }
    }

    fn push_token(out: &mut Vec<u8>, column: &mut usize, byte: u8, literal: bool) {
        let width = if literal { 1 } else { 3 };
        if *column + width > MAX_CONTENT {
            out.extend_from_slice(b"=\r\n");
            *column = 0;
        }
        if literal {
            out.push(byte);
        } else {
            out.extend_from_slice(&Digits::escape(b'=', byte));
        }
        *column += width;
    }

    fn encode_line(line: &[u8], out: &mut Vec<u8>) {
        let mut column = 0;
        for (index, &byte) in line.iter().enumerate() {
            let is_last = index + 1 == line.len();
            let literal =
                matches!(byte, b'!'..=b'<' | b'>'..=b'~') || (Digits::is_blank(byte) && !is_last);
            Self::push_token(out, &mut column, byte, literal);
        }
    }

    pub fn encode(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len() * 3);
        let mut lines = input.split(|&byte| byte == b'\n').peekable();
        while let Some(line) = lines.next() {
            let has_break = lines.peek().is_some();
            let line = match has_break {
                true => line.strip_suffix(b"\r").unwrap_or(line),
                false => line,
            };
            Self::encode_line(line, &mut out);
            if has_break {
                out.extend_from_slice(b"\r\n");
            }
        }
        out
    }
}

pub struct Binary;

impl Binary {
    pub fn encode(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len() * 3);
        Body::encode_line(input, &mut out);
        out
    }
}

pub struct Q;

impl Q {
    pub fn decode(input: &[u8], word: bool) -> Result<(Vec<u8>, usize), Failure> {
        let mut out = Vec::with_capacity(input.len());
        let mut at = 0;
        loop {
            match input.get(at..).unwrap_or_default() {
                [] if word => {
                    return Err(Failure::Truncated {
                        offset: input.len(),
                    });
                }
                [] => return Ok((out, at)),
                [b'?', b'=', ..] if word => return Ok((out, at + 2)),
                [b'_', ..] => {
                    out.push(b' ');
                    at += 1;
                }
                [b'=', after @ ..] => match after {
                    [high, low, ..] => match (Digits::value(*high), Digits::value(*low)) {
                        (Some(high), Some(low)) => {
                            out.push((high << 4) | low);
                            at += 3;
                        }
                        (None, _) => {
                            return Err(Failure::InvalidByte {
                                offset: at + 1,
                                byte: *high,
                            });
                        }
                        (_, None) => {
                            return Err(Failure::InvalidByte {
                                offset: at + 2,
                                byte: *low,
                            });
                        }
                    },
                    [high] if Digits::value(*high).is_none() => {
                        return Err(Failure::InvalidByte {
                            offset: at + 1,
                            byte: *high,
                        });
                    }
                    _ => {
                        return Err(Failure::Truncated {
                            offset: input.len(),
                        });
                    }
                },
                [b'\r', ..] => at += 1,
                [b'\n', after @ ..] => {
                    at += 1 + after
                        .iter()
                        .take_while(|&&byte| Digits::is_blank(byte))
                        .count();
                }
                [byte, ..] => {
                    out.push(*byte);
                    at += 1;
                }
            }
        }
    }

    pub fn encode(input: &[u8], phrase: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len() * 3);
        for &byte in input {
            let literal = match phrase {
                true => matches!(
                    byte,
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'!' | b'*' | b'+' | b'-' | b'/'
                ),
                false => matches!(byte, b'!'..=b'~') && !matches!(byte, b'=' | b'?' | b'_'),
            };
            if byte == b' ' {
                out.push(b'_');
            } else if literal {
                out.push(byte);
            } else {
                out.extend_from_slice(&Digits::escape(b'=', byte));
            }
        }
        out
    }
}

pub struct Dkim;

impl Dkim {
    pub fn is_safe(byte: u8) -> bool {
        matches!(byte, 0x21..=0x3a | 0x3c | 0x3e..=0x7e)
    }

    pub fn decode(input: &[u8]) -> Result<Vec<u8>, Failure> {
        let significant: Vec<(usize, u8)> = input
            .iter()
            .copied()
            .enumerate()
            .filter(|&(_, byte)| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            .collect();
        let mut out = Vec::with_capacity(input.len());
        let mut rest = significant.as_slice();
        loop {
            match rest {
                [] => return Ok(out),
                [(_, b'='), (at_high, high), (at_low, low), tail @ ..] => {
                    match (Digits::value(*high), Digits::value(*low)) {
                        (Some(high), Some(low)) => out.push((high << 4) | low),
                        (None, _) => {
                            return Err(Failure::InvalidByte {
                                offset: *at_high,
                                byte: *high,
                            });
                        }
                        (_, None) => {
                            return Err(Failure::InvalidByte {
                                offset: *at_low,
                                byte: *low,
                            });
                        }
                    }
                    rest = tail;
                }
                [(_, b'='), (at_high, high)] if Digits::value(*high).is_none() => {
                    return Err(Failure::InvalidByte {
                        offset: *at_high,
                        byte: *high,
                    });
                }
                [(_, b'='), ..] => {
                    return Err(Failure::Truncated {
                        offset: input.len(),
                    });
                }
                [(offset, byte), tail @ ..] => {
                    if !Self::is_safe(*byte) && *byte < 0x80 {
                        return Err(Failure::InvalidByte {
                            offset: *offset,
                            byte: *byte,
                        });
                    }
                    out.push(*byte);
                    rest = tail;
                }
            }
        }
    }

    pub fn is_literal(byte: u8) -> bool {
        Self::is_safe(byte) && byte != b'|'
    }

    pub fn encode(input: &[u8]) -> Vec<u8> {
        Hex::encode(input, b'=', Self::is_literal)
    }
}

pub struct Hex;

impl Hex {
    pub fn is_attribute_char(byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'&'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'{'
                    | b'|'
                    | b'}'
                    | b'~'
            )
    }

    pub fn is_xchar(byte: u8) -> bool {
        matches!(byte, b'!'..=b'~') && !matches!(byte, b'+' | b'=')
    }

    pub fn encode(input: &[u8], marker: u8, safe: fn(u8) -> bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len() * 3);
        for &byte in input {
            if safe(byte) {
                out.push(byte);
            } else {
                out.extend_from_slice(&Digits::escape(marker, byte));
            }
        }
        out
    }

    pub fn decode(input: &[u8], marker: u8) -> Result<Vec<u8>, Failure> {
        let mut out = Vec::with_capacity(input.len());
        let mut at = 0;
        loop {
            match input.get(at..).unwrap_or_default() {
                [] => return Ok(out),
                [first, after @ ..] if *first == marker => match after {
                    [high, low, ..] => match (Digits::value(*high), Digits::value(*low)) {
                        (Some(high), Some(low)) => {
                            out.push((high << 4) | low);
                            at += 3;
                        }
                        (None, _) => {
                            return Err(Failure::InvalidByte {
                                offset: at + 1,
                                byte: *high,
                            });
                        }
                        (_, None) => {
                            return Err(Failure::InvalidByte {
                                offset: at + 2,
                                byte: *low,
                            });
                        }
                    },
                    [high] if Digits::value(*high).is_none() => {
                        return Err(Failure::InvalidByte {
                            offset: at + 1,
                            byte: *high,
                        });
                    }
                    _ => {
                        return Err(Failure::Truncated {
                            offset: input.len(),
                        });
                    }
                },
                [byte, ..] => {
                    out.push(*byte);
                    at += 1;
                }
            }
        }
    }
}

pub struct Wrapping;

impl Wrapping {
    pub fn lines(encoded: &[u8]) -> Vec<&[u8]> {
        let mut lines = Vec::new();
        let mut rest = encoded;
        while let Some(at) = rest.windows(2).position(|pair| pair == b"\r\n") {
            let (line, tail) = rest.split_at(at);
            lines.push(line);
            rest = tail.get(2..).unwrap_or_default();
        }
        lines.push(rest);
        lines
    }

    pub fn check(encoded: &[u8]) -> Result<(), String> {
        for line in Self::lines(encoded) {
            if line.len() > MAX_CONTENT + 1 {
                return Err(format!("line of {} characters", line.len()));
            }
            if line.last().is_some_and(|&byte| Digits::is_blank(byte)) {
                return Err("line ends with white space".into());
            }
            if let Some(byte) = line
                .iter()
                .find(|&&byte| !matches!(byte, b' ' | b'\t' | b'!'..=b'~'))
            {
                return Err(format!("raw byte 0x{byte:02x}"));
            }
            let is_upper_hex = |byte: &u8| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase();
            if let Some((at, _)) = line
                .iter()
                .enumerate()
                .filter(|&(_, &byte)| byte == b'=')
                .find(|&(at, _)| {
                    at + 1 != line.len()
                        && !line
                            .get(at + 1..at + 3)
                            .is_some_and(|pair| pair.iter().all(is_upper_hex))
                })
            {
                return Err(format!("split or malformed escape at {at}"));
            }
        }
        Ok(())
    }
}
