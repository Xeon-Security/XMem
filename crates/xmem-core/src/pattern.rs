use crate::{Result, XmemError};

/// 패턴 최대 길이(바이트).
pub const MAX_PATTERN_LEN: usize = 4096;

/// 바이트 패턴. mask가 0xFF면 정확 일치, 0xF0/0x0F면 니블 일치, 0x00이면 무시.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePattern {
    bytes: Vec<u8>,
    mask: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternKind {
    Hex,
    Ascii,
    Wide,
}

impl PatternKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PatternKind::Hex => "hex",
            PatternKind::Ascii => "ascii",
            PatternKind::Wide => "wide",
        }
    }
}

/// 사용자 입력에서 만든 검색 패턴.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPattern {
    pub pattern: BytePattern,
    pub kind: PatternKind,
    pub source: String,
}

impl ScanPattern {
    pub fn hex(source: &str) -> Result<Self> {
        Ok(Self {
            pattern: BytePattern::parse_hex(source)?,
            kind: PatternKind::Hex,
            source: source.to_string(),
        })
    }

    pub fn ascii(source: &str) -> Result<Self> {
        Ok(Self {
            pattern: BytePattern::from_ascii(source)?,
            kind: PatternKind::Ascii,
            source: source.to_string(),
        })
    }

    pub fn wide(source: &str) -> Result<Self> {
        Ok(Self {
            pattern: BytePattern::from_wide(source)?,
            kind: PatternKind::Wide,
            source: source.to_string(),
        })
    }

    pub fn len(&self) -> usize {
        self.pattern.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pattern.is_empty()
    }
}

fn invalid(reason: impl Into<String>) -> XmemError {
    XmemError::InvalidInput {
        reason: reason.into(),
    }
}

fn hex_digit(c: char) -> Option<u8> {
    c.to_digit(16).map(|d| d as u8)
}

impl BytePattern {
    /// 공백 구분 16진 토큰. `??`는 임의 바이트, `4?`/`?8`은 니블 마스크, 한 자리는 0x0v.
    pub fn parse_hex(input: &str) -> Result<Self> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();
        for token in input.split_whitespace() {
            let chars: Vec<char> = token.chars().collect();
            match chars.as_slice() {
                ['?'] => {
                    bytes.push(0);
                    mask.push(0x00);
                }
                [c] => {
                    let v = hex_digit(*c).ok_or_else(|| {
                        invalid(format!("패턴 토큰 '{token}'이(가) 16진수가 아님"))
                    })?;
                    bytes.push(v);
                    mask.push(0xFF);
                }
                [hi, lo] => {
                    let (mut value, mut m) = (0u8, 0u8);
                    if *hi != '?' {
                        value |= hex_digit(*hi).ok_or_else(|| {
                            invalid(format!("패턴 토큰 '{token}'이(가) 16진수가 아님"))
                        })? << 4;
                        m |= 0xF0;
                    }
                    if *lo != '?' {
                        value |= hex_digit(*lo).ok_or_else(|| {
                            invalid(format!("패턴 토큰 '{token}'이(가) 16진수가 아님"))
                        })?;
                        m |= 0x0F;
                    }
                    bytes.push(value);
                    mask.push(m);
                }
                _ => {
                    return Err(invalid(format!("패턴 토큰 '{token}'이(가) 너무 김(1~2자)")));
                }
            }
            if bytes.len() > MAX_PATTERN_LEN {
                return Err(invalid(format!(
                    "패턴이 너무 김(최대 {MAX_PATTERN_LEN}바이트)"
                )));
            }
        }
        if bytes.is_empty() {
            return Err(invalid("빈 패턴"));
        }
        Ok(Self { bytes, mask })
    }

    pub fn from_ascii(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(invalid("빈 문자열 패턴"));
        }
        let bytes = input.as_bytes().to_vec();
        if bytes.len() > MAX_PATTERN_LEN {
            return Err(invalid(format!(
                "패턴이 너무 김(최대 {MAX_PATTERN_LEN}바이트)"
            )));
        }
        Ok(Self {
            mask: vec![0xFF; bytes.len()],
            bytes,
        })
    }

    pub fn from_wide(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(invalid("빈 문자열 패턴"));
        }
        let mut bytes = Vec::new();
        for unit in input.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        if bytes.len() > MAX_PATTERN_LEN {
            return Err(invalid(format!(
                "패턴이 너무 김(최대 {MAX_PATTERN_LEN}바이트)"
            )));
        }
        Ok(Self {
            mask: vec![0xFF; bytes.len()],
            bytes,
        })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// hay에서 패턴이 시작하는 위치들. limit개까지만 수집(0이면 0개, usize::MAX=무제한).
    pub fn find_in(&self, hay: &[u8], limit: usize) -> Vec<usize> {
        let n = self.len();
        let mut out = Vec::new();
        if n == 0 || hay.len() < n || limit == 0 {
            return out;
        }
        'outer: for i in 0..=hay.len() - n {
            for j in 0..n {
                if hay[i + j] & self.mask[j] != self.bytes[j] {
                    continue 'outer;
                }
            }
            out.push(i);
            if out.len() >= limit {
                break;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(input: &str, f: impl Fn(&str) -> Result<BytePattern>) {
        assert!(
            matches!(f(input), Err(XmemError::InvalidInput { .. })),
            "input {input:?}는 InvalidInput이어야 함"
        );
    }

    #[test]
    fn parse_hex_literals_and_wildcards() {
        let p = BytePattern::parse_hex("48 8B ?? C0").unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p.bytes, vec![0x48, 0x8B, 0x00, 0xC0]);
        assert_eq!(p.mask, vec![0xFF, 0xFF, 0x00, 0xFF]);
        let p = BytePattern::parse_hex("8").unwrap();
        assert_eq!(p.bytes, vec![0x08]);
        assert_eq!(p.mask, vec![0xFF]);
    }

    #[test]
    fn parse_hex_nibble_masks() {
        let p = BytePattern::parse_hex("4? ?8 ?? ?").unwrap();
        assert_eq!(p.bytes, vec![0x40, 0x08, 0x00, 0x00]);
        assert_eq!(p.mask, vec![0xF0, 0x0F, 0x00, 0x00]);
        assert_eq!(p.len(), 4);
    }

    #[test]
    fn parse_hex_rejects_bad_input() {
        err("", BytePattern::parse_hex);
        err("   ", BytePattern::parse_hex);
        err("GG", BytePattern::parse_hex);
        err("4?8", BytePattern::parse_hex);
    }

    #[test]
    fn parse_hex_rejects_over_max_len() {
        let long = "AA ".repeat(MAX_PATTERN_LEN + 1);
        err(&long, BytePattern::parse_hex);
    }

    #[test]
    fn from_ascii_and_wide_encode_bytes() {
        let a = BytePattern::from_ascii("AB").unwrap();
        assert_eq!(a.bytes, vec![0x41, 0x42]);
        assert_eq!(a.mask, vec![0xFF, 0xFF]);
        let w = BytePattern::from_wide("AB").unwrap();
        assert_eq!(w.bytes, vec![0x41, 0x00, 0x42, 0x00]);
        err("", BytePattern::from_ascii);
        err("", BytePattern::from_wide);
    }

    #[test]
    fn find_in_exact_and_mask() {
        let hay = [0x00, 0x48, 0x8B, 0x11, 0xC0, 0x48, 0x8B, 0x22, 0xC0];
        let p = BytePattern::parse_hex("48 8B ?? C0").unwrap();
        assert_eq!(p.find_in(&hay, usize::MAX), vec![1, 5]);
        let p = BytePattern::parse_hex("4? 8B").unwrap();
        assert_eq!(p.find_in(&hay, usize::MAX), vec![1, 5]);
    }

    #[test]
    fn find_in_limits_and_edges() {
        let hay = [0x7A, 0x7A, 0x7A];
        let p = BytePattern::parse_hex("7A").unwrap();
        assert_eq!(p.find_in(&hay, 2), vec![0, 1]);
        assert_eq!(p.find_in(&hay, 0), Vec::<usize>::new());
        let long = BytePattern::parse_hex("7A 7A 7A 7A").unwrap();
        assert!(long.find_in(&hay, usize::MAX).is_empty());
    }

    #[test]
    fn scan_pattern_kinds() {
        let p = ScanPattern::hex("48 8B").unwrap();
        assert_eq!(p.kind, PatternKind::Hex);
        assert_eq!(p.kind.as_str(), "hex");
        assert_eq!(p.len(), 2);
        assert_eq!(p.source, "48 8B");
        assert_eq!(ScanPattern::ascii("hi").unwrap().kind, PatternKind::Ascii);
        assert_eq!(ScanPattern::wide("hi").unwrap().len(), 4);
    }
}
