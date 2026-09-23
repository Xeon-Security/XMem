//! Windows API 경계에서 쓰는 소형 유틸.

/// NUL 종료 UTF-16 버퍼를 String으로 변환한다(손상된 입력은 lossy 치환).
pub fn utf16_z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stops_at_nul() {
        let buf = [0x48u16, 0x69, 0x00, 0x58];
        assert_eq!(utf16_z_to_string(&buf), "Hi");
    }

    #[test]
    fn no_nul_uses_whole_buffer() {
        let buf = [0x48u16, 0x69];
        assert_eq!(utf16_z_to_string(&buf), "Hi");
    }

    #[test]
    fn empty_buffer_is_empty_string() {
        assert_eq!(utf16_z_to_string(&[]), "");
    }
}
