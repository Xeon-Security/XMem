use std::path::{Path, PathBuf};

use xmem_core::{Result, SNAPSHOT_FORMAT_VERSION, XmemError};

use crate::envelope::SnapshotEnvelope;

pub const MAGIC: [u8; 4] = *b"XMEM";
pub const HEADER_LEN: usize = 12;

fn snapshot_error(reason: impl Into<String>) -> XmemError {
    XmemError::SnapshotError {
        reason: reason.into(),
    }
}

/// envelope → `header + UTF-8 JSON payload` 바이트.
pub fn encode(envelope: &SnapshotEnvelope) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec_pretty(envelope)
        .map_err(|error| snapshot_error(format!("JSON 직렬화 실패: {error}")))?;
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| snapshot_error(format!("payload가 너무 큼: {} bytes", payload.len())))?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&SNAPSHOT_FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// 바이트 → envelope. magic/version/flags/길이를 엄격히 검사한다.
pub fn decode(bytes: &[u8]) -> Result<SnapshotEnvelope> {
    if bytes.len() < HEADER_LEN {
        return Err(snapshot_error(format!(
            "파일이 너무 짧음: {} bytes",
            bytes.len()
        )));
    }
    if bytes[0..4] != MAGIC {
        return Err(snapshot_error("magic 불일치 (XMEM 파일 아님)"));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != SNAPSHOT_FORMAT_VERSION {
        return Err(snapshot_error(format!(
            "지원하지 않는 format_version: {version} (현재 {SNAPSHOT_FORMAT_VERSION})"
        )));
    }
    let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
    if flags != 0 {
        return Err(snapshot_error(format!("알 수 없는 flags: {flags:#06x}")));
    }
    let payload_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    let end = HEADER_LEN
        .checked_add(payload_len)
        .ok_or_else(|| snapshot_error("payload 길이 오버플로"))?;
    if bytes.len() != end {
        return Err(snapshot_error(format!(
            "payload 길이 불일치: header {payload_len}, 실제 {}",
            bytes.len().saturating_sub(HEADER_LEN)
        )));
    }
    let envelope: SnapshotEnvelope = serde_json::from_slice(&bytes[HEADER_LEN..end])
        .map_err(|error| snapshot_error(format!("JSON 파싱 실패: {error}")))?;
    if envelope.format_version != version {
        return Err(snapshot_error(format!(
            "payload format_version 불일치: {} vs {version}",
            envelope.format_version
        )));
    }
    Ok(envelope)
}

/// temp 파일에 쓰고 재파싱으로 검증한 뒤 atomic rename. 실패 시 temp를 제거한다.
pub fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = temp_path(path);
    if let Err(error) = std::fs::write(&temp, bytes) {
        std::fs::remove_file(&temp).ok();
        return Err(XmemError::Io(error));
    }
    let validate = (|| -> Result<()> {
        let read_back = std::fs::read(&temp).map_err(XmemError::Io)?;
        if read_back != bytes {
            return Err(snapshot_error("검증 실패: 기록 내용 불일치"));
        }
        decode(&read_back)?;
        Ok(())
    })();
    if let Err(err) = validate {
        std::fs::remove_file(&temp).ok();
        return Err(err);
    }
    if let Err(error) = std::fs::rename(&temp, path) {
        std::fs::remove_file(&temp).ok();
        return Err(XmemError::Io(error));
    }
    Ok(())
}

/// 파일 → envelope.
pub fn read_file(path: &Path) -> Result<SnapshotEnvelope> {
    let bytes = std::fs::read(path).map_err(XmemError::Io)?;
    decode(&bytes)
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "snapshot.xmem".into());
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::sample_envelope;

    #[test]
    fn encode_decode_roundtrip() {
        let envelope = sample_envelope(7, 0x2000, 0x40);
        let bytes = encode(&envelope).unwrap();
        assert_eq!(&bytes[0..4], b"XMEM");
        let back = decode(&bytes).unwrap();
        assert_eq!(back.process.pid, 7);
        assert_eq!(back.regions[0].base, 0x2000);
    }

    #[test]
    fn decode_rejects_short_bad_magic_and_version() {
        assert!(matches!(
            decode(b"XM"),
            Err(XmemError::SnapshotError { .. })
        ));
        let envelope = sample_envelope(1, 0x1000, 0x04);
        let mut bytes = encode(&envelope).unwrap();
        bytes[0] = b'Y';
        assert!(matches!(
            decode(&bytes),
            Err(XmemError::SnapshotError { .. })
        ));
        let mut bytes = encode(&envelope).unwrap();
        bytes[4] = 99;
        assert!(matches!(
            decode(&bytes),
            Err(XmemError::SnapshotError { .. })
        ));
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        let envelope = sample_envelope(1, 0x1000, 0x04);
        let bytes = encode(&envelope).unwrap();
        let truncated = &bytes[..bytes.len() - 1];
        assert!(matches!(
            decode(truncated),
            Err(XmemError::SnapshotError { .. })
        ));
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(matches!(
            decode(&extended),
            Err(XmemError::SnapshotError { .. })
        ));
    }

    #[test]
    fn write_read_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("xmem-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("roundtrip.xmem");
        let envelope = sample_envelope(9, 0x3000, 0x20);
        let bytes = encode(&envelope).unwrap();
        write_file(&path, &bytes).unwrap();
        let back = read_file(&path).unwrap();
        assert_eq!(back.process.pid, 9);
        assert_eq!(back.regions[0].base, 0x3000);
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_file_replaces_existing_and_cleans_temp() {
        let dir = std::env::temp_dir().join(format!("xmem-test-replace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("replace.xmem");
        let first = encode(&sample_envelope(1, 0x1000, 0x04)).unwrap();
        write_file(&path, &first).unwrap();
        let second = encode(&sample_envelope(2, 0x4000, 0x40)).unwrap();
        write_file(&path, &second).unwrap();
        let back = read_file(&path).unwrap();
        assert_eq!(back.process.pid, 2);
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
