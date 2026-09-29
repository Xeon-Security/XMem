//! 오류 로그 ring buffer (최근 200건).

use chrono::Local;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub time: String,
    pub level: LogLevel,
    pub message: String,
}

pub struct LogBuffer {
    entries: VecDeque<LogEntry>,
    capacity: usize,
    filter: Option<LogLevel>,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            capacity,
            filter: None,
        }
    }

    pub fn push(&mut self, level: LogLevel, message: impl Into<String>) {
        self.entries.push_back(LogEntry {
            time: Local::now().format("%H:%M:%S").to_string(),
            level,
            message: message.into(),
        });
        while self.entries.len() > self.capacity {
            self.entries.pop_front();
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// 보기 필터(최소 레벨). `None`이면 전체를 보여준다. 저장에는 영향을 주지 않는다.
    pub fn set_filter(&mut self, filter: Option<LogLevel>) {
        self.filter = filter;
    }

    pub fn filter(&self) -> Option<LogLevel> {
        self.filter
    }

    /// 필터를 적용한 엔트리(오래된 것부터).
    pub fn iter_visible(&self) -> impl DoubleEndedIterator<Item = &LogEntry> {
        let filter = self.filter;
        self.entries
            .iter()
            .filter(move |entry| filter.is_none_or(|min| entry.level >= min))
    }

    pub fn visible_len(&self) -> usize {
        self.iter_visible().count()
    }

    /// 필터와 무관하게 전체 엔트리를 "HH:MM:SS LEVEL message" 줄로 만든다.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for entry in &self.entries {
            let level = match entry.level {
                LogLevel::Info => "INFO",
                LogLevel::Warn => "WARN",
                LogLevel::Error => "ERROR",
            };
            out.push_str(&format!("{} {} {}\n", entry.time, level, entry.message));
        }
        out
    }

    /// 전체 로그를 파일에 쓴다(UTF-8). 기록한 바이트 수를 돌려준다.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<u64> {
        let text = self.to_text();
        std::fs::write(path, text.as_bytes())?;
        Ok(text.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_drops_oldest() {
        let mut log = LogBuffer::new(3);
        for i in 0..5 {
            log.push(LogLevel::Info, format!("msg {i}"));
        }
        assert_eq!(log.len(), 3);
        let messages: Vec<_> = log.iter_visible().map(|e| e.message.clone()).collect();
        assert_eq!(messages, vec!["msg 2", "msg 3", "msg 4"]);
    }

    #[test]
    fn clear_empties_buffer() {
        let mut log = LogBuffer::new(10);
        log.push(LogLevel::Error, "x");
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn iter_visible_filters_by_min_level() {
        let mut log = LogBuffer::new(10);
        log.push(LogLevel::Info, "i");
        log.push(LogLevel::Warn, "w");
        log.push(LogLevel::Error, "e");
        log.set_filter(Some(LogLevel::Warn));
        let messages: Vec<_> = log.iter_visible().map(|e| e.message.clone()).collect();
        assert_eq!(messages, vec!["w", "e"]);
        assert_eq!(log.visible_len(), 2);
        assert_eq!(log.len(), 3);
        log.set_filter(None);
        assert_eq!(log.visible_len(), 3);
    }

    #[test]
    fn save_writes_all_entries_even_when_filtered() {
        let mut log = LogBuffer::new(10);
        log.push(LogLevel::Info, "info line");
        log.push(LogLevel::Error, "error line");
        log.set_filter(Some(LogLevel::Error));
        let path = std::env::temp_dir().join(format!("xmem-log-{}.txt", std::process::id()));
        let bytes = log.save(&path).unwrap();
        assert!(bytes > 0);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("INFO info line"),
            "필터와 무관하게 전체를 저장한다"
        );
        assert!(text.contains("ERROR error line"));
        std::fs::remove_file(&path).ok();
    }
}
