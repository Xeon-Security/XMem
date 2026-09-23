//! 오류 로그 ring buffer (최근 200건).

use chrono::Local;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            capacity,
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

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &LogEntry> {
        self.entries.iter()
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
        let messages: Vec<_> = log.iter().map(|e| e.message.clone()).collect();
        assert_eq!(messages, vec!["msg 2", "msg 3", "msg 4"]);
    }

    #[test]
    fn clear_empties_buffer() {
        let mut log = LogBuffer::new(10);
        log.push(LogLevel::Error, "x");
        log.clear();
        assert!(log.is_empty());
    }
}
