//! 백그라운드 태스크: 스레드 + 취소 플래그 + mpsc. UI는 poll만 한다.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use xmem_core::{Result, XmemError};

pub enum TaskState<T> {
    Idle,
    Running,
    Done(T),
    Failed(XmemError),
    Cancelled,
}

enum TaskMessage<T> {
    Done(T),
    Failed(XmemError),
}

pub struct BackgroundTask<T> {
    label: String,
    state: TaskState<T>,
    cancel: Arc<AtomicBool>,
    rx: Option<Receiver<TaskMessage<T>>>,
    pid: Option<u32>,
}

impl<T: Send + 'static> BackgroundTask<T> {
    pub fn idle() -> Self {
        Self {
            label: String::new(),
            state: TaskState::Idle,
            cancel: Arc::new(AtomicBool::new(false)),
            rx: None,
            pid: None,
        }
    }

    pub fn spawn(
        label: impl Into<String>,
        f: impl FnOnce(&AtomicBool) -> Result<T> + Send + 'static,
    ) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let flag = Arc::clone(&cancel);
        std::thread::spawn(move || {
            let message = match f(&flag) {
                Ok(value) => TaskMessage::Done(value),
                Err(err) => TaskMessage::Failed(err),
            };
            let _ = tx.send(message);
        });
        Self {
            label: label.into(),
            state: TaskState::Running,
            cancel,
            rx: Some(rx),
            pid: None,
        }
    }

    /// 실패 배너 분류에 쓸 대상 PID를 기록한다.
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn state(&self) -> &TaskState<T> {
        &self.state
    }

    pub fn is_running(&self) -> bool {
        matches!(self.state, TaskState::Running)
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Idle로 되돌리고 취소 플래그를 세운다. 진행 중 워커의 결과는 버려진다
    /// (수신 채널을 끊으므로 늦게 도착한 결과는 무시된다).
    pub fn reset(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.rx = None;
        self.state = TaskState::Idle;
    }

    /// 논블로킹으로 결과를 반영한다. 상태가 바뀌면 true.
    pub fn poll(&mut self) -> bool {
        let Some(rx) = &self.rx else {
            return false;
        };
        match rx.try_recv() {
            Ok(TaskMessage::Done(value)) => {
                self.state = TaskState::Done(value);
                self.rx = None;
                true
            }
            Ok(TaskMessage::Failed(XmemError::Cancelled { .. })) => {
                self.state = TaskState::Cancelled;
                self.rx = None;
                true
            }
            Ok(TaskMessage::Failed(err)) => {
                self.state = TaskState::Failed(err);
                self.rx = None;
                true
            }
            Err(TryRecvError::Empty) => false,
            Err(TryRecvError::Disconnected) => {
                self.state = TaskState::Cancelled;
                self.rx = None;
                true
            }
        }
    }

    /// Done이면 값을 꺼내고 Idle로 되돌린다.
    pub fn take_done(&mut self) -> Option<T> {
        if matches!(self.state, TaskState::Done(_)) {
            match std::mem::replace(&mut self.state, TaskState::Idle) {
                TaskState::Done(value) => Some(value),
                _ => None,
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait_polled<T: Send + 'static>(task: &mut BackgroundTask<T>) {
        for _ in 0..100 {
            if task.poll() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("태스크가 시간 안에 끝나지 않았다");
    }

    #[test]
    fn done_task_transitions_and_yields_value() {
        let mut task = BackgroundTask::spawn("test", |_| Ok(7u32));
        wait_polled(&mut task);
        assert!(!task.is_running());
        assert_eq!(task.take_done(), Some(7u32));
        assert!(matches!(task.state(), TaskState::Idle));
    }

    #[test]
    fn failed_task_stores_error() {
        let mut task: BackgroundTask<u32> = BackgroundTask::spawn("fail", |_| {
            Err(XmemError::InvalidInput { reason: "x".into() })
        });
        wait_polled(&mut task);
        assert!(matches!(task.state(), TaskState::Failed(_)));
    }

    #[test]
    fn cancelled_error_maps_to_cancelled_state() {
        let mut task: BackgroundTask<u32> = BackgroundTask::spawn("cancel", |_| {
            Err(XmemError::Cancelled {
                reason: "user".into(),
            })
        });
        wait_polled(&mut task);
        assert!(matches!(task.state(), TaskState::Cancelled));
    }

    #[test]
    fn cancel_flag_is_visible_to_worker() {
        let mut task = BackgroundTask::spawn("flag", |flag| {
            std::thread::sleep(std::time::Duration::from_millis(30));
            Ok(flag.load(Ordering::Relaxed))
        });
        task.cancel();
        wait_polled(&mut task);
        assert_eq!(task.take_done(), Some(true));
    }
}
