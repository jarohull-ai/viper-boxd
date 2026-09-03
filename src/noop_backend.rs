use std::{collections::BTreeMap, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendStatus {
    Running,
    Killed,
    Cleaned,
}

#[derive(Debug, Clone)]
pub struct BackendSpec {
    pub box_id: String,
    pub task_id: String,
    pub workspace_id: String,
    pub profile_id: String,
    pub audit_trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendHandle(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    InvalidRequest(&'static str),
    DuplicateBox,
    UnknownHandle,
    MustStopBeforeCleanup,
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(field) => write!(formatter, "missing required field: {field}"),
            Self::DuplicateBox => write!(formatter, "box already exists"),
            Self::UnknownHandle => write!(formatter, "unknown backend handle"),
            Self::MustStopBeforeCleanup => write!(formatter, "box must be stopped before cleanup"),
        }
    }
}

#[derive(Debug, Default)]
pub struct NoopBackend {
    boxes: BTreeMap<String, BackendStatus>,
}

impl NoopBackend {
    /// Creates an empty in-memory backend. It performs no system operations.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a simulated spawn and returns an opaque in-memory handle.
    pub fn spawn(&mut self, spec: &BackendSpec) -> Result<BackendHandle, BackendError> {
        for (name, value) in [
            ("box_id", spec.box_id.as_str()),
            ("task_id", spec.task_id.as_str()),
            ("workspace_id", spec.workspace_id.as_str()),
            ("profile_id", spec.profile_id.as_str()),
            ("audit_trace_id", spec.audit_trace_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(BackendError::InvalidRequest(name));
            }
        }
        if self.boxes.contains_key(&spec.box_id) {
            return Err(BackendError::DuplicateBox);
        }
        self.boxes
            .insert(spec.box_id.clone(), BackendStatus::Running);
        Ok(BackendHandle(format!("noop:{}", spec.box_id)))
    }

    /// Returns the simulated lifecycle state for a handle.
    pub fn status(&self, handle: &BackendHandle) -> Result<BackendStatus, BackendError> {
        self.box_id(handle).and_then(|box_id| {
            self.boxes
                .get(box_id)
                .cloned()
                .ok_or(BackendError::UnknownHandle)
        })
    }

    /// Simulates an idempotent termination of a Box.
    pub fn kill(&mut self, handle: &BackendHandle) -> Result<BackendStatus, BackendError> {
        let box_id = self.box_id(handle)?.to_owned();
        let status = self
            .boxes
            .get_mut(&box_id)
            .ok_or(BackendError::UnknownHandle)?;
        if *status == BackendStatus::Running {
            *status = BackendStatus::Killed;
        }
        Ok(status.clone())
    }

    /// Simulates idempotent cleanup after termination.
    pub fn cleanup(&mut self, handle: &BackendHandle) -> Result<BackendStatus, BackendError> {
        let box_id = self.box_id(handle)?.to_owned();
        let status = self
            .boxes
            .get_mut(&box_id)
            .ok_or(BackendError::UnknownHandle)?;
        if *status == BackendStatus::Running {
            return Err(BackendError::MustStopBeforeCleanup);
        }
        *status = BackendStatus::Cleaned;
        Ok(status.clone())
    }

    fn box_id<'a>(&self, handle: &'a BackendHandle) -> Result<&'a str, BackendError> {
        handle
            .0
            .strip_prefix("noop:")
            .ok_or(BackendError::UnknownHandle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> BackendSpec {
        BackendSpec {
            box_id: "BOX_001".into(),
            task_id: "TASK_001".into(),
            workspace_id: "WORKSPACE_A".into(),
            profile_id: "PROFILE_V1".into(),
            audit_trace_id: "TRACE_001".into(),
        }
    }

    #[test]
    fn lifecycle_is_spawn_kill_cleanup_and_is_idempotent() {
        let mut backend = NoopBackend::new();
        let handle = backend.spawn(&spec()).expect("spawn");
        assert_eq!(backend.status(&handle), Ok(BackendStatus::Running));
        assert_eq!(backend.kill(&handle), Ok(BackendStatus::Killed));
        assert_eq!(backend.kill(&handle), Ok(BackendStatus::Killed));
        assert_eq!(backend.cleanup(&handle), Ok(BackendStatus::Cleaned));
        assert_eq!(backend.cleanup(&handle), Ok(BackendStatus::Cleaned));
    }

    #[test]
    fn cleanup_cannot_run_while_box_is_running() {
        let mut backend = NoopBackend::new();
        let handle = backend.spawn(&spec()).expect("spawn");
        assert_eq!(
            backend.cleanup(&handle),
            Err(BackendError::MustStopBeforeCleanup)
        );
    }

    #[test]
    fn rejects_duplicate_and_incomplete_requests() {
        let mut backend = NoopBackend::new();
        let mut invalid = spec();
        invalid.profile_id.clear();
        assert_eq!(
            backend.spawn(&invalid),
            Err(BackendError::InvalidRequest("profile_id"))
        );
        backend.spawn(&spec()).expect("first spawn");
        assert_eq!(backend.spawn(&spec()), Err(BackendError::DuplicateBox));
    }

    #[test]
    fn unknown_handles_fail_closed() {
        let mut backend = NoopBackend::new();
        let unknown = BackendHandle("host-pid:1".into());
        assert_eq!(backend.status(&unknown), Err(BackendError::UnknownHandle));
        assert_eq!(backend.kill(&unknown), Err(BackendError::UnknownHandle));
        assert_eq!(backend.cleanup(&unknown), Err(BackendError::UnknownHandle));
    }
}
