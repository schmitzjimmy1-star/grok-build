use std::time::Duration;

use crate::computer::types::{
    BackgroundHandle, ComputerError, KillOutcome, TaskSnapshot, TerminalBackend,
    TerminalRunRequest, TerminalRunResult,
};

/// A terminal backend that cannot create a process.
///
/// Hard-budget acceptance uses this instead of a local, parent, or reverse-ACP
/// backend so direct execution remains impossible even if a higher layer
/// accidentally exposes a terminal route.
#[derive(Debug, Default)]
pub struct DeniedTerminalBackend;

fn denied() -> ComputerError {
    ComputerError::io_with_kind(
        "terminal execution is disabled while the hard-token budget is armed",
        std::io::ErrorKind::PermissionDenied,
    )
}

#[async_trait::async_trait]
impl TerminalBackend for DeniedTerminalBackend {
    async fn run(&self, _request: TerminalRunRequest) -> Result<TerminalRunResult, ComputerError> {
        Err(denied())
    }

    async fn run_background(
        &self,
        _request: TerminalRunRequest,
    ) -> Result<BackgroundHandle, ComputerError> {
        Err(denied())
    }

    async fn get_task(&self, _task_id: &str) -> Option<TaskSnapshot> {
        None
    }

    async fn kill_task(&self, _task_id: &str) -> KillOutcome {
        KillOutcome::NotFound
    }

    async fn wait_for_completion(
        &self,
        _task_id: &str,
        _timeout: Option<Duration>,
    ) -> Option<TaskSnapshot> {
        None
    }

    async fn list_tasks(&self) -> Vec<TaskSnapshot> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification::ToolNotificationHandle;
    use std::{collections::HashMap, path::PathBuf, sync::Arc};

    fn request() -> TerminalRunRequest {
        TerminalRunRequest {
            command: "echo should-not-run".to_string(),
            working_directory: PathBuf::from("/tmp"),
            env: HashMap::new(),
            timeout: Duration::from_secs(1),
            output_byte_limit: 1024,
            output_file: PathBuf::from("/tmp/denied-terminal-output"),
            notification_handle: ToolNotificationHandle::noop(),
            tool_call_id: "denied".to_string(),
            display_command: None,
            auto_background_on_timeout: false,
            foreground_block_budget: None,
            kind: crate::computer::types::TaskKind::Bash,
            owner_session_id: None,
            description: None,
        }
    }

    #[tokio::test]
    async fn refuses_foreground_and_background_without_creating_tasks() {
        let backend: Arc<dyn TerminalBackend> = Arc::new(DeniedTerminalBackend);
        let foreground_error = match backend.run(request()).await {
            Ok(_) => panic!("denied terminal unexpectedly ran a foreground process"),
            Err(error) => error,
        };
        assert_eq!(
            foreground_error.io_error_kind(),
            Some(std::io::ErrorKind::PermissionDenied)
        );
        let background_error = match backend.run_background(request()).await {
            Ok(_) => panic!("denied terminal unexpectedly ran a background process"),
            Err(error) => error,
        };
        assert_eq!(
            background_error.io_error_kind(),
            Some(std::io::ErrorKind::PermissionDenied)
        );
        assert!(backend.list_tasks().await.is_empty());
    }
}
