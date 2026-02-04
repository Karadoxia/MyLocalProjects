//! Tool executor - runs tools safely in a controlled environment

use crate::common::{ToolDefinition, ToolError, ToolResult, default_tools};
use chrono::Utc;
use std::collections::HashMap;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, error, info};

/// Tool executor with sandboxing and timeout support
pub struct ToolExecutor {
    /// Available tools
    tools: HashMap<String, ToolDefinition>,
    /// Allowed tools (subset of available)
    allowed: Vec<String>,
    /// Default timeout
    default_timeout: Duration,
    /// Working directory
    working_dir: Option<String>,
}

impl ToolExecutor {
    /// Create new executor with default tools
    pub fn new() -> Self {
        let tools: HashMap<String, ToolDefinition> = default_tools()
            .into_iter()
            .map(|t| (t.name.clone(), t))
            .collect();
        
        let allowed: Vec<String> = tools.keys().cloned().collect();

        Self {
            tools,
            allowed,
            default_timeout: Duration::from_secs(300),
            working_dir: None,
        }
    }

    /// Set allowed tools
    pub fn with_allowed(mut self, allowed: Vec<String>) -> Self {
        self.allowed = allowed;
        self
    }

    /// Set default timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Set working directory
    pub fn with_working_dir(mut self, dir: &str) -> Self {
        self.working_dir = Some(dir.to_string());
        self
    }

    /// Check if a tool is available
    pub fn is_available(&self, name: &str) -> bool {
        self.tools.contains_key(name) && self.allowed.contains(&name.to_string())
    }

    /// Get tool definition
    pub fn get_tool(&self, name: &str) -> Option<&ToolDefinition> {
        self.tools.get(name)
    }

    /// Execute a tool command
    pub async fn execute(&self, command: &str) -> Result<ToolResult, ToolError> {
        // Parse command
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return Err(ToolError::ExecutionFailed("Empty command".to_string()));
        }

        let tool_name = parts[0];
        let args = &parts[1..];

        // Check if tool is allowed
        if !self.is_available(tool_name) {
            return Err(ToolError::NotAllowed(tool_name.to_string()));
        }

        let tool = self.tools.get(tool_name)
            .ok_or_else(|| ToolError::NotFound(tool_name.to_string()))?;

        info!("Executing: {} {:?}", tool.binary, args);
        let start = Instant::now();

        // Build command
        let mut cmd = Command::new(&tool.binary);
        cmd.args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        // Execute with timeout
        let timeout_duration = Duration::from_secs(tool.timeout_secs);
        let result = timeout(timeout_duration, cmd.output()).await;

        let duration = start.elapsed();

        match result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let exit_code = output.status.code().unwrap_or(-1);

                debug!("Tool {} completed with exit code {}", tool_name, exit_code);

                Ok(ToolResult {
                    tool: tool_name.to_string(),
                    command: command.to_string(),
                    exit_code,
                    stdout,
                    stderr,
                    duration_ms: duration.as_millis() as u64,
                    timestamp: Utc::now(),
                    parsed: None,
                })
            }
            Ok(Err(e)) => {
                error!("Tool execution failed: {}", e);
                Err(ToolError::ExecutionFailed(e.to_string()))
            }
            Err(_) => {
                error!("Tool {} timed out after {} seconds", tool_name, tool.timeout_secs);
                Err(ToolError::Timeout(tool.timeout_secs))
            }
        }
    }

    /// Check if a binary exists on the system
    pub async fn check_binary(&self, name: &str) -> bool {
        Command::new("which")
            .arg(name)
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Get list of available tools
    pub fn list_tools(&self) -> Vec<&ToolDefinition> {
        self.allowed
            .iter()
            .filter_map(|name| self.tools.get(name))
            .collect()
    }
}

impl Default for ToolExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_executor_creation() {
        let executor = ToolExecutor::new();
        assert!(executor.is_available("nmap"));
        assert!(executor.is_available("curl"));
    }

    #[tokio::test]
    async fn test_disallowed_tool() {
        let executor = ToolExecutor::new().with_allowed(vec!["curl".to_string()]);
        assert!(!executor.is_available("nmap"));
        assert!(executor.is_available("curl"));
    }
}
