//! Common types and utilities for tools

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Tool execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Tool name
    pub tool: String,
    /// Full command that was run
    pub command: String,
    /// Exit code (0 = success)
    pub exit_code: i32,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Parsed output (tool-specific)
    pub parsed: Option<serde_json::Value>,
}

impl ToolResult {
    /// Check if tool executed successfully
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    /// Get combined output
    pub fn output(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else {
            format!("{}\n--- STDERR ---\n{}", self.stdout, self.stderr)
        }
    }
}

/// Tool execution error
#[derive(Debug, Error)]
pub enum ToolError {
    #[error("Tool not found: {0}")]
    NotFound(String),

    #[error("Tool not allowed: {0}")]
    NotAllowed(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Timeout after {0} seconds")]
    Timeout(u64),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Tool name
    pub name: String,
    /// Binary name
    pub binary: String,
    /// Description
    pub description: String,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Default timeout in seconds
    pub timeout_secs: u64,
    /// Required for tool to work
    pub requires_root: bool,
}

/// Risk level for tools
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Info => write!(f, "INFO"),
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Common tool definitions
pub fn default_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "nmap".to_string(),
            binary: "nmap".to_string(),
            description: "Network scanner".to_string(),
            risk_level: RiskLevel::Low,
            timeout_secs: 300,
            requires_root: false,
        },
        ToolDefinition {
            name: "gobuster".to_string(),
            binary: "gobuster".to_string(),
            description: "Directory/file brute-forcer".to_string(),
            risk_level: RiskLevel::Medium,
            timeout_secs: 600,
            requires_root: false,
        },
        ToolDefinition {
            name: "nikto".to_string(),
            binary: "nikto".to_string(),
            description: "Web server scanner".to_string(),
            risk_level: RiskLevel::Medium,
            timeout_secs: 600,
            requires_root: false,
        },
        ToolDefinition {
            name: "whois".to_string(),
            binary: "whois".to_string(),
            description: "Domain lookup".to_string(),
            risk_level: RiskLevel::Info,
            timeout_secs: 30,
            requires_root: false,
        },
        ToolDefinition {
            name: "dig".to_string(),
            binary: "dig".to_string(),
            description: "DNS lookup".to_string(),
            risk_level: RiskLevel::Info,
            timeout_secs: 30,
            requires_root: false,
        },
        ToolDefinition {
            name: "curl".to_string(),
            binary: "curl".to_string(),
            description: "HTTP client".to_string(),
            risk_level: RiskLevel::Info,
            timeout_secs: 60,
            requires_root: false,
        },
    ]
}
