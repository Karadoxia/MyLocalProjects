//! Shared types for Bombina
//! 
//! Common data structures used across the application.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Target type for pentest operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TargetType {
    /// Single IP address
    IpAddress,
    /// IP range in CIDR notation
    IpRange,
    /// Domain name
    Domain,
    /// Full URL
    Url,
    /// Hostname
    Hostname,
}

/// Target information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Target {
    /// Raw value entered by user
    pub value: String,
    /// Detected target type
    pub target_type: TargetType,
    /// Whether target is in scope
    pub in_scope: bool,
    /// Optional notes
    pub notes: Option<String>,
}

impl Target {
    /// Parse a target string and detect its type
    pub fn parse(value: &str) -> Self {
        let value = value.trim().to_string();
        let target_type = Self::detect_type(&value);
        
        Self {
            value,
            target_type,
            in_scope: false, // Must be validated by policy engine
            notes: None,
        }
    }

    fn detect_type(value: &str) -> TargetType {
        // Check for URL
        if value.starts_with("http://") || value.starts_with("https://") {
            return TargetType::Url;
        }

        // Check for CIDR notation
        if value.contains('/') {
            if let Some((ip_part, _)) = value.split_once('/') {
                if Self::is_ip_address(ip_part) {
                    return TargetType::IpRange;
                }
            }
        }

        // Check for IP address
        if Self::is_ip_address(value) {
            return TargetType::IpAddress;
        }

        // Check for domain (contains dots, no spaces)
        if value.contains('.') && !value.contains(' ') {
            return TargetType::Domain;
        }

        // Default to hostname
        TargetType::Hostname
    }

    fn is_ip_address(value: &str) -> bool {
        // Simple IPv4 check
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() == 4 {
            return parts.iter().all(|p| p.parse::<u8>().is_ok());
        }
        // IPv6 check (simplified)
        value.contains(':') && value.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
    }
}

/// Chat message role
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    System,
    User,
    Assistant,
}

/// A single chat message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
}

impl ChatMessage {
    pub fn user(content: &str) -> Self {
        Self {
            role: ChatRole::User,
            content: content.to_string(),
        }
    }

    pub fn assistant(content: &str) -> Self {
        Self {
            role: ChatRole::Assistant,
            content: content.to_string(),
        }
    }

    pub fn system(content: &str) -> Self {
        Self {
            role: ChatRole::System,
            content: content.to_string(),
        }
    }
}

/// Generate request for Ollama
#[derive(Debug, Serialize)]
pub struct GenerateRequest {
    pub model: String,
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<serde_json::Value>,
}

/// Generate response from Ollama
#[derive(Debug, Deserialize)]
pub struct GenerateResponse {
    pub response: String,
    #[serde(default)]
    pub done: bool,
    #[serde(default)]
    pub context: Vec<i64>,
    #[serde(default)]
    pub total_duration: u64,
    #[serde(default)]
    pub load_duration: u64,
    #[serde(default)]
    pub eval_count: u32,
    #[serde(default)]
    pub eval_duration: u64,
}

/// Model information from Ollama
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub name: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub modified_at: Option<String>,
}

/// Tool execution result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolResult {
    /// Tool name that was executed
    pub tool: String,
    /// Command that was run
    pub command: String,
    /// Exit code (0 = success)
    pub exit_code: i32,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl ToolResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Risk level for actions
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

/// Pentest finding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub severity: RiskLevel,
    pub target: String,
    pub evidence: Vec<String>,
    pub recommendations: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub cwe: Option<String>,
    pub cvss: Option<f32>,
    pub timestamp: DateTime<Utc>,
}

impl Finding {
    pub fn new(title: &str, description: &str, severity: RiskLevel, target: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.to_string(),
            description: description.to_string(),
            severity,
            target: target.to_string(),
            evidence: Vec::new(),
            recommendations: Vec::new(),
            mitre_techniques: Vec::new(),
            cwe: None,
            cvss: None,
            timestamp: Utc::now(),
        }
    }
}

/// Application state that can be serialized
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    pub current_target: Option<Target>,
    pub messages: Vec<ChatMessage>,
    pub findings: Vec<Finding>,
    pub tool_history: Vec<ToolResult>,
    pub selected_model: String,
    pub session_id: Uuid,
    pub started_at: DateTime<Utc>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            current_target: None,
            messages: Vec::new(),
            findings: Vec::new(),
            tool_history: Vec::new(),
            selected_model: crate::DEFAULT_MODEL.to_string(),
            session_id: Uuid::new_v4(),
            started_at: Utc::now(),
        }
    }
}
