//! Session management for Bombina
//! 
//! Handles saving, loading, and managing pentest sessions.

use crate::types::{AppState, ChatMessage, Finding, ToolResult, Target};
use crate::config::BombinaConfig;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;
use tracing::{debug, info};

/// A complete pentest session that can be saved/restored
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Session {
    /// Unique session identifier
    pub id: Uuid,
    /// Session name (user-provided)
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Current target
    pub target: Option<Target>,
    /// Chat history
    pub messages: Vec<ChatMessage>,
    /// Discovered findings
    pub findings: Vec<Finding>,
    /// Tool execution history
    pub tool_history: Vec<ToolResult>,
    /// Model used
    pub model: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub modified_at: DateTime<Utc>,
    /// Session status
    pub status: SessionStatus,
    /// Custom tags
    pub tags: Vec<String>,
}

/// Session status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    Active,
    Paused,
    Completed,
    Archived,
}

impl Session {
    /// Create a new session
    pub fn new(name: &str) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: None,
            target: None,
            messages: Vec::new(),
            findings: Vec::new(),
            tool_history: Vec::new(),
            model: crate::DEFAULT_MODEL.to_string(),
            created_at: now,
            modified_at: now,
            status: SessionStatus::Active,
            tags: Vec::new(),
        }
    }

    /// Add a chat message
    pub fn add_message(&mut self, message: ChatMessage) {
        self.messages.push(message);
        self.modified_at = Utc::now();
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
        self.modified_at = Utc::now();
    }

    /// Add a tool result
    pub fn add_tool_result(&mut self, result: ToolResult) {
        self.tool_history.push(result);
        self.modified_at = Utc::now();
    }

    /// Set target
    pub fn set_target(&mut self, target: Target) {
        self.target = Some(target);
        self.modified_at = Utc::now();
    }

    /// Convert to AppState for UI
    pub fn to_app_state(&self) -> AppState {
        AppState {
            current_target: self.target.clone(),
            messages: self.messages.clone(),
            findings: self.findings.clone(),
            tool_history: self.tool_history.clone(),
            selected_model: self.model.clone(),
            session_id: self.id,
            started_at: self.created_at,
        }
    }

    /// Get session file path
    fn file_path(&self) -> Result<PathBuf> {
        let sessions_dir = BombinaConfig::sessions_dir()?;
        Ok(sessions_dir.join(format!("{}.json", self.id)))
    }

    /// Save session to disk
    pub fn save(&self) -> Result<()> {
        let path = self.file_path()?;
        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize session")?;
        std::fs::write(&path, content)
            .context("Failed to write session file")?;
        debug!("Saved session {} to {:?}", self.id, path);
        Ok(())
    }

    /// Load session from disk
    pub fn load(id: Uuid) -> Result<Self> {
        let sessions_dir = BombinaConfig::sessions_dir()?;
        let path = sessions_dir.join(format!("{}.json", id));
        let content = std::fs::read_to_string(&path)
            .context("Failed to read session file")?;
        let session: Self = serde_json::from_str(&content)
            .context("Failed to parse session file")?;
        debug!("Loaded session {} from {:?}", id, path);
        Ok(session)
    }
}

/// Manages multiple sessions
pub struct SessionManager {
    /// Currently active session
    current: Option<Session>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self { current: None }
    }

    /// Create and set a new session
    pub fn new_session(&mut self, name: &str) -> &Session {
        let session = Session::new(name);
        info!("Created new session: {} ({})", name, session.id);
        self.current = Some(session);
        self.current.as_ref().unwrap()
    }

    /// Get current session
    pub fn current(&self) -> Option<&Session> {
        self.current.as_ref()
    }

    /// Get current session mutably
    pub fn current_mut(&mut self) -> Option<&mut Session> {
        self.current.as_mut()
    }

    /// Load an existing session
    pub fn load_session(&mut self, id: Uuid) -> Result<&Session> {
        let session = Session::load(id)?;
        info!("Loaded session: {} ({})", session.name, session.id);
        self.current = Some(session);
        Ok(self.current.as_ref().unwrap())
    }

    /// Save current session
    pub fn save_current(&self) -> Result<()> {
        if let Some(session) = &self.current {
            session.save()?;
        }
        Ok(())
    }

    /// List all saved sessions
    pub fn list_sessions() -> Result<Vec<SessionSummary>> {
        let sessions_dir = BombinaConfig::sessions_dir()?;
        let mut summaries = Vec::new();

        for entry in std::fs::read_dir(&sessions_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().map_or(false, |e| e == "json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(session) = serde_json::from_str::<Session>(&content) {
                        summaries.push(SessionSummary {
                            id: session.id,
                            name: session.name,
                            status: session.status,
                            target: session.target.map(|t| t.value),
                            message_count: session.messages.len(),
                            finding_count: session.findings.len(),
                            created_at: session.created_at,
                            modified_at: session.modified_at,
                        });
                    }
                }
            }
        }

        // Sort by modified date, newest first
        summaries.sort_by(|a, b| b.modified_at.cmp(&a.modified_at));
        Ok(summaries)
    }

    /// Delete a session
    pub fn delete_session(id: Uuid) -> Result<()> {
        let sessions_dir = BombinaConfig::sessions_dir()?;
        let path = sessions_dir.join(format!("{}.json", id));
        std::fs::remove_file(&path)?;
        info!("Deleted session: {}", id);
        Ok(())
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of a session for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: Uuid,
    pub name: String,
    pub status: SessionStatus,
    pub target: Option<String>,
    pub message_count: usize,
    pub finding_count: usize,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new("Test Pentest");
        assert_eq!(session.name, "Test Pentest");
        assert_eq!(session.status, SessionStatus::Active);
        assert!(session.messages.is_empty());
    }

    #[test]
    fn test_session_manager() {
        let mut manager = SessionManager::new();
        manager.new_session("My Pentest");
        assert!(manager.current().is_some());
    }
}
