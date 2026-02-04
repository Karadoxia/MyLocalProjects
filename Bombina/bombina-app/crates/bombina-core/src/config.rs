//! Configuration management for Bombina
//! 
//! Handles loading, saving, and managing application configuration.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BombinaConfig {
    /// Ollama server settings
    pub ollama: OllamaConfig,
    /// UI preferences
    pub ui: UiConfig,
    /// Security/policy settings
    pub security: SecurityConfig,
    /// Tool settings
    pub tools: ToolsConfig,
    /// Logging settings
    pub logging: LoggingConfig,
}

/// Ollama connection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaConfig {
    /// Ollama API URL
    pub url: String,
    /// Default model to use
    pub default_model: String,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Context window size
    pub num_ctx: u32,
    /// Max tokens to generate
    pub num_predict: u32,
    /// Temperature for generation
    pub temperature: f32,
}

/// UI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Dark mode enabled
    pub dark_mode: bool,
    /// Font size
    pub font_size: u8,
    /// Window width
    pub window_width: u32,
    /// Window height
    pub window_height: u32,
    /// Show timestamps in chat
    pub show_timestamps: bool,
    /// Enable streaming responses
    pub streaming: bool,
}

/// Security and policy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Require target scope validation
    pub require_scope: bool,
    /// Allowed IP ranges (CIDR notation)
    pub allowed_ranges: Vec<String>,
    /// Allowed domains
    pub allowed_domains: Vec<String>,
    /// Max risk level allowed
    pub max_risk_level: String,
    /// Enable audit logging
    pub audit_logging: bool,
    /// Require confirmation for high-risk actions
    pub confirm_high_risk: bool,
}

/// Tool execution settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsConfig {
    /// Enable tool execution
    pub enabled: bool,
    /// Path to tools directory
    pub tools_path: Option<String>,
    /// Allowed tools list
    pub allowed_tools: Vec<String>,
    /// Tool execution timeout in seconds
    pub timeout_secs: u64,
}

/// Logging settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Log to file
    pub file_logging: bool,
    /// Log file path
    pub log_path: Option<String>,
    /// Keep session logs
    pub session_logs: bool,
}

impl Default for BombinaConfig {
    fn default() -> Self {
        Self {
            ollama: OllamaConfig {
                url: "http://localhost:11434".to_string(),
                default_model: "bombina-stable".to_string(),
                timeout_secs: 120,
                num_ctx: 2048,
                num_predict: 1024,
                temperature: 0.7,
            },
            ui: UiConfig {
                dark_mode: true,
                font_size: 14,
                window_width: 1200,
                window_height: 800,
                show_timestamps: true,
                streaming: false, // Disabled by default for CPU mode
            },
            security: SecurityConfig {
                require_scope: true,
                allowed_ranges: vec![
                    "10.0.0.0/8".to_string(),
                    "172.16.0.0/12".to_string(),
                    "192.168.0.0/16".to_string(),
                ],
                allowed_domains: Vec::new(),
                max_risk_level: "HIGH".to_string(),
                audit_logging: true,
                confirm_high_risk: true,
            },
            tools: ToolsConfig {
                enabled: true,
                tools_path: None,
                allowed_tools: vec![
                    "nmap".to_string(),
                    "gobuster".to_string(),
                    "whois".to_string(),
                    "dig".to_string(),
                    "curl".to_string(),
                    "nikto".to_string(),
                ],
                timeout_secs: 300,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_logging: true,
                log_path: None,
                session_logs: true,
            },
        }
    }
}

impl BombinaConfig {
    /// Load configuration from file or create default
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;
        
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)
                .context("Failed to read config file")?;
            let config: Self = toml::from_str(&content)
                .context("Failed to parse config file")?;
            info!("Loaded configuration from {:?}", config_path);
            Ok(config)
        } else {
            let config = Self::default();
            config.save()?;
            info!("Created default configuration at {:?}", config_path);
            Ok(config)
        }
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;
        
        // Ensure directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create config directory")?;
        }

        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;
        
        std::fs::write(&config_path, content)
            .context("Failed to write config file")?;
        
        Ok(())
    }

    /// Get the configuration file path
    pub fn config_path() -> Result<PathBuf> {
        let proj_dirs = ProjectDirs::from("com", "bombina", "bombina-app")
            .context("Failed to determine config directory")?;
        
        Ok(proj_dirs.config_dir().join("config.toml"))
    }

    /// Get the data directory path
    pub fn data_dir() -> Result<PathBuf> {
        let proj_dirs = ProjectDirs::from("com", "bombina", "bombina-app")
            .context("Failed to determine data directory")?;
        
        Ok(proj_dirs.data_dir().to_path_buf())
    }

    /// Get the sessions directory path
    pub fn sessions_dir() -> Result<PathBuf> {
        let data_dir = Self::data_dir()?;
        let sessions_dir = data_dir.join("sessions");
        std::fs::create_dir_all(&sessions_dir)?;
        Ok(sessions_dir)
    }

    /// Get the logs directory path
    pub fn logs_dir() -> Result<PathBuf> {
        let data_dir = Self::data_dir()?;
        let logs_dir = data_dir.join("logs");
        std::fs::create_dir_all(&logs_dir)?;
        Ok(logs_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BombinaConfig::default();
        assert_eq!(config.ollama.default_model, "bombina-stable");
        assert!(config.ui.dark_mode);
        assert!(config.security.require_scope);
    }

    #[test]
    fn test_config_serialization() {
        let config = BombinaConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: BombinaConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.ollama.url, parsed.ollama.url);
    }
}
