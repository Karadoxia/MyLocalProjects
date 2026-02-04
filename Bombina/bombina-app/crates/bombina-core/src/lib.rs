//! Bombina Core Library
//! 
//! Platform-agnostic core logic for the Bombina pentest AI assistant.
//! Handles Ollama API communication, session management, and configuration.

pub mod ollama;
pub mod config;
pub mod session;
pub mod types;
pub mod policy;

pub use ollama::OllamaClient;
pub use config::BombinaConfig;
pub use session::{Session, SessionManager};
pub use types::*;
pub use policy::PolicyEngine;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default Ollama endpoint
pub const DEFAULT_OLLAMA_URL: &str = "http://localhost:11434";

/// Default model name
pub const DEFAULT_MODEL: &str = "bombina-stable";

/// Available Bombina models
pub const AVAILABLE_MODELS: &[&str] = &[
    "bombina-stable",
    "bombina-enhanced", 
    "bombina-ultimate",
    "bombina",
    "qwen2.5-coder:3b",
];
