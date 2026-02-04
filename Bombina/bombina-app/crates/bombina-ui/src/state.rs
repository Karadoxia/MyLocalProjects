//! Application state management

use bombina_core::types::{ChatMessage, Target, Finding, ToolResult};
use bombina_core::session::Session;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Main application state
#[derive(Clone, PartialEq)]
pub struct AppState {
    /// Current page/view
    pub current_page: Page,
    /// Current session
    pub session: Option<Session>,
    /// Current target
    pub current_target: Option<Target>,
    /// Target input value
    pub target_input: String,
    /// Target validation message
    pub target_validation: Option<String>,
    /// Whether target is valid
    pub target_valid: bool,
    /// Chat messages
    pub messages: Vec<ChatMessage>,
    /// Findings
    pub findings: Vec<Finding>,
    /// Tool history
    pub tool_history: Vec<ToolResult>,
    /// Is AI loading
    pub is_loading: bool,
    /// Is tool executing
    pub is_executing: bool,
    /// Selected model
    pub selected_model: String,
    /// Ollama connected
    pub ollama_connected: bool,
    /// Dark mode
    pub dark_mode: bool,
    /// Sidebar collapsed
    pub sidebar_collapsed: bool,
    /// Show settings modal
    pub show_settings: bool,
}

/// Application pages/views
#[derive(Clone, PartialEq, Eq)]
pub enum Page {
    Home,
    Scan,
    Enumerate,
    Attack,
    Reports,
    History,
    Tools,
    Settings,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            current_page: Page::Home,
            session: None,
            current_target: None,
            target_input: String::new(),
            target_validation: None,
            target_valid: true,
            messages: Vec::new(),
            findings: Vec::new(),
            tool_history: Vec::new(),
            is_loading: false,
            is_executing: false,
            selected_model: "bombina-stable".to_string(),
            ollama_connected: false,
            dark_mode: true,
            sidebar_collapsed: false,
            show_settings: false,
        }
    }
}

impl AppState {
    /// Create new state
    pub fn new() -> Self {
        Self::default()
    }

    /// Navigate to page
    pub fn navigate(&mut self, page: Page) {
        self.current_page = page;
    }

    /// Set target
    pub fn set_target(&mut self, target: Target, valid: bool, message: Option<String>) {
        self.target_input = target.value.clone();
        self.current_target = Some(target);
        self.target_valid = valid;
        self.target_validation = message;
    }

    /// Add user message
    pub fn add_user_message(&mut self, content: &str) {
        self.messages.push(ChatMessage::user(content));
    }

    /// Add assistant message
    pub fn add_assistant_message(&mut self, content: &str) {
        self.messages.push(ChatMessage::assistant(content));
    }

    /// Clear chat
    pub fn clear_chat(&mut self) {
        self.messages.clear();
    }

    /// Start new session
    pub fn new_session(&mut self, name: &str) {
        let session = Session::new(name);
        self.session = Some(session);
        self.current_page = Page::Scan;
        self.clear_chat();
        self.current_target = None;
        self.target_input = String::new();
        self.findings.clear();
        self.tool_history.clear();
    }

    /// Get page id for sidebar
    pub fn page_id(&self) -> &'static str {
        match self.current_page {
            Page::Home => "home",
            Page::Scan => "scan",
            Page::Enumerate => "enum",
            Page::Attack => "attack",
            Page::Reports => "report",
            Page::History => "history",
            Page::Tools => "tools",
            Page::Settings => "settings",
        }
    }

    /// Set page from id
    pub fn set_page_from_id(&mut self, id: &str) {
        self.current_page = match id {
            "home" => Page::Home,
            "scan" => Page::Scan,
            "enum" => Page::Enumerate,
            "attack" => Page::Attack,
            "report" => Page::Reports,
            "history" => Page::History,
            "tools" => Page::Tools,
            "settings" => Page::Settings,
            _ => Page::Home,
        };
    }
}
