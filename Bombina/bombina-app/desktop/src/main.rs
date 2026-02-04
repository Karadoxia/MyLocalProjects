//! Bombina Desktop Application
//! 
//! Cross-platform AI-powered penetration testing assistant.

#![allow(non_snake_case)]

use dioxus::prelude::*;
use dioxus_desktop::{Config, WindowBuilder, LogicalSize};
use bombina_core::{OllamaClient, BombinaConfig, PolicyEngine};
use bombina_core::types::{ChatMessage, Target, ChatRole};
use bombina_ui::{
    Sidebar, Header, StatusBar, ChatPanel, TargetInput, ToolsPanel,
    HomePage, PentestPage,
    Theme,
    state::{AppState, Page},
};
use tracing::{info, error, warn};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Main application entry point
fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting Bombina Desktop Application");

    // Launch Dioxus desktop app
    dioxus_desktop::launch::launch(App, vec![], 
        Config::new()
            .with_window(
                WindowBuilder::new()
                    .with_title("🐸 Bombina - Pentest AI")
                    .with_inner_size(LogicalSize::new(1400.0, 900.0))
                    .with_min_inner_size(LogicalSize::new(800.0, 600.0))
            )
.with_custom_head(CUSTOM_HEAD.to_string()),
    );
}

/// Custom HTML head with styles
const CUSTOM_HEAD: &str = r#"
<style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    :root {
        --background: #0f0f23;
        --surface: #1a1a2e;
        --primary-color: #4ecca3;
        --secondary-color: #4d96ff;
        --text-color: #eeeeee;
        --text-muted: #888888;
        --border-color: #333333;
        --success-color: #4ecca3;
        --warning-color: #ffd93d;
        --error-color: #ff6b6b;
        --info-color: #4d96ff;
        --header-bg: #0f0f23;
        --sidebar-bg: #1a1a2e;
        --card-bg: #1a1a2e;
        --input-bg: #0f0f23;
        --chat-bg: #16213e;
        --statusbar-bg: #0a0a1a;
        --message-user-bg: #4ecca3;
        --message-assistant-bg: #1a1a2e;
        --message-system-bg: #333333;
    }

    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
        background: var(--background);
        color: var(--text-color);
        overflow: hidden;
    }

    button:hover {
        opacity: 0.9;
    }

    input:focus, textarea:focus {
        border-color: var(--primary-color) !important;
    }

    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }

    ::-webkit-scrollbar-track {
        background: var(--background);
    }

    ::-webkit-scrollbar-thumb {
        background: var(--border-color);
        border-radius: 4px;
    }

    ::-webkit-scrollbar-thumb:hover {
        background: var(--text-muted);
    }

    @keyframes bounce {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-4px); }
    }

    .sidebar-item:hover {
        background: rgba(78, 204, 163, 0.1) !important;
    }

    .tool-item:hover {
        background: rgba(78, 204, 163, 0.1) !important;
        border-color: var(--border-color) !important;
    }

    code {
        font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    }
</style>
"#;

/// Main App component
#[component]
fn App() -> Element {
    // Application state
    let mut state = use_signal(AppState::default);
    let mut ollama_client = use_signal(|| OllamaClient::default_local());
    let mut policy_engine = use_signal(|| PolicyEngine::default_security());

    // Check Ollama connection on startup
    use_future(move || {
        let client = ollama_client.read().clone();
        async move {
            match client.health_check().await {
                Ok(true) => {
                    info!("Connected to Ollama");
                    state.write().ollama_connected = true;
                }
                _ => {
                    warn!("Could not connect to Ollama");
                    state.write().ollama_connected = false;
                }
            }
        }
    });

    // Handle navigation
    let handle_nav = move |page_id: String| {
        state.write().set_page_from_id(&page_id);
    };

    // Handle new session
    let handle_new_session = move |name: String| {
        state.write().new_session(&name);
        info!("Created new session: {}", name);
    };

    // Handle target change
    let handle_target_change = move |value: String| {
        state.write().target_input = value;
    };

    // Handle target submit
    let handle_target_submit = {
        move |target: Target| {
            let result = policy_engine.write().validate_target(&target);
            state.write().set_target(
                target.clone(),
                result.allowed,
                Some(result.reason.clone()),
            );
            
            if result.allowed {
                info!("Target set: {}", target.value);
            } else {
                warn!("Target rejected: {}", result.reason);
            }
        }
    };

    // Handle send message
    let handle_send_message = {
        let ollama = ollama_client.read().clone();
        move |content: String| {
            let ollama = ollama.clone();
            
            // Add user message
            state.write().add_user_message(&content);
            state.write().is_loading = true;

            // Get context
            let target_context = state.read().current_target.as_ref()
                .map(|t| format!("Current target: {}", t.value));

            spawn(async move {
                match ollama.pentest_query(&content, target_context.as_deref()).await {
                    Ok(response) => {
                        state.write().add_assistant_message(&response);
                    }
                    Err(e) => {
                        error!("Ollama error: {}", e);
                        state.write().add_assistant_message(
                            &format!("⚠️ Error communicating with AI: {}", e)
                        );
                    }
                }
                state.write().is_loading = false;
            });
        }
    };

    // Handle tool select
    let handle_tool_select = move |(tool_id, command): (String, String)| {
        info!("Tool selected: {} -> {}", tool_id, command);
    };

    // Handle tool execute
    let handle_tool_execute = move |command: String| {
        info!("Executing tool: {}", command);
        state.write().is_executing = true;
        
        // Add message about tool execution
        state.write().add_assistant_message(
            &format!("🔧 Executing: `{}`\n\n_Tool execution coming soon..._", command)
        );
        
        state.write().is_executing = false;
    };

    // Handle theme toggle
    let handle_toggle_theme = move |_| {
        let current = state.read().dark_mode;
        state.write().dark_mode = !current;
    };

    // Handle settings
    let handle_settings = move |_| {
        let current = state.read().show_settings;
        state.write().show_settings = !current;
    };

    let current_state = state.read();

    rsx! {
        div {
            class: "app-container",
            style: "
                display: flex;
                flex-direction: column;
                height: 100vh;
                background: var(--background);
            ",

            // Header
            Header {
                is_connected: current_state.ollama_connected,
                model_name: current_state.selected_model.clone(),
                dark_mode: current_state.dark_mode,
                on_toggle_theme: handle_toggle_theme,
                on_settings: handle_settings,
            }

            // Main content area
            div {
                style: "
                    display: flex;
                    flex: 1;
                    min-height: 0;
                ",

                // Sidebar
                Sidebar {
                    selected: current_state.page_id().to_string(),
                    on_select: handle_nav,
                    collapsed: current_state.sidebar_collapsed,
                }

                // Main content
                main {
                    style: "
                        flex: 1;
                        min-width: 0;
                        overflow: hidden;
                    ",

                    match current_state.current_page {
                        Page::Home => rsx! {
                            HomePage {
                                on_new_session: handle_new_session,
                                recent_sessions: vec![],
                                on_load_session: move |_| {},
                            }
                        },
                        Page::Scan | Page::Enumerate | Page::Attack => rsx! {
                            PentestPage {
                                target_value: current_state.target_input.clone(),
                                current_target: current_state.current_target.clone(),
                                messages: current_state.messages.clone(),
                                is_loading: current_state.is_loading,
                                is_executing: current_state.is_executing,
                                target_validation: current_state.target_validation.clone(),
                                target_valid: current_state.target_valid,
                                on_target_change: handle_target_change,
                                on_target_submit: handle_target_submit,
                                on_send_message: handle_send_message,
                                on_tool_select: handle_tool_select,
                                on_tool_execute: handle_tool_execute,
                            }
                        },
                        _ => rsx! {
                            div {
                                style: "
                                    display: flex;
                                    align-items: center;
                                    justify-content: center;
                                    height: 100%;
                                    color: var(--text-muted);
                                ",
                                p { "🚧 This page is under construction" }
                            }
                        }
                    }
                }
            }

            // Status bar
            StatusBar {
                ollama_connected: current_state.ollama_connected,
                target: current_state.current_target.as_ref().map(|t| t.value.clone()),
                model: current_state.selected_model.clone(),
                session_name: current_state.session.as_ref().map(|s| s.name.clone()),
                message_count: current_state.messages.len(),
                finding_count: current_state.findings.len(),
            }
        }
    }
}
