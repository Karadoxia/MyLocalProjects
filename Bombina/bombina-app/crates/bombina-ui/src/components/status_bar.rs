//! Status Bar Component

use dioxus::prelude::*;

/// Status bar props
#[derive(Props, Clone, PartialEq)]
pub struct StatusBarProps {
    /// Ollama connection status
    pub ollama_connected: bool,
    /// Current target
    pub target: Option<String>,
    /// Current model
    pub model: String,
    /// Session name
    pub session_name: Option<String>,
    /// Message count
    #[props(default = 0)]
    pub message_count: usize,
    /// Finding count  
    #[props(default = 0)]
    pub finding_count: usize,
}

/// Status bar component
#[component]
pub fn StatusBar(props: StatusBarProps) -> Element {
    let status_color = if props.ollama_connected { "#4ecca3" } else { "#ff6b6b" };
    let status_text = if props.ollama_connected { "Connected" } else { "Disconnected" };
    
    rsx! {
        footer {
            class: "status-bar",
            style: "display: flex; align-items: center; justify-content: space-between; padding: 8px 16px; background: #0a0a1a; border-top: 1px solid #333; font-size: 12px; color: #888;",

            // Left section
            div {
                style: "display: flex; align-items: center; gap: 16px;",

                // Ollama status
                div {
                    style: "display: flex; align-items: center; gap: 6px;",
                    span {
                        style: "width: 6px; height: 6px; border-radius: 50%; background: {status_color};",
                    }
                    span { "Ollama: {status_text}" }
                }

                // Divider
                span { style: "color: #333;", "|" }

                // Model
                div {
                    style: "display: flex; align-items: center; gap: 6px;",
                    span { "🤖" }
                    span { "{props.model}" }
                }

                // Divider
                span { style: "color: #333;", "|" }

                // Target
                div {
                    style: "display: flex; align-items: center; gap: 6px;",
                    span { "🎯" }
                    if let Some(target) = &props.target {
                        span { style: "color: #4ecca3;", "{target}" }
                    } else {
                        span { style: "color: #666;", "No target" }
                    }
                }
            }

            // Right section
            div {
                style: "display: flex; align-items: center; gap: 16px;",

                // Session info
                if let Some(session) = &props.session_name {
                    div {
                        style: "display: flex; align-items: center; gap: 6px;",
                        span { "📁" }
                        span { "{session}" }
                    }
                }

                // Message count
                div {
                    style: "display: flex; align-items: center; gap: 6px;",
                    span { "💬" }
                    span { "{props.message_count} msgs" }
                }

                // Finding count
                div {
                    style: "display: flex; align-items: center; gap: 6px;",
                    span { "🔍" }
                    span { "{props.finding_count} findings" }
                }
            }
        }
    }
}
