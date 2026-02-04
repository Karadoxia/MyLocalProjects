//! Header Component

use dioxus::prelude::*;

/// Header props
#[derive(Props, Clone, PartialEq)]
pub struct HeaderProps {
    /// Connection status
    pub is_connected: bool,
    /// Current model name
    pub model_name: String,
    /// Dark mode enabled
    pub dark_mode: bool,
    /// Toggle dark mode callback
    pub on_toggle_theme: EventHandler<()>,
    /// Open settings callback
    pub on_settings: EventHandler<()>,
}

/// Header component
#[component]
pub fn Header(props: HeaderProps) -> Element {
    rsx! {
        header {
            class: "app-header",
            style: "
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 12px 20px;
                background: var(--header-bg, #0f0f23);
                border-bottom: 1px solid var(--border-color, #333);
            ",

            // Left: Logo and title
            div {
                style: "display: flex; align-items: center; gap: 12px;",
                
                span { style: "font-size: 28px;", "🐸" }
                h1 {
                    style: "
                        margin: 0;
                        font-size: 20px;
                        font-weight: 700;
                        color: var(--primary-color, #4ecca3);
                        letter-spacing: 1px;
                    ",
                    "BOMBINA"
                }
                span {
                    style: "
                        padding: 4px 8px;
                        background: var(--badge-bg, #333);
                        border-radius: 4px;
                        font-size: 11px;
                        color: var(--text-muted, #888);
                    ",
                    "Pentest AI"
                }
            }

            // Right: Status and actions
            div {
                style: "display: flex; align-items: center; gap: 16px;",

                // Connection status
                div {
                    style: "display: flex; align-items: center; gap: 8px;",
                    
                    {
                        let bg_color = if props.is_connected { "#4ecca3" } else { "#ff6b6b" };
                        rsx! {
                            span {
                                style: "width: 8px; height: 8px; border-radius: 50%; background: {bg_color}; box-shadow: 0 0 8px {bg_color};",
                            }
                        }
                    }
                    span {
                        style: "font-size: 13px; color: var(--text-muted, #888);",
                        "{props.model_name}"
                    }
                }

                // Theme toggle
                button {
                    style: "
                        padding: 8px;
                        border: none;
                        border-radius: 8px;
                        background: var(--button-bg, #1a1a2e);
                        color: var(--text-color, #eee);
                        cursor: pointer;
                        font-size: 18px;
                    ",
                    title: if props.dark_mode { "Switch to light mode" } else { "Switch to dark mode" },
                    onclick: move |_| props.on_toggle_theme.call(()),
                    
                    if props.dark_mode { "☀️" } else { "🌙" }
                }

                // Settings button
                button {
                    style: "
                        padding: 8px;
                        border: none;
                        border-radius: 8px;
                        background: var(--button-bg, #1a1a2e);
                        color: var(--text-color, #eee);
                        cursor: pointer;
                        font-size: 18px;
                    ",
                    title: "Settings",
                    onclick: move |_| props.on_settings.call(()),
                    "⚙️"
                }

                // Help button
                button {
                    style: "
                        padding: 8px;
                        border: none;
                        border-radius: 8px;
                        background: var(--button-bg, #1a1a2e);
                        color: var(--text-color, #eee);
                        cursor: pointer;
                        font-size: 18px;
                    ",
                    title: "Help",
                    "❓"
                }
            }
        }
    }
}
