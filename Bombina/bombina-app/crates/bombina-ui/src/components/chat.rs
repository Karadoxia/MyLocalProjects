//! Chat Panel Component
//! 
//! Main chat interface for interacting with Bombina AI.

use dioxus::prelude::*;
use bombina_core::types::{ChatMessage, ChatRole};
use chrono::{DateTime, Utc};

/// Chat panel props
#[derive(Props, Clone, PartialEq)]
pub struct ChatPanelProps {
    /// Chat messages
    pub messages: Vec<ChatMessage>,
    /// Whether AI is currently thinking
    #[props(default = false)]
    pub is_loading: bool,
    /// Callback when user sends a message
    pub on_send: EventHandler<String>,
    /// Show timestamps
    #[props(default = true)]
    pub show_timestamps: bool,
}

/// Chat panel component
#[component]
pub fn ChatPanel(props: ChatPanelProps) -> Element {
    let mut input_value = use_signal(|| String::new());
    
    let handle_send = move |_| {
        let value = input_value.read().trim().to_string();
        if !value.is_empty() {
            props.on_send.call(value);
            input_value.set(String::new());
        }
    };

    let handle_keypress = move |evt: KeyboardEvent| {
        if evt.key() == Key::Enter && !evt.modifiers().shift() {
            let value = input_value.read().trim().to_string();
            if !value.is_empty() {
                props.on_send.call(value);
                input_value.set(String::new());
            }
        }
    };
    
    rsx! {
        div {
            class: "chat-panel",
            style: "
                display: flex;
                flex-direction: column;
                height: 100%;
                background: var(--chat-bg, #16213e);
                border-radius: 8px;
                overflow: hidden;
            ",

            // Messages area
            div {
                class: "chat-messages",
                style: "
                    flex: 1;
                    overflow-y: auto;
                    padding: 16px;
                    display: flex;
                    flex-direction: column;
                    gap: 16px;
                ",

                if props.messages.is_empty() {
                    // Empty state
                    div {
                        style: "
                            display: flex;
                            flex-direction: column;
                            align-items: center;
                            justify-content: center;
                            height: 100%;
                            color: var(--text-muted, #888);
                        ",
                        span { style: "font-size: 48px;", "🐸" }
                        p { style: "margin-top: 16px; font-size: 16px;", "Hello! I'm Bombina, your pentest AI assistant." }
                        p { style: "font-size: 14px;", "Set a target and ask me anything about penetration testing." }
                    }
                } else {
                    for (idx, msg) in props.messages.iter().enumerate() {
                        ChatMessageComponent {
                            key: "{idx}",
                            message: msg.clone(),
                            show_timestamp: props.show_timestamps,
                        }
                    }
                }

                // Loading indicator
                if props.is_loading {
                    div {
                        style: "
                            display: flex;
                            align-items: center;
                            gap: 8px;
                            padding: 12px 16px;
                            background: var(--message-assistant-bg, #1a1a2e);
                            border-radius: 12px;
                            max-width: 80%;
                        ",
                        span { "🐸" }
                        div {
                            class: "typing-indicator",
                            style: "
                                display: flex;
                                gap: 4px;
                            ",
                            span { style: "animation: bounce 1s infinite;", "●" }
                            span { style: "animation: bounce 1s infinite 0.2s;", "●" }
                            span { style: "animation: bounce 1s infinite 0.4s;", "●" }
                        }
                    }
                }
            }

            // Input area
            div {
                class: "chat-input-area",
                style: "
                    padding: 16px;
                    border-top: 1px solid var(--border-color, #333);
                    background: var(--input-bg, #0f0f23);
                ",

                div {
                    style: "
                        display: flex;
                        gap: 8px;
                        align-items: flex-end;
                    ",

                    textarea {
                        class: "chat-input",
                        style: "
                            flex: 1;
                            padding: 12px 16px;
                            border: 1px solid var(--border-color, #333);
                            border-radius: 12px;
                            background: var(--input-field-bg, #1a1a2e);
                            color: var(--text-color, #eee);
                            font-size: 14px;
                            resize: none;
                            min-height: 44px;
                            max-height: 150px;
                            outline: none;
                        ",
                        placeholder: "Ask Bombina anything about pentesting...",
                        value: "{input_value}",
                        rows: "1",
                        disabled: props.is_loading,
                        oninput: move |evt| input_value.set(evt.value()),
                        onkeypress: handle_keypress,
                    }

                    {
                        let btn_opacity = if props.is_loading || input_value.read().trim().is_empty() { "0.5" } else { "1" };
                        rsx! {
                            button {
                                class: "send-button",
                                style: "padding: 12px 20px; border: none; border-radius: 12px; background: #4ecca3; color: #000; font-size: 14px; font-weight: bold; cursor: pointer; transition: opacity 0.2s; opacity: {btn_opacity};",
                                disabled: props.is_loading || input_value.read().trim().is_empty(),
                                onclick: handle_send,
                                "Send"
                            }
                        }
                    }
                }

                // Quick actions
                div {
                    style: "
                        display: flex;
                        gap: 8px;
                        margin-top: 8px;
                        flex-wrap: wrap;
                    ",
                    
                    QuickAction { label: "🔍 Port Scan", on_click: props.on_send.clone(), text: "Perform a port scan on the target" }
                    QuickAction { label: "🌐 Web Enum", on_click: props.on_send.clone(), text: "Enumerate web directories on the target" }
                    QuickAction { label: "📋 Suggest Attack", on_click: props.on_send.clone(), text: "Based on what we know, suggest the best attack path" }
                }
            }
        }
    }
}

/// Quick action button props
#[derive(Props, Clone, PartialEq)]
struct QuickActionProps {
    label: &'static str,
    text: &'static str,
    on_click: EventHandler<String>,
}

/// Quick action button
#[component]
fn QuickAction(props: QuickActionProps) -> Element {
    rsx! {
        button {
            style: "
                padding: 6px 12px;
                border: 1px solid var(--border-color, #333);
                border-radius: 16px;
                background: transparent;
                color: var(--text-muted, #888);
                font-size: 12px;
                cursor: pointer;
                transition: all 0.2s;
            ",
            onclick: move |_| props.on_click.call(props.text.to_string()),
            "{props.label}"
        }
    }
}

/// Single chat message props
#[derive(Props, Clone, PartialEq)]
pub struct ChatMessageProps {
    pub message: ChatMessage,
    #[props(default = true)]
    pub show_timestamp: bool,
}

/// Single chat message component
#[component]
pub fn ChatMessageComponent(props: ChatMessageProps) -> Element {
    let is_user = props.message.role == ChatRole::User;
    let is_system = props.message.role == ChatRole::System;
    
    let (bg_color, align, avatar) = if is_user {
        ("var(--message-user-bg, #4ecca3)", "flex-end", "👤")
    } else if is_system {
        ("var(--message-system-bg, #333)", "center", "⚙️")
    } else {
        ("var(--message-assistant-bg, #1a1a2e)", "flex-start", "🐸")
    };
    
    let text_color = if is_user { "#000" } else { "#eee" };
    let self_align = if is_user { "flex-end" } else { "flex-start" };
    let flex_dir = if is_user { "row-reverse" } else { "row" };

    rsx! {
        div {
            class: "chat-message",
            style: "display: flex; flex-direction: column; align-items: {align}; max-width: 85%; align-self: {self_align};",

            div {
                style: "display: flex; align-items: flex-start; gap: 8px; flex-direction: {flex_dir};",

                // Avatar
                span {
                    style: "
                        font-size: 20px;
                        line-height: 1;
                    ",
                    "{avatar}"
                }

                // Message bubble
                div {
                    style: "
                        padding: 12px 16px;
                        background: {bg_color};
                        border-radius: 12px;
                        color: {text_color};
                        font-size: 14px;
                        line-height: 1.5;
                        white-space: pre-wrap;
                        word-wrap: break-word;
                    ",
                    
                    // Parse and render message content with formatting
                    {render_message_content(&props.message.content)}
                }
            }
        }
    }
}

/// Render message content with special formatting for Bombina responses
fn render_message_content(content: &str) -> Element {
    // Check for structured response sections
    let sections = vec![
        ("[REASONING]:", "💭", "var(--section-reasoning, #ffd93d)"),
        ("[ACTION]:", "⚡", "var(--section-action, #6bcb77)"),
        ("[RISK]:", "⚠️", "var(--section-risk, #ff6b6b)"),
        ("[NEXT]:", "➡️", "var(--section-next, #4d96ff)"),
    ];

    let mut has_sections = false;
    for (marker, _, _) in &sections {
        if content.contains(marker) {
            has_sections = true;
            break;
        }
    }

    if has_sections {
        // Render structured response
        rsx! {
            div {
                class: "structured-response",
                for line in content.lines() {
                    {
                        let mut rendered = false;
                        for (marker, icon, color) in &sections {
                            if line.starts_with(marker) {
                                let text = line.strip_prefix(marker).unwrap_or("").trim();
                                rendered = true;
                                return rsx! {
                                    div {
                                        key: "{line}",
                                        style: "
                                            margin: 8px 0;
                                            padding: 8px 12px;
                                            background: {color}22;
                                            border-left: 3px solid {color};
                                            border-radius: 4px;
                                        ",
                                        span { style: "margin-right: 8px;", "{icon}" }
                                        strong { "{marker} " }
                                        span { "{text}" }
                                    }
                                };
                            }
                        }
                        if !rendered {
                            rsx! {
                                p { key: "{line}", style: "margin: 4px 0;", "{line}" }
                            }
                        } else {
                            rsx! {}
                        }
                    }
                }
            }
        }
    } else {
        // Render plain text
        rsx! {
            span { "{content}" }
        }
    }
}
