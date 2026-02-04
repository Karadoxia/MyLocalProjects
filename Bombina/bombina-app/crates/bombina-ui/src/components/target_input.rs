//! Target Input Component
//! 
//! Input field for IP, domain, URL, or CIDR range.

use dioxus::prelude::*;
use bombina_core::types::{Target, TargetType};

/// Target input props
#[derive(Props, Clone, PartialEq)]
pub struct TargetInputProps {
    /// Current target value
    pub value: String,
    /// Callback when target changes
    pub on_change: EventHandler<String>,
    /// Callback when target is submitted
    pub on_submit: EventHandler<Target>,
    /// Whether target is valid
    #[props(default = true)]
    pub is_valid: bool,
    /// Validation message
    #[props(default = None)]
    pub validation_message: Option<String>,
    /// Placeholder text
    #[props(default = "Enter IP, domain, URL, or CIDR range...".to_string())]
    pub placeholder: String,
    /// Whether input is disabled
    #[props(default = false)]
    pub disabled: bool,
}

/// Target input component
#[component]
pub fn TargetInput(props: TargetInputProps) -> Element {
    let mut local_value = use_signal(|| props.value.clone());
    let mut detected_type = use_signal(|| None::<TargetType>);
    
    // Update local value when prop changes
    use_effect(move || {
        local_value.set(props.value.clone());
    });

    let handle_input = move |evt: Event<FormData>| {
        let value = evt.value();
        local_value.set(value.clone());
        
        // Detect target type as user types
        if !value.is_empty() {
            let target = Target::parse(&value);
            detected_type.set(Some(target.target_type));
        } else {
            detected_type.set(None);
        }
        
        props.on_change.call(value);
    };

    let handle_submit = move |_| {
        let value = local_value.read().trim().to_string();
        if !value.is_empty() {
            let target = Target::parse(&value);
            props.on_submit.call(target);
        }
    };

    let handle_keypress = move |evt: KeyboardEvent| {
        if evt.key() == Key::Enter {
            let value = local_value.read().trim().to_string();
            if !value.is_empty() {
                let target = Target::parse(&value);
                props.on_submit.call(target);
            }
        }
    };

    let type_badge = detected_type.read().as_ref().map(|t| {
        let (label, color) = match t {
            TargetType::IpAddress => ("IP", "#4ecca3"),
            TargetType::IpRange => ("CIDR", "#ffd93d"),
            TargetType::Domain => ("Domain", "#6bcb77"),
            TargetType::Url => ("URL", "#4d96ff"),
            TargetType::Hostname => ("Host", "#ff9f43"),
        };
        (label, color)
    });

    rsx! {
        div {
            class: "target-input-container",
            style: "
                background: var(--card-bg, #1a1a2e);
                border-radius: 12px;
                padding: 16px;
                margin-bottom: 16px;
            ",

            // Header
            div {
                style: "
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    margin-bottom: 12px;
                ",
                
                label {
                    style: "
                        font-size: 14px;
                        font-weight: 600;
                        color: var(--text-color, #eee);
                    ",
                    "🎯 Target"
                }

                if let Some((label, color)) = type_badge {
                    span {
                        style: "
                            padding: 4px 8px;
                            border-radius: 4px;
                            background: {color}33;
                            color: {color};
                            font-size: 12px;
                            font-weight: 500;
                        ",
                        "{label}"
                    }
                }
            }

            // Input row
            div {
                style: "
                    display: flex;
                    gap: 8px;
                ",

                {
                    let border_color = if props.is_valid { "#333" } else { "#ff6b6b" };
                    rsx! {
                        input {
                            r#type: "text",
                            class: "target-input",
                            style: "flex: 1; padding: 12px 16px; border: 2px solid {border_color}; border-radius: 8px; background: #0f0f23; color: #eee; font-size: 14px; font-family: 'JetBrains Mono', 'Fira Code', monospace; outline: none; transition: border-color 0.2s;",
                            placeholder: "{props.placeholder}",
                            value: "{local_value}",
                            disabled: props.disabled,
                            oninput: handle_input,
                            onkeypress: handle_keypress,
                        }
                    }
                }

                {
                    let btn_opacity = if local_value.read().trim().is_empty() { "0.5" } else { "1" };
                    rsx! {
                        button {
                            style: "padding: 12px 20px; border: none; border-radius: 8px; background: #4ecca3; color: #000; font-size: 14px; font-weight: 600; cursor: pointer; transition: opacity 0.2s; opacity: {btn_opacity};",
                            disabled: local_value.read().trim().is_empty() || props.disabled,
                            onclick: handle_submit,
                            "Set Target"
                        }
                    }
                }
            }

            // Type selector buttons
            div {
                style: "
                    display: flex;
                    gap: 8px;
                    margin-top: 12px;
                ",

                TypeButton { icon: "🖥️", label: "IP", example: "192.168.1.1", on_click: props.on_change.clone() }
                TypeButton { icon: "🌐", label: "Domain", example: "example.com", on_click: props.on_change.clone() }
                TypeButton { icon: "🔗", label: "URL", example: "http://target.local", on_click: props.on_change.clone() }
                TypeButton { icon: "📡", label: "Range", example: "10.0.0.0/24", on_click: props.on_change.clone() }
            }

            // Validation message
            if let Some(ref msg) = props.validation_message {
                {
                    let bg = if props.is_valid { "rgba(78, 204, 163, 0.2)" } else { "rgba(255, 107, 107, 0.2)" };
                    let color = if props.is_valid { "#4ecca3" } else { "#ff6b6b" };
                    rsx! {
                        div {
                            style: "margin-top: 8px; padding: 8px 12px; border-radius: 6px; background: {bg}; color: {color}; font-size: 13px;",
                            "{msg}"
                        }
                    }
                }
            }
        }
    }
}

/// Type button props
#[derive(Props, Clone, PartialEq)]
struct TypeButtonProps {
    icon: &'static str,
    label: &'static str,
    example: &'static str,
    on_click: EventHandler<String>,
}

/// Type selector button
#[component]
fn TypeButton(props: TypeButtonProps) -> Element {
    rsx! {
        button {
            style: "
                padding: 6px 12px;
                border: 1px solid var(--border-color, #333);
                border-radius: 6px;
                background: transparent;
                color: var(--text-muted, #888);
                font-size: 12px;
                cursor: pointer;
                transition: all 0.2s;
                display: flex;
                align-items: center;
                gap: 4px;
            ",
            title: "Example: {props.example}",
            onclick: move |_| props.on_click.call(props.example.to_string()),
            
            span { "{props.icon}" }
            span { "{props.label}" }
        }
    }
}
