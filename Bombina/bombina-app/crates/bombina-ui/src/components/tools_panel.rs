//! Tools Panel Component
//! 
//! Panel for selecting and executing pentest tools.

use dioxus::prelude::*;

/// Available tool category
#[derive(Clone, PartialEq)]
pub struct ToolCategory {
    pub id: &'static str,
    pub name: &'static str,
    pub icon: &'static str,
    pub tools: Vec<Tool>,
}

/// Individual tool definition
#[derive(Clone, PartialEq)]
pub struct Tool {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub command: &'static str,
    pub risk_level: &'static str,
}

/// Default tool categories
pub fn default_tool_categories() -> Vec<ToolCategory> {
    vec![
        ToolCategory {
            id: "recon",
            name: "Reconnaissance",
            icon: "🔍",
            tools: vec![
                Tool {
                    id: "nmap_quick",
                    name: "Quick Scan",
                    description: "Fast port scan of common ports",
                    command: "nmap -T4 -F {target}",
                    risk_level: "LOW",
                },
                Tool {
                    id: "nmap_full",
                    name: "Full Scan",
                    description: "Comprehensive port and service scan",
                    command: "nmap -sV -sC -p- {target}",
                    risk_level: "LOW",
                },
                Tool {
                    id: "whois",
                    name: "WHOIS",
                    description: "Domain registration lookup",
                    command: "whois {target}",
                    risk_level: "INFO",
                },
                Tool {
                    id: "dig",
                    name: "DNS Lookup",
                    description: "DNS enumeration",
                    command: "dig {target} ANY",
                    risk_level: "INFO",
                },
            ],
        },
        ToolCategory {
            id: "web",
            name: "Web Testing",
            icon: "🌐",
            tools: vec![
                Tool {
                    id: "gobuster",
                    name: "Directory Brute",
                    description: "Enumerate web directories",
                    command: "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt",
                    risk_level: "MEDIUM",
                },
                Tool {
                    id: "nikto",
                    name: "Nikto Scan",
                    description: "Web vulnerability scanner",
                    command: "nikto -h {target}",
                    risk_level: "MEDIUM",
                },
                Tool {
                    id: "curl",
                    name: "HTTP Headers",
                    description: "Fetch HTTP headers",
                    command: "curl -I {target}",
                    risk_level: "INFO",
                },
            ],
        },
        ToolCategory {
            id: "vuln",
            name: "Vulnerability",
            icon: "⚠️",
            tools: vec![
                Tool {
                    id: "nmap_vuln",
                    name: "Vuln Scripts",
                    description: "Nmap vulnerability scripts",
                    command: "nmap --script vuln {target}",
                    risk_level: "MEDIUM",
                },
                Tool {
                    id: "searchsploit",
                    name: "SearchSploit",
                    description: "Search for exploits",
                    command: "searchsploit {service}",
                    risk_level: "INFO",
                },
            ],
        },
        ToolCategory {
            id: "network",
            name: "Network",
            icon: "📡",
            tools: vec![
                Tool {
                    id: "ping",
                    name: "Ping",
                    description: "Check host availability",
                    command: "ping -c 4 {target}",
                    risk_level: "INFO",
                },
                Tool {
                    id: "traceroute",
                    name: "Traceroute",
                    description: "Trace network path",
                    command: "traceroute {target}",
                    risk_level: "INFO",
                },
            ],
        },
    ]
}

/// Tools panel props
#[derive(Props, Clone, PartialEq)]
pub struct ToolsPanelProps {
    /// Current target
    pub target: Option<String>,
    /// Callback when tool is selected
    pub on_tool_select: EventHandler<(String, String)>, // (tool_id, command)
    /// Callback when tool should be executed
    pub on_tool_execute: EventHandler<String>, // command
    /// Whether tool execution is in progress
    #[props(default = false)]
    pub is_executing: bool,
}

/// Tools panel component
#[component]
pub fn ToolsPanel(props: ToolsPanelProps) -> Element {
    let categories = default_tool_categories();
    let mut expanded_category = use_signal(|| Some("recon".to_string()));
    let mut selected_tool = use_signal(|| None::<String>);

    rsx! {
        div {
            class: "tools-panel",
            style: "
                background: var(--card-bg, #1a1a2e);
                border-radius: 12px;
                padding: 16px;
                height: 100%;
                overflow-y: auto;
            ",

            // Header
            div {
                style: "
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    margin-bottom: 16px;
                    padding-bottom: 12px;
                    border-bottom: 1px solid var(--border-color, #333);
                ",
                
                h3 {
                    style: "
                        margin: 0;
                        font-size: 16px;
                        color: var(--text-color, #eee);
                    ",
                    "🛠️ Tools"
                }

                if props.target.is_some() {
                    span {
                        style: "
                            padding: 4px 8px;
                            background: var(--success-bg, #4ecca333);
                            color: var(--success-color, #4ecca3);
                            border-radius: 4px;
                            font-size: 12px;
                        ",
                        "Target Set"
                    }
                }
            }

            // No target warning
            if props.target.is_none() {
                div {
                    style: "
                        padding: 16px;
                        background: var(--warning-bg, #ffd93d22);
                        border: 1px solid var(--warning-color, #ffd93d);
                        border-radius: 8px;
                        margin-bottom: 16px;
                    ",
                    p {
                        style: "
                            margin: 0;
                            color: var(--warning-color, #ffd93d);
                            font-size: 14px;
                        ",
                        "⚠️ Set a target first to use tools"
                    }
                }
            }

            // Tool categories
            for category in categories.iter() {
                {
                    let cat_id = category.id.to_string();
                    let is_expanded = expanded_category.read().as_ref() == Some(&cat_id);
                    
                    rsx! {
                        div {
                            key: "{category.id}",
                            class: "tool-category",
                            style: "margin-bottom: 8px;",

                            // Category header
                            button {
                                style: "
                                    width: 100%;
                                    display: flex;
                                    align-items: center;
                                    justify-content: space-between;
                                    padding: 12px;
                                    border: none;
                                    border-radius: 8px;
                                    background: var(--category-bg, #16213e);
                                    color: var(--text-color, #eee);
                                    cursor: pointer;
                                    transition: background 0.2s;
                                ",
                                onclick: move |_| {
                                    let current = expanded_category.read().clone();
                                    if current.as_ref() == Some(&cat_id) {
                                        expanded_category.set(None);
                                    } else {
                                        expanded_category.set(Some(cat_id.clone()));
                                    }
                                },

                                div {
                                    style: "display: flex; align-items: center; gap: 8px;",
                                    span { "{category.icon}" }
                                    span { style: "font-weight: 500;", "{category.name}" }
                                    span {
                                        style: "
                                            padding: 2px 6px;
                                            background: var(--badge-bg, #333);
                                            border-radius: 10px;
                                            font-size: 11px;
                                            color: var(--text-muted, #888);
                                        ",
                                        "{category.tools.len()}"
                                    }
                                }

                                span {
                                    {
                                        let rotation = if is_expanded { "rotate(180deg)" } else { "rotate(0)" };
                                        rsx! {
                                            span {
                                                style: "transition: transform 0.2s; transform: {rotation};",
                                                "▼"
                                            }
                                        }
                                    }
                                }
                            }

                            // Tools list
                            if is_expanded {
                                div {
                                    style: "
                                        padding: 8px;
                                        display: flex;
                                        flex-direction: column;
                                        gap: 4px;
                                    ",

                                    for tool in category.tools.iter() {
                                        {
                                            let tool_id = tool.id.to_string();
                                            let is_selected = selected_tool.read().as_ref() == Some(&tool_id);
                                            let target = props.target.clone().unwrap_or_default();
                                            let command = tool.command.replace("{target}", &target);
                                            
                                            let risk_color = match tool.risk_level {
                                                "INFO" => "#4d96ff",
                                                "LOW" => "#4ecca3",
                                                "MEDIUM" => "#ffd93d",
                                                "HIGH" => "#ff9f43",
                                                _ => "#ff6b6b",
                                            };
                                            
                                            let tool_bg = if is_selected { "rgba(78, 204, 163, 0.13)" } else { "#0f0f23" };
                                            let tool_border = if is_selected { "#4ecca3" } else { "transparent" };

                                            rsx! {
                                                div {
                                                    key: "{tool.id}",
                                                    class: "tool-item",
                                                    style: "padding: 12px; border-radius: 8px; background: {tool_bg}; border: 1px solid {tool_border}; cursor: pointer; transition: all 0.2s;",
                                                    onclick: {
                                                        let tool_id = tool_id.clone();
                                                        let command = command.clone();
                                                        move |_| {
                                                            selected_tool.set(Some(tool_id.clone()));
                                                            props.on_tool_select.call((tool_id.clone(), command.clone()));
                                                        }
                                                    },

                                                    div {
                                                        style: "display: flex; justify-content: space-between; align-items: center;",
                                                        
                                                        span {
                                                            style: "font-weight: 500; color: var(--text-color, #eee);",
                                                            "{tool.name}"
                                                        }
                                                        
                                                        span {
                                                            style: "
                                                                padding: 2px 6px;
                                                                background: {risk_color}22;
                                                                color: {risk_color};
                                                                border-radius: 4px;
                                                                font-size: 10px;
                                                                font-weight: 600;
                                                            ",
                                                            "{tool.risk_level}"
                                                        }
                                                    }

                                                    p {
                                                        style: "
                                                            margin: 4px 0 0 0;
                                                            font-size: 12px;
                                                            color: var(--text-muted, #888);
                                                        ",
                                                        "{tool.description}"
                                                    }

                                                    if is_selected && props.target.is_some() {
                                                        div {
                                                            style: "margin-top: 8px;",
                                                            
                                                            code {
                                                                style: "
                                                                    display: block;
                                                                    padding: 8px;
                                                                    background: var(--code-bg, #000);
                                                                    border-radius: 4px;
                                                                    font-size: 11px;
                                                                    color: var(--code-color, #4ecca3);
                                                                    margin-bottom: 8px;
                                                                    word-break: break-all;
                                                                ",
                                                                "{command}"
                                                            }

                                                            button {
                                                                style: "
                                                                    width: 100%;
                                                                    padding: 8px;
                                                                    border: none;
                                                                    border-radius: 6px;
                                                                    background: var(--primary-color, #4ecca3);
                                                                    color: #000;
                                                                    font-weight: 600;
                                                                    cursor: pointer;
                                                                    opacity: 1;
                                                                ",
                                                                disabled: props.is_executing,
                                                                onclick: {
                                                                    let cmd = command.clone();
                                                                    move |evt: MouseEvent| {
                                                                        evt.stop_propagation();
                                                                        props.on_tool_execute.call(cmd.clone());
                                                                    }
                                                                },
                                                                
                                                                if props.is_executing {
                                                                    "Running..."
                                                                } else {
                                                                    "▶ Execute"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
