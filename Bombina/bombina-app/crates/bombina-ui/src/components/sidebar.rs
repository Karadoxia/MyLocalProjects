//! Sidebar Component
//! 
//! Left navigation panel with vertical buttons.

use dioxus::prelude::*;

/// Navigation item for sidebar
#[derive(Clone, PartialEq)]
pub struct NavItem {
    pub id: &'static str,
    pub icon: &'static str,
    pub label: &'static str,
    pub shortcut: Option<&'static str>,
}

/// Default navigation items
pub fn default_nav_items() -> Vec<NavItem> {
    vec![
        NavItem { id: "home", icon: "🏠", label: "Home", shortcut: Some("Ctrl+1") },
        NavItem { id: "scan", icon: "🎯", label: "Scan", shortcut: Some("Ctrl+2") },
        NavItem { id: "enum", icon: "🔍", label: "Enumerate", shortcut: Some("Ctrl+3") },
        NavItem { id: "attack", icon: "⚔️", label: "Attack", shortcut: Some("Ctrl+4") },
        NavItem { id: "report", icon: "📊", label: "Reports", shortcut: Some("Ctrl+5") },
        NavItem { id: "history", icon: "📜", label: "History", shortcut: Some("Ctrl+6") },
        NavItem { id: "tools", icon: "🛠️", label: "Tools", shortcut: Some("Ctrl+7") },
        NavItem { id: "settings", icon: "⚙️", label: "Settings", shortcut: Some("Ctrl+,") },
    ]
}

/// Sidebar props
#[derive(Props, Clone, PartialEq)]
pub struct SidebarProps {
    /// Currently selected item ID
    pub selected: String,
    /// Callback when item is selected
    pub on_select: EventHandler<String>,
    /// Whether sidebar is collapsed
    #[props(default = false)]
    pub collapsed: bool,
    /// Navigation items
    #[props(default = default_nav_items())]
    pub items: Vec<NavItem>,
}

/// Sidebar navigation component
#[component]
pub fn Sidebar(props: SidebarProps) -> Element {
    let width = if props.collapsed { "60px" } else { "200px" };
    
    rsx! {
        nav {
            class: "sidebar",
            style: "
                width: {width};
                min-width: {width};
                height: 100%;
                background: var(--sidebar-bg, #1a1a2e);
                display: flex;
                flex-direction: column;
                padding: 8px;
                gap: 4px;
                transition: width 0.2s ease;
                overflow: hidden;
            ",

            // Logo/Brand
            div {
                class: "sidebar-brand",
                style: "
                    padding: 16px 8px;
                    text-align: center;
                    border-bottom: 1px solid var(--border-color, #333);
                    margin-bottom: 8px;
                ",
                if props.collapsed {
                    span { style: "font-size: 24px;", "🐸" }
                } else {
                    div {
                        span { style: "font-size: 24px; margin-right: 8px;", "🐸" }
                        span { 
                            style: "font-size: 18px; font-weight: bold; color: var(--primary-color, #4ecca3);",
                            "BOMBINA" 
                        }
                    }
                }
            }

            // Navigation items
            div {
                class: "sidebar-nav",
                style: "flex: 1; display: flex; flex-direction: column; gap: 4px;",
                
                for item in props.items.iter() {
                    {
                        let item_id = item.id.to_string();
                        let is_selected = props.selected == item.id;
                        let on_select = props.on_select.clone();
                        
                        rsx! {
                            {
                                let bg = if is_selected { "#4ecca3" } else { "transparent" };
                                let text_color = if is_selected { "#000" } else { "#eee" };
                                rsx! {
                                    button {
                                        key: "{item.id}",
                                        class: "sidebar-item",
                                        class: if is_selected { "selected" } else { "" },
                                        style: "display: flex; align-items: center; gap: 12px; padding: 12px; border: none; border-radius: 8px; background: {bg}; color: {text_color}; cursor: pointer; width: 100%; text-align: left; font-size: 14px; transition: all 0.2s ease;",
                                        onclick: move |_| {
                                            on_select.call(item_id.clone());
                                        },
                                        title: "{item.label}",
                                        
                                        span { style: "font-size: 18px;", "{item.icon}" }
                                        if !props.collapsed {
                                            span { "{item.label}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Bottom section
            div {
                class: "sidebar-footer",
                style: "
                    padding-top: 8px;
                    border-top: 1px solid var(--border-color, #333);
                ",
                
                if !props.collapsed {
                    div {
                        style: "
                            font-size: 11px;
                            color: var(--text-muted, #888);
                            text-align: center;
                        ",
                        "v0.1.0"
                    }
                }
            }
        }
    }
}
