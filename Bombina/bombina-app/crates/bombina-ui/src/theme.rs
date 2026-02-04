//! Theme definitions

use serde::{Deserialize, Serialize};

/// Theme colors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Theme {
    /// Theme name
    pub name: String,
    /// Is dark theme
    pub is_dark: bool,
    /// Colors
    pub colors: ThemeColors,
}

/// Theme color palette
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeColors {
    pub background: String,
    pub surface: String,
    pub primary: String,
    pub secondary: String,
    pub text: String,
    pub text_muted: String,
    pub border: String,
    pub success: String,
    pub warning: String,
    pub error: String,
    pub info: String,
}

impl Theme {
    /// Dark theme (default)
    pub fn dark() -> Self {
        Self {
            name: "Dark".to_string(),
            is_dark: true,
            colors: ThemeColors {
                background: "#0f0f23".to_string(),
                surface: "#1a1a2e".to_string(),
                primary: "#4ecca3".to_string(),
                secondary: "#4d96ff".to_string(),
                text: "#eeeeee".to_string(),
                text_muted: "#888888".to_string(),
                border: "#333333".to_string(),
                success: "#4ecca3".to_string(),
                warning: "#ffd93d".to_string(),
                error: "#ff6b6b".to_string(),
                info: "#4d96ff".to_string(),
            },
        }
    }

    /// Light theme
    pub fn light() -> Self {
        Self {
            name: "Light".to_string(),
            is_dark: false,
            colors: ThemeColors {
                background: "#f5f5f5".to_string(),
                surface: "#ffffff".to_string(),
                primary: "#2d9c6f".to_string(),
                secondary: "#2563eb".to_string(),
                text: "#1a1a1a".to_string(),
                text_muted: "#666666".to_string(),
                border: "#e0e0e0".to_string(),
                success: "#2d9c6f".to_string(),
                warning: "#d97706".to_string(),
                error: "#dc2626".to_string(),
                info: "#2563eb".to_string(),
            },
        }
    }

    /// Generate CSS variables
    pub fn to_css_vars(&self) -> String {
        format!(
            r#"
            :root {{
                --background: {};
                --surface: {};
                --primary-color: {};
                --secondary-color: {};
                --text-color: {};
                --text-muted: {};
                --border-color: {};
                --success-color: {};
                --warning-color: {};
                --error-color: {};
                --info-color: {};
                
                /* Component specific */
                --header-bg: {};
                --sidebar-bg: {};
                --card-bg: {};
                --input-bg: {};
                --chat-bg: {};
                --statusbar-bg: {};
                
                /* Message colors */
                --message-user-bg: {};
                --message-assistant-bg: {};
                --message-system-bg: {};
            }}
            "#,
            self.colors.background,
            self.colors.surface,
            self.colors.primary,
            self.colors.secondary,
            self.colors.text,
            self.colors.text_muted,
            self.colors.border,
            self.colors.success,
            self.colors.warning,
            self.colors.error,
            self.colors.info,
            // Component specific
            self.colors.background,
            self.colors.surface,
            self.colors.surface,
            self.colors.background,
            self.colors.surface,
            if self.is_dark { "#0a0a1a" } else { "#e0e0e0" },
            // Message colors
            self.colors.primary,
            self.colors.surface,
            self.colors.border,
        )
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}
