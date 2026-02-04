//! Home Page

use dioxus::prelude::*;

/// Home page props
#[derive(Props, Clone, PartialEq)]
pub struct HomePageProps {
    /// Callback to start new session
    pub on_new_session: EventHandler<String>,
    /// Recent sessions
    #[props(default = vec![])]
    pub recent_sessions: Vec<(String, String, String)>, // (id, name, date)
    /// Callback to load session
    pub on_load_session: EventHandler<String>,
}

/// Home page component
#[component]
pub fn HomePage(props: HomePageProps) -> Element {
    let mut session_name = use_signal(|| String::new());

    rsx! {
        div {
            class: "home-page",
            style: "
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                height: 100%;
                padding: 40px;
            ",

            // Welcome section
            div {
                style: "text-align: center; margin-bottom: 48px;",
                
                span { style: "font-size: 72px;", "🐸" }
                h1 {
                    style: "
                        font-size: 36px;
                        color: var(--primary-color, #4ecca3);
                        margin: 16px 0 8px 0;
                    ",
                    "Welcome to Bombina"
                }
                p {
                    style: "
                        font-size: 18px;
                        color: var(--text-muted, #888);
                        margin: 0;
                    ",
                    "Your AI-powered penetration testing assistant"
                }
            }

            // New session card
            div {
                style: "
                    background: var(--card-bg, #1a1a2e);
                    border-radius: 16px;
                    padding: 32px;
                    width: 100%;
                    max-width: 500px;
                    margin-bottom: 32px;
                ",

                h3 {
                    style: "
                        margin: 0 0 16px 0;
                        color: var(--text-color, #eee);
                    ",
                    "🚀 Start New Session"
                }

                div {
                    style: "display: flex; gap: 12px;",
                    
                    input {
                        r#type: "text",
                        style: "
                            flex: 1;
                            padding: 14px 18px;
                            border: 2px solid var(--border-color, #333);
                            border-radius: 10px;
                            background: var(--input-bg, #0f0f23);
                            color: var(--text-color, #eee);
                            font-size: 15px;
                            outline: none;
                        ",
                        placeholder: "Session name (e.g., Client ABC Pentest)",
                        value: "{session_name}",
                        oninput: move |evt| session_name.set(evt.value()),
                        onkeypress: move |evt: KeyboardEvent| {
                            if evt.key() == Key::Enter && !session_name.read().trim().is_empty() {
                                props.on_new_session.call(session_name.read().clone());
                                session_name.set(String::new());
                            }
                        },
                    }

                    button {
                        style: "
                            padding: 14px 28px;
                            border: none;
                            border-radius: 10px;
                            background: var(--primary-color, #4ecca3);
                            color: #000;
                            font-size: 15px;
                            font-weight: 600;
                            cursor: pointer;
                        ",
                        disabled: session_name.read().trim().is_empty(),
                        onclick: move |_| {
                            if !session_name.read().trim().is_empty() {
                                props.on_new_session.call(session_name.read().clone());
                                session_name.set(String::new());
                            }
                        },
                        "Start"
                    }
                }
            }

            // Recent sessions
            if !props.recent_sessions.is_empty() {
                div {
                    style: "
                        width: 100%;
                        max-width: 500px;
                    ",

                    h3 {
                        style: "
                            color: var(--text-muted, #888);
                            font-size: 14px;
                            margin-bottom: 12px;
                        ",
                        "📜 Recent Sessions"
                    }

                    div {
                        style: "display: flex; flex-direction: column; gap: 8px;",
                        
                        for (id, name, date) in props.recent_sessions.iter() {
                            button {
                                key: "{id}",
                                style: "
                                    display: flex;
                                    justify-content: space-between;
                                    align-items: center;
                                    padding: 16px;
                                    border: 1px solid var(--border-color, #333);
                                    border-radius: 10px;
                                    background: var(--card-bg, #1a1a2e);
                                    color: var(--text-color, #eee);
                                    cursor: pointer;
                                    transition: all 0.2s;
                                    text-align: left;
                                ",
                                onclick: {
                                    let id = id.clone();
                                    move |_| props.on_load_session.call(id.clone())
                                },
                                
                                span { style: "font-weight: 500;", "{name}" }
                                span { 
                                    style: "font-size: 12px; color: var(--text-muted, #888);",
                                    "{date}" 
                                }
                            }
                        }
                    }
                }
            }

            // Quick tips
            div {
                style: "
                    margin-top: 48px;
                    display: flex;
                    gap: 24px;
                    flex-wrap: wrap;
                    justify-content: center;
                ",

                QuickTip { icon: "🎯", title: "Set Target", description: "Start by setting your target IP, domain, or URL" }
                QuickTip { icon: "💬", title: "Ask Anything", description: "Chat with Bombina about attack strategies" }
                QuickTip { icon: "🛠️", title: "Use Tools", description: "Execute nmap, gobuster, and other tools directly" }
                QuickTip { icon: "📊", title: "Generate Reports", description: "Create professional pentest reports" }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct QuickTipProps {
    icon: &'static str,
    title: &'static str,
    description: &'static str,
}

#[component]
fn QuickTip(props: QuickTipProps) -> Element {
    rsx! {
        div {
            style: "
                text-align: center;
                width: 150px;
            ",
            
            span { style: "font-size: 28px;", "{props.icon}" }
            h4 {
                style: "
                    margin: 8px 0 4px 0;
                    color: var(--text-color, #eee);
                    font-size: 14px;
                ",
                "{props.title}"
            }
            p {
                style: "
                    margin: 0;
                    color: var(--text-muted, #888);
                    font-size: 12px;
                ",
                "{props.description}"
            }
        }
    }
}
