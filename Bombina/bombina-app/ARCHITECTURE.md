# Bombina Cross-Platform Application Architecture

## 🎯 Overview

**Bombina** is a cross-platform penetration testing AI assistant that runs on:
- 🐧 Linux (primary)
- 🪟 Windows
- 🍎 macOS
- 📱 Android
- 📱 iOS

## 🏗️ Technology Stack

### Core Framework: **Dioxus**
- React-like Rust framework
- Native rendering on all platforms
- Hot-reload for development
- Shared codebase across platforms

### Why Dioxus over alternatives:
| Framework | Desktop | Mobile | Performance | Ecosystem |
|-----------|---------|--------|-------------|-----------|
| Tauri     | ✅      | ⚠️     | Good        | Large     |
| egui      | ✅      | ⚠️     | Excellent   | Medium    |
| **Dioxus**| ✅      | ✅     | Excellent   | Growing   |
| Slint     | ✅      | ✅     | Good        | Small     |

### Backend Communication
- **HTTP/REST** to Ollama API (localhost:11434)
- **WebSocket** for streaming responses
- **gRPC** (optional) for high-performance scenarios

---

## 📁 Project Structure

```
bombina-app/
├── Cargo.toml                 # Workspace root
├── ARCHITECTURE.md            # This file
├── README.md
│
├── crates/
│   ├── bombina-core/          # Core logic (platform-agnostic)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── ollama.rs      # Ollama API client
│   │       ├── config.rs      # Configuration management
│   │       ├── session.rs     # Session state
│   │       └── types.rs       # Shared types
│   │
│   ├── bombina-ui/            # Shared UI components
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── components/
│   │       │   ├── mod.rs
│   │       │   ├── sidebar.rs     # Left panel
│   │       │   ├── chat.rs        # Chat interface
│   │       │   ├── target_input.rs # IP/domain input
│   │       │   ├── tools_panel.rs # Tool selection
│   │       │   └── settings.rs    # Settings modal
│   │       ├── pages/
│   │       │   ├── mod.rs
│   │       │   ├── home.rs
│   │       │   ├── pentest.rs
│   │       │   ├── reports.rs
│   │       │   └── history.rs
│   │       └── theme.rs       # Dark/light themes
│   │
│   └── bombina-tools/         # Pentest tool wrappers
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── nmap.rs
│           ├── gobuster.rs
│           ├── whois.rs
│           └── common.rs
│
├── desktop/                   # Desktop app (Linux/Win/Mac)
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
│
├── mobile/                    # Mobile app (Android/iOS)
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
│
├── web/                       # Web version (optional)
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
│
└── assets/
    ├── icons/
    │   ├── bombina-icon.png
    │   ├── bombina-icon.svg
    │   └── bombina-icon.ico
    ├── fonts/
    └── styles/
```

---

## 🖼️ UI Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  🐸 BOMBINA                              [Settings] [Theme] [?] │
├──────────────┬──────────────────────────────────────────────────┤
│              │                                                  │
│  ┌────────┐  │  ┌─────────────────────────────────────────────┐ │
│  │🏠 Home │  │  │  Target Input                               │ │
│  └────────┘  │  │  ┌───────────────────────────────────────┐  │ │
│              │  │  │ 192.168.1.0/24                        │  │ │
│  ┌────────┐  │  │  └───────────────────────────────────────┘  │ │
│  │🎯 Scan │  │  │  [IP] [Domain] [URL] [Range]                │ │
│  └────────┘  │  └─────────────────────────────────────────────┘ │
│              │                                                  │
│  ┌────────┐  │  ┌─────────────────────────────────────────────┐ │
│  │🔍 Enum │  │  │                                             │ │
│  └────────┘  │  │  Chat with Bombina AI                       │ │
│              │  │                                             │ │
│  ┌────────┐  │  │  🤖: How can I help with your pentest?     │ │
│  │⚔️ Attack│ │  │                                             │ │
│  └────────┘  │  │  👤: Scan target for open ports            │ │
│              │  │                                             │ │
│  ┌────────┐  │  │  🤖: I'll perform reconnaissance first...  │ │
│  │📊 Report│ │  │      [Reasoning: ...]                      │ │
│  └────────┘  │  │      [Tool: nmap -sV -sC 192.168.1.1]      │ │
│              │  │      [Risk: Low]                           │ │
│  ┌────────┐  │  │                                             │ │
│  │📜 Logs │  │  │                                             │ │
│  └────────┘  │  └─────────────────────────────────────────────┘ │
│              │                                                  │
│  ┌────────┐  │  ┌─────────────────────────────────────────────┐ │
│  │⚙️ Tools│  │  │ [Run Tool] [Generate Report] [Clear Chat]  │ │
│  └────────┘  │  └─────────────────────────────────────────────┘ │
│              │                                                  │
├──────────────┴──────────────────────────────────────────────────┤
│  Status: Connected to bombina-stable | Ollama: ✅ | Target: Set │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔌 API Integration

### Ollama API Endpoints

```rust
// POST /api/generate - Single response
// POST /api/chat - Chat with history
// GET /api/tags - List models
// POST /api/pull - Pull model
```

### Request Flow

```
┌──────────┐     ┌──────────────┐     ┌────────────┐     ┌────────┐
│  User    │────▶│ Bombina App  │────▶│ Ollama API │────▶│ Model  │
│  Input   │     │ (Dioxus)     │     │ :11434     │     │        │
└──────────┘     └──────────────┘     └────────────┘     └────────┘
                        │
                        ▼
                 ┌──────────────┐
                 │ Tool Executor│
                 │ (nmap, etc.) │
                 └──────────────┘
```

---

## 📱 Platform-Specific Notes

### Linux
- Native GTK rendering
- System tray integration
- Direct tool execution (nmap, gobuster, etc.)

### Windows
- Native Win32 rendering
- WSL tool execution (optional)
- Portable mode support

### macOS
- Native Cocoa rendering
- Homebrew tool integration
- Notarization for distribution

### Android
- Material Design adaptation
- Tool execution via Termux (optional)
- Reduced feature set (analysis only)

### iOS
- iOS Human Interface Guidelines
- Analysis-only mode (no tool execution)
- Report viewing and export

---

## 🔐 Security Architecture

```
┌─────────────────────────────────────────┐
│           Security Boundaries           │
├─────────────────────────────────────────┤
│                                         │
│  ┌─────────────────────────────────┐   │
│  │     User Authentication         │   │
│  │     (optional, local PIN)       │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │     Scope Validation            │   │
│  │     (IP ranges, domains)        │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │     Tool Sandboxing             │   │
│  │     (controlled execution)      │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │     Audit Logging               │   │
│  │     (all actions recorded)      │   │
│  └─────────────────────────────────┘   │
│                                         │
└─────────────────────────────────────────┘
```

---

## 🚀 Build & Distribution

### Development
```bash
# Desktop development with hot-reload
dx serve --platform desktop

# Mobile development
dx serve --platform android
dx serve --platform ios
```

### Production Builds
```bash
# Linux (AppImage, deb, rpm)
dx build --release --platform linux

# Windows (MSI, portable)
dx build --release --platform windows

# macOS (DMG, app bundle)
dx build --release --platform macos

# Android (APK, AAB)
dx build --release --platform android

# iOS (IPA)
dx build --release --platform ios
```

---

## 📊 Data Flow

```
User Input
    │
    ▼
┌───────────────┐
│ Target Parser │ ──▶ IP / Domain / URL / CIDR
└───────────────┘
    │
    ▼
┌───────────────┐
│ Policy Engine │ ──▶ Scope validation
└───────────────┘
    │
    ▼
┌───────────────┐
│ Ollama Client │ ──▶ Send to bombina-stable
└───────────────┘
    │
    ▼
┌───────────────┐
│ Response Parse│ ──▶ Extract reasoning + tools
└───────────────┘
    │
    ▼
┌───────────────┐
│ Tool Executor │ ──▶ Run approved tools
└───────────────┘
    │
    ▼
┌───────────────┐
│ Result Parser │ ──▶ Analyze output
└───────────────┘
    │
    ▼
┌───────────────┐
│ Display/Report│ ──▶ Show to user
└───────────────┘
```

---

## 🛠️ Features by Platform

| Feature              | Linux | Windows | macOS | Android | iOS |
|---------------------|-------|---------|-------|---------|-----|
| Chat with AI        | ✅    | ✅      | ✅    | ✅      | ✅  |
| Target scanning     | ✅    | ⚠️      | ✅    | ❌      | ❌  |
| Tool execution      | ✅    | ⚠️      | ✅    | ⚠️      | ❌  |
| Report generation   | ✅    | ✅      | ✅    | ✅      | ✅  |
| Session history     | ✅    | ✅      | ✅    | ✅      | ✅  |
| Offline mode        | ✅    | ✅      | ✅    | ✅      | ✅  |
| Dark theme          | ✅    | ✅      | ✅    | ✅      | ✅  |

⚠️ = Limited functionality
❌ = Not available (platform restriction)

---

## 📦 Dependencies

```toml
[dependencies]
dioxus = "0.5"
dioxus-desktop = "0.5"
dioxus-mobile = "0.5"
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.11", features = ["json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = "0.4"
uuid = { version = "1", features = ["v4"] }
tracing = "0.1"
thiserror = "1"
```

---

## 🎯 MVP Features (Phase 1)

1. ✅ Connect to local Ollama
2. ✅ Chat interface with bombina-stable
3. ✅ Target input (IP/domain/URL)
4. ✅ Left sidebar navigation
5. ✅ Dark theme
6. ✅ Session history
7. ✅ Basic tool execution (nmap)

## 📈 Future Features (Phase 2+)

- Multiple AI model selection
- Report export (PDF/HTML/Markdown)
- Tool result visualization
- Network diagram generation
- Vulnerability database integration
- Multi-target campaigns
- Team collaboration (optional server)
