# 🐸 Bombina - Cross-Platform Pentest AI

A powerful, cross-platform AI-powered penetration testing assistant built with Rust.

![Bombina](assets/icons/bombina-icon.svg)

## Features

- 🤖 **AI-Powered Analysis** - Integrated with local Ollama LLM for intelligent pentesting guidance
- 🔍 **Tool Integration** - Direct execution of nmap, gobuster, nikto, and more
- 📊 **Professional Reports** - Generate certification-ready pentest reports
- 🔐 **Policy Engine** - Built-in scope validation and safety controls
- 🌙 **Dark/Light Themes** - Easy on the eyes during long assessments
- 💾 **Session Management** - Save and resume pentest sessions
- 📱 **Cross-Platform** - Works on Linux, Windows, macOS (mobile coming soon)

## Quick Start

### Prerequisites

1. **Rust** (latest stable)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Ollama** with Bombina model
   ```bash
   # Install Ollama
   curl -fsSL https://ollama.ai/install.sh | sh
   
   # Run bombina-stable model
   ollama run bombina-stable
   ```

3. **Dioxus CLI** (for development)
   ```bash
   cargo install dioxus-cli
   ```

### Build & Run

```bash
# Clone repository
cd /home/redbend/MyLocalProjects/Bombina/bombina-app

# Build and run desktop app
cargo run --package bombina-desktop

# Or use release build for better performance
cargo run --release --package bombina-desktop
```

## Project Structure

```
bombina-app/
├── Cargo.toml                 # Workspace configuration
├── ARCHITECTURE.md            # Detailed architecture docs
│
├── crates/
│   ├── bombina-core/          # Core logic (Ollama client, sessions, policy)
│   ├── bombina-ui/            # Shared UI components (Dioxus)
│   └── bombina-tools/         # Pentest tool wrappers
│
├── desktop/                   # Desktop application
│   └── src/main.rs
│
├── mobile/                    # Mobile app (WIP)
└── web/                       # Web version (WIP)
```

## Usage

### 1. Set Target
Enter an IP address, domain, URL, or CIDR range in the target field.

### 2. Chat with AI
Ask Bombina about attack strategies, tool usage, or get pentest guidance.

### 3. Execute Tools
Select and run tools directly from the interface with real-time output.

### 4. Generate Reports
Create professional pentest reports with findings and recommendations.

## Configuration

Configuration is stored at:
- Linux: `~/.config/bombina-app/config.toml`
- macOS: `~/Library/Application Support/com.bombina.bombina-app/config.toml`
- Windows: `%APPDATA%\bombina\bombina-app\config.toml`

### Example Config

```toml
[ollama]
url = "http://localhost:11434"
default_model = "bombina-stable"
timeout_secs = 120

[ui]
dark_mode = true
font_size = 14

[security]
require_scope = true
allowed_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
max_risk_level = "HIGH"
audit_logging = true

[tools]
enabled = true
allowed_tools = ["nmap", "gobuster", "whois", "dig", "curl", "nikto"]
timeout_secs = 300
```

## Available Models

| Model | Description | Use Case |
|-------|-------------|----------|
| `bombina-stable` | Lightweight, fast | Daily use, CPU-friendly |
| `bombina-enhanced` | Medium prompt, balanced | Better reasoning |
| `bombina-ultimate` | Full reasoning injection | Complex scenarios |
| `qwen2.5-coder:3b` | Base model | Fallback |

## Development

### Hot Reload (Desktop)
```bash
dx serve --platform desktop
```

### Build for Release
```bash
# Linux AppImage
dx build --release --platform linux

# Windows MSI
dx build --release --platform windows

# macOS DMG
dx build --release --platform macos
```

### Run Tests
```bash
cargo test --workspace
```

## Security Notice

⚠️ **IMPORTANT**: Bombina is designed for authorized penetration testing only.

- Always obtain written permission before testing
- Use the policy engine to enforce scope boundaries
- All actions are logged for audit purposes
- No autonomous exploitation without confirmation

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## Support

- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/your-repo/bombina-app/issues)
- 💬 [Discussions](https://github.com/your-repo/bombina-app/discussions)

---

Made with 🐸 by the Bombina Team
