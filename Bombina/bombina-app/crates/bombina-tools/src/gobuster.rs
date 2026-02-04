//! Gobuster wrapper

use serde::{Deserialize, Serialize};

/// Gobuster mode
#[derive(Debug, Clone, Copy)]
pub enum GobusterMode {
    /// Directory enumeration
    Dir,
    /// DNS subdomain enumeration
    Dns,
    /// Virtual host enumeration
    Vhost,
    /// S3 bucket enumeration
    S3,
    /// Google Cloud bucket enumeration
    Gcs,
    /// Fuzzing
    Fuzz,
}

impl GobusterMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            GobusterMode::Dir => "dir",
            GobusterMode::Dns => "dns",
            GobusterMode::Vhost => "vhost",
            GobusterMode::S3 => "s3",
            GobusterMode::Gcs => "gcs",
            GobusterMode::Fuzz => "fuzz",
        }
    }
}

/// Common wordlists
pub const WORDLISTS: &[(&str, &str)] = &[
    ("common", "/usr/share/wordlists/dirb/common.txt"),
    ("big", "/usr/share/wordlists/dirb/big.txt"),
    ("dirbuster-medium", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
    ("dirbuster-small", "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"),
    ("rockyou", "/usr/share/wordlists/rockyou.txt"),
    ("subdomains", "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
];

/// Build gobuster command
pub fn build_command(
    mode: GobusterMode,
    target: &str,
    wordlist: &str,
    extra_args: &[&str],
) -> String {
    let mut parts = vec!["gobuster", mode.as_str(), "-u", target, "-w", wordlist];
    parts.extend(extra_args);
    parts.join(" ")
}

/// Parsed gobuster finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GobusterFinding {
    pub path: String,
    pub status_code: u16,
    pub size: Option<u64>,
    pub redirect: Option<String>,
}

/// Parse gobuster output
pub fn parse_output(stdout: &str) -> Vec<GobusterFinding> {
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        
        // Skip non-result lines
        if line.is_empty() || line.starts_with("===") || line.starts_with("Gobuster") {
            continue;
        }

        // Parse lines like: /admin (Status: 200) [Size: 1234]
        if line.starts_with('/') || line.starts_with("http") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let path = parts[0].to_string();
                let mut status_code = 0u16;
                let mut size = None;
                let mut redirect = None;

                for (i, part) in parts.iter().enumerate() {
                    if *part == "(Status:" {
                        if let Some(code) = parts.get(i + 1) {
                            let code = code.trim_end_matches(')');
                            status_code = code.parse().unwrap_or(0);
                        }
                    }
                    if *part == "[Size:" {
                        if let Some(s) = parts.get(i + 1) {
                            let s = s.trim_end_matches(']');
                            size = s.parse().ok();
                        }
                    }
                    if *part == "[->" {
                        if let Some(r) = parts.get(i + 1) {
                            redirect = Some(r.trim_end_matches(']').to_string());
                        }
                    }
                }

                if status_code > 0 {
                    findings.push(GobusterFinding {
                        path,
                        status_code,
                        size,
                        redirect,
                    });
                }
            }
        }
    }

    findings
}
