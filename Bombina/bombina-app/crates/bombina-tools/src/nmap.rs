//! Nmap wrapper

use crate::common::{ToolResult, ToolError};
use serde::{Deserialize, Serialize};

/// Nmap scan types
#[derive(Debug, Clone, Copy)]
pub enum ScanType {
    /// Quick scan (-T4 -F)
    Quick,
    /// Full port scan (-p-)
    Full,
    /// Service version scan (-sV)
    Version,
    /// Default scripts (-sC)
    Scripts,
    /// Comprehensive (-sV -sC -p-)
    Comprehensive,
    /// UDP scan (-sU)
    Udp,
    /// OS detection (-O)
    OsDetect,
}

impl ScanType {
    pub fn to_args(&self) -> Vec<&'static str> {
        match self {
            ScanType::Quick => vec!["-T4", "-F"],
            ScanType::Full => vec!["-p-"],
            ScanType::Version => vec!["-sV"],
            ScanType::Scripts => vec!["-sC"],
            ScanType::Comprehensive => vec!["-sV", "-sC", "-p-"],
            ScanType::Udp => vec!["-sU"],
            ScanType::OsDetect => vec!["-O"],
        }
    }
}

/// Build nmap command
pub fn build_command(target: &str, scan_type: ScanType, extra_args: &[&str]) -> String {
    let mut parts = vec!["nmap"];
    parts.extend(scan_type.to_args());
    parts.extend(extra_args);
    parts.push(target);
    parts.join(" ")
}

/// Parsed nmap output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapOutput {
    pub host: String,
    pub status: String,
    pub ports: Vec<PortInfo>,
    pub os_guess: Option<String>,
}

/// Port information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
}

/// Parse nmap output (basic parser)
pub fn parse_output(stdout: &str) -> Option<NmapOutput> {
    let mut output = NmapOutput {
        host: String::new(),
        status: String::new(),
        ports: Vec::new(),
        os_guess: None,
    };

    for line in stdout.lines() {
        let line = line.trim();

        // Parse host
        if line.starts_with("Nmap scan report for") {
            output.host = line.replace("Nmap scan report for ", "").trim().to_string();
        }

        // Parse host status
        if line.starts_with("Host is") {
            output.status = line.replace("Host is ", "").trim().to_string();
        }

        // Parse port lines (e.g., "22/tcp   open  ssh")
        if line.contains("/tcp") || line.contains("/udp") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Some((port_str, proto)) = parts[0].split_once('/') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        output.ports.push(PortInfo {
                            port,
                            protocol: proto.to_string(),
                            state: parts[1].to_string(),
                            service: parts.get(2).map(|s| s.to_string()),
                            version: if parts.len() > 3 {
                                Some(parts[3..].join(" "))
                            } else {
                                None
                            },
                        });
                    }
                }
            }
        }

        // Parse OS guess
        if line.starts_with("OS details:") || line.starts_with("Running:") {
            output.os_guess = Some(line.to_string());
        }
    }

    if !output.host.is_empty() {
        Some(output)
    } else {
        None
    }
}
