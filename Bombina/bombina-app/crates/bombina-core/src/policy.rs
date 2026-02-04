//! Policy Engine for Bombina
//! 
//! Validates targets, actions, and enforces security boundaries.

use crate::types::{RiskLevel, Target, TargetType};
use crate::config::SecurityConfig;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::{debug, warn};

/// Policy validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub allowed: bool,
    pub reason: String,
    pub risk_level: RiskLevel,
    pub requires_confirmation: bool,
}

/// Policy engine for security enforcement
pub struct PolicyEngine {
    config: SecurityConfig,
    audit_log: Vec<AuditEntry>,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub target: Option<String>,
    pub result: PolicyResult,
    pub user_confirmed: bool,
}

impl PolicyEngine {
    /// Create a new policy engine from config
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config,
            audit_log: Vec::new(),
        }
    }

    /// Create with default security settings
    pub fn default_security() -> Self {
        Self::new(SecurityConfig {
            require_scope: true,
            allowed_ranges: vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
                "127.0.0.0/8".to_string(),
            ],
            allowed_domains: Vec::new(),
            max_risk_level: "HIGH".to_string(),
            audit_logging: true,
            confirm_high_risk: true,
        })
    }

    /// Validate a target against policy
    pub fn validate_target(&mut self, target: &Target) -> PolicyResult {
        let result = self.check_target(target);
        
        if self.config.audit_logging {
            self.audit_log.push(AuditEntry {
                timestamp: Utc::now(),
                action: "target_validation".to_string(),
                target: Some(target.value.clone()),
                result: result.clone(),
                user_confirmed: false,
            });
        }
        
        result
    }

    fn check_target(&self, target: &Target) -> PolicyResult {
        if !self.config.require_scope {
            return PolicyResult {
                allowed: true,
                reason: "Scope validation disabled".to_string(),
                risk_level: RiskLevel::Medium,
                requires_confirmation: false,
            };
        }

        match target.target_type {
            TargetType::IpAddress | TargetType::IpRange => {
                self.validate_ip(&target.value)
            }
            TargetType::Domain | TargetType::Hostname => {
                self.validate_domain(&target.value)
            }
            TargetType::Url => {
                // Extract domain from URL
                if let Some(domain) = Self::extract_domain_from_url(&target.value) {
                    self.validate_domain(&domain)
                } else {
                    PolicyResult {
                        allowed: false,
                        reason: "Invalid URL format".to_string(),
                        risk_level: RiskLevel::Info,
                        requires_confirmation: false,
                    }
                }
            }
        }
    }

    fn validate_ip(&self, ip_str: &str) -> PolicyResult {
        // Handle CIDR notation
        let ip_part = ip_str.split('/').next().unwrap_or(ip_str);
        
        let ip: IpAddr = match ip_part.parse() {
            Ok(ip) => ip,
            Err(_) => {
                return PolicyResult {
                    allowed: false,
                    reason: format!("Invalid IP address: {}", ip_str),
                    risk_level: RiskLevel::Info,
                    requires_confirmation: false,
                };
            }
        };

        // Check against allowed ranges
        for range in &self.config.allowed_ranges {
            if self.ip_in_range(&ip, range) {
                debug!("IP {} is in allowed range {}", ip, range);
                return PolicyResult {
                    allowed: true,
                    reason: format!("IP {} is within allowed range {}", ip, range),
                    risk_level: RiskLevel::Low,
                    requires_confirmation: false,
                };
            }
        }

        // Check for private IP ranges (always allowed by default)
        if self.is_private_ip(&ip) {
            return PolicyResult {
                allowed: true,
                reason: "Private IP address".to_string(),
                risk_level: RiskLevel::Low,
                requires_confirmation: false,
            };
        }

        warn!("IP {} is not in any allowed range", ip);
        PolicyResult {
            allowed: false,
            reason: format!("IP {} is not in allowed scope", ip),
            risk_level: RiskLevel::High,
            requires_confirmation: true,
        }
    }

    fn validate_domain(&self, domain: &str) -> PolicyResult {
        let domain_lower = domain.to_lowercase();

        // Check allowed domains
        for allowed in &self.config.allowed_domains {
            let allowed_lower = allowed.to_lowercase();
            if domain_lower == allowed_lower || domain_lower.ends_with(&format!(".{}", allowed_lower)) {
                return PolicyResult {
                    allowed: true,
                    reason: format!("Domain {} is in allowed list", domain),
                    risk_level: RiskLevel::Low,
                    requires_confirmation: false,
                };
            }
        }

        // Common test/local domains
        let safe_domains = ["localhost", "local", "test", "example", "internal", ".local", ".test"];
        for safe in safe_domains {
            if domain_lower == safe || domain_lower.ends_with(safe) {
                return PolicyResult {
                    allowed: true,
                    reason: "Local/test domain".to_string(),
                    risk_level: RiskLevel::Low,
                    requires_confirmation: false,
                };
            }
        }

        // Unknown domain - require confirmation
        PolicyResult {
            allowed: false,
            reason: format!("Domain {} is not in allowed scope. Add to allowed_domains in config to allow.", domain),
            risk_level: RiskLevel::High,
            requires_confirmation: true,
        }
    }

    fn ip_in_range(&self, ip: &IpAddr, cidr: &str) -> bool {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        let network: IpAddr = match parts[0].parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        };
        let prefix: u32 = match parts[1].parse() {
            Ok(p) => p,
            Err(_) => return false,
        };

        match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let ip_u32 = u32::from(*ip);
                let net_u32 = u32::from(net);
                let mask = !((1u32 << (32 - prefix)) - 1);
                (ip_u32 & mask) == (net_u32 & mask)
            }
            _ => false,
        }
    }

    fn is_private_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
            }
        }
    }

    fn extract_domain_from_url(url: &str) -> Option<String> {
        let without_scheme = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .unwrap_or(url);
        
        let domain = without_scheme.split('/').next()?;
        let domain = domain.split(':').next()?; // Remove port
        Some(domain.to_string())
    }

    /// Validate an action risk level
    pub fn validate_action(&mut self, action: &str, risk: RiskLevel) -> PolicyResult {
        let max_risk = self.parse_risk_level(&self.config.max_risk_level);
        
        let result = if risk > max_risk {
            PolicyResult {
                allowed: false,
                reason: format!("Action '{}' has risk level {:?} which exceeds maximum allowed {:?}", 
                              action, risk, max_risk),
                risk_level: risk,
                requires_confirmation: true,
            }
        } else if risk >= RiskLevel::High && self.config.confirm_high_risk {
            PolicyResult {
                allowed: true,
                reason: format!("Action '{}' requires confirmation due to {:?} risk", action, risk),
                risk_level: risk,
                requires_confirmation: true,
            }
        } else {
            PolicyResult {
                allowed: true,
                reason: format!("Action '{}' is within policy limits", action),
                risk_level: risk,
                requires_confirmation: false,
            }
        };

        if self.config.audit_logging {
            self.audit_log.push(AuditEntry {
                timestamp: Utc::now(),
                action: action.to_string(),
                target: None,
                result: result.clone(),
                user_confirmed: false,
            });
        }

        result
    }

    fn parse_risk_level(&self, level: &str) -> RiskLevel {
        match level.to_uppercase().as_str() {
            "INFO" => RiskLevel::Info,
            "LOW" => RiskLevel::Low,
            "MEDIUM" => RiskLevel::Medium,
            "HIGH" => RiskLevel::High,
            "CRITICAL" => RiskLevel::Critical,
            _ => RiskLevel::High,
        }
    }

    /// Add a domain to allowed list
    pub fn allow_domain(&mut self, domain: &str) {
        if !self.config.allowed_domains.contains(&domain.to_string()) {
            self.config.allowed_domains.push(domain.to_string());
        }
    }

    /// Add an IP range to allowed list
    pub fn allow_range(&mut self, cidr: &str) {
        if !self.config.allowed_ranges.contains(&cidr.to_string()) {
            self.config.allowed_ranges.push(cidr.to_string());
        }
    }

    /// Get audit log
    pub fn audit_log(&self) -> &[AuditEntry] {
        &self.audit_log
    }

    /// Export audit log to JSON
    pub fn export_audit_log(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&self.audit_log)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ip_allowed() {
        let mut engine = PolicyEngine::default_security();
        let target = Target::parse("192.168.1.100");
        let result = engine.validate_target(&target);
        assert!(result.allowed);
    }

    #[test]
    fn test_public_ip_denied() {
        let mut engine = PolicyEngine::default_security();
        let target = Target::parse("8.8.8.8");
        let result = engine.validate_target(&target);
        assert!(!result.allowed);
    }

    #[test]
    fn test_localhost_allowed() {
        let mut engine = PolicyEngine::default_security();
        let target = Target::parse("localhost");
        let result = engine.validate_target(&target);
        assert!(result.allowed);
    }
}
