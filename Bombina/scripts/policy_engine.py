#!/usr/bin/env python3
"""
Bombina Policy Engine
Scope validation and safety enforcement for autonomous operations

Features:
- Engagement scope validation (targets, actions, networks)
- Risk threshold enforcement
- Action authorization before execution
- Audit logging for compliance

Usage:
    from policy_engine import PolicyEngine, EngagementScope
    
    engine = PolicyEngine(scope)
    if engine.authorize_action(target, action):
        # proceed
"""

import json
import re
import ipaddress
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from datetime import datetime
from enum import Enum


class RiskLevel(Enum):
    """Risk classification for actions."""
    INFO = 1        # Passive information gathering
    LOW = 2         # Non-intrusive active recon
    MEDIUM = 3      # Active scanning, enumeration
    HIGH = 4        # Exploitation, credential access
    CRITICAL = 5    # Destructive, persistent access


class ActionCategory(Enum):
    """Categories of pentest actions."""
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    CLEANUP = "cleanup"


# ═══════════════════════════════════════════════════════════════════════════════
# ENGAGEMENT SCOPE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EngagementScope:
    """Defines the authorized scope for a penetration test."""
    
    # Target definitions
    in_scope_hosts: List[str] = field(default_factory=list)      # IPs, CIDRs, hostnames
    in_scope_domains: List[str] = field(default_factory=list)    # Domain patterns
    out_of_scope_hosts: List[str] = field(default_factory=list)  # Explicitly excluded
    out_of_scope_domains: List[str] = field(default_factory=list)
    
    # Action restrictions
    allowed_categories: List[ActionCategory] = field(default_factory=list)
    forbidden_actions: List[str] = field(default_factory=list)   # Specific tool/technique names
    max_risk_level: RiskLevel = RiskLevel.HIGH
    
    # Time restrictions
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    allowed_hours: Optional[tuple] = None  # (start_hour, end_hour) in 24h
    
    # Special conditions
    require_notification_before: List[str] = field(default_factory=list)  # Actions requiring prior notice
    credential_handling: str = "hash_only"  # "none", "hash_only", "plaintext_allowed"
    data_handling: str = "no_exfil"  # "no_exfil", "limited", "full"
    
    # Metadata
    engagement_id: str = ""
    client_name: str = ""
    rules_of_engagement_ref: str = ""
    
    @classmethod
    def from_file(cls, path: Path) -> "EngagementScope":
        """Load scope from JSON file."""
        with open(path) as f:
            data = json.load(f)
        
        # Convert string enums
        if "allowed_categories" in data:
            data["allowed_categories"] = [ActionCategory(c) for c in data["allowed_categories"]]
        if "max_risk_level" in data:
            data["max_risk_level"] = RiskLevel[data["max_risk_level"]]
        
        return cls(**data)
    
    def to_file(self, path: Path):
        """Save scope to JSON file."""
        data = {
            "engagement_id": self.engagement_id,
            "client_name": self.client_name,
            "in_scope_hosts": self.in_scope_hosts,
            "in_scope_domains": self.in_scope_domains,
            "out_of_scope_hosts": self.out_of_scope_hosts,
            "out_of_scope_domains": self.out_of_scope_domains,
            "allowed_categories": [c.value for c in self.allowed_categories],
            "forbidden_actions": self.forbidden_actions,
            "max_risk_level": self.max_risk_level.name,
            "credential_handling": self.credential_handling,
            "data_handling": self.data_handling,
            "rules_of_engagement_ref": self.rules_of_engagement_ref
        }
        
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# ACTION DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Map common tools/techniques to risk levels and categories
ACTION_REGISTRY = {
    # Passive Recon - INFO risk
    "whois": {"risk": RiskLevel.INFO, "category": ActionCategory.PASSIVE_RECON},
    "dig": {"risk": RiskLevel.INFO, "category": ActionCategory.PASSIVE_RECON},
    "nslookup": {"risk": RiskLevel.INFO, "category": ActionCategory.PASSIVE_RECON},
    "shodan_search": {"risk": RiskLevel.INFO, "category": ActionCategory.PASSIVE_RECON},
    "certificate_transparency": {"risk": RiskLevel.INFO, "category": ActionCategory.PASSIVE_RECON},
    
    # Active Recon - LOW risk
    "ping": {"risk": RiskLevel.LOW, "category": ActionCategory.ACTIVE_RECON},
    "traceroute": {"risk": RiskLevel.LOW, "category": ActionCategory.ACTIVE_RECON},
    "nmap_discovery": {"risk": RiskLevel.LOW, "category": ActionCategory.ACTIVE_RECON},
    "banner_grab": {"risk": RiskLevel.LOW, "category": ActionCategory.ACTIVE_RECON},
    
    # Vulnerability Scanning - MEDIUM risk
    "nmap_vuln": {"risk": RiskLevel.MEDIUM, "category": ActionCategory.VULNERABILITY_SCAN},
    "nikto": {"risk": RiskLevel.MEDIUM, "category": ActionCategory.VULNERABILITY_SCAN},
    "nuclei": {"risk": RiskLevel.MEDIUM, "category": ActionCategory.VULNERABILITY_SCAN},
    "gobuster": {"risk": RiskLevel.MEDIUM, "category": ActionCategory.VULNERABILITY_SCAN},
    "feroxbuster": {"risk": RiskLevel.MEDIUM, "category": ActionCategory.VULNERABILITY_SCAN},
    "wpscan": {"risk": RiskLevel.MEDIUM, "category": ActionCategory.VULNERABILITY_SCAN},
    
    # Exploitation - HIGH risk
    "sqlmap": {"risk": RiskLevel.HIGH, "category": ActionCategory.EXPLOITATION},
    "metasploit_exploit": {"risk": RiskLevel.HIGH, "category": ActionCategory.EXPLOITATION},
    "manual_exploit": {"risk": RiskLevel.HIGH, "category": ActionCategory.EXPLOITATION},
    "web_shell_upload": {"risk": RiskLevel.HIGH, "category": ActionCategory.EXPLOITATION},
    
    # Credential Access - HIGH risk
    "kerberoasting": {"risk": RiskLevel.HIGH, "category": ActionCategory.CREDENTIAL_ACCESS},
    "asrep_roast": {"risk": RiskLevel.HIGH, "category": ActionCategory.CREDENTIAL_ACCESS},
    "lsass_dump": {"risk": RiskLevel.HIGH, "category": ActionCategory.CREDENTIAL_ACCESS},
    "secretsdump": {"risk": RiskLevel.HIGH, "category": ActionCategory.CREDENTIAL_ACCESS},
    "responder": {"risk": RiskLevel.HIGH, "category": ActionCategory.CREDENTIAL_ACCESS},
    "bloodhound_collection": {"risk": RiskLevel.MEDIUM, "category": ActionCategory.CREDENTIAL_ACCESS},
    
    # Lateral Movement - HIGH risk
    "psexec": {"risk": RiskLevel.HIGH, "category": ActionCategory.LATERAL_MOVEMENT},
    "wmiexec": {"risk": RiskLevel.HIGH, "category": ActionCategory.LATERAL_MOVEMENT},
    "smbexec": {"risk": RiskLevel.HIGH, "category": ActionCategory.LATERAL_MOVEMENT},
    "evil_winrm": {"risk": RiskLevel.HIGH, "category": ActionCategory.LATERAL_MOVEMENT},
    "rdp": {"risk": RiskLevel.HIGH, "category": ActionCategory.LATERAL_MOVEMENT},
    
    # Persistence - CRITICAL risk (requires special approval)
    "scheduled_task": {"risk": RiskLevel.CRITICAL, "category": ActionCategory.PERSISTENCE},
    "registry_run_key": {"risk": RiskLevel.CRITICAL, "category": ActionCategory.PERSISTENCE},
    "golden_ticket": {"risk": RiskLevel.CRITICAL, "category": ActionCategory.PERSISTENCE},
    "skeleton_key": {"risk": RiskLevel.CRITICAL, "category": ActionCategory.PERSISTENCE},
    "backdoor_install": {"risk": RiskLevel.CRITICAL, "category": ActionCategory.PERSISTENCE},
    
    # Exfiltration - HIGH/CRITICAL risk
    "data_exfil": {"risk": RiskLevel.CRITICAL, "category": ActionCategory.EXFILTRATION},
    "screenshot": {"risk": RiskLevel.MEDIUM, "category": ActionCategory.EXFILTRATION},
    
    # Cleanup - LOW risk
    "cleanup_artifacts": {"risk": RiskLevel.LOW, "category": ActionCategory.CLEANUP},
    "log_cleanup": {"risk": RiskLevel.MEDIUM, "category": ActionCategory.CLEANUP},
}


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AuthorizationResult:
    """Result of an authorization check."""
    authorized: bool
    reason: str
    warnings: List[str] = field(default_factory=list)
    requires_notification: bool = False
    risk_level: Optional[RiskLevel] = None


class PolicyEngine:
    """Enforces engagement scope and safety policies."""
    
    def __init__(self, scope: EngagementScope, audit_log_path: Optional[Path] = None):
        self.scope = scope
        self.audit_log_path = audit_log_path or Path("audit_log.jsonl")
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficient matching."""
        # Compile domain patterns
        self._in_scope_domain_patterns = []
        for domain in self.scope.in_scope_domains:
            pattern = domain.replace(".", r"\.").replace("*", r".*")
            self._in_scope_domain_patterns.append(re.compile(f"^{pattern}$", re.IGNORECASE))
        
        self._out_scope_domain_patterns = []
        for domain in self.scope.out_of_scope_domains:
            pattern = domain.replace(".", r"\.").replace("*", r".*")
            self._out_scope_domain_patterns.append(re.compile(f"^{pattern}$", re.IGNORECASE))
        
        # Parse IP networks
        self._in_scope_networks = []
        for host in self.scope.in_scope_hosts:
            try:
                self._in_scope_networks.append(ipaddress.ip_network(host, strict=False))
            except ValueError:
                pass  # Not an IP, will be matched as hostname
        
        self._out_scope_networks = []
        for host in self.scope.out_of_scope_hosts:
            try:
                self._out_scope_networks.append(ipaddress.ip_network(host, strict=False))
            except ValueError:
                pass
    
    def is_target_in_scope(self, target: str) -> tuple[bool, str]:
        """Check if a target (IP, hostname, URL) is within scope."""
        # Extract hostname from URL if needed
        if target.startswith(("http://", "https://")):
            target = target.split("//")[1].split("/")[0].split(":")[0]
        
        # Check explicit out-of-scope first (takes precedence)
        if target in self.scope.out_of_scope_hosts:
            return False, f"Target {target} is explicitly out of scope"
        
        for pattern in self._out_scope_domain_patterns:
            if pattern.match(target):
                return False, f"Target {target} matches out-of-scope pattern"
        
        # Check IP addresses
        try:
            ip = ipaddress.ip_address(target)
            for network in self._out_scope_networks:
                if ip in network:
                    return False, f"IP {target} is in out-of-scope network {network}"
            
            for network in self._in_scope_networks:
                if ip in network:
                    return True, f"IP {target} is in scope network {network}"
            
            # IP not in any defined network
            if self._in_scope_networks:  # If we have defined networks, IP must be in one
                return False, f"IP {target} not in any in-scope network"
        except ValueError:
            pass  # Not an IP, continue with hostname checks
        
        # Check hostname
        if target in self.scope.in_scope_hosts:
            return True, f"Target {target} is explicitly in scope"
        
        for pattern in self._in_scope_domain_patterns:
            if pattern.match(target):
                return True, f"Target {target} matches in-scope pattern"
        
        # Default deny if we have defined scope
        if self.scope.in_scope_hosts or self.scope.in_scope_domains:
            return False, f"Target {target} not found in defined scope"
        
        # No scope defined = warn but allow
        return True, "WARNING: No scope defined, allowing by default"
    
    def is_action_allowed(self, action: str) -> tuple[bool, str, RiskLevel]:
        """Check if an action/tool is allowed within engagement rules."""
        action_lower = action.lower()
        
        # Check explicit forbidden list
        for forbidden in self.scope.forbidden_actions:
            if forbidden.lower() in action_lower:
                return False, f"Action '{action}' is explicitly forbidden", RiskLevel.INFO
        
        # Look up action in registry
        action_info = ACTION_REGISTRY.get(action_lower)
        
        if action_info:
            risk = action_info["risk"]
            category = action_info["category"]
            
            # Check risk level
            if risk.value > self.scope.max_risk_level.value:
                return False, f"Action '{action}' risk level ({risk.name}) exceeds maximum ({self.scope.max_risk_level.name})", risk
            
            # Check category
            if self.scope.allowed_categories and category not in self.scope.allowed_categories:
                return False, f"Action category '{category.value}' not in allowed categories", risk
            
            return True, f"Action '{action}' is allowed (risk: {risk.name})", risk
        
        # Unknown action - warn but allow if within risk level
        return True, f"WARNING: Unknown action '{action}', allowing with caution", RiskLevel.MEDIUM
    
    def is_within_time_window(self) -> tuple[bool, str]:
        """Check if current time is within authorized testing window."""
        now = datetime.now()
        
        # Check date range
        if self.scope.start_time and now < self.scope.start_time:
            return False, f"Engagement has not started (starts: {self.scope.start_time})"
        
        if self.scope.end_time and now > self.scope.end_time:
            return False, f"Engagement has ended (ended: {self.scope.end_time})"
        
        # Check hour restrictions
        if self.scope.allowed_hours:
            start_hour, end_hour = self.scope.allowed_hours
            current_hour = now.hour
            
            if start_hour <= end_hour:
                if not (start_hour <= current_hour < end_hour):
                    return False, f"Outside allowed hours ({start_hour}:00 - {end_hour}:00)"
            else:  # Overnight window (e.g., 22:00 - 06:00)
                if not (current_hour >= start_hour or current_hour < end_hour):
                    return False, f"Outside allowed hours ({start_hour}:00 - {end_hour}:00)"
        
        return True, "Within authorized time window"
    
    def authorize_action(self, target: str, action: str, context: Optional[Dict] = None) -> AuthorizationResult:
        """
        Main authorization check combining all policy validations.
        
        Args:
            target: The target host/IP/URL
            action: The action/tool to perform
            context: Additional context (optional)
        
        Returns:
            AuthorizationResult with decision and reasoning
        """
        warnings = []
        
        # Time window check
        time_ok, time_reason = self.is_within_time_window()
        if not time_ok:
            self._audit_log("DENIED", target, action, time_reason)
            return AuthorizationResult(
                authorized=False,
                reason=time_reason,
                warnings=warnings
            )
        
        # Target scope check
        target_ok, target_reason = self.is_target_in_scope(target)
        if not target_ok:
            self._audit_log("DENIED", target, action, target_reason)
            return AuthorizationResult(
                authorized=False,
                reason=target_reason,
                warnings=warnings
            )
        
        if "WARNING" in target_reason:
            warnings.append(target_reason)
        
        # Action check
        action_ok, action_reason, risk_level = self.is_action_allowed(action)
        if not action_ok:
            self._audit_log("DENIED", target, action, action_reason)
            return AuthorizationResult(
                authorized=False,
                reason=action_reason,
                warnings=warnings,
                risk_level=risk_level
            )
        
        if "WARNING" in action_reason:
            warnings.append(action_reason)
        
        # Check notification requirements
        requires_notification = action.lower() in [a.lower() for a in self.scope.require_notification_before]
        if requires_notification:
            warnings.append(f"Action '{action}' requires prior client notification per RoE")
        
        # All checks passed
        self._audit_log("AUTHORIZED", target, action, action_reason)
        
        return AuthorizationResult(
            authorized=True,
            reason=f"Authorized: {target_reason}; {action_reason}",
            warnings=warnings,
            requires_notification=requires_notification,
            risk_level=risk_level
        )
    
    def _audit_log(self, decision: str, target: str, action: str, reason: str):
        """Write authorization decision to audit log."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "engagement_id": self.scope.engagement_id,
            "decision": decision,
            "target": target,
            "action": action,
            "reason": reason
        }
        
        with open(self.audit_log_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def get_scope_summary(self) -> str:
        """Generate human-readable scope summary."""
        lines = [
            f"═══════════════════════════════════════════════════════════════",
            f"ENGAGEMENT SCOPE: {self.scope.engagement_id}",
            f"Client: {self.scope.client_name}",
            f"═══════════════════════════════════════════════════════════════",
            "",
            "IN-SCOPE TARGETS:",
        ]
        
        for host in self.scope.in_scope_hosts:
            lines.append(f"  ✓ {host}")
        for domain in self.scope.in_scope_domains:
            lines.append(f"  ✓ {domain}")
        
        if self.scope.out_of_scope_hosts or self.scope.out_of_scope_domains:
            lines.append("\nOUT-OF-SCOPE (EXCLUDED):")
            for host in self.scope.out_of_scope_hosts:
                lines.append(f"  ✗ {host}")
            for domain in self.scope.out_of_scope_domains:
                lines.append(f"  ✗ {domain}")
        
        lines.extend([
            "",
            f"Maximum Risk Level: {self.scope.max_risk_level.name}",
            f"Credential Handling: {self.scope.credential_handling}",
            f"Data Handling: {self.scope.data_handling}",
        ])
        
        if self.scope.forbidden_actions:
            lines.append(f"\nForbidden Actions: {', '.join(self.scope.forbidden_actions)}")
        
        if self.scope.rules_of_engagement_ref:
            lines.append(f"\nRoE Reference: {self.scope.rules_of_engagement_ref}")
        
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# EXAMPLE USAGE & CLI
# ═══════════════════════════════════════════════════════════════════════════════

def create_example_scope() -> EngagementScope:
    """Create an example engagement scope for testing."""
    return EngagementScope(
        engagement_id="PENTEST-2024-001",
        client_name="Example Corp",
        in_scope_hosts=["192.168.1.0/24", "10.0.0.0/8"],
        in_scope_domains=["*.example.com", "example.org"],
        out_of_scope_hosts=["192.168.1.1"],  # Router
        out_of_scope_domains=["payment.example.com"],  # Payment system
        allowed_categories=[
            ActionCategory.PASSIVE_RECON,
            ActionCategory.ACTIVE_RECON,
            ActionCategory.VULNERABILITY_SCAN,
            ActionCategory.EXPLOITATION,
            ActionCategory.CREDENTIAL_ACCESS,
            ActionCategory.LATERAL_MOVEMENT
        ],
        forbidden_actions=["skeleton_key", "log_cleanup"],
        max_risk_level=RiskLevel.HIGH,
        require_notification_before=["lsass_dump", "dcsync"],
        credential_handling="hash_only",
        data_handling="no_exfil",
        rules_of_engagement_ref="RoE-2024-001-signed.pdf"
    )


def main():
    """Demonstration of Policy Engine."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA POLICY ENGINE
   Engagement Scope Validation & Safety Enforcement
═══════════════════════════════════════════════════════════════════
""")
    
    # Create example scope
    scope = create_example_scope()
    engine = PolicyEngine(scope)
    
    # Display scope
    print(engine.get_scope_summary())
    
    # Test authorizations
    print("\n\n🔐 AUTHORIZATION TESTS:\n")
    
    test_cases = [
        ("192.168.1.100", "nmap_discovery"),      # Should pass
        ("192.168.1.1", "nmap_discovery"),         # Out of scope (router)
        ("payment.example.com", "sqlmap"),         # Out of scope (payment)
        ("web.example.com", "gobuster"),           # Should pass
        ("10.0.0.50", "kerberoasting"),           # Should pass
        ("10.0.0.50", "skeleton_key"),            # Forbidden action
        ("10.0.0.50", "golden_ticket"),           # Exceeds risk level (CRITICAL)
        ("external.com", "nmap_vuln"),            # Out of scope
    ]
    
    for target, action in test_cases:
        result = engine.authorize_action(target, action)
        status = "✅ AUTHORIZED" if result.authorized else "❌ DENIED"
        print(f"{status}: {action} → {target}")
        print(f"   Reason: {result.reason}")
        if result.warnings:
            for warning in result.warnings:
                print(f"   ⚠ {warning}")
        if result.requires_notification:
            print(f"   📞 Requires prior notification!")
        print()


if __name__ == "__main__":
    main()
