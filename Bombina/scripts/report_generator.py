#!/usr/bin/env python3
"""
Bombina Professional Report Generator
Generates pentest reports with executive summary, findings, MITRE mapping

Output formats: Markdown, HTML (future: PDF via weasyprint)

Usage: python report_generator.py --input findings.json --output report.md
"""

import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime
from enum import Enum


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFORMATIONAL = 0


class FindingStatus(Enum):
    """Finding status."""
    OPEN = "open"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


# ═══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class MitreMapping:
    """MITRE ATT&CK mapping for a finding."""
    tactic: str
    technique_id: str
    technique_name: str
    subtechnique_id: Optional[str] = None
    subtechnique_name: Optional[str] = None
    
    def __str__(self):
        if self.subtechnique_id:
            return f"{self.technique_id}.{self.subtechnique_id} - {self.subtechnique_name}"
        return f"{self.technique_id} - {self.technique_name}"


@dataclass
class Finding:
    """Individual security finding."""
    id: str
    title: str
    severity: Severity
    description: str
    impact: str
    affected_assets: List[str]
    evidence: str
    remediation: str
    references: List[str] = field(default_factory=list)
    mitre_mappings: List[MitreMapping] = field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict) -> "Finding":
        """Create Finding from dictionary."""
        mitre = [MitreMapping(**m) for m in data.get("mitre_mappings", [])]
        return cls(
            id=data["id"],
            title=data["title"],
            severity=Severity[data["severity"].upper()],
            description=data["description"],
            impact=data["impact"],
            affected_assets=data.get("affected_assets", []),
            evidence=data.get("evidence", ""),
            remediation=data["remediation"],
            references=data.get("references", []),
            mitre_mappings=mitre,
            status=FindingStatus(data.get("status", "open")),
            cvss_score=data.get("cvss_score"),
            cwe_id=data.get("cwe_id")
        )


@dataclass
class EngagementInfo:
    """Engagement metadata."""
    engagement_id: str
    client_name: str
    assessment_type: str  # "External Network", "Internal Network", "Web Application", etc.
    start_date: str
    end_date: str
    scope_summary: str
    methodology: str
    testers: List[str]
    version: str = "1.0"
    classification: str = "CONFIDENTIAL"


@dataclass
class PentestReport:
    """Complete penetration test report."""
    engagement: EngagementInfo
    findings: List[Finding]
    executive_summary: Optional[str] = None
    technical_summary: Optional[str] = None
    attack_narrative: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Generates professional pentest reports."""
    
    SEVERITY_COLORS = {
        Severity.CRITICAL: "#8B0000",
        Severity.HIGH: "#FF4500",
        Severity.MEDIUM: "#FFA500",
        Severity.LOW: "#FFD700",
        Severity.INFORMATIONAL: "#4169E1"
    }
    
    SEVERITY_EMOJI = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🟢",
        Severity.INFORMATIONAL: "🔵"
    }
    
    def __init__(self, report: PentestReport):
        self.report = report
    
    def generate_executive_summary(self) -> str:
        """Auto-generate executive summary from findings."""
        findings = self.report.findings
        total = len(findings)
        
        by_severity = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        
        critical = by_severity.get(Severity.CRITICAL, 0)
        high = by_severity.get(Severity.HIGH, 0)
        medium = by_severity.get(Severity.MEDIUM, 0)
        low = by_severity.get(Severity.LOW, 0)
        info = by_severity.get(Severity.INFORMATIONAL, 0)
        
        # Determine overall risk posture
        if critical > 0:
            posture = "**Critical Risk**"
            posture_desc = "The assessment identified critical vulnerabilities that pose immediate risk to the organization. Immediate remediation is strongly recommended."
        elif high > 2:
            posture = "**High Risk**"
            posture_desc = "Multiple high-severity findings were identified that could lead to significant compromise. Prioritized remediation is recommended."
        elif high > 0 or medium > 3:
            posture = "**Moderate Risk**"
            posture_desc = "The assessment identified vulnerabilities that should be addressed in a timely manner to reduce organizational risk."
        else:
            posture = "**Low Risk**"
            posture_desc = "The overall security posture is reasonable. Identified findings should be addressed as part of ongoing security improvement."
        
        summary = f"""
## Executive Summary

{self.report.engagement.client_name} engaged a penetration test of their {self.report.engagement.assessment_type} environment from {self.report.engagement.start_date} to {self.report.engagement.end_date}.

### Overall Risk Assessment

{posture}

{posture_desc}

### Finding Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {critical} |
| 🟠 High | {high} |
| 🟡 Medium | {medium} |
| 🟢 Low | {low} |
| 🔵 Informational | {info} |
| **Total** | **{total}** |

### Key Findings

"""
        # Add top 3 most critical findings
        sorted_findings = sorted(findings, key=lambda f: f.severity.value, reverse=True)
        for i, finding in enumerate(sorted_findings[:3], 1):
            emoji = self.SEVERITY_EMOJI[finding.severity]
            summary += f"{i}. {emoji} **{finding.title}** ({finding.severity.name})\n"
        
        return summary
    
    def generate_mitre_matrix(self) -> str:
        """Generate MITRE ATT&CK matrix visualization."""
        tactics_order = [
            "Reconnaissance", "Resource Development", "Initial Access",
            "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact"
        ]
        
        # Collect techniques by tactic
        tactic_techniques = {t: [] for t in tactics_order}
        
        for finding in self.report.findings:
            for mapping in finding.mitre_mappings:
                if mapping.tactic in tactic_techniques:
                    tactic_techniques[mapping.tactic].append({
                        "technique": str(mapping),
                        "finding_id": finding.id,
                        "severity": finding.severity
                    })
        
        # Build markdown table
        matrix = """
## MITRE ATT&CK® Mapping

The following matrix shows the ATT&CK techniques observed during the assessment:

| Tactic | Techniques Observed |
|--------|---------------------|
"""
        
        for tactic in tactics_order:
            techniques = tactic_techniques.get(tactic, [])
            if techniques:
                tech_list = ", ".join([f"`{t['technique']}`" for t in techniques])
                matrix += f"| {tactic} | {tech_list} |\n"
        
        # Add technique details
        matrix += "\n### Technique Details\n\n"
        
        all_mappings = []
        for finding in self.report.findings:
            for mapping in finding.mitre_mappings:
                all_mappings.append((mapping, finding))
        
        for mapping, finding in all_mappings:
            emoji = self.SEVERITY_EMOJI[finding.severity]
            matrix += f"- **{mapping}** - {emoji} Found in [{finding.id}](#{finding.id.lower()}): {finding.title}\n"
        
        return matrix
    
    def generate_finding_section(self, finding: Finding) -> str:
        """Generate detailed section for a single finding."""
        emoji = self.SEVERITY_EMOJI[finding.severity]
        
        section = f"""
---

### {emoji} {finding.id}: {finding.title}

| Attribute | Value |
|-----------|-------|
| **Severity** | {finding.severity.name} |
| **Status** | {finding.status.value.replace('_', ' ').title()} |
"""
        
        if finding.cvss_score:
            section += f"| **CVSS Score** | {finding.cvss_score} |\n"
        
        if finding.cwe_id:
            section += f"| **CWE** | {finding.cwe_id} |\n"
        
        section += f"""
**Affected Assets:**
"""
        for asset in finding.affected_assets:
            section += f"- `{asset}`\n"
        
        section += f"""
#### Description

{finding.description}

#### Impact

{finding.impact}

#### Evidence

```
{finding.evidence}
```

#### Remediation

{finding.remediation}

"""
        
        if finding.mitre_mappings:
            section += "#### MITRE ATT&CK® Mapping\n\n"
            for mapping in finding.mitre_mappings:
                section += f"- **{mapping.tactic}**: {mapping}\n"
            section += "\n"
        
        if finding.references:
            section += "#### References\n\n"
            for ref in finding.references:
                section += f"- {ref}\n"
        
        return section
    
    def generate_methodology_section(self) -> str:
        """Generate methodology section."""
        return f"""
## Methodology

The assessment followed a structured methodology aligned with industry standards:

### Assessment Approach

{self.report.engagement.methodology}

### Scope

{self.report.engagement.scope_summary}

### Testing Team

| Role | Name |
|------|------|
""" + "\n".join([f"| Penetration Tester | {t} |" for t in self.report.engagement.testers])
    
    def generate_attack_narrative(self) -> str:
        """Generate attack narrative if provided."""
        if not self.report.attack_narrative:
            return ""
        
        return f"""
## Attack Narrative

The following describes the attack path taken during the assessment:

{self.report.attack_narrative}
"""
    
    def generate_markdown_report(self) -> str:
        """Generate complete Markdown report."""
        header = f"""# Penetration Test Report

**Client:** {self.report.engagement.client_name}  
**Assessment Type:** {self.report.engagement.assessment_type}  
**Engagement ID:** {self.report.engagement.engagement_id}  
**Report Date:** {datetime.now().strftime('%Y-%m-%d')}  
**Version:** {self.report.engagement.version}  
**Classification:** {self.report.engagement.classification}

---

**Assessment Period:** {self.report.engagement.start_date} to {self.report.engagement.end_date}

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Methodology](#methodology)
3. [Attack Narrative](#attack-narrative)
4. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
5. [Detailed Findings](#detailed-findings)
6. [Appendix](#appendix)

---
"""
        
        # Build report sections
        sections = [
            header,
            self.generate_executive_summary(),
            self.generate_methodology_section(),
            self.generate_attack_narrative(),
            self.generate_mitre_matrix(),
            "\n---\n\n## Detailed Findings\n",
        ]
        
        # Add findings sorted by severity
        sorted_findings = sorted(
            self.report.findings,
            key=lambda f: f.severity.value,
            reverse=True
        )
        
        for finding in sorted_findings:
            sections.append(self.generate_finding_section(finding))
        
        # Appendix
        sections.append("""
---

## Appendix

### Severity Rating Definitions

| Rating | Description |
|--------|-------------|
| 🔴 Critical | Immediate exploitation possible with significant business impact. Requires immediate attention. |
| 🟠 High | Exploitation possible with notable impact. Should be addressed within 30 days. |
| 🟡 Medium | Exploitation possible with moderate impact. Should be addressed within 90 days. |
| 🟢 Low | Exploitation difficult or impact limited. Address as resources permit. |
| 🔵 Informational | Best practice recommendation or observation. No direct security impact. |

### Disclaimer

This report contains confidential information about the security posture of {client}. Distribution should be limited to authorized personnel. The findings represent point-in-time observations and may not reflect the current state of the environment.

---

*Report generated by Bombina Report Generator*
""".format(client=self.report.engagement.client_name))
        
        return "\n".join(sections)
    
    def generate_html_report(self) -> str:
        """Generate HTML report with styling."""
        markdown_content = self.generate_markdown_report()
        
        # Simple markdown to HTML conversion (basic)
        # In production, use markdown library
        html_content = markdown_content
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {self.report.engagement.client_name}</title>
    <style>
        :root {{
            --critical: #8B0000;
            --high: #FF4500;
            --medium: #FFA500;
            --low: #FFD700;
            --info: #4169E1;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            background: #f5f5f5;
        }}
        
        .report-container {{
            background: white;
            padding: 3rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        h1, h2, h3 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 0.5rem;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }}
        
        th, td {{
            border: 1px solid #ddd;
            padding: 0.75rem;
            text-align: left;
        }}
        
        th {{
            background: #3498db;
            color: white;
        }}
        
        tr:nth-child(even) {{
            background: #f9f9f9;
        }}
        
        code {{
            background: #f4f4f4;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: 'Consolas', monospace;
        }}
        
        pre {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 1rem;
            border-radius: 5px;
            overflow-x: auto;
        }}
        
        .severity-critical {{ color: var(--critical); font-weight: bold; }}
        .severity-high {{ color: var(--high); font-weight: bold; }}
        .severity-medium {{ color: var(--medium); font-weight: bold; }}
        .severity-low {{ color: var(--low); font-weight: bold; }}
        .severity-info {{ color: var(--info); font-weight: bold; }}
        
        .finding-card {{
            border: 1px solid #ddd;
            border-radius: 8px;
            margin: 1rem 0;
            padding: 1.5rem;
        }}
        
        .classification-banner {{
            background: #e74c3c;
            color: white;
            text-align: center;
            padding: 0.5rem;
            font-weight: bold;
            position: sticky;
            top: 0;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            .report-container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="classification-banner">{self.report.engagement.classification}</div>
    <div class="report-container">
        <pre style="background: white; color: black; white-space: pre-wrap;">{html_content}</pre>
    </div>
</body>
</html>
"""
        return html
    
    def save_report(self, output_path: Path, format: str = "markdown"):
        """Save report to file."""
        if format == "markdown":
            content = self.generate_markdown_report()
            suffix = ".md"
        elif format == "html":
            content = self.generate_html_report()
            suffix = ".html"
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        output_path = output_path.with_suffix(suffix)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(content)
        
        return output_path


# ═══════════════════════════════════════════════════════════════════════════════
# EXAMPLE & CLI
# ═══════════════════════════════════════════════════════════════════════════════

def create_example_report() -> PentestReport:
    """Create example report for demonstration."""
    engagement = EngagementInfo(
        engagement_id="PENTEST-2024-001",
        client_name="Example Corporation",
        assessment_type="Internal Network",
        start_date="2024-01-15",
        end_date="2024-01-22",
        scope_summary="Internal network assessment covering 192.168.1.0/24, all Active Directory assets, and internal web applications.",
        methodology="The assessment followed PTES (Penetration Testing Execution Standard) methodology, including reconnaissance, enumeration, vulnerability assessment, exploitation, and post-exploitation phases.",
        testers=["Security Analyst - Bombina AI", "Lead Tester - John Doe"],
        classification="CONFIDENTIAL"
    )
    
    findings = [
        Finding(
            id="FIND-001",
            title="Domain Admin via Kerberoasting",
            severity=Severity.CRITICAL,
            description="A service account with Domain Admin privileges was configured with a weak password. The account's SPN allowed Kerberoasting, and the password was cracked offline within 4 hours using hashcat.",
            impact="Complete domain compromise. An attacker could access all domain resources, exfiltrate sensitive data, deploy ransomware, or establish persistent backdoors.",
            affected_assets=["svc_backup@example.local", "DC01.example.local"],
            evidence="impacket-GetUserSPNs -dc-ip 192.168.1.10 example.local/jdoe\n$krb5tgs$23$*svc_backup$EXAMPLE.LOCAL$...[hash truncated]...\n\nhashcat -m 13100 hash.txt rockyou.txt\n[CRACKED] Summer2023!",
            remediation="1. Immediately change the svc_backup password to a 25+ character random string\n2. Remove unnecessary Domain Admin privileges from service accounts\n3. Implement Group Managed Service Accounts (gMSA) for service accounts\n4. Enable monitoring for Kerberoasting (Event ID 4769 with encryption type 0x17)",
            cvss_score=9.8,
            cwe_id="CWE-521",
            mitre_mappings=[
                MitreMapping(tactic="Credential Access", technique_id="T1558", technique_name="Steal or Forge Kerberos Tickets", subtechnique_id="003", subtechnique_name="Kerberoasting")
            ],
            references=[
                "https://attack.mitre.org/techniques/T1558/003/",
                "https://adsecurity.org/?p=2293"
            ]
        ),
        Finding(
            id="FIND-002",
            title="ADCS ESC1 Privilege Escalation",
            severity=Severity.HIGH,
            description="A certificate template 'UserAuthentication' was found with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT enabled, allowing any authenticated user to request certificates for arbitrary users including Domain Admins.",
            impact="Any domain user can escalate to Domain Admin by requesting a certificate with Domain Admin SAN.",
            affected_assets=["CA01.example.local", "UserAuthentication template"],
            evidence="Certify.exe find /vulnerable\n\n[!] Vulnerable Certificate Template: UserAuthentication\n    CA Name: CA01.example.local\n    Enrollee Supplies Subject: True\n    Client Authentication: True",
            remediation="1. Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from the template\n2. Restrict enrollment permissions to specific security groups\n3. Enable 'CA certificate manager approval' for sensitive templates\n4. Implement certificate request monitoring",
            cvss_score=8.8,
            cwe_id="CWE-863",
            mitre_mappings=[
                MitreMapping(tactic="Privilege Escalation", technique_id="T1649", technique_name="Steal or Forge Authentication Certificates")
            ]
        ),
        Finding(
            id="FIND-003",
            title="SMB Signing Disabled",
            severity=Severity.MEDIUM,
            description="SMB signing is not enforced on multiple servers, allowing potential relay attacks.",
            impact="Attacker can relay NTLM authentication to execute commands on vulnerable servers.",
            affected_assets=["192.168.1.50", "192.168.1.51", "192.168.1.52"],
            evidence="crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt\n[*] 192.168.1.50 - SMB signing: False\n[*] 192.168.1.51 - SMB signing: False\n[*] 192.168.1.52 - SMB signing: False",
            remediation="Enable and require SMB signing via Group Policy:\n- Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options\n- Set 'Microsoft network server: Digitally sign communications (always)' to Enabled",
            cvss_score=5.9,
            mitre_mappings=[
                MitreMapping(tactic="Credential Access", technique_id="T1557", technique_name="Adversary-in-the-Middle", subtechnique_id="001", subtechnique_name="LLMNR/NBT-NS Poisoning and SMB Relay")
            ]
        ),
        Finding(
            id="FIND-004",
            title="Default Credentials on Network Device",
            severity=Severity.LOW,
            description="A network printer was found using default credentials.",
            impact="Limited impact - printer configuration could be modified.",
            affected_assets=["192.168.1.200 (HP LaserJet)"],
            evidence="Default credentials admin:admin allowed access to printer web interface.",
            remediation="Change default credentials on all network devices.",
            cvss_score=3.1
        )
    ]
    
    return PentestReport(
        engagement=engagement,
        findings=findings,
        attack_narrative="""
### Phase 1: Initial Foothold

After successful phishing simulation, the testing team obtained valid domain credentials for a standard user account (jdoe).

### Phase 2: Enumeration

BloodHound data collection revealed the Kerberoastable service account (svc_backup) with Domain Admin privileges.

### Phase 3: Privilege Escalation

The svc_backup account was Kerberoasted and cracked, providing Domain Admin access within 4 hours.

### Phase 4: Objective Achievement

With Domain Admin credentials, the team demonstrated access to:
- Domain Controller file systems
- SQL Server databases containing PII
- Backup infrastructure

Additionally, the ADCS vulnerability (ESC1) was identified as an alternative escalation path.
"""
    )


def main():
    parser = argparse.ArgumentParser(description="Bombina Report Generator")
    parser.add_argument("--input", "-i", help="Input findings JSON file")
    parser.add_argument("--output", "-o", default="report", help="Output filename (without extension)")
    parser.add_argument("--format", "-f", choices=["markdown", "html"], default="markdown", help="Output format")
    parser.add_argument("--example", action="store_true", help="Generate example report")
    args = parser.parse_args()
    
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA REPORT GENERATOR
   Professional Penetration Test Reports
═══════════════════════════════════════════════════════════════════
""")
    
    if args.example or not args.input:
        print("📝 Generating example report...")
        report = create_example_report()
    else:
        print(f"📂 Loading findings from: {args.input}")
        with open(args.input) as f:
            data = json.load(f)
        
        engagement = EngagementInfo(**data["engagement"])
        findings = [Finding.from_dict(f) for f in data["findings"]]
        report = PentestReport(
            engagement=engagement,
            findings=findings,
            attack_narrative=data.get("attack_narrative")
        )
    
    generator = ReportGenerator(report)
    output_path = Path(args.output)
    saved_path = generator.save_report(output_path, args.format)
    
    print(f"✅ Report generated: {saved_path}")
    print(f"   Findings: {len(report.findings)}")
    print(f"   Format: {args.format}")


if __name__ == "__main__":
    main()
