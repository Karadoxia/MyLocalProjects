#!/usr/bin/env python3
"""
Cloud Attack Extractor for Bombina
Generates high-quality training samples for AWS, Azure, GCP attacks
Focus: IAM misconfigurations, privilege escalation, persistence

Usage: python extract_cloud.py
"""

import json
from pathlib import Path
from typing import Dict, List

BASE_DIR = Path(__file__).parent.parent.parent
OUTPUT_DIR = BASE_DIR / "data" / "datasets" / "cloud_attacks"

# ═══════════════════════════════════════════════════════════════════════════════
# AWS ATTACK KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════════════════════════════

AWS_ATTACKS = [
    {
        "name": "IAM Privilege Escalation via Policy Attachment",
        "technique": "iam:AttachUserPolicy / iam:AttachRolePolicy",
        "scenario": "User has permission to attach policies",
        "reasoning": """When a principal has iam:AttachUserPolicy or iam:AttachRolePolicy permissions, they can escalate privileges by attaching AdministratorAccess or custom high-privilege policies to themselves. Detection: CloudTrail logs show AttachUserPolicy/AttachRolePolicy events. The attack is noisy because policy changes are typically monitored. Alternative approach: If iam:PutUserPolicy is available, create inline policies which may evade some detection rules focused on managed policy attachment."""
    },
    {
        "name": "Lambda Function Privilege Escalation",
        "technique": "lambda:CreateFunction + iam:PassRole",
        "scenario": "User can create Lambda functions and pass roles",
        "reasoning": """With lambda:CreateFunction and iam:PassRole, create a Lambda function that assumes a higher-privileged role. The function executes with the attached role's permissions. Detection risk: Medium - Lambda creation is logged but may not trigger alerts in dev environments. Key insight: Target roles with overly permissive trust policies that allow Lambda service principal. Check for roles with 'lambda.amazonaws.com' in trust policy."""
    },
    {
        "name": "EC2 Instance Profile Abuse",
        "technique": "ec2:RunInstances + iam:PassRole",
        "scenario": "Can launch EC2 instances with IAM roles",
        "reasoning": """Launch an EC2 instance with a high-privilege instance profile attached. SSH into the instance and use the metadata service (169.254.169.254) to obtain temporary credentials. IMDSv2 enforcement adds complexity but can often be bypassed in misconfigured environments. Detection: ec2:RunInstances with iam:PassRole is logged. Stealth consideration: Use existing authorized AMIs to blend in."""
    },
    {
        "name": "STS AssumeRole Chain",
        "technique": "sts:AssumeRole across accounts/roles",
        "scenario": "Role trust policies allow assumption",
        "reasoning": """Map out role trust relationships to find assumption chains leading to higher privileges. Cross-account roles often have overly permissive trust policies. Use enumerate-iam or pacu to discover assumable roles. The attack is relatively quiet - AssumeRole is normal behavior. Focus on roles trusting '*' or overly broad principals. Each hop in the chain provides new permissions to enumerate."""
    },
    {
        "name": "S3 Bucket Policy Modification",
        "technique": "s3:PutBucketPolicy",
        "scenario": "User can modify S3 bucket policies",
        "reasoning": """Modify bucket policy to grant yourself or an external account access to sensitive data. Can be used for data exfiltration or to establish persistence. Detection: S3 bucket policy changes are logged in CloudTrail and often monitored. Stealth approach: Add a condition that only allows access from specific IPs rather than granting broad public access. Consider time-limited policies that auto-expire."""
    },
    {
        "name": "CloudFormation Stack Privilege Escalation",
        "technique": "cloudformation:CreateStack + iam:PassRole",
        "scenario": "Can create CloudFormation stacks with IAM roles",
        "reasoning": """Create a CloudFormation stack that provisions resources with elevated IAM role. The stack executes with the passed role's permissions. Can create IAM users, roles, or EC2 instances with admin access. Detection: CloudFormation stack creation is logged. Stealth: Use legitimate-looking template names and descriptions. Consider deploying to less-monitored regions."""
    },
    {
        "name": "SSM Session Manager Lateral Movement",
        "technique": "ssm:StartSession",
        "scenario": "Has SSM permissions, targets have SSM agent",
        "reasoning": """Use SSM Session Manager to establish shell access to EC2 instances without SSH keys. Works even if security groups block SSH. Requires ssm:StartSession permission and target instance must have SSM agent running with appropriate IAM role. Detection: SSM sessions are logged in CloudTrail and Session Manager logs. Advantage: No need to modify security groups or have SSH keys."""
    },
    {
        "name": "Secrets Manager / Parameter Store Extraction",
        "technique": "secretsmanager:GetSecretValue / ssm:GetParameter",
        "scenario": "Read access to secrets storage",
        "reasoning": """Extract credentials, API keys, and sensitive configuration from Secrets Manager or SSM Parameter Store. Often contains database credentials, third-party API keys, or service account credentials. Detection: Get operations are logged but high volume makes monitoring difficult. Prioritize secrets with names suggesting database, admin, or production credentials. Check for rotation configuration - non-rotated secrets are higher value targets."""
    },
    {
        "name": "GuardDuty Evasion",
        "technique": "Behavioral evasion",
        "scenario": "GuardDuty is enabled in the account",
        "reasoning": """GuardDuty detects anomalous API behavior, cryptocurrency mining, and known malicious IPs. Evasion strategies: 1) Use slow, low-volume reconnaissance to avoid behavioral anomalies. 2) Operate during business hours from geographic regions matching normal usage. 3) Avoid obvious indicators like scanning or brute force. 4) Use AWS-native tools (CLI, SDK) rather than third-party pentest tools with known signatures. 5) Disable GuardDuty if you have guardduty:DeleteDetector permission - but this is highly visible."""
    },
    {
        "name": "Cross-Account Data Exfiltration",
        "technique": "Resource-based policy abuse",
        "scenario": "Can modify resource policies on S3/KMS/SNS",
        "reasoning": """Add cross-account access to resource policies allowing data exfiltration to attacker-controlled account. S3 bucket policies, KMS key policies, and SNS topic policies can grant cross-account access. Detection: Policy modifications are logged. Stealth: Use legitimate-looking account IDs (from same organization if compromised) rather than obviously external accounts. Consider using AWS Organizations to identify accounts that might have implicit trust."""
    }
]

# ═══════════════════════════════════════════════════════════════════════════════
# AZURE ATTACK KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════════════════════════════

AZURE_ATTACKS = [
    {
        "name": "Azure AD Privilege Escalation via App Registration",
        "technique": "Application.ReadWrite.All abuse",
        "scenario": "User can create/modify app registrations",
        "reasoning": """With Application.ReadWrite.All permission, create an application with high-privilege API permissions and grant admin consent. Alternatively, add credentials to existing applications with elevated permissions. Detection: Application creation and modification is logged in Azure AD audit logs. Focus on applications with Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory, or similar sensitive permissions. Check for applications without credential expiration or with multiple credentials (indicating potential abuse)."""
    },
    {
        "name": "Managed Identity Token Theft",
        "technique": "IMDS exploitation on Azure VMs",
        "scenario": "Access to Azure VM with managed identity",
        "reasoning": """Query the Instance Metadata Service (169.254.169.254) to obtain access tokens for the VM's managed identity. Works for both system-assigned and user-assigned identities. Token is valid for downstream Azure resource access. Detection: IMDS queries are not logged - this is relatively stealthy. However, subsequent API calls using the token are logged. Enumerate identity permissions with az role assignment list before taking high-visibility actions."""
    },
    {
        "name": "Azure Key Vault Extraction",
        "technique": "Key Vault access policy abuse",
        "scenario": "Has Get/List permissions on Key Vault",
        "reasoning": """Extract secrets, keys, and certificates from Azure Key Vault. Common targets: storage account keys, database connection strings, service principal credentials. Detection: Key Vault has detailed diagnostic logging if enabled. Check vault access policies for overly permissive configurations. Soft-delete recovery: Deleted secrets can often be recovered if soft-delete is enabled and purge protection is off."""
    },
    {
        "name": "Service Principal Credential Addition",
        "technique": "microsoft.directory/servicePrincipals/credentials/update",
        "scenario": "Can add credentials to service principals",
        "reasoning": """Add new client secret or certificate to existing service principal. Provides persistent access as that service principal. Target service principals with high-privilege role assignments or API permissions. Detection: Credential additions are logged in audit logs. Stealth: Add certificate-based credential rather than client secret - less commonly monitored. Set long expiration to maintain persistence."""
    },
    {
        "name": "Azure Resource Manager Role Assignment",
        "technique": "Microsoft.Authorization/roleAssignments/write",
        "scenario": "Can create role assignments",
        "reasoning": """Assign privileged roles (Owner, Contributor, User Access Administrator) to controlled identities. Can be done at subscription, resource group, or resource scope. Detection: Role assignment changes are logged and often alerted on. Stealth approach: Assign roles at resource level rather than subscription level to reduce visibility. Target custom roles that may have privileged permissions but less monitoring."""
    },
    {
        "name": "Azure Automation Runbook Execution",
        "technique": "Automation Account with Run As Account",
        "scenario": "Access to Automation Account",
        "reasoning": """Execute PowerShell/Python runbooks using the Automation Account's Run As Account (service principal). Runbooks can perform actions with the service principal's permissions. Detection: Runbook executions are logged in job history. Stealth: Modify existing runbooks rather than creating new ones. Use hybrid workers if available to execute outside Azure."""
    },
    {
        "name": "Conditional Access Policy Bypass",
        "technique": "Policy analysis and evasion",
        "scenario": "Conditional Access policies restrict access",
        "reasoning": """Analyze CA policies for gaps: legacy authentication exclusions, location-based exclusions, device trust bypasses. Legacy protocols (IMAP, SMTP, POP3) often bypass modern CA policies. Test from excluded locations or using excluded applications. Detection: Sign-in logs show CA policy evaluation results. Stealth is difficult - focus on finding legitimate exclusions rather than bypassing."""
    },
    {
        "name": "Azure AD Connect Password Extraction",
        "technique": "AD Connect server compromise",
        "scenario": "Access to Azure AD Connect server",
        "reasoning": """Azure AD Connect server contains credentials for directory synchronization. AADInternals module can extract sync credentials. Provides ability to modify on-prem objects that sync to Azure AD. Detection: Requires local admin on AD Connect server - initial access is the challenge. Once on the server, extraction is difficult to detect. Consider DPAPI extraction and credential file access. High-value target for hybrid environment compromise."""
    }
]

# ═══════════════════════════════════════════════════════════════════════════════
# GCP ATTACK KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════════════════════════════

GCP_ATTACKS = [
    {
        "name": "Service Account Key Creation",
        "technique": "iam.serviceAccountKeys.create",
        "scenario": "Can create keys for service accounts",
        "reasoning": """Create a new key for an existing service account to obtain persistent credentials. Target service accounts with project-level Editor/Owner roles. Detection: Service account key creation is logged in Cloud Audit Logs. Keys created but not associated with legitimate automation are suspicious. Stealth: Target service accounts that already have multiple keys - one more is less noticeable."""
    },
    {
        "name": "Compute Instance Privilege Escalation",
        "technique": "compute.instances.setServiceAccount",
        "scenario": "Can modify VM service account",
        "reasoning": """Change the service account attached to a Compute Engine instance to one with higher privileges. Requires compute.instances.setServiceAccount and iam.serviceAccounts.actAs on target service account. Restart required for change to take effect. Detection: Instance metadata modification is logged. Alternative: If you have setMetadata permission, add SSH keys to gain instance access without changing service account."""
    },
    {
        "name": "Cloud Function Privilege Escalation",
        "technique": "cloudfunctions.functions.create + iam.serviceAccounts.actAs",
        "scenario": "Can create Cloud Functions with service accounts",
        "reasoning": """Create a Cloud Function that runs with a privileged service account. Function code executes with the service account's permissions. Detection: Function creation is logged. Stealth: Use existing function names/patterns that match legitimate deployment. Consider Cloud Run as alternative if Functions are more heavily monitored."""
    },
    {
        "name": "IAM Policy Binding Escalation",
        "technique": "resourcemanager.projects.setIamPolicy",
        "scenario": "Can modify project IAM policy",
        "reasoning": """Add IAM policy binding granting privileged roles to controlled identity. Can grant roles at project, folder, or organization level depending on permissions. Detection: IAM policy changes are logged and typically alerted on. Stealth: Grant predefined roles rather than primitive roles (roles/viewer vs roles/editor). Consider granting on specific resources rather than project-wide."""
    },
    {
        "name": "Storage Bucket Access",
        "technique": "storage.buckets.setIamPolicy",
        "scenario": "Can modify bucket IAM policies",
        "reasoning": """Modify bucket IAM policy to grant access to controlled identity or allUsers. Common misconfiguration target for data exfiltration. Detection: Bucket policy changes are logged. Public bucket access triggers additional alerts in many configurations. Stealth: Grant access to specific service account rather than broad access. Consider signed URLs for temporary access that doesn't modify policies."""
    },
    {
        "name": "Metadata Server Token Theft",
        "technique": "GCE metadata service abuse",
        "scenario": "Access to Compute Engine instance",
        "reasoning": """Query metadata server at http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token to obtain access token for instance's service account. Works for any GCE instance with attached service account. Detection: Metadata queries are not externally logged. Token use is logged based on API calls. Enumerate scopes at metadata endpoint before using token to understand available permissions."""
    },
    {
        "name": "VPC Service Controls Bypass",
        "technique": "Authorized network/identity abuse",
        "scenario": "Target resources protected by VPC-SC",
        "reasoning": """VPC Service Controls create perimeters around sensitive resources. Bypass techniques: compromise authorized identities, use authorized networks, exploit ingress/egress rules. Access context levels may allow bypass based on device state or IP. Detection: VPC-SC violations are logged as audit logs. Finding authorized entry points requires enumeration of perimeter configuration."""
    },
    {
        "name": "Workload Identity Federation Abuse",
        "technique": "External identity provider trust",
        "scenario": "GCP trusts external IdP",
        "reasoning": """If GCP workload identity federation trusts an external identity provider (AWS, Azure AD, OIDC), compromise of external identity can lead to GCP access. Enumerate workload identity pools and their provider configurations. Target: Service accounts that trust external identities. Detection: Token exchange is logged. Useful for cross-cloud lateral movement."""
    }
]

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD EVASION & DEFENSE SAMPLES
# ═══════════════════════════════════════════════════════════════════════════════

CLOUD_DEFENSE_AWARENESS = [
    {
        "instruction": "You are testing an AWS environment with CloudTrail and GuardDuty enabled.",
        "input": "Need to enumerate IAM permissions without triggering alerts. Current user has basic read access.",
        "output": "GuardDuty detects reconnaissance patterns and anomalous API behavior. Approach: 1) Use sts:GetCallerIdentity first - this is expected and establishes baseline. 2) Enumerate slowly with delays between API calls. 3) Focus on specific services rather than broad enumeration - targeted iam:ListAttachedUserPolicies on your own user is less suspicious than iam:ListUsers. 4) Avoid pacu/ScoutSuite signatures - use AWS CLI directly. 5) Check CloudTrail configuration with cloudtrail:DescribeTrails to understand logging coverage. Detection risk: Medium if slow and targeted. High if using automated enumeration tools."
    },
    {
        "instruction": "Azure environment has Conditional Access policies requiring compliant devices and MFA.",
        "input": "Have valid credentials but failing CA policy evaluation. Need to gain access.",
        "output": "CA policy bypass strategies: 1) Check for legacy authentication exclusions - protocols like IMAP/SMTP often bypass modern policies. Test with basic auth against Exchange Online. 2) Analyze policy details via Graph API if you have AuditLog.Read.All. 3) Look for service principal credentials - SP authentication often has fewer CA restrictions. 4) Check for B2B/guest account policies - different CA policies may apply. 5) If device compliance required, check for hybrid join misconfiguration allowing any domain-joined device. Detection risk: Failed CA evaluations are logged. Multiple failures increase suspicion. Stealth approach: Analyze policies before attempting access."
    },
    {
        "instruction": "GCP environment uses Organization Policy constraints restricting external IP addresses on VMs.",
        "input": "Need to establish C2 channel from compromised VM without external IP.",
        "output": "Egress without external IP: 1) Cloud NAT - check if configured for the VPC. VMs can reach internet through NAT gateway. 2) Private Google Access - can reach Google APIs including Cloud Functions for data staging. 3) VPC peering - check for peered networks that might have less restrictive egress. 4) Internal load balancer with external backend - unusual but possible. 5) Cloud Interconnect/VPN - check for on-prem connectivity that might provide egress. 6) Use GCP APIs as C2 channel - store commands in GCS bucket, results in Pub/Sub. Detection risk: Unusual egress patterns are detectable. Using native GCP services is stealthier than external C2."
    },
    {
        "instruction": "Multi-cloud environment with AWS, Azure, and GCP. Need to plan lateral movement approach.",
        "input": "Initial access to AWS with IAM user credentials. Observed cross-cloud trusts in use.",
        "output": "Cross-cloud lateral movement strategy: 1) In AWS, enumerate roles with external trust policies - look for sts:AssumeRoleWithWebIdentity configurations trusting Azure AD or external OIDC. 2) Check for AWS credentials stored in Azure Key Vault or GCP Secret Manager via cross-cloud integrations. 3) Look for federated identity configurations - Azure AD applications with AWS role trust, GCP Workload Identity Federation. 4) CI/CD pipelines often have multi-cloud credentials - check CodePipeline, Azure DevOps, or Cloud Build for stored secrets. 5) Infrastructure-as-code repos may contain credentials for multiple clouds. Detection risk varies by cloud - focus on least-monitored environment for pivot. Priority: Find identity federation trust relationships that provide seamless cross-cloud access."
    }
]


def generate_cloud_samples() -> List[Dict]:
    """Generate training samples from cloud attack knowledge."""
    samples = []
    
    # AWS Samples
    for attack in AWS_ATTACKS:
        samples.append({
            "instruction": f"You are conducting a cloud penetration test against an AWS environment.",
            "input": f"Scenario: {attack['scenario']}. The technique {attack['technique']} appears possible. How do you approach this?",
            "output": attack['reasoning']
        })
        
        # Decision-making sample
        samples.append({
            "instruction": f"Evaluate the attack path: {attack['name']} in AWS.",
            "input": f"Available technique: {attack['technique']}. What are the tradeoffs?",
            "output": f"Attack analysis for {attack['name']}: {attack['reasoning'][:500]}... Key decision factors: detection likelihood, permission requirements, and persistence value. Always enumerate current permissions before attempting privilege escalation."
        })
    
    # Azure Samples
    for attack in AZURE_ATTACKS:
        samples.append({
            "instruction": f"You are conducting a cloud penetration test against an Azure/Entra ID environment.",
            "input": f"Scenario: {attack['scenario']}. Considering {attack['technique']}. What's your approach?",
            "output": attack['reasoning']
        })
        
        # Failure handling sample
        samples.append({
            "instruction": f"Your attempt at {attack['name']} in Azure failed due to insufficient permissions.",
            "input": "Need to find alternative escalation path. What do you check next?",
            "output": f"When {attack['technique']} fails, enumerate alternative paths: 1) Check for other high-privilege applications/service principals. 2) Look for group memberships that might provide indirect access. 3) Review custom roles for overlooked permissions. 4) Check PIM (Privileged Identity Management) for eligible role activations. The original technique ({attack['name']}) failing suggests monitoring may be in place - adjust operational tempo."
        })
    
    # GCP Samples
    for attack in GCP_ATTACKS:
        samples.append({
            "instruction": f"You are conducting a cloud penetration test against a GCP environment.",
            "input": f"Scenario: {attack['scenario']}. Technique available: {attack['technique']}. Analysis?",
            "output": attack['reasoning']
        })
    
    # Defense awareness samples
    samples.extend(CLOUD_DEFENSE_AWARENESS)
    
    return samples


def main():
    """Generate and save cloud attack samples."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA CLOUD ATTACK EXTRACTOR
   Generating AWS/Azure/GCP training samples
═══════════════════════════════════════════════════════════════════
""")
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    samples = generate_cloud_samples()
    
    output_file = OUTPUT_DIR / "cloud_samples.jsonl"
    with open(output_file, 'w') as f:
        for sample in samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"✅ Generated {len(samples)} cloud attack samples")
    print(f"📁 Output: {output_file}")


if __name__ == "__main__":
    main()
