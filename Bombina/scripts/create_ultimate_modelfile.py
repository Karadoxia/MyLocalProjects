#!/usr/bin/env python3
"""
Create Ultimate Modelfile for Ollama
Maximum reasoning injection via system prompt + few-shot examples

This pushes the limits of what's possible without GPU fine-tuning.

Usage: python create_ultimate_modelfile.py
       ollama create bombina-ultimate -f Modelfile.ultimate
"""

import json
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
TRAIN_FILE = BASE_DIR / "data" / "train.jsonl"
OUTPUT_FILE = BASE_DIR / "Modelfile.ultimate"


def load_best_samples(max_samples=25):
    """Load the highest quality samples across all categories."""
    samples_by_category = {}
    
    with open(TRAIN_FILE) as f:
        for line in f:
            sample = json.loads(line)
            output = sample.get('output', '')
            
            # Score sample quality
            quality_score = 0
            quality_keywords = [
                'detection', 'risk', 'stealth', 'alternative', 'because',
                'trade-off', 'evasion', 'consider', 'however', 'instead',
                'fallback', 'prioritize', 'constraint', 'blue team', 'edr'
            ]
            for kw in quality_keywords:
                if kw in output.lower():
                    quality_score += 1
            
            # Must have substantial reasoning
            if len(output) > 400 and quality_score >= 4:
                # Categorize
                text_lower = (sample.get('instruction', '') + sample.get('input', '')).lower()
                
                if any(k in text_lower for k in ['kerberos', 'active directory', 'ad ', 'domain']):
                    cat = 'ad_attacks'
                elif any(k in text_lower for k in ['aws', 'azure', 'gcp', 'cloud', 'iam']):
                    cat = 'cloud'
                elif any(k in text_lower for k in ['lateral', 'pivot', 'movement']):
                    cat = 'lateral'
                elif any(k in text_lower for k in ['evasion', 'edr', 'detection', 'stealth']):
                    cat = 'evasion'
                elif any(k in text_lower for k in ['fail', 'blocked', 'alternative']):
                    cat = 'failure'
                elif any(k in text_lower for k in ['web', 'sql', 'xss', 'waf']):
                    cat = 'web'
                else:
                    cat = 'general'
                
                if cat not in samples_by_category:
                    samples_by_category[cat] = []
                samples_by_category[cat].append((quality_score, sample))
    
    # Take best from each category
    selected = []
    per_category = max_samples // len(samples_by_category) if samples_by_category else max_samples
    
    for cat, samples in samples_by_category.items():
        samples.sort(key=lambda x: x[0], reverse=True)
        selected.extend([s[1] for s in samples[:per_category]])
    
    return selected[:max_samples]


def format_examples(samples):
    """Format samples as expert reasoning demonstrations."""
    examples = []
    
    for i, s in enumerate(samples, 1):
        # Truncate if too long but keep reasoning intact
        output = s['output']
        if len(output) > 600:
            # Find a good breaking point
            sentences = output.split('. ')
            truncated = []
            length = 0
            for sent in sentences:
                if length + len(sent) < 550:
                    truncated.append(sent)
                    length += len(sent)
                else:
                    break
            output = '. '.join(truncated) + '.'
        
        example = f"""<example_{i}>
Scenario: {s['instruction']}
Context: {s.get('input', 'N/A')}
Expert Analysis: {output}
</example_{i}>"""
        examples.append(example)
    
    return "\n\n".join(examples)


def create_ultimate_modelfile():
    """Generate the ultimate Modelfile."""
    
    samples = load_best_samples(25)
    examples = format_examples(samples)
    
    system_prompt = f'''You are Bombina, an elite penetration testing AI with 20+ years of offensive security experience.

## CORE IDENTITY

You think like the world's best penetration testers:
- Every decision has a WHY
- Every technique has detection risks
- Every attack path has alternatives
- Every failure teaches something

## MANDATORY RESPONSE STRUCTURE

For ANY pentest question, you MUST address:

1. **Environment Analysis** - What constraints exist? (EDR, network segmentation, credentials available)
2. **Attack Path Prioritization** - WHY this path over others?
3. **Detection Risk Assessment** - What alerts could fire? What logs are generated?
4. **Execution Approach** - Stealth vs speed trade-off
5. **Fallback Strategy** - What if this fails?

## EXPERTISE DOMAINS

### Active Directory
- Kerberoasting, AS-REP roasting, Golden/Silver tickets
- ADCS abuse (ESC1-ESC8), delegation attacks
- DCSync, LSASS alternatives, DPAPI abuse
- BloodHound attack paths, ACL abuse

### Cloud Security
- AWS: IAM privesc, STS abuse, Lambda pivoting, GuardDuty evasion
- Azure: App Registration abuse, Managed Identity theft, PRT attacks
- GCP: Service account key creation, metadata abuse

### Evasion & Stealth
- EDR bypass techniques and their detection signatures
- Living-off-the-land binaries (LOLBins)
- Process injection alternatives
- Log evasion and timestamp manipulation

### Web Applications
- WAF bypass methodologies
- Authentication bypass logic
- SQLi/XSS in hardened environments
- API security weaknesses

## EXPERT REASONING EXAMPLES

{examples}

## CRITICAL RULES

1. **Never just list commands** - Explain WHY each step
2. **Always consider detection** - What would blue team see?
3. **Provide alternatives** - First path blocked? What's plan B?
4. **Know when to stop** - Some risks aren't worth taking
5. **Think adversarially** - What would a defender do next?

## OUTPUT STYLE

- Be direct and technical
- Use specific tool names and techniques
- Include detection considerations inline
- Provide risk assessments (Low/Medium/High)
- Structure complex responses with headers'''

    modelfile_content = f'''# Bombina Ultimate - Maximum Reasoning Injection
# Fine-tuned behavior via comprehensive system prompt

FROM qwen2.5-coder:3b

# Inference parameters optimized for reasoning
PARAMETER temperature 0.4
PARAMETER top_p 0.9
PARAMETER top_k 40
PARAMETER num_ctx 4096
PARAMETER repeat_penalty 1.1
PARAMETER stop "### Instruction:"
PARAMETER stop "<example_"
PARAMETER stop "Scenario:"

SYSTEM """
{system_prompt}
"""
'''

    with open(OUTPUT_FILE, 'w') as f:
        f.write(modelfile_content)
    
    print(f"""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA ULTIMATE MODELFILE CREATED
═══════════════════════════════════════════════════════════════════

📁 Output: {OUTPUT_FILE}
📊 Embedded: {len(samples)} high-quality reasoning examples
🧠 System prompt: ~{len(system_prompt)} characters

To create the ultimate model:

    ollama create bombina-ultimate -f {OUTPUT_FILE}

Then test with:

    ollama run bombina-ultimate "You have domain user creds and BloodHound shows a path via constrained delegation. EDR is CrowdStrike. Walk me through the attack."

═══════════════════════════════════════════════════════════════════
""")


if __name__ == "__main__":
    create_ultimate_modelfile()
