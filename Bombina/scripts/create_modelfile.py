#!/usr/bin/env python3
"""
Create Enhanced Modelfile for Ollama
Embeds pentest reasoning patterns directly into the model via system prompt

This is a workaround when GPU fine-tuning isn't possible.
Not as good as LoRA, but functional.

Usage: python create_modelfile.py
       ollama create bombina-enhanced -f Modelfile.enhanced
"""

import json
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
TRAIN_FILE = BASE_DIR / "data" / "train.jsonl"
OUTPUT_FILE = BASE_DIR / "Modelfile.enhanced"

# Select the best samples to embed (limited by context window)
CATEGORIES_TO_INCLUDE = [
    "ad_attacks",
    "cloud_attacks", 
    "privilege_escalation",
    "lateral_movement",
    "evasion"
]

def extract_key_samples(max_samples=15):
    """Extract the most valuable training samples for embedding."""
    samples = []
    
    with open(TRAIN_FILE) as f:
        for line in f:
            sample = json.loads(line)
            # Prioritize samples with rich reasoning
            output = sample.get('output', '')
            if len(output) > 300 and any(kw in output.lower() for kw in 
                ['detection', 'risk', 'stealth', 'alternative', 'because', 'trade-off']):
                samples.append(sample)
    
    # Take diverse samples
    return samples[:max_samples]


def build_reasoning_examples(samples):
    """Format samples as few-shot examples."""
    examples = []
    
    for i, s in enumerate(samples, 1):
        example = f"""
### Example {i}
**Scenario**: {s['instruction']}
**Context**: {s.get('input', 'N/A')}
**Expert Analysis**:
{s['output']}
"""
        examples.append(example)
    
    return "\n".join(examples)


def create_modelfile():
    """Generate enhanced Modelfile."""
    
    samples = extract_key_samples(15)
    examples = build_reasoning_examples(samples)
    
    system_prompt = f'''You are Bombina, an elite penetration testing AI assistant with decades of offensive security experience.

## Core Principles

1. **Reasoning First**: Never suggest tools without explaining WHY. Think in attack paths, trade-offs, and detection risk.

2. **Detection Awareness**: Always consider EDR, SIEM, and blue team detection. Mention specific detection risks.

3. **Adaptability**: Provide multiple approaches and fallback strategies when attacks fail.

4. **Restraint**: Respect engagement scope. Know when to stop or escalate to human judgment.

5. **Stealth Over Speed**: Prefer quiet techniques over noisy ones unless explicitly allowed.

## Your Expertise Includes

- Active Directory attacks (Kerberoasting, ADCS abuse, delegation attacks, DCSync)
- Cloud security (AWS IAM privesc, Azure AD, GCP service accounts)
- Web application testing (SQLi, auth bypass, WAF evasion)
- Network pivoting and lateral movement
- EDR/AV evasion techniques
- Post-exploitation and persistence
- Blue team detection patterns

## Response Format

When analyzing attack scenarios:
1. Assess the environment constraints
2. Identify viable attack paths
3. Evaluate detection risk for each path
4. Recommend the optimal approach with reasoning
5. Provide alternatives if primary path fails

## Expert Knowledge Examples
{examples}

## Important Rules

- Think step-by-step before answering
- Explain reasoning, not just commands
- Consider what could go wrong
- Mention detection/monitoring risks
- Suggest stealth alternatives when available
- Know when to recommend stopping or human escalation'''

    modelfile_content = f'''# Bombina Enhanced - Pentest AI
# Created with embedded reasoning patterns

FROM qwen2.5-coder:3b

PARAMETER temperature 0.3
PARAMETER top_p 0.9
PARAMETER num_ctx 4096
PARAMETER stop "### Instruction:"
PARAMETER stop "### Example"

SYSTEM """
{system_prompt}
"""
'''

    with open(OUTPUT_FILE, 'w') as f:
        f.write(modelfile_content)
    
    print(f"""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA ENHANCED MODELFILE CREATED
═══════════════════════════════════════════════════════════════════

📁 Output: {OUTPUT_FILE}
📊 Embedded: {len(samples)} expert reasoning samples

To create the enhanced model, run:

    ollama create bombina-enhanced -f {OUTPUT_FILE}

Then test with:

    ollama run bombina-enhanced

This is a workaround for GPU fine-tuning limitations.
For best results, use cloud GPU for proper LoRA training.
═══════════════════════════════════════════════════════════════════
""")


if __name__ == "__main__":
    create_modelfile()
