#!/usr/bin/env python3
"""
Merge all deep knowledge datasets and integrate with main dataset
Creates unified training set with enhanced innovation capabilities
"""

import json
import hashlib
from pathlib import Path

base_dir = Path(__file__).parent.parent
deep_knowledge_dir = base_dir / "data" / "deep_knowledge"
final_dir = base_dir / "data" / "final"

print("="*70)
print("🔗 MERGING DEEP KNOWLEDGE WITH MAIN DATASET")
print("="*70)

# Collect all deep knowledge samples
deep_samples = []
seen_hashes = set()

def get_hash(sample):
    content = f"{sample.get('instruction', '')}|{sample.get('input', '')}"
    return hashlib.md5(content.encode()).hexdigest()

# Load deep knowledge files
print("\n📚 Loading deep knowledge datasets...")
deep_files = list(deep_knowledge_dir.glob("*_train.jsonl"))
for f in sorted(deep_files):
    count = 0
    with open(f) as fp:
        for line in fp:
            sample = json.loads(line)
            h = get_hash(sample)
            if h not in seen_hashes:
                seen_hashes.add(h)
                deep_samples.append(sample)
                count += 1
    print(f"   {f.name}: {count} samples")

print(f"\n✅ Total deep knowledge samples: {len(deep_samples)}")

# Load existing main dataset
print("\n📚 Loading main training dataset...")
main_train_file = final_dir / "train.jsonl"
main_samples = []
main_count = 0
duplicates = 0

with open(main_train_file) as f:
    for line in f:
        sample = json.loads(line)
        h = get_hash(sample)
        if h not in seen_hashes:
            seen_hashes.add(h)
            main_samples.append(sample)
            main_count += 1
        else:
            duplicates += 1

print(f"   Main dataset: {main_count} unique samples")
print(f"   Duplicates skipped: {duplicates}")

# Combine all samples
combined = main_samples + deep_samples
print(f"\n📊 Combined dataset: {len(combined)} samples")

# Calculate split
import random
random.shuffle(combined)
split_idx = int(len(combined) * 0.95)
train_combined = combined[:split_idx]
val_combined = combined[split_idx:]

# Save enhanced dataset
enhanced_dir = base_dir / "data" / "enhanced"
enhanced_dir.mkdir(parents=True, exist_ok=True)

train_file = enhanced_dir / "train.jsonl"
val_file = enhanced_dir / "val.jsonl"

with open(train_file, "w") as f:
    for s in train_combined:
        f.write(json.dumps(s) + "\n")

with open(val_file, "w") as f:
    for s in val_combined:
        f.write(json.dumps(s) + "\n")

print(f"\n{'='*70}")
print("💾 ENHANCED DATASET SAVED")
print(f"{'='*70}")
print(f"\n✅ Train: {len(train_combined)} samples")
print(f"✅ Val: {len(val_combined)} samples")
print(f"✅ Total: {len(combined)} samples")
print(f"\n📁 Output: {enhanced_dir}")

# Category breakdown
categories = {}
for s in combined:
    cat = s.get("category", "unknown")
    categories[cat] = categories.get(cat, 0) + 1

print(f"\n📊 Top categories in enhanced dataset:")
for cat, count in sorted(categories.items(), key=lambda x: -x[1])[:20]:
    pct = count / len(combined) * 100
    print(f"   - {cat}: {count} ({pct:.1f}%)")

# Summary stats
deep_cats = [
    "memory_primitives", "auth_primitives", "logic_primitives", "vuln_theory",
    "protocol_deepdive", "system_internals", "exploitation_theory",
    "primitive_combination", "creative_attack", "innovation_template",
    "vuln_analysis", "workflow", "root_causes", "primitives_deep",
    "attack_patterns", "mechanism_analysis", "creative_thinking",
    "windows_internals", "linux_internals", "web_internals",
    "crypto_internals", "cloud_internals", "root_cause_matrix",
    "technique_chains", "protocol_vulns", "boundary_analysis",
    "pattern_variants", "creative_scenarios", "defense_bypass",
    "zeroday_discovery", "first_principles", "innovation_frameworks",
    "novel_creation", "surface_expansion", "pattern_generalization",
    "advanced_composition", "exploit_thinking", "constraint_exploitation"
]

deep_count = sum(categories.get(c, 0) for c in deep_cats)
print(f"\n🧠 Deep Knowledge samples: {deep_count} ({deep_count/len(combined)*100:.1f}%)")
print(f"📝 Original samples: {len(combined) - deep_count} ({(len(combined)-deep_count)/len(combined)*100:.1f}%)")
