#!/usr/bin/env python3
"""
Master Sample Merger and Statistics
Combines all generated samples with existing dataset
"""

import json
import random
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
GENERATED_DIR = DATA_DIR / "generated"
OUTPUT_FILE = DATA_DIR / "processed" / "train.jsonl"
ORIGINAL_TRAIN = PROJECT_ROOT.parent / "data" / "train.jsonl"  # Original training data

def load_jsonl(file_path):
    """Load samples from JSONL file"""
    samples = []
    if file_path.exists():
        with open(file_path, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        samples.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return samples


def validate_sample(sample):
    """Validate sample has required fields"""
    required = ['instruction', 'output']
    return all(field in sample and sample[field] for field in required)


def deduplicate_samples(samples):
    """Remove duplicate samples based on instruction+input"""
    seen = set()
    unique = []
    for sample in samples:
        key = (sample.get('instruction', ''), sample.get('input', ''))
        if key not in seen:
            seen.add(key)
            unique.append(sample)
    return unique


def categorize_sample(sample):
    """Categorize sample based on content"""
    text = (sample.get('instruction', '') + sample.get('input', '') + sample.get('output', '')).lower()
    
    categories = {
        'reconnaissance': ['nmap', 'recon', 'scan', 'enumerat', 'discover'],
        'web': ['sql', 'xss', 'injection', 'http', 'web', 'cookie', 'session'],
        'network': ['smb', 'ftp', 'ssh', 'port', 'tcp', 'udp', 'snmp'],
        'exploitation': ['exploit', 'payload', 'shell', 'reverse', 'bind'],
        'privilege_escalation': ['privesc', 'privilege', 'escalat', 'root', 'admin'],
        'lateral_movement': ['lateral', 'pivot', 'movement', 'pass.*hash'],
        'credential': ['credential', 'password', 'hash', 'crack', 'mimikatz'],
        'evasion': ['evasion', 'bypass', 'avoid', 'stealth', 'detection'],
        'cloud': ['aws', 'azure', 'cloud', 'iam', 's3', 'ec2'],
        'active_directory': ['domain', 'kerberos', 'ldap', 'bloodhound', 'dcsc'],
        'wireless': ['wifi', 'wireless', 'wpa', 'wep', 'aircrack'],
        'forensics': ['forensic', 'memory', 'disk', 'pcap', 'volatil'],
        'crypto': ['crypto', 'rsa', 'aes', 'encrypt', 'decrypt'],
        'binary': ['buffer', 'overflow', 'rop', 'shellcode', 'binary'],
    }
    
    for category, keywords in categories.items():
        for keyword in keywords:
            if keyword in text:
                return category
    
    return 'general'


def print_statistics(samples, title="Dataset Statistics"):
    """Print detailed statistics about the dataset"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print(f"{'='*60}")
    
    print(f"\nTotal Samples: {len(samples)}")
    
    # Category distribution
    categories = Counter(categorize_sample(s) for s in samples)
    print(f"\nCategory Distribution:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        pct = count / len(samples) * 100
        bar = '█' * int(pct / 2)
        print(f"  {cat:25} {count:5} ({pct:5.1f}%) {bar}")
    
    # Sample length statistics
    instruction_lens = [len(s.get('instruction', '')) for s in samples]
    output_lens = [len(s.get('output', '')) for s in samples]
    
    print(f"\nInstruction Length (chars):")
    print(f"  Min: {min(instruction_lens)}, Max: {max(instruction_lens)}, Avg: {sum(instruction_lens)//len(samples)}")
    
    print(f"\nOutput Length (chars):")
    print(f"  Min: {min(output_lens)}, Max: {max(output_lens)}, Avg: {sum(output_lens)//len(samples)}")
    
    # Quality tiers
    print(f"\n{'='*60}")
    print(" Training Data Quality Assessment")
    print(f"{'='*60}")
    
    tiers = [
        (500, "Minimal", "Not recommended for fine-tuning"),
        (1000, "Basic", "May work for simple tasks"),
        (2000, "Acceptable", "Reasonable for specific domain"),
        (5000, "Solid", "Good for comprehensive training"),
        (8000, "Strong", "Excellent dataset size"),
        (15000, "Professional", "Production-ready dataset"),
    ]
    
    current_tier = "Minimal"
    tier_desc = "Not recommended for fine-tuning"
    for threshold, tier, desc in tiers:
        if len(samples) >= threshold:
            current_tier = tier
            tier_desc = desc
    
    print(f"\nCurrent Tier: {current_tier}")
    print(f"Assessment: {tier_desc}")
    
    for threshold, tier, desc in tiers:
        marker = "✅" if len(samples) >= threshold else "⬜"
        print(f"  {marker} {threshold:>6} samples - {tier:12} ({desc})")
    
    # Next milestone
    for threshold, tier, desc in tiers:
        if len(samples) < threshold:
            remaining = threshold - len(samples)
            print(f"\n📈 Next Milestone: {tier} ({remaining} more samples needed)")
            break


def main():
    """Merge all samples and generate statistics"""
    print("🔄 Merging all training samples...")
    
    all_samples = []
    
    # Load original training data (main dataset)
    if ORIGINAL_TRAIN.exists():
        original = load_jsonl(ORIGINAL_TRAIN)
        all_samples.extend(original)
        print(f"  ✓ Loaded {len(original)} original samples from data/train.jsonl")
    
    # Load existing processed data
    existing_file = OUTPUT_FILE
    if existing_file.exists():
        existing = load_jsonl(existing_file)
        all_samples.extend(existing)
        print(f"  ✓ Loaded {len(existing)} existing samples from processed/train.jsonl")
    
    # Load all generated files
    if GENERATED_DIR.exists():
        for jsonl_file in GENERATED_DIR.glob("*.jsonl"):
            samples = load_jsonl(jsonl_file)
            if samples:
                all_samples.extend(samples)
                print(f"  ✓ Added {len(samples)} samples from {jsonl_file.name}")
    
    # Validate all samples
    valid_samples = [s for s in all_samples if validate_sample(s)]
    invalid_count = len(all_samples) - len(valid_samples)
    if invalid_count > 0:
        print(f"  ⚠ Removed {invalid_count} invalid samples")
    
    # Deduplicate
    unique_samples = deduplicate_samples(valid_samples)
    dup_count = len(valid_samples) - len(unique_samples)
    if dup_count > 0:
        print(f"  ⚠ Removed {dup_count} duplicate samples")
    
    # Shuffle for training
    random.shuffle(unique_samples)
    
    # Save merged dataset
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        for sample in unique_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Saved {len(unique_samples)} samples to {OUTPUT_FILE}")
    
    # Print statistics
    print_statistics(unique_samples)
    
    # Create a validation split (10%)
    split_idx = int(len(unique_samples) * 0.9)
    train_samples = unique_samples[:split_idx]
    val_samples = unique_samples[split_idx:]
    
    train_file = DATA_DIR / "processed" / "train_split.jsonl"
    val_file = DATA_DIR / "processed" / "val_split.jsonl"
    
    with open(train_file, 'w') as f:
        for sample in train_samples:
            f.write(json.dumps(sample) + '\n')
    
    with open(val_file, 'w') as f:
        for sample in val_samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n📊 Created train/val split:")
    print(f"   Train: {len(train_samples)} samples ({train_file.name})")
    print(f"   Val:   {len(val_samples)} samples ({val_file.name})")
    
    return len(unique_samples)


if __name__ == "__main__":
    main()
