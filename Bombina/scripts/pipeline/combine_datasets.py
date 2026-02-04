#!/usr/bin/env python3
"""
Dataset Combiner for Bombina
Combines all JSONL files into a single training dataset
Deduplicates and shuffles for optimal training

Usage: python combine_datasets.py
"""

import json
import hashlib
import random
from pathlib import Path
from typing import Dict, List, Set
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent.parent
DATA_DIR = BASE_DIR / "data" / "datasets"
OUTPUT_DIR = BASE_DIR / "data"


def hash_sample(sample: Dict) -> str:
    """Create hash of sample for deduplication."""
    content = f"{sample.get('instruction', '')}{sample.get('input', '')}"
    return hashlib.md5(content.encode()).hexdigest()


def load_all_samples() -> List[Dict]:
    """Load all samples from all JSONL files."""
    samples = []
    seen_hashes: Set[str] = set()
    duplicates = 0
    
    for jsonl_file in DATA_DIR.rglob("*.jsonl"):
        # Skip quality_filtered files to avoid double-counting
        if "quality_filtered" in jsonl_file.name:
            continue
            
        category = jsonl_file.parent.name
        
        with open(jsonl_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    sample = json.loads(line)
                    
                    # Add category metadata
                    sample['_category'] = category
                    sample['_source'] = jsonl_file.stem
                    
                    # Deduplicate
                    sample_hash = hash_sample(sample)
                    if sample_hash in seen_hashes:
                        duplicates += 1
                        continue
                    
                    seen_hashes.add(sample_hash)
                    samples.append(sample)
                    
                except json.JSONDecodeError:
                    continue
    
    print(f"  ✅ Loaded {len(samples)} unique samples")
    print(f"  ⚠️  Skipped {duplicates} duplicates")
    
    return samples


def clean_sample(sample: Dict) -> Dict:
    """Remove internal metadata and ensure required fields."""
    cleaned = {
        "instruction": sample.get("instruction", ""),
        "input": sample.get("input", ""),
        "output": sample.get("output", "")
    }
    
    # Validate all fields are present and non-empty
    if not all(cleaned.values()):
        return None
    
    return cleaned


def main():
    """Combine all datasets into single training file."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA DATASET COMBINER
   Creating unified training dataset
═══════════════════════════════════════════════════════════════════
""")
    
    # Load all samples
    print("📂 Loading samples from all categories...")
    samples = load_all_samples()
    
    # Clean samples
    print("\n🧹 Cleaning samples...")
    cleaned = []
    for sample in samples:
        clean = clean_sample(sample)
        if clean:
            cleaned.append(clean)
    
    print(f"  ✅ {len(cleaned)} samples passed validation")
    
    # Shuffle for training
    print("\n🔀 Shuffling...")
    random.shuffle(cleaned)
    
    # Split into train/eval
    eval_size = min(500, int(len(cleaned) * 0.05))
    train_samples = cleaned[:-eval_size]
    eval_samples = cleaned[-eval_size:]
    
    # Save combined datasets
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    train_file = OUTPUT_DIR / "train.jsonl"
    eval_file = OUTPUT_DIR / "eval.jsonl"
    
    with open(train_file, 'w') as f:
        for sample in train_samples:
            f.write(json.dumps(sample) + '\n')
    
    with open(eval_file, 'w') as f:
        for sample in eval_samples:
            f.write(json.dumps(sample) + '\n')
    
    # Also save category distribution
    categories = {}
    for sample in samples:
        cat = sample.get('_category', 'unknown')
        categories[cat] = categories.get(cat, 0) + 1
    
    print(f"""
═══════════════════════════════════════════════════════════════
✅ DATASET COMBINATION COMPLETE

Training samples: {len(train_samples)} → {train_file}
Evaluation samples: {len(eval_samples)} → {eval_file}

Category distribution:""")
    
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        pct = count / len(samples) * 100
        print(f"  • {cat}: {count} ({pct:.1f}%)")
    
    print(f"""
═══════════════════════════════════════════════════════════════

Ready for fine-tuning! Run:
  python finetune_v2.py
═══════════════════════════════════════════════════════════════
""")


if __name__ == "__main__":
    main()
