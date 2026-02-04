#!/usr/bin/env python3
"""
Bombina Dataset Curator
Converts corrections and feedback into training data.
Run this before retraining.

Usage: python curate_dataset.py
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict
import shutil

# Paths
BASE_DIR = Path(__file__).parent.parent
CORRECTIONS_DIR = BASE_DIR / "data" / "logs" / "corrections"
FEEDBACK_DIR = BASE_DIR / "data" / "logs" / "feedback"
DATASETS_DIR = BASE_DIR / "data" / "datasets"
RETRAIN_DIR = BASE_DIR / "retrain"
CURATED_DIR = RETRAIN_DIR / "curated"
REJECTED_DIR = RETRAIN_DIR / "rejected"
PENDING_DIR = RETRAIN_DIR / "pending"


def load_corrections() -> List[Dict]:
    """Load all pending corrections."""
    corrections = []
    
    for file_path in CORRECTIONS_DIR.glob("*.json"):
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                data['source_file'] = str(file_path)
                corrections.append(data)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
    
    return corrections


def load_positive_feedback() -> List[Dict]:
    """Load interactions with positive feedback (good training examples)."""
    positive_examples = []
    
    for file_path in FEEDBACK_DIR.glob("*.jsonl"):
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    entry = json.loads(line)
                    if entry.get('rating') == 'positive':
                        positive_examples.append(entry)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
    
    return positive_examples


def convert_correction_to_training(correction: Dict) -> Dict:
    """Convert a correction entry to training format."""
    return {
        "instruction": correction.get('instruction', 'Provide accurate cybersecurity guidance.'),
        "input": correction.get('input', ''),
        "output": correction.get('corrected_output', '')
    }


def interactive_curation():
    """Interactive curation of corrections."""
    corrections = load_corrections()
    
    if not corrections:
        print("📭 No corrections to curate.")
        return
    
    print(f"\n🔍 Found {len(corrections)} corrections to review.\n")
    
    curated = []
    rejected = []
    
    for i, correction in enumerate(corrections, 1):
        print("=" * 70)
        print(f"[{i}/{len(corrections)}] Correction Review")
        print("=" * 70)
        print(f"\n📥 User Input:\n{correction.get('input', 'N/A')[:500]}")
        print(f"\n❌ Bad Response:\n{correction.get('bad_output', 'N/A')[:500]}")
        print(f"\n✅ Correction:\n{correction.get('corrected_output', 'N/A')[:500]}")
        print("\n" + "-" * 70)
        
        while True:
            choice = input("\n[A]ccept / [R]eject / [E]dit / [S]kip? ").strip().lower()
            
            if choice == 'a':
                training_entry = convert_correction_to_training(correction)
                curated.append(training_entry)
                # Move original file to processed
                source_file = Path(correction['source_file'])
                if source_file.exists():
                    source_file.unlink()
                print("✅ Accepted")
                break
            
            elif choice == 'r':
                rejected.append(correction)
                # Move to rejected
                source_file = Path(correction['source_file'])
                if source_file.exists():
                    dest = REJECTED_DIR / source_file.name
                    shutil.move(str(source_file), str(dest))
                print("🗑️ Rejected")
                break
            
            elif choice == 'e':
                print("\nEdit the corrected output (Ctrl+D or empty line to finish):")
                lines = []
                try:
                    while True:
                        line = input()
                        if line == '':
                            break
                        lines.append(line)
                except EOFError:
                    pass
                
                if lines:
                    correction['corrected_output'] = '\n'.join(lines)
                    training_entry = convert_correction_to_training(correction)
                    curated.append(training_entry)
                    # Remove original
                    source_file = Path(correction['source_file'])
                    if source_file.exists():
                        source_file.unlink()
                    print("✅ Edited and accepted")
                break
            
            elif choice == 's':
                print("⏭️ Skipped")
                break
            
            else:
                print("Invalid choice. Use A/R/E/S")
    
    # Save curated data
    if curated:
        output_file = CURATED_DIR / f"curated_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        with open(output_file, 'w') as f:
            for entry in curated:
                f.write(json.dumps(entry) + '\n')
        
        print(f"\n✅ Saved {len(curated)} curated entries to {output_file}")
    
    print(f"\n📊 Summary: {len(curated)} accepted, {len(rejected)} rejected")


def combine_all_datasets():
    """Combine all dataset files into single training file."""
    all_entries = []
    
    # Load from datasets directory
    for jsonl_file in DATASETS_DIR.rglob("*.jsonl"):
        print(f"Loading {jsonl_file.relative_to(BASE_DIR)}...")
        with open(jsonl_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    all_entries.append(entry)
                except:
                    pass
    
    # Load from curated corrections
    for jsonl_file in CURATED_DIR.glob("*.jsonl"):
        print(f"Loading {jsonl_file.relative_to(BASE_DIR)}...")
        with open(jsonl_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    all_entries.append(entry)
                except:
                    pass
    
    # Save combined dataset
    output_file = BASE_DIR / "data" / "training" / "combined_training_data.jsonl"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        for entry in all_entries:
            f.write(json.dumps(entry) + '\n')
    
    print(f"\n✅ Combined {len(all_entries)} entries into {output_file}")
    return output_file


def show_stats():
    """Show dataset statistics."""
    print("\n📊 DATASET STATISTICS")
    print("=" * 50)
    
    total = 0
    
    # Count by category
    for category_dir in DATASETS_DIR.iterdir():
        if category_dir.is_dir():
            count = 0
            for jsonl_file in category_dir.glob("*.jsonl"):
                with open(jsonl_file, 'r') as f:
                    count += sum(1 for _ in f)
            print(f"  {category_dir.name}: {count} samples")
            total += count
    
    # Count curated
    curated_count = 0
    for jsonl_file in CURATED_DIR.glob("*.jsonl"):
        with open(jsonl_file, 'r') as f:
            curated_count += sum(1 for _ in f)
    print(f"  curated corrections: {curated_count} samples")
    total += curated_count
    
    print("-" * 50)
    print(f"  TOTAL: {total} samples")
    
    # Quality assessment
    print("\n📈 QUALITY ASSESSMENT")
    if total < 2000:
        print("  ⚠️  Below minimum viable (2k). Add more samples.")
    elif total < 5000:
        print("  📝 Minimum viable. Consider adding more.")
    elif total < 8000:
        print("  ✅ Solid dataset size.")
    else:
        print("  🏆 Elite dataset size!")


def main():
    """Main menu."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA DATASET CURATOR
   Prepare training data for fine-tuning
═══════════════════════════════════════════════════════════════════
""")
    
    while True:
        print("\n📋 OPTIONS:")
        print("  1. Review & curate corrections")
        print("  2. Combine all datasets for training")
        print("  3. Show dataset statistics")
        print("  4. Exit")
        
        choice = input("\nSelect [1-4]: ").strip()
        
        if choice == '1':
            interactive_curation()
        elif choice == '2':
            combine_all_datasets()
        elif choice == '3':
            show_stats()
        elif choice == '4':
            print("👋 Goodbye!")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
