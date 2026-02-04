#!/usr/bin/env python3
"""
Bombina Fine-tuning Script v2.0
Optimized for: Quadro M1000M (4GB VRAM) + 62GB RAM
Uses Unsloth + QLoRA for efficient training

Run: python finetune_v2.py
"""

import os
import sys
import yaml
from pathlib import Path
from datetime import datetime
from datasets import load_dataset, Dataset
import torch

# Paths
BASE_DIR = Path(__file__).parent.parent
CONFIG_FILE = BASE_DIR / "configs" / "lora_config.yaml"
DATA_DIR = BASE_DIR / "data" / "training"
LORA_DIR = BASE_DIR / "lora"
MODELS_DIR = BASE_DIR / "models"

def load_config():
    """Load LoRA configuration from YAML."""
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)

def check_gpu():
    """Check GPU availability and VRAM."""
    if torch.cuda.is_available():
        gpu_name = torch.cuda.get_device_name(0)
        vram = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        print(f"🎮 GPU: {gpu_name}")
        print(f"💾 VRAM: {vram:.1f} GB")
        
        if vram < 6:
            print("⚠️  Low VRAM detected. Using aggressive memory optimization.")
            return "low_vram"
        return "normal"
    else:
        print("⚠️  No GPU detected. Training will be slow.")
        return "cpu"

def format_prompt(example):
    """Format training examples into instruction format."""
    instruction = example.get('instruction', '')
    input_text = example.get('input', '')
    output = example.get('output', '')
    
    if input_text:
        return f"""### Instruction:
{instruction}

### Input:
{input_text}

### Response:
{output}"""
    else:
        return f"""### Instruction:
{instruction}

### Response:
{output}"""

def prepare_dataset():
    """Load and prepare training dataset."""
    training_file = DATA_DIR / "combined_training_data.jsonl"
    
    if not training_file.exists():
        print(f"❌ Training file not found: {training_file}")
        print("   Run: python curate_dataset.py (option 2) first!")
        sys.exit(1)
    
    print(f"📂 Loading dataset from {training_file}")
    dataset = load_dataset('json', data_files=str(training_file), split='train')
    
    print(f"   Found {len(dataset)} training samples")
    return dataset

def finetune_bombina():
    """Main fine-tuning function."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA FINE-TUNING v2.0
   Optimized for low-VRAM GPUs
═══════════════════════════════════════════════════════════════════
""")
    
    # Check GPU
    gpu_mode = check_gpu()
    
    # Load config
    config = load_config()
    print(f"\n📋 Config loaded: {CONFIG_FILE}")
    
    # Load dataset
    dataset = prepare_dataset()
    
    # Import Unsloth (do it here to show nice error if not installed)
    try:
        from unsloth import FastLanguageModel
        from trl import SFTTrainer
        from transformers import TrainingArguments
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("   Install with: pip install unsloth trl transformers datasets")
        sys.exit(1)
    
    # Load base model with Unsloth
    print(f"\n🔄 Loading base model: {config['model_name']}")
    
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=config['model_name'],
        max_seq_length=config['max_seq_length'],
        dtype=None,  # Auto-detect
        load_in_4bit=config['load_in_4bit'],
    )
    
    # Add LoRA adapters
    print("🔧 Adding LoRA adapters...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=config['lora_r'],
        target_modules=config['target_modules'],
        lora_alpha=config['lora_alpha'],
        lora_dropout=config['lora_dropout'],
        bias="none",
        use_gradient_checkpointing="unsloth" if config.get('gradient_checkpointing', True) else False,
        random_state=42,
    )
    
    # Format dataset
    def format_examples(examples):
        texts = []
        for i in range(len(examples['instruction'])):
            example = {
                'instruction': examples['instruction'][i],
                'input': examples.get('input', [''] * len(examples['instruction']))[i] if 'input' in examples else '',
                'output': examples['output'][i]
            }
            texts.append(format_prompt(example))
        return {'text': texts}
    
    dataset = dataset.map(format_examples, batched=True, remove_columns=dataset.column_names)
    
    # Training arguments (optimized for 4GB VRAM)
    version = datetime.now().strftime("%Y%m%d_%H%M")
    output_dir = LORA_DIR / f"v_{version}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Adjust batch size based on GPU
    batch_size = 1 if gpu_mode == "low_vram" else config.get('per_device_train_batch_size', 2)
    
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=config.get('gradient_accumulation_steps', 8),
        warmup_ratio=config.get('warmup_ratio', 0.05),
        num_train_epochs=config.get('num_train_epochs', 3),
        learning_rate=config.get('learning_rate', 2e-4),
        fp16=config.get('fp16', True),
        bf16=config.get('bf16', False),
        logging_steps=config.get('logging_steps', 10),
        save_steps=config.get('save_steps', 100),
        save_total_limit=3,
        optim=config.get('optim', 'adamw_8bit'),
        lr_scheduler_type=config.get('lr_scheduler_type', 'cosine'),
        seed=42,
        report_to="none",  # Disable wandb etc
    )
    
    # Initialize trainer
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        args=training_args,
        max_seq_length=config['max_seq_length'],
        dataset_text_field="text",
    )
    
    # Train
    print("\n🚀 Starting fine-tuning...")
    print(f"   Output: {output_dir}")
    print(f"   Batch size: {batch_size}")
    print(f"   Epochs: {config.get('num_train_epochs', 3)}")
    print("-" * 50)
    
    trainer.train()
    
    # Save the model
    print("\n💾 Saving fine-tuned model...")
    model.save_pretrained(output_dir / "lora_adapter")
    tokenizer.save_pretrained(output_dir / "lora_adapter")
    
    # Export to GGUF for Ollama
    print("\n📦 Exporting to GGUF format...")
    gguf_dir = output_dir / "gguf"
    gguf_dir.mkdir(exist_ok=True)
    
    try:
        model.save_pretrained_gguf(
            str(gguf_dir),
            tokenizer,
            quantization_method="q4_k_m",
        )
        print(f"   GGUF saved to: {gguf_dir}")
    except Exception as e:
        print(f"   ⚠️ GGUF export failed: {e}")
        print("   You can convert manually using llama.cpp")
    
    print(f"""
✅ ═══════════════════════════════════════════════════════════════
   FINE-TUNING COMPLETE
═══════════════════════════════════════════════════════════════════

📁 Output directory: {output_dir}
   ├── lora_adapter/   (LoRA weights)
   └── gguf/           (Ollama-ready model)

🔄 To use in Ollama:
   1. Create new Modelfile pointing to GGUF
   2. ollama create bombina-v2 -f Modelfile
   
📊 Next steps:
   1. Test the new model
   2. Run evaluation scenarios
   3. If good, archive current and promote new version
""")

if __name__ == "__main__":
    finetune_bombina()
