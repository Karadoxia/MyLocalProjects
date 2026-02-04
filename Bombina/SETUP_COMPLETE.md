# 🐸 Bombina - Complete Setup Guide

## Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| ✅ Dataset | 3,868 samples | Cloud, AD, MITRE, methodology |
| ✅ RAG System | Working | FAISS + local embeddings |
| ✅ Agent Framework | Working | Tool-calling autonomous agent |
| ✅ Policy Engine | Working | Scope/action validation |
| ✅ Evaluation Framework | Working | 6 red team scenarios |
| ✅ Report Generator | Working | Markdown/HTML output |
| ⚠️ **Fine-tuning** | **BLOCKED** | GPU too old (CUDA 5.0) |

## 🔴 The Problem

Your Quadro M1000M GPU has CUDA 5.0, but PyTorch requires CUDA 7.0+.
The base model scores **0.20/1.00** on evaluations because it hasn't been trained on your pentest dataset.

---

## 🎯 Solutions (Pick One)

### Option A: Cloud Fine-tuning (Recommended - Fast)

Use Google Colab (free T4 GPU) or RunPod ($0.20/hr for A100):

```bash
# 1. Upload your dataset
scp data/train.jsonl user@colab:/content/

# 2. Run fine-tuning in cloud (takes 2-4 hours)
# Use scripts/finetune_v2.py

# 3. Download the LoRA adapter (~300MB)
scp user@colab:/content/lora/bombina_v1/* lora/
```

### Option B: CPU Fine-tuning (Slow but Local)

Uses your 62GB RAM, but takes 24-48 hours with smaller model:

```bash
cd /home/redbend/MyLocalProjects/Bombina
python scripts/finetune_cpu.py
```

### Option C: Use Ollama's Built-in Training (Experimental)

Create a Modelfile with your dataset embedded as system prompt:

```bash
# See scripts/create_modelfile.py (I'll create this)
python scripts/create_modelfile.py
ollama create bombina-trained -f Modelfile.trained
```

---

## 📁 What You Have

```
Bombina/
├── data/
│   ├── train.jsonl          # 3,868 training samples
│   ├── eval.jsonl           # 203 evaluation samples
│   └── datasets/            # Organized by category
│       ├── ad_attacks/      # 59 AD/Kerberos samples
│       ├── cloud_attacks/   # 48 AWS/Azure/GCP samples
│       └── ...
│
├── scripts/
│   ├── bombina_agent.py     # Autonomous pentest agent
│   ├── policy_engine.py     # Scope/safety validation
│   ├── report_generator.py  # Professional reports
│   ├── finetune_v2.py       # GPU fine-tuning (needs CUDA 7+)
│   └── finetune_cpu.py      # CPU fallback (slow)
│
├── evaluation/
│   └── scenarios.py         # 6 red team test scenarios
│
├── rag/
│   └── rag_engine.py        # FAISS-based retrieval
│
└── configs/
    └── lora_config.yaml     # Fine-tuning configuration
```

---

## 🚀 Quick Start (After Fine-tuning)

```bash
# 1. Run the agent
python scripts/bombina_agent.py

# 2. Generate a report
python scripts/report_generator.py --example

# 3. Run evaluation
python evaluation/scenarios.py --model bombina:latest
```

---

## 📊 Target Scores After Fine-tuning

| Dimension | Current | Target |
|-----------|---------|--------|
| Overall | 0.20 | 0.60+ |
| Reasoning Clarity | 0.13 | 0.70+ |
| Risk Awareness | 0.15 | 0.75+ |
| Adaptability | 0.25 | 0.65+ |
| Restraint | 0.28 | 0.70+ |

---

## Need Help?

1. **Cloud GPU**: Use Google Colab (free) or RunPod ($0.20/hr)
2. **More samples**: Run `python scripts/pipeline/generate_synthetic.py`
3. **Test agent**: `python scripts/bombina_agent.py --interactive`
