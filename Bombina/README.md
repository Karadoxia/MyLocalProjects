# Bombina 🐸
## Portable Offensive Security AI Assistant

A **fully offline, portable** cybersecurity AI built on local LLM with RAG capabilities.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      BOMBINA STACK                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│   │  User Chat  │───▶│  RAG Layer  │───▶│   Bombina   │    │
│   │   (Input)   │    │   (FAISS)   │    │    (LLM)    │    │
│   └─────────────┘    └─────────────┘    └─────────────┘    │
│                             │                   │           │
│                             ▼                   ▼           │
│                    ┌─────────────┐    ┌─────────────┐       │
│                    │  Knowledge  │    │    LoRA     │       │
│                    │    Base     │    │   Weights   │       │
│                    └─────────────┘    └─────────────┘       │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│   Feedback Loop: Logs → Curation → Retraining → Upgrade    │
└─────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
Bombina/
├── configs/
│   ├── modelfile           # Ollama model configuration
│   └── lora_config.yaml    # LoRA fine-tuning parameters
├── data/
│   ├── datasets/           # Training data by category
│   ├── logs/               # Session & feedback logs
│   ├── rag/                # RAG knowledge base documents
│   ├── training/           # Combined training data
│   └── faiss_index/        # FAISS vector index
├── lora/                   # LoRA adapter versions
├── models/                 # Model files & embeddings
├── retrain/                # Retraining pipeline
├── scripts/                # All Python scripts
└── evaluation/             # Model evaluation results
```

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd Bombina
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Create Bombina Model
```bash
cd configs && ollama create bombina -f modelfile
```

### 3. Run Bombina
```bash
# Simple chat with logging
python scripts/bombina_chat.py

# Chat with RAG integration
python scripts/bombina_unified.py
```

---

## 📊 Training Pipeline

1. **Collect Feedback**: Use /feedback and /correct during chat
2. **Curate Dataset**: python scripts/curate_dataset.py
3. **Fine-tune**: python scripts/finetune_v2.py
4. **Update Model**: ollama create bombina-v2 -f modelfile

---

## 🗄️ RAG Setup

Add documents to data/rag/ then:
```bash
python scripts/rag_v2.py  # Select option 1
```

---

## 📜 License
For educational and authorized security testing only.
