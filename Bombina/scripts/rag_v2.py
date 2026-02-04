#!/usr/bin/env python3
"""
Bombina RAG System v2.0 - Portable Cybersecurity Knowledge Base
Uses FAISS + HuggingFace embeddings for 100% offline operation

Features:
- Local vector storage (FAISS)
- Local embeddings (no API calls)
- Portable: Copy entire folder to any machine
"""

import os
import json
from pathlib import Path
from typing import List, Optional
import numpy as np

# Paths
BASE_DIR = Path(__file__).parent.parent
RAG_DATA_DIR = BASE_DIR / "data" / "rag"
FAISS_INDEX_DIR = BASE_DIR / "data" / "faiss_index"
EMBEDDINGS_CACHE = BASE_DIR / "models" / "embeddings"


class BombinaRAG:
    """Portable RAG system for Bombina."""
    
    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5"):
        """Initialize RAG with local embeddings."""
        self.model_name = model_name
        self.index = None
        self.documents = []
        self.embeddings_model = None
        
    def _load_embeddings_model(self):
        """Load local embedding model."""
        if self.embeddings_model is not None:
            return
            
        try:
            from sentence_transformers import SentenceTransformer
            
            print(f"🔄 Loading embedding model: {self.model_name}")
            EMBEDDINGS_CACHE.mkdir(parents=True, exist_ok=True)
            
            self.embeddings_model = SentenceTransformer(
                self.model_name,
                cache_folder=str(EMBEDDINGS_CACHE)
            )
            print("✅ Embedding model loaded")
            
        except ImportError:
            print("❌ sentence-transformers not installed")
            print("   Install: pip install sentence-transformers")
            raise
    
    def _load_faiss(self):
        """Load FAISS library."""
        try:
            import faiss
            return faiss
        except ImportError:
            print("❌ FAISS not installed")
            print("   Install: pip install faiss-cpu")
            raise
    
    def _chunk_text(self, text: str, chunk_size: int = 512, overlap: int = 50) -> List[str]:
        """Split text into overlapping chunks."""
        words = text.split()
        chunks = []
        
        for i in range(0, len(words), chunk_size - overlap):
            chunk = ' '.join(words[i:i + chunk_size])
            if chunk:
                chunks.append(chunk)
        
        return chunks
    
    def ingest_documents(self, directory: Optional[Path] = None):
        """Ingest documents from directory into FAISS index."""
        self._load_embeddings_model()
        faiss = self._load_faiss()
        
        if directory is None:
            directory = RAG_DATA_DIR
        
        directory = Path(directory)
        if not directory.exists():
            print(f"❌ Directory not found: {directory}")
            return
        
        # Supported file types
        extensions = ['.txt', '.md', '.json', '.jsonl', '.py', '.sh', '.yaml', '.yml']
        
        print(f"📂 Scanning {directory} for documents...")
        
        all_chunks = []
        all_metadata = []
        
        for ext in extensions:
            for file_path in directory.rglob(f"*{ext}"):
                try:
                    print(f"   Processing: {file_path.name}")
                    
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    chunks = self._chunk_text(content)
                    
                    for i, chunk in enumerate(chunks):
                        all_chunks.append(chunk)
                        all_metadata.append({
                            'source': str(file_path.relative_to(directory)),
                            'chunk_id': i,
                            'total_chunks': len(chunks)
                        })
                        
                except Exception as e:
                    print(f"   ⚠️ Error processing {file_path}: {e}")
        
        if not all_chunks:
            print("❌ No documents found to ingest")
            return
        
        print(f"\n🔢 Creating embeddings for {len(all_chunks)} chunks...")
        embeddings = self.embeddings_model.encode(
            all_chunks, 
            show_progress_bar=True,
            convert_to_numpy=True
        )
        
        # Create FAISS index
        dimension = embeddings.shape[1]
        self.index = faiss.IndexFlatIP(dimension)  # Inner product for cosine similarity
        
        # Normalize for cosine similarity
        faiss.normalize_L2(embeddings)
        self.index.add(embeddings)
        
        self.documents = list(zip(all_chunks, all_metadata))
        
        # Save index and documents
        self._save_index()
        
        print(f"✅ Indexed {len(all_chunks)} chunks from {len(set(m['source'] for _, m in self.documents))} files")
    
    def _save_index(self):
        """Save FAISS index and documents to disk."""
        faiss = self._load_faiss()
        
        FAISS_INDEX_DIR.mkdir(parents=True, exist_ok=True)
        
        # Save FAISS index
        faiss.write_index(self.index, str(FAISS_INDEX_DIR / "bombina.faiss"))
        
        # Save documents
        with open(FAISS_INDEX_DIR / "documents.json", 'w') as f:
            json.dump(self.documents, f)
        
        print(f"💾 Index saved to {FAISS_INDEX_DIR}")
    
    def load_index(self) -> bool:
        """Load existing FAISS index from disk."""
        faiss = self._load_faiss()
        
        index_file = FAISS_INDEX_DIR / "bombina.faiss"
        docs_file = FAISS_INDEX_DIR / "documents.json"
        
        if not index_file.exists() or not docs_file.exists():
            return False
        
        print(f"📂 Loading index from {FAISS_INDEX_DIR}")
        self.index = faiss.read_index(str(index_file))
        
        with open(docs_file, 'r') as f:
            self.documents = json.load(f)
        
        print(f"✅ Loaded {len(self.documents)} chunks")
        return True
    
    def search(self, query: str, top_k: int = 5) -> List[dict]:
        """Search for relevant documents."""
        if self.index is None:
            if not self.load_index():
                print("❌ No index found. Run ingest_documents() first.")
                return []
        
        self._load_embeddings_model()
        faiss = self._load_faiss()
        
        # Encode query
        query_embedding = self.embeddings_model.encode([query], convert_to_numpy=True)
        faiss.normalize_L2(query_embedding)
        
        # Search
        scores, indices = self.index.search(query_embedding, top_k)
        
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < len(self.documents):
                chunk, metadata = self.documents[idx]
                results.append({
                    'content': chunk,
                    'source': metadata['source'],
                    'score': float(score)
                })
        
        return results
    
    def query_with_context(self, query: str, top_k: int = 5) -> str:
        """Search and format context for LLM."""
        results = self.search(query, top_k)
        
        if not results:
            return ""
        
        context_parts = []
        for i, result in enumerate(results, 1):
            context_parts.append(f"[Source: {result['source']}]\n{result['content']}")
        
        return "\n\n---\n\n".join(context_parts)


def interactive_mode():
    """Interactive RAG query mode."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA RAG - Portable Knowledge Base
═══════════════════════════════════════════════════════════════════
""")
    
    rag = BombinaRAG()
    
    # Try to load existing index
    if not rag.load_index():
        print("No existing index found.")
        choice = input("Ingest documents now? [y/n]: ").strip().lower()
        if choice == 'y':
            rag.ingest_documents()
        else:
            print("Add documents to data/rag/ and run again.")
            return
    
    print("\n🔍 Enter queries (type 'quit' to exit)\n")
    
    while True:
        try:
            query = input("Query: ").strip()
            
            if query.lower() in ['quit', 'exit', 'q']:
                break
            
            if not query:
                continue
            
            results = rag.search(query, top_k=3)
            
            if results:
                print("\n📄 Results:\n")
                for i, result in enumerate(results, 1):
                    print(f"[{i}] Score: {result['score']:.3f} | Source: {result['source']}")
                    print(f"    {result['content'][:200]}...")
                    print()
            else:
                print("No results found.\n")
                
        except KeyboardInterrupt:
            break
    
    print("\n👋 Goodbye!")


def main():
    """Main menu."""
    print("""
🐸 BOMBINA RAG MANAGER

Options:
  1. Ingest documents (rebuild index)
  2. Interactive search
  3. Exit
""")
    
    while True:
        choice = input("Select [1-3]: ").strip()
        
        if choice == '1':
            rag = BombinaRAG()
            rag.ingest_documents()
        elif choice == '2':
            interactive_mode()
        elif choice == '3':
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
