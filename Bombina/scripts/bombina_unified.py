#!/usr/bin/env python3
"""
Bombina Unified Chat - LLM + RAG Integration
Combines local RAG context with Bombina LLM responses

Usage: python bombina_unified.py
"""

import json
from datetime import datetime
from pathlib import Path
import ollama

# Import RAG system
from rag_v2 import BombinaRAG

# Paths
BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = BASE_DIR / "data" / "logs" / "sessions"


class BombinaUnified:
    """Unified chat with RAG-enhanced responses."""
    
    def __init__(self, model: str = "bombina", use_rag: bool = True):
        self.model = model
        self.use_rag = use_rag
        self.rag = None
        self.conversation_history = []
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if use_rag:
            self._init_rag()
    
    def _init_rag(self):
        """Initialize RAG system."""
        try:
            self.rag = BombinaRAG()
            if not self.rag.load_index():
                print("⚠️  RAG index not found. Running without RAG context.")
                print("   To enable: python rag_v2.py (option 1)")
                self.use_rag = False
        except Exception as e:
            print(f"⚠️  RAG initialization failed: {e}")
            self.use_rag = False
    
    def _get_rag_context(self, query: str) -> str:
        """Get relevant context from RAG."""
        if not self.use_rag or not self.rag:
            return ""
        
        try:
            results = self.rag.search(query, top_k=3)
            if not results:
                return ""
            
            context_parts = []
            for result in results:
                if result['score'] > 0.3:  # Only include relevant results
                    context_parts.append(f"[{result['source']}]: {result['content'][:500]}")
            
            if context_parts:
                return "\n\n".join(context_parts)
            return ""
            
        except Exception as e:
            print(f"⚠️  RAG search error: {e}")
            return ""
    
    def _build_prompt_with_context(self, user_input: str, rag_context: str) -> str:
        """Build prompt with RAG context."""
        if rag_context:
            return f"""Use the following reference information to help answer the question. If the information is not relevant, rely on your training.

REFERENCE INFORMATION:
{rag_context}

USER QUESTION:
{user_input}"""
        return user_input
    
    def chat(self, user_input: str) -> str:
        """Send message with RAG-enhanced context."""
        # Get RAG context
        rag_context = self._get_rag_context(user_input)
        
        # Build enhanced prompt
        enhanced_input = self._build_prompt_with_context(user_input, rag_context)
        
        # Add to conversation history
        self.conversation_history.append({
            'role': 'user',
            'content': enhanced_input
        })
        
        # Get response from Ollama
        response = ollama.chat(
            model=self.model,
            messages=self.conversation_history
        )
        
        assistant_response = response['message']['content']
        
        # Add response to history (with original user input for clarity)
        self.conversation_history[-1]['content'] = user_input  # Store original
        self.conversation_history.append({
            'role': 'assistant',
            'content': assistant_response
        })
        
        # Log interaction
        self._log_interaction(user_input, assistant_response, bool(rag_context))
        
        return assistant_response, bool(rag_context)
    
    def _log_interaction(self, user_input: str, response: str, used_rag: bool):
        """Log interaction to file."""
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        
        log_file = LOGS_DIR / f"unified_{self.session_id}.jsonl"
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "user_input": user_input,
            "response": response,
            "used_rag": used_rag
        }
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')


def main():
    """Main chat loop."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA UNIFIED - LLM + RAG
   Cybersecurity AI with local knowledge base
═══════════════════════════════════════════════════════════════════
""")
    
    chat = BombinaUnified()
    
    print(f"📁 Session: {chat.session_id}")
    print(f"🔍 RAG: {'Enabled' if chat.use_rag else 'Disabled'}")
    print("\nType 'exit' to quit, '/rag on|off' to toggle RAG\n")
    
    while True:
        try:
            user_input = input("🔐 You: ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ['exit', 'quit', 'q']:
                print("\n👋 Session ended.")
                break
            
            if user_input.lower() == '/rag on':
                chat.use_rag = True
                if not chat.rag:
                    chat._init_rag()
                print("🔍 RAG enabled\n")
                continue
            
            if user_input.lower() == '/rag off':
                chat.use_rag = False
                print("🔍 RAG disabled\n")
                continue
            
            print("\n🐸 Bombina: ", end="", flush=True)
            response, used_rag = chat.chat(user_input)
            print(response)
            
            if used_rag:
                print("\n   [📚 Response enhanced with RAG context]")
            print()
            
        except KeyboardInterrupt:
            print("\n\n👋 Session ended.")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()
