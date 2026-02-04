#!/usr/bin/env python3
"""
Bombina Session Logger & Feedback System
Logs all interactions for future retraining

Usage: python bombina_chat.py
"""

import json
import os
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional
import ollama

# Paths
BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = BASE_DIR / "data" / "logs"
SESSIONS_DIR = LOGS_DIR / "sessions"
FEEDBACK_DIR = LOGS_DIR / "feedback"
CORRECTIONS_DIR = LOGS_DIR / "corrections"

# Ensure directories exist
for dir_path in [SESSIONS_DIR, FEEDBACK_DIR, CORRECTIONS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)


class BombinaChat:
    """Interactive chat with Bombina including logging and feedback."""
    
    def __init__(self, model: str = "bombina"):
        self.model = model
        self.session_id = self._generate_session_id()
        self.session_file = SESSIONS_DIR / f"{self.session_id}.jsonl"
        self.conversation_history = []
        self.interaction_count = 0
        
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_hash = hashlib.md5(os.urandom(8)).hexdigest()[:8]
        return f"session_{timestamp}_{random_hash}"
    
    def _log_interaction(self, user_input: str, response: str, 
                         feedback: Optional[str] = None,
                         correction: Optional[str] = None):
        """Log interaction to session file."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "interaction_id": self.interaction_count,
            "user_input": user_input,
            "response": response,
            "feedback": feedback,
            "correction": correction,
            "model": self.model
        }
        
        with open(self.session_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def _save_correction(self, user_input: str, bad_response: str, 
                         correction: str):
        """Save correction for future training."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            "instruction": "Provide accurate cybersecurity guidance.",
            "input": user_input,
            "bad_output": bad_response,
            "corrected_output": correction,
            "status": "pending_review"
        }
        
        correction_file = CORRECTIONS_DIR / f"correction_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(correction_file, 'w') as f:
            json.dump(entry, f, indent=2)
        
        print(f"💾 Correction saved to {correction_file.name}")
    
    def chat(self, user_input: str) -> str:
        """Send message to Bombina and get response."""
        self.interaction_count += 1
        
        # Add to conversation history
        self.conversation_history.append({
            'role': 'user',
            'content': user_input
        })
        
        # Get response from Ollama
        response = ollama.chat(
            model=self.model,
            messages=self.conversation_history
        )
        
        assistant_response = response['message']['content']
        
        # Add response to history
        self.conversation_history.append({
            'role': 'assistant',
            'content': assistant_response
        })
        
        # Log interaction
        self._log_interaction(user_input, assistant_response)
        
        return assistant_response
    
    def provide_feedback(self, feedback: str):
        """Provide feedback on last response."""
        if self.interaction_count == 0:
            print("No interaction to provide feedback on.")
            return
        
        feedback_entry = {
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            "interaction_id": self.interaction_count,
            "feedback": feedback,
            "rating": self._parse_rating(feedback)
        }
        
        feedback_file = FEEDBACK_DIR / f"feedback_{datetime.now().strftime('%Y%m%d')}.jsonl"
        with open(feedback_file, 'a') as f:
            f.write(json.dumps(feedback_entry) + '\n')
        
        print("📝 Feedback recorded.")
    
    def provide_correction(self, correction: str):
        """Provide correction for last response (for retraining)."""
        if self.interaction_count == 0 or len(self.conversation_history) < 2:
            print("No interaction to correct.")
            return
        
        # Get last user input and bad response
        user_input = self.conversation_history[-2]['content']
        bad_response = self.conversation_history[-1]['content']
        
        self._save_correction(user_input, bad_response, correction)
    
    def _parse_rating(self, feedback: str) -> str:
        """Parse feedback into rating category."""
        feedback_lower = feedback.lower()
        if any(word in feedback_lower for word in ['good', 'great', 'perfect', 'helpful', 'correct']):
            return 'positive'
        elif any(word in feedback_lower for word in ['bad', 'wrong', 'incorrect', 'useless', 'hallucination']):
            return 'negative'
        else:
            return 'neutral'


def print_help():
    """Print help message."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    BOMBINA COMMANDS                          ║
╠══════════════════════════════════════════════════════════════╣
║  /feedback <text>  - Provide feedback on last response       ║
║  /correct <text>   - Provide correction (saved for training) ║
║  /clear            - Clear conversation history              ║
║  /save             - Save conversation to file               ║
║  /help             - Show this help                          ║
║  /quit or exit     - Exit chat                               ║
╚══════════════════════════════════════════════════════════════╝
""")


def main():
    """Main chat loop."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA - Cybersecurity AI Assistant
   Session logging ENABLED for continuous improvement
   Type /help for commands
═══════════════════════════════════════════════════════════════════
""")
    
    chat = BombinaChat()
    print(f"📁 Session: {chat.session_id}\n")
    
    while True:
        try:
            user_input = input("🔐 You: ").strip()
            
            if not user_input:
                continue
            
            # Handle commands
            if user_input.startswith('/'):
                parts = user_input.split(' ', 1)
                command = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""
                
                if command in ['/quit', '/exit'] or user_input.lower() in ['exit', 'quit']:
                    print("\n👋 Session ended. Logs saved.")
                    break
                elif command == '/help':
                    print_help()
                elif command == '/feedback':
                    if args:
                        chat.provide_feedback(args)
                    else:
                        print("Usage: /feedback <your feedback>")
                elif command == '/correct':
                    if args:
                        chat.provide_correction(args)
                    else:
                        print("Usage: /correct <the correct response>")
                elif command == '/clear':
                    chat.conversation_history = []
                    print("🔄 Conversation cleared.")
                elif command == '/save':
                    print(f"💾 Session saved to: {chat.session_file}")
                else:
                    print(f"Unknown command: {command}. Type /help for commands.")
                continue
            
            # Regular chat
            print("\n🐸 Bombina: ", end="", flush=True)
            response = chat.chat(user_input)
            print(response)
            print()
            
        except KeyboardInterrupt:
            print("\n\n👋 Session ended. Logs saved.")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")
            print("Make sure Ollama is running: ollama serve")


if __name__ == "__main__":
    main()
