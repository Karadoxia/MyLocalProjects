#!/usr/bin/env python3
"""
Bombina Agent - Tool-Calling Pentest AI Framework

This implements the autonomous agent architecture:
1. LLM Core (Bombina via Ollama) - Reasoning and decision making
2. Planner - Breaks down objectives into actionable steps  
3. Tool Selector - Picks appropriate tool based on context
4. Executor - Runs tools with safety checks
5. Analyzer - Interprets results and determines next action
6. Memory - Tracks engagement state and findings

Usage:
    python bombina_agent.py --objective "Enumerate the target network 192.168.1.0/24"
    python bombina_agent.py --interactive
"""

import json
import subprocess
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import requests

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

BASE_DIR = Path(__file__).parent.parent
LOG_DIR = BASE_DIR / "data" / "agent_logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

OLLAMA_API = "http://localhost:11434/api/generate"
MODEL_NAME = "bombina"

# Risk thresholds for detection-aware execution
class RiskLevel(Enum):
    LOW = 1      # Passive techniques, unlikely to trigger alerts
    MEDIUM = 2   # Active but common techniques
    HIGH = 3     # Noisy techniques, likely to trigger alerts
    CRITICAL = 4 # Destructive or highly detectable

@dataclass
class ToolDefinition:
    """Definition of an available tool."""
    name: str
    description: str
    category: str
    risk_level: RiskLevel
    requires_sudo: bool
    example_usage: str
    executor: Callable
    detection_notes: str = ""


@dataclass
class EngagementState:
    """Tracks the current state of the engagement."""
    objective: str
    current_phase: str = "reconnaissance"
    findings: List[Dict] = field(default_factory=list)
    actions_taken: List[Dict] = field(default_factory=list)
    risk_budget: int = 10  # How many high-risk actions allowed
    current_target: Optional[str] = None
    credentials: List[Dict] = field(default_factory=list)
    access_level: str = "none"  # none, user, admin, root


@dataclass 
class ActionResult:
    """Result of a tool execution."""
    success: bool
    output: str
    tool_name: str
    command: str
    timestamp: str
    risk_cost: int = 0
    findings: List[Dict] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

def execute_nmap(target: str, options: str = "-sV") -> ActionResult:
    """Execute nmap scan."""
    cmd = f"nmap {options} {target}"
    try:
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=300
        )
        return ActionResult(
            success=result.returncode == 0,
            output=result.stdout + result.stderr,
            tool_name="nmap",
            command=cmd,
            timestamp=datetime.now().isoformat(),
            risk_cost=2
        )
    except subprocess.TimeoutExpired:
        return ActionResult(
            success=False,
            output="Scan timed out",
            tool_name="nmap",
            command=cmd,
            timestamp=datetime.now().isoformat()
        )
    except Exception as e:
        return ActionResult(
            success=False,
            output=str(e),
            tool_name="nmap",
            command=cmd,
            timestamp=datetime.now().isoformat()
        )


def execute_gobuster(target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> ActionResult:
    """Execute gobuster directory scan."""
    cmd = f"gobuster dir -u {target} -w {wordlist} -q"
    try:
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=600
        )
        return ActionResult(
            success=result.returncode == 0,
            output=result.stdout + result.stderr,
            tool_name="gobuster",
            command=cmd,
            timestamp=datetime.now().isoformat(),
            risk_cost=2
        )
    except Exception as e:
        return ActionResult(
            success=False,
            output=str(e),
            tool_name="gobuster",
            command=cmd,
            timestamp=datetime.now().isoformat()
        )


def execute_curl(url: str, method: str = "GET", data: str = "") -> ActionResult:
    """Execute HTTP request with curl."""
    cmd = ["curl", "-s", "-X", method, url]
    if data:
        cmd.extend(["-d", data])
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        return ActionResult(
            success=result.returncode == 0,
            output=result.stdout,
            tool_name="curl",
            command=" ".join(cmd),
            timestamp=datetime.now().isoformat(),
            risk_cost=1
        )
    except Exception as e:
        return ActionResult(
            success=False,
            output=str(e),
            tool_name="curl",
            command=" ".join(cmd),
            timestamp=datetime.now().isoformat()
        )


def execute_whois(domain: str) -> ActionResult:
    """Execute WHOIS lookup."""
    cmd = f"whois {domain}"
    try:
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=30
        )
        return ActionResult(
            success=result.returncode == 0,
            output=result.stdout,
            tool_name="whois",
            command=cmd,
            timestamp=datetime.now().isoformat(),
            risk_cost=0  # Passive
        )
    except Exception as e:
        return ActionResult(
            success=False,
            output=str(e),
            tool_name="whois",
            command=cmd,
            timestamp=datetime.now().isoformat()
        )


def execute_dig(domain: str, record_type: str = "ANY") -> ActionResult:
    """Execute DNS lookup."""
    cmd = f"dig {domain} {record_type}"
    try:
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=30
        )
        return ActionResult(
            success=result.returncode == 0,
            output=result.stdout,
            tool_name="dig",
            command=cmd,
            timestamp=datetime.now().isoformat(),
            risk_cost=0  # Passive
        )
    except Exception as e:
        return ActionResult(
            success=False,
            output=str(e),
            tool_name="dig",
            command=cmd,
            timestamp=datetime.now().isoformat()
        )


# Tool registry
TOOL_REGISTRY: Dict[str, ToolDefinition] = {
    "nmap": ToolDefinition(
        name="nmap",
        description="Network scanner for host discovery and service enumeration",
        category="reconnaissance",
        risk_level=RiskLevel.MEDIUM,
        requires_sudo=False,
        example_usage="nmap -sV -sC 192.168.1.1",
        executor=execute_nmap,
        detection_notes="Creates TCP connections, may trigger IDS. Use timing options (-T2) for stealth."
    ),
    "gobuster": ToolDefinition(
        name="gobuster",
        description="Directory and file brute-forcer for web applications",
        category="web_enumeration",
        risk_level=RiskLevel.MEDIUM,
        requires_sudo=False,
        example_usage="gobuster dir -u http://target -w wordlist.txt",
        executor=execute_gobuster,
        detection_notes="High request volume. Use -t flag to reduce threads."
    ),
    "curl": ToolDefinition(
        name="curl",
        description="HTTP client for making web requests",
        category="web_interaction",
        risk_level=RiskLevel.LOW,
        requires_sudo=False,
        example_usage="curl -X GET http://target/api",
        executor=execute_curl,
        detection_notes="Single requests blend with normal traffic."
    ),
    "whois": ToolDefinition(
        name="whois",
        description="Domain registration information lookup",
        category="passive_recon",
        risk_level=RiskLevel.LOW,
        requires_sudo=False,
        example_usage="whois example.com",
        executor=execute_whois,
        detection_notes="Passive - no direct target interaction."
    ),
    "dig": ToolDefinition(
        name="dig",
        description="DNS lookup utility",
        category="passive_recon",
        risk_level=RiskLevel.LOW,
        requires_sudo=False,
        example_usage="dig example.com ANY",
        executor=execute_dig,
        detection_notes="Queries public DNS - minimal detection risk."
    )
}


# ═══════════════════════════════════════════════════════════════════════════════
# BOMBINA LLM INTERFACE
# ═══════════════════════════════════════════════════════════════════════════════

class BombinaLLM:
    """Interface to Bombina model via Ollama."""
    
    def __init__(self, model: str = MODEL_NAME):
        self.model = model
        self.api_url = OLLAMA_API
    
    def query(self, prompt: str, system: str = None) -> str:
        """Query the LLM and return response."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "num_ctx": 2048
            }
        }
        
        if system:
            payload["system"] = system
        
        try:
            response = requests.post(self.api_url, json=payload, timeout=120)
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            logging.error(f"LLM query failed: {e}")
            return f"Error querying LLM: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════════

class Planner:
    """Breaks down objectives into actionable steps."""
    
    def __init__(self, llm: BombinaLLM):
        self.llm = llm
    
    def create_plan(self, objective: str, state: EngagementState) -> List[Dict]:
        """Create a plan of steps to achieve the objective."""
        system = """You are a penetration testing planner. Given an objective, break it down into specific, actionable steps.
Each step should be concrete and achievable with standard pentest tools.
Consider the current engagement state when planning.
Output steps as a numbered list."""

        prompt = f"""Objective: {objective}

Current state:
- Phase: {state.current_phase}
- Access level: {state.access_level}
- Risk budget remaining: {state.risk_budget}
- Findings so far: {len(state.findings)}

Create a plan with 3-5 specific steps to progress toward the objective.
For each step, indicate the category (recon/scan/exploit/post) and risk level (low/medium/high)."""

        response = self.llm.query(prompt, system)
        
        # Parse response into structured steps
        steps = []
        for i, line in enumerate(response.strip().split('\n')):
            if line.strip():
                steps.append({
                    "step_number": i + 1,
                    "description": line.strip(),
                    "status": "pending"
                })
        
        return steps


class ToolSelector:
    """Selects appropriate tool based on task and context."""
    
    def __init__(self, llm: BombinaLLM):
        self.llm = llm
    
    def select_tool(self, task: str, state: EngagementState) -> Optional[Dict]:
        """Select the best tool for a given task."""
        available_tools = "\n".join([
            f"- {name}: {tool.description} (risk: {tool.risk_level.name})"
            for name, tool in TOOL_REGISTRY.items()
        ])
        
        system = """You are a tool selection expert for penetration testing.
Given a task and available tools, select the most appropriate tool.
Consider detection risk and the current engagement context.
Respond with ONLY the tool name and required parameters in JSON format."""

        prompt = f"""Task: {task}

Available tools:
{available_tools}

Current risk budget: {state.risk_budget}
Target: {state.current_target or 'Not specified'}

Select the best tool and specify parameters. Respond in JSON:
{{"tool": "tool_name", "target": "target_value", "options": "additional_options"}}"""

        response = self.llm.query(prompt, system)
        
        # Parse JSON from response
        try:
            # Find JSON in response
            start = response.find('{')
            end = response.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            logging.warning(f"Failed to parse tool selection: {response}")
        
        return None


class Executor:
    """Executes tools with safety checks and logging."""
    
    def __init__(self, max_risk: RiskLevel = RiskLevel.HIGH):
        self.max_risk = max_risk
        self.log_file = LOG_DIR / f"execution_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    
    def execute(self, tool_name: str, params: Dict, state: EngagementState) -> ActionResult:
        """Execute a tool with safety checks."""
        # Validate tool exists
        if tool_name not in TOOL_REGISTRY:
            return ActionResult(
                success=False,
                output=f"Unknown tool: {tool_name}",
                tool_name=tool_name,
                command="",
                timestamp=datetime.now().isoformat()
            )
        
        tool = TOOL_REGISTRY[tool_name]
        
        # Check risk level
        if tool.risk_level.value > self.max_risk.value:
            return ActionResult(
                success=False,
                output=f"Tool risk level ({tool.risk_level.name}) exceeds maximum allowed ({self.max_risk.name})",
                tool_name=tool_name,
                command="",
                timestamp=datetime.now().isoformat()
            )
        
        # Check risk budget
        risk_cost = tool.risk_level.value
        if risk_cost > state.risk_budget:
            return ActionResult(
                success=False,
                output=f"Insufficient risk budget. Need {risk_cost}, have {state.risk_budget}",
                tool_name=tool_name,
                command="",
                timestamp=datetime.now().isoformat()
            )
        
        # Execute the tool
        target = params.get("target", state.current_target or "")
        options = params.get("options", "")
        
        print(f"🔧 Executing: {tool_name} on {target}")
        result = tool.executor(target, options) if options else tool.executor(target)
        result.risk_cost = risk_cost
        
        # Log execution
        self._log_execution(result, params)
        
        return result
    
    def _log_execution(self, result: ActionResult, params: Dict):
        """Log execution to file."""
        log_entry = {
            "timestamp": result.timestamp,
            "tool": result.tool_name,
            "command": result.command,
            "success": result.success,
            "params": params,
            "output_length": len(result.output)
        }
        
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')


class Analyzer:
    """Analyzes tool output and extracts findings."""
    
    def __init__(self, llm: BombinaLLM):
        self.llm = llm
    
    def analyze(self, result: ActionResult, state: EngagementState) -> Dict:
        """Analyze execution result and extract findings."""
        system = """You are a penetration testing analyst. Analyze tool output and extract:
1. Key findings (hosts, services, vulnerabilities)
2. Suggested next actions
3. Risk assessment of findings
Be concise and technical."""

        # Truncate long output
        output = result.output[:3000] if len(result.output) > 3000 else result.output
        
        prompt = f"""Tool: {result.tool_name}
Command: {result.command}
Success: {result.success}

Output:
{output}

Analyze this output. What did we find? What should we do next?"""

        response = self.llm.query(prompt, system)
        
        return {
            "analysis": response,
            "tool": result.tool_name,
            "timestamp": datetime.now().isoformat()
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN AGENT
# ═══════════════════════════════════════════════════════════════════════════════

class BombinaAgent:
    """Main agent orchestrating the pentest workflow."""
    
    def __init__(self, max_risk: RiskLevel = RiskLevel.HIGH):
        self.llm = BombinaLLM()
        self.planner = Planner(self.llm)
        self.tool_selector = ToolSelector(self.llm)
        self.executor = Executor(max_risk)
        self.analyzer = Analyzer(self.llm)
        self.state: Optional[EngagementState] = None
    
    def start_engagement(self, objective: str, target: str = None):
        """Start a new engagement with given objective."""
        self.state = EngagementState(
            objective=objective,
            current_target=target
        )
        
        print(f"""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA AGENT - Autonomous Pentest Framework
═══════════════════════════════════════════════════════════════

📋 Objective: {objective}
🎯 Target: {target or 'To be determined'}
⚡ Risk budget: {self.state.risk_budget}

""")
        
        # Create initial plan
        print("📝 Creating plan...")
        plan = self.planner.create_plan(objective, self.state)
        
        print("\n📋 Plan:")
        for step in plan:
            print(f"  {step['step_number']}. {step['description']}")
        
        return plan
    
    def execute_step(self, step_description: str) -> Dict:
        """Execute a single step from the plan."""
        if not self.state:
            return {"error": "No engagement started"}
        
        # Select tool for this step
        print(f"\n🔍 Analyzing step: {step_description[:50]}...")
        tool_selection = self.tool_selector.select_tool(step_description, self.state)
        
        if not tool_selection:
            return {"error": "Could not determine appropriate tool"}
        
        print(f"🔧 Selected: {tool_selection.get('tool')} → {tool_selection.get('target')}")
        
        # Execute the tool
        result = self.executor.execute(
            tool_selection.get('tool', ''),
            tool_selection,
            self.state
        )
        
        # Deduct risk budget
        self.state.risk_budget -= result.risk_cost
        
        # Analyze results
        if result.success:
            print(f"✅ Execution successful (risk cost: {result.risk_cost})")
            analysis = self.analyzer.analyze(result, self.state)
            
            # Store findings
            self.state.findings.append({
                "step": step_description,
                "result": result.output[:500],
                "analysis": analysis
            })
            
            self.state.actions_taken.append({
                "tool": result.tool_name,
                "command": result.command,
                "timestamp": result.timestamp
            })
            
            print(f"\n📊 Analysis:\n{analysis['analysis'][:500]}...")
            
            return {
                "success": True,
                "output": result.output,
                "analysis": analysis
            }
        else:
            print(f"❌ Execution failed: {result.output[:200]}")
            return {
                "success": False,
                "error": result.output
            }
    
    def run_autonomous(self, max_steps: int = 5):
        """Run the agent autonomously for a number of steps."""
        if not self.state:
            print("❌ No engagement started. Call start_engagement() first.")
            return
        
        plan = self.planner.create_plan(self.state.objective, self.state)
        
        for i, step in enumerate(plan[:max_steps]):
            if self.state.risk_budget <= 0:
                print("\n⚠️  Risk budget exhausted. Stopping.")
                break
            
            print(f"\n{'='*60}")
            print(f"Step {i+1}/{len(plan)}: {step['description']}")
            print('='*60)
            
            result = self.execute_step(step['description'])
            
            if not result.get('success'):
                print(f"\n⚠️  Step failed, continuing to next...")
        
        self.print_summary()
    
    def print_summary(self):
        """Print engagement summary."""
        if not self.state:
            return
        
        print(f"""
{'='*60}
📋 ENGAGEMENT SUMMARY
{'='*60}

Objective: {self.state.objective}
Actions taken: {len(self.state.actions_taken)}
Findings: {len(self.state.findings)}
Risk budget remaining: {self.state.risk_budget}

Actions:
""")
        for action in self.state.actions_taken:
            print(f"  • {action['tool']}: {action['command'][:60]}...")
        
        print("\nFindings:")
        for finding in self.state.findings:
            print(f"  • {finding['step'][:50]}...")


def interactive_mode():
    """Run agent in interactive mode."""
    agent = BombinaAgent()
    
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA AGENT - Interactive Mode
═══════════════════════════════════════════════════════════════

Commands:
  start <objective> [target] - Start new engagement
  plan                       - Show/regenerate plan  
  step <description>         - Execute a specific step
  auto [n]                   - Run n steps autonomously
  status                     - Show current state
  tools                      - List available tools
  quit                       - Exit

""")
    
    while True:
        try:
            cmd = input("🐸 > ").strip()
            
            if not cmd:
                continue
            
            parts = cmd.split(maxsplit=2)
            action = parts[0].lower()
            
            if action == "quit" or action == "exit":
                break
            
            elif action == "start":
                if len(parts) < 2:
                    print("Usage: start <objective> [target]")
                    continue
                objective = parts[1]
                target = parts[2] if len(parts) > 2 else None
                agent.start_engagement(objective, target)
            
            elif action == "step":
                if len(parts) < 2:
                    print("Usage: step <description>")
                    continue
                agent.execute_step(parts[1])
            
            elif action == "auto":
                n = int(parts[1]) if len(parts) > 1 else 5
                agent.run_autonomous(n)
            
            elif action == "status":
                if agent.state:
                    agent.print_summary()
                else:
                    print("No engagement started")
            
            elif action == "tools":
                print("\nAvailable tools:")
                for name, tool in TOOL_REGISTRY.items():
                    print(f"  • {name} ({tool.risk_level.name}): {tool.description}")
            
            else:
                print(f"Unknown command: {action}")
                
        except KeyboardInterrupt:
            print("\nInterrupted")
            break
        except Exception as e:
            print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description='Bombina Agent - Autonomous Pentest Framework')
    parser.add_argument('--objective', type=str, help='Engagement objective')
    parser.add_argument('--target', type=str, help='Primary target')
    parser.add_argument('--interactive', '-i', action='store_true', help='Run in interactive mode')
    parser.add_argument('--max-steps', type=int, default=5, help='Maximum autonomous steps')
    parser.add_argument('--max-risk', type=str, default='HIGH', 
                       choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                       help='Maximum risk level allowed')
    
    args = parser.parse_args()
    
    if args.interactive:
        interactive_mode()
    elif args.objective:
        risk_level = RiskLevel[args.max_risk]
        agent = BombinaAgent(max_risk=risk_level)
        agent.start_engagement(args.objective, args.target)
        agent.run_autonomous(args.max_steps)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
