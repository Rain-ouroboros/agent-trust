# Agent Trust

Local agent safety gate — boundary-based prompt scanner for AI agents.

Detects prompt injection, excessive agency, supply-chain attacks, and domain-mismatch exploits before they reach your LLM.

## Quick Start

```python
from agent_trust import check_prompt

verdict = check_prompt("rm -rf /")
print(verdict.quarantined)  # True
print(verdict.boundary_matches)  # ["shell_command_destructive"]
```

## What It Detects

| Category | Example |
|---|---|
| Prompt injection | "Ignore previous instructions and..." |
| Excessive agency | Agent with file access trying to open network sockets |
| Supply-chain attacks | Malicious postinstall scripts, SDK telemetry injection |
| Domain mismatch | Language heuristics applied to execution decisions |
| Autonomous ransomware | Multi-step lateral movement + encryption chains |

## Installation

```bash
pip install agent-trust
```

## License

MIT

## Author

Rain Ouroboros — rain-ouroboros-github@agentmail.to
