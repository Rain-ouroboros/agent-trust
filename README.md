# Agent Trust

Agent Trust is a zero-dependency Python library for deterministic, local,
advisory checks around AI-agent prompts, actions, scopes, and external tool
descriptors.

It produces sanitized receipts with `allow`, `review`, `quarantine`, or `deny`
verdicts. It does **not** intercept an LLM call or tool execution by itself. Your
application must enforce the verdict at its own policy boundary.

## Quick start

```python
from agent_trust import check_prompt

verdict = check_prompt("rm -rf /")

print(verdict.verdict)          # quarantine
print(verdict.quarantined)      # True
print(verdict.boundary_matches) # ("destructive_shell_command_boundary",)
print(verdict.enforced)         # False: the caller owns enforcement
```

A minimal caller-side boundary can look like this:

```python
verdict = check_prompt(untrusted_prompt)
if verdict.quarantined:
    raise ValueError(f"prompt rejected: {verdict.boundary_matches}")

# Only now pass the prompt to your model or action planner.
```

The receipt never contains the raw prompt. Inputs larger than 65,536 bytes and
unexpected analyzer failures return non-allow verdicts rather than silently
failing open.

## Installation

Agent Trust is not currently published on PyPI. Install it from GitHub:

```bash
python -m pip install "agent-trust @ git+https://github.com/Rain-ouroboros/agent-trust.git"
```

For development:

```bash
git clone https://github.com/Rain-ouroboros/agent-trust.git
cd agent-trust
python -m venv .venv
. .venv/bin/activate
python -m pip install -e . pytest
pytest -q
```

## Main APIs

### Prompt scan

`check_prompt()` and `check_prompts_batch()` detect high-confidence instruction
override phrases, destructive shell commands, credential-bearing text,
reality-frame overrides, supply-chain signals, and other catalogued boundaries.

### Action and provenance receipts

```python
from agent_trust import gate_zero_trust_agent_action

receipt = gate_zero_trust_agent_action({
    "agent_identity": {"id": "local-reviewer", "verified": True},
    "requested_action": "fetch dependency metadata",
    "required_scopes": ["network:read"],
    "granted_scopes": ["network:read"],
    "provenance": "verified local policy",
    "sensitivity": "low",
})
print(receipt["pre_action_decision"])
```

Additional receipt APIs include:

- `classify_agent_trust_boundaries()`
- `gate_external_skill_descriptor()`
- `gate_runtime_pre_action_with_signals()`
- `gate_static_scope_manifest_consistency()`
- `evaluate_agent_trust_change_control()`

### Scope and excessive-agency checks

```python
from agent_trust import ScopeGrants, check_scope

grants = ScopeGrants.from_dict("reviewer", {"filesystem": "read"})
receipt = check_scope("repo_write_commit", {}, grants)
print(receipt["verdict"])  # quarantine
```

Unknown tools default to `review`. Missing write capabilities default to
`quarantine`; missing read-only capabilities default to `review`.

## Security model and limitations

- The library is local and deterministic: no network, LLM, wallet, or tool call
  is made by the checks themselves.
- Verdicts are advisory receipts. Installing the wheel does not hook an agent's
  executor and does not create a sandbox.
- Keyword and regular-expression checks can be bypassed by paraphrase, encoding,
  or unknown homoglyphs and can also produce false positives. Do not use this as
  your only security control.
- Descriptor and manifest metadata are evidence, not proof. Keep authorization,
  least privilege, sandboxing, provenance, and audit controls outside the model.
- Rain's live Ouroboros runtime has its own explicit enforcement integration.
  This standalone package does not acquire that integration merely by being
  installed.

## Version

The current package version is `0.2.0`. It introduces the working public prompt
API, removes the always-allow scope stub, and makes every shipped module
importable without the Ouroboros monorepo.

## License

MIT

## Author

Rain Ouroboros — rain-ouroboros-github@agentmail.to
