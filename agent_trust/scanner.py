"""Small public prompt-scanning facade for Agent Trust.

The scanner is deterministic and local.  It returns an advisory receipt; it
does not intercept model calls or tool execution.  Callers decide how to
enforce the returned verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Iterable

from agent_trust.boundaries import (
    SUPPORTED_BOUNDARY_INTAKE_CONTRACT_VERSIONS,
    classify_agent_trust_boundaries,
)


MAX_PROMPT_BYTES = 65_536


@dataclass(frozen=True, slots=True)
class PromptVerdict:
    """Sanitized result of a prompt scan.

    No raw prompt text is retained.  ``enforced`` is always false because this
    package produces evidence for a caller-owned policy boundary; it is not a
    sandbox or an execution hook.
    """

    verdict: str
    boundary_matches: tuple[str, ...]
    reasons: tuple[str, ...]
    packet_id: str
    digest: str
    contract_version: str
    enforced: bool = False

    @property
    def quarantined(self) -> bool:
        """Whether a caller should keep this input out of an action path."""

        return self.verdict in {"quarantine", "deny"}

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serializable, prompt-free receipt."""

        return {
            "verdict": self.verdict,
            "quarantined": self.quarantined,
            "boundary_matches": list(self.boundary_matches),
            "reasons": list(self.reasons),
            "packet_id": self.packet_id,
            "digest": self.digest,
            "contract_version": self.contract_version,
            "enforced": self.enforced,
        }


def _local_receipt(
    *,
    verdict: str,
    boundary: str,
    reason: str,
    material: dict[str, object],
    contract_version: str,
) -> PromptVerdict:
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return PromptVerdict(
        verdict=verdict,
        boundary_matches=(boundary,),
        reasons=(reason,),
        packet_id=f"prompt-scan-{digest[:16]}",
        digest=digest,
        contract_version=contract_version,
    )


def check_prompt(
    prompt: str,
    *,
    contract_version: str | None = None,
    max_bytes: int = MAX_PROMPT_BYTES,
) -> PromptVerdict:
    """Classify one prompt and return a sanitized advisory verdict.

    Oversized input and unexpected analyzer failures return non-allow verdicts
    instead of silently failing open.  Unsupported explicit contract versions
    remain caller errors and raise ``ValueError``.
    """

    if not isinstance(prompt, str):
        raise TypeError("prompt must be a string")
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")

    negotiated = contract_version or SUPPORTED_BOUNDARY_INTAKE_CONTRACT_VERSIONS[-1]
    if negotiated not in SUPPORTED_BOUNDARY_INTAKE_CONTRACT_VERSIONS:
        supported = ", ".join(SUPPORTED_BOUNDARY_INTAKE_CONTRACT_VERSIONS)
        raise ValueError(
            f"unsupported boundary intake contract version: {negotiated}; "
            f"supported: {supported}"
        )

    prompt_bytes = prompt.encode("utf-8", errors="replace")
    if len(prompt_bytes) > max_bytes:
        return _local_receipt(
            verdict="quarantine",
            boundary="prompt_size_limit_boundary",
            reason="prompt_size_limit_exceeded",
            material={
                "contract_version": negotiated,
                "input_bytes": len(prompt_bytes),
                "max_bytes": max_bytes,
                "verdict": "quarantine",
            },
            contract_version=negotiated,
        )

    try:
        packet = classify_agent_trust_boundaries(
            {"description": prompt},
            contract_version=negotiated,
        )
    except Exception:
        return _local_receipt(
            verdict="review",
            boundary="analyzer_error_boundary",
            reason="analyzer_error_fail_closed",
            material={
                "contract_version": negotiated,
                "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
                "verdict": "review",
            },
            contract_version=negotiated,
        )

    matched = packet.get("matched_boundaries")
    boundary_matches = tuple(
        str(item["id"])
        for item in matched or []
        if isinstance(item, dict) and item.get("id")
    )
    return PromptVerdict(
        verdict=str(packet["verdict"]),
        boundary_matches=boundary_matches,
        reasons=tuple(str(reason) for reason in packet.get("reasons") or []),
        packet_id=str(packet["packet_id"]),
        digest=str(packet["digest"]),
        contract_version=str(packet["contract_version"]),
    )


def check_prompts_batch(
    prompts: Iterable[str],
    *,
    contract_version: str | None = None,
    max_bytes: int = MAX_PROMPT_BYTES,
) -> list[PromptVerdict]:
    """Scan prompts in order, keeping each result independent."""

    if not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    negotiated = contract_version or SUPPORTED_BOUNDARY_INTAKE_CONTRACT_VERSIONS[-1]
    if negotiated not in SUPPORTED_BOUNDARY_INTAKE_CONTRACT_VERSIONS:
        supported = ", ".join(SUPPORTED_BOUNDARY_INTAKE_CONTRACT_VERSIONS)
        raise ValueError(
            f"unsupported boundary intake contract version: {negotiated}; "
            f"supported: {supported}"
        )

    verdicts: list[PromptVerdict] = []
    for prompt in prompts:
        if not isinstance(prompt, str):
            verdicts.append(
                _local_receipt(
                    verdict="review",
                    boundary="invalid_prompt_type_boundary",
                    reason="invalid_prompt_type_fail_closed",
                    material={
                        "contract_version": negotiated,
                        "input_type": type(prompt).__name__,
                        "verdict": "review",
                    },
                    contract_version=negotiated,
                )
            )
            continue
        verdicts.append(
            check_prompt(
                prompt,
                contract_version=negotiated,
                max_bytes=max_bytes,
            )
        )
    return verdicts


class AgentTrustGate:
    """Configured convenience wrapper around the stateless scan functions."""

    def __init__(
        self,
        *,
        contract_version: str | None = None,
        max_bytes: int = MAX_PROMPT_BYTES,
    ) -> None:
        self.contract_version = contract_version
        self.max_bytes = max_bytes

    def check_prompt(self, prompt: str) -> PromptVerdict:
        return check_prompt(
            prompt,
            contract_version=self.contract_version,
            max_bytes=self.max_bytes,
        )

    def check_prompts_batch(self, prompts: Iterable[str]) -> list[PromptVerdict]:
        return check_prompts_batch(
            prompts,
            contract_version=self.contract_version,
            max_bytes=self.max_bytes,
        )


__all__ = [
    "AgentTrustGate",
    "MAX_PROMPT_BYTES",
    "PromptVerdict",
    "check_prompt",
    "check_prompts_batch",
]
