from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any, Mapping

SCHEMA_VERSION = "neuruh.agent-run-manifest.v0.1"
STATUSES = {"completed", "denied", "escalated", "failed", "dry_run"}
DECISIONS = {"allow", "deny", "escalate"}
INFERENCE_HEALTH = {"healthy", "degraded", "unavailable", "not_used"}
EXECUTION_STATUSES = {"executed", "dry_run", "failed", "not_started"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


class ManifestValidationError(ValueError):
    """Fail-closed refusal for malformed, ambiguous, or internally inconsistent manifests."""


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_ref(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return "sha256:" + sha256(value).hexdigest()


def _require_nonempty(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManifestValidationError(f"{name} must be a non-empty string")
    return value


def _validate_sha256_ref(value: Any, name: str) -> str:
    value = _require_nonempty(value, name)
    if not value.startswith("sha256:") or not HEX64.fullmatch(value[7:]):
        raise ManifestValidationError(f"{name} must be sha256:<64 lowercase hex>")
    return value


def _validate_receipt_hash(value: Any, name: str) -> str:
    value = _require_nonempty(value, name)
    if not HEX64.fullmatch(value):
        raise ManifestValidationError(f"{name} must be 64 lowercase hex")
    return value


def _validate_commit(value: Any, name: str) -> str:
    value = _require_nonempty(value, name)
    if not HEX40.fullmatch(value):
        raise ManifestValidationError(
            f"{name} must be a 40-character lowercase git commit SHA"
        )
    return value


def _parse_time(value: Any, name: str) -> datetime:
    value = _require_nonempty(value, name)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ManifestValidationError(f"{name} must be RFC3339/ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ManifestValidationError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _exact_keys(
    raw: Mapping[str, Any], required: set[str], optional: set[str], context: str
) -> None:
    missing = sorted(required - set(raw))
    unknown = sorted(set(raw) - required - optional)
    if missing:
        raise ManifestValidationError(
            f"{context} missing required field(s): {', '.join(missing)}"
        )
    if unknown:
        raise ManifestValidationError(
            f"{context} contains unknown field(s): {', '.join(unknown)}"
        )


@dataclass(frozen=True)
class ArtifactRef:
    artifact_id: str
    sha256: str
    media_type: str = "application/octet-stream"

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ArtifactRef":
        _exact_keys(raw, {"artifact_id", "sha256"}, {"media_type"}, "artifact")
        return cls(
            _require_nonempty(raw["artifact_id"], "artifact_id"),
            _validate_sha256_ref(raw["sha256"], "artifact sha256"),
            _require_nonempty(
                raw.get("media_type", "application/octet-stream"), "media_type"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "sha256": self.sha256,
            "media_type": self.media_type,
        }


@dataclass(frozen=True)
class ComponentRef:
    name: str
    version: str
    source_commit: str | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ComponentRef":
        _exact_keys(raw, {"name", "version"}, {"source_commit"}, "component")
        commit = raw.get("source_commit")
        return cls(
            _require_nonempty(raw["name"], "component name"),
            _require_nonempty(raw["version"], "component version"),
            _validate_commit(commit, "source_commit") if commit is not None else None,
        )

    def to_dict(self) -> dict[str, Any]:
        out = {"name": self.name, "version": self.version}
        if self.source_commit is not None:
            out["source_commit"] = self.source_commit
        return out


@dataclass(frozen=True)
class PolicyRef:
    policy_id: str
    policy_version: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PolicyRef":
        _exact_keys(raw, {"policy_id", "policy_version"}, set(), "policy")
        return cls(
            _require_nonempty(raw["policy_id"], "policy_id"),
            _validate_sha256_ref(raw["policy_version"], "policy_version"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"policy_id": self.policy_id, "policy_version": self.policy_version}


@dataclass(frozen=True)
class InferenceRef:
    backend: str | None
    model: str | None
    health: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "InferenceRef":
        _exact_keys(raw, {"backend", "model", "health"}, set(), "inference")
        health = _require_nonempty(raw["health"], "inference health")
        if health not in INFERENCE_HEALTH:
            raise ManifestValidationError(f"unknown inference health: {health}")
        backend = raw["backend"]
        model = raw["model"]
        if backend is not None:
            backend = _require_nonempty(backend, "inference backend")
        if model is not None:
            model = _require_nonempty(model, "inference model")
        if health in {"not_used", "unavailable"} and (
            backend is not None or model is not None
        ):
            raise ManifestValidationError(
                f"{health} inference cannot name a backend or model"
            )
        if health in {"healthy", "degraded"} and backend is None:
            raise ManifestValidationError(f"{health} inference requires a backend")
        return cls(backend, model, health)

    def to_dict(self) -> dict[str, Any]:
        return {"backend": self.backend, "model": self.model, "health": self.health}


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    sha256: str
    state: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "EvidenceRef":
        _exact_keys(raw, {"evidence_id", "sha256", "state"}, set(), "evidence")
        state = _require_nonempty(raw["state"], "evidence state")
        if state not in {"supported", "observed", "abstained", "contradicted"}:
            raise ManifestValidationError(f"unknown evidence state: {state}")
        return cls(
            _require_nonempty(raw["evidence_id"], "evidence_id"),
            _validate_sha256_ref(raw["sha256"], "evidence sha256"),
            state,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "sha256": self.sha256,
            "state": self.state,
        }


@dataclass(frozen=True)
class DecisionRef:
    action_id: str
    decision: str
    policy_version: str
    sha256: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "DecisionRef":
        _exact_keys(
            raw,
            {"action_id", "decision", "policy_version", "sha256"},
            set(),
            "decision",
        )
        decision = _require_nonempty(raw["decision"], "decision")
        if decision not in DECISIONS:
            raise ManifestValidationError(f"unknown decision: {decision}")
        return cls(
            _require_nonempty(raw["action_id"], "action_id"),
            decision,
            _validate_sha256_ref(raw["policy_version"], "decision policy_version"),
            _validate_sha256_ref(raw["sha256"], "decision sha256"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "decision": self.decision,
            "policy_version": self.policy_version,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class ReceiptRef:
    receipt_id: str
    seq: int
    entry_hash: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ReceiptRef":
        _exact_keys(raw, {"receipt_id", "seq", "entry_hash"}, set(), "receipt")
        seq = raw["seq"]
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ManifestValidationError("receipt seq must be a non-negative integer")
        return cls(
            _require_nonempty(raw["receipt_id"], "receipt_id"),
            seq,
            _validate_receipt_hash(raw["entry_hash"], "receipt entry_hash"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "seq": self.seq,
            "entry_hash": self.entry_hash,
        }


@dataclass(frozen=True)
class ExecutionRef:
    execution_id: str
    capability: str
    status: str
    decision_action_id: str
    receipt_id: str | None
    sha256: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ExecutionRef":
        _exact_keys(
            raw,
            {
                "execution_id",
                "capability",
                "status",
                "decision_action_id",
                "receipt_id",
                "sha256",
            },
            set(),
            "execution",
        )
        status = _require_nonempty(raw["status"], "execution status")
        if status not in EXECUTION_STATUSES:
            raise ManifestValidationError(f"unknown execution status: {status}")
        receipt_id = raw["receipt_id"]
        if receipt_id is not None:
            receipt_id = _require_nonempty(receipt_id, "execution receipt_id")
        if status == "executed" and receipt_id is None:
            raise ManifestValidationError("executed execution requires receipt_id")
        return cls(
            _require_nonempty(raw["execution_id"], "execution_id"),
            _require_nonempty(raw["capability"], "execution capability"),
            status,
            _require_nonempty(raw["decision_action_id"], "decision_action_id"),
            receipt_id,
            _validate_sha256_ref(raw["sha256"], "execution sha256"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "capability": self.capability,
            "status": self.status,
            "decision_action_id": self.decision_action_id,
            "receipt_id": self.receipt_id,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class RunManifest:
    run_id: str
    actor_id: str
    mission: str
    started_at: str
    ended_at: str
    status: str
    components: tuple[ComponentRef, ...]
    policy: PolicyRef
    inference: InferenceRef
    inputs: tuple[ArtifactRef, ...] = ()
    evidence: tuple[EvidenceRef, ...] = ()
    decisions: tuple[DecisionRef, ...] = ()
    executions: tuple[ExecutionRef, ...] = ()
    receipts: tuple[ReceiptRef, ...] = ()
    outputs: tuple[ArtifactRef, ...] = ()
    manifest_digest: str | None = None

    def body_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "actor_id": self.actor_id,
            "mission": self.mission,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "status": self.status,
            "components": [x.to_dict() for x in self.components],
            "policy": self.policy.to_dict(),
            "inference": self.inference.to_dict(),
            "inputs": [x.to_dict() for x in self.inputs],
            "evidence": [x.to_dict() for x in self.evidence],
            "decisions": [x.to_dict() for x in self.decisions],
            "executions": [x.to_dict() for x in self.executions],
            "receipts": [x.to_dict() for x in self.receipts],
            "outputs": [x.to_dict() for x in self.outputs],
        }

    def calculated_digest(self) -> str:
        return sha256_ref(canonical_json(self.body_dict()))

    def seal(self) -> "RunManifest":
        self.validate(check_digest=False)
        return RunManifest(
            **{**self.__dict__, "manifest_digest": self.calculated_digest()}
        )

    def to_dict(self) -> dict[str, Any]:
        if self.manifest_digest is None:
            raise ManifestValidationError(
                "manifest must be sealed before serialization"
            )
        out = self.body_dict()
        out["manifest_digest"] = self.manifest_digest
        return out

    def validate(self, *, check_digest: bool = True) -> None:
        _require_nonempty(self.run_id, "run_id")
        _require_nonempty(self.actor_id, "actor_id")
        _require_nonempty(self.mission, "mission")
        start = _parse_time(self.started_at, "started_at")
        end = _parse_time(self.ended_at, "ended_at")
        if end < start:
            raise ManifestValidationError("ended_at cannot be before started_at")
        if self.status not in STATUSES:
            raise ManifestValidationError(f"unknown run status: {self.status}")
        if not self.components:
            raise ManifestValidationError(
                "at least one component reference is required"
            )

        component_names = [c.name for c in self.components]
        if len(component_names) != len(set(component_names)):
            raise ManifestValidationError("component names must be unique")

        artifact_ids = [x.artifact_id for x in (*self.inputs, *self.outputs)]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ManifestValidationError(
                "artifact IDs must be unique across inputs and outputs"
            )

        evidence_ids = [x.evidence_id for x in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ManifestValidationError("evidence IDs must be unique")

        action_ids = [x.action_id for x in self.decisions]
        if len(action_ids) != len(set(action_ids)):
            raise ManifestValidationError("decision action IDs must be unique")
        for decision in self.decisions:
            if decision.policy_version != self.policy.policy_version:
                raise ManifestValidationError(
                    "decision policy_version does not match manifest policy"
                )

        receipt_ids = [x.receipt_id for x in self.receipts]
        if len(receipt_ids) != len(set(receipt_ids)):
            raise ManifestValidationError("receipt IDs must be unique")
        receipt_seqs = [x.seq for x in self.receipts]
        if sorted(receipt_seqs) != list(range(len(receipt_seqs))):
            raise ManifestValidationError(
                "receipt seq values must be contiguous from zero"
            )
        receipt_id_set = set(receipt_ids)

        execution_ids = [x.execution_id for x in self.executions]
        if len(execution_ids) != len(set(execution_ids)):
            raise ManifestValidationError("execution IDs must be unique")
        action_id_set = set(action_ids)
        for execution in self.executions:
            if execution.decision_action_id not in action_id_set:
                raise ManifestValidationError(
                    "execution references an unknown decision action_id"
                )
            if (
                execution.receipt_id is not None
                and execution.receipt_id not in receipt_id_set
            ):
                raise ManifestValidationError(
                    "execution references an unknown receipt_id"
                )

        if self.status == "denied":
            if not any(x.decision == "deny" for x in self.decisions):
                raise ManifestValidationError("denied run requires a deny decision")
            if any(x.status in {"executed", "dry_run"} for x in self.executions):
                raise ManifestValidationError(
                    "denied run cannot contain executed/dry-run execution"
                )
        if self.status == "escalated":
            if not any(x.decision == "escalate" for x in self.decisions):
                raise ManifestValidationError(
                    "escalated run requires an escalate decision"
                )
            if any(x.status in {"executed", "dry_run"} for x in self.executions):
                raise ManifestValidationError(
                    "escalated run cannot contain executed/dry-run execution"
                )
        if self.status == "completed" and any(
            x.status != "executed" for x in self.executions
        ):
            raise ManifestValidationError(
                "completed run cannot contain non-executed execution records"
            )
        if self.status == "dry_run":
            if not any(x.status == "dry_run" for x in self.executions):
                raise ManifestValidationError(
                    "dry_run status requires at least one dry_run execution"
                )
            if any(x.status == "executed" for x in self.executions):
                raise ManifestValidationError(
                    "dry_run status cannot contain executed execution records"
                )

        if check_digest:
            if self.manifest_digest is None:
                raise ManifestValidationError("manifest_digest is required")
            _validate_sha256_ref(self.manifest_digest, "manifest_digest")
            if self.manifest_digest != self.calculated_digest():
                raise ManifestValidationError("manifest_digest mismatch")

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "RunManifest":
        required = {
            "schema_version",
            "run_id",
            "actor_id",
            "mission",
            "started_at",
            "ended_at",
            "status",
            "components",
            "policy",
            "inference",
            "inputs",
            "evidence",
            "decisions",
            "executions",
            "receipts",
            "outputs",
            "manifest_digest",
        }
        _exact_keys(raw, required, set(), "manifest")
        if raw["schema_version"] != SCHEMA_VERSION:
            raise ManifestValidationError("unsupported schema_version")
        for field in (
            "components",
            "inputs",
            "evidence",
            "decisions",
            "executions",
            "receipts",
            "outputs",
        ):
            if not isinstance(raw[field], list):
                raise ManifestValidationError(f"{field} must be an array")
        if not isinstance(raw["policy"], Mapping) or not isinstance(
            raw["inference"], Mapping
        ):
            raise ManifestValidationError("policy and inference must be objects")

        manifest = cls(
            run_id=_require_nonempty(raw["run_id"], "run_id"),
            actor_id=_require_nonempty(raw["actor_id"], "actor_id"),
            mission=_require_nonempty(raw["mission"], "mission"),
            started_at=_require_nonempty(raw["started_at"], "started_at"),
            ended_at=_require_nonempty(raw["ended_at"], "ended_at"),
            status=_require_nonempty(raw["status"], "status"),
            components=tuple(ComponentRef.from_mapping(x) for x in raw["components"]),
            policy=PolicyRef.from_mapping(raw["policy"]),
            inference=InferenceRef.from_mapping(raw["inference"]),
            inputs=tuple(ArtifactRef.from_mapping(x) for x in raw["inputs"]),
            evidence=tuple(EvidenceRef.from_mapping(x) for x in raw["evidence"]),
            decisions=tuple(DecisionRef.from_mapping(x) for x in raw["decisions"]),
            executions=tuple(ExecutionRef.from_mapping(x) for x in raw["executions"]),
            receipts=tuple(ReceiptRef.from_mapping(x) for x in raw["receipts"]),
            outputs=tuple(ArtifactRef.from_mapping(x) for x in raw["outputs"]),
            manifest_digest=_validate_sha256_ref(
                raw["manifest_digest"], "manifest_digest"
            ),
        )
        manifest.validate()
        return manifest
