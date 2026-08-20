import copy
import json
import unittest

from neuruh_agent_run_manifest import (
    SCHEMA_VERSION,
    ArtifactRef,
    ComponentRef,
    DecisionRef,
    EvidenceRef,
    ExecutionRef,
    InferenceRef,
    ManifestValidationError,
    PolicyRef,
    ReceiptRef,
    RunManifest,
)

H = "sha256:" + "a" * 64
H2 = "sha256:" + "b" * 64
RH = "c" * 64
POL = "sha256:" + "d" * 64
COMMIT = "e" * 40


def valid_dict():
    raw = {
        "schema_version": SCHEMA_VERSION,
        "run_id": "run-001",
        "actor_id": "agent-demo",
        "mission": "synthetic mission",
        "started_at": "2026-08-08T19:00:00Z",
        "ended_at": "2026-08-08T19:00:01Z",
        "status": "completed",
        "components": [
            {"name": "starter", "version": "0.1.0a0", "source_commit": COMMIT}
        ],
        "policy": {"policy_id": "demo", "policy_version": POL},
        "inference": {
            "backend": "local-demo",
            "model": "demo-model",
            "health": "healthy",
        },
        "inputs": [{"artifact_id": "input-1", "sha256": H, "media_type": "text/plain"}],
        "evidence": [{"evidence_id": "ev-1", "sha256": H2, "state": "observed"}],
        "decisions": [
            {"action_id": "a1", "decision": "allow", "policy_version": POL, "sha256": H}
        ],
        "receipts": [{"receipt_id": "r1", "seq": 0, "entry_hash": RH}],
        "executions": [
            {
                "execution_id": "x1",
                "capability": "demo.print",
                "status": "executed",
                "decision_action_id": "a1",
                "receipt_id": "r1",
                "sha256": H2,
            }
        ],
        "outputs": [
            {"artifact_id": "output-1", "sha256": H2, "media_type": "text/plain"}
        ],
    }
    m = RunManifest(
        run_id=raw["run_id"],
        actor_id=raw["actor_id"],
        mission=raw["mission"],
        started_at=raw["started_at"],
        ended_at=raw["ended_at"],
        status=raw["status"],
        components=tuple(ComponentRef.from_mapping(x) for x in raw["components"]),
        policy=PolicyRef.from_mapping(raw["policy"]),
        inference=InferenceRef.from_mapping(raw["inference"]),
        inputs=tuple(ArtifactRef.from_mapping(x) for x in raw["inputs"]),
        evidence=tuple(EvidenceRef.from_mapping(x) for x in raw["evidence"]),
        decisions=tuple(DecisionRef.from_mapping(x) for x in raw["decisions"]),
        executions=tuple(ExecutionRef.from_mapping(x) for x in raw["executions"]),
        receipts=tuple(ReceiptRef.from_mapping(x) for x in raw["receipts"]),
        outputs=tuple(ArtifactRef.from_mapping(x) for x in raw["outputs"]),
    ).seal()
    return m.to_dict()


class ManifestTests(unittest.TestCase):
    def test_valid_roundtrip(self):
        self.assertEqual(RunManifest.from_mapping(valid_dict()).run_id, "run-001")

    def test_digest_deterministic(self):
        a = valid_dict()
        b = json.loads(json.dumps(a, sort_keys=False))
        self.assertEqual(
            RunManifest.from_mapping(a).manifest_digest,
            RunManifest.from_mapping(b).manifest_digest,
        )

    def test_missing_run_id(self):
        x = valid_dict()
        del x["run_id"]
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_unknown_top_field_rejected(self):
        x = valid_dict()
        x["private_route"] = "nope"
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_bad_artifact_hash_rejected(self):
        x = valid_dict()
        x["inputs"][0]["sha256"] = "bad"
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_duplicate_artifact_ids_rejected(self):
        x = valid_dict()
        x["outputs"][0]["artifact_id"] = "input-1"
        x["manifest_digest"] = RunManifest.from_mapping(valid_dict()).manifest_digest
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_duplicate_receipts_rejected(self):
        x = valid_dict()
        x["receipts"].append(copy.deepcopy(x["receipts"][0]))
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_decision_policy_mismatch_rejected(self):
        x = valid_dict()
        x["decisions"][0]["policy_version"] = "sha256:" + "f" * 64
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_execution_unknown_decision_rejected(self):
        x = valid_dict()
        x["executions"][0]["decision_action_id"] = "missing"
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_execution_unknown_receipt_rejected(self):
        x = valid_dict()
        x["executions"][0]["receipt_id"] = "missing"
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_executed_requires_receipt(self):
        x = valid_dict()
        x["executions"][0]["receipt_id"] = None
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_denied_run_cannot_execute(self):
        x = valid_dict()
        x["status"] = "denied"
        x["decisions"][0]["decision"] = "deny"
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_escalated_run_cannot_execute(self):
        x = valid_dict()
        x["status"] = "escalated"
        x["decisions"][0]["decision"] = "escalate"
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_end_before_start_rejected(self):
        x = valid_dict()
        x["ended_at"] = "2026-08-08T18:59:59Z"
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_tamper_changes_digest(self):
        x = valid_dict()
        x["mission"] = "tampered"
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_unknown_status_rejected(self):
        x = valid_dict()
        x["status"] = "maybe"
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_bad_source_commit_rejected(self):
        x = valid_dict()
        x["components"][0]["source_commit"] = "deadbeef"
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_receipt_sequence_must_be_contiguous(self):
        x = valid_dict()
        x["receipts"][0]["seq"] = 2
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_unavailable_inference_cannot_name_backend(self):
        x = valid_dict()
        x["inference"]["health"] = "unavailable"
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)

    def test_completed_cannot_contain_failed_execution(self):
        x = valid_dict()
        x["executions"][0]["status"] = "failed"
        self.assertRaises(ManifestValidationError, RunManifest.from_mapping, x)


if __name__ == "__main__":
    unittest.main()
