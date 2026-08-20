# Neuruh Agent Run Manifest

A dependency-free, content-bound manifest for governed agent runs.

It records the run identity, policy, component versions, inference state, content-hashed artifacts, evidence, decisions, executions, and receipt references behind a claim.

## Install

```bash
git clone https://github.com/NeuruhAI/neuruh-agent-run-manifest.git
cd neuruh-agent-run-manifest
python -m venv .venv
source .venv/bin/activate
pip install .
```

Or install a pinned release directly:

```bash
pip install "neuruh-agent-run-manifest @ git+https://github.com/NeuruhAI/neuruh-agent-run-manifest.git@v0.1.2-alpha"
```

## Verify a manifest

```bash
neuruh-agent-run-manifest validate examples/manifest.synthetic.json
neuruh-agent-run-manifest digest examples/manifest.synthetic.json
```

Expected output:

```text
VALID run-c1dc2e9e445d4eff870e8353ac1d9a30 sha256:e670c86613b1d4d5ba064c3598ca7d0e32b7464eeea7cfebbbeff943ac439d13
sha256:e670c86613b1d4d5ba064c3598ca7d0e32b7464eeea7cfebbbeff943ac439d13
```

Validation fails closed on unknown fields, broken hashes, duplicate IDs, bad cross-references, inconsistent policy versions, impossible timestamps, and contradictory run states. A failing manifest exits nonzero with a `ManifestValidationError` message.

## API

| Name | Purpose |
| --- | --- |
| `RunManifest.from_mapping(raw)` | Parse and structurally validate a manifest body. |
| `RunManifest.validate(check_digest=True)` | Fail-closed cross-reference and consistency checks. |
| `RunManifest.calculated_digest()` | `sha256:` digest over the canonical body. |
| `RunManifest.seal()` | Return a copy carrying `manifest_digest`. |
| `RunManifest.to_dict()` | Serialize a sealed manifest. |
| `ArtifactRef`, `ComponentRef`, `PolicyRef`, `InferenceRef`, `EvidenceRef`, `DecisionRef`, `ReceiptRef`, `ExecutionRef` | Typed sections of the manifest body. |
| `canonical_json(value)`, `sha256_ref(value)` | Deterministic serialization and hashing helpers. |
| `SCHEMA_VERSION` | `neuruh.agent-run-manifest.v0.1`. |
| `ManifestValidationError` | Raised for every rejection. |

## Test

```bash
python -m unittest discover -s tests -v
```

## Safety boundary

A run manifest is evidence about a run. It does not grant authority, prove a business outcome, or attest identity — the digest is tamper evidence, not a signature. A valid manifest means the recorded claims are internally consistent and content-bound, not that the run was correct or authorized.

The example manifest is synthetic. See the [Neuruh Public Commons boundary](https://github.com/NeuruhAI/public-commons/blob/main/PUBLIC_PRIVATE_BOUNDARY.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
