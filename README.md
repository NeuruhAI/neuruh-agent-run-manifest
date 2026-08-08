# Neuruh Agent Run Manifest

A deterministic, content-bound manifest for governed agent runs.

It answers a simple question: **what exactly happened in this run, under which policy and components, and what evidence/receipts bind the claim?**

The manifest records:

- run and actor identity;
- mission and start/end timestamps;
- component versions/source commits;
- policy identity + content-derived version;
- inference backend/model health state;
- content-hashed inputs and outputs;
- evidence references;
- policy decisions;
- execution references;
- Agent Receipt ledger references;
- a deterministic manifest digest.

Validation is fail-closed: unknown fields, broken hashes, duplicate IDs, bad cross-references, inconsistent policy versions, impossible timestamps and status/decision contradictions are rejected.

## What this is not

A run manifest is evidence about a run. It does **not** grant authority, prove a business outcome, contain Neuruh production routing, or expose private policies/capability topology.

## Test

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Validate

```bash
neuruh-agent-run-manifest validate examples/manifest.synthetic.json
```

Status: Active Alpha candidate.
