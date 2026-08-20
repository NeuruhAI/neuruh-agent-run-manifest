from .core import (
    SCHEMA_VERSION,
    ManifestValidationError,
    ArtifactRef,
    ComponentRef,
    PolicyRef,
    InferenceRef,
    EvidenceRef,
    DecisionRef,
    ReceiptRef,
    ExecutionRef,
    RunManifest,
    canonical_json,
    sha256_ref,
)

__all__ = [
    "SCHEMA_VERSION",
    "ManifestValidationError",
    "ArtifactRef",
    "ComponentRef",
    "PolicyRef",
    "InferenceRef",
    "EvidenceRef",
    "DecisionRef",
    "ReceiptRef",
    "ExecutionRef",
    "RunManifest",
    "canonical_json",
    "sha256_ref",
]

from importlib.metadata import PackageNotFoundError, version as _metadata_version

try:
    __version__ = _metadata_version("neuruh-agent-run-manifest")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "unknown"
