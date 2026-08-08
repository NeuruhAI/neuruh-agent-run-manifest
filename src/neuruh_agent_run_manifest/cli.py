from __future__ import annotations
import argparse, json
from pathlib import Path
from .core import RunManifest, ManifestValidationError

def main(argv=None) -> int:
    p=argparse.ArgumentParser(prog="neuruh-agent-run-manifest")
    sub=p.add_subparsers(dest="command", required=True)
    v=sub.add_parser("validate", help="validate a sealed run manifest")
    v.add_argument("path")
    d=sub.add_parser("digest", help="print the verified manifest digest")
    d.add_argument("path")
    args=p.parse_args(argv)
    try:
        raw=json.loads(Path(args.path).read_text())
        manifest=RunManifest.from_mapping(raw)
    except (OSError, json.JSONDecodeError, ManifestValidationError) as exc:
        print(f"INVALID: {exc}")
        return 2
    if args.command == "validate":
        print(f"VALID {manifest.run_id} {manifest.manifest_digest}")
    else:
        print(manifest.manifest_digest)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
