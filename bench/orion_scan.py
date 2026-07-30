"""Thin, self-contained entrypoint for a full Orion scan — no changes to Orion's source.

Why this wrapper exists: the semantic index uses `jinaai/jina-embeddings-v2-base-code`, whose
`trust_remote_code` model breaks on `transformers` 5.x (an embedding-lookup crash on CPU and a
device-side assert on CUDA), so `bench/setup.sh` pins `transformers<5`. But Orion's own
`embed._patch_transformers_compat()` imports `PreTrainedConfig`, which only exists under
transformers 5.x — under 4.x it is spelled `PretrainedConfig`. Aliasing the new name onto the old
one before Orion imports `transformers` satisfies that import; the shim's three patches are all
`hasattr`-guarded and no-op on 4.x. This keeps Orion's source untouched while the GPU semantic index
works. See bench/README.md.

Usage (normally via bench/scan.sh, which sets the environment):
    python bench/orion_scan.py <repo> [--json out.json] [--no-semantic] [passthrough orion args...]
"""
from __future__ import annotations

import sys


def _alias_transformers_config() -> None:
    try:
        import transformers.configuration_utils as cu
        if not hasattr(cu, "PreTrainedConfig") and hasattr(cu, "PretrainedConfig"):
            cu.PreTrainedConfig = cu.PretrainedConfig
    except Exception:  # noqa: BLE001 -- a missing/renamed transformers must not break the scan
        pass


def main() -> int:
    _alias_transformers_config()
    # Import AFTER the alias so Orion's lazy transformers import resolves.
    from orion.cli import main as orion_main

    argv = sys.argv[1:]
    if not argv:
        print("usage: python bench/orion_scan.py <repo> [--json out.json] [orion scan args...]",
              file=sys.stderr)
        return 2
    # First positional is the repo; everything else passes through to `orion scan`.
    repo, rest = argv[0], argv[1:]
    return orion_main(["scan", repo, *rest])


if __name__ == "__main__":
    sys.exit(main())
