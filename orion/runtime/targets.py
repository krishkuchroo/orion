"""Target selection: pick a (Driver, Tracer) for a repo, or None if unsupported. PURE detection.

This is the NEW framework seam, parallel to graph/profiles.py (which answers STATIC source/sink
questions). Here we answer "how do we boot/build and drive this?" -- an orthogonal axis.

Because boot commands, base URLs, and especially LOGIN are inherently app-specific (the honest
"authed fuzzing needs per-app knowledge" limit), a repo may drop a `.orion/runtime.json` descriptor
to override the defaults:

    {"kind":"http","boot":["npm","start"],"base_url":"http://localhost:4000",
     "login":{"path":"/login","fields":{"userName":"user1","password":"User1_123"}}}
    {"kind":"process","build":["go","build","./..."],"out":"target.bin"}

Absent a descriptor we fall back to conservative defaults from the manifest. `select` returns None
(→ stage skipped, graph untouched) when nothing fits.
"""
from __future__ import annotations

import json
from pathlib import Path

from .go_tracer import GoCoverTracer
from .http_driver import HttpDriver
from .process_driver import ProcessDriver
from .v8_tracer import V8Tracer

DESCRIPTOR = ".orion/runtime.json"


def load_descriptor(repo: str) -> dict | None:
    p = Path(repo) / DESCRIPTOR
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def _has(repo: str, name: str) -> bool:
    return (Path(repo) / name).exists()


def _package_start(repo: str) -> list[str] | None:
    pj = Path(repo) / "package.json"
    if not pj.exists():
        return None
    try:
        data = json.loads(pj.read_text())
    except (OSError, ValueError):
        return None
    scripts = data.get("scripts", {})
    if "start" in scripts:
        return ["npm", "start"]
    return None


def select(repo: str, profile=None):
    """Return (Driver, Tracer) or None. Descriptor wins; else sniff the manifest."""
    desc = load_descriptor(repo)
    v8 = V8Tracer()

    if desc:
        if desc.get("kind") == "http":
            drv = HttpDriver(
                boot_cmd=desc.get("boot", ["npm", "start"]),
                base_url=desc.get("base_url", "http://localhost:3000"),
                tracer=v8,
                login=desc.get("login"),
            )
            return drv, v8
        if desc.get("kind") == "process":
            tracer = GoCoverTracer(module_prefix=desc.get("module_prefix", ""))
            drv = ProcessDriver(
                build_cmd=desc.get("build", ["go", "build", "./..."]),
                out_bin=desc.get("out", "orion-target.bin"),
                tracer=tracer,
            )
            return drv, tracer
        return None

    # No descriptor: conservative manifest sniff.
    start = _package_start(repo)
    if start is not None:
        drv = HttpDriver(boot_cmd=start, base_url="http://localhost:3000", tracer=v8, login=None)
        return drv, v8
    if _has(repo, "go.mod"):
        tracer = GoCoverTracer()
        drv = ProcessDriver(build_cmd=["go", "build", "./..."], out_bin="orion-target.bin",
                            tracer=tracer)
        return drv, tracer
    return None
