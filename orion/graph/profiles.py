"""Language/framework profiles — the ONE place framework-specific knowledge lives.

Orion is agnostic by construction: the graph builder and the discovery prompts read a `Profile`
instead of hardcoding any one framework. A profile answers three questions the rest of the builder
must not answer itself:

  - what is an attacker-controlled SOURCE?  (request-object roots, or — generically — the
    parameters of entry-point methods)
  - what does an ENTRY POINT look like?     (a structural fallback works for any language; a
    framework profile can refine it)
  - what SOURCE/SINK/entry vocabulary should the discovery prompts speak?

Two profiles ship today:
  - EXPRESS — formalizes the exact behavior Orion had hardcoded (`req`/`request` field-access
    taint sources), so a JS/Express repo like NodeGoat builds byte-for-byte the same.
  - GENERIC — the language-agnostic fallback: no request-object names, sources come structurally
    from entry-point parameters. This is what makes an UNKNOWN stack work without anyone writing a
    profile for it.

`select_profile(repo)` sniffs the repo (manifest) and returns EXPRESS when it clearly is one, else
GENERIC. Adding Flask/Spring/etc. later is just another `Profile` literal + a detect rule here —
no change anywhere else in the builder.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Profile:
    name: str

    # --- taint sources ---
    # Root identifier names that ARE the attacker-controlled request object (req.body.*, etc.).
    # Empty for GENERIC — a framework-free repo has no such global object.
    request_source_names: frozenset[str] = frozenset()
    # When true, the parameters of detected entry-point methods are treated as taint sources.
    # This is the structural, language-agnostic source model the GENERIC profile relies on.
    entrypoint_params_are_sources: bool = False

    # --- discovery-prompt vocabulary (Phase 5: injected into strategies.py prompts) ---
    # Human-readable examples of where untrusted input enters, shown to the discovery agent.
    source_examples: tuple[str, ...] = ()
    # Category -> example sink call names, to steer shape-A/B without hardcoding them in prompts.
    sink_hints: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # One line describing how request handlers / entry points are wired in this stack.
    entrypoint_hint: str = ""


EXPRESS = Profile(
    name="express",
    request_source_names=frozenset({"req", "request"}),
    source_examples=("req.body.*", "req.query.*", "req.params.*", "req.headers.*", "req.cookies.*"),
    sink_hints={
        "code_exec": ("eval", "Function", "exec", "execSync"),
        "nosql": ("find", "findOne", "$where"),
        "redirect": ("redirect",),
        "render": ("render", "send"),
        "log": ("log",),
    },
    entrypoint_hint="Express route handlers registered via app.get/post/put/delete/use(path, handler).",
)

GENERIC = Profile(
    name="generic",
    request_source_names=frozenset(),
    entrypoint_params_are_sources=True,
    source_examples=(
        "the parameters of EntryPoint methods — query (:EntryPoint)-[:ENTERS_AT]->(:CpgMethod) and "
        "treat that method's parameters as untrusted input",
    ),
    sink_hints={
        "code_exec": ("eval", "exec", "system", "spawn"),
        "sql": ("execute", "query", "raw"),
        "redirect": ("redirect",),
    },
    entrypoint_hint=(
        "No framework assumed: entry points are first-party methods that nothing else in the code "
        "calls (call-graph roots) — request handlers, exported API, main. Their parameters are the "
        "untrusted inputs."
    ),
)


def _package_json_requires(repo: Path, pkg: str) -> bool:
    """True if `pkg` appears in package.json dependencies/devDependencies."""
    pj = repo / "package.json"
    if not pj.exists():
        return False
    try:
        data = json.loads(pj.read_text())
    except (ValueError, OSError):
        return False
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(key)
        if isinstance(deps, dict) and pkg in deps:
            return True
    return False


def select_profile(repo_path: str | Path, language: str | None = None) -> Profile:
    """Pick the best-fitting profile for a repo. EXPRESS when it clearly is a JS/Express app;
    otherwise the language-agnostic GENERIC fallback — never a hard failure on an unknown stack."""
    repo = Path(repo_path)
    if _package_json_requires(repo, "express"):
        return EXPRESS
    return GENERIC
