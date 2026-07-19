"""Dependency manifests -> (name, version) pairs, for the `Dependency` graph nodes.

Closes a data-gap that was empty on every repo before: with dependencies populated, discovery
shape D can reason about outdated/known-vulnerable components (the OWASP A9 class). Language-
agnostic by dispatch on manifest filename — package.json / requirements.txt / pom.xml / go.mod.
Every parser is defensive: a malformed manifest yields [] (a warn, never a crashed build).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree import ElementTree


def _from_package_json(repo: Path) -> list[tuple[str, str]]:
    pj = repo / "package.json"
    if not pj.exists():
        return []
    try:
        data = json.loads(pj.read_text())
    except (ValueError, OSError):
        return []
    out: list[tuple[str, str]] = []
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(key)
        if isinstance(deps, dict):
            out.extend((name, str(ver)) for name, ver in deps.items() if isinstance(name, str))
    return out


_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*([=<>!~]=?[^#;]+)?")


def _from_requirements(repo: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for req in list(repo.glob("requirements*.txt")):
        try:
            lines = req.read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            # Skip blanks, comments, pip options (-e/-r/...), and URL/VCS requirement lines. Match
            # real URL schemes ("http://"/"https://"/"git+"), NOT any package NAMED like "httpx".
            if not line or line.startswith(("#", "-", "git+", "http://", "https://")):
                continue
            m = _REQ_LINE.match(line)
            if m:
                out.append((m.group(1), (m.group(2) or "").strip()))
    return out


def _from_pom(repo: Path) -> list[tuple[str, str]]:
    pom = repo / "pom.xml"
    if not pom.exists():
        return []
    try:
        root = ElementTree.fromstring(pom.read_text())
    except (ElementTree.ParseError, OSError):
        return []
    out: list[tuple[str, str]] = []
    for dep in root.iter():
        if not dep.tag.endswith("dependency"):
            continue
        artifact = version = None
        for child in dep:
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "artifactId":
                artifact = (child.text or "").strip()
            elif tag == "version":
                version = (child.text or "").strip()
        if artifact:
            out.append((artifact, version or ""))
    return out


_GOMOD_REQUIRE = re.compile(r"^\s*([^\s]+)\s+(v[^\s]+)")


def _from_gomod(repo: Path) -> list[tuple[str, str]]:
    gm = repo / "go.mod"
    if not gm.exists():
        return []
    try:
        lines = gm.read_text().splitlines()
    except OSError:
        return []
    out: list[tuple[str, str]] = []
    in_block = False
    for line in lines:
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        target = s[len("require "):] if s.startswith("require ") and not s.endswith("(") else (s if in_block else "")
        m = _GOMOD_REQUIRE.match(target)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def parse_dependencies(repo_path: str | Path) -> list[tuple[str, str]]:
    """All declared dependencies of `repo` as (name, version) pairs, deduped by name (first wins).
    Reads whatever manifests are present; returns [] for a repo with none."""
    repo = Path(repo_path)
    pairs: list[tuple[str, str]] = []
    for parser in (_from_package_json, _from_requirements, _from_pom, _from_gomod):
        pairs.extend(parser(repo))
    seen: set[str] = set()
    deduped: list[tuple[str, str]] = []
    for name, version in pairs:
        if name and name not in seen:
            seen.add(name)
            deduped.append((name, version))
    return deduped
