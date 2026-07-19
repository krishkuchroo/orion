"""Profile selection + shape — the seam that makes Orion framework-agnostic. Token-free, no Joern.

A repo that clearly is Express gets the EXPRESS profile (so its request-object taint fires exactly
as before); anything else falls back to GENERIC (structural, framework-free) rather than failing.
"""
from __future__ import annotations

import json

from orion.graph import profiles
from orion.graph.profiles import EXPRESS, GENERIC, select_profile


def test_express_repo_selects_express():
    assert select_profile("fixtures/NodeGoat") is EXPRESS


def test_no_manifest_falls_back_to_generic(tmp_path):
    (tmp_path / "main.py").write_text("def handler(request):\n    return request\n")
    assert select_profile(tmp_path) is GENERIC


def test_non_express_manifest_is_generic(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"koa": "^2.0.0"}}))
    assert select_profile(tmp_path) is GENERIC


def test_express_profile_carries_request_sources():
    # EXPRESS formalizes exactly what was hardcoded before — the source-name set is unchanged.
    assert EXPRESS.request_source_names == frozenset({"req", "request"})
    assert not EXPRESS.entrypoint_params_are_sources


def test_generic_profile_is_structural_not_name_based():
    # GENERIC has NO request-object names — an unknown stack has no such global. Its sources come
    # structurally from entry-point parameters instead.
    assert GENERIC.request_source_names == frozenset()
    assert GENERIC.entrypoint_params_are_sources is True


def test_malformed_package_json_does_not_crash(tmp_path):
    (tmp_path / "package.json").write_text("{ this is not json ]")
    assert select_profile(tmp_path) is GENERIC


def test_prompt_is_agnostic_without_a_profile():
    """The base discovery prompt must be framework-free: anchored on :EntryPoint (populated for any
    language), valid with no profile at all."""
    from orion import strategies
    base = strategies.system_for("A", "scan123")
    assert "scan123" in base
    assert "EntryPoint" in base            # generic source anchor, not a framework literal


def test_prompt_injects_profile_vocabulary():
    from orion import strategies
    express = strategies.system_for("A", "scan123", profile=EXPRESS)
    assert "req.body.*" in express and "express" in express.lower()
    generic = strategies.system_for("A", "scan123", profile=GENERIC)
    assert "EntryPoint" in generic and "parameters" in generic.lower()
