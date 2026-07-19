"""Manifest -> (name, version) parsing for Dependency nodes. Token-free, no Joern, no DB.

Covers each supported manifest and the defensive contract: a malformed manifest yields [] rather
than crashing the build.
"""
from __future__ import annotations

import json

from orion.graph.deps import parse_dependencies


def test_package_json(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"express": "^4.13.4", "marked": "0.3.5"},
        "devDependencies": {"mocha": "^3.0.0"},
    }))
    deps = dict(parse_dependencies(tmp_path))
    assert deps["express"] == "^4.13.4"
    assert deps["marked"] == "0.3.5"
    assert deps["mocha"] == "^3.0.0"


def test_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "Flask==2.0.1\nrequests>=2.20\n# a comment\n-e .\nDjango~=4.1\n"
    )
    deps = dict(parse_dependencies(tmp_path))
    assert deps["Flask"] == "==2.0.1"
    assert deps["requests"] == ">=2.20"
    assert deps["Django"] == "~=4.1"
    assert "#" not in " ".join(deps)  # the comment line produced no phantom dep


def test_pom_xml(tmp_path):
    (tmp_path / "pom.xml").write_text(
        """<project><dependencies>
             <dependency><groupId>org.springframework</groupId>
               <artifactId>spring-core</artifactId><version>5.3.0</version></dependency>
             <dependency><groupId>com.google</groupId>
               <artifactId>guava</artifactId><version>30.0</version></dependency>
           </dependencies></project>"""
    )
    deps = dict(parse_dependencies(tmp_path))
    assert deps["spring-core"] == "5.3.0"
    assert deps["guava"] == "30.0"


def test_requirements_keeps_packages_named_like_http(tmp_path):
    """The URL-line skip must match real schemes, not any package NAMED 'http...' (httpx/httplib2)."""
    (tmp_path / "requirements.txt").write_text(
        "httpx==0.27\nhttplib2==0.22\nrequests==2.31\nhttps://ex.com/pkg.whl\n"
    )
    deps = dict(parse_dependencies(tmp_path))
    assert deps["httpx"] == "==0.27"
    assert deps["httplib2"] == "==0.22"
    assert deps["requests"] == "==2.31"


def test_go_mod(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\ngo 1.21\n\nrequire (\n"
        "\tgithub.com/gin-gonic/gin v1.9.1\n\tgithub.com/pkg/errors v0.9.1\n)\n"
    )
    deps = dict(parse_dependencies(tmp_path))
    assert deps["github.com/gin-gonic/gin"] == "v1.9.1"
    assert deps["github.com/pkg/errors"] == "v0.9.1"


def test_malformed_manifest_yields_empty_not_crash(tmp_path):
    (tmp_path / "package.json").write_text("{ not valid json ]")
    assert parse_dependencies(tmp_path) == []


def test_nodegoat_dependencies_are_populated():
    deps = dict(parse_dependencies("fixtures/NodeGoat"))
    assert "express" in deps          # the A9 data-gap is now closed for a real repo
    assert len(deps) > 5
