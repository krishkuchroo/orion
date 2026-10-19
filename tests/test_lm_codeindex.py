from orion.lm import codeindex as ci


def _idx(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)
    return ci.RepoIndex(str(tmp_path))


def test_spans_and_calls_in_all_four_languages(tmp_path):
    """Function spans and callee names come out right for JS, TS (arrow const), Python, Java."""
    idx = _idx(tmp_path, {
        "a.js": "function run(x){\n  exec(x)\n  helper(x)\n}\nfunction helper(y){ return y }\n",
        "b.py": "def view(req):\n    q = build(req)\n    return db.execute(q)\n\ndef build(r):\n    return r\n",
        "C.java": "class C {\n  void h(String s) {\n    run(s);\n  }\n  void run(String s) { }\n}\n",
        "t.ts": "export const go = (u: string) => {\n  fetch(u)\n}\n"})
    run = idx.enclosing("a.js", 2)
    assert (run.name, run.start, run.end) == ("run", 1, 4) and run.calls[:2] == ("exec", "helper")
    assert "execute" in idx.enclosing("b.py", 3).calls
    assert idx.enclosing("C.java", 3).name == "h"
    assert idx.enclosing("t.ts", 2).name == "go"


def test_callers_callees_deterministic_same_file_first(tmp_path):
    """Name collisions resolve same-file first; callers found across files (Review Focus 3)."""
    idx = _idx(tmp_path, {"a.js": "function run(x){ helper(x) }\nfunction helper(y){ return y }\n",
                          "z/b.js": "function helper(y){ return 0 }\nfunction other(){ run(1) }\n"})
    run = idx.enclosing("a.js", 1)
    assert [(s.file, s.name) for s in idx.callees(run, 2)] == [("a.js", "helper")]
    assert [(s.file, s.name) for s in idx.callers(run, 2)] == [("z/b.js", "other")]


def test_bad_minified_huge_test_and_vendored_files_never_crash(tmp_path):
    """Review Focus 1: skipped with a reason; node_modules never walked; index still builds."""
    idx = _idx(tmp_path, {"ok.py": "def f():\n    return 1\n", "bad.py": "def (:\n",
                          "x.min.js": "function a(){}", "node_modules/m/i.js": "function b(){}",
                          "tests/test_ok.py": "def test_f():\n    pass\n",
                          "big.js": "//" + "x" * (ci.MAX_FILE_BYTES + 1)})
    assert "ok.py" in idx.files and "node_modules/m/i.js" not in idx.files
    assert {"x.min.js", "tests/test_ok.py", "big.js"} <= set(idx.skipped)


def test_module_level_line_gets_module_window(tmp_path):
    """Review Focus 5: a top-level sink still has a target span."""
    idx = _idx(tmp_path, {"s.py": "import os\nos.system(input())\n"})
    sp = idx.enclosing("s.py", 2)
    assert sp.name == "<module>" and sp.start <= 2 <= sp.end


def test_member_calls_nested_functions_and_update(tmp_path):
    """Member call -> last identifier; nested functions are own spans; update re-parses."""
    idx = _idx(tmp_path, {"n.js": "function outer(){\n  function inner(){ deep() }\n  obj.a.b()\n}\n"
                                  "obj.f = function(){ x() }\n"})
    assert idx.enclosing("n.js", 2).name == "inner"
    outer = idx.enclosing("n.js", 3)
    assert outer.name == "outer" and outer.calls == ("b",)
    assert idx.enclosing("n.js", 5).name == "f"
    assert ci.parse_text("README.md", "x") is None
    idx.update("n.js", "function only(){ z() }\n")
    assert [s.name for s in idx.files["n.js"]] == ["only"]
    assert idx.source("n.js", 1, 1) == "function only(){ z() }"
