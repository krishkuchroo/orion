"""orion.lm.sinks.annotate: a code-only case gets ONE sink node from Orion's own sink rules
(pathfind._classify_sink over the target snippet's lines), so training rows and runtime code-only cases
carry the same kind of sink line a graph flow does."""
import copy
import inspect

import pytest

from orion.graph import profiles
from orion.lm import sinks


def _case(code: str, *, start: int = 10, file: str = "a.js", function: str = "f", extra_snippets=()) -> dict:
    return {"flow_id": "F0", "rank": 0, "sink_category": None, "source_uid": None, "sink_uid": None,
            "nodes": [],
            "snippets": [{"role": "target", "file": file, "function": function, "start": start,
                          "end": start + code.count("\n"), "code": code}, *extra_snippets]}


# (language, file, code, expected category, offset of the sink line within the snippet)
EXAMPLES = [
    # code_exec
    ("js", "a.js", "function f(x){\n  eval(x)\n}", "code_exec", 1),
    ("py", "a.py", "def f(cmd):\n    os.system(cmd)", "code_exec", 1),
    ("java", "A.java", "void f(String c) {\n  Runtime.getRuntime().exec(c);\n}", "code_exec", 1),
    # sql
    ("py", "a.py", "def f(q):\n    return User.objects.raw(q)", "sql", 1),
    ("java", "A.java", "void f(String q) {\n  jdbcTemplate.query(q, mapper);\n}", "sql", 1),
    ("js", "a.js", "function f(q){\n  db.query(q)\n}", "sql", 1),
    # path
    ("js", "a.js", "function f(p){\n  fs.readFile(p, cb)\n}", "path", 1),
    ("py", "a.py", "def f(p):\n    return os.path.join(base, p)", "path", 1),
    ("java", "A.java", "void f(String p) {\n  new FileInputStream(p);\n}", "path", 1),
    # template
    ("py", "a.py", "def f(t):\n    return render_template_string(t)", "template", 1),
    ("js", "a.js", "function f(t){\n  return ejs.render(t)\n}", "template", 1),
    ("java", "A.java", "void f(String t) {\n  new Template(\"x\", new StringReader(t), cfg);\n}", "template", 1),
    # deserialize
    ("py", "a.py", "def f(b):\n    return pickle.loads(b)", "deserialize", 1),
    ("java", "A.java", "Object f(InputStream s) {\n  return new ObjectInputStream(s).readObject();\n}",
     "deserialize", 1),
    ("js", "a.js", "function f(s){\n  return unserialize(s)\n}", "deserialize", 1),
    # xxe
    ("java", "A.java", "void f(InputStream s) {\n  DocumentBuilderFactory.newInstance();\n}", "xxe", 1),
    ("py", "a.py", "def f(s):\n    return etree.fromstring(s)", "xxe", 1),
    ("js", "a.js", "function f(s){\n  return libxmljs.parseXmlString(s)\n}", "xxe", 1),
    # ssrf
    ("py", "a.py", "def f(u):\n    return requests.get(u)", "ssrf", 1),
    ("js", "a.js", "function f(u){\n  return axios(u)\n}", "ssrf", 1),
    ("java", "A.java", "void f(URL u) {\n  u.openConnection();\n}", "ssrf", 1),
    # prototype_pollution
    ("js", "a.js", "function f(o){\n  _.defaultsDeep(target, o)\n}", "prototype_pollution", 1),
    # redirect
    ("js", "a.js", "function f(u){\n  res.redirect(u)\n}", "redirect", 1),
    ("py", "a.py", "def f(u):\n    return redirect(u)", "redirect", 1),
    ("java", "A.java", "void f(String u) {\n  response.sendRedirect(u);\n}", "redirect", 1),
]


@pytest.mark.parametrize("lang,file,code,category,offset", EXAMPLES, ids=[f"{e[0]}-{e[3]}" for e in EXAMPLES])
def test_category_per_language(lang, file, code, category, offset):
    out = sinks.annotate(_case(code, start=10, file=file, function="f"))
    assert out["sink_category"] == category
    line = code.split("\n")[offset]
    assert out["nodes"] == [{"role": "sink", "file": file, "line": 10 + offset, "function": "f",
                             "code": line.strip()}]
    assert out["source_uid"] is None and out["sink_uid"] is None


def test_highest_severity_wins_over_an_earlier_line():
    code = "function f(x){\n  res.redirect(x)\n  fs.readFile(x)\n  db.query(x)\n  eval(x)\n}"
    out = sinks.annotate(_case(code, start=1))
    assert out["sink_category"] == "code_exec" and out["nodes"][0]["line"] == 5


def test_ties_go_to_the_first_line():
    code = "def f(a, b):\n    db.query(a)\n    requests.get(b)\n    db.query(b)"
    out = sinks.annotate(_case(code, start=20, file="a.py"))
    assert out["sink_category"] == "sql" and out["nodes"][0]["line"] == 21


def test_line_is_absolute_snippet_start_plus_offset():
    code = "\n".join(["  x()"] * 7 + ["  eval(y)"])
    out = sinks.annotate(_case(code, start=181))
    assert out["nodes"][0]["line"] == 188


def test_no_sink_returns_the_case_unchanged():
    case = _case("function f(a, b){\n  return a + b\n}")
    out = sinks.annotate(case)
    assert out == case and out["sink_category"] is None and out["nodes"] == []


def test_graph_flow_is_untouched():
    case = _case("function f(x){\n  eval(x)\n}")
    case.update(sink_category=None, source_uid="s", sink_uid="k",
                nodes=[{"file": "a.js", "line": 1, "function": "g", "code": "f(req.q)"},
                       {"file": "a.js", "line": 11, "function": "f", "code": "eval(x)"}])
    snapshot = copy.deepcopy(case)
    assert sinks.annotate(case) == snapshot


def test_existing_sink_category_is_kept():
    case = _case("function f(x){\n  eval(x)\n}")
    case["sink_category"] = "sql"
    assert sinks.annotate(case) == case


def test_idempotent():
    once = sinks.annotate(_case("def f(b):\n    return pickle.loads(b)", file="a.py"))
    assert sinks.annotate(once) == once


def test_pure_returns_a_new_dict_and_never_mutates_input():
    case = _case("function f(x){\n  eval(x)\n}")
    snapshot = copy.deepcopy(case)
    out = sinks.annotate(case)
    assert case == snapshot and out is not case and out["nodes"]
    none = _case("function f(){}")
    assert sinks.annotate(none) is not none


def test_only_the_target_snippet_is_scanned():
    caller = {"role": "caller", "file": "a.js", "function": "g", "start": 1, "end": 1, "code": "eval(x)"}
    out = sinks.annotate(_case("function f(a){\n  return a\n}", extra_snippets=(caller,)))
    assert out["sink_category"] is None and out["nodes"] == []


def test_case_without_snippets_is_unchanged():
    case = {"flow_id": "F0", "rank": 0, "sink_category": None, "source_uid": None, "sink_uid": None,
            "nodes": [], "snippets": []}
    assert sinks.annotate(case) == case


def test_label_lead_and_fix_are_never_consulted():
    """Same code -> same answer whatever label/lead/fix fields ride along (vulnerable, patched and
    negative rows go through one rule)."""
    code = "def f(q):\n    db.query(q)"
    base = sinks.annotate(_case(code, file="a.py"))
    for extra in ({"label": "vulnerable"}, {"label": "patched"}, {"label": "negative"},
                  {"lead": {"file": "a.py", "line": 99, "function": "zzz"}}, {"fix_line": 10}):
        case = {**_case(code, file="a.py"), **extra}
        out = sinks.annotate(case)
        assert (out["sink_category"], out["nodes"]) == (base["sink_category"], base["nodes"])
    assert list(inspect.signature(sinks.annotate).parameters) == ["case", "profile"]


def test_sql_execute_is_code_exec_because_exec_is_a_substring():
    """Orion's rule as it is: 'execute' contains the code_exec hint 'exec' (severity 5 > sql's 4)."""
    out = sinks.annotate(_case("def f(q):\n    cur.execute(q)", file="a.py"))
    assert out["sink_category"] == "code_exec"


def test_default_profile_is_generic_plus_lm_sinks():
    assert sinks.default_profile() == profiles.with_lm_sinks(profiles.GENERIC)


def test_explicit_profile_is_used():
    code = "const f = (x) => {\n  res.send(x)\n}"      # no 'function' keyword: EXPRESS's 'Function' hint
    assert sinks.annotate(_case(code))["sink_category"] is None             # GENERIC+lm has no 'send'
    out = sinks.annotate(_case(code), profiles.with_lm_sinks(profiles.EXPRESS))
    assert out["sink_category"] == "render" and out["nodes"][0]["line"] == 11
