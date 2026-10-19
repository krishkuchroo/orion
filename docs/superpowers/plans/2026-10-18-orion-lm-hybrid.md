# Orion-LM Hybrid Training Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Train the Orion-LM judge mostly on code. Stage 1 uses all real pairs as code plus context, with no Joern. Stage 2 adds a small set of real-graph examples. At test time Orion's graph picks candidate flows, and the model judges each one with its code context.

**Architecture:** One case builder, `orion/lm/cases.py` (backed by a tree-sitter code index, `orion/lm/codeindex.py`), turns either a graph CandidateFlow (runtime and Stage 2) or a changed function from git (Stage 1) into the same **CodeCase**. That case is rendered by the existing single formatter (`orion/lm/format.py`). Runtime and training therefore show the model identical inputs. Stage 1 fetches partial git snapshots, one pair at a time. Stage 2 reuses D2/D3 builds on a small, language-stratified subset of dataflow pairs. The test-time pipeline is unchanged except that each candidate flow is judged on its own, as an enriched CodeCase (K=1).

**Tech Stack:** Python 3.13 (`.venv`), tree-sitter with the official JavaScript, TypeScript, Python and Java grammars (new, pinned in the `lm` extra), git partial clone and sparse checkout, existing MLX-LM/Outlines runtime, Unsloth on a cloud GPU (training only), `mlx_lm convert`.

**Spec:** `docs/superpowers/specs/2026-10-18-orion-lm-design.md`, plus the design change below. This plan supersedes Tasks C2 and D4–D6 of `docs/superpowers/plans/2026-10-18-orion-lm.md`. It keeps D1 (done) and D2/D3 (Stage 2 and E5 path ground truth).

## Design change (Krish, 2026-10-18): hybrid training

The original design trained the model only on graph traces. That needed about 8,100 Joern builds, which is too big. Approved instead:
- **Stage 1 (big, cheap):** all ~4,058 mined pairs, as code plus context. The vulnerable function gets a lead, the fixed function gets no lead, and random unchanged functions are negatives.
- **Stage 2 (small):** a few hundred dataflow pairs built with real Orion graphs, so the model sees the exact test-time input. A few graph queries come from Krish's templates once those exist.
- **Test:** unchanged. Orion builds graphs for the test repos only, and the model judges the candidate flows.

What this costs:
- "The model explores the graph" is weakened to "the model may query", and Stage 1 examples are single-step.
- Positioning moves toward LLMxCPG (graph slice → judge). VulAgentRL (2607.26656) is the main related work to cite.

| Original task | Status under this plan |
|---|---|
| D1 pair mining | done (`2efa200`, `d20173a`) |
| D2 dual-commit builds, D3 fixmap | done on `train/d2-d3` (`91c3a7e`, `8594969`, `0fcc7e9`); used by H6/H8 and E5 |
| D4 gold traces | replaced by H8 (Stage 2 cases/traces) + H11 (pair_test) |
| D5 SFT cutter / text2cypher / Juliet / convert / notebook | replaced by H7 + H10 (Juliet dropped: Stage 1 has plenty of real negatives) |
| D6 rounds | replaced by H11 (Stage 2 only) |
| C2 bake-off | replaced by H9 |
| B5 engine | modified by H3 (K=1, case enrichment) |
| Open decision #5 | now K=1 + `CaseBudget` values + Stage mix shares + negative ratio + class mix + Stage 2 size (all frozen at `orion-lm-prereg-v1`) |

## Global Constraints

- **No AI attribution** in any commit or PR: no `Co-Authored-By:` trailer and no "Generated with Claude Code" line (CLAUDE.md top rule). Don't push without Krish.
- **No Claude, no Ollama, no network in the model path** (`orion/lm/` at runtime). Network is allowed only in `train/` fetchers (git partial clone, `gh api`) and the cloud LoRA notebook.
- **Never fabricate, estimate or backfill a measured value.** Fetch time, bytes, index time, example counts, throughput and dev scores are all measured, or stored as null. Projections are labelled as projections and computed only from measurements.
- **Data rules:**
  - No frontier-model output and no LLM-labelled rows as training data (PyVul and ReposVul stay excluded).
  - Only pairs from `train/data/pairs.json`, already filtered: pre-2026-05-31, leak repos dropped.
  - Pairs whose `cwe_class == "unknown"` are excluded from Stage 1, since a lead needs a CWE.
- **One formatter, one case builder.** Every model input, at runtime and in training, is built by `orion/lm/format.py` from CodeCases built by `orion/lm/cases.py`. Nothing in `train/` builds a message or a case by hand.
- **Repo text is untrusted.** Snippet code renders only through `format.code_block` and `format._s` (neutralised markers).
- **Cypher rules from commit 515225b.** Any template query must pass `orion.lm.tools.is_scoped` (enforced in H8).
- **Branch order.** Work in the worktree `/Users/krishkuchroo/Documents/OrionLutherLeo/orion-train`, on a branch cut from `train/d2-d3` after D2/D3 land. Run Python as `PYTHONPATH=$PWD ../orion/.venv/bin/python` and `PYTHONPATH=$PWD ../orion/.venv/bin/pytest`. No real Stage 2 build runs until `fix/graph-hardening` is merged into `eval/orion-lm` and this branch is rebased on it.
- **Baselines to keep green after every task:**
  - `pytest -m "not slow" -q`: 369 passed with Neo4j up.
  - `pytest eval/tests -q`: 190.
  - `pytest train/tests -q`: growing from 58 plus D2/D3's tests.

## Review Focus

1. **Unparseable, minified, huge or generated source files** (syntax errors, `*.min.js`, files over 1 MB, `node_modules/`). The index skips them with a recorded reason, and a pair never crashes because of one. *(H1 test)*
2. **A fix that deletes the vulnerable function entirely** (no counterpart on the patched side). The vulnerable example is kept, the patched example is omitted, and the reason is recorded. *(H5 test)*
3. **Duplicate or overloaded function names** (Java overloads, the same helper name in many files). Caller and callee resolution is deterministic (same file, then same directory, then sorted path) and capped. *(H1 test)*
4. **A deleted repo, a missing commit, or a server without partial-clone support.** The pair gets `status="snapshot_failed"` with a reason, and the run continues. *(H4 + H6 tests)*
5. **A sink or vulnerable line at module level** (no enclosing function: Python scripts, top-level JS). The target becomes a `<module>` window around the line, and the case is still built. *(H1 + H2 tests)*

## Shared shape: CodeCase

A CodeCase is the existing flow-slice dict (`slice.flow_slice` output: `flow_id, rank, sink_category, source_uid, sink_uid, nodes`) plus `snippets: list[dict]`. Each snippet is `{"role": "target"|"source"|"caller"|"callee", "file", "function", "start", "end", "code"}`, with the target first. Stage 1 cases use `flow_id="F0"`, `rank=0`, `sink_category=None`, `source_uid=None`, `sink_uid=None`, `nodes=[]`. A lead's `flow_id` is the case's `flow_id`, so `engine._map_batch` is unchanged.

---

### Task H1: Tree-sitter code index (+ record the design change)

**Files:**
- Create: `orion/lm/codeindex.py`
- Modify: `pyproject.toml` (`lm` extra gains the pinned tree-sitter packages)
- Modify (docs):
  - `docs/superpowers/specs/2026-10-18-orion-lm-design.md`: dated "Design change: hybrid" addendum under §5.2, with the text of this plan's Design change section.
  - `docs/superpowers/plans/2026-10-18-orion-lm.md`: header note pointing to this plan.
  - `CLAUDE.md`: Orion-LM status line.
- Test: `tests/test_lm_codeindex.py`

**Interfaces:**
- Produces:
  - `codeindex.Span`: frozen dataclass `(file: str, name: str, start: int, end: int, calls: tuple[str, ...])`. `file` is repo-relative with `/` separators. Lines are 1-based and inclusive. `calls` holds bare callee names in body order, deduplicated. `name == "<module>"` marks a module window.
  - `codeindex.LANG_BY_EXT = {".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "tsx", ".py": "python", ".java": "java"}`
  - Constants: `MAX_FILE_BYTES = 1_000_000`, `MODULE_WINDOW = 20`, `SKIP_DIRS = ("node_modules", "vendor", "dist", "build", "target", ".git", "__pycache__", "venv", ".venv")`
  - `codeindex.parse_text(rel: str, text: str) -> list[Span] | None`: `None` means unsupported extension or no parser.
  - `codeindex.RepoIndex(root: str)`:
    - Walks `root` (never descending into `SKIP_DIRS`) and parses supported files.
    - Skips `*.min.js`, files over `MAX_FILE_BYTES`, and test files (`eval.dataset.enrich._is_test`). Each skip is recorded in `.skipped: dict[rel, reason]`; parsed spans go in `.files: dict[rel, list[Span]]`.
    - `.enclosing(file, line) -> Span | None`: the innermost span containing the line. For a supported, indexed file where the line is in no function, it returns a `<module>` Span of `line ± MODULE_WINDOW`, clipped to the file.
    - `.callers(span, limit) -> list[Span]`, `.callees(span, limit) -> list[Span]`: resolution order is same file, then same directory, then the rest by `(file, start)`; the span itself is excluded; one definition per callee name.
    - `.update(rel, text) -> None`: re-parses one file.
    - `.source(file, start, end) -> str`
- What counts as a function (any language): function and method declarations, plus arrow or function expressions bound to a name (`const f = () => …`, `obj.f = function …`). Nested functions are their own spans.

- [ ] **Step 1: Install and pin.** `../orion/.venv/bin/pip install tree-sitter tree-sitter-javascript tree-sitter-typescript tree-sitter-python tree-sitter-java`. Pin the resolved versions in the `lm` extra, with a dated comment like the existing one.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_lm_codeindex.py
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
```

- [ ] **Step 3: Run it and confirm it fails.** `PYTHONPATH=$PWD ../orion/.venv/bin/pytest tests/test_lm_codeindex.py -v` should fail with `ModuleNotFoundError: orion.lm.codeindex`.
- [ ] **Step 4: Implement `codeindex.py`.** Grammars are loaded lazily inside `parse_text`, so `import orion.lm` stays light. Callee names come from call-expression nodes: for a member call, the last identifier (`obj.a.b()` → `b`).
- [ ] **Step 5: Run it and confirm it passes**, plus `pytest -m "not slow" -q` stays at 0 failures.
- [ ] **Step 6: Write the three doc edits** (spec addendum, plan header note, CLAUDE.md status line).
- [ ] **Step 7: Commit:** `git add orion/lm/codeindex.py tests/test_lm_codeindex.py pyproject.toml docs/superpowers/specs/2026-10-18-orion-lm-design.md docs/superpowers/plans/2026-10-18-orion-lm.md CLAUDE.md && git commit -m "orion/lm: tree-sitter code index (spans, calls, callers/callees, module windows); record hybrid design change"`

---

### Task H2: CodeCase builder + formatter renders snippets

**Files:**
- Create: `orion/lm/cases.py`
- Modify: `orion/lm/format.py` (`_render_flow` renders `snippets` when present; `task_message` text says "candidate", not "flow")
- Test: `tests/test_lm_cases.py`; update `tests/test_lm_format.py` only where the task text changed

**Interfaces:**
- Consumes: `codeindex.RepoIndex`, `Span` (H1); the flow-slice dict (`slice.flow_slice`).
- Produces:
  - `cases.CaseBudget`: frozen dataclass `(max_target_lines: int = 120, max_context_lines: int = 40, max_callers: int = 2, max_callees: int = 2)`. The values are frozen at prereg.
  - `cases.case_from_flow(flow: dict, index: RepoIndex, *, budget: CaseBudget = CaseBudget()) -> dict` returns the flow dict plus `snippets`:
    - target = `index.enclosing` of the LAST node (the sink), anchored on the sink line;
    - `source` snippet = enclosing span of the FIRST node, if it's a different span;
    - then callers and callees of the target, without duplicates.
    - If there's no sink node, or the file isn't indexed, `snippets == []` and the case is still returned.
  - `cases.case_from_function(index, file: str, span: Span, *, anchor: int, case_id: str = "F0", budget: CaseBudget = CaseBudget()) -> dict`: the Stage 1 case (shape in "Shared shape" above).
  - Truncation (one helper used everywhere):
    - A snippet longer than its budget becomes a window of `max` lines containing the anchor, centred where possible.
    - The anchor is the sink or vulnerable line for targets, the first line naming the target for callers, and the span start for callees.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_lm_cases.py
from orion.lm import cases, codeindex as ci, format as fmt

def test_case_from_flow_target_is_sink_function_with_source_and_path(tmp_path):
    """The model sees the sink's whole function, the source's function, and the path nodes."""
    (tmp_path / "a.js").write_text("function run(x){\n  const y = x\n  exec(y)\n}\nfunction caller(){ run(req.q) }\n")
    idx = ci.RepoIndex(str(tmp_path))
    flow = {"flow_id": "F0", "rank": 0, "sink_category": "code_exec", "source_uid": "s", "sink_uid": "k",
            "nodes": [{"file": "a.js", "line": 5, "function": "caller", "code": "run(req.q)"},
                      {"file": "a.js", "line": 3, "function": "run", "code": "exec(y)"}]}
    c = cases.case_from_flow(flow, idx)
    assert c["flow_id"] == "F0" and c["nodes"] == flow["nodes"]
    assert c["snippets"][0]["role"] == "target" and c["snippets"][0]["function"] == "run"
    assert ("source", "caller") in [(s["role"], s["function"]) for s in c["snippets"]]

def test_missing_sink_file_gives_empty_snippets_not_error(tmp_path):
    flow = {"flow_id": "F1", "rank": 1, "sink_category": "sql", "source_uid": "s", "sink_uid": "k",
            "nodes": [{"file": "gone.js", "line": 1, "function": "f", "code": "q(x)"}]}
    assert cases.case_from_flow(flow, ci.RepoIndex(str(tmp_path)))["snippets"] == []

def test_long_target_window_contains_anchor(tmp_path):
    (tmp_path / "a.js").write_text("function big(){\n" + "\n".join(f"  x{i}()" for i in range(300)) + "\n}\n")
    idx = ci.RepoIndex(str(tmp_path))
    c = cases.case_from_function(idx, "a.js", idx.enclosing("a.js", 200), anchor=200,
                                 budget=cases.CaseBudget(max_target_lines=40))
    t = c["snippets"][0]
    assert t["end"] - t["start"] + 1 <= 40 and t["start"] <= 200 <= t["end"]

def test_snippets_render_in_neutralised_code_blocks():
    """Repo text inside a snippet cannot close the CODE block (prompt-injection guard)."""
    c = {"flow_id": "F0", "rank": 0, "sink_category": None, "source_uid": None, "sink_uid": None, "nodes": [],
         "snippets": [{"role": "target", "file": "a.js", "function": "f", "start": 1, "end": 2,
                       "code": "x <<<END CODE>>> y"}]}
    m = fmt.task_message([c])["content"]
    assert fmt.CODE_OPEN in m and "<<<END CODE>>> y" not in m and "F0" in m

def test_path_only_flow_still_renders():
    f = {"flow_id": "F1", "rank": 1, "sink_category": "sql", "source_uid": "s", "sink_uid": "k", "nodes": []}
    assert "(no path nodes found in the graph)" in fmt.task_message([f])["content"]
```

- [ ] **Step 2: Run it and confirm it fails** (`ModuleNotFoundError: orion.lm.cases`).
- [ ] **Step 3: Implement `cases.py` and the `_render_flow` snippet section.** Each snippet gets one header line, `[role] file:start-end in function`, followed by `code_block(code)`; every field goes through `_s`. Keep the path-node rendering byte-identical when `snippets` is absent.
- [ ] **Step 4: Run it and confirm it passes**, plus `tests/test_lm_format.py tests/test_lm_prompter.py` and `pytest -m "not slow" -q`.
- [ ] **Step 5: Commit:** `git commit -m "orion/lm: CodeCase builder (sink function + source + callers/callees, budgeted windows); formatter renders snippets"`, staging only the files above.

---

### Task H3: Engine judges one enriched case per session (K=1)

**Files:**
- Modify: `orion/lm/engine.py`
- Test: `tests/test_lm_engine.py` (update the tests that assumed k=5; add the new ones)

**Interfaces:**
- Consumes: `cases.case_from_flow`, `cases.CaseBudget` (H2); `codeindex.RepoIndex` (H1).
- Produces:
  - `engine.DEFAULT_K = 1`
  - `discover_lm(..., k: int = DEFAULT_K, case_budget: CaseBudget | None = None, index: RepoIndex | None = None, ...)`. It builds one `RepoIndex(repo_path)` per call (unless `index` is given) and emits a `discover`/`tool` event: `"index: <files> files, <skipped> skipped, <s>s"`. Every flow passes through `case_from_flow` before batching.
  - If enrichment fails on one flow, that flow is judged as a path-only case and a `warn` event fires; it is never dropped.
  - CLI and F3 need no change; they inherit the default.

- [ ] **Step 1: Write the failing test**

```python
def test_each_flow_enriched_and_judged_alone(monkeypatch, tmp_path):
    """K=1: one session per flow; the sink's function is in the case; a flow with no code is still judged."""
    (tmp_path / "a.js").write_text("function run(x){\n  exec(x)\n}\n")
    flows = [{**FLOWS[0], "nodes": [{"file": "a.js", "function": "run", "line": 2, "code": "exec(x)"}]}, FLOWS[1]]
    seen = []
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: flows)
    monkeypatch.setattr(engine, "_session", lambda gen, db, repo, sid, batch, **k: seen.append(batch) or ([], []))
    engine.discover_lm("s", str(tmp_path), lambda e: None, model=object(), db=object())
    assert [len(b) for b in seen] == [1, 1]
    assert seen[0][0]["snippets"][0]["function"] == "run" and seen[1][0]["snippets"] == []
```

- [ ] **Step 2: Run it and confirm it fails** (batch sizes `[2]`, no `snippets` key).
- [ ] **Step 3: Implement.** Update the existing engine tests whose expectations depended on k=5, deliberately, and say so in the commit message.
- [ ] **Step 4: Run** `tests/test_lm_engine.py tests/test_cli_engine.py` and `pytest -m "not slow" -q`, all green.
- [ ] **Step 5: Commit:** `git commit -m "orion/lm: engine judges one enriched CodeCase per session (K=1); index built once per scan"`

---

### Task H4: Partial git snapshots

**Files:**
- Create: `train/snapshot.py`
- Test: `train/tests/test_snapshot.py`

**Interfaces:**
- Produces:
  - `snapshot.LANG_GLOBS = {"js": ["*.js", "*.mjs", "*.cjs", "*.jsx", "*.ts", "*.tsx"], "py": ["*.py"], "java": ["*.java"]}`
  - `snapshot.fetch(repo_url: str, sha: str, dest: str, *, globs: list[str], run=None) -> dict` returns `{"ok": bool, "seconds": float, "bytes": int | None, "error": str | None}`. It runs:
    1. `git clone --filter=blob:none --no-checkout --quiet <url> <dest>`
    2. `git -C <dest> sparse-checkout set --no-cone <globs…>`
    3. `git -C <dest> checkout --quiet <sha>`

    `bytes` is the size of `dest` on disk afterwards. It never raises: a failure returns `ok=False` with the head of stderr.
  - `snapshot.show(dest: str, sha: str, path: str, *, run=None) -> str | None`: `git show <sha>:<path>`, or `None` if the path doesn't exist at that commit.

- [ ] **Step 1: Write the failing test** (real git; `file://` with filters enabled)

```python
# train/tests/test_snapshot.py
import subprocess
from train import snapshot

def _git(*a): return subprocess.run(["git", *a], check=True, capture_output=True, text=True).stdout.strip()

def _repo(tmp_path):
    src = tmp_path / "src"; src.mkdir(); _git("init", "-q", str(src))
    _git("-C", str(src), "config", "uploadpack.allowFilter", "true")
    _git("-C", str(src), "config", "uploadpack.allowAnySHA1InWant", "true")
    (src / "a.py").write_text("v1\n"); (src / "blob.bin").write_bytes(b"\0" * 1000); (src / "README.md").write_text("r")
    _git("-C", str(src), "add", "."); _git("-C", str(src), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c1")
    c1 = _git("-C", str(src), "rev-parse", "HEAD")
    (src / "a.py").write_text("v2\n")
    _git("-C", str(src), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "c2")
    return src, c1, _git("-C", str(src), "rev-parse", "HEAD")

def test_fetch_checks_out_only_language_files_at_sha(tmp_path):
    """Only *.py is materialised, at the requested (older) commit."""
    src, c1, c2 = _repo(tmp_path)
    out = snapshot.fetch(f"file://{src}", c1, str(tmp_path / "snap"), globs=["*.py"])
    assert out["ok"] and (tmp_path / "snap" / "a.py").read_text() == "v1\n"
    assert not (tmp_path / "snap" / "blob.bin").exists() and not (tmp_path / "snap" / "README.md").exists()
    assert snapshot.show(str(tmp_path / "snap"), c2, "a.py") == "v2\n"
    assert snapshot.show(str(tmp_path / "snap"), c2, "nope.py") is None

def test_missing_sha_or_repo_is_reported_not_raised(tmp_path):
    """Review Focus 4."""
    src, _, _ = _repo(tmp_path)
    assert snapshot.fetch(f"file://{src}", "0" * 40, str(tmp_path / "s1"), globs=["*.py"])["ok"] is False
    assert snapshot.fetch(f"file://{tmp_path}/nope", "0" * 40, str(tmp_path / "s2"), globs=["*.py"])["ok"] is False
```

- [ ] **Step 2: Run it and confirm it fails** (`ModuleNotFoundError: train.snapshot`).
- [ ] **Step 3: Implement `snapshot.py`** (subprocess argv lists, no shell).
- [ ] **Step 4: Run it and confirm it passes.**
- [ ] **Step 5: Commit:** `git commit -m "train: partial-clone + sparse-checkout snapshots (language files only), failures reported"`

---

### Task H5: Stage 1 targets and examples (pure)

**Files:**
- Create: `train/stage1.py` (pure part)
- Test: `train/tests/test_stage1_cases.py`

**Interfaces:**
- Consumes: `train.diffs.parse_u0` (D3: `{file, old_file, old_start, old_end, new_start, new_end}`, where an empty old range has `old_end = old_start - 1`); `codeindex.RepoIndex`, `parse_text` (H1); `cases.case_from_function`, `CaseBudget` (H2); pair rows from `pairs.json` (`id, cwe, cwe_class, vuln_methods, fix_methods, sink_location, locations, source_sink`).
- Produces:
  - `stage1.MAX_MULTI = 3`, `stage1.MIN_NEG_LINES = 5`
  - `stage1.primary_cwe(pair) -> str | None`: the first CWE that is a dataflow CWE (same list as D1's `cwe_class`), otherwise the first CWE.
  - `stage1.targets(pair, hunks, vuln_idx, patched_text: dict[str, str | None]) -> tuple[list[dict], str | None]` returns `(targets, reason)`. Each target is `{file, name, vuln_span, patched_span, anchor_old, anchor_new, tier}`. Tiers:
    - `"annotated"`: the pair's method or location annotations resolve to a span; this tier wins.
    - `"single"`: exactly one changed non-test function.
    - `"multi"`: 2..`MAX_MULTI` changed functions.

    Reasons: `"sprawling"` (more than `MAX_MULTI` changed functions), `"no_target"` (nothing changed outside tests, or nothing resolves).

    Anchors:
    - `anchor_old`: the first annotated `vulnerable_lines` entry if there is one, else the first changed old line inside the span, else the insertion line for add-only hunks.
    - `patched_span`: the same-named function in the patched text, or `None` if it was deleted.
  - `stage1.cases_from(pair, hunks, vuln_idx, patched_text, *, budget, n_negatives: int, seed: int) -> tuple[list[dict], dict]`:
    - Each example is `{"pair_id", "label": "vulnerable"|"patched"|"negative", "tier", "cwe_class", "case", "lead"}`.
    - Vulnerable lead: `{"flow_id": "F0", "file", "function", "line": anchor_old, "cwe": primary_cwe, "confidence": "HIGH"}`. Patched and negative examples have `lead=None`.
    - The patched case is built from `vuln_idx` after `update()` with the patched text of the changed files.
    - Negatives are drawn with `random.Random(f"{seed}:{pair['id']}")` from non-test spans of at least `MIN_NEG_LINES` lines with at least one call, not overlapping any hunk or target, each anchored on a seeded line.
    - The record is `{id, status, reason, n_targets, tiers, n_negatives}`.

- [ ] **Step 1: Write the failing test**

```python
# train/tests/test_stage1_cases.py
from orion.lm import codeindex as ci, cases
from train import stage1

VULN = ("def view(r):\n    q = 'SELECT ' + r\n    return db.execute(q)\n\n"
        "def other(a):\n    log(a)\n    x = a\n    y = x\n    return y\n\n"
        "def third(b):\n    x = f(b)\n    y = x\n    z = y\n    return z\n")
PATCHED = VULN.replace("    q = 'SELECT ' + r\n    return db.execute(q)\n", "    return db.execute('SELECT ?', [r])\n")
PAIR = {"id": "CVE-1", "cwe": ["CWE-89"], "cwe_class": "dataflow"}
HUNK = [{"file": "app.py", "old_file": "app.py", "old_start": 2, "old_end": 3, "new_start": 2, "new_end": 2}]

def _idx(tmp_path, text=VULN):
    (tmp_path / "app.py").write_text(text); return ci.RepoIndex(str(tmp_path))

def test_single_function_fix_gives_vuln_patched_negatives(tmp_path):
    """The changed function is the positive, its fixed version the negative pair, and unchanged functions are extra negatives."""
    ex, rec = stage1.cases_from(PAIR, HUNK, _idx(tmp_path), {"app.py": PATCHED},
                                budget=cases.CaseBudget(), n_negatives=2, seed=0)
    assert [e["label"] for e in ex] == ["vulnerable", "patched", "negative", "negative"]
    assert ex[0]["lead"] == {"flow_id": "F0", "file": "app.py", "function": "view", "line": 2,
                             "cwe": "CWE-89", "confidence": "HIGH"}
    assert ex[1]["lead"] is None and "execute('SELECT ?'" in ex[1]["case"]["snippets"][0]["code"]
    assert {e["case"]["snippets"][0]["function"] for e in ex[2:]} == {"other", "third"}
    assert rec["status"] == "ok" and rec["tiers"] == {"single": 1}

def test_seeded_negatives_are_deterministic(tmp_path):
    a, _ = stage1.cases_from(PAIR, HUNK, _idx(tmp_path), {"app.py": PATCHED}, budget=cases.CaseBudget(), n_negatives=1, seed=3)
    b, _ = stage1.cases_from(PAIR, HUNK, _idx(tmp_path), {"app.py": PATCHED}, budget=cases.CaseBudget(), n_negatives=1, seed=3)
    assert a == b

def test_annotation_beats_changed_functions(tmp_path):
    pair = {**PAIR, "vuln_methods": [{"file": "app.py", "method": "third", "start_line": 11, "end_line": 15, "vulnerable_lines": [12]}]}
    ex, rec = stage1.cases_from(pair, HUNK, _idx(tmp_path), {"app.py": PATCHED}, budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert ex[0]["lead"]["function"] == "third" and ex[0]["lead"]["line"] == 12 and rec["tiers"] == {"annotated": 1}

def test_deleted_function_keeps_vulnerable_drops_patched(tmp_path):
    """Review Focus 2."""
    ex, rec = stage1.cases_from(PAIR, HUNK, _idx(tmp_path), {"app.py": VULN.split("def other")[0].replace("view", "renamed")},
                                budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert [e["label"] for e in ex] == ["vulnerable"] and "patched_missing" in rec["reason"]

def test_sprawling_and_test_only_fixes_yield_nothing(tmp_path):
    """More than MAX_MULTI changed functions is too noisy to label; test-only fixes have no target."""
    vuln4 = VULN + "\ndef fourth(c):\n    g(c)\n    return c\n"          # fourth = lines 17-19
    four = [{"file": "app.py", "old_file": "app.py", "old_start": s, "old_end": s, "new_start": s, "new_end": s}
            for s in (2, 6, 12, 18)]                                       # one line in each of 4 functions
    ex, rec = stage1.cases_from(PAIR, four, _idx(tmp_path, vuln4), {"app.py": vuln4},
                                budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert ex == [] and rec["reason"] == "sprawling"
    tests_only = [{"file": "tests/test_app.py", "old_file": "tests/test_app.py", "old_start": 1, "old_end": 1, "new_start": 1, "new_end": 1}]
    ex, rec = stage1.cases_from(PAIR, tests_only, _idx(tmp_path), {}, budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert ex == [] and rec["reason"] == "no_target"
```

- [ ] **Step 2: Run it and confirm it fails** (`ModuleNotFoundError: train.stage1`).
- [ ] **Step 3: Implement the pure part of `stage1.py`.**
- [ ] **Step 4: Run it and confirm it passes.**
- [ ] **Step 5: Commit:** `git commit -m "train: Stage-1 targets (annotated > single > multi) and examples (vuln / patched / seeded negatives)"`

---

### Task H6: Stage 1 runner, frozen splits, pilot, full run

**Files:**
- Modify: `train/stage1.py` (add `build` + `main`)
- Create: `docs/notes/orion-lm-stage1.md` (measured pilot and full-run numbers)
- Create: `train/data/splits.json` (frozen; committed)
- Test: `train/tests/test_stage1_build.py`

**Interfaces:**
- Consumes:
  - `snapshot.fetch`, `snapshot.show` (H4)
  - `train.build.resolve_commits(pair, mirror_dir, *, run) -> {status, reason, vulnerable, patched, first_fix, fix_shas, multi_commit_nonlinear, vuln_sha_source, vuln_sha_matches}` (D2, `0fcc7e9`).
    - `status` is one of `ok | no_fix_commit | commit_missing | no_parent`.
    - Pass the partial-clone snapshot dir as `mirror_dir`: a blobless clone has every commit, so `rev-parse`/`merge-base` work.
  - `train.fixmap.fix_hunks(mirror_dir, vulnerable, patched, *, fix_shas, run) -> list[hunk]` (D3, `8594969`). Use it rather than raw `git_diff_u0`: it keeps only files a fix commit touched, so unrelated commits inside a linear fix range are excluded.
  - `stage1.cases_from` (H5); `splits.assign`, `write`, `load` (D1)
- Produces:
  - `stage1.build(pairs, splits, *, work_root, out_jsonl, ledger, budget, n_negatives, seed, on_event=print, fetch=snapshot.fetch, run=None) -> dict`. Behaviour:
    - Pairs are grouped by `repo_url` so one snapshot serves all of a repo's pairs; the snapshot is deleted after the repo's last pair.
    - Pairs already in the ledger are skipped.
    - Each output example carries its `split`.
    - The ledger gets one line per pair: `{id, status, reason, seconds_fetch, bytes, seconds_index, n_files, n_skipped, n_examples}` (nulls when a value isn't available).
    - It prints `[i/N] <id> …`, and Ctrl-C finishes the current pair and exits cleanly.
    - It returns totals.
  - `python -m train.stage1 --pairs … --splits … --out train/data/stage1.jsonl --ledger train/data/stage1_ledger.jsonl [--limit N] [--per-language N] [--languages js,py,java] [--classes dataflow,other] [--n-negatives 2] [--seed 0]`. The output files are gitignored.

- [ ] **Step 1: Write the failing test** (two local repos; one with a missing fix sha)

```python
# train/tests/test_stage1_build.py
def test_build_writes_examples_ledger_and_resumes(tmp_path):
    """Pair 1 builds examples; pair 2 (missing sha) is recorded as failed; a rerun skips both."""
    # fixture: real git repo with a 2-commit SQL fix as in test_stage1_cases.VULN/PATCHED; uploadpack filters on
    ...
    t1 = stage1.build(pairs, {"CVE-1": "train", "CVE-2": "dev"}, work_root=str(tmp_path / "w"),
                      out_jsonl=str(out), ledger=str(led), budget=cases.CaseBudget(), n_negatives=1, seed=0,
                      on_event=lambda *_: None)
    rows = [json.loads(l) for l in out.read_text().splitlines()]
    assert {r["label"] for r in rows} >= {"vulnerable", "patched"} and all(r["split"] == "train" for r in rows)
    lines = [json.loads(l) for l in led.read_text().splitlines()]
    assert [l["status"] for l in lines] == ["ok", "snapshot_failed"] and lines[0]["seconds_fetch"] is not None
    assert not any((tmp_path / "w").iterdir())          # snapshots deleted
    stage1.build(pairs, {"CVE-1": "train", "CVE-2": "dev"}, work_root=str(tmp_path / "w"), out_jsonl=str(out),
                 ledger=str(led), budget=cases.CaseBudget(), n_negatives=1, seed=0, on_event=lambda *_: None)
    assert len(led.read_text().splitlines()) == 2       # resumed, nothing redone

def test_keyboard_interrupt_finishes_current_pair(tmp_path, monkeypatch):
    """Stoppable: an interrupt after pair 1 leaves pair 1's ledger line intact and exits cleanly."""
    ...
```

The implementer writes the fixture body: a real `git init` with filters, the same text as H5, and a `repo_url` of `file://…`.

- [ ] **Step 2: Run it and confirm it fails** (`AttributeError: build`).
- [ ] **Step 3: Implement `build` and `main`.**
- [ ] **Step 4: Run it and confirm it passes**, plus `pytest train/tests -q`.
- [ ] **Step 5: Commit:** `git commit -m "train: Stage-1 runner (repo-grouped snapshots, resumable ledger, stoppable)"`
- [ ] **Step 6: GATE: Krish confirms the source list is final.** Then run `splits.write("train/data/splits.json", splits.assign(pairs, seed=0), seed=0)` and commit `train/data/splits.json`: `git commit -m "train: freeze by-repo splits (seed 0)"`. From here on, `splits.load` refuses any change.
- [ ] **Step 7: Pilot (measure).** `python -m train.stage1 --per-language 10` (seeded sample: 10 js, 10 py, 10 java). Record into `docs/notes/orion-lm-stage1.md`:
  - per-pair seconds_fetch, bytes, seconds_index, n_examples, and status counts with reasons
  - tier counts
  - a projection for the full run, computed only from these measurements and labelled as a projection
- [ ] **Step 8: Full run in the background** (resumable). When it finishes, record the final counts per split, label, tier, language and cwe_class in the same note, and commit the note: `git commit -m "docs: Stage-1 measured pilot and full-run counts"`

---

### Task H7: SFT export and mixing (one formatter)

**Files:**
- Create: `train/examples.py`
- Test: `train/tests/test_examples.py`

**Interfaces:**
- Consumes: `format.system_message`, `task_message`, `tool_result_message`, `dumps_action` (B3/D5 helpers already in `format.py`); `slice.pruned_schema()`.
- Produces:
  - `examples.to_sft(example: dict, *, schema_text: str) -> dict` returns:
    - `messages = [system_message(schema_text), task_message([example["case"]])]`
    - `target = dumps_action({"action": "final", "leads": [lead] if lead else []})`
    - `meta = {pair_id, label, tier, stage}` (`stage` is `example.get("stage", 1)`)
  - `examples.cut(trace: dict, *, schema_text: str) -> list[dict]`: Stage 2 multi-step. `trace = {"case", "actions": [...], "results": [...], "meta"}`. It produces one example per action; the conversation so far is built from `system_message`/`task_message`/assistant `dumps_action`/`tool_result_message`.
  - `examples.mix(groups: dict[str, list[dict]], shares: dict[str, float], *, total: int | None, seed: int) -> list[dict]`: draws from each group in proportion to its share (shares sum to 1; a group smaller than its share is used whole, and the shortfall is logged). Seeded shuffle.
  - `examples.export(stage1_jsonl, stage2_jsonl | None, cypher_rows | None, *, out_dir, schema_text, shares, seed) -> dict`: writes `train.jsonl` and `dev.jsonl` by each example's `split` (`oldcve` is never written) and returns the counts.

- [ ] **Step 1: Write the failing test**

```python
# train/tests/test_examples.py
from orion.lm import format as fmt
from train import examples

CASE = {"flow_id": "F0", "rank": 0, "sink_category": None, "source_uid": None, "sink_uid": None, "nodes": [],
        "snippets": [{"role": "target", "file": "a.py", "function": "f", "start": 1, "end": 2, "code": "x"}]}
LEAD = {"flow_id": "F0", "file": "a.py", "function": "f", "line": 1, "cwe": "CWE-89", "confidence": "HIGH"}

def test_to_sft_uses_runtime_formatter_and_canonical_target():
    """A training example is byte-identical to what the runtime would show at that step."""
    s = examples.to_sft({"pair_id": "P", "label": "vulnerable", "tier": "single", "case": CASE, "lead": LEAD}, schema_text="S")
    assert s["messages"] == [fmt.system_message("S"), fmt.task_message([CASE])]
    assert s["target"] == fmt.dumps_action({"action": "final", "leads": [LEAD]})
    p = examples.to_sft({"pair_id": "P", "label": "patched", "tier": "single", "case": CASE, "lead": None}, schema_text="S")
    assert p["target"] == fmt.dumps_action({"action": "final", "leads": []})

def test_cut_one_example_per_action_with_tool_results():
    q = {"action": "run_cypher", "query": "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c.code"}
    t = {"case": CASE, "actions": [q, {"action": "final", "leads": []}], "results": [{"rows": [], "row_count": 0}], "meta": {}}
    ex = examples.cut(t, schema_text="S")
    assert len(ex) == 2 and ex[1]["messages"][-1] == fmt.tool_result_message(q, {"rows": [], "row_count": 0})

def test_mix_shares_and_no_dev_in_train(tmp_path):
    out = examples.mix({"stage1": [{"g": 1}] * 90, "stage2": [{"g": 2}] * 100}, {"stage1": 0.9, "stage2": 0.1}, total=100, seed=0)
    assert sum(1 for e in out if e["g"] == 2) == 10
```

Add a test that `export` never writes a `dev` or `oldcve` pair_id into `train.jsonl`, built from a tiny stage1 JSONL.

- [ ] **Step 2: Run it and confirm it fails.**
- [ ] **Step 3: Implement `examples.py`.**
- [ ] **Step 4: Run it and confirm it passes.**
- [ ] **Step 5: Commit:** `git commit -m "train: SFT export via the runtime formatter, multi-step cutter, seeded mixing, split-safe export"`

---

### Task H8: Stage 2, real-graph examples on a small subset

**Files:**
- Create: `train/repo_sizes.py`, `train/stage2.py`, `train/templates/README.md` (Krish writes `queries.json`; until then this README says the templates are absent)
- Test: `train/tests/test_stage2.py`, `train/tests/test_repo_sizes.py`

**Interfaces:**
- Consumes:
  - `train.build.ensure_mirror(pair, mirror_root, *, run)`, `build_pair(pair, mirror_dir, work_root, *, builder=None, …)`, `evict(scan_ids, db)` (D2). Note that D2 maps js/py/java to `jssrc`/`pythonsrc`/`javasrc`.
  - `train.fixmap.pair_yield(db, pair_id, hunks, *, vulnerable_scan_id, patched_scan_id, root=None, window=3)` (D3) returns `{id, vulnerable_scan_id, patched_scan_id, n_sites, n_site_calls, n_site_flows, gold_flow, reason, flows_gone_on_patched, flows_unresolved}`.
    - `gold_flow` is `{uid, source_uid, sink_uid, sink_category, rank}` or `None`.
    - Cross-scan flow matching works by (file, diff-mapped line, call name), because uids hash the scan_id.
    - `fixmap.gold_flow` itself returns `(flow, reason)`, which E5 must unpack.
  - `slice.candidate_flows`, `flow_slice` (B2)
  - `cases.case_from_flow` (H2), `codeindex.RepoIndex` (H1)
  - `tools.run_cypher`, `is_scoped` (B1 / 515225b)
  - `stage1.primary_cwe` (H5)
- Produces:
  - `repo_sizes.fetch_sizes(repos: list[str], cache: str, *, run=None) -> dict[str, int | None]`: `gh api repos/<o>/<r> --jq .size` (KB). Cached as JSONL and resumable; 404 → `None`.
  - `stage2.select(pairs, splits, sizes, *, n: int, max_repo_kb: int, seed: int) -> list[dict]`: dataflow pairs in the `train`/`dev` splits with a known size ≤ `max_repo_kb`, picked round-robin across js/py/java in a seeded order.
  - `stage2.cases_from_graph(db, yield_rec, pair, vuln_tree, patched_tree, *, budget, n_negatives, seed) -> list[dict]`. Same example shape as Stage 1, plus `stage: 2`:
    - **vulnerable:** the gold flow's case. Its lead is the fix-site node on the gold path (file/line, tree-sitter enclosing function) plus `primary_cwe` (final-review I1; it was the sink node). No fix-site node on the path: the pair is skipped (`no_fix_site_node`).
    - **patched:** the gold flow's counterpart on the patched scan. If the gold flow's uid is in `flows_gone_on_patched`, it's omitted (`flow_gone`); if it's in `flows_unresolved`, it's omitted (`flow_unresolved`).
    - To find the counterpart, add a public `fixmap.patched_counterpart(db, gold_flow, hunks, *, vulnerable_scan_id, patched_scan_id, root=None) -> dict | None` that MOVES D3's existing private matching into a reusable function (no second copy). `pair_yield` then calls it too.
    - **negatives:** seeded vulnerable-scan flows whose path touches no fix site.
  - `stage2.trace_for(case, db, scan_id, templates: list[str] | None) -> dict | None`: `None` when the templates are absent. Otherwise it fills each template with the case's uids, rejects any that fail `is_scoped` (raising, since a bad template is a bug), runs them through `tools.run_cypher`, and returns `{case, actions: [*queries, final], results, meta}`.
  - `stage2.build(selected, *, mirror_root, work_root, out_jsonl, ledger, budget, n_negatives, seed, templates, on_event=print) -> dict`. For each selected pair: `build_pair` → `pair_yield` → `cases_from_graph` → `trace_for` → write → `evict`. One ledger line per pair, with D2's stage timings plus `n_examples` and the yield reason. Resumable and stoppable.

- [ ] **Step 1: Write the failing test** (stub DB plus injected `build_pair`/`pair_yield`; trees in tmp_path)

```python
def test_select_is_dataflow_only_size_capped_and_language_balanced():
    pairs = [{"id": f"{l}{i}", "language": l, "cwe_class": c, "repo": f"o/{l}{i}"}
             for l in ("js", "py", "java") for i in range(10) for c in ("dataflow",)] + \
            [{"id": "x", "language": "js", "cwe_class": "other", "repo": "o/x"}]
    sizes = {p["repo"]: (999_999 if p["id"] == "js0" else 10) for p in pairs}
    sel = stage2.select(pairs, {p["id"]: "train" for p in pairs}, sizes, n=6, max_repo_kb=1000, seed=0)
    assert len(sel) == 6 and {p["language"] for p in sel} == {"js", "py", "java"}
    assert all(p["cwe_class"] == "dataflow" and p["id"] != "js0" for p in sel)

def test_cases_from_graph_vuln_patched_and_flow_gone(tmp_path):
    """The gold flow becomes the positive; a same-sink patched flow becomes the negative pair; a missing patched flow is omitted."""
    # vuln tree a.js: "function run(x){\n  exec(x)\n}\n", patched: "function run(x){\n  exec(clean(x))\n}\n", plus b.js
    # StubDB: vulnerable scan -> CandidateFlows gold "fl0" (sink a.js:2 in run, code_exec) and "fl1" (sink in b.js);
    #         patched scan   -> one flow whose sink is a.js:2 in run, code_exec
    ex = stage2.cases_from_graph(db, {"id": "P", "gold_flow": "fl0", "vulnerable_scan_id": "P:vulnerable",
                                      "patched_scan_id": "P:patched"}, PAIR, str(vt), str(pt),
                                 budget=cases.CaseBudget(), n_negatives=1, seed=0)
    assert [e["label"] for e in ex] == ["vulnerable", "patched", "negative"] and all(e["stage"] == 2 for e in ex)
    assert ex[0]["lead"]["function"] == "run" and ex[0]["lead"]["line"] == 2 and ex[1]["lead"] is None
    # same call with the patched scan returning no flows: labels == ["vulnerable", "negative"]

def test_trace_for_rejects_unscoped_template_and_returns_none_without_templates():
    assert stage2.trace_for(CASE, StubDB(), "s:vulnerable", None) is None
    import pytest
    with pytest.raises(ValueError):
        stage2.trace_for(CASE, StubDB(), "s:vulnerable", ["MATCH (n) RETURN n"])
```

The StubDB used through `tools.run_cypher` must accept `**kw` and return `"query_type": "r"` for EXPLAIN (commit 515225b). The `repo_sizes` test uses an injected runner returning `"123"`, then raises for 404, and asserts that both the cache and the resume behaviour work.

- [ ] **Step 2: Run it and confirm it fails.**
- [ ] **Step 3: Implement** `repo_sizes.py`, `stage2.py` and `templates/README.md`.
- [ ] **Step 4: Run it and confirm it passes**, plus `pytest train/tests -q`.
- [ ] **Step 5: Commit:** `git commit -m "train: Stage-2 real-graph examples (size-capped language-balanced subset, gold/patched/negative flows, scoped template traces)"`
- [ ] **Step 6: GATE: graph-hardening is merged into `eval/orion-lm` and this branch is rebased on it.** Then run `repo_sizes.fetch_sizes` over the dataflow repos (measured, cached).
- [ ] **Step 7: Timing run (measure).** `stage2.build` on 10 selected pairs (n=10, `max_repo_kb` = the 75th percentile of the measured sizes). Record per-stage seconds, peak RSS, Neo4j nodes, cpg size and the yield reasons in `docs/notes/orion-lm-stage2.md`. Choose `n` and `max_repo_kb` for the real Stage 2 from these numbers, record the choice and its reason, and confirm it with Krish. Then run it in the background.

---

### Task H9: Dev scoring + bake-off

**Files:**
- Create: `train/devscore.py`, `eval/bakeoff.py`
- Create: `docs/notes/orion-lm-bakeoff.md` (measured)
- Test: `train/tests/test_devscore.py`, `eval/tests/test_bakeoff.py`

**Interfaces:**
- Consumes: `format.system_message`, `task_message`, `forced_final_message`, `parse_action` (B3); `model.load` (B4); dev examples from H6/H8 (`split == "dev"`).
- Produces:
  - `devscore.judge(generate, dev_examples, *, schema_text) -> dict`. Tool-less judgement: send `[system, task]`. If the first action isn't `final`, append the assistant turn plus `forced_final_message()` and generate once more. Unparseable output counts as no lead plus `parse_fail`. It returns `{n, vuln_recall, patched_silence, negative_silence, pair_correct, parse_fail_rate, tokens, tok_per_s}`, where:
    - `pair_correct` is the share of pairs whose vulnerable example is flagged AND whose patched example is silent;
    - `tokens` is Σ(prompt + completion) from `GenResult`.
  - `bakeoff.run_candidate(model_path, dev_examples, *, schema_text, load=model.load, sample_n=300, seed=0) -> dict` returns `devscore.judge`'s fields plus `model, peak_rss_mb, train_cutoff`. The sample is seeded and identical for every candidate.
  - `bakeoff.table(rows) -> str`

- [ ] **Step 1: Write the failing test** (scripted generate, no model)

```python
def test_judge_scores_pairs_and_forces_final():
    """Patched silent + vulnerable flagged = pair-correct; a non-final first action gets one forced final."""
    exs = [{"pair_id": "P", "label": "vulnerable", "case": CASE, "lead": LEAD},
           {"pair_id": "P", "label": "patched", "case": CASE, "lead": None},
           {"pair_id": "Q", "label": "negative", "case": CASE, "lead": None}]
    replies = iter([json.dumps({"action": "read_code", "file": "a.py", "start": 1, "end": 2}),
                    json.dumps({"action": "final", "leads": [LEAD]}),
                    json.dumps({"action": "final", "leads": []}), "garbage", json.dumps({"action": "final", "leads": []})])
    out = devscore.judge(lambda m: GenResult(text=next(replies), prompt_tokens=10, completion_tokens=2, cached_tokens=0),
                         exs, schema_text="S")
    assert out["vuln_recall"] == 1.0 and out["patched_silence"] == 1.0 and out["pair_correct"] == 1.0
    assert out["negative_silence"] == 1.0 and out["parse_fail_rate"] > 0 and out["tokens"] == 60
```

The bake-off test: `run_candidate` with an injected `load` returning a scripted model yields every listed field, and `table` names every model.

- [ ] **Step 2: Run it and confirm it fails.** **Step 3: Implement.** **Step 4: Run it and confirm it passes.**
- [ ] **Step 5: Commit:** `git commit -m "train/eval: tool-less dev judge (pair-correct, silence rates, tokens) + bake-off harness"`
- [ ] **Step 6: Real bake-off (measure).** Candidates: Gemma 4 E4B, Granite 4.1 8B, and Gemma 4 12B only if its published cutoff is before 2026-05-31. Each runs on the same 300-example dev sample through the same `mlx_lm convert -q` pipeline (H10 `to_mlx`). Record the table in `docs/notes/orion-lm-bakeoff.md`. The winner, or E4B if the results are inconclusive, is confirmed with Krish.

---

### Task H10: Training notebook, MLX convert, text2cypher retention

**Files:**
- Create: `train/convert.py`, `train/cypher_data.py`, `train/unsloth_lora.ipynb`
- Test: `train/tests/test_convert.py`, `train/tests/test_cypher_data.py`, `train/tests/test_notebook.py`

**Interfaces:**
- Produces:
  - `convert.to_mlx(model_dir: str, out_dir: str, *, q_bits: int = 4, run=None) -> str`: runs `python -m mlx_lm convert --hf-path <model_dir> --mlx-path <out_dir> -q --q-bits <q_bits>` and returns `out_dir`. Used for BOTH the base model (`orion-lm-base`) and the merged fine-tune (`orion-lm`).
  - `cypher_data.ALLOWED_SOURCES: tuple[str, ...]` (a provenance comment per entry; none LLM-generated) and `cypher_data.load_text2cypher(path) -> list[dict]` (spec in the original plan, D5). Rows become `{"messages": [{"role": "system", "content": "Write one Cypher query for this schema."}, {"role": "user", "content": schema + question}], "target": cypher}`.
  - The notebook:
    - reads `train.jsonl`/`dev.jsonl` from H7;
    - applies `orion.lm.model.merge_consecutive_roles` before the chat template (same as runtime);
    - computes loss on `target` tokens only;
    - keeps its LoRA hyperparameters in one constants cell;
    - **cell 2 measures throughput on 200 examples and prints a projection from that measurement** before the full run;
    - merges and saves the model.

    Krish runs it on a cloud GPU.

- [ ] **Step 1: Write the failing tests:**
  - `to_mlx` builds exactly that argv through an injected `run`.
  - `load_text2cypher` keeps only `ALLOWED_SOURCES` rows (original D5 test).
  - The notebook JSON loads, has a cell referencing `train.jsonl`, and has a cell calling `merge_consecutive_roles`.
- [ ] **Step 2: Run them and confirm they fail.** **Step 3: Implement.** **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit:** `git commit -m "train: MLX convert (same pipeline for base and fine-tune), non-LLM text2cypher loader, LoRA notebook with measured-throughput cell"`

---

### Task H11: Pair test + rounds (Stage 2 multi-step only)

**Files:**
- Create: `train/rounds.py`
- Test: `train/tests/test_rounds.py`

**Interfaces:**
- Consumes: `eval.match.l1` (E2); `prompter.run_session` (B3); `examples.cut` (H7); `model.load(..., seed=)` (B4); Stage 2 traces (H8).
- Produces:
  - `rounds.pair_test(vuln_leads: list[dict], patched_leads: list[dict], fix_site: dict) -> bool`: True iff a vulnerable lead `l1`-matches the fix site AND no patched lead does, AND at most one vulnerable lead misses the fix site (anti-spray). Imports `eval.match.l1`; no second copy.
  - `rounds._pick(candidates: list[dict]) -> list | None`: the shortest passing trace.
  - `rounds.rollout_round(stage2_cases, db, load, model_path, *, samples: int, seed: int) -> list[dict]`: seeds `seed + i`, train split only, retraining from the base model each round (ReST-EM).
  - `rounds.should_stop(dev_scores: list[dict]) -> bool`: stop after 3 rounds or when `pair_correct` doesn't improve.
- Scope: rounds run only if Stage 2 has multi-step traces (templates exist). Otherwise H11 ships the functions and its tests, and the plan note records "rounds skipped: no templates". Stage 1 is single-step SFT, so rejection sampling would add nothing there.

- [ ] **Step 1: Write the failing test** (from the original D4/D6 tests)

```python
FIX = {"file": "a.js", "line": 10, "function": "f", "line_start": 10, "line_end": 10}

def test_pair_test_flag_vuln_silent_patched():
    assert rounds.pair_test([{"file": "a.js", "line": 10, "function": "f"}], [{"file": "b.js", "line": 99, "function": "o"}], FIX)
    assert not rounds.pair_test([{"file": "a.js", "line": 10, "function": "f"}], [{"file": "a.js", "line": 10, "function": "f"}], FIX)

def test_pair_test_rejects_spray():
    v = [{"file": "a.js", "line": 10, "function": "f"}, {"file": "z.js", "line": 1, "function": "g"}, {"file": "y.js", "line": 2, "function": "h"}]
    assert not rounds.pair_test(v, [], FIX)

def test_pick_shortest_passing_and_stop_rule():
    assert rounds._pick([{"trace": [1, 2, 3], "passes": True}, {"trace": [1, 2], "passes": True}, {"trace": [1], "passes": False}]) == [1, 2]
    assert rounds.should_stop([{"pair_correct": 0.3}, {"pair_correct": 0.3}]) and not rounds.should_stop([{"pair_correct": 0.1}, {"pair_correct": 0.2}])
```

Before writing the assertions, check how `eval.match.l1` reads an answer key: the `FIX` dict must carry the key fields `l1` expects (`line_start`/`line_end`).

- [ ] **Step 2: Run it and confirm it fails.** **Step 3: Implement.** **Step 4: Run it and confirm it passes.**
- [ ] **Step 5: Commit:** `git commit -m "train: pair test (flag vuln, silent at fix on patched, anti-spray) + ReST-EM rounds for Stage-2 traces"`

> **Status (2026-10-18):** functions and tests shipped (`train/rounds.py`). Rounds skipped: no templates yet (`train/templates/queries.json` is Krish's). Built as: `pair_test` scores with `eval.match.l1` against an answer-key-shaped fix site `{file, function, line_start, line_end}` built from the fix hunk (final-review I1, 2026-10-18: ONE location convention, the FIX SITE, in Stage 1, the Stage 2 lead (`stage2._lead`: the fix-site node on the gold path, never the sink), the rounds and the test rule; Stage 2 writes it as `meta.fix_site` on the vulnerable trace); `rollout_round` takes a required `repo_for(pair_id, side)` and an optional `on_event`, skips pairs whose scans are gone (`scan_missing`), and never trains. The caller rebuilds Stage 2 scans and retrains from the base model each round.

---

## Execution order and gates

H1 → H2 → H3 (runtime, independent of training data) ∥ H4 → H5 → H6 (needs D3's `train/diffs.py`) → H7 → H9 → H10. H8 needs D2/D3 + H2 and the graph-hardening gate. H11 is last.

Human gates:
- H6 Step 6: the source list is final, so splits freeze.
- H8 Step 6: graph-hardening is merged.
- H8 Step 7: the Stage 2 size is confirmed.
- H9 Step 6: the bake-off winner.
- H10: Krish runs the notebook.
- Before the prereg tag: Krish's system prompt (it must state the 515225b query rules) and `train/templates/queries.json`.

## Self-review

- **Coverage:** Stage 1 (H4–H7), Stage 2 (H8), a test pipeline unchanged except K=1 (H3), the single formatter and case builder (H1–H2, H7), dev and bake-off (H9), training and convert (H10), rounds (H11), the design-change record (H1 Step 6).
- **Review Focus:** all 5 are pinned to tests (H1 ×3, H2, H4/H6, H5).
- **Names checked against the code on 2026-10-18:**
  - `format.system_message`/`task_message`/`tool_result_message`/`forced_final_message`/`parse_action`/`dumps_action`
  - `engine.discover_lm(..., k=5, ..., db=None)`
  - `slice.flow_slice`
  - `model.merge_consecutive_roles`, `model.load(path, *, gguf_path=None, **sampling)`
  - `eval.dataset.enrich._is_test`
  - `splits.assign`/`write`/`load`
  - `tools.is_scoped`
- **D2/D3 names were checked against the landed code** (`91c3a7e`, `8594969`, `0fcc7e9`): `build.resolve_commits`/`ensure_mirror`/`build_pair`/`evict`, `fixmap.fix_hunks`/`pair_yield`/`gold_flow` (which returns a tuple), `diffs.git_diff_u0`/`parse_u0`. The real `CpgCall.file_path` is repo-relative POSIX (`fixmap.norm_path`).
