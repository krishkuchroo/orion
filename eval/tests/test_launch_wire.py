import io
import json

from eval.arms import launch, ArmResult


class FakePopen:
    def __init__(self, lines=("done",), **kw):
        self.stdout = io.StringIO("".join(l + "\n" for l in lines))
        self.returncode = 0
        self.pid = 4321

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


def _run(tmp_path, arm="plain-opus5", lines=("done",), **over):
    from eval.arms import plain
    kw = dict(arm=arm, repo_dir=str(tmp_path / "tree"), model_tag="m", effort="xhigh",
              json_out=str(tmp_path / "out" / "findings.json"), usage_log=str(tmp_path / "u.jsonl"),
              shim_dir="/s", base_env={"PATH": "/bin"}, on_line=lambda l: None,
              popen=lambda cmd, **kw: FakePopen(lines))
    kw.update(over)
    return plain.plain_arm(**kw)


def test_stream_calls_on_start_with_proc():
    seen = {}
    launch.stream_subprocess(["x"], env={}, cwd=".", on_line=lambda l: None,
                             on_start=lambda p: seen.setdefault("pid", p.pid),
                             popen=lambda cmd, **kw: FakePopen())
    assert seen["pid"] == 4321


def test_stream_on_start_is_optional():
    status = launch.stream_subprocess(["x"], env={}, cwd=".", on_line=lambda l: None,
                                      popen=lambda cmd, **kw: FakePopen())
    assert status == "ok"


def test_plain_arm_returns_armresult_and_copies_findings(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "findings.json").write_text('{"findings": []}')
    (tmp_path / "u.jsonl").write_text('{"type":"result","usage":{"input_tokens":5,"output_tokens":1}}\n')
    res = _run(tmp_path)
    assert isinstance(res, ArmResult) and res.status == "ok"
    assert (tmp_path / "out" / "findings.json").exists()
    assert res.findings_path == str(tmp_path / "out" / "findings.json")
    assert res.usage[0]["uncached_in"] == 5 and res.usage[0]["out"] == 1
    assert res.usage[0]["cache_read"] is None            # absent in the event -> None, not 0


def test_plain_arm_missing_findings_is_a_miss_not_error(tmp_path):
    (tmp_path / "tree").mkdir()          # agent wrote nothing
    (tmp_path / "u.jsonl").write_text("")
    res = _run(tmp_path)
    assert res.status == "ok" and res.findings_path is None   # scored as a miss; tokens still logged
    assert res.usage == []
    assert not (tmp_path / "out" / "findings.json").exists()


def test_plain_arm_missing_usage_log_gives_empty_usage(tmp_path):
    (tmp_path / "tree").mkdir()
    res = _run(tmp_path)                 # u.jsonl never written (shim did not run)
    assert res.usage == [] and res.status == "ok"


def test_plain_arm_invalid_findings_is_a_miss_with_warning(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "findings.json").write_text('{"findings": [{"file": "a.js"}]}')   # fields missing
    (tmp_path / "u.jsonl").write_text("")
    warned = []
    res = _run(tmp_path, on_line=warned.append)
    assert res.status == "ok" and res.findings_path is None
    assert (tmp_path / "out" / "findings.json").exists()           # raw artifact still kept
    assert any("findings.json" in w and "missing" in w for w in warned)


def test_plain_arm_unparseable_findings_is_a_miss_with_warning(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "findings.json").write_text("not json")
    warned = []
    res = _run(tmp_path, on_line=warned.append)
    assert res.findings_path is None and res.status == "ok"
    assert any("findings.json" in w for w in warned)


def test_plain_arm_keeps_crashed_status_but_still_reads_usage(tmp_path):
    class Bad(FakePopen):
        def __init__(self, *a, **k):
            super().__init__(("oops",))
            self.returncode = 1
    (tmp_path / "tree").mkdir()
    (tmp_path / "u.jsonl").write_text('{"type":"result","usage":{"input_tokens":3}}\n')
    res = _run(tmp_path, popen=lambda cmd, **kw: Bad())
    assert res.status == "crashed" and res.usage[0]["uncached_in"] == 3


def test_plain_arm_ignores_non_result_lines(tmp_path):
    (tmp_path / "tree").mkdir()
    (tmp_path / "u.jsonl").write_text(
        '{"type":"system"}\nnot json\n'
        '{"type":"result","usage":{"input_tokens":1,"output_tokens":2}}\n')
    res = _run(tmp_path)
    assert len(res.usage) == 1 and res.usage[0] == {
        "uncached_in": 1, "cache_read": None, "cache_write": None, "out": 2, "reasoning": None}


def test_gpt_arm_tees_codex_events_to_usage_log_and_normalizes(tmp_path):
    (tmp_path / "tree").mkdir()
    turn = {"type": "turn.completed", "usage": {"input_tokens": 100, "cached_input_tokens": 60,
                                                 "output_tokens": 7, "reasoning_output_tokens": 2}}
    res = _run(tmp_path, arm="plain-gpt",
               lines=('{"type":"item.completed"}', json.dumps(turn)))
    assert res.usage == [{"uncached_in": 40, "cache_read": 60, "cache_write": None,
                          "out": 7, "reasoning": 2}]
    # Codex has no shim: the arm keeps the raw event stream itself
    raw = (tmp_path / "u.jsonl").read_text().splitlines()
    assert raw == ['{"type":"item.completed"}', json.dumps(turn)]


def test_plain_arm_forwards_on_start(tmp_path):
    (tmp_path / "tree").mkdir()
    seen = {}
    _run(tmp_path, on_start=lambda p: seen.setdefault("pid", p.pid))
    assert seen["pid"] == 4321


def test_read_usage_warns_on_malformed_usage_event(tmp_path):
    log = tmp_path / "u.jsonl"
    log.write_text('{"type":"result","usage":{"input_tokens":5,"output_tok\n')   # truncated line
    warned = []
    from eval.arms import plain
    blocks = plain.read_usage(str(log), source="claude", on_line=warned.append)
    assert blocks == []
    assert any("usage" in w and "parse" in w for w in warned)


def test_read_usage_warns_when_nonempty_log_yields_no_blocks(tmp_path):
    log = tmp_path / "u.jsonl"
    log.write_text('{"type":"system"}\n{"type":"assistant"}\n')   # claude ran, no result event
    warned = []
    from eval.arms import plain
    assert plain.read_usage(str(log), source="claude", on_line=warned.append) == []
    assert any("no usage" in w for w in warned)


def test_read_usage_is_quiet_on_a_clean_log(tmp_path):
    log = tmp_path / "u.jsonl"
    log.write_text('{"type":"system"}\n{"type":"result","usage":{"input_tokens":1}}\n')
    warned = []
    from eval.arms import plain
    assert len(plain.read_usage(str(log), source="claude", on_line=warned.append)) == 1
    assert warned == []


def test_plain_arm_surfaces_corrupt_usage_line_through_on_line(tmp_path):
    (tmp_path / "tree").mkdir()
    warned = []
    # Codex printed a truncated turn.completed event; the arm tees it into usage.jsonl verbatim
    res = _run(tmp_path, arm="plain-gpt", on_line=warned.append,
               lines=('{"type":"turn.completed","usage":{"input_tokens":1',))
    assert res.usage == []
    assert any("parse" in w and "turn.completed" in w for w in warned)
    assert (tmp_path / "u.jsonl").read_text() == '{"type":"turn.completed","usage":{"input_tokens":1\n'
