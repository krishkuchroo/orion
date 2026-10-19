import inspect
import json
import os
import textwrap

from orion.lm import model

NB = os.path.join(os.path.dirname(__file__), "..", "unsloth_lora.ipynb")


def _cells():
    with open(NB, encoding="utf-8") as f:
        nb = json.load(f)
    return [(c["cell_type"], "".join(c["source"])) for c in nb["cells"]]


def _code():
    return [s for t, s in _cells() if t == "code"]


def test_loads_and_has_no_outputs():
    with open(NB, encoding="utf-8") as f:
        nb = json.load(f)
    assert all(c.get("outputs", []) == [] for c in nb["cells"] if c["cell_type"] == "code")


def test_reads_h7_jsonl_and_applies_merge():
    code = _code()
    assert any("train.jsonl" in s and "dev.jsonl" in s for s in code)
    assert any("merge_consecutive_roles(" in s and "apply_chat_template" in s for s in code)


def test_vendored_merge_equals_repo_function():
    cells = [s for s in _code() if "def merge_consecutive_roles" in s]
    assert len(cells) == 1
    assert "orion/lm/model.py" in cells[0]
    start = cells[0].index("def merge_consecutive_roles")
    lines = cells[0][start:].splitlines()
    body = [lines[0]]
    for ln in lines[1:]:
        if ln.strip() and not ln.startswith((" ", "\t")):
            break
        body.append(ln)
    vendored = "\n".join(body).rstrip() + "\n"
    assert vendored == textwrap.dedent(inspect.getsource(model.merge_consecutive_roles))


def test_loss_on_target_tokens_only():
    assert any("-100" in s and "target" in s for s in _code())


def test_hyperparameters_in_one_constants_cell():
    code = _code()
    names = ["LORA_R", "LORA_ALPHA", "LORA_DROPOUT", "LEARNING_RATE", "EPOCHS", "BATCH_SIZE",
             "GRAD_ACCUM", "MAX_SEQ_LEN", "TARGET_MODULES", "SEED"]
    holders = [s for s in code if "LORA_R" in s and "=" in s]
    assert len(holders) == 1
    for n in names:
        assert f"\n{n} =" in "\n" + holders[0], n
    for n in names:  # defined nowhere else
        assert sum(f"\n{n} =" in "\n" + s for s in code) == 1, n


def test_cell_2_is_labelled_throughput_projection():
    s = _code()[2]
    assert "THROUGHPUT_N = 200" in s
    assert "PROJECTION" in s and "measured" in s.lower()


def test_merges_and_saves():
    assert any("save_pretrained_merged" in s or "merge_and_unload" in s for s in _code())
