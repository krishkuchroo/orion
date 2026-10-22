import pkgutil
import subprocess
import sys
from pathlib import Path

from eval import judge

ROOT = Path(__file__).resolve().parents[2]


def test_classify_uses_injected_judge():
    out = judge.classify({"raw_text": "maybe a bug", "file": None}, ask=lambda p: "false_alarm")
    assert out["label"] == "false_alarm"


def test_classify_unparseable_reply_is_unsure_and_kept():
    out = judge.classify({"raw_text": "x"}, ask=lambda p: "I think it is probably fine")
    assert out["label"] == "unsure" and out["raw_reply"] == "I think it is probably fine"
    assert out["parsed"] is False
    assert judge.classify({"raw_text": "x"}, ask=lambda p: None)["label"] == "unsure"


def test_classify_tolerates_formatting():
    for r in ("Real_Other_Bug\n", "`real other bug`", "real-other-bug."):
        assert judge.classify({"raw_text": "x"}, ask=lambda p, r=r: r)["label"] == "real_other_bug"


def test_prompt_is_blinded_to_arm():
    seen = []
    judge.classify({"raw_text": "sqli", "arm": "plain-sonnet5", "file": "a.js"},
                   ask=lambda p: seen.append(p) or "unsure")
    assert "plain-sonnet5" not in seen[0]
    assert "sqli" in seen[0]
    assert "{arm" not in judge.JUDGE_PROMPT


def test_prompt_hash_and_model_recorded():
    assert len(judge.prompt_sha256()) == 64
    assert judge.judge_record() == {"model": None, "prompt_sha256": judge.prompt_sha256()}


def test_calibrate_reports_kappa_and_ac1():
    out = judge.calibrate(["real_other_bug", "real_other_bug", "false_alarm"], ["real_other_bug", "false_alarm", "false_alarm"])
    assert "kappa" in out and "ac1" in out
    assert abs(out["kappa"] - 0.4) < 1e-9
    assert out["min_n_met"] is False


def test_calibrate_perfect_agreement_single_class_is_none():
    out = judge.calibrate(["real_other_bug", "real_other_bug"], ["real_other_bug", "real_other_bug"])
    assert out["agreement"] == 1.0 and out["kappa"] is None and out["ac1"] == 1.0


def test_calibrate_empty_is_none():
    out = judge.calibrate([], [])
    assert out["n"] == 0 and out["kappa"] is None and out["agreement"] is None


def test_calibrate_perfect_two_class():
    out = judge.calibrate(["real_other_bug", "false_alarm", "real_other_bug", "false_alarm"], ["real_other_bug", "false_alarm", "real_other_bug", "false_alarm"])
    assert out["kappa"] == 1.0 and out["ac1"] == 1.0


def test_calibrate_per_arm():
    out = judge.calibrate(["real_other_bug", "real_other_bug", "false_alarm", "false_alarm"], ["real_other_bug", "real_other_bug", "false_alarm", "real_other_bug"], arms=["x", "x", "y", "y"])
    assert out["per_arm"]["x"]["agreement"] == 1.0
    assert out["per_arm"]["y"]["agreement"] == 0.5 and out["per_arm"]["y"]["n"] == 2


def test_ac1_uses_fixed_q_across_arms():
    # arm x sees 2 categories, arm y only 1; both use q=3 from the label scale.
    j = ["real_other_bug", "false_alarm", "real_other_bug", "false_alarm", "real_other_bug", "real_other_bug"]
    h = ["real_other_bug", "false_alarm", "real_other_bug", "false_alarm", "real_other_bug", "real_other_bug"]
    out = judge.calibrate(j, h, arms=["x"] * 4 + ["y"] * 2)
    assert out["per_arm"]["y"]["ac1"] == 1.0 and out["per_arm"]["y"]["kappa"] is None
    assert out["per_arm"]["x"]["ac1"] == 1.0
    # q matters: same data, q=2 vs q=3 gives different chance agreement
    j2, h2 = ["real_other_bug", "real_other_bug", "false_alarm", "real_other_bug"], ["real_other_bug", "false_alarm", "false_alarm", "real_other_bug"]
    q3 = judge.calibrate(j2, h2)["ac1"]
    q2 = judge.calibrate(j2, h2, categories=("real_other_bug", "false_alarm"))["ac1"]
    # hand-computed: po=.75, sum p(1-p)=.46875; q=3 -> .515625/.765625, q=2 -> .28125/.53125
    assert abs(q3 - 0.515625 / 0.765625) < 1e-9 and abs(q2 - 0.28125 / 0.53125) < 1e-9


def test_calibrate_rejects_labels_outside_categories():
    import pytest
    with pytest.raises(ValueError):
        judge.calibrate(["a"], ["a"])


def test_calibrate_length_mismatch_raises():
    import pytest
    with pytest.raises(ValueError):
        judge.calibrate(["real_other_bug"], ["real_other_bug", "false_alarm"])
    with pytest.raises(ValueError):
        judge.calibrate(["real_other_bug"], ["real_other_bug"], arms=["x", "y"])


def test_ppi_perfect_judge_matches_classical():
    j = ["real_other_bug", "false_alarm"] * 10
    out = judge.ppi_precision(5, j, list(j))
    assert abs(out["precision"] - (5 + 10) / 25) < 1e-12
    assert abs(out["precision"] - out["classical"]) < 1e-12


def test_ppi_corrects_judge_bias():
    # judge says everything real; humans (on a subset) say half are.
    j = ["real_other_bug"] * 20
    h = ["real_other_bug", "false_alarm"] * 5 + [None] * 10
    out = judge.ppi_precision(0, j, h)
    assert abs(out["precision"] - 0.5) < 1e-12
    assert out["ci"] is not None and out["ci"][0] < 0.5 < out["ci"][1]


def test_ppi_undefined_cases_are_none():
    assert judge.ppi_precision(0, [], [])["precision"] is None
    out = judge.ppi_precision(3, ["false_alarm"] * 4, [None] * 4)
    assert out["precision"] is None and out["n_labeled"] == 0
    one = judge.ppi_precision(0, ["false_alarm"] * 4, ["false_alarm", None, None, None])
    assert one["precision"] == 0.0 and one["ci"] is None


def test_unsure_counts_as_not_real():
    out = judge.ppi_precision(0, ["unsure"] * 2, ["unsure", "unsure"])
    assert out["precision"] == 0.0


def test_train_and_bakeoff_do_not_import_judge():
    # fresh interpreter: this test module itself imports eval.judge above
    import train
    mods = sorted(m.name for m in pkgutil.iter_modules(train.__path__) if m.name != "__init__")
    assert mods, "no train modules discovered"
    imports = "".join(f"importlib.import_module('train.{m}');" for m in mods)
    code = (f"import sys, importlib; {imports} importlib.import_module('eval.bakeoff'); "
            "sys.exit(1 if 'eval.judge' in sys.modules else 0)")
    r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-800:]
