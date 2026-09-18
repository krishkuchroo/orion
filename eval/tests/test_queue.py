from eval import db, queue


def test_plan_orders_by_arm_then_repo_then_run():
    p = queue.plan(["orion-gemma4", "plain-opus5"], ["r1", "r2"], 2)
    assert p[0] == ("orion-gemma4", "r1", 1)
    assert p[:4] == [("orion-gemma4", "r1", 1), ("orion-gemma4", "r1", 2),
                     ("orion-gemma4", "r2", 1), ("orion-gemma4", "r2", 2)]
    assert p[-1] == ("plain-opus5", "r2", 2)


def test_pending_skips_completed_ok_runs(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = db.start_run(conn, arm="a", repo="r1", tier="headline", run_no=1, model_tag="m",
                       cli_versions="", orion_commit="c")
    db.finish_run(conn, rid, "ok")
    plan = [("a", "r1", 1), ("a", "r1", 2)]
    assert queue.pending(conn, plan) == [("a", "r1", 2)]
