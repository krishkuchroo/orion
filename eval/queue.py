"""Run queue. Every attempt is a row in `runs`; nothing is silently requeued.

Terminal statuses (ok|crashed|hung|error) are scored as they stand: a hung or crashed run is a
miss whose tokens count. The one exception is `aborted` (a subscription usage limit killed the
run): it is not the model's miss, is never scored, and gets a fresh attempt_no."""

from . import db

TERMINAL = ("ok", "crashed", "hung", "error")


def plan(arms, items, runs):
    """(arm, repo, commit_sha, case_id, run_no); items maps repo -> [(commit_sha, commit_kind, case_id)]."""
    out = []
    for arm in arms:
        for repo, commits in items.items():
            for commit_sha, _kind, case_id in commits:
                for n in range(1, runs + 1):
                    out.append((arm, repo, commit_sha, case_id, n))
    return out


def reconcile_stale(conn) -> int:
    """Runs are sequential, so any `running` row at planning time belongs to a dead process."""
    cur = conn.execute("UPDATE runs SET status='crashed', ended=COALESCE(ended, ?)"
                       " WHERE status='running'", (db._utc(),))
    conn.commit()
    return cur.rowcount


def pending(conn, plan):
    reconcile_stale(conn)
    latest = {}
    for arm, repo, sha, case, _n_att, status, run_no in conn.execute(
            "SELECT arm, repo, COALESCE(commit_sha,''), COALESCE(case_id,''), attempt_no, status, run_no"
            " FROM runs ORDER BY attempt_no"):
        latest[(arm, repo, sha, case, run_no)] = status  # ascending attempt_no: last write wins
    return [t for t in plan if latest.get(t) not in TERMINAL]
