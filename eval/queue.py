def plan(arms, repos, runs):
    out = []
    for arm in arms:
        for repo in repos:
            for n in range(1, runs + 1):
                out.append((arm, repo, n))
    return out


def pending(conn, plan):
    done = {(a, r, n) for a, r, n in conn.execute(
        "SELECT arm, repo, run_no FROM runs WHERE status='ok'").fetchall()}
    return [t for t in plan if t not in done]
