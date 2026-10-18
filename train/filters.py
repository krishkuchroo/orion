"""Keep/drop rules for training pairs. Every dropped row carries a ``reason``; nothing is backfilled.

Checks run in a fixed order and the first failing one is the row's reason, so the reasons double as
a funnel (``STAGES``):

0. labels not LLM-made              llm_assisted_labels  (unless allow_llm_assisted=True)
1. a GitHub fix commit exists       no_fix_commit / non_github_repo / fix_pr_unresolved
2. language is JS/TS, Python, Java  language_unknown / language_unsupported:<lang>
3. advisory published < cutoff      advisory_date_missing / advisory_after_cutoff
4. not a test-set candidate repo    post_cutoff_repo / post_cutoff_package
5. fix commit metadata obtained     enrich_pending / commit_missing / enrich_error / fix_date_missing
6. fix commit date < cutoff         fix_after_cutoff
7. fix touches the language         no_source_files_in_language
8. dedupe (alias, then repo+sha)    duplicate_alias:<id> / duplicate_commit:<id>
9. fix size                         files_unknown / too_many_files   (skipped when max_files=None)

Dedupe runs after the per-row checks so a broken record (e.g. a commit GitHub no longer has) never
shadows a good duplicate. There is NO per-repo cap.
"""
from __future__ import annotations

from train.sources import ANNOTATION_KEYS, CUTOFF, SOURCE_PRIORITY, SUPPORTED_LANGUAGES, cwe_class

STAGES = ("llm_assisted_labels",
          "no_fix_commit", "non_github_repo", "fix_pr_unresolved",
          "language_unknown", "language_unsupported",
          "advisory_date_missing", "advisory_after_cutoff",
          "post_cutoff_repo", "post_cutoff_package",
          "enrich_pending", "commit_missing", "enrich_error", "fix_date_missing",
          "fix_after_cutoff",
          "no_source_files_in_language",
          "duplicate_alias", "duplicate_commit",
          "files_unknown", "too_many_files")


def reason_kind(reason: str) -> str:
    return reason.split(":", 1)[0]


def row_reason(r: dict, *, cutoff: str = CUTOFF, post_cutoff_repos=frozenset(), post_cutoff_packages=frozenset(),
               languages=SUPPORTED_LANGUAGES, stop_before_enrichment: bool = False,
               allow_unknown_language: bool = False, allow_llm_assisted: bool = False) -> str | None:
    """First failing per-row check (stages 1-7), or None. ``stop_before_enrichment`` evaluates only
    the checks that need no GitHub data (used to decide which commits are worth fetching; a PR-only
    row passes it because the PR is resolved during enrichment)."""
    if r.get("llm_assisted_labels") and not allow_llm_assisted:
        return "llm_assisted_labels"
    if not r.get("repo"):
        return "non_github_repo" if r.get("repo_url") else "no_fix_commit"
    if not r.get("fix_sha") and not (stop_before_enrichment and r.get("fix_pr")):
        return "fix_pr_unresolved" if r.get("fix_pr") else "no_fix_commit"
    lang = r.get("language")
    if lang is None:
        if not allow_unknown_language:
            return "language_unknown"
    elif lang not in languages:
        return f"language_unsupported:{lang}"
    adv = r.get("advisory_published")
    if not adv:
        return "advisory_date_missing"
    if adv >= cutoff:
        return "advisory_after_cutoff"
    if r["repo"] in post_cutoff_repos or (r.get("repo_canonical") or r["repo"]) in post_cutoff_repos:
        return "post_cutoff_repo"
    if any(tuple(p) in post_cutoff_packages for p in r.get("packages") or []):
        return "post_cutoff_package"
    if stop_before_enrichment:
        return None
    status = r.get("enrich_status")
    if status == "commit_missing":
        return "commit_missing"
    if status == "error":
        return "enrich_error"
    if status != "ok":
        return "enrich_pending"
    fix_date = r.get("fix_commit_date")
    if not fix_date:
        return "fix_date_missing"
    if fix_date >= cutoff:
        return "fix_after_cutoff"
    if r.get("n_files_lang") == 0:
        return "no_source_files_in_language"
    return None


def _rank(r: dict):
    src = r.get("source", "")
    pri = SOURCE_PRIORITY.index(src) if src in SOURCE_PRIORITY else len(SOURCE_PRIORITY)
    return (pri, 0 if str(r.get("source_id", "")).upper().startswith("GHSA-") else 1, r["id"], str(r.get("source_id")))


def _tag(r: dict) -> str:
    return f"{r.get('source')}:{r.get('source_id')}"


def _merge(group: list[dict]) -> dict:
    """Survivor = best-ranked row; it takes the union of the group's real ids/CWEs/packages/sources,
    the earliest real advisory date, and any location annotation it lacks from a duplicate."""
    group = sorted(group, key=_rank)
    s = dict(group[0])
    s["aliases"] = sorted({a for r in group for a in r.get("aliases") or [r["id"]]})
    cwes = {c for r in group for c in r.get("cwe") or []}
    s["cwe"] = sorted(cwes, key=lambda c: int(c[4:]))
    if s["cwe"]:
        s["cwe_class"], s["cwe_class_basis"] = cwe_class(s["cwe"]), "cwe"
    else:                               # no CWE id anywhere: keep a dataset's own class tag (SecBench.js)
        tagged = next((r for r in group if r.get("cwe_class_basis") == "vuln_class"), None)
        s["cwe_class"] = tagged["cwe_class"] if tagged else "unknown"
        s["cwe_class_basis"] = "vuln_class" if tagged else None
    s["packages"] = sorted({tuple(p) for r in group for p in r.get("packages") or []})
    s["packages"] = [list(p) for p in s["packages"]]
    for k in ANNOTATION_KEYS:
        if not s.get(k):
            donor = next((r for r in group if r.get(k)), None)
            if donor:
                s[k], s[f"{k}_from"] = donor[k], _tag(donor)
    dates = [r["advisory_published"] for r in group if r.get("advisory_published")]
    s["advisory_published"] = min(dates) if dates else None
    s["sources"] = [_tag(r) for r in group]
    return s


def _dedupe(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    parent = list(range(len(rows)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    first: dict[str, int] = {}
    for i, r in enumerate(rows):
        for a in r.get("aliases") or [r["id"]]:
            if a in first:
                parent[find(i)] = find(first[a])
            else:
                first[a] = i
    groups: dict[int, list[int]] = {}
    for i in range(len(rows)):
        groups.setdefault(find(i), []).append(i)
    survivors, dropped = [], []
    for idx in groups.values():
        g = [rows[i] for i in idx]
        best = min(g, key=_rank)
        merged = _merge(g)
        survivors.append(merged)
        dropped += [dict(r, reason=f"duplicate_alias:{merged['id']}") for r in g if r is not best]
    by_commit: dict[tuple, dict] = {}
    kept = []
    for s in sorted(survivors, key=_rank):
        key = (s.get("repo_canonical") or s["repo"], s.get("fix_sha_full") or s["fix_sha"])
        if key in by_commit:
            dropped.append(dict(s, reason=f"duplicate_commit:{by_commit[key]['id']}"))
            continue
        by_commit[key] = s
        kept.append(s)
    return kept, dropped


def keep(pairs: list[dict], *, cutoff: str = CUTOFF, post_cutoff_repos, post_cutoff_packages=frozenset(),
         max_files: int | None = 10, languages=SUPPORTED_LANGUAGES,
         allow_llm_assisted: bool = False) -> tuple[list[dict], list[dict]]:
    """Returns ``(kept, dropped)``; every dropped row is a copy of the input row plus ``reason``."""
    passed, dropped = [], []
    for r in pairs:
        why = row_reason(r, cutoff=cutoff, post_cutoff_repos=post_cutoff_repos,
                         post_cutoff_packages=post_cutoff_packages, languages=languages,
                         allow_llm_assisted=allow_llm_assisted)
        if why:
            dropped.append(dict(r, reason=why))
        else:
            passed.append(r)
    unique, dups = _dedupe(passed)
    dropped += dups
    kept = []
    for r in unique:
        if max_files is not None:
            if r.get("n_files") is None:
                dropped.append(dict(r, reason="files_unknown"))
                continue
            if r["n_files"] > max_files:
                dropped.append(dict(r, reason="too_many_files"))
                continue
        kept.append(r)
    kept.sort(key=lambda r: (r["id"], _rank(r)))
    return kept, dropped
