"""The bounded, coverage-guided mutational loop. Language-agnostic.

Orion's own engine (not AFL++/libFuzzer): the goal here is OBSERVING linkages, not crash-hunting, so
a simple loop that keeps inputs which reach new coverage is enough and runs on any target with zero
install burden. The impurity is entirely inside the injected `driver.send` and `tracer.collect`; the
control flow and the mutator are pure and DETERMINISTIC given a seed, so a fixed seed + fake driver
yields a fixed corpus (test 8). No `Math.random`-style ambient randomness.
"""
from __future__ import annotations

import random
import urllib.parse
from dataclasses import replace

from .base import Driver, Input, RuntimeTrace, Tracer

# Byte menu for mutation -- small, deterministic, security-flavoured (path traversal, template/JS
# injection, SQL/NoSQL metacharacters). Not exhaustive; enough to reach error branches.
_INJECT = [
    b"'", b'"', b"<script>", b"../../../../etc/passwd", b"{{7*7}}", b"$where",
    b"; ls", b"| id", b"\x00", b"%00", b"-1", b"0", b"true", b"[]", b"{}",
]


def _mutate(rng: random.Random, inp: Input) -> Input:
    """Derive one variant of `inp`. Pure given `rng`. Mutates the body/stdin and, occasionally, a
    query string on the path -- the attacker-controlled surfaces the graph's sources point at."""
    payload = rng.choice(_INJECT)
    if inp.kind == "http":
        if rng.random() < 0.5 and "?" not in inp.path:
            # Percent-encode the payload: raw control bytes (\x00 etc.) are illegal in a URL and
            # urllib rejects them with ValueError. The server still decodes them back on receipt.
            q = urllib.parse.quote(payload, safe="")
            return replace(inp, path=f"{inp.path}?q={q}", label=f"{inp.label}~q")
        return replace(inp, body=inp.body + payload, label=f"{inp.label}~b")
    return replace(inp, stdin=inp.stdin + payload, label=f"{inp.label}~s")


def _coverage_keys(trace: RuntimeTrace) -> set:
    return {(h.file_path, h.line) for h in trace.coverage}


def run(
    driver: Driver,
    tracer: Tracer,
    target,
    seeds: list[Input],
    *,
    budget: int = 200,
    seed: int = 1337,
    on_step=None,
) -> RuntimeTrace:
    """Drive `target` for up to `budget` inputs, keeping the ones that grow coverage as new parents.

    Deterministic: same seed + same driver/tracer responses -> same sequence of inputs. Returns the
    accumulated RuntimeTrace (coverage + any observed calls). `on_step(i, input, new_cov)` is an
    optional progress hook."""
    rng = random.Random(seed)
    corpus: list[Input] = list(seeds)
    seen: set = set()
    total = RuntimeTrace()
    sent = 0

    def _drive(inp: Input) -> set:
        """Send one input, fold its trace in, and return the NEW coverage keys it reached."""
        nonlocal total, sent
        driver.send(target, inp)
        sent += 1
        trace = tracer.collect(target.work, target.repo)
        total = total.merge(trace)
        new = _coverage_keys(trace) - seen
        if on_step is not None:
            on_step(sent, inp, len(new))
        tracer.reset(target.work)
        return new

    # Prime with the seeds first, then mutate the fruitful ones until the budget is spent.
    for inp in seeds:
        if sent >= budget:
            break
        new = _drive(inp)
        if new:
            seen |= new
            corpus.append(inp)

    while sent < budget and corpus:
        parent = corpus[rng.randrange(len(corpus))]
        child = _mutate(rng, parent)
        new = _drive(child)
        if new:
            seen |= new
            corpus.append(child)

    return total
