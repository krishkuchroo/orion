"""Machine failures vs. commit or model failures (shared by eval.precheck and the orion-lm arm).

A MACHINE failure is not the commit's or the model's doing: Neo4j unreachable, a dropped bolt
connection, an auth error, a missing Joern binary. The pre-check records it as "not_checked" (the
row is never moved); the orion-lm arm records the run "aborted" (not scored, re-attempted after
eval.run's --resume-wait), never as a terminal miss. A genuine build or model failure is not one.

  is_infra(exc)        exc, or anything in its __cause__/__context__ chain, is a machine failure:
                       an InfraError, a neo4j ServiceUnavailable / SessionExpired / AuthError (and
                       subclasses), a FileNotFoundError naming a joern binary, or an exception whose
                       text is a machine-failure text (below).
  is_infra_text(text)  `text` is "<Neo4jMachineError>: ..." optionally behind exception class names
                       ("RuntimeError: ServiceUnavailable: ..."), the form an error takes once
                       orion.graphdb.GraphDB.run_cypher has turned it into {"error": "<Class>: <msg>"}
                       and orion/lm/slice.py has re-raised it as RuntimeError. Anchored at the start, so
                       an error that merely quotes such a word (a Cypher syntax error echoing a query)
                       is not one.
  joern_missing()      the Joern executables the streaming build runs that are not there.
"""
import os
import re

_NEO4J_MACHINE = r"(?:\w*ServiceUnavailable|SessionExpired|AuthError)"
_INFRA_TEXT = re.compile(r"^(?:[A-Z]\w*: )*" + _NEO4J_MACHINE + r":")


class InfraError(RuntimeError):
    """The machine failed, not the commit or the model (e.g. a Joern binary is missing)."""


def is_infra_text(text) -> bool:
    return isinstance(text, str) and bool(_INFRA_TEXT.match(text.strip()))


def is_infra(exc) -> bool:
    """True when `exc` (or anything in its __cause__/__context__ chain) is a machine failure."""
    from neo4j.exceptions import AuthError, ServiceUnavailable, SessionExpired
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, (InfraError, ServiceUnavailable, SessionExpired, AuthError)):
            return True
        if isinstance(exc, FileNotFoundError) and "joern" in os.path.basename(str(exc.filename or "")):
            return True
        if is_infra_text(f"{exc.__class__.__name__}: {exc}"):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def joern_missing() -> list:
    """The Joern executables the streaming build runs (joern-parse, joern) that are not there."""
    from orion.graph import joern_adapter
    paths = (joern_adapter._joern_bin("joern-parse"), joern_adapter._joern_bin("joern"))
    return [str(p) for p in paths if not (p.is_file() and os.access(p, os.X_OK))]
