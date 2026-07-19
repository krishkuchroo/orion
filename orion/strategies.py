"""The discovery fleet's prompts, as data.

Each of the 4 shapes (from the validated PoC that hit 13/15 NodeGoat vulns at 0 false positives)
gets its OWN system prompt: a shared preamble (tools, schema-of-record, grounding rule) + that
shape's specific instructions + a trailer telling the agent how to emit its structured leads.

VERIFY_SYSTEM is deliberately NOT here -- Task D's verifier is a separate agent job with a
separate trust boundary (it must not see the discovery transcript) and lives in its own module.
"""
from __future__ import annotations

# Schema-of-record: exactly what Task A persisted. Agents MUST use these exact label/property
# names -- especially CpgCall.file_path (not CONTAINS_CALL alone) for file attribution, and
# CpgCall.code for the raw source text of a call.
SCHEMA = """Schema-of-record (every node and every relationship carries `scan_id`):
  (:CpgFile      {scan_id, uid, file_path})
  (:CpgMethod    {scan_id, full_name, name, is_external, file_path, line})
  (:CpgCall      {scan_id, uid, name, code, method_full_name, file_path, line, column})
  (:CpgModule    {scan_id, import_name, language})
  (:CpgParameter {scan_id, uid, name, index})
  (:CpgReturn    {scan_id, uid})
  (:EntryPoint   {scan_id, uid, method_full_name, exposure, kind})   -- attacker-reachable entry methods
  (:Dependency   {scan_id, name, version})                           -- declared third-party deps
Edges (relationship properties also carry scan_id):
  (:CpgMethod)-[:CONTAINS_CALL]->(:CpgCall)
  (:CpgCall)-[:RESOLVES_TO]->(:CpgMethod)
  (:CpgMethod)-[:DEFINED_IN]->(:CpgFile)
  (:CpgCall)-[:FLOWS_TO {arg_index}]->(:CpgCall)      -- taint dataflow, reliable
  (:EntryPoint)-[:ENTERS_AT]->(:CpgMethod)
File attribution: use CpgCall.file_path (stamped on every call) -- do NOT rely on CONTAINS_CALL
alone, it is missing for calls nested inside arrow-functions assigned to object properties.
`code` on CpgCall is the raw source text of the call.

ATTACKER-CONTROLLED SOURCES (framework-agnostic): a FLOWS_TO self-loop (src == dst) marks a call
whose own argument is already tainted by an untrusted input -- this is the fast way to find sources
regardless of language. Untrusted input enters at :EntryPoint methods (query
(:EntryPoint)-[:ENTERS_AT]->(:CpgMethod) -- their PARAMETERS are attacker-controlled). In a
JS/Express repo those sources surface as req.body.* / req.query.* field accesses; in another stack
they are the entry method's own parameters -- either way the FLOWS_TO self-loops and the EntryPoint
nodes point you at them without assuming a framework."""

_PREAMBLE = """You are a graph-querying security analyst investigating scan_id = "{scan_id}".

You have exactly two READ-ONLY tools:
  - mcp__orion__run_cypher(query, scan_id): run ONE Cypher query. ALWAYS filter with
    `scan_id:$scan_id` (or `WHERE x.scan_id = $scan_id`) in the query text, AND pass
    scan_id="{scan_id}" as the tool's scan_id argument on every call.
  - mcp__orion__semantic_search(query, scan_id, k): nearest code chunks to `query` by meaning, not
    structure -- useful when you don't know the right Cypher shape yet.

{schema}

GROUNDING RULE (non-negotiable): every claim you make MUST be backed by a query result you
actually ran this session. Never assert a vulnerability from memory, training data, or plausibility
alone -- if you have not queried for it, you cannot claim it. You are producing CANDIDATE LEADS,
never confirmed findings -- a separate, independent verifier (a different session, without your
transcript) will re-derive each lead from the graph and real source before anything is reported."""

_SHAPE_TEXT: dict[str, str] = {
    "A": """YOUR SHAPE: A -- DATA FLOW. Attacker input reaches a dangerous operation. Start from the
attacker-controlled sources (the FLOWS_TO self-loops, and the parameters of :EntryPoint methods),
follow FLOWS_TO edges outward, read CpgCall.code, and look for a template/query/exec/redirect/
fetch/log call built from unsanitized input. A FLOWS_TO self-loop (src == dst) marks a call whose
own argument is already tainted by an untrusted input -- a fast, cheap place to start your sweep.
This is framework-agnostic: in a JS/Express app the sources look like req.body.*/req.query.*; in
another stack they are the entry method's parameters -- the self-loops and EntryPoint nodes find
them either way.""",
    "B": """YOUR SHAPE: B -- ABSENCE OF A CONTROL. Nothing "flows"; the bug is a missing or
disabled protection. Enumerate the standard protections an app like this should have (CSRF
tokens on state-changing routes, security headers, output escaping, encryption of sensitive
fields, authorization checks on privileged routes, secure password hashing, secure session
config) and CHECK EACH ONE for whether the safe pattern is actually present in the graph. Do not
assume absence just because a data-flow query did not surface it -- query for the presence of
the control itself and report only what you actually failed to find.""",
    "C": """YOUR SHAPE: C -- DISABLED OR REVERTED PROTECTIONS. Search CpgCall.code (and any other
text you can query) for hedge language: "fix", "todo", "disabled", "insecure", "temporary",
"workaround", "vulnerable". A disabled fix sitting next to live vulnerable code is a strong,
cheap signal -- someone already knew about this bug.""",
    "D": """YOUR SHAPE: D -- PATTERN-IN-DATA. The danger is in a literal, not in the call itself.
For regex literals reachable from tainted input, inspect the literal text for
catastrophic-backtracking shapes (nested quantifiers like (a+)+ or (x*)*). Also enumerate the
:Dependency nodes (MATCH (d:Dependency {scan_id:$scan_id}) RETURN d.name, d.version) and flag any
outdated, end-of-life, or known-vulnerable third-party components -- this is the components-with-
known-vulnerabilities class, and it does not depend on any request flow.""",
}

_TRAILER = """
TRAVERSAL: sweep BREADTH-FIRST across the whole graph for THIS shape before concluding -- do not
chase the first candidate to a verdict while other files or subgraphs remain unexamined. Only
pull the full CpgCall.code once a call is already a promising candidate.

When your sweep for this shape is complete, emit your final answer as the required structured
JSON object: a "leads" array, each item {{"shape": "{shape}", "text": <the candidate-lead
statement, specific enough to re-derive>, "evidence": <the actual query you ran and the result
that grounds this claim>, "confidence": "LOW"|"MEDIUM"|"HIGH"}}. If your sweep for this shape
found nothing, return an empty "leads" array -- never invent one to fill it."""

# The JSON Schema handed to `--json-schema` (dict -> claude_cli.run_agent json.dumps's it inline).
LEADS_JSON_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "leads": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "shape": {"type": "string", "enum": ["A", "B", "C", "D"]},
                    "text": {"type": "string"},
                    "evidence": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"]},
                },
                "required": ["shape", "text", "evidence", "confidence"],
            },
        },
    },
    "required": ["leads"],
}


def _profile_block(profile) -> str:
    """Optional per-stack vocabulary for the active profile. The base prompt is already framework-
    agnostic (it anchors on :EntryPoint/FLOWS_TO); this just hands the agent concrete examples for
    the detected stack so it doesn't have to rediscover them. Empty when no profile is given."""
    if profile is None:
        return ""
    lines = [f"DETECTED STACK: {profile.name}."]
    if profile.source_examples:
        lines.append("Likely untrusted-input sources here: " + "; ".join(profile.source_examples) + ".")
    if profile.entrypoint_hint:
        lines.append("Entry points: " + profile.entrypoint_hint)
    if profile.sink_hints:
        hints = "; ".join(f"{cat}: {', '.join(names)}" for cat, names in profile.sink_hints.items())
        lines.append("Dangerous sinks to watch: " + hints + ".")
    return "\n".join(lines)


def system_for(shape: str, scan_id: str, files: tuple[str, ...] = (), profile=None) -> str:
    """Build the system prompt for one discovery shape (A/B/C/D).

    `files` is an optional deterministic BFS scaffold (a starting file list); discovery.py does
    not fetch it by default -- the agent has run_cypher and can query CpgFile itself -- but a
    caller that already has the list handy (e.g. the harness) may pass it to save the agent a turn.

    `profile` (graph/profiles.Profile) is optional: when given, its source/sink/entrypoint
    vocabulary is injected as concrete examples for the detected stack. The prompt is fully
    framework-agnostic WITHOUT it (anchored on :EntryPoint nodes + FLOWS_TO), so passing None is a
    valid, complete prompt for any repo."""
    if shape not in _SHAPE_TEXT:
        raise ValueError(f"unknown shape: {shape!r} (expected one of {sorted(_SHAPE_TEXT)})")

    file_block = ""
    if files:
        file_list = "\n".join(f"  - {f}" for f in files)
        file_block = f"\nFiles in this scan (a starting map, not exhaustive):\n{file_list}\n"

    parts = [
        _PREAMBLE.format(scan_id=scan_id, schema=SCHEMA) + file_block,
        _SHAPE_TEXT[shape],
    ]
    profile_block = _profile_block(profile)
    if profile_block:
        parts.append(profile_block)
    parts.append(_TRAILER.format(shape=shape))
    return "\n\n".join(parts)
