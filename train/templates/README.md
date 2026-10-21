# Stage 2 query templates

`train/templates/queries.json` does not exist yet. Krish writes it. Until it does, `stage2.trace_for`
returns `None` and `stage2.build` writes only the example rows (vulnerable / patched / negative), no
traces.

## Format

A JSON list of query strings. For every example, `stage2.trace_for` fills each template, runs the
queries in order through `orion.lm.tools.run_cypher` on the example's own scan (the patched example on
the patched scan, the others on the vulnerable scan), and ends the trace with a `final` action (the
lead for a vulnerable example, no leads for patched and negative ones).

Placeholders, filled with the case's uids as quoted Cypher string literals (the database binds only
`$scan_id`, so other values are inlined):

- `<<source_uid>>`
- `<<sink_uid>>`

Any other `<<name>>` is an error. Example:

    MATCH (c:CpgCall {scan_id:$scan_id}) WHERE c.uid = <<sink_uid>> RETURN c.code AS code

`stage2.load_templates` and `stage2.build` check every template with `orion.lm.tools.is_scoped`
(placeholders filled) before doing any work, and raise `ValueError` for a template that fails. A query
that errors at run time drops that trace (counted as `traces_dropped` in the ledger).

## Query rules (copied from the docstring of `orion/lm/tools.py`)

Neo4j also holds the PATCHED graph of the same CVE (the answer) and every training graph, so the
model's query must stay inside its own scan. Query rules, which the system prompt and the training
templates must follow:

1. Every labeled node pattern carries `scan_id:$scan_id` in its property map, exactly once.
2. A label-less node pattern, `(m)` or `()`, is allowed only inside a connected path that also has a
   node carrying `{scan_id:$scan_id}`. Edges only ever join nodes of the same scan (schema.emit_edge
   stamps scan_id on both endpoints; runtime OBSERVED_CALL matches both by scan_id), so such a
   neighbour is in-scan. Comma-separated patterns are separate paths. Variables are NOT trusted
   across clauses: re-scope a carried one, `WITH c MATCH (c:CpgCall {scan_id:$scan_id})-->(m)`.
3. No WHERE or IS inside parentheses: put conditions in a WHERE clause after the pattern.
4. Variable-length relationships need an upper bound <= MAX_VAR_LENGTH: `*1..3`, `*..12`, `*3`.
   No quantified paths or relationships (`+`, `*`, `{m,n}` after a relationship or a group).
5. Not allowed: writes, CALL, UNION, LOAD CSV, SHOW, TERMINATE, USE, FOREACH, `{ }` subqueries
   (EXISTS/COUNT/COLLECT/CALL), functions outside the built-in namespaces (apoc., db., dbms., gds.
   ...), backtick-quoted function names or map keys, label expressions (| & ! %), dynamic labels.
6. One statement, starting with MATCH, OPTIONAL MATCH, WITH, UNWIND or RETURN.

The checker fails closed: whatever it cannot classify with confidence is rejected, with a short
message naming the offending part (as written).

Execution (also from `tools.py`): `run_cypher` checks for write keywords, then the static check, then
an EXPLAIN pre-flight whose plan must be read-only (query type "r"), then runs the query. Both database
calls use a READ-access session with a `QUERY_TIMEOUT_S` (10 s) transaction timeout, and at most
`ROW_LIMIT` (25) rows are fetched. `MAX_VAR_LENGTH` is 12.
