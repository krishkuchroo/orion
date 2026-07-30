"""The semantic index that complements the structural graph.

The graph answers "what calls what". This answers "where is X handled", by meaning. It backs the
`semantic_search` MCP tool (orion/mcp_server.py) so a discovery agent can ask, for example, "where
is authentication enforced?" and get relevant code chunks, not just a call subtree.

Chunking: one chunk per internal (non-external) CpgMethod — read `full_name`/`file_path`/`line`
from the graph, then read a ~40-line source window starting at `line` off disk (we don't have an
end line, so a fixed window is the pragmatic choice). Files with zero internal methods fall back
to fixed ~60-line blocks. Chunks are stored as dedicated `(:Chunk {scan_id, file, span, text,
embedding})` nodes — kept separate from `CpgMethod` so the semantic layer never pollutes the
structural graph GraphDB reads.

Backend: `config.SEMANTIC_BACKEND` selects the vector store. "neo4j" (default) uses Neo4j's native
vector index and is the only backend implemented here; writes go straight through the `neo4j`
driver (not GraphDB, which is read-only by design). "lancedb" is a documented swap-point, stubbed
below with a clear NotImplementedError.

Embeddings: `config.EMBED_MODEL` (jinaai/jina-embeddings-v2-base-code) via sentence-transformers,
loaded locally (no API key, `trust_remote_code=True`), 768-dim vectors, lazy module-level singleton
so the ~300MB model loads once per process.
"""
from __future__ import annotations

import os
import threading

from neo4j import GraphDatabase

from . import config

EMBED_DIM = 768
VECTOR_INDEX_NAME = "chunk_embedding_index"
METHOD_LINE_WINDOW = 40
FALLBACK_BLOCK_LINES = 60

# The GLOBAL exploit-reference corpus (not scan_id-scoped, like get_schema): a dedicated label +
# vector index so it never mixes with per-scan Chunk nodes. See orion/exploit_corpus.py.
EXPLOIT_LABEL = "ExploitChunk"
EXPLOIT_VECTOR_INDEX_NAME = "exploit_embedding_index"

_model = None
_model_lock = threading.Lock()


def _patch_transformers_compat() -> None:
    """jina-embeddings-v2-base-code ships its own `trust_remote_code=True` modeling file, pinned
    to `transformers==4.35.2`-era APIs. The `transformers` installed here (5.x) removed several of
    those APIs, so the remote code fails at import/forward time with no way to pin an older
    `transformers` (we don't pip install). Shim the missing pieces back in with their historical
    implementations — pure, self-contained, no dependency on anything else removed — so the remote
    model code runs unmodified. Each shim is a no-op if the installed `transformers` already
    provides it, so this stays harmless if/when the environment's `transformers` changes.
    """
    import torch
    import transformers.pytorch_utils as pt_utils
    from transformers.configuration_utils import PreTrainedConfig
    from transformers.modeling_utils import PreTrainedModel

    # 1) `from transformers.pytorch_utils import find_pruneable_heads_and_indices` (removed).
    if not hasattr(pt_utils, "find_pruneable_heads_and_indices"):

        def find_pruneable_heads_and_indices(heads, n_heads, head_size, already_pruned_heads):
            mask = torch.ones(n_heads, head_size)
            heads = set(heads) - already_pruned_heads
            for head in heads:
                head = head - sum(1 if h < head else 0 for h in already_pruned_heads)
                mask[head] = 0
            mask = mask.view(-1).contiguous().eq(1)
            index = torch.arange(len(mask))[mask].long()
            return heads, index

        pt_utils.find_pruneable_heads_and_indices = find_pruneable_heads_and_indices

    # 2) `config.is_decoder` / `.add_cross_attention` / `.chunk_size_feed_forward` — PreTrainedConfig
    # no longer sets these encoder/decoder-era defaults; the old modeling file reads them directly.
    _legacy_config_defaults = {
        "is_decoder": False,
        "add_cross_attention": False,
        "chunk_size_feed_forward": 0,
    }
    if not getattr(PreTrainedConfig, "_orion_legacy_getattr_patched", False):
        _orig_config_getattr = getattr(PreTrainedConfig, "__getattr__", None)

        def _config_getattr(self, key, _orig=_orig_config_getattr, _defaults=_legacy_config_defaults):
            if _orig is not None:
                try:
                    return _orig(self, key)
                except AttributeError:
                    pass
            if key in _defaults:
                return _defaults[key]
            raise AttributeError(key)

        PreTrainedConfig.__getattr__ = _config_getattr
        PreTrainedConfig._orion_legacy_getattr_patched = True

    # 3) `model.get_head_mask(...)` — removed from PreTrainedModel; old modeling file calls it
    # unconditionally. head_mask is always None for our use (plain embedding forward pass).
    if not hasattr(PreTrainedModel, "get_head_mask"):

        def _convert_head_mask_to_5d(self, head_mask, num_hidden_layers):
            if head_mask.dim() == 1:
                head_mask = head_mask.unsqueeze(0).unsqueeze(0).unsqueeze(-1).unsqueeze(-1)
                head_mask = head_mask.expand(num_hidden_layers, -1, -1, -1, -1)
            elif head_mask.dim() == 2:
                head_mask = head_mask.unsqueeze(1).unsqueeze(-1).unsqueeze(-1)
            return head_mask.to(dtype=self.dtype)

        def get_head_mask(self, head_mask, num_hidden_layers, is_attention_chunked=False):
            if head_mask is not None:
                head_mask = self._convert_head_mask_to_5d(head_mask, num_hidden_layers)
                if is_attention_chunked is True:
                    head_mask = head_mask.unsqueeze(-1)
            else:
                head_mask = [None] * num_hidden_layers
            return head_mask

        PreTrainedModel._convert_head_mask_to_5d = _convert_head_mask_to_5d
        PreTrainedModel.get_head_mask = get_head_mask


def _get_model():
    """Lazy singleton: load the local embedding model once per process."""
    global _model
    if _model is not None:
        return _model
    with _model_lock:
        if _model is None:
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:
                raise RuntimeError(
                    "sentence-transformers is not installed; cannot embed code chunks"
                ) from exc
            _patch_transformers_compat()
            try:
                _model = SentenceTransformer(config.EMBED_MODEL, trust_remote_code=True)
            except Exception as exc:  # noqa: BLE001 — surface as one clear, actionable error
                raise RuntimeError(
                    f"failed to load embedding model {config.EMBED_MODEL!r}: "
                    f"{exc.__class__.__name__}: {exc}"
                ) from exc
    return _model


def _driver():
    try:
        driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
        driver.verify_connectivity()
        return driver
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"cannot connect to Neo4j at {config.NEO4J_URI}: {exc}") from exc


def _require_neo4j_backend() -> None:
    if config.SEMANTIC_BACKEND == "lancedb":
        raise NotImplementedError(
            "LanceDB backend is not implemented; set ORION_SEMANTIC_BACKEND=neo4j "
            "(the native Neo4j vector index is the fully-supported backend)."
        )
    if config.SEMANTIC_BACKEND != "neo4j":
        raise RuntimeError(f"unknown SEMANTIC_BACKEND {config.SEMANTIC_BACKEND!r}")


def _ensure_vector_index(session) -> None:
    session.run(
        f"""
        CREATE VECTOR INDEX {VECTOR_INDEX_NAME} IF NOT EXISTS
        FOR (c:Chunk) ON (c.embedding)
        OPTIONS {{indexConfig: {{
            `vector.dimensions`: $dims,
            `vector.similarity_function`: 'cosine'
        }}}}
        """,
        dims=EMBED_DIM,
    )


def _read_window(repo_path: str, file_path: str, start_line: int, num_lines: int):
    """Read a line window from `file_path` (relative to repo_path) starting at 1-indexed
    `start_line`. Returns (text, end_line) or None if the file/line can't be read."""
    full = os.path.join(repo_path, file_path)
    try:
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return None
    start_idx = max(start_line - 1, 0)
    if not lines or start_idx >= len(lines):
        return None
    end_idx = min(start_idx + num_lines, len(lines))
    text = "".join(lines[start_idx:end_idx])
    if not text.strip():
        return None
    return text, start_idx + (end_idx - start_idx)  # 1-indexed inclusive end line


def _build_chunks(repo_path: str, methods: list[dict], all_files: list[str]) -> list[dict]:
    """One chunk per internal method's source window; files with no such method fall back to
    fixed-size blocks over the whole file. Returns [{"file","span","text"}]."""
    chunks: list[dict] = []
    files_with_methods: set[str] = set()

    for m in methods:
        file_path, line = m["file_path"], m["line"]
        if file_path is None or line is None:
            continue
        window = _read_window(repo_path, file_path, line, METHOD_LINE_WINDOW)
        if window is None:
            continue
        text, end_line = window
        files_with_methods.add(file_path)
        chunks.append({
            "file": file_path,
            "span": f"{file_path}:{line}-{end_line}",
            "text": text,
        })

    for file_path in all_files:
        if file_path in files_with_methods:
            continue
        full = os.path.join(repo_path, file_path)
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        for start in range(0, len(lines), FALLBACK_BLOCK_LINES):
            block = lines[start:start + FALLBACK_BLOCK_LINES]
            if not any(line.strip() for line in block):
                continue
            chunks.append({
                "file": file_path,
                "span": f"{file_path}:{start + 1}-{start + len(block)}",
                "text": "".join(block),
            })

    return chunks


def _spans_from_graph(session, scan_id: str) -> tuple[list[dict], list[str]]:
    """The (methods, all_files) span inputs `index` needs, read from the PERSISTED graph. Methods:
    CpgMethod with a non-null file_path AND line, (full_name, file_path, line) ordered by
    (file_path, line). Files: distinct CpgFile.file_path, ordered. Used when no in-memory batch is
    supplied (the --scan-id path, where the graph already exists)."""
    methods = [
        dict(r) for r in session.run(
            "MATCH (m:CpgMethod {scan_id: $scan_id}) "
            "WHERE m.file_path IS NOT NULL AND m.line IS NOT NULL "
            "RETURN m.full_name AS full_name, m.file_path AS file_path, m.line AS line "
            "ORDER BY m.file_path, m.line",
            scan_id=scan_id,
        )
    ]
    all_files = [
        r["file_path"] for r in session.run(
            "MATCH (f:CpgFile {scan_id: $scan_id}) "
            "RETURN f.file_path AS file_path ORDER BY file_path",
            scan_id=scan_id,
        )
    ]
    return methods, all_files


def _spans_from_batch(batch) -> tuple[list[dict], list[str]]:
    """The same (methods, all_files) inputs, derived from the IN-MEMORY `schema.Batch` instead of a
    graph query -- so indexing does NOT depend on persist having finished and can run concurrently
    with it (item 4). Reproduces `_spans_from_graph` on the batch persist would write: CpgMethod is
    deduped by full_name (NODE_KEY) by UNIONING props across duplicate rows, then filtered to
    non-null file_path AND line, projected, and ordered by (file_path, line); CpgFile is distinct
    file_path, ordered.

    The union (NOT a plain replace) is load-bearing and must track `persist._node_rows`: Joern emits
    several CpgMethod rows sharing a full_name -- an internal definition carrying FILENAME/LINE_NUMBER
    and an external stub carrying neither -- and `normalize` OMITS file_path/line rather than setting
    them to None. Under a replace, a trailing stub row would erase the span the earlier row set, and
    the non-null-span filter below would then drop the method from the semantic index entirely (a
    silent recall loss: the function becomes invisible to `semantic_search`). Persist fixed exactly
    this by unioning; this path is the mirror and has to agree, or the concurrent batch-fed index and
    the persisted graph disagree about which methods exist."""
    by_fullname: dict = {}                          # union dedup == persist._node_rows / MERGE SET n +=
    files: set = set()
    for label, props in batch.nodes:
        if label == "CpgMethod":
            fn = props.get("full_name")
            by_fullname[fn] = {**by_fullname.get(fn, {}), **props}
        elif label == "CpgFile":
            fp = props.get("file_path")
            if fp is not None:
                files.add(fp)
    methods = [
        {"full_name": p.get("full_name"), "file_path": p.get("file_path"), "line": p.get("line")}
        for p in by_fullname.values()
        if p.get("file_path") is not None and p.get("line") is not None
    ]
    methods.sort(key=lambda m: (m["file_path"], m["line"]))
    return methods, sorted(files)


def index(repo_path: str, scan_id: str, *, batch=None) -> None:
    """Chunk `repo_path`'s code (per the graph for `scan_id`), embed each chunk locally, and store
    the vectors as Chunk nodes so `search` can retrieve them for this scan. Idempotent: clears this
    scan's existing Chunk nodes first, then writes fresh ones.

    `batch` (a `schema.Batch`) is the item-4 overlap hook: when given, the code spans come from the
    in-memory batch (`_spans_from_batch`) rather than a graph query, so indexing does not wait on
    persist and can run concurrently with it. When None (the --scan-id path), spans are read from the
    already-persisted graph."""
    _require_neo4j_backend()
    if not os.path.isdir(repo_path):
        raise ValueError(f"repo_path does not exist or is not a directory: {repo_path}")

    model = _get_model()
    driver = _driver()
    try:
        with driver.session(database=config.NEO4J_DATABASE) as session:
            _ensure_vector_index(session)
            session.run("MATCH (c:Chunk {scan_id: $scan_id}) DETACH DELETE c", scan_id=scan_id)
            if batch is None:
                methods, all_files = _spans_from_graph(session, scan_id)
            else:
                methods, all_files = _spans_from_batch(batch)

        chunks = _build_chunks(repo_path, methods, all_files)
        if not chunks:
            return  # scan cleared above; nothing to embed (e.g. empty repo) — not an error

        texts = [c["text"] for c in chunks]
        vectors = model.encode(texts, batch_size=16, show_progress_bar=False, convert_to_numpy=True)

        rows = [
            {"file": c["file"], "span": c["span"], "text": c["text"], "embedding": vec.tolist()}
            for c, vec in zip(chunks, vectors)
        ]
        with driver.session(database=config.NEO4J_DATABASE) as session:
            session.run(
                "UNWIND $rows AS row "
                "CREATE (c:Chunk {scan_id: $scan_id, file: row.file, span: row.span, "
                "text: row.text, embedding: row.embedding})",
                scan_id=scan_id, rows=rows,
            )
    finally:
        driver.close()


def _ensure_exploit_vector_index(session) -> None:
    session.run(
        f"""
        CREATE VECTOR INDEX {EXPLOIT_VECTOR_INDEX_NAME} IF NOT EXISTS
        FOR (c:{EXPLOIT_LABEL}) ON (c.embedding)
        OPTIONS {{indexConfig: {{
            `vector.dimensions`: $dims,
            `vector.similarity_function`: 'cosine'
        }}}}
        """,
        dims=EMBED_DIM,
    )


def exploit_index_ready() -> bool:
    """True if the exploit-reference vector index exists AND has at least one ExploitChunk node."""
    _require_neo4j_backend()
    driver = _driver()
    try:
        with driver.session(database=config.NEO4J_DATABASE) as session:
            has_index = session.run(
                "SHOW INDEXES YIELD name WHERE name = $name RETURN count(*) AS c",
                name=EXPLOIT_VECTOR_INDEX_NAME,
            ).single()["c"]
            if not has_index:
                return False
            n = session.run(f"MATCH (c:{EXPLOIT_LABEL}) RETURN count(c) AS c").single()["c"]
            return n > 0
    finally:
        driver.close()


def index_exploits(metadata_path: str | None = None, *, metadata: dict | None = None,
                   model=None) -> int:
    """Build the GLOBAL exploit-reference corpus: distill MSF module records into ExploitChunk nodes
    with embeddings, behind a dedicated vector index. NOT scan_id-scoped. Idempotent: clears any
    existing ExploitChunk nodes first, then writes fresh ones. Returns the number of docs indexed.

    `metadata` (in-memory dict) takes precedence over `metadata_path` (defaults to the gitignored
    fixtures file); `model` is injectable for tests. Raises FileNotFoundError if neither is available.
    """
    from . import exploit_corpus

    _require_neo4j_backend()
    if metadata is None:
        path = metadata_path or exploit_corpus.DEFAULT_METADATA_PATH
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"exploit metadata not found at {path!r}; run `orion index-exploits` "
                "(it fetches the Metasploit index first) or call exploit_corpus.fetch_metadata()"
            )
        metadata = exploit_corpus.load_metadata(path)

    docs = exploit_corpus.to_documents(metadata)
    model = model or _get_model()
    driver = _driver()
    try:
        with driver.session(database=config.NEO4J_DATABASE) as session:
            _ensure_exploit_vector_index(session)
            session.run(f"MATCH (c:{EXPLOIT_LABEL}) DETACH DELETE c")
        if not docs:
            return 0
        vectors = model.encode([d.text for d in docs], batch_size=16,
                               show_progress_bar=False, convert_to_numpy=True)
        rows = [
            {"module": d.module, "name": d.name, "cves": list(d.cves), "rank": d.rank,
             "mtype": d.mtype, "disclosure_date": d.disclosure_date, "path": d.path,
             "text": d.text, "embedding": vec.tolist()}
            for d, vec in zip(docs, vectors)
        ]
        with driver.session(database=config.NEO4J_DATABASE) as session:
            session.run(
                f"UNWIND $rows AS row CREATE (c:{EXPLOIT_LABEL} {{"
                "module: row.module, name: row.name, cves: row.cves, rank: row.rank, "
                "mtype: row.mtype, disclosure_date: row.disclosure_date, path: row.path, "
                "text: row.text, embedding: row.embedding})",
                rows=rows,
            )
            # Wait for the vector index to finish populating so the very next exploit_search sees
            # the freshly written nodes (same discipline as persist.py's range indexes).
            session.run("CALL db.awaitIndexes(60)")
        return len(rows)
    finally:
        driver.close()


def ensure_exploit_index(metadata_path: str | None = None) -> bool:
    """Build the exploit corpus ONLY if it isn't already indexed AND the metadata file is present
    locally (never triggers a surprise download inside a scan). Returns True if the corpus is ready
    for exploit_search afterwards, else False. Intended as a best-effort caller wrapper."""
    from . import exploit_corpus
    if exploit_index_ready():
        return True
    path = metadata_path or exploit_corpus.DEFAULT_METADATA_PATH
    if not os.path.exists(path):
        return False
    index_exploits(path)
    return True


def exploit_search(query: str, k: int = 5, model=None) -> list[dict]:
    """Nearest exploit-reference modules to `query` from the GLOBAL corpus (NOT scan-scoped), best
    first. Returns [] if the corpus has never been indexed (not an error). Each result carries
    module, name, cves, rank, disclosure_date, text, score. `model` is injectable for tests."""
    _require_neo4j_backend()
    driver = _driver()
    try:
        with driver.session(database=config.NEO4J_DATABASE) as session:
            has_index = session.run(
                "SHOW INDEXES YIELD name WHERE name = $name RETURN count(*) AS c",
                name=EXPLOIT_VECTOR_INDEX_NAME,
            ).single()["c"]
            if not has_index:
                return []
            model = model or _get_model()
            query_vector = model.encode(query, convert_to_numpy=True).tolist()
            result = session.run(
                f"CALL db.index.vector.queryNodes('{EXPLOIT_VECTOR_INDEX_NAME}', $k, $query_vector) "
                "YIELD node, score "
                "RETURN node.module AS module, node.name AS name, node.cves AS cves, "
                "node.rank AS rank, node.disclosure_date AS disclosure_date, "
                "node.text AS text, score ORDER BY score DESC LIMIT $k",
                k=k, query_vector=query_vector,
            )
            return [dict(r) for r in result]
    finally:
        driver.close()


def search(query: str, scan_id: str, k: int = 5) -> list[dict]:
    """Nearest code chunks to `query` (by meaning), scoped to `scan_id`, best first. Returns []
    if this scan has never been indexed (no vector index yet, or no matching chunks) — that is
    not an error. A missing model or an unreachable DB still raises."""
    _require_neo4j_backend()
    driver = _driver()
    try:
        with driver.session(database=config.NEO4J_DATABASE) as session:
            has_index = session.run(
                "SHOW INDEXES YIELD name WHERE name = $name RETURN count(*) AS c",
                name=VECTOR_INDEX_NAME,
            ).single()["c"]
            if not has_index:
                return []

            # Load the (~300MB) model only once we know there IS an index to search -- a
            # never-indexed scan returns [] without paying the model load.
            model = _get_model()
            query_vector = model.encode(query, convert_to_numpy=True).tolist()
            top_k = max(k * 20, 200)  # overfetch: Neo4j's ANN search isn't scan-filtered upstream
            result = session.run(
                f"CALL db.index.vector.queryNodes('{VECTOR_INDEX_NAME}', $top_k, $query_vector) "
                "YIELD node, score "
                "WHERE node.scan_id = $scan_id "
                "RETURN node.file AS file, node.span AS span, node.text AS text, score "
                "ORDER BY score DESC LIMIT $k",
                top_k=top_k, query_vector=query_vector, scan_id=scan_id, k=k,
            )
            return [dict(r) for r in result]
    finally:
        driver.close()
