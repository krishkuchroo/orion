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


def index(repo_path: str, scan_id: str) -> None:
    """Chunk `repo_path`'s code (per the loaded graph for `scan_id`), embed each chunk locally,
    and store the vectors as Chunk nodes so `search` can retrieve them for this scan. Idempotent:
    clears this scan's existing Chunk nodes first, then writes fresh ones."""
    _require_neo4j_backend()
    if not os.path.isdir(repo_path):
        raise ValueError(f"repo_path does not exist or is not a directory: {repo_path}")

    model = _get_model()
    driver = _driver()
    try:
        with driver.session(database=config.NEO4J_DATABASE) as session:
            _ensure_vector_index(session)
            session.run("MATCH (c:Chunk {scan_id: $scan_id}) DETACH DELETE c", scan_id=scan_id)

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
