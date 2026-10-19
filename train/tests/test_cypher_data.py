import json

from train import cypher_data


def _write(tmp_path, rows):
    p = tmp_path / "t.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows))
    return str(p)


ROWS = [{"data_source": "llm_x", "question": "q0", "cypher": "c0", "schema": "s0"},
        {"data_source": "functional_cypher", "question": "q1", "cypher": "c1", "schema": "s1"},
        {"data_source": "human_x", "question": "q2", "cypher": "c2", "schema": "s2"},
        {"question": "q3", "cypher": "c3", "schema": "s3"}]


def test_keeps_only_allowed_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(cypher_data, "ALLOWED_SOURCES", ("human_x",))
    out = cypher_data.load_text2cypher(_write(tmp_path, ROWS))
    assert out == [{"messages": [{"role": "system", "content": "Write one Cypher query for this schema."},
                                 {"role": "user", "content": "s2\n\nq2"}],
                    "target": "c2"}]


def test_shipped_allowlist_is_empty_so_nothing_unverified_is_kept(tmp_path):
    assert cypher_data.ALLOWED_SOURCES == ()
    assert cypher_data.load_text2cypher(_write(tmp_path, ROWS)) == []
