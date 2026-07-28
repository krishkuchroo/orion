"""Central configuration for Orion, read from the environment with standalone defaults.

Orion runs its OWN Neo4j (see docker-compose.yml) on ports 7688/7475 — it does NOT use
sentryV2's instance. Load your .env however you like (for example `set -a; source .env; set +a`)
before running; this module only reads os.environ with sensible localhost defaults.
"""
import os


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


# --- Orion's own code graph (Neo4j Community, standalone) ---
NEO4J_URI = _env("NEO4J_URI", "bolt://localhost:7688")
NEO4J_AUTH = (_env("NEO4J_USER", "neo4j"), _env("NEO4J_PASSWORD", "orion_dev_changeme"))
NEO4J_DATABASE = _env("NEO4J_DATABASE", "neo4j")  # Community edition = single default database

# --- Graph build (native Joern; no sentryV2 dependency) ---
JOERN_HOME = os.path.expanduser(_env("JOERN_HOME", "~/joern/joern-cli"))
# Joern JVM heap for the parse/producer subprocess. The JVM's ~25%-of-RAM default OOMs large graphs,
# so _jvm_flags hands it `-J-Xmx` sized to THIS machine. Both knobs are tunable for a side-by-side or
# a constrained/shared box: JOERN_HEAP_FRACTION is the fraction of physical RAM to claim (default
# 0.75 == the prior hard-coded value, so the default is behavior-preserving); JOERN_HEAP_GB, when set
# to a positive number, is an EXACT `-Xmx{N}g` that wins outright (skips RAM detection entirely).
JOERN_HEAP_FRACTION = float(_env("ORION_JOERN_HEAP_FRACTION", "0.75"))
JOERN_HEAP_GB = _env("ORION_JOERN_HEAP_GB", "").strip()   # "" -> derive from RAM*fraction; else exact GB

# --- Headless `claude -p` settings for discovery and verification ---
MODEL = _env("ORION_MODEL", "sonnet")
EFFORT = _env("ORION_EFFORT", "high")
MAX_TURNS = int(_env("ORION_MAX_TURNS", "40"))
VERIFY_MAX_TURNS = int(_env("ORION_VERIFY_MAX_TURNS", "10"))
# Generic fallback timeout for any run_agent call that does NOT pass its own. Discovery and
# verification below both pass explicit, purpose-sized timeouts, so this only bites a future caller.
CALL_TIMEOUT = int(_env("ORION_CALL_TIMEOUT", "180"))
# How many per-lead verifier sessions run at once. Verification is the wall-clock bottleneck (each
# lead is an independent fresh claude -p session), so it fans out; the cap keeps a big lead set from
# spawning an unbounded number of processes / tripping API rate limits. Set 1 for strictly sequential.
VERIFY_CONCURRENCY = int(_env("ORION_VERIFY_CONCURRENCY", "4"))

# --- Reality-based per-call timeouts (a flat 180s was too low; see discover_timeout below) ---
# A discovery shape is a full agentic session: MODEL at EFFORT=high looping run_cypher for up to
# MAX_TURNS turns. At ~5-10s/turn a full 40-turn sweep needs ~300-400s, and public telemetry for
# agentic coding requests puts the p90 near ~384s (avg ~258s) -- so the old flat 180s sat BELOW the
# average and silently killed thorough sweeps mid-turn on large graphs (empirically: 5 timeouts on
# the ~80k-node sharpemu scan; small validated repos like NodeGoat finish well under it). Discovery
# now floors at DISCOVER_TIMEOUT (>= p90 and a full MAX_TURNS budget) and grows with graph size,
# because a bigger graph is a bigger search space (more queries, more turns to triage), capped so a
# stuck agent still dies. The per-node slope is a heuristic anchored to one large-repo data point
# (sharpemu ~80k nodes -> ~900s), not a measured law; override any of these via env if repos differ.
# Small repos never actually reach the floor -- it caps how long we WAIT, not how long we RUN.
DISCOVER_TIMEOUT = int(_env("ORION_DISCOVER_TIMEOUT", "420"))            # seconds; per-shape floor
DISCOVER_TIMEOUT_PER_NODE = float(_env("ORION_DISCOVER_TIMEOUT_PER_NODE", "0.006"))  # +sec / graph node
DISCOVER_TIMEOUT_CAP = int(_env("ORION_DISCOVER_TIMEOUT_CAP", "1200"))   # seconds; hard ceiling (20 min)
# Verification is a focused re-derivation (VERIFY_MAX_TURNS=10) but fp-check spawns its own nested
# subagents, so it gets its own headroom -- separate from discovery, which scales with graph size.
VERIFY_TIMEOUT = int(_env("ORION_VERIFY_TIMEOUT", "300"))                # seconds per lead


def discover_timeout(node_count: int | None) -> int:
    """Reality-based per-shape discovery timeout that scales with graph size.

    Floor DISCOVER_TIMEOUT (chosen above the industry p90 for agentic coding requests and above a
    full MAX_TURNS sweep), plus DISCOVER_TIMEOUT_PER_NODE per persisted graph node, clamped to
    DISCOVER_TIMEOUT_CAP. A missing/zero/negative count falls back to the floor. Pure and monotonic
    non-decreasing in node_count -- unit-tested without a DB or a subprocess.
    """
    if not node_count or node_count <= 0:
        return DISCOVER_TIMEOUT
    scaled = DISCOVER_TIMEOUT + int(DISCOVER_TIMEOUT_PER_NODE * node_count)
    return max(DISCOVER_TIMEOUT, min(scaled, DISCOVER_TIMEOUT_CAP))

# --- MCP tool server the agents call (real tool-calling, not the old text protocol) ---
MCP_CONFIG = _env("ORION_MCP_CONFIG", ".mcp/orion.json")

# --- Semantic index: "neo4j" (native vector index) or "lancedb" (standalone fallback) ---
SEMANTIC_BACKEND = _env("ORION_SEMANTIC_BACKEND", "neo4j")
EMBED_MODEL = _env("ORION_EMBED_MODEL", "jinaai/jina-embeddings-v2-base-code")
