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

# --- Headless `claude -p` settings for discovery and verification ---
MODEL = _env("ORION_MODEL", "sonnet")
EFFORT = _env("ORION_EFFORT", "high")
MAX_TURNS = int(_env("ORION_MAX_TURNS", "40"))
VERIFY_MAX_TURNS = int(_env("ORION_VERIFY_MAX_TURNS", "10"))
CALL_TIMEOUT = int(_env("ORION_CALL_TIMEOUT", "180"))
# How many per-lead verifier sessions run at once. Verification is the wall-clock bottleneck (each
# lead is an independent fresh claude -p session), so it fans out; the cap keeps a big lead set from
# spawning an unbounded number of processes / tripping API rate limits. Set 1 for strictly sequential.
VERIFY_CONCURRENCY = int(_env("ORION_VERIFY_CONCURRENCY", "4"))

# --- MCP tool server the agents call (real tool-calling, not the old text protocol) ---
MCP_CONFIG = _env("ORION_MCP_CONFIG", ".mcp/orion.json")

# --- Semantic index: "neo4j" (native vector index) or "lancedb" (standalone fallback) ---
SEMANTIC_BACKEND = _env("ORION_SEMANTIC_BACKEND", "neo4j")
EMBED_MODEL = _env("ORION_EMBED_MODEL", "jinaai/jina-embeddings-v2-base-code")
