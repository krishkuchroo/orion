"""Orion: a GraphRAG code-security-intelligence demo.

Point it at a repo. It builds a code graph, runs a fleet of Claude agents that discover
security issues by reasoning over the graph, grounds every claim with a read-only Cypher
query, and has a separate agent verify each lead before it is reported.
"""

__version__ = "0.1.0"
