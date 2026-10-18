"""Model seam for Orion-LM. This module holds only `GenResult` for now; Task B4 adds the MLX and
llama-cpp wrappers behind lazy imports, so importing this module never pulls in MLX.

The prompter consumes a single `generate(messages: list[dict]) -> GenResult` callable and reads only
`.text` and the three token counts. The counts are MEASURED by the model wrapper (tokenizer / prompt
cache offset) — never estimated anywhere downstream.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class GenResult:
    text: str
    prompt_tokens: int
    completion_tokens: int
    cached_tokens: int
