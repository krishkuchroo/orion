"""Model seam for Orion-LM: `generate(messages) -> GenResult` over a local 4-bit model.

Two wrappers expose the one seam the prompter consumes: `MlxModel` (MLX-LM, Apple silicon) and the
`LlamaCppModel` fallback (llama-cpp-python over a GGUF). `load(path, **sampling)` picks one. Nothing in
this module touches the network at inference time: a model is loaded from a local directory or from the
local Hugging Face cache (`local_files_only=True`); downloading is a one-time setup step done elsewhere.

MLX / Outlines / llama_cpp are imported lazily inside the classes, so `from orion.lm.model import
GenResult` works on a machine without any of them (the prompter tests use a scripted `generate`).

Counts in `GenResult` are MEASURED, never estimated:
- `prompt_tokens`     = number of tokens fed for this prompt (cached + prefilled)
- `completion_tokens` = number of tokens the model emitted, INCLUDING the turn-end token it stopped on
- `cached_tokens`     = prompt tokens served from the KV cache = length of the common prefix between
  the previous call's cached token sequence (its prompt + its reply) and this prompt. The history is
  append-only, so the normal case is an exact extension: cached_tokens == previous prompt_tokens +
  completion_tokens. When the new prompt is NOT an extension, the cache is trimmed back to the common
  prefix if the cache type allows it (plain KVCache), otherwise reset (cached_tokens = 0).

Three facts measured on this machine with mlx-community/gemma-3-1b-it-4bit (details and numbers in
.superpowers/sdd/2026-10-18-orion-lm/task-B4-report.md):
1. Gemma's chat template raises `Conversation roles must alternate` on two consecutive `user` turns,
   which the prompter produces at the forced final (RESULT:/ERROR: turn, then the forced-final turn).
   `merge_consecutive_roles` joins consecutive same-role messages with a blank line before the template
   is applied, ALWAYS (not only for Gemma), so the training cutter (Task D5) applies the identical,
   model-independent merge.
2. The model's own tokens for its reply are not always the canonical tokenization of the same text
   (it emitted `[]` `}` where the tokenizer re-encodes `[]}` as one token). Re-tokenizing the history
   therefore diverges from the cache a few tokens before the end of the reply, and Gemma's sliding-window
   RotatingKVCache cannot be trimmed once it holds >512 tokens, so every such turn would reset the cache.
   Hence `prompt_tokens` SPLICES: when the new prompt text starts with the previous prompt text + the
   previous reply text, the model's own reply tokens (already in the cache) are kept and only the text
   after the reply is tokenized. The text the model conditions on is byte-identical to the training
   text; only the token boundaries inside its own past reply differ (as in every KV-cached chat server).
   TRAINING/RUNTIME GAP, stated plainly: Task D5 trains on the CANONICAL tokenization of the whole
   history, while at runtime the model's own past replies stay in its own tokenization. `GenResult.spliced`
   says whether a call took the spliced path, so Task C2 can A/B "splice" against "canonical re-tokenize
   + cache reset" on the dev set before any bake-off number is trusted; `reset_cache()` before a call
   forces the canonical path.

Caps: `context_cap` here is the HARD limit — a prompt above it raises `ContextOverflow`, nothing is
truncated. The prompter's `context_cap` is a budget that must sit at least one turn + reply lower
(`prompter.CONTEXT_MARGIN`, 1024 suggested), because its forced-final prompt is always longer than the call
that tripped the budget. The prompter catches `ContextOverflow` and ends the session with zero leads.
3. A constrained (Outlines) turn ends with the EOS token the Outlines vocabulary was built with. If that
   is the tokenizer's `<eos>` instead of the template's turn-end token (`<end_of_turn>` for Gemma), the
   cache and the template disagree at that one token and (2) applies. So the Outlines vocabulary is built
   with the TEMPLATE's turn-end token (`turn_end_id`), which is also added to the stop set. Beware: that
   token must be the ONE right after the reply; Gemma's `\\n` is an added token too and would stop every
   free-text reply at its first newline.
"""
from __future__ import annotations

import copy
import json
import logging
import os
from dataclasses import dataclass

log = logging.getLogger(__name__)

# Fallbacks when the model directory has no generation_config.json (mlx-community 4-bit conversions
# often drop it). The bake-off table records what each model actually ran with (`.sampling`).
DEFAULT_TEMPERATURE = 1.0
DEFAULT_TOP_P = 0.95
DEFAULT_TOP_K = 0  # 0 = disabled (mlx_lm make_sampler convention); per-family values below
DEFAULT_MAX_TOKENS = 1024
# Published non-greedy recommendations, keyed by the config.json `model_type` / GGUF `general.architecture`
# prefix, used only when generation_config.json is absent. Gemma 3 model card: temperature 1.0,
# top_p 0.95, top_k 64. Other families fall back to the module defaults (top_k off) — add them here as
# their cards are read, never guessed.
FAMILY_TOP_K = {"gemma": 64}


def _check_max_tokens(max_tokens: int) -> int:
    # mlx_lm treats -1 as "no limit" and rejects 0; a reply must always be bounded here.
    if int(max_tokens) < 1:
        raise ValueError(f"max_tokens must be >= 1, got {max_tokens}")
    return int(max_tokens)


@dataclass
class GenResult:
    text: str
    prompt_tokens: int
    completion_tokens: int
    cached_tokens: int
    # True when the prompt reused the model's own tokens for its previous reply instead of re-tokenizing
    # the history (module docstring, fact 2). Defaulted so scripted test generators need not set it.
    spliced: bool = False


class ContextOverflow(ValueError):
    """The templated prompt is longer than the wrapper's `context_cap`. Never truncated silently."""

    def __init__(self, prompt_tokens: int, context_cap: int):
        super().__init__(f"prompt is {prompt_tokens} tokens, context_cap is {context_cap}")
        self.prompt_tokens = prompt_tokens
        self.context_cap = context_cap


# ----------------------------------------------------------------------------- pure helpers


def merge_consecutive_roles(messages: list[dict]) -> list[dict]:
    """Join runs of consecutive same-role messages into one message (contents joined by a blank line).

    Applied before every chat-template call, in training and at runtime alike. Returns new dicts; the
    caller's (append-only) history is never mutated. Idempotent.
    """
    out: list[dict] = []
    for m in messages:
        if out and out[-1]["role"] == m["role"]:
            out[-1] = {**out[-1], "content": out[-1]["content"] + "\n\n" + m["content"]}
        else:
            out.append(dict(m))
    return out


def common_prefix_len(a, b) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def constrained_schema(schema: dict) -> dict:
    """`schema` with `properties` in sorted-key order at every level.

    Outlines' JSON-schema regex emits object members in `properties` order, and the training target
    (`format.dumps_action`) is `json.dumps(sort_keys=True)`; sorting here makes the grammar admit exactly
    the canonical order, so a fine-tuned model is never forced away from what it was trained on.
    """
    def _sort(node):
        if isinstance(node, dict):
            node = {k: _sort(v) for k, v in node.items()}
            if isinstance(node.get("properties"), dict):
                node["properties"] = dict(sorted(node["properties"].items()))
            return node
        if isinstance(node, list):
            return [_sort(x) for x in node]
        return node
    return _sort(copy.deepcopy(schema))


def splice_prompt_tokens(text: str, last: tuple | None, cache_tokens: list[int], encode,
                         stop_text: str | None) -> list[int] | None:
    """Token sequence for `text` that keeps the model's own reply tokens (module docstring, fact 2).

    `last` = (previous prompt text, previous reply text) or None; `cache_tokens` = the tokens now in the
    cache (previous prompt + reply [+ stop token]); `encode(fragment)` tokenizes without added specials;
    `stop_text` = the stop token's text when it sits at the end of `cache_tokens`, else None.
    Returns None when `text` does not continue the previous exchange (the caller tokenizes normally).
    """
    if last is None:
        return None
    head = last[0] + last[1]
    if not text.startswith(head):
        return None
    rest = text[len(head):]
    if stop_text is not None:
        if not rest.startswith(stop_text):
            return None
        rest = rest[len(stop_text):]
    return list(cache_tokens) + (list(encode(rest)) if rest else [])


def _local_model_dir(path_or_repo: str) -> str:
    """A local directory for `path_or_repo`: the path itself, or the HF cache copy. Never downloads."""
    if os.path.isdir(path_or_repo):
        return path_or_repo
    from huggingface_hub import snapshot_download
    try:
        return snapshot_download(path_or_repo, local_files_only=True)
    except Exception as e:  # LocalEntryNotFoundError / HFValidationError / OSError
        raise FileNotFoundError(
            f"{path_or_repo!r} is neither a directory nor in the local Hugging Face cache; inference is "
            f"offline, download it once first (huggingface-cli download {path_or_repo})") from e


def _read_json(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f) or {}


def _family_top_k(family: str | None) -> int:
    for prefix, k in FAMILY_TOP_K.items():
        if family and family.lower().startswith(prefix):
            return k
    return DEFAULT_TOP_K


def _resolve_sampling(model_dir: str | None, temperature, top_p, top_k, family: str | None = None) -> dict:
    """Explicit kwargs win; then the model's generation_config.json; then the family table / defaults.
    `family` defaults to config.json's `model_type` when `model_dir` is given."""
    gen_cfg: dict = {}
    if model_dir:
        gen_cfg = _read_json(os.path.join(model_dir, "generation_config.json"))
        family = family or _read_json(os.path.join(model_dir, "config.json")).get("model_type")
    return {
        "temperature": float(temperature if temperature is not None else gen_cfg.get("temperature", DEFAULT_TEMPERATURE)),
        "top_p": float(top_p if top_p is not None else gen_cfg.get("top_p", DEFAULT_TOP_P)),
        "top_k": int(top_k if top_k is not None else gen_cfg.get("top_k", _family_top_k(family))),
    }


def _turn_end_id(render, encode, special_ids: set[int]) -> int | None:
    """The special token the chat template writes IMMEDIATELY after an assistant message, or None.

    `render(messages, add_generation_prompt)` -> str, `encode(text)` -> list[int] without added
    specials. Found by rendering a one-exchange chat with and without the assistant reply. Only the
    first token after the reply counts: what follows it (Gemma: an added `\\n` token) is layout.
    """
    user = [{"role": "user", "content": "A"}]
    with_reply = render(user + [{"role": "assistant", "content": "B"}], False)
    prefix = render(user, True)
    if not with_reply.startswith(prefix + "B"):
        return None
    ids = encode(with_reply[len(prefix) + 1:])
    return ids[0] if ids and ids[0] in special_ids else None


def encode_prompt(tok, text: str) -> list[int]:
    """Token ids of a templated prompt as the runtime feeds it: the template usually writes the BOS itself, so
    specials are added only when it did not (mlx_lm's own rule). Shared by `MlxModel` and SFT encoding."""
    bos = tok.bos_token
    add_special = bos is None or not text.startswith(bos)
    return list(tok.encode(text, add_special_tokens=add_special))


def _action_regex() -> str:
    from outlines_core.json_schema import build_regex_from_schema
    from orion.lm import format as fmt
    # whitespace_pattern "" = no whitespace between JSON tokens, exactly `format.dumps_action`'s shape.
    return build_regex_from_schema(json.dumps(constrained_schema(fmt.ACTION_SCHEMA)), "")


# ----------------------------------------------------------------------------- MLX


class MlxModel:
    """MLX-LM wrapper: 4-bit weights, one prompt cache per instance, Outlines-constrained turns.

    `constrain` (constructor, default True) restricts every reply to `format.ACTION_SCHEMA` (compact
    JSON, sorted keys) via Outlines; `generate(messages, constrain=...)` overrides it per call.

    Seeding: the sampler draws from MLX's GLOBAL random stream, so `seed` is applied to the process, not
    the instance. `seed_session()` re-seeds it from the constructor seed and runs at construction and on
    every `reset_cache()`, so each fresh session starts from the same RNG state for the same `seed`.
    Limitation: two `MlxModel`s in one process share that stream — run ONE model per process when
    reproducibility matters (F3's runs are sequential).

    Cache integrity: any exception during a call resets the cache (a half-updated cache is never reused);
    after a successful call every layer's cache offset must equal the tracked token count.
    """

    backend = "mlx"

    def __init__(self, model_path: str, *, context_cap: int = 8000, thinking: bool = False,
                 temperature: float | None = None, top_p: float | None = None, top_k: int | None = None,
                 seed: int = 0, max_tokens: int = DEFAULT_MAX_TOKENS, constrain: bool = True):
        import mlx.core as mx
        from mlx_lm import load as mlx_load
        from mlx_lm.sample_utils import make_sampler

        self.model_dir = _local_model_dir(model_path)
        self.context_cap = int(context_cap)
        self.thinking = bool(thinking)
        self.max_tokens = _check_max_tokens(max_tokens)
        self.seed = int(seed)
        self.constrain = bool(constrain)
        self.sampling = _resolve_sampling(self.model_dir, temperature, top_p, top_k)

        self.model, self.tokenizer = mlx_load(self.model_dir)
        self._mx = mx
        self._sampler = make_sampler(temp=self.sampling["temperature"], top_p=self.sampling["top_p"],
                                     top_k=self.sampling["top_k"])

        # Turn-end markers are often ADDED tokens, not "special" ones (Gemma's <end_of_turn> is not in
        # all_special_ids), so consider both sets.
        special = set(self.tokenizer.all_special_ids) | set(self.tokenizer.get_added_vocab().values())
        self.turn_end_id = _turn_end_id(
            lambda msgs, gen: self.tokenizer.apply_chat_template(
                msgs, tokenize=False, add_generation_prompt=gen, enable_thinking=self.thinking),
            lambda text: self.tokenizer.encode(text, add_special_tokens=False),
            special)
        self.eos_ids = set(self.tokenizer.eos_token_ids) | ({self.turn_end_id} if self.turn_end_id is not None else set())

        self._cache = None
        self._cache_tokens: list[int] = []
        self._last: tuple[str, str] | None = None   # (prompt text, reply text) of the previous call
        self._last_stop_text: str | None = None     # text of the stop token at the end of the cache
        self._outlines_index = None
        self.seed_session()

    # -- prompt --------------------------------------------------------------------------------

    def prompt_text(self, messages: list[dict]) -> str:
        return self.tokenizer.apply_chat_template(
            merge_consecutive_roles(messages), tokenize=False, add_generation_prompt=True,
            enable_thinking=self.thinking)

    def _encode_fragment(self, text: str) -> list[int]:
        return list(self.tokenizer.encode(text, add_special_tokens=False))

    def prompt_tokens(self, messages: list[dict]) -> list[int]:
        """The tokens `generate` feeds for `messages`: the model's own tokens for its previous reply when
        `messages` continues the previous exchange (fact 2), else the canonical tokenization."""
        return self._tokens_for(self.prompt_text(messages))[0]

    def _tokens_for(self, text: str) -> tuple[list[int], bool]:
        """(tokens, spliced) for the templated `text`."""
        spliced = splice_prompt_tokens(text, self._last, self._cache_tokens, self._encode_fragment,
                                       self._last_stop_text)
        if spliced is not None:
            return spliced, True
        return encode_prompt(self.tokenizer, text), False

    # -- cache ---------------------------------------------------------------------------------

    def seed_session(self) -> None:
        """Re-seed MLX's global random stream from the constructor seed (class docstring)."""
        self._mx.random.seed(self.seed)

    def reset_cache(self) -> None:
        """Drop the prompt cache and start a fresh session from the seeded RNG state."""
        self._cache = None
        self._cache_tokens = []
        self._last = None
        self._last_stop_text = None
        self.seed_session()

    def _check_offsets(self, expected: int) -> None:
        """Every layer cache that exposes `.offset` must hold exactly `expected` tokens.

        mlx_lm's KVCache / RotatingKVCache / QuantizedKVCache all track `.offset` (total tokens seen,
        trimming subtracts); a cache type without it is skipped and the tracked list stays the source.
        """
        for i, c in enumerate(self._cache or []):
            off = getattr(c, "offset", None)
            if off is not None and int(off) != expected:
                raise RuntimeError(f"prompt cache out of sync: layer {i} offset {off}, tracked {expected}")

    def _prepare_cache(self, toks: list[int]) -> tuple[list[int], int]:
        """Return (tokens still to prefill, cached_tokens), adjusting the cache in place."""
        from mlx_lm.models.cache import can_trim_prompt_cache, make_prompt_cache, trim_prompt_cache

        common = common_prefix_len(self._cache_tokens, toks) if self._cache is not None else 0
        if common == len(toks):
            common = len(toks) - 1  # generate_step needs at least one token to produce logits
        if 0 < common < len(self._cache_tokens):
            extra = len(self._cache_tokens) - common
            if not (can_trim_prompt_cache(self._cache) and trim_prompt_cache(self._cache, extra) == extra):
                common = 0
        if common == 0:
            self._cache = make_prompt_cache(self.model)
            self._cache_tokens = []
        else:
            self._cache_tokens = self._cache_tokens[:common]
        return toks[common:], common

    # -- constraint ----------------------------------------------------------------------------

    def _action_processor(self):
        """A fresh Outlines logits processor over ACTION_SCHEMA (the compiled index is built once)."""
        from outlines.backends.outlines_core import OutlinesCoreBackend, OutlinesCoreLogitsProcessor
        if self._outlines_index is None:
            from outlines_core import Index

            tok = self.tokenizer
            # The guide's terminal token must be the TEMPLATE's turn end, not necessarily tokenizer.eos
            # (module docstring, fact 3). Fall back to the tokenizer's eos when the template gave none.
            eos_id = self.turn_end_id if self.turn_end_id is not None else tok.eos_token_id
            eos_tok = tok.convert_ids_to_tokens(eos_id)
            # The tokenizer may know more ids than the model's output layer has logits (Gemma 3:
            # 262145 vs 262144); outlines_core sizes its bitmask from the vocabulary, the kernel from
            # the logits, so only ids the model can actually emit may enter the vocabulary.
            n_logits = getattr(getattr(self.model, "args", None), "vocab_size", None) or len(tok.get_vocab())
            vocab = {t: i for t, i in tok.get_vocab().items() if i < n_logits}
            vocabulary = OutlinesCoreBackend.create_outlines_core_vocabulary(
                vocab, eos_id, eos_tok, lambda t: tok.convert_tokens_to_string([t]))
            self._outlines_index = Index(_action_regex(), vocabulary)
        return OutlinesCoreLogitsProcessor(self._outlines_index, "mlx")

    # -- generate ------------------------------------------------------------------------------

    def _decode(self, suffix: list[int], processors) -> list[int]:
        """Prefill `suffix` into the cache and sample until a stop token or `max_tokens`."""
        from mlx_lm.generate import generate_step, generation_stream, wired_limit

        mx = self._mx
        gen: list[int] = []
        with wired_limit(self.model, [generation_stream]):
            for token, _ in generate_step(mx.array(suffix), self.model, max_tokens=self.max_tokens,
                                          sampler=self._sampler, logits_processors=processors,
                                          prompt_cache=self._cache):
                gen.append(token)
                if token in self.eos_ids:
                    break
        mx.clear_cache()
        return gen

    def generate(self, messages: list[dict], *, constrain: bool | None = None) -> GenResult:
        constrain = self.constrain if constrain is None else bool(constrain)
        text = self.prompt_text(messages)
        toks, spliced = self._tokens_for(text)
        n_prompt = len(toks)
        if n_prompt > self.context_cap:
            raise ContextOverflow(n_prompt, self.context_cap)  # cache untouched: nothing was fed

        try:
            suffix, cached = self._prepare_cache(toks)
            processors = [self._action_processor()] if constrain else None
            gen = self._decode(suffix, processors)
            # Every yielded token was fed back into the cache by generate_step (including the stop token).
            self._cache_tokens = toks + gen
            self._check_offsets(len(self._cache_tokens))
        except Exception:
            # A failure anywhere after the cache was touched leaves it half-updated: never reuse it.
            self.reset_cache()
            raise

        stopped = bool(gen) and gen[-1] in self.eos_ids
        body = gen[:-1] if stopped else gen
        reply = self.tokenizer.decode(body)
        self._last = (text, reply)
        self._last_stop_text = self.tokenizer.decode([gen[-1]]) if stopped else None
        return GenResult(text=reply, prompt_tokens=n_prompt, completion_tokens=len(gen), cached_tokens=cached,
                         spliced=spliced)


# ----------------------------------------------------------------------------- llama.cpp fallback


class LlamaCppModel:
    """llama-cpp-python fallback over a GGUF file, same seam as `MlxModel`.

    Seeding: llama.cpp's sampler RNG is per `Llama` context; `seed_session()` re-applies the constructor
    seed (`Llama.set_seed`) at construction and on every `reset_cache()`. Cache integrity: a failure
    mid-call resets the context (`Llama.reset`) before re-raising.
    """

    backend = "llama_cpp"

    def __init__(self, gguf_path: str, *, context_cap: int = 8000, thinking: bool = False,
                 temperature: float | None = None, top_p: float | None = None, top_k: int | None = None,
                 seed: int = 0, max_tokens: int = DEFAULT_MAX_TOKENS, constrain: bool = True,
                 n_gpu_layers: int = -1):
        from llama_cpp import Llama
        from llama_cpp.llama_chat_format import Jinja2ChatFormatter

        if not os.path.isfile(gguf_path):
            raise FileNotFoundError(gguf_path)
        self.model_path = gguf_path
        self.context_cap = int(context_cap)
        self.thinking = bool(thinking)
        self.max_tokens = _check_max_tokens(max_tokens)
        self.seed = int(seed)
        self.constrain = bool(constrain)
        self.llm = Llama(model_path=gguf_path, n_ctx=self.context_cap + self.max_tokens, seed=self.seed,
                         n_gpu_layers=n_gpu_layers, verbose=False)
        self.sampling = _resolve_sampling(None, temperature, top_p, top_k,
                                          family=self.llm.metadata.get("general.architecture"))
        template = self.llm.metadata.get("tokenizer.chat_template")
        if not template:
            raise ValueError(f"{gguf_path}: GGUF carries no tokenizer.chat_template")
        bos = self._detok([self.llm.token_bos()])
        eos = self._detok([self.llm.token_eos()])
        self._formatter = Jinja2ChatFormatter(template=template, eos_token=eos, bos_token=bos,
                                              add_generation_prompt=True)
        self._bos_text = bos

        special = {i for i in range(self.llm.n_vocab()) if self._is_special(i)}
        self.turn_end_id = _turn_end_id(self._render, self._encode_fragment, special)
        self.eos_ids = {self.llm.token_eos()} | ({self.turn_end_id} if self.turn_end_id is not None else set())
        self._last: tuple[str, str] | None = None
        self._outlines_index = None
        self.seed_session()

    def _detok(self, ids: list[int]) -> str:
        return self.llm.detokenize(ids, special=True).decode("utf-8", "replace")

    def _is_special(self, token_id: int) -> bool:
        import llama_cpp
        attr = llama_cpp.llama_vocab_get_attr(self.llm._model.vocab, token_id)
        return bool(attr & llama_cpp.LLAMA_TOKEN_ATTR_CONTROL)

    def _render(self, messages: list[dict], add_generation_prompt: bool) -> str:
        fmt = self._formatter
        saved = fmt.add_generation_prompt
        fmt.add_generation_prompt = add_generation_prompt
        try:
            return fmt(messages=messages, enable_thinking=self.thinking).prompt
        finally:
            fmt.add_generation_prompt = saved

    def _encode_fragment(self, text: str) -> list[int]:
        return list(self.llm.tokenize(text.encode("utf-8"), add_bos=False, special=True))

    def _cache_tokens(self) -> list[int]:
        return self.llm.input_ids[:self.llm.n_tokens].tolist()

    def prompt_text(self, messages: list[dict]) -> str:
        return self._render(merge_consecutive_roles(messages), True)

    def prompt_tokens(self, messages: list[dict]) -> list[int]:
        return self._tokens_for(self.prompt_text(messages))[0]

    def _tokens_for(self, text: str) -> tuple[list[int], bool]:
        # llama.cpp evaluates a sampled token only when the next one is drawn, so the stop token is NOT in
        # its cache: the text after the reply (starting with the stop token) is tokenized in full.
        spliced = splice_prompt_tokens(text, self._last, self._cache_tokens(), self._encode_fragment, None)
        if spliced is not None:
            return spliced, True
        add_bos = not text.startswith(self._bos_text)
        return list(self.llm.tokenize(text.encode("utf-8"), add_bos=add_bos, special=True)), False

    def seed_session(self) -> None:
        self.llm.set_seed(self.seed)

    def reset_cache(self) -> None:
        self.llm.reset()
        self._last = None
        self.seed_session()

    def _action_processor(self):
        from llama_cpp import LogitsProcessorList
        from outlines.backends.outlines_core import OutlinesCoreBackend, OutlinesCoreLogitsProcessor
        # llama.cpp calls the processor from a ctypes callback that SWALLOWS exceptions ("Exception
        # ignored ..."), which would turn a missing kernel dependency into silently unconstrained
        # output. Import the kernels here so the failure is raised to the caller instead.
        import outlines_core.kernels.numpy  # noqa: F401  (needs `numba`)
        if self._outlines_index is None:
            from outlines_core import Index
            from outlines.models.llamacpp import LlamaCppTokenizer

            tok = LlamaCppTokenizer(self.llm)
            eos_id = self.turn_end_id if self.turn_end_id is not None else self.llm.token_eos()
            eos_tok = next(t for t, i in tok.vocabulary.items() if i == eos_id)
            vocabulary = OutlinesCoreBackend.create_outlines_core_vocabulary(
                tok.vocabulary, eos_id, eos_tok, tok.convert_token_to_string)
            self._outlines_index = Index(_action_regex(), vocabulary)
        return LogitsProcessorList([OutlinesCoreLogitsProcessor(self._outlines_index, "numpy")])

    def generate(self, messages: list[dict], *, constrain: bool | None = None) -> GenResult:
        constrain = self.constrain if constrain is None else bool(constrain)
        text = self.prompt_text(messages)
        toks, spliced = self._tokens_for(text)
        n_prompt = len(toks)
        if n_prompt > self.context_cap:
            raise ContextOverflow(n_prompt, self.context_cap)

        # Llama.generate(reset=True) reuses the longest common prefix of its KV cache itself; mirror its
        # arithmetic so cached_tokens is the number it really keeps (one token is always re-evaluated
        # when the whole prompt is already cached, so there are logits to sample from).
        llm = self.llm
        common = common_prefix_len(self._cache_tokens(), toks)
        cached = max(common - 1 if common == n_prompt else common, 0)

        s = self.sampling
        gen: list[int] = []
        try:
            processors = self._action_processor() if constrain else None
            for token in llm.generate(toks, temp=s["temperature"], top_p=s["top_p"], top_k=s["top_k"],
                                      min_p=0.0, repeat_penalty=1.0, reset=True, logits_processor=processors):
                gen.append(int(token))
                if token in self.eos_ids or len(gen) >= self.max_tokens:
                    break
        except Exception:
            self.reset_cache()
            raise

        stopped = bool(gen) and gen[-1] in self.eos_ids
        body = gen[:-1] if stopped else gen
        reply = llm.detokenize(body).decode("utf-8", "replace")
        self._last = (text, reply)
        return GenResult(text=reply, prompt_tokens=n_prompt, completion_tokens=len(gen), cached_tokens=cached,
                         spliced=spliced)


# ----------------------------------------------------------------------------- entry point


def load(path: str, *, gguf_path: str | None = None, **sampling):
    """The MLX wrapper for `path`, or the llama-cpp fallback when MLX cannot import/load.

    `path` may be an MLX model directory / cached repo id, or a `.gguf` file (fallback directly).
    `gguf_path` names the GGUF to fall back to when MLX fails; without one, a `.gguf` next to the MLX
    weights is used; otherwise the MLX error is raised. `sampling` = the wrappers' keyword arguments
    (`context_cap`, `thinking`, `temperature`, `top_p`, `top_k`, `seed`, `max_tokens`, `constrain`).
    The returned object's `.backend` is "mlx" or "llama_cpp"; a fallback is logged as a warning.
    """
    if path.endswith(".gguf"):
        return LlamaCppModel(path, **sampling)
    try:
        return MlxModel(path, **sampling)
    except Exception as mlx_err:
        fallback = gguf_path or _gguf_in(path)
        if fallback is None:
            raise
        log.warning("MLX load of %r failed (%r); falling back to llama-cpp over %s", path, mlx_err, fallback)
        try:
            return LlamaCppModel(fallback, **sampling)
        except Exception as cpp_err:
            raise RuntimeError(f"MLX load failed ({mlx_err!r}) and the llama-cpp fallback failed too "
                               f"({cpp_err!r})") from cpp_err


def _gguf_in(path: str) -> str | None:
    if not os.path.isdir(path):
        return None
    for name in sorted(os.listdir(path)):
        if name.endswith(".gguf"):
            return os.path.join(path, name)
    return None
