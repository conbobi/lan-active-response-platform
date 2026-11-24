"""Count tokens with the vocabulary and chat template from the deployed GGUF."""
import json
import os
from functools import lru_cache
from pathlib import Path

from gguf import GGUFReader
from jinja2.sandbox import ImmutableSandboxedEnvironment
from tokenizers import AddedToken, Regex, Tokenizer
from tokenizers.models import BPE
from tokenizers.pre_tokenizers import ByteLevel, Sequence, Split

_model_file = "Foundation-Sec-8B-Reasoning.Q5_K_M.gguf"
_local_model = Path(__file__).resolve().parents[4] / "models" / _model_file
GGUF_PATH = os.getenv("AI_TRIAGE_GGUF") or str(
    _local_model if _local_model.is_file() else Path("/models") / _model_file
)
LLAMA_SPLIT = (
    r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}"
    r"| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+"
)


class TriageTokenizer:
    def __init__(self, path: str):
        fields = GGUFReader(path).fields

        def value(key: str):
            return fields[key].contents()

        if (value("tokenizer.ggml.model"), value("tokenizer.ggml.pre")) != ("gpt2", "llama-bpe"):
            raise ValueError("Unsupported triage tokenizer metadata")
        tokens = value("tokenizer.ggml.tokens")
        merges = [tuple(merge.split(" ", 1)) for merge in value("tokenizer.ggml.merges")]
        self.tokenizer = Tokenizer(BPE({token: index for index, token in enumerate(tokens)}, merges))
        self.tokenizer.pre_tokenizer = Sequence([
            Split(Regex(LLAMA_SPLIT), behavior="isolated"),
            ByteLevel(add_prefix_space=False, use_regex=False),
        ])
        self.tokenizer.add_special_tokens([
            AddedToken(token, normalized=False, special=True)
            for token, token_type in zip(tokens, value("tokenizer.ggml.token_type"), strict=True)
            if token_type in (3, 4)
        ])
        self.bos = tokens[value("tokenizer.ggml.bos_token_id")]
        self.eos = tokens[value("tokenizer.ggml.eos_token_id")]
        self.template = ImmutableSandboxedEnvironment().from_string(value("tokenizer.chat_template"))

    def count_text(self, text: str) -> int:
        return len(self.tokenizer.encode(text, add_special_tokens=False).ids)

    def clip_text(self, text: str, limit: int) -> str:
        encoding = self.tokenizer.encode(text, add_special_tokens=False)
        if len(encoding.ids) <= limit:
            return text
        return text[:encoding.offsets[limit - 1][1]]

    def count_chat(self, system: str, user: str) -> int:
        prompt = self.template.render(
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            bos_token=self.bos, eos_token=self.eos, add_generation_prompt=True,
        )
        return self.count_text(prompt)


@lru_cache(maxsize=1)
def load_tokenizer() -> TriageTokenizer:
    return TriageTokenizer(GGUF_PATH)


def serialize_data(value: dict | list) -> str:
    """Escape template control delimiters without losing the original JSON values."""
    content = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    for character in "<>|&\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069":
        content = content.replace(character, f"\\u{ord(character):04x}")
    return content
