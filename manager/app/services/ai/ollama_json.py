"""Bounded, schema-constrained JSON generation with the local Ollama model.

The configured model (Foundation-Sec-8B-Reasoning) always reasons before answering and its chat
template has no switch to disable that, so /api/chat spends the token budget on hidden reasoning
and returns empty content. The prompt is sent raw in the model's chat format with an empty
reasoning block, so the budget goes to the JSON answer; ``format`` constrains its shape.
"""
import json
import os

import httpx


class GenerationError(ValueError):
    """The model produced no usable answer (timeout, transport error, truncated or invalid output)."""


def chat_prompt(system: str, user: str) -> str:
    return f"<|system|>\n{system}\n<|user|>\n{user}\n<|assistant|>\n<think>\n\n</think>\n"


async def raw_generate(url: str, model: str, system: str, user: str, schema: dict, *,
                       temperature: float = 0.1, num_predict: int = 512, timeout_env: str = "HARVEST_TIMEOUT_SECONDS",
                       default_timeout: float = 120.0) -> str:
    """One model call; returns the raw text, never retries."""
    payload = {
        "model": model,
        "prompt": chat_prompt(system, user),
        "raw": True,
        "format": schema,
        "stream": False,
        "keep_alive": "5m",
        "options": {"temperature": temperature, "num_predict": num_predict, "top_p": 0.9},
    }
    timeout = httpx.Timeout(float(os.getenv(timeout_env, str(default_timeout))), connect=5.0)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(f"{url}/api/generate", json=payload)
            resp.raise_for_status()
            body = resp.json()
    except httpx.TimeoutException as exc:
        raise GenerationError("Ollama generation timed out") from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise GenerationError(f"Ollama generation failed: {exc}") from exc
    if not isinstance(body, dict) or not isinstance(body.get("response"), str):
        raise GenerationError("Ollama returned no generated text")
    if body.get("done_reason") == "length":
        raise GenerationError("Model output was truncated at the token limit")
    return body["response"]


async def generate_json(url: str, model: str, system: str, user: str, schema: dict, **kwargs) -> dict:
    text = await raw_generate(url, model, system, user, schema, **kwargs)
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise GenerationError("Model output is not JSON") from exc
    if not isinstance(data, dict):
        raise GenerationError("Model output is not a JSON object")
    return data
