# manager/app/services/ai/ai_client.py
import json
import os
import re
from dataclasses import dataclass

import httpx

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
DEFAULT_MODEL = os.getenv("AI_MODEL") or "sec-q5:latest"


@dataclass(frozen=True)
class TriageInferenceSettings:
    num_ctx: int = int(os.getenv("AI_TRIAGE_NUM_CTX", "4096"))
    num_predict: int = int(os.getenv("AI_TRIAGE_NUM_PREDICT", "640"))
    temperature: float = float(os.getenv("AI_TRIAGE_TEMPERATURE", "0.1"))
    keep_alive: str = os.getenv("AI_TRIAGE_KEEP_ALIVE", "5m")
    stream: bool = os.getenv("AI_TRIAGE_STREAM", "false").lower() == "true"
    think: bool | None = {"true": True, "false": False}.get(
        os.getenv("AI_TRIAGE_THINK", "").lower()
    )

    def request_options(self) -> dict:
        return {
            "options": {
                "num_ctx": self.num_ctx, "num_predict": self.num_predict,
                "temperature": self.temperature,
            },
            "keep_alive": self.keep_alive, "stream": self.stream, "think": self.think,
        }


TRIAGE_SETTINGS = TriageInferenceSettings()


class AIClient:
    def __init__(self, base_url: str = OLLAMA_URL, model: str = DEFAULT_MODEL):
        self.base_url = base_url
        self.model = model
        self.timeout = httpx.Timeout(600.0, connect=10.0)

    async def generate(
        self, prompt: str, system: str | None = None, *,
        options: dict | None = None, format_schema: str | dict = "json",
        keep_alive: str | int = "5m", stream: bool = False,
        think: bool | None = None, timeout: httpx.Timeout | None = None,
        strict: bool = False,
    ) -> dict:
        """Call Ollama with caller-specific settings and return output and metrics."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
            "format": format_schema,
            "keep_alive": keep_alive,
            "options": {
                "temperature": 0.2,
                "num_predict": 2048,
                "top_p": 0.9,
                "num_ctx": 8192,
                **(options or {}),
            },
        }
        if think is not None:
            payload["think"] = think

        async with httpx.AsyncClient(timeout=timeout or self.timeout) as client:
            if stream:
                content, thinking = [], []
                async with client.stream("POST", f"{self.base_url}/api/chat", json=payload) as resp:
                    resp.raise_for_status()
                    data = {}
                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        data = json.loads(line)
                        if not isinstance(data, dict) or "error" in data:
                            raise ValueError("Ollama stream failed")
                        message = data.get("message", {})
                        if not isinstance(message, dict):
                            raise ValueError("Invalid Ollama stream envelope")
                        content.append(message.get("content", ""))
                        if not strict:
                            thinking.append(message.get("thinking", ""))
                message = {"content": "".join(content), "thinking": "".join(thinking)}
            else:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                data = resp.json()
                if not isinstance(data, dict):
                    raise ValueError("Invalid Ollama response envelope")
                message = data.get("message", {})
        if not isinstance(message, dict) or "error" in data:
            raise ValueError("Invalid Ollama response envelope")

        raw_content = message.get("content", "")
        result = {"answer": raw_content} if strict else self._parse_response(
            raw_content, message.get("thinking", ""),
        )
        result["metrics"] = {key: data[key] for key in (
            "done", "done_reason", "prompt_eval_count", "prompt_eval_duration",
            "eval_count", "eval_duration", "total_duration", "load_duration",
        ) if key in data}
        return result

    def _parse_response(self, text: str, thinking_from_api: str = "") -> dict:
        """
        Parse reasoning + answer từ response.
        Ưu tiên lấy thinking từ trường riêng của API, nếu không có thì parse từ <think> tags.
        """
        reasoning = thinking_from_api or ""
        answer = text

        # Nếu API không trả thinking riêng, thử parse từ <think> tags
        if not reasoning:
            match = re.search(r"<think>(.*?)</think>", text, re.DOTALL)
            if match:
                reasoning = match.group(1).strip()
                answer = text.replace(match.group(0), "").strip()
            else:
                # Fallback: reasoning trước, answer sau nhiều dòng trống
                parts = re.split(r"\n\n\n+", text, maxsplit=1)
                if len(parts) == 2 and len(parts[0]) > 100:
                    reasoning = parts[0].strip()
                    answer = parts[1].strip()

        # Strip markdown header và prefix nếu có
        if answer:
            lines = answer.split("\n", 1)
            if lines[0].startswith("#"):
                answer = lines[1].lstrip("\n") if len(lines) > 1 else ""
            answer = re.sub(r"^(ANSWER|Final Answer|Answer)\s*:\s*", "", answer, flags=re.IGNORECASE)
            answer = answer.strip()

        return {
            "reasoning": reasoning,
            "answer": answer,
            "raw": text,
        }



# Singleton
ai_client = AIClient()
