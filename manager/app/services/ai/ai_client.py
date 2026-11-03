# manager/app/services/ai/ai_client.py
import httpx
import os
import re
from typing import Optional

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
DEFAULT_MODEL = os.getenv("AI_MODEL", "foundation-sec")


class AIClient:
    def __init__(self, base_url: str = OLLAMA_URL, model: str = DEFAULT_MODEL):
        self.base_url = base_url
        self.model = model
        self.timeout = httpx.Timeout(600.0, connect=10.0)

    async def generate(self, prompt: str, system: Optional[str] = None) -> dict:
        """Gọi Ollama /api/chat, trả về {reasoning, answer, raw}."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "format": "json",
            "keep_alive": "24h",
            "options": {
                "temperature": 0.2,
                "num_predict": 1000,
                "top_p": 0.9,
                "num_ctx": 8192,
            },
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()

        # /api/chat trả về data["message"]["content"]
        raw = data.get("message", {}).get("content", "")
        return self._parse_response(raw)

    def _parse_response(self, text: str) -> dict:
        """
        Parse reasoning + answer từ response.
        Hỗ trợ 3 format:
          1. <think>reasoning</think>answer  (chuẩn Foundation-Sec)
          2. Reasoning block kết thúc bằng \n\n\nanswer
          3. Chỉ có answer (fallback)
        """
        reasoning = ""
        answer = text

        # Format 1: <think>...</think>
        match = re.search(r"<think>(.*?)</think>", text, re.DOTALL)
        if match:
            reasoning = match.group(1).strip()
            answer = text.replace(match.group(0), "").strip()
        else:
            # Format 2: reasoning trước, answer sau nhiều dòng trống
            # (thường model emit reasoning + 2-3 dòng trống + answer)
            parts = re.split(r"\n\n\n+", text, maxsplit=1)
            if len(parts) == 2 and len(parts[0]) > 100:
                # Phần đầu dài > 100 chars → coi là reasoning
                reasoning = parts[0].strip()
                answer = parts[1].strip()

        # Strip markdown header ở đầu answer (VD: "# Technical Explanation of X")
        if answer:
            # Xóa header markdown dòng đầu nếu có
            lines = answer.split("\n", 1)
            if lines[0].startswith("#"):
                answer = lines[1].lstrip("\n") if len(lines) > 1 else ""

            # Xóa prefix "ANSWER:" hoặc "Final Answer:" nếu model tự thêm
            answer = re.sub(r"^(ANSWER|Final Answer|Answer)\s*:\s*", "", answer, flags=re.IGNORECASE)
            answer = answer.strip()

        return {
            "reasoning": reasoning,
            "answer": answer,
            "raw": text,
        }


# Singleton
ai_client = AIClient()