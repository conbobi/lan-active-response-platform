"""Isolated request latency with a controlled 250 ms inference wait."""

import asyncio
import time

from test_http_response_assist import ADMIN, PATH, assist_policy, lab


def test_interactive_proposal_latency(lab, monkeypatch):
    client, _ = lab
    original = assist_policy.ai_client.generate
    calls = []

    async def delayed(*args, **kwargs):
        calls.append(True)
        await asyncio.sleep(0.25)
        return await original(*args, **kwargs)

    monkeypatch.setattr(assist_policy.ai_client, "generate", delayed)
    start = time.perf_counter()
    result = client.post(PATH, headers=ADMIN, json={})
    duration = (time.perf_counter() - start) * 1000
    assert result.status_code == 200
    print(f"proposal_ms={duration:.1f}, inference_calls={len(calls)}")
    row = client.get("/api/v1/response-actions/" + result.json()["action_id"], headers=ADMIN).json()
    print("stage_ms", row["audit"][0]["metadata"]["stage_ms"])
    assert not calls
