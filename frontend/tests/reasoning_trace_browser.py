"""Browser test (production build, Chromium, mocked API) for the shared "Quá trình phân tích" panel.

The mocked backend returns persisted Decision Trace events as the real API does; the test checks the UI shows
exactly the backend state (status, stages, timeout), that hiding/showing never calls the API, that a reload
reattaches to the same run, and that no raw <think> text or raw JSON reaches the page.
Run: npm run build && python tests/reasoning_trace_browser.py
"""
import json
import shutil
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright

import response_session_browser as base

INC = "inc_90940e8f23fb"
calls = {"questions": 0, "rule_runs": 0, "trace_gets": 0}
served = set()   # runs whose first snapshot was already served (later snapshots are final)


def snapshot(run_id, run, events):
    """First GET: the run is still RUNNING with its first events; the rest arrives over SSE."""
    if run_id not in served:
        served.add(run_id)
        return {"run": {**run, "status": "RUNNING", "result": None, "completed_at": None}, "events": events[:2]}
    return {"run": run, "events": events}


def ev(seq, event_type, stage, status, summary="", source="DETERMINISTIC", **extra):
    return {"event_id": f"tr_{seq}", "sequence": seq, "event_type": event_type, "stage": stage, "status": status,
            "source_type": source, "summary": summary, "evidence_refs": extra.pop("evidence_refs", []),
            "rule_refs": extra.pop("rule_refs", []), "duration_ms": extra.pop("duration_ms", 12),
            "safe_result": extra.pop("safe_result", None), "error_code": extra.pop("error_code", None),
            "phase": extra.pop("phase", None), "created_at": "2026-11-28T12:00:00Z"}


def question_run(run_id, status):
    timeout = status == "TIMEOUT"
    events = [
        ev(1, "run_started", "RUN", "RUNNING", "Bắt đầu trả lời câu hỏi"),
        ev(2, "stage_started", "INCIDENT_LOADED", "RUNNING", "Đang truy xuất incident."),
        ev(3, "stage_completed", "INCIDENT_LOADED", "COMPLETED", f"Đã tải {INC}: risk 75/100 (high).", "MANAGER_STORE"),
        ev(4, "stage_completed", "RISK_RULE_EXPLANATION", "COMPLETED", "Tổng đóng góp 75 khớp điểm 75.",
           safe_result={"breakdown_available": True, "final_score": 75, "rule_breakdown": [],
                        "reconciliation": {"status": "OBSERVED", "contributions_sum": 75, "final_score": 75}}),
        ev(5, "stage_started", "ANSWER_GENERATION", "RUNNING", "Đang tạo bản phân tích bằng sec-q5:latest.", "AI_INFERENCE"),
    ]
    if timeout:
        events += [ev(6, "stage_failed", "ANSWER_GENERATION", "TIMEOUT", "Mô hình vượt thời gian chờ; không có kết luận AI.",
                      "AI_INFERENCE", error_code="OLLAMA_TIMEOUT"),
                   ev(7, "run_failed", "RUN", "TIMEOUT", "Hết thời gian chờ mô hình", error_code="OLLAMA_TIMEOUT")]
    else:
        events += [ev(6, "stage_completed", "ANSWER_GENERATION", "COMPLETED", "Mô hình trả lời (lần 1).", "AI_INFERENCE",
                      safe_result={"model": "sec-q5:latest", "attempt": 1}),
                   ev(7, "stage_started", "ANSWER_VERIFICATION", "RUNNING", "Đang kiểm chứng kết luận."),
                   ev(8, "stage_completed", "ANSWER_VERIFICATION", "COMPLETED", "Lần 1: đạt 7/7 kiểm tra.",
                      safe_result={"attempt": 1, "checks": [{"check_id": "score_from_engine", "label": "Điểm khớp Detection Engine",
                                                             "passed": True, "detail": "ok"}]}),
                   # Sanitised server-side; the UI must never render a think block even if one slipped through.
                   ev(9, "answer_delta", "RESULT_SYNTHESIS", "RUNNING", "Detection Engine chấm 75/100.", "AI_INFERENCE"),
                   ev(10, "run_completed", "RUN", "COMPLETED", "Hoàn tất: kết luận AI đã kiểm chứng.")]
    result = {
        "task_type": "risk_question", "question": "Vì sao incident này có risk score 55?",
        "conclusion": ("Detection Engine chấm 75/100, không phải 55." if not timeout else
                       "Detection Engine chấm 75/100 (high). Điểm đến từ: Brute force (+75)."),
        "conclusion_source": "DETERMINISTIC" if timeout else "AI_INFERENCE",
        "risk_score": {"value": 75, "severity": "high", "source": "DETECTION_ENGINE", "breakdown_source": "risk_snapshot"},
        "observed_facts": [{"fact_id": "F1", "statement": "Detection Engine ghi nhận risk score 75/100, mức high.",
                            "certainty": "OBSERVED", "evidence_ids": [INC], "source_type": "MANAGER_STORE"},
                           {"fact_id": "F2", "statement": "16 lần đăng nhập thất bại từ 100.67.222.3.",
                            "certainty": "CORRELATED", "evidence_ids": ["auth-rec-1"], "source_type": "ENDPOINT_AGENT"}],
        "evidence_ids": [INC, "auth-rec-1"], "matched_rules": [{"rule_id": "auth_bruteforce", "label": "Brute force",
                                                                "contribution": 75, "reason": None, "evidence_ids": []}],
        "alternative_explanations": [{"alt_id": "A1", "explanation": "Người dùng nhập sai mật khẩu.", "certainty": "INFERRED",
                                      "basis": "Chỉ có xác thực thất bại.", "evidence_ids": []}],
        "missing_evidence": ["Telemetry tiến trình trong cửa sổ sự cố"],
        "validation_results": [] if timeout else [{"check_id": "score_from_engine", "label": "Điểm khớp Detection Engine",
                                                   "passed": True, "detail": "ok"}],
        "recommendations": [{"text": "Xem lại log xác thực.", "requires_approval": True}],
        "limitations": ["Risk score do Detection Engine tính; AI chỉ giải thích, không thay đổi điểm."],
        "model_name": None if timeout else "sec-q5:latest", "attempts": 0 if timeout else 1,
    }
    run = {"analysis_run_id": run_id, "run_id": run_id, "task_type": "risk_question", "incident_id": INC,
           "status": status, "question": result["question"], "model_name": "sec-q5:latest", "result": result,
           "created_at": "2026-11-28T12:00:00Z", "started_at": "2026-11-28T12:00:00Z",
           "completed_at": "2026-11-28T12:01:30Z"}
    return run, events


RUNS = {"run_q_timeout": question_run("run_q_timeout", "TIMEOUT"), "run_q_done": question_run("run_q_done", "COMPLETED")}
RULE_EVENTS = [
    ev(1, "run_started", "RUN", "RUNNING", "Bắt đầu lượt AI Rule Generator"),
    ev(2, "stage_started", "REQUEST_UNDERSTANDING", "RUNNING", "Đang hiểu yêu cầu.", "AI_INFERENCE"),
    ev(3, "stage_completed", "REQUEST_UNDERSTANDING", "COMPLETED", "Mô hình sec-q5:latest trích ý định.", "AI_INFERENCE",
       safe_result={"model_used": True, "intent": {"platform": None, "parent": [], "child": ["shell"], "command": []},
                    "notices": ["<think>chain of thought</think>"]}),
    ev(4, "stage_completed", "PLATFORM_LOGSOURCE", "COMPLETED", "Chưa xác định được nền tảng — cần hỏi lại.",
       safe_result={"platform": None, "logsource": None, "foreign_children": []}),
    ev(5, "stage_completed", "TELEMETRY_FIELDS", "COMPLETED", "Agent gửi Image, ParentImage.", "ENDPOINT_AGENT",
       safe_result={"fields": ["Image", "ParentImage"], "observed_platforms": ["linux"], "observed_parents": []}),
    ev(6, "clarification_required", "CLARIFICATION", "NEEDS_CLARIFICATION", "Cần làm rõ 1 thông tin trước khi tạo rule.",
       safe_result={"questions": [{"slot": "platform", "text": "Rule chạy trên nền tảng nào?", "options": ["linux", "windows"]}]}),
]
RULE_RUN = {"analysis_run_id": "run_rule_1", "run_id": "run_rule_1", "task_type": "rule_generation",
            "status": "NEEDS_CLARIFICATION", "model_name": "sec-q5:latest", "created_at": "2026-11-28T12:00:00Z",
            "completed_at": "2099-01-01T00:00:00Z",
            "result": {"conversation_id": "c0ffee", "revision": 1, "classification": "NEEDS_CLARIFICATION", "ready": False}}
RULE_STATE = {"conversation_id": "c0ffee", "revision": 1, "context": "Phát hiện web server sinh shell",
              "intent": {"platform": None, "parent": [], "parent_hint": "web server", "child": ["shell"], "command": [],
                         "chaining": False, "severity": "medium", "mitre": [], "title": None},
              "classification": "NEEDS_CLARIFICATION", "ready": False, "sigma_yaml": None, "notices": [],
              "questions": [{"slot": "platform", "text": "Rule chạy trên nền tảng nào?", "options": ["linux", "windows"]}],
              "model_used": True, "has_model_input": True, "model": "sec-q5:latest", "error": None}


def fulfil(route, body, status=200, sse=False):
    if sse:
        route.fulfill(status=200, headers={"content-type": "text/event-stream"}, body=base._make_sse_body(body))
    else:
        route.fulfill(status=status, headers={"content-type": "application/json"}, body=json.dumps(body))


def backend(route):
    url = urlsplit(route.request.url)
    path, query = url.path, parse_qs(url.query)
    method = route.request.method
    if path.endswith(f"/ai/incidents/{INC}/analysis/runs") and query.get("task_type") == ["risk_question"]:
        runs = [RUNS[k][0] for k in ("run_q_done", "run_q_timeout")][2 - min(calls["questions"], 2):]
        return fulfil(route, {"runs": runs})
    if path.endswith(f"/ai/incidents/{INC}/questions") and method == "POST":
        calls["questions"] += 1
        run_id = "run_q_timeout" if calls["questions"] == 1 else "run_q_done"
        return fulfil(route, {"run_id": run_id, "analysis_run_id": run_id, "task_type": "risk_question"}, 202)
    for run_id, (run, events) in RUNS.items():
        if path.endswith(f"/ai/runs/{run_id}/trace"):
            calls["trace_gets"] += 1
            return fulfil(route, snapshot(run_id, run, events))
        if path.endswith(f"/ai/runs/{run_id}/stream"):
            after = int(route.request.headers.get("last-event-id") or query.get("after_sequence", ["0"])[0])
            return fulfil(route, [e for e in events if e["sequence"] > after], sse=True)
    if path.endswith("/rules/assistant/runs"):
        calls["rule_runs"] += 1
        return fulfil(route, {"run_id": "run_rule_1", "task_type": "rule_generation"}, 202)
    if path.endswith("/ai/runs/run_rule_1/trace"):
        calls["trace_gets"] += 1
        return fulfil(route, snapshot("run_rule_1", RULE_RUN, RULE_EVENTS))
    if path.endswith("/ai/runs/run_rule_1/stream"):
        after = int(route.request.headers.get("last-event-id") or query.get("after_sequence", ["0"])[0])
        return fulfil(route, [e for e in RULE_EVENTS if e["sequence"] > after], sse=True)
    if path.endswith("/rules/assistant") and method == "POST":
        return fulfil(route, RULE_STATE)
    return base.backend(route)


def no_leaks(page):
    html = page.content()
    assert "<think>" not in html and "&lt;think&gt;" not in html and "chain of thought" not in html
    assert '"safe_result"' not in html and '"event_type"' not in html


def check(base_url):
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=shutil.which("google-chrome"), headless=True)
        page = browser.new_page()
        page.route("**/api/**", backend)
        page.goto(base_url + "/incidents/lab")
        dialog = page.get_by_role("dialog", name="Đăng nhập Dashboard")
        dialog.get_by_label("Tên đăng nhập").fill("soc-admin")
        dialog.get_by_label("Mật khẩu").fill("StrongPass123!")
        dialog.get_by_role("button", name="Đăng nhập", exact=True).click()
        expect(page.get_by_text("receipt-demo")).to_be_visible()

        # ── AI Risk Analyst ────────────────────────────────────────────────────────────────────
        page.goto(base_url + f"/incidents/{INC}")
        page.get_by_role("button", name="🤖 Phân tích AI", exact=True).click()
        qa = page.get_by_test_id("risk-analyst-qa")
        expect(qa).to_be_visible()
        qa.get_by_test_id("risk-question-input").fill("Vì sao incident này có risk score 55?")
        qa.get_by_test_id("risk-question-send").click()
        status = qa.get_by_test_id("trace-run-status")
        expect(status).to_have_attribute("data-status", "TIMEOUT")
        expect(qa.get_by_test_id("trace-timeout-fallback-banner")).to_be_visible()
        expect(qa.get_by_test_id("trace-stage-ANSWER_GENERATION")).to_have_attribute("data-status", "TIMEOUT")
        expect(qa.get_by_test_id("answer-source")).to_contain_text("không phải AI")
        assert calls["questions"] == 1

        qa.get_by_test_id("trace-retry").click()
        expect(status).to_have_attribute("data-status", "COMPLETED")
        expect(qa.get_by_test_id("answer-source")).to_contain_text("đã qua kiểm chứng")
        expect(qa.get_by_test_id("answer-risk-score")).to_contain_text("75/100")
        expect(qa.get_by_test_id("certainty-CORRELATED").first).to_be_visible()
        expect(qa.get_by_test_id("trace-stage-ANSWER_VERIFICATION")).to_have_attribute("data-status", "COMPLETED")
        assert calls["questions"] == 2
        no_leaks(page)

        before = dict(calls)
        qa.get_by_test_id("toggle-trace-details").click()
        expect(qa.get_by_test_id("trace-stage-ANSWER_VERIFICATION")).to_be_hidden()
        qa.get_by_test_id("toggle-trace-details").click()
        expect(qa.get_by_test_id("trace-stage-ANSWER_VERIFICATION")).to_be_visible()
        assert calls == before, (calls, before)   # hide/show never calls the AI or the API

        page.reload()
        page.get_by_role("button", name="🤖 Phân tích AI", exact=True).click()
        expect(page.get_by_test_id("risk-analyst-qa").get_by_test_id("answer-risk-score")).to_contain_text("75/100")
        assert calls["questions"] == 2, "reload must reattach to the stored run, not ask again"

        # ── AI Rule Generator ──────────────────────────────────────────────────────────────────
        page.goto(base_url + "/ai-dashboard/harvest")
        page.get_by_placeholder("Ví dụ: báo khi nginx sinh shell chạy whoami").fill("Phát hiện web server sinh shell")
        page.keyboard.press("Enter")
        expect(page.get_by_test_id("trace-run-status")).to_have_attribute("data-status", "NEEDS_CLARIFICATION")
        expect(page.get_by_test_id("trace-stage-REQUEST_UNDERSTANDING")).to_be_visible()
        expect(page.get_by_test_id("trace-stage-CLARIFICATION")).to_be_visible()
        expect(page.get_by_role("button", name="windows", exact=True)).to_be_visible()
        assert calls["rule_runs"] == 1
        no_leaks(page)
        rule_runs = calls["rule_runs"]
        page.get_by_test_id("toggle-trace-details").click()
        expect(page.get_by_test_id("trace-stage-CLARIFICATION")).to_be_hidden()
        assert calls["rule_runs"] == rule_runs
        print("risk analyst timeout→retry→verified, reload reattach, rule generator clarification, no leaks: passed")
        browser.close()


class SpaFiles(base.DashboardFiles):
    def do_GET(self):
        if self.path.startswith("/ai-dashboard/"):
            self.path = "/index.html"
        super().do_GET()


if __name__ == "__main__":
    dist = Path(__file__).resolve().parents[1] / "dist"
    if not (dist / "index.html").is_file():
        raise SystemExit("Build the frontend before running this browser test")
    handler = partial(SpaFiles, directory=dist)
    with ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            check(f"http://127.0.0.1:{server.server_port}")
        finally:
            server.shutdown()
            thread.join()
