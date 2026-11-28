"""Run against a local production build with Chromium and an isolated API fixture (username/password + JWT + HttpOnly refresh cookie)."""

import json
import shutil
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from time import perf_counter
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

incident = {
    "id": "lab",
    "agent_id": "victim",
    "title": "Flask login failures",
    "severity": "high",
    "status": "open",
    "detection_evidence": {
        "behavior": {"source": "auth_events", "service": "flask_web"}
    },
}
inc_ref = {
    "id": "inc_90940e8f23fb",
    "agent_id": "ip-172-31-32-238",
    "title": "HTTP Authentication Brute Force (Hydra)",
    "severity": "high",
    "risk_score": 75,
    "status": "open",
    "incident_status": "open",
    "detection_activity": "historical",
    "created_at": "2026-11-26T09:31:39Z",
    "detection_evidence": {
        "behavior": {
            "source": "auth_events",
            "classification": "authentication_brute_force",
            "source_ip": "100.67.222.3",
            "service": "flask_web",
            "auth_failures": 16,
            "auth_successes": 0,
            "http_client": "Hydra",
        }
    },
}
seen_auth = []
active_refresh_cookie = {"value": None}
trace_state = {"run_calls": 0, "inc9094_done": False, "inc9094_events": []}


def _make_sse_body(events):
    return "".join(
        f"id: {ev['sequence']}\nevent: {ev['event_type']}\ndata: {json.dumps(ev, ensure_ascii=False)}\n\n"
        for ev in events
    )


def backend(route):
    path = urlsplit(route.request.url).path
    auth = route.request.headers.get("authorization")
    csrf = route.request.headers.get("x-larp-csrf")
    cookie = route.request.headers.get("cookie", "")
    headers = {}
    status = 200

    if path.endswith("/ai/incidents/inc_90940e8f23fb/analysis/runs"):
        if trace_state["inc9094_done"]:
            body = {
                "incident_id": "inc_90940e8f23fb",
                "runs": [
                    {
                        "analysis_run_id": "run_demo_9094",
                        "incident_id": "inc_90940e8f23fb",
                        "mode": "fresh",
                        "status": "COMPLETED",
                        "model_name": "sec-q5:latest",
                        "started_at": "2026-11-26T09:32:00Z",
                        "completed_at": "2026-11-26T09:32:04Z",
                        "created_at": "2026-11-26T09:32:00Z",
                    }
                ],
            }
        else:
            body = {"incident_id": "inc_90940e8f23fb", "runs": []}
    elif path.endswith("/ai/incidents/inc_90940e8f23fb/analysis/run"):
        trace_state["run_calls"] += 1
        trace_state["inc9094_done"] = True
        trace_state["inc9094_events"] = [
            {
                "event_id": "tr_1",
                "analysis_run_id": "run_demo_9094",
                "incident_id": "inc_90940e8f23fb",
                "sequence": 1,
                "event_type": "analysis_started",
                "stage": "INCIDENT_LOADED",
                "status": "RUNNING",
                "source_type": "DETERMINISTIC",
                "duration_ms": 5,
                "summary": "Khởi tạo phiên phân tích sự cố inc_90940e8f23fb",
                "evidence_refs": ["inc_90940e8f23fb"],
                "rule_refs": [],
            },
            {
                "event_id": "tr_2",
                "analysis_run_id": "run_demo_9094",
                "incident_id": "inc_90940e8f23fb",
                "sequence": 2,
                "event_type": "stage_completed",
                "stage": "RISK_RULE_EXPLANATION",
                "status": "COMPLETED",
                "source_type": "DETERMINISTIC",
                "duration_ms": 18,
                "summary": "Phân rã điểm rủi ro 75/100 theo rule brute_force",
                "evidence_refs": ["auth-rec-1"],
                "rule_refs": ["brute_force"],
                "safe_result": {
                    "breakdown_available": True,
                    "final_score": 75.0,
                    "raw_score": 75.0,
                    "previous_smoothed": 15.0,
                    "ema_applied": False,
                    "security_attack_bypass": True,
                    "rule_breakdown": [
                        {
                            "rule_id": "brute_force",
                            "matched": True,
                            "raw_score": 75.0,
                            "debounced_score": 75.0,
                            "weight": 1.0,
                            "weighted_contribution": 75.0,
                            "evidence_ids": ["auth-rec-1"],
                            "reason": "16 auth failures from 100.67.222.3",
                        }
                    ],
                },
            },
            {
                "event_id": "tr_3",
                "analysis_run_id": "run_demo_9094",
                "incident_id": "inc_90940e8f23fb",
                "sequence": 3,
                "event_type": "stage_skipped",
                "stage": "PROCESS_NETWORK_CORRELATION",
                "status": "SKIPPED",
                "source_type": "ENDPOINT_AGENT",
                "duration_ms": 2,
                "summary": "Không có telemetry tiến trình cho brute-force HTTP; bỏ qua liên kết PID.",
                "evidence_refs": [],
                "rule_refs": [],
                "safe_result": {"status": "UNKNOWN", "matched_pids": []},
            },
            {
                "event_id": "tr_4",
                "analysis_run_id": "run_demo_9094",
                "incident_id": "inc_90940e8f23fb",
                "sequence": 4,
                "event_type": "stage_completed",
                "stage": "CLAIM_VERIFICATION",
                "status": "COMPLETED",
                "source_type": "DETERMINISTIC",
                "duration_ms": 9,
                "summary": "Đạt 6/6 kiểm chứng bằng chứng",
                "evidence_refs": ["auth-rec-1"],
                "rule_refs": [],
                "safe_result": {
                    "passed": True,
                    "checks": [
                        {
                            "check_id": "evidence_ids_exist",
                            "label": "Mã bằng chứng trích dẫn tồn tại",
                            "passed": True,
                            "certainty": "OBSERVED",
                            "detail": "Tất cả mã bằng chứng đều thuộc ngữ cảnh sự cố.",
                        }
                    ],
                },
            },
            {
                "event_id": "tr_5",
                "analysis_run_id": "run_demo_9094",
                "incident_id": "inc_90940e8f23fb",
                "sequence": 5,
                "event_type": "analysis_completed",
                "stage": "RESPONSE_RECOMMENDATION",
                "status": "COMPLETED",
                "source_type": "DETERMINISTIC",
                "duration_ms": 14,
                "summary": "Hoàn tất phân tích sự cố inc_90940e8f23fb",
                "safe_result": {"analysis_id": "ana_9094"},
            },
        ]
        status = 202
        body = {
            "status": "analyzing",
            "mode": "fresh",
            "analysis_run_id": "run_demo_9094",
            "reused_active_run": False,
            "stream_url": "/api/v1/ai/runs/run_demo_9094/stream",
        }
    elif path.endswith("/ai/runs/run_demo_9094/trace"):
        body = {
            "run": {
                "analysis_run_id": "run_demo_9094",
                "incident_id": "inc_90940e8f23fb",
                "mode": "fresh",
                "status": "COMPLETED",
                "model_name": "sec-q5:latest",
                "started_at": "2026-11-26T09:32:00Z",
                "completed_at": "2026-11-26T09:32:04Z",
                "created_at": "2026-11-26T09:32:00Z",
            },
            "events": trace_state["inc9094_events"],
        }
    elif path.endswith("/ai/runs/run_demo_9094/stream"):
        assert auth in ("Bearer jwt-access-1", "Bearer jwt-access-2"), f"Missing JWT header on SSE: {auth}"
        route.fulfill(
            status=200,
            headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache"},
            body=_make_sse_body(trace_state["inc9094_events"]),
        )
        return
    elif path.endswith("/ai/incidents/inc_chain_demo/analysis/runs"):
        body = {
            "incident_id": "inc_chain_demo",
            "runs": [
                {
                    "analysis_run_id": "run_chain_timeout",
                    "incident_id": "inc_chain_demo",
                    "mode": "fresh",
                    "status": "TIMEOUT",
                    "model_name": "sec-q5:latest",
                    "started_at": "2026-11-26T10:00:00Z",
                    "completed_at": "2026-11-26T10:02:00Z",
                    "created_at": "2026-11-26T10:00:00Z",
                }
            ],
        }
    elif path.endswith("/ai/runs/run_chain_timeout/trace"):
        body = {
            "run": {
                "analysis_run_id": "run_chain_timeout",
                "incident_id": "inc_chain_demo",
                "mode": "fresh",
                "status": "TIMEOUT",
                "model_name": "sec-q5:latest",
                "started_at": "2026-11-26T10:00:00Z",
                "completed_at": "2026-11-26T10:02:00Z",
                "created_at": "2026-11-26T10:00:00Z",
            },
            "events": [
                {
                    "event_id": "tr_c1",
                    "analysis_run_id": "run_chain_timeout",
                    "incident_id": "inc_chain_demo",
                    "sequence": 1,
                    "event_type": "stage_failed",
                    "stage": "MODEL_INFERENCE",
                    "status": "TIMEOUT",
                    "source_type": "AI_INFERENCE",
                    "duration_ms": 115000,
                    "summary": "Mô hình sec-q5:latest vượt ngưỡng thời gian chờ",
                    "evidence_refs": [],
                    "rule_refs": [],
                },
                {
                    "event_id": "tr_c2",
                    "analysis_run_id": "run_chain_timeout",
                    "incident_id": "inc_chain_demo",
                    "sequence": 2,
                    "event_type": "stage_completed",
                    "stage": "DETERMINISTIC_FALLBACK",
                    "status": "COMPLETED",
                    "source_type": "DETERMINISTIC",
                    "duration_ms": 12,
                    "summary": "Đã sinh kết luận dự phòng từ web_compromise_chain",
                    "evidence_refs": ["flow1"],
                    "rule_refs": ["web_compromise_chain"],
                },
            ],
        }
    elif path.endswith("/auth/login"):
        payload = json.loads(route.request.post_data or "{}")
        assert payload.get("username") == "soc-admin"
        assert payload.get("password") == "StrongPass123!"
        active_refresh_cookie["value"] = "rt-1"
        headers["Set-Cookie"] = "larp_refresh_token=rt-1; Path=/api/v1/auth; HttpOnly; SameSite=Lax"
        body = {
            "access_token": "jwt-access-1",
            "token_type": "bearer",
            "expires_in": 900,
            "user": {"id": "u1", "username": "soc-admin", "role": "operator", "agent_scopes": ["victim", "ip-172-31-32-238"]},
        }
    elif path.endswith("/auth/refresh"):
        assert csrf == "1"
        if active_refresh_cookie["value"] and f"larp_refresh_token={active_refresh_cookie['value']}" in cookie:
            active_refresh_cookie["value"] = "rt-2"
            headers["Set-Cookie"] = "larp_refresh_token=rt-2; Path=/api/v1/auth; HttpOnly; SameSite=Lax"
            body = {
                "access_token": "jwt-access-2",
                "token_type": "bearer",
                "expires_in": 900,
                "user": {"id": "u1", "username": "soc-admin", "role": "operator", "agent_scopes": ["victim", "ip-172-31-32-238"]},
            }
        else:
            status = 401
            body = {"detail": "Refresh session required", "outcome_code": "SESSION_EXPIRED"}
    elif path.endswith("/auth/logout"):
        assert csrf == "1"
        active_refresh_cookie["value"] = None
        headers["Set-Cookie"] = "larp_refresh_token=; Path=/api/v1/auth; Max-Age=0; HttpOnly; SameSite=Lax"
        body = {"status": "logged_out"}
    elif path.endswith("/incidents/inc_90940e8f23fb/response-proposals"):
        seen_auth.append(auth)
        if auth not in ("Bearer jwt-access-1", "Bearer jwt-access-2"):
            status = 401
            body = {"detail": "A valid administrator or operator access token is required", "outcome_code": "AUTHORIZATION_FAILED"}
        else:
            body = {
                "can_execute": True,
                "agent_online": True,
                "investigation": {
                    "classification": "authentication_brute_force",
                    "confidence": 0.9,
                    "evidence_completeness": "partial",
                    "behavioral_interpretation": "Phát hiện 16 lần đăng nhập thất bại liên tiếp từ 100.67.222.3 tới dịch vụ flask_web.",
                    "observed_facts": ["16 lần HTTP 401 tới /login từ 100.67.222.3", "Chưa ghi nhận lần đăng nhập thành công"],
                    "missing_evidence": ["Verified enforcement point"],
                    "recommended_responses": [
                        {
                            "action_id": "a8a5b2b4e9c44f779fdcbb869040c6b8",
                            "action_type": "collect_additional_evidence",
                        }
                    ],
                },
                "actions": [
                    {
                        "action_id": "a8a5b2b4e9c44f779fdcbb869040c6b8",
                        "action_type": "collect_additional_evidence",
                        "target_agent_id": "ip-172-31-32-238",
                        "recommendation_source": "evidence_policy",
                        "requires_approval": True,
                        "status": "succeeded",
                        "proposal_created_at": "2026-11-26T09:31:39Z",
                        "target_resource": {"source_ip": "100.67.222.3", "endpoint": "/login", "method": "POST"},
                        "audit_events": [
                            {"event": "proposed", "actor": "policy", "at": "2026-11-26T09:31:39Z"},
                            {"event": "pending_approval", "actor": "policy", "at": "2026-11-26T09:31:39Z"},
                            {"event": "approved", "actor": "soc-admin", "at": "2026-11-26T09:32:13Z"},
                            {"event": "dispatched", "actor": "manager", "at": "2026-11-26T09:32:27Z"},
                            {"event": "executing", "actor": "ip-172-31-32-238", "at": "2026-11-26T09:32:30Z"},
                            {"event": "verifying", "actor": "manager", "at": "2026-11-26T09:32:31Z"},
                            {"event": "succeeded", "actor": "manager", "at": "2026-11-26T09:32:31Z"},
                        ],
                        "result": {
                            "command_id": "a8a5b2b4e9c44f779fdcbb869040c6b8",
                            "verification": {
                                "verification_status": "succeeded",
                                "verification_method": "authenticated_network_snapshot",
                                "evidence_refs": ["4566437fc3ba49e0a0e1379cf7524a82"],
                                "observed_at": "2026-11-26T09:32:31Z",
                            },
                            "related_records": {
                                "http": [{"id": "http-rec-1", "method": "POST", "path": "/login", "status_code": 401, "source_ip": "100.67.222.3", "user_agent": "Hydra", "timestamp": "2026-11-26T09:31:39Z"}],
                                "authentication": [{"id": "auth-rec-1", "username": "admin", "status": "failed", "source_ip": "100.67.222.3", "timestamp": "2026-11-26T09:31:39Z"}],
                                "flows": [{"id": "flow-rec-1", "src_ip": "100.67.222.3", "dst_ip": "100.112.146.63", "dst_port": 5000, "protocol": "TCP", "timestamp": "2026-11-26T09:31:39Z"}],
                                "process_metadata_in_window": [],
                            },
                        },
                    }
                ],
            }
    elif path.endswith("/incidents/inc_90940e8f23fb/ai-analysis"):
        body = {
            "incident_id": "inc_90940e8f23fb",
            "created_at": "2026-11-26T09:31:50Z",
            "confidence": 0.9,
            "summary": "## Tóm tắt điều tra\n- Nguồn **100.67.222.3** gửi 16 yêu cầu thất bại tới `flask_web`.",
            "root_cause": "Dò mật khẩu HTTP bằng công cụ Hydra.",
            "mitre_techniques": ["T1110"],
            "recommended_actions": ["Thu thập bằng chứng và xác minh điểm chặn HTTP."],
        }
    elif path.endswith("/incidents/inc_90940e8f23fb/timeline"):
        body = [
            {
                "type": "rule_trigger",
                "title": "Phát hiện dò mật khẩu HTTP",
                "severity": "warning",
                "time": "2026-11-26T09:31:39Z",
                "details": {"rule": "authentication_brute_force", "score": 75, "reason": "16 auth failures"},
            }
        ]
    elif path.endswith("/incidents/inc_90940e8f23fb"):
        body = inc_ref
    elif path.endswith("/incidents/inc_chain_demo"):
        body = {
            "id": "inc_chain_demo",
            "agent_id": "ip-172-31-32-238",
            "title": "Web Application Compromise: reverse shell to 100.67.222.3:4444 on Agent 'ip-172-31-32-238' (Score: 100)",
            "severity": "critical",
            "risk_score": 100,
            "status": "open",
            "detection_activity": "active",
            "created_at": "2026-11-27T09:00:00Z",
            "detection_evidence": {
                "rule_id": "web_compromise_chain",
                "chain": {
                    "anchor": {"id": "proc_web", "pid": 153380, "name": "python", "exe": "/usr/bin/python3.13", "cmdline": "python /opt/larp-agent/vulnerable_web/app.py"},
                    "source_ips": ["100.67.222.3"],
                    "severity_reason": "Thực thi mã từ web process đã được quan sát và tiến trình đó giữ kết nối ra ngoài",
                    "execution_observed": True,
                    "conditions": [
                        {"id": "auth_bypass", "label": "Vượt xác thực", "status": "OBSERVED", "detail": "SQLi bypass", "evidence_ids": ["auth1"], "observed_at": "2026-11-27T09:00:00Z"},
                        {"id": "suspicious_upload", "label": "Upload file đáng ngờ", "status": "CORRELATED", "detail": "/tmp/uploads/backdoor.py", "evidence_ids": ["up1"], "observed_at": "2026-11-27T09:00:10Z", "upload_path": "/tmp/uploads/backdoor.py", "upload_sha256": "c" * 64},
                        {"id": "outbound_connection", "label": "Kết nối điều khiển ngược", "status": "OBSERVED", "detail": "PID 154107 -> 100.67.222.3:4444", "evidence_ids": ["flow1"], "observed_at": "2026-11-27T09:00:25Z"},
                    ],
                    "process_tree": [
                        {"id": "proc_web", "pid": 153380, "parent_pid": 1, "name": "python", "exe": "/usr/bin/python3.13", "cmdline": "python /opt/larp-agent/vulnerable_web/app.py"},
                        {"id": "proc_py", "pid": 154107, "parent_pid": 1, "name": "python3", "exe": "/usr/bin/python3.13", "cmdline": "python3 /tmp/uploads/backdoor.py", "euid": 0, "process_start_time": 1700000000.0, "started_at": "2026-11-27T09:00:20Z"},
                    ],
                    "network": [{"flow_id": "flow1", "src": "100.112.146.63:40986", "dst": "100.67.222.3:4444", "direction": "outbound", "pid": 154107, "socket_stdio": True, "first_seen": "2026-11-27T09:00:25Z"}],
                },
            },
        }
    elif path.endswith("/incidents/inc_chain_demo/ai-analysis"):
        body = {
            "incident_id": "inc_chain_demo",
            "created_at": "2026-11-27T09:01:00Z",
            "confidence": 0.9,
            "model_name": "rule-based",
            "summary": "### Tóm tắt sự cố\nWeb application trên Agent đã sinh tiến trình chạy /tmp/uploads/backdoor.py và mở kết nối tới 100.67.222.3:4444.",
            "root_cause": "Chuỗi xâm nhập web dẫn đến reverse shell.",
            "mitre_techniques": [{"id": "T1059.006", "name": "Python", "tactic": "Execution", "evidence": "proc_py"}],
            "raw_response": json.dumps({"status": "timeout", "analysis_source": "RULE_BASED_FALLBACK", "classification": "likely_malicious"}),
        }
    elif path.endswith("/containment/incidents/inc_chain_demo/overview"):
        body = {
            "incident_id": "inc_chain_demo",
            "agent_id": "ip-172-31-32-238",
            "severity": "critical",
            "risk_score": 100,
            "is_chain": True,
            "agent_online": True,
            "stages": [
                {"id": "auth_bypass", "status": "OBSERVED", "detail": "SQLi"},
                {"id": "suspicious_upload", "status": "CORRELATED", "detail": "/tmp/uploads/backdoor.py"},
                {"id": "outbound_connection", "status": "OBSERVED", "detail": "100.67.222.3:4444"},
            ],
            "inferred_requests": [],
            "files": [{"path": "/tmp/uploads/backdoor.py", "sha256": "c" * 64, "uploaded": True, "executed_by": [154107], "state": "EXECUTION_OBSERVED", "file_status": "FILE_EXECUTION_CORRELATED"}],
            "processes": [{"id": "proc_py", "pid": 154107, "parent_pid": 1, "exe": "/usr/bin/python3.13", "cmdline": "python3 /tmp/uploads/backdoor.py", "euid": 0, "process_start_time": 1700000000.0, "live": {"state": "RUNNING", "label": "Đang chạy"}}],
            "network": [{"flow_id": "flow1", "src": "100.112.146.63:40986", "dst": "100.67.222.3:4444", "pid": 154107, "socket_stdio": True, "live": {"state": "ESTABLISHED", "label": "Đang kết nối"}}],
            "actions": [],
            "ip_blocks": [],
            "capabilities": {"collect_process_evidence": True, "inspect_file": True, "quarantine_file": True, "restore_file": True, "terminate_process": True, "block_ip": True},
        }
    elif path.endswith("/access-control/incidents/inc_chain_demo/suggestions"):
        body = {"items": [{"ip": "100.67.222.3", "basis": ["Đích kết nối ra ngoài của PID 154107"], "allowed": True}]}
    elif path.endswith("/incidents/inc_chain_demo/timeline"):
        body = {"timeline": []}
    elif path.endswith("/response-proposals"):
        seen_auth.append(auth)
        if auth not in ("Bearer jwt-access-1", "Bearer jwt-access-2"):
            status = 401
            body = {"detail": "A valid administrator or operator access token is required", "outcome_code": "AUTHORIZATION_FAILED"}
        else:
            body = {
                "can_execute": False,
                "agent_online": False,
                "actions": [
                    {
                        "action_id": "a",
                        "action_type": "temporary_ip_block",
                        "target_agent_id": "victim",
                        "status": "succeeded",
                        "result": {
                            "verification": {
                                "verification_status": "succeeded",
                                "evidence_refs": ["receipt-demo"],
                            }
                        },
                    },
                    {
                        "action_id": "b",
                        "action_type": "apply_rate_limit",
                        "status": "approved",
                    },
                ],
            }
    elif path.endswith("/incidents/lab"):
        body = incident
    elif path.endswith("/incidents/"):
        body = [
            incident,
            inc_ref,
            {"id": "inc_chain_demo", "agent_id": "ip-172-31-32-238", "title": "Web Compromise Reverse Shell", "severity": "critical", "risk_score": 100, "status": "open", "detection_evidence": {"rule_id": "web_compromise_chain", "chain": {"execution_observed": True}}},
        ]
    else:
        body = []

    route.fulfill(status=status, headers=headers, json=body)


def check_dashboard(base_url):
    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=shutil.which("google-chrome"), headless=True
        )
        page = browser.new_page()
        page.route("**/api/**", backend)
        page.goto(base_url + "/incidents/lab")

        dialog = page.get_by_role("dialog", name="Đăng nhập Dashboard")
        expect(dialog).to_be_visible()
        dialog.get_by_label("Tên đăng nhập").fill("soc-admin")
        dialog.get_by_label("Mật khẩu").fill("StrongPass123!")

        started = perf_counter()
        dialog.get_by_role("button", name="Đăng nhập", exact=True).click()
        expect(page.get_by_text("Phiếu xác nhận bằng chứng:")).to_be_visible()
        expect(page.get_by_text("receipt-demo")).to_be_visible()
        print("ui_signin_to_receipt_ms", round((perf_counter() - started) * 1000))

        # Access/refresh tokens must never be written to localStorage or sessionStorage.
        storage_counts = page.evaluate(
            "() => ({ ls: Object.keys(localStorage).length, ss: Object.keys(sessionStorage).length })"
        )
        assert storage_counts == {"ls": 0, "ss": 0}, storage_counts

        assert page.get_by_role("button", name="Thực thi hành động", exact=False).is_disabled()
        expect(page.get_by_text("soc-admin", exact=True)).to_be_visible()

        seen_auth.clear()
        page.reload()
        expect(page.get_by_text("Phiếu xác nhận bằng chứng:")).to_be_visible()
        expect(page.get_by_text("receipt-demo")).to_be_visible()
        assert seen_auth and set(seen_auth) == {"Bearer jwt-access-2"}, seen_auth
        expect(page.get_by_role("dialog", name="Đăng nhập Dashboard")).to_be_hidden()

        # Verify reference incident inc_90940e8f23fb Vietnamese UX:
        # 1) Investigation vs Blocked banner
        # 2) EvidenceExplorer tabs (without raw JSON dump expanded by default)
        # 3) Safe AIAnalysisTab rendering without raw ## or ** Markdown syntax
        page.goto(base_url + "/incidents/inc_90940e8f23fb")
        expect(page.get_by_text("chưa thực hiện hoặc chứng minh đã chặn cuộc tấn công")).to_be_visible()
        expect(page.get_by_role("button", name="HTTP (1)", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="Xác thực (1)", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="Mạng (Flows) (1)", exact=True)).to_be_visible()
        expect(page.get_by_role("button", name="Tiến trình (0)", exact=True)).to_be_visible()
        page.get_by_role("button", name="Xác thực (1)", exact=True).click()
        expect(page.get_by_text("auth-rec-1", exact=True)).to_be_visible()
        assert page.locator("pre:visible").count() == 0

        page.get_by_role("button", name="🤖 Phân tích AI", exact=True).click()
        expect(page.get_by_text("Tóm tắt điều tra")).to_be_visible()
        expect(page.get_by_test_id("decision-trace-panel")).to_be_visible()
        expect(page.get_by_text("Sự cố này chưa có lịch sử Decision Trace")).to_be_visible()
        page.get_by_role("button", name="Phân tích lại bằng AI").first.click()
        expect(page.get_by_test_id("trace-stage-RISK_RULE_EXPLANATION")).to_be_visible()
        expect(page.get_by_test_id("trace-stage-CLAIM_VERIFICATION")).to_be_visible()
        expect(page.get_by_text("Bỏ qua EMA (Critical / Security Attack)")).to_be_visible()
        runs_before_toggle = trace_state["run_calls"]
        page.get_by_test_id("toggle-trace-details").click()
        expect(page.get_by_test_id("trace-stage-RISK_RULE_EXPLANATION")).to_be_hidden()
        assert trace_state["run_calls"] == runs_before_toggle, "Toggle must not re-run analysis"
        page.get_by_test_id("toggle-trace-details").click()
        expect(page.get_by_test_id("trace-stage-RISK_RULE_EXPLANATION")).to_be_visible()
        # Reload persists trace cleanly
        page.reload()
        page.get_by_role("button", name="🤖 Phân tích AI", exact=True).click()
        expect(page.get_by_text("run_demo_90")).to_be_visible()
        page.get_by_test_id("toggle-trace-details").click()
        expect(page.get_by_test_id("trace-stage-RISK_RULE_EXPLANATION")).to_be_visible()
        ai_text = page.locator("body").inner_text()
        assert "## " not in ai_text and "**" not in ai_text

        # Verify web_compromise_chain UX (ContainmentPanel + AIAnalysisTab timeout warning + Timeout Fallback Trace)
        page.goto(base_url + "/incidents/inc_chain_demo")
        expect(page.get_by_text("Phát hiện xâm nhập")).to_be_visible()
        expect(page.get_by_text("Đã tương quan upload & thực thi")).to_be_visible()
        expect(page.get_by_text("PID 154107").first).to_be_visible()
        expect(page.get_by_text("100.67.222.3:4444").first).to_be_visible()
        expect(page.get_by_role("button", name="Đề xuất cách ly")).to_be_visible()
        expect(page.get_by_role("button", name="Đề xuất dừng tiến trình")).to_be_visible()

        page.get_by_role("button", name="🤖 Phân tích AI", exact=True).click()
        expect(page.get_by_text("Mô hình AI quá thời gian chờ (timeout)")).to_be_visible()
        page.get_by_test_id("toggle-trace-details").click()
        expect(page.get_by_test_id("trace-timeout-fallback-banner")).to_be_visible()
        expect(page.get_by_test_id("trace-stage-DETERMINISTIC_FALLBACK")).to_be_visible()
        chain_ai_text = page.locator("body").inner_text()
        assert "## " not in chain_ai_text and "**" not in chain_ai_text

        page.get_by_role("button", name="Đăng xuất", exact=True).click()
        expect(page.get_by_role("button", name="Đăng nhập", exact=True)).to_be_visible()
        assert active_refresh_cookie["value"] is None
        print("login, in-memory JWT, reload refresh rotation, receipt, inc_90940e8f23fb Vietnamese UX, logout passed")
        browser.close()


class DashboardFiles(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/incidents/"):
            self.path = "/index.html"
        super().do_GET()


if __name__ == "__main__":
    dist = Path(__file__).resolve().parents[1] / "dist"
    if not (dist / "index.html").is_file():
        raise SystemExit("Build the frontend before running this browser test")
    handler = partial(DashboardFiles, directory=dist)
    with ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            check_dashboard(f"http://127.0.0.1:{server.server_port}")
        finally:
            server.shutdown()
            thread.join()
