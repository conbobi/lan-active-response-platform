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


def backend(route):
    path = urlsplit(route.request.url).path
    auth = route.request.headers.get("authorization")
    csrf = route.request.headers.get("x-larp-csrf")
    cookie = route.request.headers.get("cookie", "")
    headers = {}
    status = 200

    if path.endswith("/auth/login"):
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
        body = [incident, inc_ref]
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
        ai_text = page.locator("body").inner_text()
        assert "## " not in ai_text and "**" not in ai_text

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
