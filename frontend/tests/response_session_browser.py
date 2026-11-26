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
            "user": {"id": "u1", "username": "soc-admin", "role": "operator", "agent_scopes": ["victim"]},
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
                "user": {"id": "u1", "username": "soc-admin", "role": "operator", "agent_scopes": ["victim"]},
            }
        else:
            status = 401
            body = {"detail": "Refresh session required", "outcome_code": "SESSION_EXPIRED"}
    elif path.endswith("/auth/logout"):
        assert csrf == "1"
        active_refresh_cookie["value"] = None
        headers["Set-Cookie"] = "larp_refresh_token=; Path=/api/v1/auth; Max-Age=0; HttpOnly; SameSite=Lax"
        body = {"status": "logged_out"}
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
        body = [incident]
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
        expect(page.get_by_text("Evidence Receipts: receipt-demo")).to_be_visible()
        print("ui_signin_to_receipt_ms", round((perf_counter() - started) * 1000))

        # Access/refresh tokens must never be written to localStorage or sessionStorage.
        storage_counts = page.evaluate(
            "() => ({ ls: Object.keys(localStorage).length, ss: Object.keys(sessionStorage).length })"
        )
        assert storage_counts == {"ls": 0, "ss": 0}, storage_counts

        assert page.get_by_role("button", name="Execute Action", exact=False).is_disabled()
        expect(page.get_by_text("soc-admin", exact=True)).to_be_visible()

        seen_auth.clear()
        page.reload()
        expect(page.get_by_text("Evidence Receipts: receipt-demo")).to_be_visible()
        assert seen_auth and set(seen_auth) == {"Bearer jwt-access-2"}, seen_auth
        expect(page.get_by_role("dialog", name="Đăng nhập Dashboard")).to_be_hidden()

        page.get_by_role("button", name="Đăng xuất", exact=True).click()
        expect(page.get_by_role("button", name="Đăng nhập", exact=True)).to_be_visible()
        assert active_refresh_cookie["value"] is None
        print("login, in-memory JWT, reload refresh rotation, receipt, logout passed")
        browser.close()


class DashboardFiles(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/incidents/lab":
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
