"""Run against a local production build with Chromium and an isolated API fixture."""

import shutil
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from playwright.sync_api import sync_playwright, expect
from urllib.parse import urlsplit
from time import perf_counter

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
seen = []


def backend(route):
    path = urlsplit(route.request.url).path
    auth = route.request.headers.get("authorization")
    status = 200
    if path.endswith("/auth/session"):
        assert auth == "Bearer synthetic-local-operator"
        body = {
            "access_token": "test-session",
            "actor": "operator",
            "expires_at": 9999999999,
            "role": "operator",
        }
    elif path.endswith("/response-proposals"):
        seen.append(auth)
        if auth != "Bearer test-session":
            status = 401
            body = {"detail": "Sign in", "outcome_code": "AUTHORIZATION_FAILED"}
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
    route.fulfill(status=status, json=body)


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
        dialog.get_by_label("Operator token").fill("synthetic-local-operator")
        started = perf_counter()
        dialog.get_by_role("button", name="Đăng nhập", exact=True).click()
        expect(page.get_by_text("Evidence Receipts: receipt-demo")).to_be_visible()
        print("ui_signin_to_receipt_ms", round((perf_counter() - started) * 1000))
        assert page.get_by_role(
            "button", name="Execute Action", exact=False
        ).is_disabled()
        seen.clear()
        page.reload()
        expect(page.get_by_text("Evidence Receipts: receipt-demo")).to_be_visible()
        assert seen and set(seen) == {"Bearer test-session"}
        print("same-tab refresh, bearer, receipt, disabled Execute passed")
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
