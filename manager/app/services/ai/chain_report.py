"""Vietnamese incident report for a correlated web-compromise chain, built only from evidence.

Used for every analysis of a chain incident, whether the model answered or not: the narrative
sections (timeline, process / file / network evidence, impact, response priorities, missing
evidence) are rendered from the projected context, and every statement cites evidence IDs. The
model's contribution is the classification and confidence, which the header labels by source.
Nothing here claims root, RCE or a reverse shell unless the corresponding evidence exists.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

STAGE_LABEL = {
    "auth_bypass": "Đăng nhập vượt xác thực", "suspicious_upload": "Upload file đáng ngờ",
    "command_injection": "Command injection", "web_spawned_shell": "Web process sinh shell/interpreter",
    "uploaded_file_execution": "Thực thi file đáng ngờ", "outbound_connection": "Kết nối ra ngoài (điều khiển ngược)",
    "privileged_execution": "Thực thi với quyền root",
}
STAGE_ORDER = list(STAGE_LABEL)
STATUS = {"OBSERVED": "quan sát trực tiếp", "CORRELATED": "liên kết qua khóa dữ liệu", "NOT_OBSERVED": "chưa quan sát"}
SOURCE_LABEL = {
    "ok": "Phân tích AI (mô hình đã đánh giá bằng chứng hiện tại)",
    "timeout": "⚠ Mô hình AI quá thời gian — báo cáo dưới đây tổng hợp xác định từ bằng chứng, KHÔNG phải phân tích AI",
    "schema_invalid": "⚠ Mô hình AI trả kết quả không hợp lệ — báo cáo tổng hợp xác định từ bằng chứng",
    "model_error": "⚠ Không gọi được mô hình AI — báo cáo tổng hợp xác định từ bằng chứng",
    "deterministic": "Báo cáo xác định từ bằng chứng (không cần gọi mô hình)",
    "budget_exceeded": "⚠ Bằng chứng vượt giới hạn ngữ cảnh của mô hình nên không gửi cho AI — báo cáo tổng hợp xác định từ bằng chứng, KHÔNG phải phân tích AI",
    "evidence_changed": "⚠ Bằng chứng thay đổi trong lúc phân tích — đang chờ phân tích lại; nội dung dưới đây theo bằng chứng mới nhất",
}
SHELL_CHAIN = re.compile(r"[;|&`]|\$\(")
SHELL_NAMES = ("sh", "bash", "dash", "zsh")
PATH = re.compile(r"(?<![\w/])(/(?:tmp|var/tmp|dev/shm|home|var/www|srv|opt)/[^\s;|&`'\"]+)")
TZ = timezone(timedelta(hours=7))


def _vn_time(value) -> str:
    if value in (None, "N/A"):
        return "N/A"
    try:
        if isinstance(value, (int, float)):
            stamp = datetime.fromtimestamp(float(value), timezone.utc)
        else:
            stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return stamp.astimezone(TZ).strftime("%H:%M:%S %d/%m/%Y (GMT+7)")
    except (ValueError, OSError, OverflowError):
        return str(value)


def _user(proc) -> str:
    euid = proc.get("euid")
    if euid == 0:
        return "root (euid 0)"
    return f"euid {euid}" if isinstance(euid, int) else "chưa có UID trong telemetry"


def suspicious_files(chain: dict) -> list[dict]:
    """Files the evidence ties to execution: uploads recorded by the app and scripts in temp/upload dirs."""
    files: dict[str, dict] = {}
    for cond in chain.get("conditions") or []:
        if cond.get("id") == "suspicious_upload" and cond.get("upload_path"):
            files[cond["upload_path"]] = {"path": cond["upload_path"], "sha256": cond.get("upload_sha256"),
                                          "uploaded": True, "executed_by": []}
    anchor = (chain.get("anchor") or {}).get("id")
    for proc in chain.get("process_tree") or []:
        if anchor and proc.get("id") == anchor:
            continue  # the web service itself is the victim, not a suspicious file
        for path in PATH.findall(str(proc.get("cmdline") or "")):
            entry = files.setdefault(path, {"path": path, "sha256": None, "uploaded": False, "executed_by": []})
            if proc.get("pid") not in entry["executed_by"]:
                entry["executed_by"].append(proc.get("pid"))
    return list(files.values())


def render(context, verdict, status: str, *, labels: dict) -> str:
    chain = context.chain
    stages = {c.get("id"): c for c in chain.get("conditions") or []}
    seen = {k for k, c in stages.items() if c.get("status") in ("OBSERVED", "CORRELATED")}
    procs = context.processes
    pid_ref = {p["pid"]: p["id"] for p in procs}
    flows = context.flows
    executed = bool({"web_spawned_shell", "uploaded_file_execution"} & seen)
    root = any(p.get("euid") == 0 and p.get("parent") != "N/A" for p in procs)
    reverse = bool(context.verified_shell)
    cls = verdict.classification
    conf = int(round(verdict.confidence * 100))

    head = SOURCE_LABEL.get(status, f"Trạng thái phân tích: {status}")
    summary = []
    if executed:
        summary.append("Web application trên Agent đã sinh tiến trình shell/interpreter và chạy lệnh ngoài luồng xử lý thông thường"
                       + (" — có bằng chứng thực thi mã từ xa (RCE)." if "web_spawned_shell" in seen else "."))
    if reverse:
        flow = next(f for f in flows if f["id"] == context.verified_shell)
        summary.append(f"Tiến trình {flow['holders'][0]['process']} giữ kết nối tới {flow['tuple']['dst_ip']}:{flow['tuple']['dst_port']} "
                       f"với stdin/stdout gắn vào socket — dấu hiệu shell điều khiển ngược [{flow['id']}].")
    if root:
        summary.append("Các tiến trình trong chuỗi chạy với euid 0: kẻ tấn công có quyền root trên máy.")
    elif executed:
        summary.append("Chưa có bằng chứng UID của tiến trình trong chuỗi; chưa kết luận được quyền root.")
    if not summary:
        summary.append("Chưa có bằng chứng thực thi mã trên máy; chỉ ghi nhận các dấu hiệu ở tầng ứng dụng web.")

    # The command_injection stage needs a request with injection indicators. Without one, a chained shell
    # command spawned by the web process is still evidence of injection; say so instead of "not observed".
    chained = None
    if "command_injection" not in seen and "web_spawned_shell" in seen:
        anchor_pid = (chain.get("anchor") or {}).get("pid")
        chained = next((p for p in procs if str(p.get("name")) in SHELL_NAMES and p.get("ppid") == anchor_pid
                        and SHELL_CHAIN.search(str(p.get("cmdline") or "").split(" -c ", 1)[-1])), None)
    injection_note = (f"chưa có request HTTP mang chỉ báo injection; dòng lệnh shell [{chained['id']}] do web process sinh ra "
                      "chứa ký tự nối lệnh, phù hợp command injection nhưng chưa liên kết được với request cụ thể"
                      if chained else None)

    timeline = []
    for key in STAGE_ORDER:
        cond = stages.get(key) or {}
        state = cond.get("status", "NOT_OBSERVED")
        if key == "command_injection" and injection_note:
            timeline.append(f"- **{STAGE_LABEL[key]}** — {injection_note}")
            continue
        refs = ", ".join((cond.get("evidence_ids") or [])[:3])
        when = f" lúc {_vn_time(cond.get('observed_at'))}" if cond.get("observed_at") else ""
        timeline.append(f"- **{STAGE_LABEL[key]}** — {STATUS.get(state, state)}{when}"
                        + (f" (bằng chứng: `{refs}`)" if refs and state != "NOT_OBSERVED" else ""))
    for req in chain.get("inferred_requests") or []:
        timeline.append(f"- *Suy luận*: request `{req.get('method')} {req.get('path')}` (HTTP {req.get('status')}) có thể đã khởi chạy "
                        f"shell PID {req.get('shell_pid')} — {req.get('basis')}")

    process_rows = []
    for p in procs:
        state = f"đã thoát lúc {_vn_time(p['exited_at'])}" if p.get("exited_at") else "chưa thấy thoát"
        process_rows.append(f"- **[{p['id']}]** PID `{p['pid']}` (cha: `{p.get('ppid')}`), `{p.get('path')}` — lệnh `{p.get('cmdline')}`; "
                            f"người dùng: {_user(p)}; khởi chạy {_vn_time(p.get('process_start_time'))}; {state}.")

    file_rows = []
    for f in suspicious_files(chain):
        runs = ", ".join(f"PID {pid} [{pid_ref.get(pid, '?')}]" for pid in f["executed_by"])
        status_text = ("đã quan sát tiến trình chạy file (" + runs + ")") if runs else (
            "đã upload, chưa quan sát thực thi" if f["uploaded"] else "chưa quan sát thực thi")
        file_rows.append(f"- `{f['path']}` — SHA-256: {('`' + f['sha256'] + '`') if f['sha256'] else 'chưa thu thập (dùng “Thu thập bằng chứng”)'}; "
                         f"{status_text}. Tên file không phải căn cứ kết luận độc hại.")

    net_rows = []
    for flow in flows:
        holder = flow["holders"][0] if flow["holders"] else {}
        net_rows.append(f"- **[{flow['id']}]** {flow['tuple']['src_ip']}:{flow['tuple']['src_port']} → "
                        f"**{flow['tuple']['dst_ip']}:{flow['tuple']['dst_port']}** ({flow.get('direction')}), tiến trình "
                        f"{holder.get('process', 'chưa xác định')} PID {holder.get('pid', 'N/A')}, chủ sở hữu socket xác minh qua inode"
                        + ("; stdin/stdout gắn vào socket" if holder.get("stdio_fds") else "")
                        + f"; quan sát đầu tiên {_vn_time(flow.get('observed_at'))}.")

    impact = []
    impact.append("- RCE: " + ("**có bằng chứng** (web process sinh shell chạy lệnh)." if "web_spawned_shell" in seen
                               else "chưa chứng minh."))
    impact.append("- Quyền root: " + ("**có bằng chứng** (euid 0)." if root else "chưa chứng minh."))
    impact.append("- Kênh điều khiển từ xa: " + ("**có bằng chứng** (socket gắn stdio)." if reverse else "chưa chứng minh."))
    impact.append("- Lưu ý: cách ly file không ngắt shell đang chạy; tiến trình phải được dừng hoặc kết nối phải bị chặn riêng.")

    mitre = []
    if "web_spawned_shell" in seen:
        shell = next((p for p in procs if str(p.get("name")) in ("sh", "bash", "dash")), None)
        if shell:
            mitre.append(f"- **T1059.004 Unix Shell** — [{shell['id']}] shell do web process sinh ra.")
    py = next((p for p in procs if str(p.get("name", "")).startswith("python") and p.get("parent") != "N/A"), None)
    if py and "uploaded_file_execution" in seen:
        mitre.append(f"- **T1059.006 Python** — [{py['id']}] chạy script `{py.get('cmdline')}`.")
    if {"auth_bypass", "command_injection"} & seen:
        mitre.append("- **T1190 Exploit Public-Facing Application** — có bằng chứng khai thác ứng dụng web.")
    for tech in verdict.techniques:
        line = f"- **{tech['id']} {tech.get('name', '')}** — AI dẫn chứng: {tech.get('evidence')}."
        if not any(tech["id"] in m for m in mitre):
            mitre.append(line)
    if not mitre:
        mitre.append("- Chưa gán kỹ thuật: chưa đủ bằng chứng.")

    recs = ["1. **Thu thập và bảo toàn bằng chứng**: metadata, SHA-256 của file, cây tiến trình, socket (không cần phê duyệt, chỉ đọc)."]
    payload = next((p for p in procs if any(h.get("process") == p["id"] for f in flows for h in f["holders"])), None)
    if payload:
        recs.append(f"2. **Ngắt kênh điều khiển**: đề xuất dừng tiến trình PID `{payload['pid']}` [{payload['id']}] (xác minh PID + thời điểm khởi chạy)"
                    + (f" và/hoặc chặn IP `{flows[0]['tuple']['dst_ip']}`" if flows else "") + " — cần SOC Admin phê duyệt.")
    if suspicious_files(chain):
        recs.append("3. **Cách ly file đáng ngờ** sau khi thu thập SHA-256 — cần phê duyệt; file được giữ lại để điều tra, có thể khôi phục.")
    recs.append("4. **Xác minh**: tiến trình đã dừng, kết nối không còn, file không còn ở vị trí gốc, rule firewall tồn tại.")
    recs.append("5. **Khắc phục**: vá SQL injection/command injection, kiểm tra persistence (cron, systemd, SSH keys), đổi thông tin xác thực"
                + ("; máy đã bị chiếm quyền root nên cần tái tạo từ nguồn sạch." if root else "."))

    gaps = [f"- {STAGE_LABEL.get(m.split(':', 1)[1], m)}: "
            + (injection_note + "." if m == "chain_stage:command_injection" and injection_note else "chưa có bằng chứng.")
            for m in context.missing if m.startswith("chain_stage:")]
    if not any(f.get("sha256") for f in suspicious_files(chain)) and suspicious_files(chain):
        gaps.append("- SHA-256 và chủ sở hữu của file đáng ngờ: chưa thu thập.")
    if not any(isinstance(p.get("euid"), int) for p in procs):
        gaps.append("- UID của tiến trình: chưa có trong telemetry.")
    if not gaps:
        gaps.append("- Không có khoảng trống lớn trong chuỗi đã quan sát.")

    return (
        f"**Đánh giá sơ bộ:** `[{cls}]` — {labels.get(cls, cls)}\n"
        f"**Nguồn:** {head} | **Độ tin cậy:** {conf}% | **Risk Score (Detection Engine):** {context.metadata.get('risk_score')}/100\n\n"
        f"### Tóm tắt sự cố\n" + " ".join(summary) + "\n\n"
        f"### Dòng thời gian tấn công\n" + "\n".join(timeline) + "\n\n"
        f"### Bằng chứng thực thi\n" + ("\n".join(process_rows) or "Chưa có tiến trình liên quan.") + "\n\n"
        f"### File đáng ngờ\n" + ("\n".join(file_rows) or "Chưa xác định file liên quan.") + "\n\n"
        f"### Kết nối mạng\n" + ("\n".join(net_rows) or "Chưa có kết nối được xác minh.") + "\n\n"
        f"### Phân tích ảnh hưởng\n" + "\n".join(impact) + "\n\n"
        f"### MITRE ATT&CK\n" + "\n".join(mitre) + "\n\n"
        f"### Đề xuất ứng phó (theo policy, cần phê duyệt)\n" + "\n".join(recs) + "\n\n"
        f"### Bằng chứng còn thiếu\n" + "\n".join(gaps)
    )
