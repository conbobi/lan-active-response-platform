"""Rule Assistant: natural language → clarifying questions → deterministic rule.

The model never writes Sigma. It only fills a small detection intent from what the analyst typed.
Every extracted value must be grounded in the analyst's own words; anything the model guessed is
dropped and turned into a question instead. Answers to questions are merged without the model.
A fixed compiler turns the complete intent into the Sigma subset the Detection Engine executes, so
the stored rule is always runnable and always says exactly what the analyst confirmed.
"""
from __future__ import annotations

import posixpath
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import yaml
from sqlalchemy import select

from app.models.process_info import ProcessInfo
from app.services.ai.ai_client import DEFAULT_MODEL, OLLAMA_URL
from app.services.ai.ollama_json import GenerationError, generate_json
from app.services.detection import sigma_runtime

SEVERITIES = ("low", "medium", "high", "critical")
NARRATIVE = re.compile(r"\b(adversar(?:y|ies)|attackers?|exploit\w*|malicious|suspicious|threat actors?|hackers?)\b", re.I)
SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish", "busybox"}
INTERPRETERS = {"python", "python2", "python3", "node", "nodejs", "java", "php", "ruby", "perl", "pwsh"}
WINDOWS_BROAD = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "rundll32.exe"}
GENERIC_SHELL = {"shell", "shells", "unix shell", "command shell", "interactive shell", "terminal"}
DEFAULT_SHELLS = {"linux": ["sh", "bash", "dash", "zsh"], "windows": ["cmd.exe", "powershell.exe", "pwsh.exe"]}
WEB_SERVERS = ("nginx", "apache2", "httpd", "gunicorn", "uwsgi", "php-fpm", "lighttpd", "caddy", "node", "java")
CHAINING_REGEX = r"[;|&`]|\$\("
CHAINING_WORDS = re.compile(r"inject|chain|metachar|nối lệnh|chèn lệnh|tiêm lệnh|ghép lệnh|;|&&|\|\||`|\$\(", re.I)
WINDOWS_HINT = re.compile(r"\bwindows\b|\.exe\b|powershell|cmd\.exe|registry|lsass", re.I)
LINUX_HINT = re.compile(r"\blinux\b|\bubuntu\b|\bdebian\b|\bcentos\b|/bin/|/usr/|\bbash\b|\bsystemd\b", re.I)

EMPTY_INTENT: Dict[str, Any] = {
    "platform": None, "parent": [], "parent_hint": None, "child": [], "command": [], "chaining": False,
    "severity": "medium", "mitre": [], "title": None,
}

INTENT_SCHEMA = {
    "type": "object",
    "properties": {
        "platform": {"enum": ["linux", "windows", "unknown"]},
        "parent": {"type": "array", "items": {"type": "string"}, "maxItems": 6},
        "parent_hint": {"type": "string"},
        "child": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
        "command": {"type": "array", "items": {"type": "string"}, "maxItems": 10},
        "chaining": {"type": "boolean"},
        "severity": {"enum": list(SEVERITIES)},
        "mitre": {"type": "array", "items": {"type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"}, "maxItems": 3},
        "title": {"type": "string"},
    },
    "required": ["platform", "parent", "parent_hint", "child", "command", "chaining", "severity", "mitre", "title"],
    "additionalProperties": False,
}

SYSTEM = (
    "You turn a SOC analyst's detection request into a JSON detection intent for process creation events. "
    "The analyst may write in Vietnamese or English. No Markdown, no prose.\n"
    "parent: the parent process that starts the suspicious process, exactly as the analyst named it "
    "(executable, service or script name such as nginx or app.py). Empty when not named.\n"
    "parent_hint: a short English description of the parent when the analyst describes it without naming it "
    "(for example 'web server' or 'database'); empty string otherwise.\n"
    "child: names of the processes to detect (for example bash, sh, powershell.exe). "
    "command: literal command words or arguments the analyst wants to see in the command line (for example whoami, curl). "
    "chaining: true only when the analyst mentions command injection, chaining or shell metacharacters.\n"
    "Copy values from the request; never invent process names. Never use words such as attacker, exploit or malicious as values.\n"
    "platform: linux, windows, or unknown when not stated or implied. "
    "mitre: ATT&CK technique ids that fit (for example T1059.004). title: a short English rule title."
)


def blank_intent() -> Dict[str, Any]:
    return {k: (list(v) if isinstance(v, list) else v) for k, v in EMPTY_INTENT.items()}


def _strings(values: Any, limit: int = 10, size: int = 200) -> List[str]:
    if isinstance(values, str):
        values = [v for v in re.split(r"[,\n]", values)]
    out: List[str] = []
    for value in values or []:
        text = str(value).strip().strip("'\"").strip()
        if text and len(text) <= size and text.lower() not in (o.lower() for o in out):
            out.append(text)
    return out[:limit]


def _base(value: str) -> str:
    return posixpath.basename(value.replace("\\", "/")).lower()


def sanitize(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Normalise an intent (from the model, the analyst's form or an answer)."""
    intent, notices = blank_intent(), []
    platform = str(raw.get("platform") or "").lower()
    intent["platform"] = platform if platform in ("linux", "windows") else None
    for key in ("parent", "child", "command"):
        kept = []
        for value in _strings(raw.get(key)):
            if NARRATIVE.search(value):
                notices.append(f"Bỏ '{value}': từ mô tả, không phải dấu hiệu quan sát được.")
            else:
                kept.append(value)
        intent[key] = kept
    # Bare metacharacters (";", "&&") are the chaining signal, not command words.
    symbols = [v for v in intent["command"] if not re.search(r"[0-9A-Za-z]", v)]
    if symbols:
        intent["command"] = [v for v in intent["command"] if v not in symbols]
        raw = {**raw, "chaining": True}
    hint = str(raw.get("parent_hint") or "").strip()
    intent["parent_hint"] = hint[:80] or None
    intent["chaining"] = bool(raw.get("chaining"))
    severity = str(raw.get("severity") or "medium").lower()
    intent["severity"] = severity if severity in SEVERITIES else "medium"
    intent["mitre"] = [m.upper() for m in _strings(raw.get("mitre"), 3, 12)
                       if re.fullmatch(r"T\d{4}(\.\d{3})?", m.upper())]
    title = str(raw.get("title") or "").strip()
    intent["title"] = title[:120] or None
    return intent, notices


def ground(intent: Dict[str, Any], text: str) -> List[str]:
    """Drop values the analyst never wrote (model guesses); returns notices. Mutates ``intent``."""
    notices: List[str] = []
    lowered = text.lower()

    def written(needle: str) -> bool:
        return bool(needle) and re.search(rf"(?<![0-9a-z]){re.escape(needle)}(?![0-9a-z])", lowered) is not None

    for key, label in (("parent", "tiến trình cha"), ("child", "tiến trình"), ("command", "từ khóa lệnh")):
        kept = []
        for value in intent[key]:
            needle = value.lower()
            if written(needle) or written(_base(needle)) or written(needle.removesuffix(".exe")):
                kept.append(value)
            else:
                notices.append(f"AI đoán {label} '{value}' nhưng bạn chưa nêu; cần bạn xác nhận.")
                if key == "parent" and not intent.get("parent_hint"):
                    intent["parent_hint"] = "process you described"
        intent[key] = kept
    if intent["chaining"] and not CHAINING_WORDS.search(text):
        intent["chaining"] = False
    if not intent["child"] and re.search(r"\bshells?\b", lowered):
        intent["child"] = ["shell"]  # a generic "shell" is expanded to the platform's shells at compile time
    if not (WINDOWS_HINT.search(text) or LINUX_HINT.search(text)):
        intent["platform"] = None
    if intent["platform"] is None:
        if WINDOWS_HINT.search(text) and not LINUX_HINT.search(text):
            intent["platform"] = "windows"
        elif LINUX_HINT.search(text) and not WINDOWS_HINT.search(text):
            intent["platform"] = "linux"
    elif intent["platform"] == "linux" and WINDOWS_HINT.search(text) and not LINUX_HINT.search(text):
        intent["platform"] = None
    elif intent["platform"] == "windows" and LINUX_HINT.search(text) and not WINDOWS_HINT.search(text):
        intent["platform"] = None
    return notices


def merge(base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in update.items():
        if key in ("parent", "child", "command", "mitre"):
            merged[key] = _strings(list(base.get(key) or []) + list(value or []), 10)
        elif value not in (None, "", False) or key == "chaining":
            merged[key] = value if key != "chaining" else bool(base.get("chaining") or value)
    return merged


def _children(intent: Dict[str, Any]) -> List[str]:
    """Child names with a generic 'shell' expanded to the platform's real shells."""
    out: List[str] = []
    for child in intent["child"]:
        if child.lower() in GENERIC_SHELL:
            out += DEFAULT_SHELLS.get(intent["platform"] or "linux", [])
        else:
            out.append(child)
    return list(dict.fromkeys(out))


def _broad_child(intent: Dict[str, Any]) -> bool:
    names = {_base(c) for c in _children(intent)}
    return bool(names) and names <= (SHELLS | INTERPRETERS | WINDOWS_BROAD | {n.removesuffix(".exe") for n in WINDOWS_BROAD})


def _runtime_ignored(intent: Dict[str, Any]) -> bool:
    """The runtime safe-process policy drops these children unless the rule pins the parent, so a rule
    without a parent would be stored, validated and never fire."""
    if intent["parent"] or not intent["child"]:
        return False
    safe = {p.lower() for p in sigma_runtime.SAFE_PROCESSES}
    return any(_base(c) in safe or (_base(c) == "dash" and "sh" in safe) for c in _children(intent))


def _bare_parent(intent: Dict[str, Any]) -> List[str]:
    return [p for p in intent["parent"] if _base(p) in INTERPRETERS or _base(p) in SHELLS]


def _foreign_children(intent: Dict[str, Any]) -> List[str]:
    """Process names that cannot occur on the chosen platform (a /bin/sh rule with product: windows)."""
    if intent["platform"] == "windows":
        return [c for c in intent["child"] if c.startswith("/") or _base(c) in SHELLS]
    if intent["platform"] == "linux":
        return [c for c in intent["child"] if "\\" in c or _base(c).endswith(".exe")]
    return []


def questions(intent: Dict[str, Any], observed: Dict[str, List[str]] | None = None) -> List[Dict[str, Any]]:
    """What is still missing or too broad to build a precise rule. Empty list = ready."""
    observed = observed or {}
    asks: List[Dict[str, Any]] = []
    if intent["platform"] is None:
        seen = observed.get("platforms") or []
        text = "Rule áp dụng cho máy Linux hay Windows?"
        if len(seen) == 1:
            text += (f" Telemetry tiến trình 24 giờ qua chỉ có máy {seen[0].capitalize()}; "
                     "đây là gợi ý, cần bạn xác nhận.")
        asks.append({"slot": "platform", "text": text,
                     "options": seen + [p for p in ("linux", "windows") if p not in seen], "allow_text": False})
    foreign = _foreign_children(intent)
    if foreign:
        asks.append({"slot": "child", "replace": foreign,
                     "text": f"'{', '.join(foreign)}' không phải tiến trình của {intent['platform'].capitalize()}. "
                             "Chọn tiến trình đúng nền tảng hoặc đổi nền tảng.",
                     "options": DEFAULT_SHELLS[intent["platform"]], "allow_text": True})
        other = "linux" if intent["platform"] == "windows" else "windows"
        asks.append({"slot": "platform", "text": f"Hoặc đổi nền tảng của rule sang {other.capitalize()}?",
                     "options": [other, intent["platform"]], "allow_text": False})
    bare = _bare_parent(intent)
    if bare:
        asks.append({"slot": "parent", "replace": bare,
                     "text": f"'{', '.join(bare)}' quá chung (mọi script đều chạy bằng nó). Ứng dụng/script cụ thể là gì?",
                     "options": observed.get("scripts", []), "allow_text": True})
    elif not intent["parent"] and intent.get("parent_hint"):
        asks.append({"slot": "parent",
                     "text": f"Tiến trình cha ({intent['parent_hint']}) cụ thể là gì? Chọn tiến trình Agent đang thấy hoặc gõ tên.",
                     "options": observed.get("parents", []), "allow_text": True})
    if not intent["child"] and not intent["command"] and not intent["chaining"]:
        asks.append({"slot": "child", "text": "Cần phát hiện tiến trình nào được chạy (ví dụ bash, sh, powershell.exe)?",
                     "options": [], "allow_text": True})
    elif _runtime_ignored(intent) and not any(a["slot"] == "parent" for a in asks):
        asks.append({"slot": "parent",
                     "text": f"Detection Engine bỏ qua '{', '.join(intent['child'])}' nếu rule không nêu tiến trình cha "
                             "(chính sách safe-process: shell và interpreter chạy liên tục trên máy). "
                             "Tiến trình cha nào sinh ra nó? Chọn tiến trình Agent đang thấy hoặc gõ tên.",
                     "options": observed.get("parents", []), "allow_text": True})
    elif _broad_child(intent) and not intent["command"] and not intent["chaining"] and not intent["parent"] \
            and not any(a["slot"] == "parent" for a in asks):
        asks.append({"slot": "command",
                     "text": f"'{', '.join(intent['child'])}' chạy rất thường xuyên. Cần thêm tiến trình cha hoặc dấu hiệu lệnh. "
                             "Lệnh nào là đáng ngờ (ví dụ whoami, id, curl)? Hoặc chọn 'nối lệnh' để bắt ; | && $().",
                     "options": ["whoami", "id", "curl", "wget", "nối lệnh (; | && $())"], "allow_text": True,
                     "multi": True})
    return asks


def apply_answer(intent: Dict[str, Any], slot: str, value: Any, replace: Optional[List[str]] = None) -> Dict[str, Any]:
    updated = dict(intent)
    if slot == "platform":
        updated["platform"] = str(value).lower() if str(value).lower() in ("linux", "windows") else None
        return updated
    if slot not in ("parent", "child", "command"):
        raise ValueError(f"Unknown slot {slot}")
    values = _strings(value)
    if slot == "command" and any("nối lệnh" in v.lower() or "chain" in v.lower() for v in values):
        updated["chaining"] = True
        values = [v for v in values if "nối lệnh" not in v.lower() and "chain" not in v.lower()]
    current = [v for v in updated[slot] if v not in (replace or [])]
    updated[slot] = _strings(current + values)
    if slot == "parent" and updated[slot]:
        updated["parent_hint"] = None
    cleaned, _ = sanitize(updated)
    return cleaned


def _parent_value(value: str) -> str:
    # Executable paths match the parent's command line by basename (nginx workers drop the path).
    if "/" in value and " " not in value and re.match(r"^/(usr/)?(s?bin|local/s?bin)/", value):
        return posixpath.basename(value)
    return value


def _child_values(intent: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for child in _children(intent):
        name = _base(child)
        if intent["platform"] == "windows":
            out.append("\\" + (name if name.endswith(".exe") else name + ".exe"))
        else:
            out.append("/" + name)
            if name == "sh":
                out.append("/dash")  # /bin/sh is dash on Debian/Ubuntu: exe /usr/bin/dash
    return list(dict.fromkeys(out))


def _command_regex(intent: Dict[str, Any]) -> Optional[str]:
    parts = [rf"(?<![\w-]){re.escape(c)}(?![\w-])" for c in intent["command"]]
    if intent["chaining"]:
        parts.insert(0, CHAINING_REGEX)
    return "|".join(parts) if parts else None


def compile_rule(intent: Dict[str, Any], description: str = "") -> Tuple[str, Dict[str, Any]]:
    """Intent → runnable Sigma (single selection). Raises ValueError when the intent is incomplete."""
    if questions(intent):
        raise ValueError("Intent is incomplete: answer the open questions first")
    selection: Dict[str, Any] = {}
    if intent["parent"]:
        selection["ParentCommandLine|contains"] = [_parent_value(p) for p in intent["parent"]]
    children = _child_values(intent)
    if children:
        selection["Image|endswith"] = children
    regex = _command_regex(intent)
    if regex:
        selection["CommandLine|re"] = regex
    if not selection:
        raise ValueError("Rule has no detection criteria")
    title = intent["title"] or _auto_title(intent)
    rule = {
        "title": title,
        "status": "experimental",
        "description": (description or title)[:500],
        "logsource": {"category": "process_creation", "product": intent["platform"]},
        "detection": {"selection": selection, "condition": "selection"},
        "level": intent["severity"],
        "tags": [f"attack.{m.lower()}" for m in (intent["mitre"] or _default_mitre(intent))],
    }
    if not rule["tags"]:
        del rule["tags"]
    supported, reason = sigma_runtime.check_support(rule)
    if not supported:
        raise ValueError(reason)
    for pattern in [regex] if regex else []:
        re.compile(pattern)
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True), rule


def _default_mitre(intent: Dict[str, Any]) -> List[str]:
    """Fixed technique mapping for the interpreter the rule detects (used only when none was given)."""
    names = {_base(c) for c in _children(intent)}
    if intent["platform"] == "linux" and names & SHELLS:
        return ["T1059.004"]
    if names & {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}:
        return ["T1059.001"]
    if names & {"cmd.exe", "cmd"}:
        return ["T1059.003"]
    return []


def _auto_title(intent: Dict[str, Any]) -> str:
    parts = []
    if intent["parent"]:
        parts.append(f"{', '.join(_base(p) for p in intent['parent'][:2])} spawning")
    if intent["child"]:
        parts.append(", ".join(_base(c) for c in _children(intent)[:3]))
    else:
        parts.append("process")
    if intent["command"] or intent["chaining"]:
        parts.append("with suspicious command line")
    return " ".join(parts).strip().capitalize()[:120]


async def extract(text: str, intent: Dict[str, Any], *, context: str = "", url: str = OLLAMA_URL,
                  model: str = DEFAULT_MODEL) -> Tuple[Dict[str, Any], List[str]]:
    """One model call: analyst message → grounded intent merged into the current one."""
    known = {k: v for k, v in intent.items() if v not in (None, [], False, "medium")}
    user = f"Request:\n{text.strip()[:2000]}"
    if known:
        user += f"\n\nAlready known (keep unless the request changes it): {known}"
    data = await generate_json(url, model, SYSTEM, user, INTENT_SCHEMA, num_predict=320,
                               timeout_env="ASSISTANT_TIMEOUT_SECONDS", default_timeout=120.0)
    fresh, notices = sanitize(data)
    notices += ground(fresh, f"{context}\n{text}")
    if fresh["platform"] is None and intent.get("platform"):
        fresh["platform"] = intent["platform"]
    merged = merge(intent, fresh)
    if intent.get("parent") and fresh["parent_hint"] and not fresh["parent"]:
        merged["parent_hint"] = None
    return sanitize(merged)[0], notices


async def recent_process_rows(db, hours: int = 24, limit: int = 20000) -> List[ProcessInfo]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    stmt = (select(ProcessInfo).where(ProcessInfo.created_at >= since)
            .order_by(ProcessInfo.created_at.desc()).limit(limit))
    return list((await db.scalars(stmt)).all())


async def observed_options(db, hours: int = 24) -> Dict[str, List[str]]:
    """Real processes the Agents reported recently, offered as answers (never auto-selected)."""
    rows = await recent_process_rows(db, hours, 5000)
    scripts, parents, platforms = [], [], set()
    for row in rows:
        path = str(row.exe or row.exe_path or "")
        if path.startswith("/"):
            platforms.add("linux")
        elif re.match(r"^[A-Za-z]:\\", path):
            platforms.add("windows")
        name = _base(row.name or "")
        cmd = str(row.cmdline or "")
        if name.rstrip("0123456789.") in INTERPRETERS or name in INTERPRETERS:
            script = next((t for t in cmd.split()[1:] if re.search(r"\.(py|js|php|rb|pl|jar)$", t)), None)
            if script and script not in scripts:
                scripts.append(script)
                if script not in parents:
                    parents.append(script)
        elif any(name.startswith(w) for w in WEB_SERVERS) and name not in parents:
            parents.append(name)
    return {"scripts": scripts[:8], "parents": parents[:10], "platforms": sorted(platforms)}


async def preview_recent(rule: Dict[str, Any], db, hours: int = 24) -> Dict[str, Any]:
    """Dry-run the rule on recent real process snapshots (unlabelled): how often would it fire?"""
    rows = await recent_process_rows(db, hours)
    snapshots: Dict[Tuple[str, Any], List[dict]] = defaultdict(list)
    for row in rows:
        snapshots[(row.agent_id, row.created_at)].append({
            "pid": row.pid, "ppid": row.parent_pid, "name": row.name, "exe": row.exe or row.exe_path,
            "cmdline": row.cmdline, "process_start_time": row.process_start_time})
    title = str(rule.get("title") or "")
    mitre = [str(t).split(".", 1)[-1].upper() for t in rule.get("tags") or []]
    seen, samples = set(), []
    for (agent_id, _), procs in snapshots.items():
        events = sigma_runtime.candidates(rule, {"process_list": procs})
        for event in sigma_runtime.matching_events(rule, events, mitre=mitre, name=title):
            key = (agent_id, event.get("pid"), event.get("process_start_time"), event.get("cmdline"))
            if key in seen:
                continue
            seen.add(key)
            if len(samples) < 5:
                samples.append({"agent_id": agent_id, "pid": event.get("pid"), "name": event.get("name"),
                                "cmdline": str(event.get("cmdline") or "")[:300],
                                "parent_cmdline": str(event.get("parent_cmdline") or "")[:300]})
    return {"hours": hours, "snapshots": len(snapshots), "processes_scanned": len(rows),
            "matches": len(seen), "samples": samples, "labelled": False}


# Behaviours offered when the analyst names none. Only the first compiles to a process_creation Sigma rule;
# the others need file/flow events joined to a process, which the built-in Web Compromise Chain does.
SCENARIOS: Dict[str, Optional[Dict[str, Any]]] = {
    "Web process sinh shell": {"child": ["shell"], "parent_hint": "web server"},
    "Upload được thực thi": None,
    "Web process kết nối outbound": None,
}
CHAIN_ONLY = ("Sigma process_creation không ghép được sự kiện file hoặc kết nối mạng với tiến trình. "
              "Hành vi này do bộ phát hiện Web Compromise Chain (có sẵn) theo dõi; không tạo Sigma cho nó.")
SIGMA_PRIMER = ("Sigma là một quy tắc mô tả điều kiện trên sự kiện, ví dụ: tiến trình cha là web app và tiến trình con là shell. "
                "Agent LARP gửi tên tiến trình, tiến trình cha và dòng lệnh (process_creation). "
                "Shell do quản trị viên hoặc tác vụ hợp lệ của ứng dụng chạy có thể gây báo động nhầm.")
NO_GUARANTEE = ("Không bộ phát hiện nào bắt được 100% tấn công, và không có log thì không có gì để đánh giá. "
                "Hãy bật telemetry tiến trình, HTTP hoặc xác thực trên máy cần giám sát, rồi kiểm tra coverage "
                "bằng một sự kiện kiểm thử đã biết.")


def request_constraints(message: str) -> Tuple[Optional[str], List[str]]:
    """Classify what a request asks for before any model call. Returns (classification or None, notices)."""
    notices: List[str] = []
    if re.search(r"\bsigma\b", message, re.I) and re.search(r"không biết|là gì|what is|unfamiliar", message, re.I):
        notices.append(SIGMA_PRIMER)
    if re.search(r"(không (?:có |cần |thu thập )?(?:log|nhật ký|telemetry)|without (?:any )?(?:logs?|telemetry))",
                 message, re.I):
        return "INSUFFICIENT_TELEMETRY", notices + [NO_GUARANTEE]
    if WINDOWS_HINT.search(message) and LINUX_HINT.search(message):
        return "NEEDS_CLARIFICATION", notices + ["Yêu cầu nhắc cả Windows và Linux. Chọn một nền tảng trước khi tạo rule."]
    if re.search(r"\b(?:dns|registry|network_connection|file_creation)\b", message, re.I) and not re.search(
            r"process.creation|tiến trình|sinh shell|spawn", message, re.I):
        return "UNSUPPORTED_REQUIREMENT", notices + ["Bộ biên dịch chỉ hỗ trợ process_creation. Chọn hành vi tiến trình "
                                                     "hoặc dùng bộ phát hiện chuyên biệt."]
    return None, notices


def scenario_question(message: str, intent: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """A menu of supported behaviours when a server/web request names no process or command."""
    if intent["child"] or intent["command"] or intent["chaining"]:
        return None
    if not re.search(r"web|máy chủ|server|chiếm quyền|xâm nhập|hacker", message, re.I):
        return None
    return {"slot": "scenario", "text": "Bạn muốn phát hiện hành vi nào trên máy chủ?",
            "options": list(SCENARIOS), "allow_text": False}


def apply_scenario(intent: Dict[str, Any], value: str) -> Tuple[Dict[str, Any], Optional[str], List[str]]:
    if value not in SCENARIOS:
        raise ValueError("Chọn một hành vi trong danh sách.")
    fields = SCENARIOS[value]
    if fields is None:
        return intent, "UNSUPPORTED_REQUIREMENT", [CHAIN_ONLY]
    return {**intent, **fields}, None, []


__all__ = ["apply_scenario", "request_constraints", "scenario_question", "GenerationError", "apply_answer", "blank_intent", "compile_rule", "extract", "ground", "merge",
           "observed_options", "preview_recent", "questions", "sanitize"]
