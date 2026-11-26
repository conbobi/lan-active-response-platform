"""Narrow CTI context checks for the process rules supported by AI Harvest."""
import re

from app.services.detection import sigma_runtime


def web_shell_context(text):
    return bool(re.search(r"web\s*(?:server|shell)|nginx|apache|gunicorn|flask", text, re.I)
                and re.search(r"\bshells?\b|/bin/(?:ba)?sh|t1059\.004", text, re.I))


def expected_product(text):
    linux = re.search(r"\blinux\b|/bin/|t1059\.004|\bunix\b", text, re.I)
    windows = re.search(r"\bwindows\b|powershell|vssadmin|shadowcopy|mimikatz|lsass|\.exe\b", text, re.I)
    if linux and windows:
        raise ValueError("Mixed platform CTI: submit one platform per rule")
    if linux or windows:
        return "linux" if linux else "windows"
    # A web server alone supplies no OS evidence.
    return None


def process_context(text):
    if re.search(r"process[_ ]creation|spawn|execut(?:e|ion)|command line|/bin/|powershell|vssadmin|lsass", text, re.I):
        return
    if re.search(r"file[_ ](?:event|creation|change)|network[_ ]connection|dns quer|registry[_ ]event|file upload", text, re.I):
        raise ValueError("CTI describes an event category outside the supported process_creation pipeline")


def validate_selection(rule, text):
    process_context(text)
    product = rule["logsource"]["product"]
    expected = expected_product(text)
    if expected and product != expected:
        raise ValueError(f"Expected {expected} process_creation for this CTI")
    selection = rule["detection"]["selection"]
    criteria = {}
    for field, value in selection.items():
        key, *mods = [part.strip().lower() for part in field.split("|")]
        values = value if isinstance(value, list) else [value]
        if not values or any(not isinstance(v, str) or not v.strip() for v in values):
            raise ValueError(f"Empty or invalid observable in {field}")
        if any(re.search(r"\b(adversaries|adversary|exploit|attackers?|malicious|suspicious)\b", v, re.I) for v in values):
            raise ValueError(f"CTI narrative used as an observable in {field}")
        if key in ("image", "parentimage") and any(re.search(r"\s", v.strip()) for v in values):
            raise ValueError(f"{field} must hold executable paths without arguments; put command lines in "
                             f"{'ParentCommandLine' if key == 'parentimage' else 'CommandLine'}")
        if "re" in mods or "regex" in mods:
            for pattern in values:
                re.compile(pattern)
        criteria.setdefault(sigma_runtime.FIELD_ALIASES[key], []).append((field, values))

    techniques = {t.lower() for t in rule["tags"]}
    explicit = {f"attack.{t.lower()}" for t in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, re.I)}
    if explicit and techniques.isdisjoint(explicit):
        raise ValueError("Generated rule omits the CTI technique")
    if product != "linux" or not web_shell_context(text):
        return
    if "attack.t1059.004" not in techniques:
        raise ValueError("Expected attack.t1059.004 for Unix web shell execution")
    problems = web_shell_problems(criteria)
    if problems:
        raise ValueError("Web shell rule needs web parent, child shell and command evidence in one selection: "
                         + "; ".join(problems))


def web_shell_problems(criteria):
    """Why the selection does not establish parent web service + child shell + command evidence.

    Each OR alternative of a criterion is tested against representative values: it must match no
    benign sample (a bare interpreter is not a web service, "-c" is not command evidence) and, for the
    parent and the shell, a sample of the intended kind. Command evidence is open-ended: any value
    absent from benign shell invocations is accepted (CTI narrative words are rejected earlier).
    """
    def check(label, fields, positives, negatives):
        found = [(key, field, values) for key in fields for field, values in criteria.get(key, [])]
        if not found:
            return f"missing {label}"
        issues = []
        for key, field, values in found:
            bad = []
            for value in values:
                hit = next((n for n in negatives if sigma_runtime.match_field(field, value, {key: n})), None)
                if hit is not None:
                    bad.append(f"'{value}' also matches benign '{hit}'")
                elif positives and not any(sigma_runtime.match_field(field, value, {key: p}) for p in positives):
                    bad.append(f"'{value}' does not identify a {label}")
            if not bad:
                return None
            issues.append(f"{field}: {', '.join(bad)}")
        return "; ".join(issues)

    parents = ["nginx", "apache2", "httpd", "gunicorn", "uwsgi", "php-fpm", "lighttpd", "caddy", "cherokee",
               "tomcat", "php-cgi", "puma", "unicorn", "flask",
               "/usr/bin/python3 /srv/vulnerable_web/app.py", "python3 app.py", "node server.js"]
    parents += ["/usr/sbin/" + p for p in parents[:13]]
    shells = ["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish", "busybox"]
    results = [
        check("web service parent", ("parent_name", "parent_exe", "parent_cmdline"), parents,
              ["python3", "/usr/bin/python3", "/usr/bin/python3 backup.py", "systemd", "cron", "node", "/usr/bin/node"]),
        check("Unix child shell", ("name", "exe"), shells + [d + s for d in ("/bin/", "/usr/bin/") for s in shells],
              ["ssh", "/usr/bin/ssh", "crash", "/usr/bin/fishfood", "python3"]),
        check("suspicious command evidence", ("cmdline",), None,
              ["/bin/sh", "/bin/bash -c true", "/bin/sh -c ping localhost", "/bin/dash -c date",
               "/bin/sh -c ping -c 1 example.com", "sh -c ls /var/www", "/bin/bash /usr/local/bin/healthcheck.sh"]),
    ]
    return [r for r in results if r]
