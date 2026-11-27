"""File investigation / quarantine / restore in an isolated temporary tree (no system paths touched)."""
import hashlib
import os
import stat
import subprocess
import sys
import uuid

import pytest

import file_containment as fc

BODY = b"#!/usr/bin/env python3\nprint('lab payload')\n"


@pytest.fixture
def lab(tmp_path, monkeypatch):
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    store = tmp_path / "store"
    monkeypatch.setenv("LARP_QUARANTINE_ALLOWED_ROOTS", str(uploads))
    monkeypatch.setenv("LARP_QUARANTINE_DIR", str(store))
    target = uploads / "backdoor.py"
    target.write_bytes(BODY)
    os.chmod(target, 0o755)
    return uploads, store, target, hashlib.sha256(BODY).hexdigest()


def qid():
    return uuid.uuid4().hex


def test_inspect_reports_metadata_hash_and_processes_using_the_file(lab):
    uploads, _, target, sha = lab
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)", str(target)])
    try:
        info = fc.inspect(str(target))
    finally:
        proc.kill()
    assert info["exists"] and info["sha256"] == sha and info["size"] == len(BODY) and info["kind"] == "script"
    assert info["mode"] == "0o755" and info["executable_bits"] and info["owner"]["uid"] == os.getuid()
    assert any(p["pid"] == proc.pid and "command_line" in p["reasons"] for p in info["processes"])
    assert fc.inspect(str(uploads / "gone.py"))["exists"] is False


def test_quarantine_moves_exact_file_keeps_bytes_and_blocks_execution_bits(lab):
    _, store, target, sha = lab
    quarantine_id = qid()
    receipt = fc.quarantine(str(target), sha, quarantine_id)
    assert receipt["status"] == "success" and receipt["outcome"] == "quarantined"
    assert receipt["original_absent"] and receipt["stored_hash_verified"] and receipt["stored_mode"] == "0o400"
    assert not target.exists()
    stored = store / quarantine_id / "payload.quarantined"
    assert stored.read_bytes() == BODY  # forensic copy preserved, nothing deleted
    assert stat.S_IMODE(os.stat(stored.parent).st_mode) == 0o700
    again = fc.quarantine(str(target), sha, quarantine_id)  # replayed command
    assert again["outcome"] == "already_quarantined" and again["status"] == "success"


def test_quarantine_refuses_a_changed_file(lab):
    _, _, target, _ = lab
    with pytest.raises(fc.FileContainmentError) as error:
        fc.quarantine(str(target), "0" * 64, qid())
    assert error.value.code == "HASH_MISMATCH" and target.exists()


@pytest.mark.parametrize("make,code", [
    (lambda up, t: (os.symlink(t, up / "link.py"), str(up / "link.py"))[1], "SYMLINK"),
    (lambda up, t: str(up / ".." / "uploads" / "backdoor.py"), "PATH_TRAVERSAL"),
    (lambda up, t: "/etc/passwd", "OUTSIDE_ALLOWED_ROOTS"),
    (lambda up, t: "relative/backdoor.py", "INVALID_PATH"),
])
def test_unsafe_paths_are_refused(lab, make, code):
    uploads, _, target, sha = lab
    with pytest.raises(fc.FileContainmentError) as error:
        fc.quarantine(make(uploads, target), sha, qid())
    assert error.value.code == code and target.exists()


def test_symlinked_parent_directory_is_refused(lab, tmp_path):
    uploads, _, target, sha = lab
    os.symlink(uploads, uploads / "alias")
    with pytest.raises(fc.FileContainmentError) as error:
        fc.quarantine(str(uploads / "alias" / "backdoor.py"), sha, qid())
    assert error.value.code == "SYMLINK"


def test_protected_paths_win_over_broad_allowed_roots(monkeypatch):
    monkeypatch.setenv("LARP_QUARANTINE_ALLOWED_ROOTS", "/")
    with pytest.raises(fc.FileContainmentError) as error:
        fc.check_path("/usr/bin/python3")
    assert error.value.code == "PROTECTED_PATH"


def test_hard_linked_file_is_refused(lab):
    uploads, _, target, sha = lab
    os.link(target, uploads / "second-name.py")
    with pytest.raises(fc.FileContainmentError) as error:
        fc.quarantine(str(target), sha, qid())
    assert error.value.code == "HARD_LINKED"


def test_restore_puts_the_file_back_and_keeps_the_audit_record(lab):
    _, store, target, sha = lab
    quarantine_id = qid()
    fc.quarantine(str(target), sha, quarantine_id)
    restored = fc.restore(quarantine_id, sha)
    assert restored["status"] == "success" and restored["restored_hash_verified"] and restored["restored_mode"] == "0o755"
    assert target.read_bytes() == BODY and (store / quarantine_id / "metadata.json").exists()
    assert fc.restore(quarantine_id, sha)["outcome"] == "already_restored"


def test_restore_never_overwrites_a_new_file(lab):
    _, _, target, sha = lab
    quarantine_id = qid()
    fc.quarantine(str(target), sha, quarantine_id)
    target.write_bytes(b"new legitimate content")
    with pytest.raises(fc.FileContainmentError) as error:
        fc.restore(quarantine_id, sha)
    assert error.value.code == "RESTORE_CONFLICT" and target.read_bytes() == b"new legitimate content"
