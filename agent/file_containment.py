"""Suspicious file investigation and quarantine owned by LARP.

inspect   read-only metadata, SHA-256 and the processes currently referencing the file.
quarantine move the exact file (same inode and SHA-256 the SOC approved) into a root-only LARP store,
           mode 0400 in a 0700 directory, with a metadata record. The bytes are kept (forensic copy);
           nothing is deleted. Running processes are NOT stopped by this — reported separately.
restore   put the quarantined bytes back at the original path with the original mode/owner, only if
           that path is free, and verify the hash there.

Safety: absolute normalised paths only; every component is checked with lstat (no symlink anywhere);
the file is opened with O_NOFOLLOW and its inode compared before and after hashing; only regular files
under the allowed roots and outside protected system/agent paths are eligible.
"""
from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

QUARANTINE_ID = re.compile(r"[0-9a-f]{32}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_BYTES = 64 * 1024 * 1024
DEFAULT_ALLOWED = "/tmp,/var/tmp,/dev/shm,/home,/var/www,/srv,/opt/larp-agent/vulnerable_web"
PROTECTED = ("/bin", "/sbin", "/usr", "/lib", "/lib32", "/lib64", "/etc", "/boot", "/proc", "/sys", "/dev",
             "/run", "/var/lib", "/var/log", "/root", "/opt/larp-agent", "/snap")


class FileContainmentError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _roots(env: str, default: str) -> List[str]:
    return [os.path.normpath(p) for p in os.getenv(env, default).split(",") if p.strip().startswith("/")]


def store_root() -> Path:
    return Path(os.getenv("LARP_QUARANTINE_DIR", "/var/lib/larp-agent/quarantine"))


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def check_path(path: Any) -> str:
    """Validated absolute path of an existing-or-absent regular file location (no symlinks, no traversal)."""
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path or len(path) > 4096:
        raise FileContainmentError("INVALID_PATH", "Đường dẫn phải là đường dẫn tuyệt đối hợp lệ")
    if os.path.normpath(path) != path or "/../" in f"{path}/" or "/./" in f"{path}/":
        raise FileContainmentError("PATH_TRAVERSAL", "Đường dẫn không được chứa '..', '.' hoặc dấu '/' thừa")
    allowed = _roots("LARP_QUARANTINE_ALLOWED_ROOTS", DEFAULT_ALLOWED)
    allowed_root = max((r for r in allowed if _under(path, r)), key=len, default=None)
    if allowed_root is None:
        raise FileContainmentError("OUTSIDE_ALLOWED_ROOTS", "Đường dẫn nằm ngoài các thư mục được phép cách ly")
    store = os.path.normpath(str(store_root()))
    for protected in (*PROTECTED, store):
        if _under(path, protected) and len(protected) >= len(allowed_root):
            raise FileContainmentError("PROTECTED_PATH", f"Không thao tác trên đường dẫn được bảo vệ ({protected})")
    current = "/"
    for part in path.strip("/").split("/")[:-1]:
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            raise FileContainmentError("NOT_FOUND", "Thư mục chứa file không tồn tại") from None
        if stat.S_ISLNK(info.st_mode):
            raise FileContainmentError("SYMLINK", f"Thành phần đường dẫn là symlink: {current}")
    return path


def _sha256_fd(fd: int) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1 << 20):
        size += len(chunk)
        if size > MAX_BYTES:
            raise FileContainmentError("TOO_LARGE", "File vượt giới hạn 64 MiB")
        digest.update(chunk)
    return digest.hexdigest(), size


def _open_regular(path: str) -> tuple[int, os.stat_result]:
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        raise FileContainmentError("NOT_FOUND", "File không còn tồn tại") from None
    if stat.S_ISLNK(before.st_mode):
        raise FileContainmentError("SYMLINK", "File là symlink; không thao tác qua liên kết")
    if not stat.S_ISREG(before.st_mode):
        raise FileContainmentError("NOT_REGULAR", "Chỉ thao tác trên file thường")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
        os.close(fd)
        raise FileContainmentError("CHANGED", "File bị thay đổi trong lúc mở")
    return fd, info


def _owner(uid: int, gid: int) -> Dict[str, Any]:
    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        user = None
    try:
        group = grp.getgrgid(gid).gr_name
    except KeyError:
        group = None
    return {"uid": uid, "gid": gid, "user": user, "group": group}


def _iso(stamp: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp))


def processes_using(path: str, inode: Optional[tuple] = None) -> List[Dict[str, Any]]:
    """Processes whose executable, command line or open descriptors reference the file."""
    out = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time", "uids", "ppid"]):
        info = proc.info
        reasons = []
        if info.get("exe") == path:
            reasons.append("executable")
        if any(arg == path for arg in (info.get("cmdline") or [])):
            reasons.append("command_line")
        try:
            if any(f.path == path for f in proc.open_files()):
                reasons.append("open_file")
        except (psutil.Error, OSError):
            pass
        if reasons:
            out.append({"pid": info["pid"], "ppid": info.get("ppid"), "name": info.get("name"),
                        "process_start_time": info.get("create_time"),
                        "cmdline": " ".join(info.get("cmdline") or [])[:512],
                        "euid": info["uids"].effective if info.get("uids") else None, "reasons": reasons})
    return out[:20]


def inspect(path: str) -> Dict[str, Any]:
    path = check_path(path)
    observed = time.time()
    try:
        fd, info = _open_regular(path)
    except FileContainmentError as error:
        if error.code == "NOT_FOUND":
            return {"status": "success", "path": path, "exists": False, "observed_at": observed,
                    "processes": processes_using(path)}
        raise
    try:
        sha, size = _sha256_fd(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        head = os.read(fd, 4)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if (after.st_ino, after.st_size, after.st_mtime_ns) != (info.st_ino, info.st_size, info.st_mtime_ns):
        raise FileContainmentError("CHANGED", "File thay đổi trong lúc tính SHA-256")
    return {
        "status": "success", "path": path, "exists": True, "sha256": sha, "size": size,
        "mode": oct(stat.S_IMODE(info.st_mode)), "executable_bits": bool(info.st_mode & 0o111),
        "owner": _owner(info.st_uid, info.st_gid), "inode": info.st_ino, "device": info.st_dev, "links": info.st_nlink,
        "created_at": _iso(getattr(info, "st_birthtime", None)) if getattr(info, "st_birthtime", None) else None,
        "modified_at": _iso(info.st_mtime), "changed_at": _iso(info.st_ctime), "accessed_at": _iso(info.st_atime),
        "kind": "elf" if head.startswith(b"\x7fELF") else "script" if head.startswith(b"#!") else "data",
        "processes": processes_using(path), "observed_at": observed,
    }


def _record_path(quarantine_id: str) -> Path:
    return store_root() / quarantine_id / "metadata.json"


def quarantine(path: str, expected_sha256: str, quarantine_id: str) -> Dict[str, Any]:
    if not QUARANTINE_ID.fullmatch(str(quarantine_id)) or not SHA256.fullmatch(str(expected_sha256)):
        raise FileContainmentError("INVALID_REQUEST", "Thiếu mã cách ly hoặc SHA-256 hợp lệ")
    record = _record_path(quarantine_id)
    if record.exists():  # replayed command: report the existing state, act once
        meta = json.loads(record.read_text())
        return {**_verify_quarantined(meta), "outcome": "already_quarantined"}
    path = check_path(path)
    fd, info = _open_regular(path)
    try:
        sha, size = _sha256_fd(fd)
    finally:
        os.close(fd)
    if sha != expected_sha256:
        raise FileContainmentError("HASH_MISMATCH", "SHA-256 hiện tại khác giá trị đã được phê duyệt; không cách ly")
    if info.st_nlink != 1:
        raise FileContainmentError("HARD_LINKED", "File có nhiều hard link; cần xử lý thủ công")
    directory = store_root() / quarantine_id
    directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory.parent, 0o700)
    directory.mkdir(mode=0o700)
    payload = directory / "payload.quarantined"
    meta = {
        "quarantine_id": quarantine_id, "original_path": path, "sha256": sha, "size": size,
        "mode": stat.S_IMODE(info.st_mode), "owner": _owner(info.st_uid, info.st_gid), "inode": info.st_ino,
        "modified_at": _iso(info.st_mtime), "processes_at_quarantine": processes_using(path),
        "quarantined_at": time.time(), "restored_at": None, "store": str(payload),
    }
    current = os.lstat(path)
    if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
        raise FileContainmentError("CHANGED", "File bị thay thế trong lúc cách ly")
    if current.st_dev == os.stat(directory).st_dev:
        os.rename(path, payload)
    else:
        with open(payload, "xb") as out, open(path, "rb", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW)) as src:
            shutil.copyfileobj(src, out)
            out.flush()
            os.fsync(out.fileno())
        if _sha_of(payload) != sha:
            payload.unlink()
            raise FileContainmentError("COPY_FAILED", "Bản sao cách ly không khớp SHA-256")
        os.unlink(path)
    os.chmod(payload, 0o400)
    os.chown(payload, 0, 0) if os.geteuid() == 0 else None
    record.write_text(json.dumps(meta, ensure_ascii=False))
    os.chmod(record, 0o600)
    return {**_verify_quarantined(meta), "outcome": "quarantined"}


def _sha_of(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return _sha256_fd(fd)[0]
    finally:
        os.close(fd)


def _verify_quarantined(meta: Dict[str, Any]) -> Dict[str, Any]:
    payload = Path(meta["store"])
    try:
        original = os.lstat(meta["original_path"])
        original_gone = original.st_ino != meta["inode"]
    except FileNotFoundError:
        original_gone = True
    stored_ok = payload.exists() and _sha_of(payload) == meta["sha256"]
    stored_mode = oct(stat.S_IMODE(os.lstat(payload).st_mode)) if payload.exists() else None
    verified = original_gone and stored_ok and meta.get("restored_at") is None
    return {
        "status": "success" if verified else "failed", "quarantine_id": meta["quarantine_id"],
        "original_path": meta["original_path"], "sha256": meta["sha256"], "size": meta["size"],
        "original_absent": original_gone, "stored_hash_verified": stored_ok, "stored_mode": stored_mode,
        "processes_still_running": [p for p in processes_using(meta["original_path"]) if p.get("pid")],
        "processes_at_quarantine": meta.get("processes_at_quarantine", []), "observed_at": time.time(),
        **({} if verified else {"code": "NOT_VERIFIED", "message": "Không xác minh được trạng thái cách ly"}),
    }


def restore(quarantine_id: str, expected_sha256: str) -> Dict[str, Any]:
    if not QUARANTINE_ID.fullmatch(str(quarantine_id)) or not SHA256.fullmatch(str(expected_sha256)):
        raise FileContainmentError("INVALID_REQUEST", "Thiếu mã cách ly hoặc SHA-256 hợp lệ")
    record = _record_path(quarantine_id)
    if not record.exists():
        raise FileContainmentError("NOT_FOUND", "Không có bản ghi cách ly tương ứng")
    meta = json.loads(record.read_text())
    if meta["sha256"] != expected_sha256:
        raise FileContainmentError("HASH_MISMATCH", "SHA-256 không khớp bản ghi cách ly")
    path = check_path(meta["original_path"])
    if meta.get("restored_at"):
        return {**_verify_restored(meta), "outcome": "already_restored"}
    if os.path.lexists(path):
        raise FileContainmentError("RESTORE_CONFLICT", "Đã có file khác ở vị trí gốc; không ghi đè")
    payload = Path(meta["store"])
    if _sha_of(payload) != meta["sha256"]:
        raise FileContainmentError("HASH_MISMATCH", "Bản cách ly đã bị thay đổi; không khôi phục")
    if os.stat(payload).st_dev == os.stat(os.path.dirname(path)).st_dev:
        os.rename(payload, path)
    else:
        with open(path, "xb") as out, open(payload, "rb") as src:
            shutil.copyfileobj(src, out)
            out.flush()
            os.fsync(out.fileno())
        payload.unlink()
    os.chmod(path, meta["mode"])
    if os.geteuid() == 0:
        os.chown(path, meta["owner"]["uid"], meta["owner"]["gid"])
    meta["restored_at"] = time.time()
    record.write_text(json.dumps(meta, ensure_ascii=False))  # the audit record stays in the store
    return {**_verify_restored(meta), "outcome": "restored"}


def _verify_restored(meta: Dict[str, Any]) -> Dict[str, Any]:
    path = meta["original_path"]
    try:
        info = os.lstat(path)
        present = stat.S_ISREG(info.st_mode) and _sha_of(Path(path)) == meta["sha256"]
        mode = oct(stat.S_IMODE(info.st_mode))
    except FileNotFoundError:
        present, mode = False, None
    return {
        "status": "success" if present else "failed", "quarantine_id": meta["quarantine_id"], "original_path": path,
        "sha256": meta["sha256"], "restored_hash_verified": present, "restored_mode": mode, "observed_at": time.time(),
        **({} if present else {"code": "NOT_VERIFIED", "message": "File chưa có ở vị trí gốc sau khôi phục"}),
    }
