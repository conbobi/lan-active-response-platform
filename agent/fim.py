# agent/fim.py
import hashlib
import os
import glob
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any


class FileIntegrityMonitor:
    """
    File Integrity Monitoring (FIM) for detecting unauthorized changes to critical system files.
    Tracks SHA-256 hashes and generates state-transition alerts to prevent alert flooding.
    """

    DEFAULT_WATCHED_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
    ]
    DEFAULT_WATCHED_DIRS = [
        "/tmp/malware_sim",
    ]

    def __init__(self, agent_id: str = "agent", watched_files: Optional[List[str]] = None, watched_dirs: Optional[List[str]] = None):
        self.agent_id = agent_id
        self.watched_files = list(watched_files or self.DEFAULT_WATCHED_FILES)
        self.watched_dirs = list(watched_dirs or self.DEFAULT_WATCHED_DIRS)
        self.file_hashes: Dict[str, str] = {}
        self.initialized = False
        # Initialize baseline on startup
        self.initialize_baseline()

    @staticmethod
    def calculate_sha256(filepath: str) -> Optional[str]:
        """Calculates SHA-256 hash of a file. Returns None if unreadable or not found."""
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return None
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, OSError):
            return None

    def get_all_target_files(self) -> List[str]:
        """Resolves target files including directory contents."""
        targets = set(self.watched_files)
        for directory in self.watched_dirs:
            if os.path.exists(directory) and os.path.isdir(directory):
                try:
                    for root, _, files in os.walk(directory):
                        for f in files:
                            targets.add(os.path.join(root, f))
                except Exception:
                    pass
        return sorted(list(targets))

    def initialize_baseline(self) -> None:
        """Initializes the baseline hash cache without generating alerts."""
        targets = self.get_all_target_files()
        for filepath in targets:
            h = self.calculate_sha256(filepath)
            if h is not None:
                self.file_hashes[filepath] = h
        self.initialized = True

    def check_integrity(self) -> List[Dict[str, Any]]:
        """
        Scans monitored files and detects modifications, deletions, or additions.
        Updates internal hash cache to ensure each event only alerts once (State-Transition).
        """
        alerts = []
        now_iso = datetime.now(timezone.utc).isoformat()
        current_targets = set(self.get_all_target_files())

        # 1. Check existing cached files for modifications or deletions
        cached_paths = list(self.file_hashes.keys())
        for filepath in cached_paths:
            old_hash = self.file_hashes[filepath]
            if not os.path.exists(filepath):
                # File was deleted
                alerts.append({
                    "agent_id": self.agent_id,
                    "file_path": filepath,
                    "old_hash": old_hash,
                    "new_hash": "",
                    "action": "DELETED",
                    "timestamp": now_iso
                })
                del self.file_hashes[filepath]
            else:
                curr_hash = self.calculate_sha256(filepath)
                if curr_hash is not None and curr_hash != old_hash:
                    # File was modified
                    alerts.append({
                        "agent_id": self.agent_id,
                        "file_path": filepath,
                        "old_hash": old_hash,
                        "new_hash": curr_hash,
                        "action": "MODIFIED",
                        "timestamp": now_iso
                    })
                    # Update cache to suppress repeated alerts for the same change
                    self.file_hashes[filepath] = curr_hash

        # 2. Check for newly appeared files in watched targets
        for filepath in current_targets:
            if filepath not in self.file_hashes and os.path.exists(filepath):
                new_hash = self.calculate_sha256(filepath)
                if new_hash is not None:
                    # If already initialized, new file in watched directory is an alert
                    if self.initialized:
                        alerts.append({
                            "agent_id": self.agent_id,
                            "file_path": filepath,
                            "old_hash": "",
                            "new_hash": new_hash,
                            "action": "CREATED",
                            "timestamp": now_iso
                        })
                    self.file_hashes[filepath] = new_hash

        return alerts
