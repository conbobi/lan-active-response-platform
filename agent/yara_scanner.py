import os
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_FALLBACK_RULES = """
rule Generic_Suspicious_Webshell {
    strings:
        $s1 = "eval($_POST[" nocase
        $s2 = "system($_REQUEST[" nocase
        $s3 = "passthru($_POST[" nocase
        $s4 = "shell_exec(" nocase
    condition:
        any of them
}

rule Generic_Ransomware_Note {
    strings:
        $r1 = "All your files have been encrypted" nocase
        $r2 = "ransomware_sim" nocase
        $r3 = "DECRYPT_NOTE.txt" nocase
    condition:
        any of them
}
"""


class YaraScanner:
    """
    In-memory YARA scanner module for Agent host.
    Compiles rules dynamically and scans target files or directories.
    """

    def __init__(self, rules_source: Optional[str] = None):
        self._compiled_rules = None
        self.load_rules(rules_source or DEFAULT_FALLBACK_RULES)

    def load_rules(self, rules_source: str):
        try:
            import yara
            self._compiled_rules = yara.compile(source=rules_source)
            logger.info("Compiled YARA rules successfully via yara-python.")
        except ImportError:
            logger.warning("yara-python not installed. Using simple keyword fallback engine.")
            self._compiled_rules = None
        except Exception as e:
            logger.error(f"Error compiling YARA rules: {e}")
            self._compiled_rules = None

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single file against loaded YARA rules."""
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return []

        # Skip scanning files > 10MB to conserve agent memory and CPU
        try:
            if os.path.getsize(file_path) > 10 * 1024 * 1024:
                return []
        except Exception:
            return []

        matches = []
        if self._compiled_rules is not None:
            try:
                results = self._compiled_rules.match(file_path, timeout=5)
                for r in results:
                    matches.append({
                        "rule": r.rule,
                        "tags": r.tags,
                        "meta": r.meta,
                        "strings": [str(s.identifier) for s in r.strings[:5]],
                        "file_path": file_path
                    })
            except Exception as e:
                logger.error(f"YARA scan error on '{file_path}': {e}")
        else:
            # Fallback simple string search if yara library is missing
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(100000)
                if "eval($_POST[" in content or "shell_exec(" in content:
                    matches.append({
                        "rule": "Generic_Suspicious_Webshell",
                        "tags": ["fallback", "webshell"],
                        "meta": {},
                        "strings": ["eval/shell_exec"],
                        "file_path": file_path
                    })
                if "ransomware_sim" in content or "All your files have been encrypted" in content:
                    matches.append({
                        "rule": "Generic_Ransomware_Note",
                        "tags": ["fallback", "ransomware"],
                        "meta": {},
                        "strings": ["ransomware_note"],
                        "file_path": file_path
                    })
            except Exception:
                pass

        return matches

    def scan_directory(self, dir_path: str, recursive: bool = True) -> List[Dict[str, Any]]:
        """Scan directory files recursively or flat."""
        all_matches = []
        if not os.path.exists(dir_path):
            return all_matches

        try:
            if recursive:
                for root, _, files in os.walk(dir_path):
                    for f in files:
                        fp = os.path.join(root, f)
                        res = self.scan_file(fp)
                        if res:
                            all_matches.extend(res)
            else:
                for f in os.listdir(dir_path):
                    fp = os.path.join(dir_path, f)
                    if os.path.isfile(fp):
                        res = self.scan_file(fp)
                        if res:
                            all_matches.extend(res)
        except Exception as e:
            logger.error(f"Error scanning directory '{dir_path}': {e}")

        return all_matches


# Global singleton instance for agent
global_yara_scanner = YaraScanner()
