import os
import asyncio
from .base import BaseCommand
from yara_scanner import global_yara_scanner


class YaraScanCommand(BaseCommand):
    name = "yara_scan"

    async def execute(self, params, websocket):
        """
        Execute YARA scan on specified target path.
        Optional rules_source to update scanner rules.
        """
        try:
            target_path = params.get("target_path", "/tmp")
            recursive = bool(params.get("recursive", True))
            rules_source = params.get("rules_source")

            if rules_source:
                global_yara_scanner.load_rules(rules_source)

            # Run scan in threadpool
            def _do_scan():
                if os.path.isfile(target_path):
                    return global_yara_scanner.scan_file(target_path)
                return global_yara_scanner.scan_directory(target_path, recursive=recursive)

            matches = await asyncio.to_thread(_do_scan)

            rule_names = list(set(m.get("rule", "") for m in matches if m.get("rule")))

            return {
                "status": "success",
                "message": f"YARA scan completed on '{target_path}'. Found {len(matches)} matches.",
                "target_path": target_path,
                "matches_count": len(matches),
                "matched_rules": rule_names,
                "matches": matches[:20]  # Cap at 20 details to avoid large WebSocket packet
            }
        except Exception as e:
            return {"status": "error", "message": f"YARA scan failed: {str(e)}"}
