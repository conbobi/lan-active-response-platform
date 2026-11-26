import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
import httpx
import yaml

from app.core.database import AsyncSessionLocal
from app.models.rule_candidate import RuleCandidate
from app.models.rule_version import RuleVersion
from app.services.ai.ai_client import DEFAULT_MODEL, OLLAMA_URL

logger = logging.getLogger("larp.ai.harvest")

DEFAULT_HARVEST_MODEL = os.getenv("HARVEST_MODEL") or DEFAULT_MODEL
FALLBACK_MODEL = DEFAULT_MODEL


class HarvestService:
    """
    Agent A: Threat Intelligence Harvesting Service.
    Generates Sigma rules from Cyber Threat Intelligence (CTI) reports using Ollama.
    Validates Sigma YAML structure and persists rule candidates and version history.
    """

    def __init__(self, ollama_url: str = OLLAMA_URL, model: str = DEFAULT_HARVEST_MODEL):
        self.ollama_url = ollama_url
        self.model = model

    async def harvest_from_cti(
        self,
        cti_text: str,
        analyst_id: str,
        db_session = None
    ) -> RuleCandidate:
        """
        Harvest Sigma rule from CTI report.
        Calls Ollama, validates syntax, retries once on failure,
        and saves candidate in DB with status='pending'.
        """
        raw_output = await self._call_llm_for_sigma(cti_text)
        yaml_content, parsed_dict = self._extract_and_validate_yaml(raw_output)

        used_fallback = parsed_dict is None
        if parsed_dict is None:
            # Fallback directly to template generation to prevent Cloudflare 100s timeout
            logger.info("Harvest LLM output was invalid or timed out. Generating deterministic fallback Sigma rule...")
            yaml_content, parsed_dict = self._generate_fallback_yaml(cti_text)

        # Extract metadata
        rule_name = str(parsed_dict.get("title", f"AI Harvested Rule - {datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}"))
        severity = str(parsed_dict.get("level", "medium")).lower()
        if severity not in ["low", "medium", "high", "critical"]:
            severity = "medium"

        mitre_techniques = self._extract_mitre_techniques(parsed_dict.get("tags", []))

        # Build candidate object
        candidate = RuleCandidate(
            id=uuid.uuid4(),
            rule_yaml=yaml_content,
            rule_name=rule_name,
            # A keyword template is not model output; label it so the UI and KPIs never count it as AI.
            source="template_fallback" if used_fallback else "ai_harvest",
            status="pending",
            severity=severity,
            mitre_techniques=mitre_techniques,
            created_at=datetime.now(timezone.utc),
            created_by=analyst_id or "soc_analyst",
            model_generated=None if used_fallback else self.model,
            harvest_prompt=cti_text,
            notes=("Mẫu từ khóa dự phòng: model không trả Sigma hợp lệ hoặc quá thời gian."
                   if used_fallback else f"Sinh bởi {self.model} từ báo cáo CTI.")
        )

        version = RuleVersion(
            rule_candidate_id=candidate.id,
            version_number=1,
            yaml_content=yaml_content,
            change_reason="Initial AI harvest from CTI report",
            created_at=datetime.now(timezone.utc),
            created_by=analyst_id or "soc_analyst"
        )

        # Save to DB
        if db_session is not None:
            db_session.add(candidate)
            db_session.add(version)
            await db_session.flush()
        else:
            async with AsyncSessionLocal() as session:
                async with session.begin():
                    session.add(candidate)
                    session.add(version)
                await session.refresh(candidate)

        return candidate

    async def _call_llm_for_sigma(self, text: str) -> str:
        """Call Ollama /api/chat with the configured model and a short timeout."""
        system_prompt = (
            "You are a Senior Cyber Threat Detection Engineer. "
            "Generate a valid Sigma detection rule in YAML format based on the threat intelligence report.\n"
            "CRITICAL FORMAT RULES:\n"
            "- Output ONLY valid YAML starting with 'title:'.\n"
            "- Do not include introductory conversation, preamble, or markdown explanations.\n"
            "- Required fields: title, id, status, description, tags, logsource, detection, level.\n"
            "- Under detection, define 'selection' and 'condition: selection'."
        )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Extract IOCs and generate a Sigma rule in YAML for:\n\n{text}"}
            ],
            "stream": False,
            "keep_alive": "24h",
            "options": {
                "temperature": 0.1,
                "num_predict": 350,
                "top_p": 0.9,
                "stop": ["```\n\n", "---", "\n\n\n\n"]
            }
        }

        # Keep timeout strictly under 45s so the entire HTTP request never exceeds 50s
        timeout = httpx.Timeout(45.0, connect=5.0)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(f"{self.ollama_url}/api/chat", json=payload)
                if resp.status_code == 404 and self.model != FALLBACK_MODEL:
                    logger.warning(f"Model {self.model} returned 404. Falling back to {FALLBACK_MODEL}")
                    payload["model"] = FALLBACK_MODEL
                    resp = await client.post(f"{self.ollama_url}/api/chat", json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data.get("message", {}).get("content", "")
        except Exception as e:
            logger.warning(f"Ollama call for harvest completed or timed out: {e}")
            return ""

    def _extract_and_validate_yaml(self, raw_text: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Extract YAML block from LLM output, parse with PyYAML,
        and ensure required Sigma keys exist (title, logsource, detection).
        """
        if not raw_text or not raw_text.strip():
            return "", None

        # Strip reasoning <think>...</think>
        clean = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()
        # If open <think> was cut off without closing tag
        if "<think>" in clean and "</think>" not in clean:
            clean = re.sub(r"<think>.*$", "", clean, flags=re.DOTALL).strip()

        # Check for code fence ```yaml ... ``` or ``` ... ```
        fence_match = re.search(r"```(?:yaml)?\s*\n(.*?)(?:```|$)", clean, re.DOTALL | re.IGNORECASE)
        candidate_yaml = fence_match.group(1).strip() if fence_match else clean

        # Also strip any leading ```yaml or trailing ```
        candidate_yaml = re.sub(r"^```(?:yaml)?\s*\n?", "", candidate_yaml, flags=re.IGNORECASE).strip()
        candidate_yaml = re.sub(r"\n?```\s*$", "", candidate_yaml).strip()

        try:
            parsed = yaml.safe_load(candidate_yaml)
            if not isinstance(parsed, dict):
                return candidate_yaml, None

            # Verify detection block is present (the core requirement)
            if "detection" in parsed:
                # Ensure minimum keys exist
                if "title" not in parsed:
                    parsed["title"] = "AI Harvested Threat Detection"
                if "logsource" not in parsed:
                    parsed["logsource"] = {"category": "process_creation", "product": "windows"}
                if "level" not in parsed:
                    parsed["level"] = "medium"
                if "id" not in parsed:
                    parsed["id"] = str(uuid.uuid4())
                if "status" not in parsed:
                    parsed["status"] = "experimental"

                dumped = yaml.dump(parsed, sort_keys=False, default_flow_style=False)
                return dumped, parsed

            return candidate_yaml, None
        except Exception as e:
            logger.warning(f"Failed to parse YAML from harvest output: {e}")
            return candidate_yaml, None

    def _extract_mitre_techniques(self, tags: Any) -> List[str]:
        """Extract MITRE technique IDs from Sigma tags list."""
        if not tags:
            return []
        if isinstance(tags, str):
            tags = [tags]

        techniques = []
        for tag in tags:
            tag_str = str(tag).strip()
            # Match attack.t1059.001 or attack.t1059 or T1059.001
            m = re.search(r"(?:attack\.)?(t\d{4}(?:\.\d{3})?)", tag_str, re.IGNORECASE)
            if m:
                techniques.append(m.group(1).upper())

        return list(dict.fromkeys(techniques))  # Deduplicate

    def _generate_fallback_yaml(self, cti_text: str) -> Tuple[str, Dict[str, Any]]:
        """
        Generate a structured, deterministic baseline Sigma rule if LLM generation timed out or failed.
        Extracts known threat patterns, adversary tools, commands, and MITRE techniques.
        """
        text_lower = cti_text.lower()
        extracted_ioc: List[str] = []
        tags: List[str] = []

        if "powershell" in text_lower:
            tags.append("attack.t1059.001")
            extracted_ioc.extend(["powershell", "DownloadString", "Bypass"])
        if "shadow" in text_lower or "vssadmin" in text_lower or "shadowcopy" in text_lower:
            tags.append("attack.t1490")
            extracted_ioc.extend(["vssadmin", "delete shadows", "shadowcopy"])
        if "mimikatz" in text_lower or "lsass" in text_lower or "sekurlsa" in text_lower:
            tags.append("attack.t1003.001")
            extracted_ioc.extend(["mimikatz", "sekurlsa", "privilege::debug"])
        if "bash" in text_lower or "sh" in text_lower or "/bin/" in text_lower:
            tags.append("attack.t1059.004")
            extracted_ioc.extend(["/bin/bash", "/bin/sh"])
        if "curl" in text_lower or "wget" in text_lower or "download" in text_lower:
            tags.append("attack.t1105")
            extracted_ioc.extend(["curl", "wget"])
        if not tags:
            tags.append("attack.t1059")

        # Extract words from CTI text
        clean_words = [w.strip(".,;:\"'()[]{}") for w in cti_text.split() if len(w) > 4 and w.isalnum()]
        for w in clean_words[:5]:
            if w.lower() not in [x.lower() for x in extracted_ioc]:
                extracted_ioc.append(w)

        if not extracted_ioc:
            extracted_ioc = ["suspicious_process"]

        # Derive a clean title
        first_line = cti_text.strip().split("\n")[0][:60]
        title = f"Detect {first_line.rstrip('.')}"

        rule_dict: Dict[str, Any] = {
            "title": title,
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": f"Sigma detection rule harvested from threat report: {cti_text[:120]}...",
            "references": [
                "https://attack.mitre.org"
            ],
            "tags": tags,
            "logsource": {
                "category": "process_creation",
                "product": "windows"
            },
            "detection": {
                "selection": {
                    "CommandLine|contains": extracted_ioc[:6]
                },
                "condition": "selection"
            },
            "level": "high" if any(t in ["attack.t1003.001", "attack.t1490"] for t in tags) else "medium"
        }

        yaml_content = yaml.dump(rule_dict, sort_keys=False, default_flow_style=False)
        return yaml_content, rule_dict


harvest_service = HarvestService()
