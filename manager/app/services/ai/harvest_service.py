import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, List
import httpx
import yaml

from app.services.ai.harvest_context import expected_product, process_context, validate_selection, web_shell_context
from app.services.detection import sigma_runtime
from app.core.database import AsyncSessionLocal
from app.models.rule_candidate import RuleCandidate
from app.models.rule_version import RuleVersion
from app.services.ai.ai_client import DEFAULT_MODEL, OLLAMA_URL

DEFAULT_HARVEST_MODEL = os.getenv("HARVEST_MODEL") or DEFAULT_MODEL


# Selection keys the model may emit: exactly the process fields and modifiers the runtime executes.
SELECTION_FIELDS = ("ParentImage", "ParentCommandLine", "Image", "CommandLine")
SELECTION_MODIFIERS = ("contains", "endswith", "startswith")
MAX_ATTEMPTS = max(1, min(3, int(os.getenv("HARVEST_MAX_ATTEMPTS", "2"))))


def sigma_output_schema(platform):
    """Constrain model output to the runtime-supported Sigma subset; observables come from the CTI."""
    def mapping(properties, required=None):
        return {"type": "object", "properties": properties, "required": required or list(properties),
                "additionalProperties": False}

    string = {"type": "string", "minLength": 1}
    value = {"anyOf": [string, {"type": "array", "items": string, "minItems": 1, "maxItems": 8}]}
    keys = [f"{f}|{m}" for f in SELECTION_FIELDS for m in SELECTION_MODIFIERS]
    selection = {"type": "object", "properties": {k: value for k in keys}, "additionalProperties": False,
                 "minProperties": 1}
    return mapping({
        "title": string,
        "logsource": mapping({"product": {"enum": [platform] if platform else ["linux", "windows"]},
                              "category": {"const": "process_creation"}}),
        "detection": mapping({"selection": selection, "condition": {"const": "selection"}}),
        "level": {"enum": ["low", "medium", "high", "critical"]},
        "tags": {"type": "array", "minItems": 1, "maxItems": 4,
                 "items": {"type": "string", "pattern": "^attack\\.t[0-9]{4}(\\.[0-9]{3})?$"}},
    })


SYSTEM_PROMPT = (
    "You write Sigma detection rules as one JSON object. No Markdown, no prose.\n"
    "Fields in detection.selection are ANDed; a list value means any of its values (OR). "
    "Values are literal strings matched with the field modifier; no wildcards.\n"
    "Use only concrete process observables named in the report: executable paths, script names, command fragments. "
    "Never use narrative words such as adversaries, attackers, exploit, malicious or suspicious as values.\n"
    "Image and ParentImage are executable paths without arguments (match them with endswith, e.g. /nginx, /bash); "
    "script names and arguments belong in CommandLine or ParentCommandLine with contains.\n"
    "Tags are MITRE ATT&CK ids such as attack.t1059.004.\n"
    "Example (a different scenario, for format and field use only):\n"
    "Report: The PostgreSQL server (/usr/lib/postgresql/16/bin/postgres) was abused with COPY FROM PROGRAM; "
    "the database process started /bin/sh -c and ran curl and wget to fetch a payload.\n"
    '{"title":"PostgreSQL Server Spawning Shell Downloader","logsource":{"product":"linux","category":"process_creation"},'
    '"detection":{"selection":{"ParentImage|endswith":"/postgres","Image|endswith":["/sh","/bash","/dash"],'
    '"CommandLine|contains":["curl ","wget "]},"condition":"selection"},"level":"high","tags":["attack.t1059.004"]}'
)
WEB_SHELL_PROMPT = (
    "\nFor a web server or web application spawning a shell, one selection must require all three: "
    "the web service parent (its executable in ParentImage|endswith, or the web application script or server name in "
    "ParentCommandLine|contains; never a bare interpreter such as python3), the Unix child shell in Image|endswith, "
    "and the command line evidence the report describes (reconnaissance commands, download tools or shell chaining) "
    "in CommandLine|contains. Tag attack.t1059.004."
)


class GenerationError(ValueError):
    """No usable model-generated candidate was produced."""


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
        Calls Ollama, validates the result,
        and saves candidate in DB with status='pending'.
        """
        feedback = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            raw_output = await self._call_llm_for_sigma(cti_text, feedback)
            try:
                yaml_content, parsed_dict = self._extract_and_validate_yaml(raw_output, cti_text)
                break
            except GenerationError as exc:
                if attempt == MAX_ATTEMPTS:
                    raise GenerationError(f"{exc} (after {attempt} model attempt(s))") from exc
                feedback = str(exc)

        mitre_techniques = self._extract_mitre_techniques(parsed_dict.get("tags", []))

        # Build candidate object
        candidate = RuleCandidate(
            id=uuid.uuid4(),
            rule_yaml=yaml_content,
            rule_name=parsed_dict["title"],
            source="ai_harvest",
            status="pending",
            severity=parsed_dict["level"],
            mitre_techniques=mitre_techniques,
            created_at=datetime.now(timezone.utc),
            created_by=analyst_id or "soc_analyst",
            model_generated=self.model,
            harvest_prompt=cti_text,
            notes=f"Sinh bởi {self.model} từ báo cáo CTI (lần thử {attempt}/{MAX_ATTEMPTS})."
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

    async def _call_llm_for_sigma(self, text: str, feedback: str | None = None) -> str:
        """One bounded Ollama generation constrained to the supported Sigma subset.

        The harvest model (Foundation-Sec-8B-Reasoning) always reasons before answering and its
        template has no switch to disable that, so /api/chat spent the whole token budget on
        hidden reasoning and returned empty content. The prompt is sent raw in the model's chat
        format with an empty reasoning block, so the token budget goes to the JSON answer.
        """
        try:
            process_context(text)
            platform = expected_product(text)
        except ValueError as exc:
            raise GenerationError(str(exc)) from exc
        system = SYSTEM_PROMPT + (WEB_SHELL_PROMPT if platform == "linux" and web_shell_context(text) else "")
        task = (f"Write the Sigma rule for product {platform}, category process_creation."
                if platform else "Write the Sigma rule; set logsource.product from the report (linux or windows).")
        if feedback:
            task += (f"\nYour previous answer was rejected: {feedback}\n"
                     "Write a corrected rule: drop every value named above and keep only values that satisfy the rules.")
        prompt = (f"<|system|>\n{system}\n<|user|>\nReport:\n{text.strip()[:4000]}\n\n{task}\n"
                  "<|assistant|>\n<think>\n\n</think>\n")
        payload = {
            "model": self.model,
            "prompt": prompt,
            "raw": True,
            "format": sigma_output_schema(platform),
            "stream": False,
            "keep_alive": "5m",
            "options": {"temperature": 0.3 if feedback else 0.1, "num_predict": 512, "top_p": 0.9},
        }
        timeout = httpx.Timeout(float(os.getenv("HARVEST_TIMEOUT_SECONDS", "120")), connect=5.0)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(f"{self.ollama_url}/api/generate", json=payload)
                resp.raise_for_status()
                body = resp.json()
        except httpx.TimeoutException as exc:
            raise GenerationError("Ollama generation timed out") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise GenerationError(f"Ollama generation failed: {exc}") from exc
        if not isinstance(body, dict) or not isinstance(body.get("response"), str):
            raise GenerationError("Ollama returned no generated text")
        if body.get("done_reason") == "length":
            raise GenerationError("Model output was truncated at the token limit")
        return body["response"]

    def _extract_and_validate_yaml(self, raw_text, cti_text):
        if not isinstance(raw_text, str) or not raw_text.strip() or "```" in raw_text:
            raise GenerationError("Expected raw Sigma YAML; received empty output or Markdown")
        try:
            rule = yaml.safe_load(raw_text)
            if not isinstance(rule, dict) or not isinstance(rule.get("title"), str) or not rule["title"].strip():
                raise ValueError("Missing Sigma title")
            source = rule.get("logsource")
            if not isinstance(source, dict) or source.get("product") not in ("windows", "linux") or source.get("category") != "process_creation":
                raise ValueError("Expected an explicit Linux or Windows process_creation logsource")
            if rule.get("level") not in ("informational", "low", "medium", "high", "critical"):
                raise ValueError("Missing or invalid Sigma level")
            tags = rule.get("tags")
            if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
                raise ValueError("Expected Sigma tags list")
            if not any(re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", t, re.I) for t in tags):
                raise ValueError("Expected at least one MITRE technique tag")
            supported, reason = sigma_runtime.check_support(rule)
            if not supported or rule["detection"].get("condition") != "selection":
                raise ValueError(reason if not supported else "Expected explicit condition: selection")
            validate_selection(rule, cti_text)
        except (yaml.YAMLError, TypeError, ValueError, re.error, AttributeError) as exc:
            raise GenerationError(f"Invalid generated Sigma: {exc}") from exc
        return yaml.safe_dump(rule, sort_keys=False), rule

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


harvest_service = HarvestService()
