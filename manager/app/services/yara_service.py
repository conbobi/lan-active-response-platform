import asyncio
import logging
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.yara_rule import YaraRule
from app.repositories.yara_rule_repository import YaraRuleRepository
from app.schemas.yara import YaraRuleCreate, YaraRuleUpdate, YaraScanRequest
from app.services.command_dispatcher import command_dispatcher
from app.core.exceptions import AppException

logger = logging.getLogger(__name__)

DEFAULT_YARA_RULES = [
    {
        "name": "Webshell_Generic_PHP",
        "category": "webshell",
        "severity": "critical",
        "rule_content": """rule Webshell_Generic_PHP {
    meta:
        description = "Detects generic PHP webshell signatures"
        author = "LARP SOC"
    strings:
        $p1 = "eval($_POST[" nocase
        $p2 = "eval($_GET[" nocase
        $p3 = "system($_REQUEST[" nocase
        $p4 = "passthru($_POST[" nocase
        $p5 = "base64_decode($_POST[" nocase
        $p6 = "shell_exec(" nocase
    condition:
        2 of them
}"""
    },
    {
        "name": "ELF_Ransomware_LockBit_Sim",
        "category": "ransomware",
        "severity": "critical",
        "rule_content": """rule ELF_Ransomware_LockBit_Sim {
    meta:
        description = "Detects ransomware strings and simulation artifacts"
        author = "LARP SOC"
    strings:
        $s1 = "All your files have been encrypted" nocase
        $s2 = ".encrypted" nocase
        $s3 = "DECRYPT_NOTE.txt" nocase
        $s4 = "ransomware_sim" nocase
    condition:
        2 of them
}"""
    },
    {
        "name": "Credential_Dumping_Strings",
        "category": "malware",
        "severity": "high",
        "rule_content": """rule Credential_Dumping_Strings {
    meta:
        description = "Detects credential dumper strings"
        author = "LARP SOC"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "lsass.dump" nocase
        $m3 = "wdigest.dll" nocase
        $m4 = "mimikatz" nocase
    condition:
        any of them
}"""
    }
]


class YaraService:
    """Service for managing YARA rules and distributing scan commands to agents."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = YaraRuleRepository(session)

    async def seed_default_rules(self) -> List[YaraRule]:
        existing = await self.repo.list(limit=1)
        if not existing:
            created = []
            for r in DEFAULT_YARA_RULES:
                rule = YaraRule(
                    name=r["name"],
                    rule_content=r["rule_content"],
                    category=r["category"],
                    severity=r["severity"],
                    enabled=True
                )
                await self.repo.add(rule)
                created.append(rule)
            await self.session.commit()
            logger.info("Seeded default YARA rules.")
            return created
        return []

    async def list_rules(self) -> List[YaraRule]:
        await self.seed_default_rules()
        return await self.repo.list()

    async def get_rule(self, rule_id: str) -> Optional[YaraRule]:
        return await self.repo.get(rule_id)

    def _validate_yara_syntax(self, rule_content: str) -> bool:
        """Validate YARA syntax via yara-python inside worker thread."""
        try:
            import yara
            yara.compile(source=rule_content)
            return True
        except ImportError:
            # Fallback basic structural check if yara-python not available on manager host
            return "rule " in rule_content and "condition:" in rule_content
        except Exception as e:
            raise AppException(f"Invalid YARA rule syntax: {e}", status_code=400)

    async def create_rule(self, dto: YaraRuleCreate) -> YaraRule:
        existing = await self.repo.get_by_name(dto.name)
        if existing:
            raise AppException(f"Yara rule with name '{dto.name}' already exists.", status_code=400)

        # Validate syntax non-blocking
        await asyncio.to_thread(self._validate_yara_syntax, dto.rule_content)

        rule = YaraRule(
            name=dto.name,
            rule_content=dto.rule_content,
            category=dto.category,
            severity=dto.severity,
            enabled=dto.enabled
        )
        await self.repo.add(rule)
        await self.session.commit()
        return rule

    async def update_rule(self, rule_id: str, dto: YaraRuleUpdate) -> YaraRule:
        rule = await self.repo.get(rule_id)
        if not rule:
            raise AppException("Yara rule not found", status_code=404)

        if dto.rule_content is not None:
            await asyncio.to_thread(self._validate_yara_syntax, dto.rule_content)
            rule.rule_content = dto.rule_content
        if dto.name is not None:
            rule.name = dto.name
        if dto.category is not None:
            rule.category = dto.category
        if dto.severity is not None:
            rule.severity = dto.severity
        if dto.enabled is not None:
            rule.enabled = dto.enabled

        await self.session.commit()
        return rule

    async def delete_rule(self, rule_id: str) -> None:
        rule = await self.repo.get(rule_id)
        if not rule:
            raise AppException("Yara rule not found", status_code=404)
        await self.repo.delete(rule_id)
        await self.session.commit()

    async def get_combined_rules_bundle(self) -> str:
        """Combine all enabled YARA rules into a single string for distribution."""
        rules = await self.repo.get_enabled_rules()
        if not rules:
            await self.seed_default_rules()
            rules = await self.repo.get_enabled_rules()
        return "\n\n".join(r.rule_content for r in rules)

    async def trigger_agent_scan(self, dto: YaraScanRequest) -> Dict[str, Any]:
        """Dispatch a yara_scan command down to the targeted agent."""
        rules_bundle = await self.get_combined_rules_bundle()
        cmd = await command_dispatcher.push_command(
            agent_id=dto.agent_id,
            action="yara_scan",
            payload={
                "target_path": dto.target_path,
                "recursive": dto.recursive,
                "rules_source": rules_bundle
            },
            session=self.session
        )
        return {
            "status": "dispatched",
            "command_id": cmd.id,
            "agent_id": dto.agent_id,
            "target_path": dto.target_path
        }
