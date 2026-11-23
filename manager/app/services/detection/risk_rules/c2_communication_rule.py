from typing import Any, Dict, Tuple

from app.services.detection.risk_rules.base import RiskRule


class C2CommunicationRule(RiskRule):
    rule_id = "c2_communication"
    name = "Possible C2 Communication"
    description = "Records dynamic DNS indicators associated with possible C2 infrastructure."
    category = "network"

    DEFAULT_SUSPICIOUS_DOMAINS = (
        ".duckdns.org", ".ngrok.io", ".onion", ".bazar", ".bip.sh", ".serveo.net", ".trycloudflare.com",
    )

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        domains = self.config.get("suspicious_domains", self.DEFAULT_SUSPICIOUS_DOMAINS)
        suffixes = tuple("." + domain.lower().strip(".") for domain in domains if isinstance(domain, str) and domain.strip("."))
        indicators = set()
        for entry in telemetry.get("dns_queries", []):
            query = entry.get("query", "") if isinstance(entry, dict) else getattr(entry, "query", entry)
            if not isinstance(query, str):
                continue
            query = query.lower().rstrip(".")
            if query.endswith(suffixes):
                indicators.add(query)

        if indicators:
            score = min(20.0, len(indicators) * 12.0) * self.base_score
            return score, f"Possible C2 communication indicator detected (DNS): {', '.join(sorted(indicators)[:10])}"
        return 0.0, ""
