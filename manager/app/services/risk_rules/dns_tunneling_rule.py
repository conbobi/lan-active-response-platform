import asyncio
from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule
from app.services.dns_analyzer_service import DnsAnalyzerService


class DnsTunnelingRule(RiskRule):
    """
    Risk rule detecting DNS Tunneling and data exfiltration through DNS protocol.
    Evaluates Shannon entropy, label lengths, and query type spikes.
    """
    rule_id = "dns_tunneling"
    name = "DNS Tunneling & Exfiltration Detection"
    description = "Detects anomalous DNS queries with high Shannon entropy, unusual length, or abnormal query types."
    enabled = True
    weight = 1.0
    base_score = 1.0
    category = "network"

    DEFAULT_CONFIG = {
        "entropy_threshold": 3.8,
        "length_threshold": 45,
        "txt_rate_threshold": 10
    }

    async def evaluate(self, telemetry: Dict[str, Any], context: Dict[str, Any]) -> Tuple[float, str]:
        dns_queries: List[Any] = telemetry.get("dns_queries", [])
        if not dns_queries:
            return 0.0, ""

        # Analyze batch in threadpool to keep FastAPI non-blocking
        analysis = await asyncio.to_thread(DnsAnalyzerService.analyze_batch, dns_queries)

        suspicious_items = [d for d in analysis["details"] if d["is_suspicious"]]
        txt_count = analysis["txt_or_null_count"]

        if not suspicious_items and txt_count < int(self.config.get("txt_rate_threshold", 10)):
            return 0.0, ""

        score = 0.0
        reasons = []

        entropy_th = float(self.config.get("entropy_threshold", 3.8))
        len_th = int(self.config.get("length_threshold", 45))
        txt_th = int(self.config.get("txt_rate_threshold", 10))

        has_high_entropy = any(d["entropy"] >= entropy_th for d in suspicious_items)
        has_long_labels = any(d["length"] >= len_th for d in suspicious_items)

        if has_long_labels:
            score += 25.0
            reasons.append("Abnormal query length (>45 chars)")

        if has_high_entropy:
            score += 35.0
            reasons.append(f"High Shannon entropy (>={entropy_th})")

        if txt_count >= txt_th:
            score += 30.0
            reasons.append(f"Excessive TXT/NULL queries ({txt_count})")

        if score > 0:
            final_score = min(80.0, score * self.base_score)
            sample_queries = [d["query"] for d in suspicious_items[:3]]
            sample_str = f" [e.g., {', '.join(sample_queries)}]" if sample_queries else ""
            return final_score, f"DNS Tunneling indicator: {', '.join(reasons)}{sample_str}"

        return 0.0, ""
