import math
import asyncio
from collections import Counter
from typing import Any, Dict, Tuple, List
from app.services.risk_rules.base import RiskRule


class DnsAnalyzerService:
    """
    Analyzes DNS queries to detect DNS Tunneling, DGA, and Data Exfiltration techniques.
    Calculates Shannon entropy, label lengths, and query type anomalies.
    """

    COMMON_LEGIT_DOMAINS = {
        "google.com", "microsoft.com", "cloudflare.com", "apple.com", "amazon.com",
        "github.com", "ubuntu.com", "debian.org", "docker.com", "larp.local", "local"
    }

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """
        Calculate Shannon entropy for a given string:
        H(X) = - sum(p(x) * log2(p(x)))
        Higher values (> 3.8) indicate high randomness (Base64/Hex encoding, encryption).
        """
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = 0.0
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        return round(entropy, 3)

    @classmethod
    def analyze_query(cls, query: str, query_type: str = "A") -> Dict[str, Any]:
        """
        Analyze a single DNS query:
        Extracts subdomains, calculates entropy, length, and suspicious flags.
        """
        clean_q = query.strip().lower().rstrip(".")
        labels = clean_q.split(".")

        # Extract subdomain part (exclude top 2 apex labels like evil.com)
        if len(labels) > 2:
            subdomain_part = ".".join(labels[:-2])
            apex_domain = ".".join(labels[-2:])
        elif len(labels) == 2:
            subdomain_part = labels[0]
            apex_domain = clean_q
        else:
            subdomain_part = clean_q
            apex_domain = clean_q

        entropy = cls.calculate_shannon_entropy(subdomain_part)
        max_label_len = max(len(l) for l in labels) if labels else 0
        total_len = len(clean_q)

        # Check legit apex
        is_legit = any(apex_domain == d or apex_domain.endswith("." + d) for d in cls.COMMON_LEGIT_DOMAINS)

        q_type_upper = str(query_type).upper()
        is_unusual_type = q_type_upper in ("TXT", "NULL", "ANY", "CNAME")

        is_suspicious = False
        reasons = []

        if not is_legit:
            if entropy > 3.8 and len(subdomain_part) >= 15:
                is_suspicious = True
                reasons.append(f"High entropy ({entropy})")
            if total_len > 50 or max_label_len > 35:
                is_suspicious = True
                reasons.append(f"Abnormal label length ({total_len} chars)")
            if is_unusual_type and len(subdomain_part) >= 20:
                is_suspicious = True
                reasons.append(f"Unusual query type '{q_type_upper}' with long payload")

        return {
            "query": clean_q,
            "query_type": q_type_upper,
            "subdomain": subdomain_part,
            "apex_domain": apex_domain,
            "entropy": entropy,
            "length": total_len,
            "max_label_length": max_label_len,
            "is_suspicious": is_suspicious,
            "reasons": reasons
        }

    @classmethod
    def analyze_batch(cls, dns_queries: List[Any]) -> Dict[str, Any]:
        """Analyze a batch of DNS queries and return composite tunneling metrics."""
        results = []
        suspicious_count = 0
        txt_or_null_count = 0

        for item in dns_queries:
            if isinstance(item, str):
                analysis = cls.analyze_query(item, "A")
            elif isinstance(item, dict):
                analysis = cls.analyze_query(item.get("query", ""), item.get("query_type", "A"))
            elif hasattr(item, "query"):
                analysis = cls.analyze_query(getattr(item, "query", ""), getattr(item, "query_type", "A"))
            else:
                continue

            results.append(analysis)
            if analysis["is_suspicious"]:
                suspicious_count += 1
            if analysis["query_type"] in ("TXT", "NULL"):
                txt_or_null_count += 1

        return {
            "total_queries": len(results),
            "suspicious_count": suspicious_count,
            "txt_or_null_count": txt_or_null_count,
            "details": results
        }


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
