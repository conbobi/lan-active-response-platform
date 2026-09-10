import pytest
from app.services.dns_analyzer_service import DnsAnalyzerService
from app.services.risk_rules.dns_tunneling_rule import DnsTunnelingRule


def test_shannon_entropy_calculation():
    # Low entropy ordinary English domain
    entropy_normal = DnsAnalyzerService.calculate_shannon_entropy("google")
    assert entropy_normal < 2.5

    # High entropy base64 encoded string
    entropy_high = DnsAnalyzerService.calculate_shannon_entropy("4a8b9c1d2e3f4a5b6c7d8e9f0a1b2c3d")
    assert entropy_high >= 3.8


def test_dns_analyzer_single_query():
    legit = DnsAnalyzerService.analyze_query("www.google.com")
    assert not legit["is_suspicious"]

    tunnel = DnsAnalyzerService.analyze_query("7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d.tunnel.attacker-c2.net", "TXT")
    assert tunnel["is_suspicious"]
    assert tunnel["entropy"] >= 3.5


@pytest.mark.asyncio
async def test_dns_tunneling_rule():
    rule = DnsTunnelingRule()

    # Normal queries
    score_normal, _ = await rule.evaluate({"dns_queries": ["api.github.com", "ubuntu.com"]}, {})
    assert score_normal == 0.0

    # Exfiltration tunnel queries
    malicious_queries = [
        {"query": "dGhpcyBpcyBhIHZlcnkgc2VjcmV0IHBheWxvYWQgdG8gZXhmaWx0cmF0ZQ.c2.evil.com", "query_type": "TXT"},
        {"query": "ZXhmaWx0cmF0aW9uIGRhdGEgYmxvYiBudW1iZXIgdHdv.c2.evil.com", "query_type": "TXT"}
    ]
    score_mal, reason = await rule.evaluate({"dns_queries": malicious_queries}, {})
    assert score_mal >= 35.0
    assert "DNS Tunneling" in reason
