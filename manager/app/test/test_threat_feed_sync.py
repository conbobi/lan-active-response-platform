import pytest
from app.services.threat_intelligence_service import ThreatIntelligenceService


def test_extract_indicators_from_text():
    service = ThreatIntelligenceService(None)

    # IP Feed
    ip_raw = """
    # Feodo Tracker blocklist
    198.51.100.15
    203.0.113.88
    127.0.0.1
    """
    ips = service._extract_indicators_from_text(ip_raw, "ip")
    assert "198.51.100.15" in ips
    assert "203.0.113.88" in ips
    assert "127.0.0.1" not in ips  # Loopback excluded

    # URL Feed (URLhaus style)
    url_raw = """
    # URLhaus dump
    http://malware-dist.xyz/payload.exe
    https://evil-c2.net/gate.php
    """
    urls = service._extract_indicators_from_text(url_raw, "url")
    assert any("malware-dist.xyz" in u for u in urls)
