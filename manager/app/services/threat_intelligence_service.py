import os
import logging
from typing import Dict, Any, Optional
import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_indicator import ThreatIndicator
from app.repositories.threat_indicator_repository import ThreatIndicatorRepository

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    """
    Threat Intelligence Service querying local database cache or external providers (VirusTotal, AbuseIPDB, AlienVault).
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = ThreatIndicatorRepository(session)
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", "")

    async def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check hash reputation in local DB, then fallback to VirusTotal API."""
        existing = await self.repo.lookup(file_hash, indicator_type="hash")
        if existing:
            return {
                "is_malicious": existing.confidence >= 50.0,
                "threat_type": existing.threat_type,
                "confidence": existing.confidence,
                "source": existing.source,
                "cached": True
            }

        if not self.vt_api_key:
            return {"is_malicious": False, "threat_type": "unknown", "confidence": 0.0, "source": "none"}

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_api_key}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else 1
                    confidence = round((malicious / total) * 100.0, 2) if total > 0 else 0.0
                    is_mal = malicious > 2

                    if is_mal:
                        indicator = ThreatIndicator(
                            indicator_type="hash",
                            value=file_hash,
                            threat_type="malware",
                            confidence=confidence,
                            source="virustotal"
                        )
                        await self.repo.add(indicator)
                        await self.session.flush()

                    return {
                        "is_malicious": is_mal,
                        "threat_type": "malware" if is_mal else "clean",
                        "confidence": confidence,
                        "source": "virustotal",
                        "cached": False
                    }
        except Exception as e:
            logger.exception(f"VirusTotal API check failed: {e}")

        return {"is_malicious": False, "threat_type": "unknown", "confidence": 0.0, "source": "virustotal_error"}

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation in local DB, then fallback to AbuseIPDB API."""
        existing = await self.repo.lookup(ip, indicator_type="ip")
        if existing:
            return {
                "is_malicious": existing.confidence >= 50.0,
                "threat_type": existing.threat_type,
                "confidence": existing.confidence,
                "source": existing.source,
                "cached": True
            }

        if not self.abuseipdb_api_key:
            return {"is_malicious": False, "threat_type": "unknown", "confidence": 0.0, "source": "none"}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    abuse_score = float(data.get("abuseConfidenceScore", 0))
                    is_mal = abuse_score >= 50.0

                    if is_mal:
                        indicator = ThreatIndicator(
                            indicator_type="ip",
                            value=ip,
                            threat_type="malicious_host",
                            confidence=abuse_score,
                            source="abuseipdb"
                        )
                        await self.repo.add(indicator)
                        await self.session.flush()

                    return {
                        "is_malicious": is_mal,
                        "threat_type": "malicious_host" if is_mal else "clean",
                        "confidence": abuse_score,
                        "source": "abuseipdb",
                        "cached": False
                    }
        except Exception as e:
            logger.exception(f"AbuseIPDB API check failed: {e}")

        return {"is_malicious": False, "threat_type": "unknown", "confidence": 0.0, "source": "abuseipdb_error"}

    async def check_indicator(self, value: str, indicator_type: str) -> Dict[str, Any]:
        """Unified checker dispatcher for hash, ip, or domain."""
        if indicator_type == "hash":
            return await self.check_hash(value)
        elif indicator_type == "ip":
            return await self.check_ip(value)
        else:
            existing = await self.repo.lookup(value, indicator_type=indicator_type)
            if existing:
                return {
                    "is_malicious": existing.confidence >= 50.0,
                    "threat_type": existing.threat_type,
                    "confidence": existing.confidence,
                    "source": existing.source,
                    "cached": True
                }
            return {"is_malicious": False, "threat_type": "unknown", "confidence": 0.0, "source": "none"}
