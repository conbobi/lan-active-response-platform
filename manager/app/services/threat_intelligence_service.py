import os
import re
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
import httpx
from sqlalchemy import select, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_indicator import ThreatIndicator
from app.models.threat_feed import ThreatFeed
from app.repositories.threat_indicator_repository import ThreatIndicatorRepository
from app.repositories.threat_feed_repository import ThreatFeedRepository
from app.schemas.threat_feed import ThreatFeedCreate, ThreatFeedUpdate, ThreatFeedSyncResult

logger = logging.getLogger(__name__)

DEFAULT_FEEDS = [
    {
        "name": "Feodo Tracker C2 IP Blocklist",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "feed_type": "ip",
        "interval_hours": 6
    },
    {
        "name": "URLhaus Recent Malicious URLs",
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "feed_type": "url",
        "interval_hours": 6
    },
    {
        "name": "ThreatFox Recent IOCs",
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "feed_type": "domain",
        "interval_hours": 12
    }
]


class ThreatIntelligenceService:
    """
    Threat Intelligence Service querying local database cache or external providers (VirusTotal, AbuseIPDB, AlienVault),
    with automated background IoC ingestion from open-source threat feeds.
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = ThreatIndicatorRepository(session)
        self.feed_repo = ThreatFeedRepository(session)
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY", "")

    async def seed_default_feeds(self) -> List[ThreatFeed]:
        """Seed open-source default threat feeds if none exist."""
        existing = await self.feed_repo.list(limit=1)
        if not existing:
            created = []
            for item in DEFAULT_FEEDS:
                feed = ThreatFeed(
                    name=item["name"],
                    url=item["url"],
                    feed_type=item["feed_type"],
                    enabled=True,
                    interval_hours=item["interval_hours"],
                    status="idle",
                    indicator_count=0
                )
                await self.feed_repo.add(feed)
                created.append(feed)
            await self.session.commit()
            logger.info("Seeded default threat intelligence feeds.")
            return created
        return []

    async def list_feeds(self) -> List[ThreatFeed]:
        await self.seed_default_feeds()
        return await self.feed_repo.list()

    async def create_feed(self, dto: ThreatFeedCreate) -> ThreatFeed:
        feed = ThreatFeed(
            name=dto.name,
            url=dto.url,
            feed_type=dto.feed_type,
            enabled=dto.enabled,
            interval_hours=dto.interval_hours
        )
        await self.feed_repo.add(feed)
        await self.session.commit()
        return feed

    async def update_feed(self, feed_id: str, dto: ThreatFeedUpdate) -> Optional[ThreatFeed]:
        feed = await self.feed_repo.get(feed_id)
        if not feed:
            return None
        if dto.name is not None:
            feed.name = dto.name
        if dto.url is not None:
            feed.url = dto.url
        if dto.feed_type is not None:
            feed.feed_type = dto.feed_type
        if dto.enabled is not None:
            feed.enabled = dto.enabled
        if dto.interval_hours is not None:
            feed.interval_hours = dto.interval_hours
        await self.session.commit()
        return feed

    async def delete_feed(self, feed_id: str) -> bool:
        feed = await self.feed_repo.get(feed_id)
        if not feed:
            return False
        await self.feed_repo.delete(feed_id)
        await self.session.commit()
        return True

    def _extract_indicators_from_text(self, text: str, feed_type: str) -> List[str]:
        """Extract clean IoCs according to feed type (IP, Domain, Hash, URL)."""
        lines = text.splitlines()
        extracted = set()

        ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        hash_pattern = re.compile(r"^[a-fA-F0-9]{32,64}$")
        domain_pattern = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            # Check if CSV line (like ThreatFox or URLhaus)
            parts = [p.strip().strip('"') for p in line.split(",")]
            candidate = parts[0] if parts else line

            if feed_type == "ip":
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if match:
                    ip_str = match.group(1)
                    if not (ip_str.startswith("127.") or ip_str.startswith("10.") or ip_str.startswith("192.168.")):
                        extracted.add(ip_str)
            elif feed_type == "hash":
                for part in parts:
                    if hash_pattern.match(part):
                        extracted.add(part.lower())
            elif feed_type in ("domain", "url"):
                if candidate.startswith("http://") or candidate.startswith("https://"):
                    extracted.add(candidate)
                else:
                    for part in parts:
                        clean_d = re.sub(r"^https?://", "", part).split("/")[0].split(":")[0]
                        if domain_pattern.match(clean_d):
                            extracted.add(clean_d.lower())

        return list(extracted)[:500]  # Cap at 500 per sync cycle to keep DB fast and light

    async def sync_feed(self, feed_id: str) -> ThreatFeedSyncResult:
        """Download raw feed, parse IoCs, and update local database."""
        feed = await self.feed_repo.get(feed_id)
        if not feed:
            return ThreatFeedSyncResult(
                feed_id=feed_id,
                name="Unknown",
                status="error",
                indicators_added=0,
                indicators_updated=0,
                message="Feed not found"
            )

        feed.status = "syncing"
        await self.session.commit()

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(feed.url)
                if resp.status_code != 200:
                    feed.status = "error"
                    await self.session.commit()
                    return ThreatFeedSyncResult(
                        feed_id=feed.id,
                        name=feed.name,
                        status="error",
                        indicators_added=0,
                        indicators_updated=0,
                        message=f"HTTP Error {resp.status_code}"
                    )

                text_data = resp.text
                iocs = self._extract_indicators_from_text(text_data, feed.feed_type)

                added = 0
                updated = 0
                now_dt = datetime.now(timezone.utc)

                for val in iocs:
                    existing = await self.repo.lookup(val, indicator_type=feed.feed_type)
                    if existing:
                        existing.confidence = max(existing.confidence, 85.0)
                        existing.threat_type = "botnet_c2" if feed.feed_type == "ip" else "malware"
                        updated += 1
                    else:
                        ind = ThreatIndicator(
                            indicator_type=feed.feed_type,
                            value=val,
                            threat_type="botnet_c2" if feed.feed_type == "ip" else "malware",
                            confidence=85.0,
                            source=feed.name[:64],
                            created_at=now_dt
                        )
                        await self.repo.add(ind)
                        added += 1

                feed.status = "success"
                feed.last_sync_at = now_dt
                feed.indicator_count += added
                await self.session.commit()

                logger.info(f"Feed '{feed.name}' synced successfully. Added: {added}, Updated: {updated}")
                return ThreatFeedSyncResult(
                    feed_id=feed.id,
                    name=feed.name,
                    status="success",
                    indicators_added=added,
                    indicators_updated=updated,
                    message=f"Successfully imported {added} new IoCs ({updated} updated)."
                )

        except Exception as e:
            feed.status = "error"
            await self.session.commit()
            logger.error(f"Error syncing threat feed '{feed.name}': {e}", exc_info=True)
            return ThreatFeedSyncResult(
                feed_id=feed.id,
                name=feed.name,
                status="error",
                indicators_added=0,
                indicators_updated=0,
                message=str(e)
            )

    async def sync_all_feeds(self) -> List[ThreatFeedSyncResult]:
        """Sync all enabled feeds periodically."""
        feeds = await self.feed_repo.get_enabled_feeds()
        results = []
        for feed in feeds:
            res = await self.sync_feed(feed.id)
            results.append(res)
        return results

    async def list_indicators(
        self,
        skip: int = 0,
        limit: int = 100,
        query: Optional[str] = None,
        indicator_type: Optional[str] = None
    ) -> Tuple[List[ThreatIndicator], int]:
        """List and search cached threat indicators."""
        stmt = select(ThreatIndicator)
        count_stmt = select(func.count(ThreatIndicator.id))

        filters = []
        if indicator_type:
            filters.append(ThreatIndicator.indicator_type == indicator_type)
        if query:
            q_str = f"%{query.strip()}%"
            filters.append(or_(
                ThreatIndicator.value.ilike(q_str),
                ThreatIndicator.source.ilike(q_str),
                ThreatIndicator.threat_type.ilike(q_str)
            ))

        if filters:
            stmt = stmt.where(*filters)
            count_stmt = count_stmt.where(*filters)

        stmt = stmt.order_by(ThreatIndicator.created_at.desc()).offset(skip).limit(limit)
        items_res = await self.session.execute(stmt)
        count_res = await self.session.execute(count_stmt)

        return list(items_res.scalars().all()), int(count_res.scalar() or 0)

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
