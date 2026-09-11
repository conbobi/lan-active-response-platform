import asyncio
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from sqlalchemy import select, text
from app.core.database import AsyncSessionLocal
from app.models.risk_score import RiskScoreRecord


async def main():
    async with AsyncSessionLocal() as session:
        # Lấy 20 record gần nhất có score > 0
        stmt = text("""
            SELECT agent_id, score, smoothed_score, factors, timestamp
            FROM risk_score_records
            WHERE timestamp > NOW() - INTERVAL '30 minutes'
            ORDER BY timestamp DESC
            LIMIT 20
        """)
        result = await session.execute(stmt)
        
        print(f"{'agent':<12} {'raw':>8} {'smooth':>8} {'factors_summary':<60} {'time':<20}")
        print("=" * 110)
        for row in result:
            agent_id = row[0]
            raw = row[1]
            smooth = row[2]
            factors = row[3]
            ts = row[4]
            
            # Tóm tắt factors
            if factors and isinstance(factors, dict):
                summary = ", ".join([
                    f"{k}={round(v, 1) if isinstance(v, (int, float)) else str(v)[:25]}"
                    for k, v in factors.items() if (v > 0 if isinstance(v, (int, float)) else bool(v))
                ])
            else:
                summary = "(none)"
            
            print(f"{agent_id:<12} {raw:>8.2f} {smooth:>8.2f} {summary[:60]:<60} {str(ts):<20}")


if __name__ == "__main__":
    asyncio.run(main())
