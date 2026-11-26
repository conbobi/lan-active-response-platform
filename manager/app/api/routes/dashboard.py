import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.rule_candidate import RuleCandidate
from app.models.ai_analysis import AIAnalysis

logger = logging.getLogger("larp.api.ai_dashboard")
router = APIRouter()

MITRE_NAME_MAP = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell",
    "T1490": "Inhibit System Recovery",
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1078": "Valid Accounts",
    "T1112": "Modify Registry",
    "T1543": "Create or Modify System Process",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1070": "Indicator Removal on Host",
    "T1036": "Masquerading",
    "T1053": "Scheduled Task/Job",
    "T1105": "Ingress Tool Transfer",
    "T1027": "Obfuscated Files or Information",
    "T1204": "User Execution",
    "T1021": "Remote Services",
    "T1566": "Phishing",
}


@router.get("/ai-metrics")
async def get_ai_metrics(
    period: str = Query("7d", description="Time period filter (e.g. 7d, 30d)"),
    db: AsyncSession = Depends(get_db)
):
    """
    GET /api/dashboard/ai-metrics?period=7d
    Rule lifecycle counts, validation accuracy, trend, MITRE coverage and triage stats computed
    from the database only. Values without a data source are null (UI: "Chưa đủ dữ liệu");
    nothing is filled in with baseline or demo numbers.
    """
    try:
        now = datetime.now(timezone.utc)
        days = 30 if period == "30d" else 7

        all_rules = (await db.execute(select(RuleCandidate))).scalars().all()
        by_status = {name: sum(1 for r in all_rules if r.status == name)
                     for name in ("pending", "validated", "rejected", "active", "disabled")}
        by_source: Dict[str, int] = {}
        for r in all_rules:
            by_source[r.source or "unknown"] = by_source.get(r.source or "unknown", 0) + 1

        # Accuracy only from rules with an actual statistical verdict.
        measured = [r for r in all_rules
                    if (r.validation_result or {}).get("verdict") in ("PASSED", "FAILED")
                    and r.fpr is not None and r.precision is not None]

        def mean(values):
            values = [v for v in values if v is not None]
            return round(sum(values) / len(values), 4) if values else None

        avg_fpr = mean(r.fpr for r in measured)
        avg_precision = mean(r.precision for r in measured)
        avg_recall = mean(r.recall for r in measured)
        avg_f1 = (round(2 * avg_precision * avg_recall / (avg_precision + avg_recall), 4)
                  if avg_precision is not None and avg_recall is not None and (avg_precision + avg_recall) > 0 else None)

        trend_days = []
        for i in range(days - 1, -1, -1):
            day_dt = (now - timedelta(days=i)).date()
            fprs = [r.fpr for r in measured if r.validated_at and r.validated_at.date() == day_dt]
            trend_days.append({
                "date": day_dt.strftime("%Y-%m-%d"),
                "rules_generated": sum(1 for r in all_rules if r.created_at and r.created_at.date() == day_dt),
                "validated": sum(1 for r in all_rules if r.validated_at and r.validated_at.date() == day_dt
                                 and r.status in ("validated", "active", "disabled")),
                "rejected": sum(1 for r in all_rules if r.status == "rejected" and r.validated_at
                                and r.validated_at.date() == day_dt),
                "avg_fpr": round(sum(fprs) / len(fprs), 4) if fprs else None,
            })

        technique_counts: Dict[str, int] = {}
        for r in all_rules:
            if isinstance(r.mitre_techniques, list):
                for tech in r.mitre_techniques:
                    key = str(tech).upper()
                    technique_counts[key] = technique_counts.get(key, 0) + 1
        top_mitre_list = [{"id": tech_id, "count": count, "name": MITRE_NAME_MAP.get(tech_id, tech_id)}
                          for tech_id, count in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:10]]

        analyses = (await db.execute(select(AIAnalysis))).scalars().all()
        confidences = [a.confidence for a in analyses if a.confidence is not None]

        return {
            "period": period,
            "rule_stats": {
                "total": len(all_rules),
                **by_status,
                "by_source": {"ai_harvest": by_source.get("ai_harvest", 0),
                              "human": len(all_rules) - by_source.get("ai_harvest", 0) - by_source.get("template_fallback", 0),
                              "template_fallback": by_source.get("template_fallback", 0)},
            },
            "accuracy_metrics": {
                "measured_rules": len(measured),
                "avg_fpr": avg_fpr,
                "avg_precision": avg_precision,
                "avg_recall": avg_recall,
                "avg_f1": avg_f1,
                "median_validation_time_sec": None,
            },
            "trend_last_7_days": trend_days,
            "top_mitre_techniques": top_mitre_list,
            "ai_triage_stats": {
                "total_analyses": len(analyses),
                "avg_confidence": round(sum(confidences) / len(confidences), 2) if confidences else None,
                "hallucinated_mitre_rejected": None,
                "avg_latency_sec": None,  # not recorded per analysis yet
            },
        }
    except Exception as e:
        logger.error(f"Error in /ai-metrics: {e}", exc_info=True)
        return {"error": f"Failed to get AI metrics: {str(e)}"}

