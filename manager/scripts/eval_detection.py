"""
Script đánh giá hiệu năng (Precision / Recall) của 18 detection rules
dựa trên ground truth label (true_positive, false_positive, benign, inconclusive) từ SOC Analyst.

Chạy:
  docker compose exec manager python -m scripts.eval_detection
  docker compose exec manager python -m scripts.eval_detection --json output.json
"""
import os
import sys
import json
import argparse
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import logging
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

from sqlalchemy import select
from app.core.database import AsyncSessionLocal, async_engine
from app.models.incident import Incident
from app.models.risk_score import RiskScoreRecord
from app.services.incident.incident_timeline_service import _parse_factors

# Turn off SQL statement echo for cleaner CLI reports
async_engine.echo = False

ALL_RULES = [
    "process_chain_rule",
    "living_off_land_rule",
    "suspicious_process_rule",
    "credential_dumping_rule",
    "shadow_copy_rule",
    "c2_communication_rule",
    "lateral_movement_rule",
    "dns_tunneling_rule",
    "http_beaconing_rule",
    "brute_force_rule",
    "injection_rule",
    "network_connection_rule",
    "file_changes_rule",
    "mass_file_modification_rule",
    "registry_rule",
    "yara_match_rule",
    "cpu_spike_rule",
    "ml_anomaly_rule",
]

RULE_KEY_MAP = {
    "cpu_spike": "cpu_spike_rule",
    "cpu_spike_rule": "cpu_spike_rule",
    "suspicious_process": "suspicious_process_rule",
    "suspicious_process_rule": "suspicious_process_rule",
    "network_connection": "network_connection_rule",
    "network_connection_rule": "network_connection_rule",
    "file_changes": "file_changes_rule",
    "file_changes_rule": "file_changes_rule",
    "process_chain": "process_chain_rule",
    "process_chain_rule": "process_chain_rule",
    "injection": "injection_rule",
    "injection_rule": "injection_rule",
    "living_off_land": "living_off_land_rule",
    "living_off_land_rule": "living_off_land_rule",
    "registry": "registry_rule",
    "registry_rule": "registry_rule",
    "credential_dumping": "credential_dumping_rule",
    "credential_dumping_rule": "credential_dumping_rule",
    "shadow_copy": "shadow_copy_rule",
    "shadow_copy_rule": "shadow_copy_rule",
    "c2_communication": "c2_communication_rule",
    "c2_communication_rule": "c2_communication_rule",
    "lateral_movement": "lateral_movement_rule",
    "lateral_movement_rule": "lateral_movement_rule",
    "mass_file_modification": "mass_file_modification_rule",
    "mass_file_modification_rule": "mass_file_modification_rule",
    "brute_force": "brute_force_rule",
    "brute_force_rule": "brute_force_rule",
    "dns_tunneling": "dns_tunneling_rule",
    "dns_tunneling_rule": "dns_tunneling_rule",
    "http_beaconing": "http_beaconing_rule",
    "http_beaconing_rule": "http_beaconing_rule",
    "yara_match": "yara_match_rule",
    "yara_match_rule": "yara_match_rule",
    "ml_behavioral_anomaly": "ml_anomaly_rule",
    "ml_anomaly": "ml_anomaly_rule",
    "ml_anomaly_rule": "ml_anomaly_rule",
}


def normalize_rule_name(raw_key: str) -> Optional[str]:
    """Map raw telemetry factors key to standard rule identifier."""
    if not raw_key:
        return None
    k = str(raw_key).strip().lower()
    if k in ("total_score", "score", "smoothed_score", "risk_spike"):
        return None
    if k in RULE_KEY_MAP:
        return RULE_KEY_MAP[k]
    if f"{k}_rule" in RULE_KEY_MAP:
        return RULE_KEY_MAP[f"{k}_rule"]
    return f"{k}_rule" if not k.endswith("_rule") else k


async def extract_triggered_rules(
    session,
    incident: Incident
) -> Set[str]:
    """Extract list of triggered rules for an incident via risk_score_records or fallback description."""
    triggered: Set[str] = set()

    # 1. Thử lấy từ risk_score_records theo agent_id và thời gian tương ứng (trong vòng 15 phút)
    if incident.agent_id:
        target_time = incident.created_at or datetime.now(timezone.utc)
        risk_stmt = (
            select(RiskScoreRecord)
            .where(RiskScoreRecord.agent_id == incident.agent_id)
            .where(RiskScoreRecord.timestamp >= target_time - timedelta(minutes=15))
            .where(RiskScoreRecord.timestamp <= target_time + timedelta(minutes=15))
            .order_by(RiskScoreRecord.timestamp.desc())
            .limit(5)
        )
        res = await session.execute(risk_stmt)
        records = res.scalars().all()
        for rrec in records:
            if rrec and rrec.factors and isinstance(rrec.factors, dict):
                for k in rrec.factors.keys():
                    norm = normalize_rule_name(k)
                    if norm:
                        triggered.add(norm)
            if triggered:
                break

    # 2. Fallback: Parse từ description nếu chưa có factors
    if not triggered and incident.description:
        parsed = _parse_factors(incident.description)
        if parsed and isinstance(parsed, dict):
            for k in parsed.keys():
                norm = normalize_rule_name(k)
                if norm:
                    triggered.add(norm)

    return triggered


async def evaluate_detection_rules(json_export_path: Optional[str] = None):
    async with AsyncSessionLocal() as session:
        # Query tất cả incidents có label IS NOT NULL
        stmt = select(Incident).where(Incident.label.is_not(None)).order_by(Incident.created_at.desc())
        res = await session.execute(stmt)
        incidents = res.scalars().all()

        total_labeled = len(incidents)
        tp_total = sum(1 for i in incidents if i.label == "true_positive")
        fp_total = sum(1 for i in incidents if i.label == "false_positive")
        benign_total = sum(1 for i in incidents if i.label == "benign")
        inconclusive_total = sum(1 for i in incidents if i.label == "inconclusive")

        # Khởi tạo stats cho tất cả 18 rules
        rule_stats: Dict[str, Dict[str, int]] = {
            r: {"tp": 0, "fp": 0} for r in ALL_RULES
        }

        # Duyệt qua từng incident đã gán nhãn
        for inc in incidents:
            label = (inc.label or "").strip().lower()
            rules = await extract_triggered_rules(session, inc)

            for rule in rules:
                if rule not in rule_stats:
                    rule_stats[rule] = {"tp": 0, "fp": 0}
                if label == "true_positive":
                    rule_stats[rule]["tp"] += 1
                elif label == "false_positive":
                    rule_stats[rule]["fp"] += 1

        # Tính toán Precision và Recall
        rows = []
        weak_rules = []
        for rule, stats in rule_stats.items():
            tp = stats["tp"]
            fp = stats["fp"]
            total_rule = tp + fp
            prec = (tp / total_rule * 100.0) if total_rule > 0 else 0.0
            recall = (tp / tp_total * 100.0) if tp_total > 0 else 0.0
            is_weak = total_rule > 0 and prec < 50.0

            rows.append({
                "rule": rule,
                "tp": tp,
                "fp": fp,
                "precision": prec,
                "recall": recall,
                "total_rule": total_rule,
                "is_weak": is_weak
            })

            if is_weak:
                weak_rules.append({
                    "rule": rule,
                    "precision": prec,
                    "tp": tp,
                    "fp": fp
                })

        # Sắp xếp: Ưu tiên các rule có activity (total_rule > 0), sau đó theo TP giảm dần, rồi Precision giảm dần
        rows.sort(key=lambda x: (x["total_rule"] > 0, x["tp"], x["precision"]), reverse=True)

        # In Header báo cáo
        current_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        print(f"\nRULE EVAL REPORT — {current_date}")
        summary_str = f"Total labeled incidents: {total_labeled} (TP={tp_total}, FP={fp_total}, Benign={benign_total}"
        if inconclusive_total > 0:
            summary_str += f", Inconclusive={inconclusive_total})"
        else:
            summary_str += ")"
        print(summary_str)

        # Cảnh báo nếu < 10 incidents
        if total_labeled < 10:
            print(f"⚠️  Cảnh báo: Not enough data, need ≥ 10 (hiện tại có {total_labeled} incidents đã gán nhãn)\n")
        else:
            print()

        # In bảng dạng Unicode box
        print("┌─────────────────────────────┬──────────┬──────────┬────────┬────────┐")
        print("│ Rule                        │ TP       │ FP       │ Prec.  │ Recall │")
        print("├─────────────────────────────┼──────────┼──────────┼────────┼────────┤")
        for row in rows:
            rule_str = row["rule"].ljust(27)[:27]
            tp_str = str(row["tp"]).ljust(8)
            fp_str = str(row["fp"]).ljust(8)
            prec_str = f"{row['precision']:.1f}%".ljust(6)
            rec_str = f"{row['recall']:.1f}%".ljust(6)
            weak_suffix = "  ← rule yếu" if row["is_weak"] else ""
            print(f"│ {rule_str} │ {tp_str} │ {fp_str} │ {prec_str} │ {rec_str} │{weak_suffix}")
        print("└─────────────────────────────┴──────────┴──────────┴────────┴────────┘")

        # In danh sách rule yếu (< 50% precision)
        if weak_rules:
            print("\n📊 Rules with precision < 50% (candidates for tuning):")
            for w in weak_rules:
                print(f"  • {w['rule']} ({w['precision']:.1f}%) — {w['fp']} FP, chỉ {w['tp']} TP")
        else:
            print("\n📊 No active rules with precision < 50%.")

        # Export JSON nếu có cờ --json
        if json_export_path:
            export_data = {
                "date": current_date,
                "total_labeled_incidents": total_labeled,
                "label_counts": {
                    "true_positive": tp_total,
                    "false_positive": fp_total,
                    "benign": benign_total,
                    "inconclusive": inconclusive_total,
                },
                "rules": [
                    {
                        "rule": r["rule"],
                        "tp": r["tp"],
                        "fp": r["fp"],
                        "precision": round(r["precision"], 2),
                        "recall": round(r["recall"], 2),
                        "is_weak": r["is_weak"]
                    }
                    for r in rows
                ],
                "weak_rules": weak_rules
            }
            with open(json_export_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            print(f"\n[✓] Đã xuất báo cáo JSON thành công ra file: {json_export_path}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate Detection Rules Precision and Recall using Ground Truth labels")
    parser.add_argument("--json", dest="json_path", type=str, default=None, help="Export evaluation results to JSON file")
    args = parser.parse_args()

    asyncio.run(evaluate_detection_rules(json_export_path=args.json_path))


if __name__ == "__main__":
    main()
