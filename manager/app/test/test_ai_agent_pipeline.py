import pytest
import pandas as pd
import uuid
from app.services.ai.validation_service import ValidationService
from app.services.ai.harvest_service import HarvestService


@pytest.mark.asyncio
async def test_validation_service_statistical_accuracy():
    """Test Agent B statistical calculation with scikit-learn without LLM."""
    val_service = ValidationService()

    # Synthetic historical benchmark logs
    logs_data = {
        "process": [
            "explorer.exe",
            "svchost.exe",
            "powershell.exe",
            "vssadmin.exe",
            "wmic.exe",
            "chrome.exe",
            "python.exe",
            "vssadmin.exe",
        ],
        "cmdline": [
            "C:\\Windows\\explorer.exe",
            "svchost.exe -k netsvcs",
            "powershell.exe -ExecutionPolicy Bypass",
            "vssadmin.exe delete shadows /all /quiet",
            "wmic shadowcopy delete /nointeractive",
            "chrome.exe --type=renderer",
            "python.exe agent.py",
            "vssadmin.exe list shadows",
        ],
        "host": ["WIN-01"] * 8,
        "timestamp": ["2026-11-15T10:00:00Z"] * 8,
    }
    df = pd.DataFrame(logs_data)

    # Ground truth: only index 3 and 4 are malicious attacks
    ground_truth = pd.Series([0, 0, 0, 1, 1, 0, 0, 0])

    # Rule targeting volume shadow deletion
    rule_yaml = """
title: Delete Volume Shadow Copies
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process|endswith:
      - 'vssadmin.exe'
      - 'wmic.exe'
    cmdline|contains:
      - 'delete shadows'
      - 'shadowcopy delete'
  condition: selection
level: high
"""

    result = await val_service.validate_rule(
        rule_yaml=rule_yaml,
        historical_logs_df=df,
        ground_truth=ground_truth,
        fpr_threshold=0.05,
        precision_threshold=0.95
    )

    assert result["passed"] is True
    assert result["verdict"] == "PASSED"
    assert result["fpr"] == 0.0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["f1"] == 1.0
    assert result["confusion"]["tp"] == 2
    assert result["confusion"]["fp"] == 0
    assert result["confusion"]["fn"] == 0
    assert result["confusion"]["tn"] == 6
    assert len(result["fp_samples"]) == 0


@pytest.mark.asyncio
async def test_validation_service_high_fpr_rejection():
    """Test Agent B correctly flags and rejects rules with high False Positive Rate."""
    val_service = ValidationService()

    logs_data = {
        "process": ["powershell.exe"] * 10 + ["explorer.exe"] * 10,
        "cmdline": [f"powershell.exe task_{i}" for i in range(10)] + ["explorer.exe"] * 10,
        "host": ["WIN-01"] * 20,
        "timestamp": ["2026-11-15T10:00:00Z"] * 20,
    }
    df = pd.DataFrame(logs_data)
    # Only index 0 is malicious, rest are benign
    ground_truth = pd.Series([1] + [0] * 19)

    # Overly broad rule that matches all powershell.exe executions
    bad_rule_yaml = """
title: Match Any PowerShell Execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process|endswith: 'powershell.exe'
  condition: selection
level: low
"""

    result = await val_service.validate_rule(
        rule_yaml=bad_rule_yaml,
        historical_logs_df=df,
        ground_truth=ground_truth,
        fpr_threshold=0.05,
        precision_threshold=0.95
    )

    assert result["passed"] is False
    assert result["verdict"] == "FAILED"
    # 9 benign powershell executions matched -> 9 / 19 = 47.37% FPR
    assert result["fpr"] > 0.05
    assert result["confusion"]["fp"] == 9
    assert len(result["fp_samples"]) == 9
    assert "FPR" in result["reason"]


def test_harvest_service_yaml_extraction():
    """Test HarvestService YAML extractor handles Markdown code fences and tags."""
    harvest_svc = HarvestService()

    llm_markdown_output = """
Here is the Sigma rule for the threat:

<think>
Adversary uses powershell to download payload.
Technique is T1059.001.
</think>

```yaml
title: Suspicious PowerShell Download
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Detects IEX download string
tags:
  - attack.t1059.001
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process|endswith: 'powershell.exe'
    cmdline|contains: 'DownloadString'
  condition: selection
level: high
```
Hope this helps!
"""

    yaml_str, parsed = harvest_svc._extract_and_validate_yaml(llm_markdown_output)
    assert parsed is not None
    assert parsed["title"] == "Suspicious PowerShell Download"
    assert parsed["level"] == "high"

    techniques = harvest_svc._extract_mitre_techniques(parsed.get("tags", []))
    assert "T1059.001" in techniques
    assert "T1105" in techniques

