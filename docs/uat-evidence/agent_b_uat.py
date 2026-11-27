"""UAT: Agent B on good and bad rules (isolated; no DB, no model: FP explanation disabled)."""
import asyncio, json, yaml
from app.services.ai import rule_assistant as ra
from app.services.ai.validation_service import validation_service as vs

async def no_llm(*a, **k): return None
vs._generate_llm_fp_explanation = no_llm

def compiled(**raw):
    intent, _ = ra.sanitize(raw); return ra.compile_rule(intent)[0]

RULES = {
 "C1 web app sinh shell (lựa chọn C, không điều kiện lệnh)": compiled(platform="linux", parent=["vulnerable_web/app.py"], child=["shell"]),
 "C2 web app sinh shell + nối lệnh": compiled(platform="linux", parent=["vulnerable_web/app.py"], child=["shell"], chaining=True, mitre=["T1059.004"]),
 "E1 /bin/sh + whoami (không tiến trình cha)": compiled(platform="linux", child=["sh"], command=["whoami"]),
 "X1 mọi /bin/sh (viết tay)": yaml.safe_dump({"title":"Any sh","logsource":{"category":"process_creation","product":"linux"},"detection":{"selection":{"Image|endswith":["/sh"]},"condition":"selection"},"tags":["attack.t1059.004"]}),
 "X1b mọi shell /sh /dash /bash (viết tay)": yaml.safe_dump({"title":"Any shell","logsource":{"category":"process_creation","product":"linux"},"detection":{"selection":{"Image|endswith":["/sh","/dash","/bash"]},"condition":"selection"},"tags":["attack.t1059.004"]}),
 "X2 từ ngữ CTI (viết tay)": yaml.safe_dump({"title":"Adversaries exploit","logsource":{"category":"process_creation","product":"linux"},"detection":{"selection":{"CommandLine|contains":["Adversaries","exploit"]},"condition":"selection"}}),
 "X3 product windows + điều kiện Linux (viết tay)": yaml.safe_dump({"title":"sh on windows","logsource":{"category":"process_creation","product":"windows"},"detection":{"selection":{"Image|endswith":["/bin/sh"]},"condition":"selection"},"tags":["attack.t1059.004"]}),
 "X4 field Agent không thu thập (viết tay)": yaml.safe_dump({"title":"registry","logsource":{"category":"process_creation","product":"linux"},"detection":{"selection":{"TargetObject|contains":["Run"]},"condition":"selection"}}),
 "X5 operator không hỗ trợ (viết tay)": yaml.safe_dump({"title":"base64","logsource":{"category":"process_creation","product":"linux"},"detection":{"selection":{"CommandLine|base64offset|contains":["id"]},"condition":"selection"}}),
 "X6 điều kiện tham chiếu selection không tồn tại": yaml.safe_dump({"title":"bad cond","logsource":{"category":"process_creation","product":"linux"},"detection":{"selection":{"Image|endswith":["/sh"]},"condition":"selection and filter"}}),
}
async def main():
    out = {}
    for name, text in RULES.items():
        r = await vs.validate_rule(text)
        out[name] = {"verdict": r["verdict"], "confusion": r.get("confusion"), "precision": r.get("precision"),
                     "recall": r.get("recall"), "fpr": r.get("fpr"), "f1": r.get("f1"), "reason": r["reason"],
                     "fp_samples": [s["cmdline"] for s in r.get("fp_samples", [])][:3],
                     "dataset": {k: (r.get("dataset") or {}).get(k) for k in ("total","attack","benign","by_source")},
                     "rule_yaml": text}
    print(json.dumps(out, ensure_ascii=False, indent=1))
asyncio.run(main())
