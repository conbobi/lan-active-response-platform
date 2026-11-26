import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Request, Depends, Query, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.rule_candidate import RuleCandidate
from app.models.rule_version import RuleVersion
from app.services.ai.harvest_service import GenerationError, harvest_service
from app.services.ai.validation_service import validation_service

logger = logging.getLogger("larp.api.rules")
router = APIRouter()


# ── Schemas ─────────────────────────────────────────────────────────────
class HarvestRequest(BaseModel):
    cti_text: str = Field(..., description="Threat intelligence report or IOC text")
    analyst_id: Optional[str] = Field("soc_analyst", description="Analyst identifier")


class RejectRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Reason for rejection")
    analyst_id: Optional[str] = Field("soc_analyst", description="Analyst identifier")


class ActivateRequest(BaseModel):
    analyst_id: Optional[str] = Field("soc_analyst", description="Analyst identifier")


class ValidateRequest(BaseModel):
    fpr_threshold: Optional[float] = Field(0.05, description="FPR threshold (default 5%)")
    precision_threshold: Optional[float] = Field(0.95, description="Precision threshold (default 95%)")


class SuggestExclusionRequest(BaseModel):
    rule_yaml: Optional[str] = None
    fp_samples: Optional[List[Dict[str, Any]]] = None


class UpdateRuleRequest(BaseModel):
    rule_name: Optional[str] = None
    rule_yaml: Optional[str] = None
    severity: Optional[str] = None
    notes: Optional[str] = None
    analyst_id: Optional[str] = "soc_analyst"


# ── Endpoints ───────────────────────────────────────────────────────────

def engine_support(rule_yaml: str) -> tuple[bool, str]:
    import yaml
    from app.services.rule_engine import RuleEngine
    try:
        parsed = yaml.safe_load(rule_yaml or "")
    except yaml.YAMLError as exc:
        return False, f"YAML không hợp lệ: {exc.__class__.__name__}"
    return RuleEngine.check_sigma_support(parsed)


def validation_summary(result: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not result:
        return None
    return {key: result.get(key) for key in ("verdict", "passed", "reason", "engine_supported", "dataset", "confusion")}


@router.post("/harvest")
async def harvest_rule(
    body: HarvestRequest
):
    """
    POST /api/rules/harvest
    Agent A: Generate Sigma rule from CTI report and save as pending candidate.
    Uses non-blocking database session to prevent connection starvation.
    """
    try:
        if not body.cti_text or not body.cti_text.strip():
            return {"error": "cti_text cannot be empty"}

        candidate = await harvest_service.harvest_from_cti(
            cti_text=body.cti_text.strip(),
            analyst_id=body.analyst_id or "soc_analyst",
            db_session=None
        )

        return {
            "rule_id": str(candidate.id),
            "rule_name": candidate.rule_name,
            "rule_yaml": candidate.rule_yaml,
            "status": candidate.status,
            "severity": candidate.severity,
            "mitre_techniques": candidate.mitre_techniques or [],
            "source": candidate.source,
            "created_at": candidate.created_at.isoformat() if candidate.created_at else None
        }
    except GenerationError as exc:
        raise HTTPException(status_code=502, detail=f"Sigma generation failed: {exc}") from exc
    except Exception as e:
        logger.error(f"Error in /harvest: {e}", exc_info=True)
        return {"error": f"Failed to harvest rule: {str(e)}"}


@router.put("/{rule_id}")
async def update_rule_endpoint(
    rule_id: str,
    body: UpdateRuleRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    PUT /api/rules/{rule_id}
    Update candidate rule name, YAML content, severity or notes, and bump version.
    """
    try:
        try:
            target_uuid = uuid.UUID(rule_id)
        except ValueError:
            return {"error": f"Invalid rule_id UUID: {rule_id}"}

        stmt = select(RuleCandidate).where(RuleCandidate.id == target_uuid)
        result = await db.execute(stmt)
        candidate = result.scalar_one_or_none()

        if not candidate:
            return {"error": f"Rule candidate '{rule_id}' not found"}

        if body.rule_name is not None and body.rule_name.strip():
            candidate.rule_name = body.rule_name.strip()
        if body.severity is not None and body.severity.strip():
            candidate.severity = body.severity.strip().lower()
        if body.notes is not None:
            candidate.notes = body.notes

        yaml_changed = False
        if body.rule_yaml is not None and body.rule_yaml.strip() != candidate.rule_yaml:
            candidate.rule_yaml = body.rule_yaml.strip()
            yaml_changed = True
            # Changed YAML is unvalidated: it must not keep running or stay approved.
            was_active = candidate.status == "active"
            if candidate.status in ("validated", "active", "rejected"):
                candidate.status = "pending"
                candidate.validation_result = None
                candidate.fpr = candidate.precision = candidate.recall = None
                candidate.validated_at = None
                candidate.activated_at = None
            if was_active:
                from app.services.rule_engine import rule_engine
                rule_engine.invalidate_cache()

            try:
                import yaml
                parsed = yaml.safe_load(candidate.rule_yaml)
                if isinstance(parsed, dict) and "tags" in parsed:
                    candidate.mitre_techniques = harvest_service._extract_mitre_techniques(parsed["tags"])
            except Exception:
                pass

            v_stmt = select(func.max(RuleVersion.version_number)).where(RuleVersion.rule_candidate_id == target_uuid)
            v_res = await db.execute(v_stmt)
            curr_max = v_res.scalar() or 1
            new_version = RuleVersion(
                rule_candidate_id=target_uuid,
                version_number=curr_max + 1,
                yaml_content=candidate.rule_yaml,
                change_reason=f"Analyst manual update ({body.analyst_id or 'soc_analyst'})",
                created_at=datetime.now(timezone.utc),
                created_by=body.analyst_id or "soc_analyst"
            )
            db.add(new_version)

        await db.commit()
        await db.refresh(candidate)

        return {
            "rule_id": str(candidate.id),
            "rule_name": candidate.rule_name,
            "rule_yaml": candidate.rule_yaml,
            "severity": candidate.severity,
            "status": candidate.status,
            "mitre_techniques": candidate.mitre_techniques or [],
            "yaml_changed": yaml_changed,
            "message": "Rule candidate updated successfully."
        }
    except Exception as e:
        logger.error(f"Error updating rule {rule_id}: {e}", exc_info=True)
        return {"error": f"Failed to update rule: {str(e)}"}


@router.post("/{rule_id}/validate")
async def validate_rule_endpoint(
    rule_id: str,
    body: Optional[ValidateRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    POST /api/rules/{rule_id}/validate
    Agent B: Statistically validate rule against historical logs.
    """
    try:
        try:
            target_uuid = uuid.UUID(rule_id)
        except ValueError:
            return {"error": f"Invalid rule_id UUID: {rule_id}"}

        stmt = select(RuleCandidate).where(RuleCandidate.id == target_uuid)
        result = await db.execute(stmt)
        candidate = result.scalar_one_or_none()

        if not candidate:
            return {"error": f"Rule candidate '{rule_id}' not found"}

        fpr_th = body.fpr_threshold if body and body.fpr_threshold is not None else 0.05
        prec_th = body.precision_threshold if body and body.precision_threshold is not None else 0.95

        supported, support_reason = engine_support(candidate.rule_yaml)
        if not supported:
            # A rule the Detection Engine cannot execute as written is not deployable; its metrics
            # would describe semantics that never run.
            candidate.validation_result = {"passed": False, "verdict": "UNSUPPORTED_BY_ENGINE",
                                           "reason": support_reason, "engine_supported": False}
            candidate.fpr = candidate.precision = candidate.recall = None
            candidate.validated_at = datetime.now(timezone.utc)
            candidate.status = "rejected"
            candidate.notes = f"Detection Engine không hỗ trợ: {support_reason}"
            await db.commit()
            await db.refresh(candidate)
            return {"rule_id": str(candidate.id), "rule_name": candidate.rule_name, "status": candidate.status,
                    "fpr": None, "precision": None, "recall": None,
                    "validation_result": candidate.validation_result}

        val_result = await validation_service.validate_rule(
            rule_yaml=candidate.rule_yaml,
            fpr_threshold=fpr_th,
            precision_threshold=prec_th,
            db_session=db,
            cti_text=candidate.harvest_prompt or "",
        )

        val_result["engine_supported"] = True
        candidate.validation_result = val_result
        candidate.fpr = val_result.get("fpr")
        candidate.precision = val_result.get("precision")
        candidate.recall = val_result.get("recall")
        candidate.false_positive_samples = val_result.get("fp_samples", [])
        candidate.validated_at = datetime.now(timezone.utc)

        if val_result.get("passed"):
            candidate.status = "validated"
        elif val_result.get("verdict") == "INCONCLUSIVE":
            # Not the rule's fault: the evaluation set has no matching positive sample.
            candidate.status = "pending"
            candidate.notes = f"Kiểm định chưa kết luận: {val_result.get('reason')}"
        else:
            candidate.status = "rejected"
            candidate.notes = f"Kiểm định thất bại: {val_result.get('reason')}"

        await db.commit()
        await db.refresh(candidate)

        return {
            "rule_id": str(candidate.id),
            "rule_name": candidate.rule_name,
            "status": candidate.status,
            "fpr": candidate.fpr,
            "precision": candidate.precision,
            "recall": candidate.recall,
            "validation_result": val_result
        }
    except Exception as e:
        logger.error(f"Error in /validate: {e}", exc_info=True)
        return {"error": f"Failed to validate rule: {str(e)}"}


@router.post("/{rule_id}/activate")
async def activate_rule(
    request: Request,
    rule_id: str,
    body: Optional[ActivateRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    POST /api/rules/{rule_id}/activate
    Activate a validated rule. Rejects activation if rule is not in 'validated' status.
    """
    try:
        try:
            target_uuid = uuid.UUID(rule_id)
        except ValueError:
            return {"error": f"Invalid rule_id UUID: {rule_id}"}

        stmt = select(RuleCandidate).where(RuleCandidate.id == target_uuid)
        result = await db.execute(stmt)
        candidate = result.scalar_one_or_none()

        if not candidate:
            return {"error": f"Rule candidate '{rule_id}' not found"}

        if candidate.status != "validated":
            return {
                "error": f"Không thể kích hoạt rule ở trạng thái '{candidate.status}'. Chỉ rule đã kiểm định đạt mới được kích hoạt."
            }
        if not (candidate.validation_result or {}).get("passed"):
            return {"error": "Rule chưa có kết quả kiểm định đạt; hãy kiểm định lại trước khi kích hoạt."}
        supported, support_reason = engine_support(candidate.rule_yaml)
        if not supported:
            return {"error": f"Detection Engine không hỗ trợ rule này: {support_reason}"}

        candidate.status = "active"
        candidate.activated_at = datetime.now(timezone.utc)
        candidate.approved_by = request.state.operator

        await db.commit()
        await db.refresh(candidate)

        from app.services.rule_engine import rule_engine
        rule_engine.invalidate_cache()

        return {
            "rule_id": str(candidate.id),
            "status": candidate.status,
            "activated_at": candidate.activated_at.isoformat(),
            "engine_supported": True,
            "message": "Rule đã được nạp vào Detection Engine của Manager."
        }
    except Exception as e:
        logger.error(f"Error in /activate: {e}", exc_info=True)
        return {"error": f"Failed to activate rule: {str(e)}"}


@router.post("/{rule_id}/reject")
async def reject_rule(
    rule_id: str,
    body: Optional[RejectRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    POST /api/rules/{rule_id}/reject
    Reject a candidate rule with an analyst reason.
    """
    try:
        try:
            target_uuid = uuid.UUID(rule_id)
        except ValueError:
            return {"error": f"Invalid rule_id UUID: {rule_id}"}

        stmt = select(RuleCandidate).where(RuleCandidate.id == target_uuid)
        result = await db.execute(stmt)
        candidate = result.scalar_one_or_none()

        if not candidate:
            return {"error": f"Rule candidate '{rule_id}' not found"}

        candidate.status = "rejected"
        if body and body.reason:
            candidate.notes = body.reason
        if body and body.analyst_id:
            candidate.approved_by = body.analyst_id

        await db.commit()
        await db.refresh(candidate)

        return {
            "rule_id": str(candidate.id),
            "status": candidate.status,
            "notes": candidate.notes,
            "message": "Rule marked as rejected."
        }
    except Exception as e:
        logger.error(f"Error in /reject: {e}", exc_info=True)
        return {"error": f"Failed to reject rule: {str(e)}"}


@router.post("/{rule_id}/disable")
async def disable_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    POST /api/rules/{rule_id}/disable
    Disable an active or validated rule.
    """
    try:
        try:
            target_uuid = uuid.UUID(rule_id)
        except ValueError:
            return {"error": f"Invalid rule_id UUID: {rule_id}"}

        stmt = select(RuleCandidate).where(RuleCandidate.id == target_uuid)
        result = await db.execute(stmt)
        candidate = result.scalar_one_or_none()

        if not candidate:
            return {"error": f"Rule candidate '{rule_id}' not found"}

        candidate.status = "disabled"
        candidate.disabled_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(candidate)

        from app.services.rule_engine import rule_engine
        rule_engine.invalidate_cache()

        return {
            "rule_id": str(candidate.id),
            "status": candidate.status,
            "disabled_at": candidate.disabled_at.isoformat(),
            "message": "Rule disabled successfully."
        }
    except Exception as e:
        logger.error(f"Error in /disable: {e}", exc_info=True)
        return {"error": f"Failed to disable rule: {str(e)}"}


@router.get("")
async def list_rules(
    status: Optional[str] = Query(None, description="Filter by status (pending, validated, rejected, active, disabled)"),
    source: Optional[str] = Query(None, description="Filter by source (ai_harvest, human)"),
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    search: Optional[str] = Query(None, description="Search in rule_name"),
    sort_by: Optional[str] = Query("created_at", description="Sort column (created_at, fpr, precision, rule_name)"),
    sort_desc: Optional[bool] = Query(True, description="Sort descending"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    GET /api/rules
    List rule candidates with status/source/severity filters and pagination.
    """
    try:
        stmt = select(RuleCandidate)

        if status and status.lower() != "all":
            stmt = stmt.where(RuleCandidate.status == status.lower())
        if source and source.lower() != "all":
            stmt = stmt.where(RuleCandidate.source == source.lower())
        if severity and severity.lower() != "all":
            stmt = stmt.where(RuleCandidate.severity == severity.lower())
        if search and search.strip():
            stmt = stmt.where(RuleCandidate.rule_name.ilike(f"%{search.strip()}%"))

        # Count total
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_res = await db.execute(count_stmt)
        total = count_res.scalar() or 0

        # Sorting
        sort_col = getattr(RuleCandidate, sort_by, RuleCandidate.created_at)
        order_clause = desc(sort_col) if sort_desc else asc(sort_col)
        stmt = stmt.order_by(order_clause).offset(offset).limit(limit)

        result = await db.execute(stmt)
        rules = result.scalars().all()

        items = []
        for r in rules:
            items.append({
                "id": str(r.id),
                "rule_name": r.rule_name,
                "rule_yaml": r.rule_yaml,
                "source": r.source,
                "status": r.status,
                "severity": r.severity,
                "mitre_techniques": r.mitre_techniques or [],
                "fpr": r.fpr,
                "precision": r.precision,
                "recall": r.recall,
                "model_generated": r.model_generated,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "validated_at": r.validated_at.isoformat() if r.validated_at else None,
                "activated_at": r.activated_at.isoformat() if r.activated_at else None,
                "disabled_at": r.disabled_at.isoformat() if r.disabled_at else None,
                "created_by": r.created_by,
                "approved_by": r.approved_by,
                "notes": r.notes,
                "validation": validation_summary(r.validation_result),
            })

        return {
            "total": total,
            "items": items,
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        logger.error(f"Error in /rules list: {e}", exc_info=True)
        return {"error": f"Failed to list rules: {str(e)}"}


@router.get("/{rule_id}")
async def get_rule_detail(
    rule_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    GET /api/rules/{rule_id}
    Get rule candidate detail, validation result, and version history.
    """
    try:
        try:
            target_uuid = uuid.UUID(rule_id)
        except ValueError:
            return {"error": f"Invalid rule_id UUID: {rule_id}"}

        stmt = select(RuleCandidate).where(RuleCandidate.id == target_uuid)
        result = await db.execute(stmt)
        candidate = result.scalar_one_or_none()

        if not candidate:
            return {"error": f"Rule candidate '{rule_id}' not found"}

        # Fetch versions
        v_stmt = select(RuleVersion).where(RuleVersion.rule_candidate_id == target_uuid).order_by(RuleVersion.version_number.desc())
        v_res = await db.execute(v_stmt)
        versions = v_res.scalars().all()

        v_list = []
        for v in versions:
            v_list.append({
                "id": v.id,
                "version_number": v.version_number,
                "yaml_content": v.yaml_content,
                "change_reason": v.change_reason,
                "created_at": v.created_at.isoformat() if v.created_at else None,
                "created_by": v.created_by
            })

        return {
            "id": str(candidate.id),
            "rule_name": candidate.rule_name,
            "rule_yaml": candidate.rule_yaml,
            "source": candidate.source,
            "status": candidate.status,
            "severity": candidate.severity,
            "mitre_techniques": candidate.mitre_techniques or [],
            "fpr": candidate.fpr,
            "precision": candidate.precision,
            "recall": candidate.recall,
            "validation_result": candidate.validation_result,
            "false_positive_samples": candidate.false_positive_samples or [],
            "model_generated": candidate.model_generated,
            "harvest_prompt": candidate.harvest_prompt,
            "created_at": candidate.created_at.isoformat() if candidate.created_at else None,
            "validated_at": candidate.validated_at.isoformat() if candidate.validated_at else None,
            "activated_at": candidate.activated_at.isoformat() if candidate.activated_at else None,
            "disabled_at": candidate.disabled_at.isoformat() if candidate.disabled_at else None,
            "created_by": candidate.created_by,
            "approved_by": candidate.approved_by,
            "notes": candidate.notes,
            "versions": v_list
        }
    except Exception as e:
        logger.error(f"Error in /rules/{rule_id}: {e}", exc_info=True)
        return {"error": f"Failed to get rule: {str(e)}"}


@router.get("/{rule_id}/samples")
async def get_rule_samples(
    rule_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    GET /api/rules/{rule_id}/samples
    Returns FP and FN sample logs from validation.
    """
    try:
        try:
            target_uuid = uuid.UUID(rule_id)
        except ValueError:
            return {"error": f"Invalid rule_id UUID: {rule_id}"}

        stmt = select(RuleCandidate).where(RuleCandidate.id == target_uuid)
        result = await db.execute(stmt)
        candidate = result.scalar_one_or_none()

        if not candidate:
            return {"error": f"Rule candidate '{rule_id}' not found"}

        fp_samples = candidate.false_positive_samples or []
        fn_samples = []
        if candidate.validation_result and isinstance(candidate.validation_result, dict):
            fn_samples = candidate.validation_result.get("fn_samples", [])

        return {
            "rule_id": str(candidate.id),
            "rule_name": candidate.rule_name,
            "fp_samples": fp_samples,
            "fn_samples": fn_samples
        }
    except Exception as e:
        logger.error(f"Error in /samples: {e}", exc_info=True)
        return {"error": f"Failed to get samples: {str(e)}"}


@router.post("/{rule_id}/suggest-exclusion")
async def suggest_rule_exclusion(
    rule_id: str,
    body: Optional[SuggestExclusionRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    POST /api/rules/{rule_id}/suggest-exclusion
    Ask AI to analyze FP samples and suggest exclusion YAML filter condition.
    """
    try:
        try:
            target_uuid = uuid.UUID(rule_id)
        except ValueError:
            return {"error": f"Invalid rule_id UUID: {rule_id}"}

        stmt = select(RuleCandidate).where(RuleCandidate.id == target_uuid)
        result = await db.execute(stmt)
        candidate = result.scalar_one_or_none()

        if not candidate:
            return {"error": f"Rule candidate '{rule_id}' not found"}

        yaml_content = body.rule_yaml if body and body.rule_yaml else candidate.rule_yaml
        fp_samples = body.fp_samples if body and body.fp_samples else (candidate.false_positive_samples or [])

        explanation = await validation_service._generate_llm_fp_explanation(
            rule_yaml=yaml_content,
            fp_samples=fp_samples[:5],
            fpr=candidate.fpr or 0.1
        )

        return {
            "rule_id": str(candidate.id),
            "suggestion": explanation or "No specific exclusion condition generated."
        }
    except Exception as e:
        logger.error(f"Error in /suggest-exclusion: {e}", exc_info=True)
        return {"error": f"Failed to suggest exclusion: {str(e)}"}

