"""Detection rules: orodha, unda, badilisha, futa, library seeding."""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core.detection_library import seed_library_committed
from app.core.errors import NotFoundError
from app.crud import detection as crud
from app.schemas.common import Message
from app.schemas.detection import RuleCreate, RuleRead, RuleUpdate

router = APIRouter(prefix="/rules", tags=["detection"])


@router.get("", response_model=list[RuleRead], summary="List detection rules")
async def list_rules(user: CurrentUser, db: DbSession) -> list[RuleRead]:
    rows = await crud.list_rules(db, user.organization_id)
    return [RuleRead.model_validate(r) for r in rows]


@router.post("", response_model=RuleRead, summary="Create a detection rule")
async def create_rule(payload: RuleCreate, user: RequireAnalyst, db: DbSession) -> RuleRead:
    rule = await crud.create_rule(
        db,
        user.organization_id,
        name=payload.name,
        condition_type=payload.condition_type,
        value=payload.value,
        severity=payload.severity,
        action=payload.action,
        description=payload.description or "",
        mitre_tactic=payload.mitre_tactic,
        mitre_technique=payload.mitre_technique,
        window_seconds=payload.window_seconds,
        group_by=payload.group_by,
        threshold=payload.threshold,
    )
    return RuleRead.model_validate(rule)


@router.patch("/{rule_id}", response_model=RuleRead, summary="Update a rule")
async def update_rule(
    rule_id: uuid.UUID, payload: RuleUpdate, user: RequireAnalyst, db: DbSession
) -> RuleRead:
    rule = await crud.get_rule(db, user.organization_id, rule_id)
    if rule is None:
        raise NotFoundError("No such rule.", code="rule_not_found")
    rule = await crud.update_rule(
        db,
        rule,
        name=payload.name,
        description=payload.description,
        enabled=payload.enabled,
        value=payload.value,
        severity=payload.severity,
        action=payload.action,
        mitre_tactic=payload.mitre_tactic,
        mitre_technique=payload.mitre_technique,
        window_seconds=payload.window_seconds,
        group_by=payload.group_by,
        threshold=payload.threshold,
    )
    return RuleRead.model_validate(rule)


@router.post("/library/seed", response_model=Message, summary="Install the built-in rule library")
async def seed_library(user: RequireAnalyst, db: DbSession) -> Message:
    added = await seed_library_committed(db, user.organization_id)
    return Message(
        detail=f"{added} library rule(s) added.",
        code="library_seeded",
    )


@router.post(
    "/{rule_id}/false-positive",
    response_model=RuleRead,
    summary="Mark a rule hit as a false positive",
)
async def mark_false_positive(rule_id: uuid.UUID, user: RequireAnalyst, db: DbSession) -> RuleRead:
    rule = await crud.get_rule(db, user.organization_id, rule_id)
    if rule is None:
        raise NotFoundError("No such rule.", code="rule_not_found")
    rule.false_positives = (rule.false_positives or 0) + 1
    await db.commit()
    await db.refresh(rule)
    return RuleRead.model_validate(rule)


@router.delete("/{rule_id}", response_model=Message, summary="Delete a rule")
async def delete_rule(rule_id: uuid.UUID, user: RequireAnalyst, db: DbSession) -> Message:
    rule = await crud.get_rule(db, user.organization_id, rule_id)
    if rule is None:
        raise NotFoundError("No such rule.", code="rule_not_found")
    await crud.delete_rule(db, rule)
    return Message(detail="Rule deleted.", code="rule_deleted")
