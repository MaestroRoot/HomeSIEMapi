import base64
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter
from pydantic import EmailStr, Field, field_serializer

from app.api.deps import CurrentUser, DbSession, RequireAnalyst
from app.core.email import Attachment, send_report_email
from app.core.errors import AppError, NotFoundError
from app.core.logging import get_logger
from app.crud import report_schedule as sched_crud
from app.crud import user as user_crud
from app.schemas.common import CamelModel, Message

logger = get_logger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])

ReportKind = Literal["weekly", "monthly", "executive", "incident"]
Frequency = Literal["daily", "weekly", "monthly"]


class ScheduleCreate(CamelModel):
    kind: ReportKind = "weekly"
    frequency: Frequency = "weekly"
    to_whole_team: bool = False
    recipients: list[EmailStr] = Field(default_factory=list, max_length=10)


class ScheduleRead(CamelModel):
    id: uuid.UUID
    kind: ReportKind
    frequency: Frequency
    to_whole_team: bool
    recipients: list[str]
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None = None

    @field_serializer("id")
    def _u(self, v: uuid.UUID) -> str:
        return str(v)


@router.get("/schedules", response_model=list[ScheduleRead], summary="List scheduled reports")
async def list_schedules(user: CurrentUser, db: DbSession) -> list[ScheduleRead]:
    rows = await sched_crud.list_schedules(db, user.organization_id)
    return [ScheduleRead.model_validate(s) for s in rows]


@router.post("/schedules", response_model=ScheduleRead, summary="Schedule a recurring report")
async def create_schedule(payload: ScheduleCreate, user: RequireAnalyst, db: DbSession) -> ScheduleRead:
    sched = await sched_crud.create_schedule(
        db,
        user.organization_id,
        kind=payload.kind,
        frequency=payload.frequency,
        to_whole_team=payload.to_whole_team,
        recipients=[str(r).lower() for r in payload.recipients],
    )
    return ScheduleRead.model_validate(sched)


@router.delete("/schedules/{schedule_id}", response_model=Message, summary="Delete a schedule")
async def delete_schedule(schedule_id: uuid.UUID, user: RequireAnalyst, db: DbSession) -> Message:
    sched = await sched_crud.get_schedule(db, user.organization_id, schedule_id)
    if sched is None:
        raise NotFoundError("No such schedule.", code="schedule_not_found")
    await sched_crud.delete_schedule(db, sched)
    return Message(detail="Schedule removed.", code="schedule_deleted")

TITLES: dict[str, str] = {
    "weekly": "Weekly security report",
    "monthly": "Monthly security report",
    "executive": "Executive summary",
    "incident": "Incident report",
}


class ReportSection(CamelModel):
    heading: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1, max_length=4000)


class ReportEmailRequest(CamelModel):
    kind: ReportKind = "weekly"
    period: str = Field(min_length=3, max_length=60)
    #: Wapokeaji. Wakiwa hawapo, inakwenda kwa mwenye kuiomba.
    recipients: list[EmailStr] = Field(default_factory=list, max_length=10)
    #: Ikiwa haipo, inakwenda kwa wanachama wote wa organization.
    to_whole_team: bool = False
    sections: list[ReportSection] = Field(default_factory=list, max_length=20)
    #: Faili tayari imefanywa base64 na frontend (PDF / Excel / CSV).
    attachment_name: str | None = Field(default=None, max_length=120)
    attachment_base64: str | None = None


class ReportEmailResponse(CamelModel):
    sent_to: list[str]
    failed: list[str]
    attached: bool


def _render(sections: list[ReportSection]) -> str:
    if not sections:
        return "<p>No findings were recorded for this period.</p>"

    parts = []
    for section in sections:
        body = section.body.replace("\n", "<br />")
        parts.append(
            f'<h2 style="font-size:15px;color:#0f172a;margin:20px 0 6px;">{section.heading}</h2>'
            f'<p style="margin:0;">{body}</p>'
        )
    return "".join(parts)


@router.post("/email", response_model=ReportEmailResponse, summary="Email a report through Brevo")
async def email_report(
    payload: ReportEmailRequest,
    user: RequireAnalyst,
    db: DbSession,
) -> ReportEmailResponse:
    """Analyst or above. Sends the report to the chosen recipients."""
    recipients: list[str] = [str(email).lower() for email in payload.recipients]

    if payload.to_whole_team:
        members, _ = await user_crud.list_by_organization(db, user.organization_id, limit=200)
        recipients.extend(member.email for member in members if member.is_active)

    if not recipients:
        recipients = [user.email]

    # Kuondoa marudio bila kubadilisha mpangilio.
    recipients = list(dict.fromkeys(recipients))

    attachment: Attachment | None = None
    if payload.attachment_base64:
        if not payload.attachment_name:
            raise AppError("An attachment needs a filename.", code="attachment_name_missing")
        try:
            base64.b64decode(payload.attachment_base64, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise AppError("The attachment is not valid base64.", code="attachment_invalid") from exc
        attachment = Attachment(
            name=payload.attachment_name, content=payload.attachment_base64
        )

    title = TITLES.get(payload.kind, "Security report")
    summary = _render(payload.sections)

    sent: list[str] = []
    failed: list[str] = []
    for email in recipients:
        ok = await send_report_email(
            to_email=email,
            to_name=None,
            title=title,
            period=payload.period,
            summary_html=summary,
            attachment=attachment,
        )
        (sent if ok else failed).append(email)

    logger.info(
        "Report '%s' imetumwa kwa %s/%s wapokeaji na %s",
        title,
        len(sent),
        len(recipients),
        user.email,
    )
    return ReportEmailResponse(sent_to=sent, failed=failed, attached=attachment is not None)


@router.get("/test", response_model=Message, summary="Send yourself a test email")
async def send_test(user: CurrentUser) -> Message:
    """Njia ya haraka ya kuthibitisha Brevo imesetiwa sawa."""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ok = await send_report_email(
        to_email=user.email,
        to_name=user.name,
        title="Email delivery test",
        period=stamp,
        summary_html="<p>If you are reading this, Brevo is wired up correctly.</p>",
    )
    if not ok:
        raise AppError(
            "Brevo rejected the message or is not configured. Check BREVO_API_KEY and "
            "that the sender address is verified in Brevo.",
            code="email_failed",
        )
    return Message(detail=f"A test email is on its way to {user.email}.", code="email_sent")
