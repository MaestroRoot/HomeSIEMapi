from fastapi import APIRouter, BackgroundTasks
from pydantic import EmailStr, Field, field_validator

from app.core.email import send_contact_form
from app.schemas.common import CamelModel, Message

router = APIRouter()


class ContactRequest(CamelModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    phone: str | None = Field(default=None, max_length=30)
    topic: str = Field(min_length=3, max_length=60)
    message: str = Field(min_length=10, max_length=5000)

    @field_validator("topic")
    @classmethod
    def _valid_topic(cls, v: str) -> str:
        allowed = {
            "General inquiry",
            "Security consultation",
            "Partnership",
            "Bug report",
            "Feature request",
            "Pricing question",
            "Other",
        }
        if v not in allowed:
            raise ValueError(f"Invalid topic. Choose from: {', '.join(allowed)}")
        return v


@router.post("", response_model=Message, status_code=202)
async def submit_contact(payload: ContactRequest, background: BackgroundTasks) -> Message:
    """Receive contact form and email it to the site owner via Brevo."""
    background.add_task(
        send_contact_form,
        name=payload.name,
        email=payload.email,
        phone=payload.phone,
        topic=payload.topic,
        message=payload.message,
    )
    return Message(
        detail="Your message has been sent. We will get back to you within 24 hours.",
        code="contact_sent",
    )
