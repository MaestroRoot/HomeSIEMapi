"""Kutuma email kupitia Brevo (transactional API v3).

Sender ni `BREVO_SENDER_EMAIL`, ambayo LAZIMA iwe imethibitishwa kwenye Brevo
(Senders & IP → Senders). Bila kuthibitishwa Brevo inakataa kwa 400.

Kila function inarudisha `bool`: True ikiwa Brevo imekubali. Hakuna
function inayorusha exception kwa mtumiaji, kushindwa kutuma email hakupaswi
kuangusha signup wala kubadilisha kifurushi.
"""

from dataclasses import dataclass

import httpx

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_BREVO_URL = "https://api.brevo.com/v3/smtp/email"
_TIMEOUT = 15.0

BRAND = "HomeSIEM"
ACCENT = "#2563eb"


@dataclass(frozen=True)
class Attachment:
    name: str
    #: base64 ya faili nzima.
    content: str


def _shell(title: str, body_html: str, footer: str | None = None) -> str:
    """Template moja inayotumika na email zote ili zionekane sawa."""
    return f"""\
<!doctype html>
<html>
  <body style="margin:0;padding:24px;background:#f1f5f9;font-family:'Segoe UI',Arial,sans-serif;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
      <tr><td align="center">
        <table role="presentation" width="100%" style="max-width:560px;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #e2e8f0;">
          <tr>
            <td style="background:{ACCENT};padding:20px 28px;">
              <span style="color:#ffffff;font-size:18px;font-weight:800;letter-spacing:-.2px;">{BRAND}</span>
            </td>
          </tr>
          <tr>
            <td style="padding:28px;">
              <h1 style="margin:0 0 14px;font-size:19px;color:#0f172a;">{title}</h1>
              <div style="font-size:14px;line-height:1.65;color:#334155;">{body_html}</div>
            </td>
          </tr>
          <tr>
            <td style="padding:16px 28px;background:#f8fafc;border-top:1px solid #e2e8f0;font-size:12px;color:#64748b;">
              {footer or f"You are receiving this because you have a {BRAND} account."}
            </td>
          </tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>"""


async def send_email(
    *,
    to_email: str,
    to_name: str | None,
    subject: str,
    html: str,
    text: str | None = None,
    attachments: list[Attachment] | None = None,
    tags: list[str] | None = None,
) -> bool:
    if not settings.brevo_api_key:
        logger.warning("BREVO_API_KEY haipo, email '%s' kwenda %s haijatumwa.", subject, to_email)
        return False

    payload: dict[str, object] = {
        "sender": {
            "email": settings.brevo_sender_email,
            "name": settings.brevo_sender_name,
        },
        "to": [{"email": to_email, **({"name": to_name} if to_name else {})}],
        "subject": subject,
        "htmlContent": html,
    }
    if text:
        payload["textContent"] = text
    if attachments:
        payload["attachment"] = [{"name": a.name, "content": a.content} for a in attachments]
    if tags:
        payload["tags"] = tags

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as http:
            response = await http.post(
                _BREVO_URL,
                json=payload,
                headers={
                    "api-key": settings.brevo_api_key,
                    "accept": "application/json",
                    "content-type": "application/json",
                },
            )
    except httpx.HTTPError as exc:
        logger.error("Brevo haipatikani: %s", exc)
        return False

    if response.status_code >= 300:
        # Brevo inaeleza vizuri kwa nini imekataa, hii ni muhimu kwenye logs.
        logger.error("Brevo imekataa (%s): %s", response.status_code, response.text[:400])
        return False

    logger.info("Email '%s' imetumwa kwenda %s", subject, to_email)
    return True


# --- Email zenyewe ---------------------------------------------------------


async def send_welcome_email(*, to_email: str, name: str) -> bool:
    dashboard = f"{settings.app_public_url.rstrip('/')}/dashboard"
    html = _shell(
        f"Welcome to {BRAND}, {name}",
        f"""
        <p>Your Home SOC is ready. You are on the <strong>Free</strong> plan, which
        covers two devices, basic alerts and your Home Security Score.</p>
        <p>Three things worth doing first:</p>
        <ol>
          <li>Register your first device.</li>
          <li>Point a log source at it.</li>
          <li>Open the dashboard and watch the first events land.</li>
        </ol>
        <p style="margin:26px 0;">
          <a href="{dashboard}" style="background:{ACCENT};color:#ffffff;text-decoration:none;
             padding:11px 22px;border-radius:8px;font-weight:700;display:inline-block;">
            Open your dashboard
          </a>
        </p>
        <p style="color:#64748b;">Only monitor networks and systems you are authorised to test.</p>
        """,
    )
    return await send_email(
        to_email=to_email,
        to_name=name,
        subject=f"Welcome to {BRAND}",
        html=html,
        text=f"Welcome to {BRAND}, {name}. Your dashboard: {dashboard}",
        tags=["welcome"],
    )


async def send_password_reset_otp(*, to_email: str, name: str | None, code: str) -> bool:
    minutes = settings.otp_ttl_minutes
    html = _shell(
        "Your password reset code",
        f"""
        <p>Use this code to reset your {BRAND} password. It expires in
        {minutes} minutes and can be used once.</p>
        <p style="margin:24px 0;text-align:center;">
          <span style="display:inline-block;background:#f1f5f9;border:1px solid #e2e8f0;
                border-radius:10px;padding:14px 26px;font-family:monospace;font-size:30px;
                font-weight:700;letter-spacing:9px;color:#0f172a;">{code}</span>
        </p>
        <p>If you did not ask to reset your password, ignore this email. Your
        password stays as it is, and it may be worth checking who else has access
        to this mailbox.</p>
        """,
        footer="Never share this code. Nobody from HomeSIEM will ask you for it.",
    )
    return await send_email(
        to_email=to_email,
        to_name=name,
        subject=f"{code} is your {BRAND} reset code",
        html=html,
        text=f"Your {BRAND} password reset code is {code}. It expires in {minutes} minutes.",
        tags=["password-reset"],
    )


async def send_mfa_otp(*, to_email: str, name: str | None, code: str) -> bool:
    """Send MFA verification OTP for login."""
    minutes = settings.otp_ttl_minutes
    html = _shell(
        "Your login verification code",
        f"""
        <p>Someone is signing into your {BRAND} account. Use this code to
        complete your login. It expires in {minutes} minutes.</p>
        <p style="margin:24px 0;text-align:center;">
          <span style="display:inline-block;background:#f1f5f9;border:1px solid #e2e8f0;
                border-radius:10px;padding:14px 26px;font-family:monospace;font-size:30px;
                font-weight:700;letter-spacing:9px;color:#0f172a;">{code}</span>
        </p>
        <p>If you did not try to sign in, someone else may have access to your
        email. Consider changing your password.</p>
        """,
        footer="Never share this code. Nobody from HomeSIEM will ask you for it.",
    )
    return await send_email(
        to_email=to_email,
        to_name=name,
        subject=f"{code} is your {BRAND} login code",
        html=html,
        text=f"Your {BRAND} login code is {code}. It expires in {minutes} minutes.",
        tags=["mfa-otp"],
    )


async def send_invitation_email(
    *, to_email: str, inviter_name: str, organization: str, role: str, accept_url: str
) -> bool:
    html = _shell(
        f"{inviter_name} invited you to {organization}",
        f"""
        <p><strong>{inviter_name}</strong> has invited you to join the
        <strong>{organization}</strong> workspace on {BRAND} as
        <strong>{role}</strong>.</p>
        <p style="margin:26px 0;">
          <a href="{accept_url}" style="background:{ACCENT};color:#ffffff;text-decoration:none;
             padding:11px 22px;border-radius:8px;font-weight:700;display:inline-block;">
            Accept the invitation
          </a>
        </p>
        <p style="color:#64748b;">Create your account with this same email address so the
        invitation matches. If you were not expecting this, you can ignore it.</p>
        """,
        footer="This invitation expires in 7 days.",
    )
    return await send_email(
        to_email=to_email,
        to_name=None,
        subject=f"{inviter_name} invited you to {organization} on {BRAND}",
        html=html,
        text=f"{inviter_name} invited you to {organization} as {role}. Accept: {accept_url}",
        tags=["invitation"],
    )


async def send_report_email(
    *,
    to_email: str,
    to_name: str | None,
    title: str,
    period: str,
    summary_html: str,
    attachment: Attachment | None = None,
) -> bool:
    html = _shell(
        title,
        f"""
        <p style="color:#64748b;margin-top:0;">Reporting period: {period}</p>
        {summary_html}
        {"<p style='color:#64748b;'>The full report is attached.</p>" if attachment else ""}
        """,
        footer=f"Generated by {BRAND}.",
    )
    return await send_email(
        to_email=to_email,
        to_name=to_name,
        subject=f"{title}, {period}",
        html=html,
        attachments=[attachment] if attachment else None,
        tags=["report"],
    )
