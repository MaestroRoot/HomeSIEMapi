"""Kufanya akaunti ya admin (ADMIN_EMAIL) ipo Firebase + DB.

Inaunda/kuweka:
  - Firebase user: `ADMIN_EMAIL` / `ADMIN_PASSWORD` (huhitajiki kama ilishawapita).
  - DB user: role=ADMIN + org yake (inahitajika kwa foreign key `organization_id`).

Run:
    .venv/Scripts/python.exe -m alembic upgrade head
    .venv/Scripts/python.exe scripts/create_admin.py

INAHITAJI service account (FIREBASE_CREDENTIALS_FILE iko tayari kwenye .env).
Migration lazima iendelee kabla ya script (enum `user_role` inapaswa kuwa na
'admin' tayari). Hii ni command ya server, isiwe mtu asimame. Unaweza
kuiendesha tena wakati wowote kurejesha password ya admin kwa `babyboy@1922`
(au ADMIN_PASSWORD).
"""

import asyncio
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy import select  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.firebase import admin_available, init_firebase  # noqa: E402
from app.core.plans import DEFAULT_PLAN  # noqa: E402
from app.db.session import AsyncSessionLocal, dispose_engine  # noqa: E402
from app.models.enums import Role, SubscriptionStatus  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.models.subscription import Subscription  # noqa: E402
from app.models.user import User  # noqa: E402

ADMIN_EMAIL = settings.admin_email_lower
ADMIN_PASSWORD = settings.admin_password
ADMIN_NAME = "Platform Admin"


async def _seed_firebase() -> None:
    from firebase_admin import auth as fb_auth

    try:
        record = fb_auth.get_user_by_email(ADMIN_EMAIL)
        print(f"[Firebase] {ADMIN_EMAIL} tayari ipo (uid={record.uid}), tunasasisha password...")
        fb_auth.update_user(record.uid, password=ADMIN_PASSWORD)
        fb_auth.revoke_refresh_tokens(record.uid)
        print("[Firebase] Password imesasishwa na refresh tokens zimefutwa.")
    except fb_auth.UserNotFoundError:
        record = fb_auth.create_user(
            email=ADMIN_EMAIL,
            password=ADMIN_PASSWORD,
            display_name=ADMIN_NAME,
            email_verified=True,
        )
        print(f"[Firebase] Akaunti mpya imeundwa (uid={record.uid}).")
    except Exception as exc:  # pragma: no cover - token yoyote mbovu
        print(f"[Firebase] KUSHINDWA: {exc}")
        raise SystemExit(1) from exc


async def _seed_db() -> None:
    async with AsyncSessionLocal() as db:
        user = (
            await db.execute(select(User).where(User.email == ADMIN_EMAIL))
        ).scalar_one_or_none()

        if user is None:
            org = Organization(name="HomeSIEM Admin", slug="homesiem-admin")
            org.subscription = Subscription(
                plan=DEFAULT_PLAN,
                status=SubscriptionStatus.ACTIVE,
                price_tzs=0,
                currency="TZS",
                auto_renew=False,
            )
            user = User(
                firebase_uid="__admin_seed__",
                email=ADMIN_EMAIL,
                name=ADMIN_NAME,
                role=Role.ADMIN,
                plan=DEFAULT_PLAN,
                email_verified=True,
                organization=org,
            )
            db.add(org)
            db.add(user)
            await db.commit()
            print(f"[DB] Akaunti ya admin imeundwa (id={user.id}).")
        else:
            user.role = Role.ADMIN
            if user.organization is None:
                print("[DB] ADMIN haiwezi kuwa bila org.")
                await db.rollback()
                raise SystemExit(1)
            await db.commit()
            print(f"[DB] role imesasishwa hadi ADMIN kwa {user.email}.")
            print(f"[DB] Org ya admin: {user.organization.slug}")


async def main() -> None:
    print(f"Admin: {ADMIN_EMAIL}")
    init_firebase()
    if not admin_available():
        print(
            "ONYO: service account haipo. Firebase inahitaji FIREBASE_CREDENTIALS_FILE "
            "kwenye .env ili kuunda/kuweka password. DB bado itasasishwa."
        )
    else:
        await _seed_firebase()

    await _seed_db()
    await dispose_engine()
    print("Kumaliza. Ingia kwa", ADMIN_EMAIL)


if __name__ == "__main__":
    asyncio.run(main())
