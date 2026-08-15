import uuid
from datetime import datetime

from pydantic import EmailStr, Field, field_serializer

from app.models.enums import Plan, Role, SubscriptionStatus
from app.schemas.common import CamelModel


class AdminSubscriptionRead(CamelModel):
    """Kifurushi cha org, kwa admin view (hakuna trial_days_left computation)."""

    plan: Plan
    status: SubscriptionStatus
    price_tzs: int
    currency: str
    current_period_end: datetime | None = None
    trial_ends_at: datetime | None = None
    auto_renew: bool


class AdminUserRead(CamelModel):
    """Mtumiaji pamoja na org + subscription, kwa ajili ya /admin pekee."""

    id: uuid.UUID
    name: str
    email: EmailStr
    phone: str | None = None
    role: Role
    plan: Plan
    mfa_enabled: bool
    email_verified: bool
    is_active: bool
    avatar_url: str | None = None
    created_at: datetime
    last_login_at: datetime | None = None
    organization_id: uuid.UUID
    organization_name: str | None = None
    subscription: AdminSubscriptionRead | None = None

    @field_serializer("id", "organization_id")
    def _uuid_to_str(self, value: uuid.UUID) -> str:
        return str(value)


class AdminUserList(CamelModel):
    items: list[AdminUserRead]
    total: int


class AdminStats(CamelModel):
    """Takwimu za jukwaa zima kwa ukurasa wa kwanza wa admin."""

    total_users: int
    total_organizations: int
    active_users_30d: int
    new_users_30d: int
    suspended_users: int
    admin_users: int
    #: Org zilizopo kwenye kila kifurushi (Free/Home/Pro/Business).
    subscription_counts: dict[str, int]
    #: Org zilizopo kwenye trial bado.
    trial_count: int
    paid_subscriptions: int


class AdminPlanUpdate(CamelModel):
    plan: Plan


class AdminRoleUpdate(CamelModel):
    role: Role = Field(description="admin | owner | analyst | viewer")


class AdminStatusUpdate(CamelModel):
    is_active: bool = Field(description="True=active, False=suspended")
