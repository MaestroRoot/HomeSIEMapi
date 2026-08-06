import pytest
from sqlalchemy import select

from app.models.enums import Role
from app.models.user import User
from tests.conftest import dev_auth


async def _provision(client, email: str, name: str = "Mtu") -> dict:
    response = await client.post("/auth/session", json={"name": name}, headers=dev_auth(email))
    return response.json()["user"]


@pytest.mark.asyncio
async def test_patch_me_inabadilisha_jina(client):
    headers = dev_auth("profile@example.com")
    await client.post("/auth/session", json={"name": "Jina la Zamani"}, headers=headers)

    response = await client.patch("/users/me", json={"name": "Jina Jipya"}, headers=headers)
    assert response.status_code == 200
    assert response.json()["name"] == "Jina Jipya"


@pytest.mark.asyncio
async def test_patch_me_hairuhusu_kubadilisha_role_wala_plan(client):
    headers = dev_auth("escalate@example.com")
    await client.post("/auth/session", json={}, headers=headers)

    # `extra="ignore"` haiko kwenye schemas, lakini fields zisizojulikana
    # zinapuuzwa na pydantic, hivyo role/plan hazibadiliki.
    response = await client.patch(
        "/users/me", json={"name": "Bado Mimi", "role": "owner", "plan": "Business"}, headers=headers
    )
    assert response.status_code == 200
    assert response.json()["plan"] == "Free"


@pytest.mark.asyncio
async def test_viewer_hawezi_kuona_orodha_ya_watumiaji(client, db):
    headers = dev_auth("viewer@example.com")
    created = await _provision(client, "viewer@example.com")

    # Anashushwa hadi viewer moja kwa moja kwenye DB.
    user = (
        await db.execute(select(User).where(User.id == created["id"]))
    ).scalar_one()
    user.role = Role.VIEWER
    await db.commit()

    response = await client.get("/users", headers=headers)
    assert response.status_code == 403
    assert response.json()["code"] == "insufficient_role"


@pytest.mark.asyncio
async def test_owner_pekee_hawezi_kujiondoa_uowner(client):
    headers = dev_auth("solo-owner@example.com")
    user = await _provision(client, "solo-owner@example.com")

    response = await client.patch(
        f"/users/{user['id']}/role", json={"role": "analyst"}, headers=headers
    )
    assert response.status_code == 403
    assert response.json()["code"] == "last_owner"


@pytest.mark.asyncio
async def test_role_ya_mtu_wa_org_nyingine_hairuhusiwi(client):
    mine = dev_auth("org-a@example.com")
    await _provision(client, "org-a@example.com")
    other = await _provision(client, "org-b@example.com")

    response = await client.patch(
        f"/users/{other['id']}/role", json={"role": "viewer"}, headers=mine
    )
    assert response.status_code == 404
