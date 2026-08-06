import pytest

from tests.conftest import dev_auth


@pytest.mark.asyncio
async def test_health_haihitaji_auth(client):
    response = await client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["checks"]["devAuthBypass"] is True


@pytest.mark.asyncio
async def test_session_bila_token_inakataliwa(client):
    response = await client.post("/auth/session", json={})
    assert response.status_code == 401
    assert response.json()["code"] == "token_missing"


@pytest.mark.asyncio
async def test_dev_token_inaunda_user(client):
    response = await client.post(
        "/auth/session", json={"name": "Hans Richard"}, headers=dev_auth("hans@example.com")
    )
    assert response.status_code == 200

    body = response.json()
    assert body["isNewUser"] is True
    assert body["user"]["email"] == "hans@example.com"
    assert body["user"]["name"] == "Hans Richard"
    # Mtu wa kwanza kwenye org yake ni owner, na anaanzia kifurushi cha Free.
    assert body["user"]["role"] == "owner"
    assert body["user"]["plan"] == "Free"
    # camelCase, sio snake_case, ili ilingane na TypeScript.
    assert "mfaEnabled" in body["user"]
    assert "organizationId" in body["user"]


@pytest.mark.asyncio
async def test_provisioning_ni_idempotent(client):
    headers = dev_auth("idem@example.com")

    first = await client.post("/auth/session", json={"name": "Idem"}, headers=headers)
    second = await client.post("/auth/session", json={"name": "Idem"}, headers=headers)

    assert first.json()["isNewUser"] is True
    assert second.json()["isNewUser"] is False
    assert first.json()["user"]["id"] == second.json()["user"]["id"]


@pytest.mark.asyncio
async def test_dev_token_bila_email_inakataliwa(client):
    response = await client.post(
        "/auth/session", json={}, headers={"Authorization": "Bearer dev:sio-email"}
    )
    assert response.status_code == 401
    assert response.json()["code"] == "token_invalid"


@pytest.mark.asyncio
async def test_me_inarudisha_user_yule_yule(client):
    headers = dev_auth("me@example.com", "Me Myself")
    created = await client.post("/auth/session", json={}, headers=headers)

    response = await client.get("/auth/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == created.json()["user"]["id"]


@pytest.mark.asyncio
async def test_session_ina_rate_limit(client):
    headers = dev_auth("flood@example.com")

    statuses = [
        (await client.post("/auth/session", json={}, headers=headers)).status_code
        for _ in range(12)
    ]

    assert statuses[:10] == [200] * 10
    assert statuses[10] == 429
