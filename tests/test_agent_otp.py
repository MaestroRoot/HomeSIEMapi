"""Tests za OTP ya kuunganisha HomeSIEM Agent desktop app kwa akaunti ya email."""

import pytest

from app.core.ratelimit import otp_limiter
from tests.conftest import dev_auth


async def _provision_user(client, email: str) -> str:
    """Inaunda user (na org yake) kwa njia ya dev bypass na kurudisha email."""
    response = await client.post(
        "/auth/session", json={"name": "Agent Owner"}, headers=dev_auth(email)
    )
    assert response.status_code == 200
    return email


async def _request_code(client, monkeypatch, email: str) -> str:
    """Inaomba OTP na kunasa code kutoka kwa send_agent_otp iliyobadilishwa."""
    captured: dict = {}

    async def _fake_send_agent_otp(**kwargs) -> bool:
        captured["code"] = kwargs["code"]
        return True

    monkeypatch.setattr(
        "app.api.v1.endpoints.agent.send_agent_otp", _fake_send_agent_otp
    )

    response = await client.post("/agent/otp/request", json={"email": email})
    assert response.status_code == 200
    assert response.json()["code"] == "otp_sent"
    assert captured["code"], "send_agent_otp haikuitwa"
    return captured["code"]


@pytest.mark.asyncio
async def test_otp_request_inakataa_email_isiyosajiliwa(client):
    otp_limiter.reset()
    response = await client.post(
        "/agent/otp/request", json={"email": "missing@example.com"}
    )
    assert response.status_code == 404
    assert response.json()["code"] == "user_not_found"


@pytest.mark.asyncio
async def test_otp_code_bora_inaleta_sensor_token_na_enroll(client, monkeypatch):
    otp_limiter.reset()
    email = await _provision_user(client, "agent@example.com")
    code = await _request_code(client, monkeypatch, email)

    verify = await client.post(
        "/agent/otp/verify", json={"email": email, "code": code}
    )
    assert verify.status_code == 200
    token = verify.json()["token"]
    assert token.startswith("hs_")

    # Token hiyo inafanya kazi kwenye enroll ya kawaida ya agent.
    enroll = await client.post(
        "/agent/enroll",
        json={"hostname": "test-pc", "os": "Windows"},
        headers={"X-Sensor-Token": token},
    )
    assert enroll.status_code == 200
    assert enroll.json()["agentId"]


@pytest.mark.asyncio
async def test_otp_huchachuata_code_isiyo_sahihi(client, monkeypatch):
    otp_limiter.reset()
    email = await _provision_user(client, "wrong@example.com")
    await _request_code(client, monkeypatch, email)

    response = await client.post(
        "/agent/otp/verify", json={"email": email, "code": "000000"}
    )
    assert response.status_code == 401
    assert response.json()["code"] == "otp_invalid"


@pytest.mark.asyncio
async def test_otp_inatumika_mara_moja_tu(client, monkeypatch):
    otp_limiter.reset()
    email = await _provision_user(client, "once@example.com")
    code = await _request_code(client, monkeypatch, email)

    first = await client.post(
        "/agent/otp/verify", json={"email": email, "code": code}
    )
    assert first.status_code == 200

    second = await client.post(
        "/agent/otp/verify", json={"email": email, "code": code}
    )
    assert second.status_code == 401
    assert second.json()["code"] == "otp_invalid"


@pytest.mark.asyncio
async def test_otp_request_jipya_linafuta_code_ya_zamani(client, monkeypatch):
    otp_limiter.reset()
    email = await _provision_user(client, "rotate@example.com")

    old_code = await _request_code(client, monkeypatch, email)
    new_code = await _request_code(client, monkeypatch, email)
    assert new_code != old_code

    old_verify = await client.post(
        "/agent/otp/verify", json={"email": email, "code": old_code}
    )
    assert old_verify.status_code == 401
    assert old_verify.json()["code"] == "otp_invalid"


@pytest.mark.asyncio
async def test_otp_verify_inakataa_code_ya_tarakimu_mbovu(client):
    otp_limiter.reset()
    response = await client.post(
        "/agent/otp/verify", json={"email": "x@example.com", "code": "abcd"}
    )
    assert response.status_code == 422
