import pytest

from tests.conftest import dev_auth

CARD = {
    "number": "4242424242424242",
    "holder": "Hans Richard",
    "expiryMonth": 11,
    "expiryYear": 2030,
    "cvv": "123",
}


@pytest.mark.asyncio
async def test_plans_zinapatikana_bila_kuingia(client):
    response = await client.get("/subscriptions/plans")
    assert response.status_code == 200

    body = response.json()
    assert body["currency"] == "TZS"
    prices = {p["plan"]: p["priceTzs"] for p in body["plans"]}
    assert prices == {"Free": 0, "Home": 15_000, "Pro": 50_000, "Business": 150_000}


@pytest.mark.asyncio
async def test_huduma_zinaongezeka_kifurushi_hadi_kifurushi(client):
    plans = (await client.get("/subscriptions/plans")).json()["plans"]
    by_plan = {p["plan"]: set(p["modules"]) for p in plans}

    assert by_plan["Free"] < by_plan["Home"] < by_plan["Pro"] < by_plan["Business"]


@pytest.mark.asyncio
async def test_mtu_mpya_anaanzia_free(client):
    headers = dev_auth("sub-new@example.com")
    await client.post("/auth/session", json={}, headers=headers)

    response = await client.get("/subscriptions/me", headers=headers)
    assert response.status_code == 200

    body = response.json()
    assert body["subscription"]["plan"] == "Free"
    assert body["subscription"]["status"] == "active"
    assert body["pendingPayment"] is None
    assert body["limits"]["devices"] == 2


@pytest.mark.asyncio
async def test_checkout_ya_simu_inaanzisha_malipo(client):
    headers = dev_auth("sub-mpesa@example.com")
    await client.post("/auth/session", json={}, headers=headers)

    response = await client.post(
        "/subscriptions/checkout",
        json={"plan": "Pro", "method": "mobile_money", "channel": "mpesa", "msisdn": "0712345678"},
        headers=headers,
    )
    assert response.status_code == 200

    body = response.json()
    assert body["payment"]["amountTzs"] == 50_000
    assert body["payment"]["status"] == "processing"
    # Namba inasanifiwa kwenda umbo la kimataifa.
    assert body["payment"]["msisdn"] == "255712345678"
    # MUHIMU: kifurushi HAKIBADILIKI hadi malipo yathibitishwe.
    assert body["subscription"]["plan"] == "Free"
    assert body["subscription"]["status"] == "pending"


@pytest.mark.asyncio
async def test_card_haihifadhiwi_zaidi_ya_tarakimu_nne_za_mwisho(client):
    headers = dev_auth("sub-card@example.com")
    await client.post("/auth/session", json={}, headers=headers)

    response = await client.post(
        "/subscriptions/checkout",
        json={"plan": "Business", "method": "bank_card", "channel": "card", "card": CARD},
        headers=headers,
    )
    assert response.status_code == 200

    payment = response.json()["payment"]
    assert payment["cardLast4"] == "4242"
    assert payment["cardBrand"] == "Visa"
    # Hakuna sehemu yoyote ya jibu inayobeba namba nzima.
    assert CARD["number"] not in response.text


@pytest.mark.asyncio
async def test_namba_mbovu_ya_simu_inakataliwa(client):
    headers = dev_auth("sub-bad-phone@example.com")
    await client.post("/auth/session", json={}, headers=headers)

    response = await client.post(
        "/subscriptions/checkout",
        json={"plan": "Home", "method": "mobile_money", "channel": "mpesa", "msisdn": "12345"},
        headers=headers,
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_channel_isiyolingana_na_method_inakataliwa(client):
    headers = dev_auth("sub-mismatch@example.com")
    await client.post("/auth/session", json={}, headers=headers)

    response = await client.post(
        "/subscriptions/checkout",
        json={"plan": "Home", "method": "bank_card", "channel": "mpesa", "msisdn": "0712345678"},
        headers=headers,
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_card_iliyoisha_muda_inakataliwa(client):
    headers = dev_auth("sub-expired@example.com")
    await client.post("/auth/session", json={}, headers=headers)

    response = await client.post(
        "/subscriptions/checkout",
        json={
            "plan": "Home",
            "method": "bank_card",
            "channel": "card",
            "card": {**CARD, "expiryYear": 2024, "expiryMonth": 1},
        },
        headers=headers,
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_free_hailipiwi(client):
    headers = dev_auth("sub-free@example.com")
    await client.post("/auth/session", json={}, headers=headers)

    response = await client.post(
        "/subscriptions/checkout",
        json={"plan": "Free", "method": "mobile_money", "channel": "mpesa", "msisdn": "0712345678"},
        headers=headers,
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_malipo_mawili_kwa_wakati_mmoja_yanazuiwa(client):
    headers = dev_auth("sub-double@example.com")
    await client.post("/auth/session", json={}, headers=headers)

    body = {"plan": "Pro", "method": "mobile_money", "channel": "airtel_money", "msisdn": "0682345678"}
    first = await client.post("/subscriptions/checkout", json=body, headers=headers)
    second = await client.post(
        "/subscriptions/checkout",
        json={**body, "plan": "Home", "channel": "yas_mix"},
        headers=headers,
    )

    assert first.status_code == 200
    assert second.status_code == 400
    assert second.json()["code"] == "payment_in_progress"


@pytest.mark.asyncio
async def test_kughairi_kunafungua_nafasi_ya_kulipa_tena(client):
    headers = dev_auth("sub-cancel@example.com")
    await client.post("/auth/session", json={}, headers=headers)

    started = await client.post(
        "/subscriptions/checkout",
        json={"plan": "Pro", "method": "mobile_money", "channel": "halopesa", "msisdn": "0622345678"},
        headers=headers,
    )
    reference = started.json()["payment"]["reference"]

    cancelled = await client.post(
        f"/subscriptions/payments/{reference}/cancel", headers=headers
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "failed"

    again = await client.post(
        "/subscriptions/checkout",
        json={"plan": "Home", "method": "mobile_money", "channel": "yas_mix", "msisdn": "0652345678"},
        headers=headers,
    )
    assert again.status_code == 200


@pytest.mark.asyncio
async def test_historia_ya_malipo_inaonyesha_yaliyopita(client):
    headers = dev_auth("sub-history@example.com")
    await client.post("/auth/session", json={}, headers=headers)
    await client.post(
        "/subscriptions/checkout",
        json={"plan": "Pro", "method": "mobile_money", "channel": "mpesa", "msisdn": "0712345678"},
        headers=headers,
    )

    response = await client.get("/subscriptions/payments", headers=headers)
    assert response.status_code == 200
    assert response.json()["total"] == 1
