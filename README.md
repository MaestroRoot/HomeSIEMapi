# HomeSIEM, Backend

FastAPI + Firebase Auth + PostgreSQL (async SQLAlchemy).

Firebase inashughulikia **identity** pekee (nani ameingia). **Authorization**
(role, plan, organization) iko kwenye database yetu, backend haiamini kamwe
`role` wala `plan` inayotumwa na client.

## Muundo

```
app/
  core/       config, logging, errors, firebase, plans, payments, ratelimit
  db/         engine, session, Base
  models/     User, Organization, Subscription, Payment, enums
  schemas/    Pydantic, snake_case ndani, camelCase kwa JSON
  crud/       shughuli za database
  api/
    deps.py             get_current_user, require_role
    v1/endpoints/       health, auth, users, subscriptions
  main.py
alembic/      migrations
schema/       nakala ya SQL ya schema (angalia schema/README.md)
tests/        pytest
```

## Kuanzisha (mara ya kwanza)

```bash
python -m venv .venv
```

```bash
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

```bash
Copy-Item .env.example .env
```

## Database

```bash
docker compose up -d
```

Container inapublish **5433** kwenye host (sio 5432, ambayo tayari imechukuliwa
na Postgres nyingine kwenye mashine hii).

```bash
.venv\Scripts\python.exe -m alembic upgrade head
```

## Kuendesha server

```bash
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

- Docs: http://localhost:8000/docs
- Health: http://localhost:8000/api/v1/health

## Auth: njia mbili za kuthibitisha token

`/api/v1/health` inaonyesha zote mbili:

| Check | Maana |
|---|---|
| `firebase` | Tunaweza kuthibitisha ID token halisi. `FIREBASE_PROJECT_ID` pekee inatosha. |
| `firebaseAdmin` | Service account ipo. Inahitajika kwa **revocation** pekee. |

**1. Public keys (default, hakuna siri inayohitajika).**
ID token ya Firebase ni JWT iliyosainiwa na Google kwa RS256. Vyeti vya umma
vinapatikana wazi, hivyo backend inathibitisha saini, `aud`, `iss` na `exp`
bila service account. Weka tu:

```
FIREBASE_PROJECT_ID=homesiem-fb222
```

Login na signup zinafanya kazi kikamilifu kwa njia hii.

**2. Admin SDK (ya hiari).**
Ukiweka service account JSON, backend inaitumia badala yake na `/auth/logout`
inaweza kufuta refresh tokens za mtumiaji kwenye devices zote papo hapo.
Bila yake, logout inamtoa client na token iliyopo mkononi inaisha yenyewe
ndani ya saa moja.

```
FIREBASE_CREDENTIALS_FILE=./secrets/firebase-service-account.json
```

Faili hiyo inapatikana: Firebase Console → Project Settings → Service accounts
→ Generate new private key. `secrets/` iko kwenye `.gitignore`, usiwahi
ku-commit.

## Endpoints zilizopo

| Method | Path | Ruhusa | Kazi |
|---|---|---|---|
| GET | `/api/v1/health` | wazi | hali ya server, DB, Firebase, Groq |
| POST | `/api/v1/auth/session` | token | inaunda/inaleta user baada ya login |
| GET | `/api/v1/auth/me` | token | user wa sasa |
| POST | `/api/v1/auth/logout` | token | inafuta refresh tokens za Firebase |
| GET | `/api/v1/users/me` | token | profile |
| PATCH | `/api/v1/users/me` | token | badilisha name / avatar / MFA |
| GET | `/api/v1/users` | analyst+ | watu wa organization |
| PATCH | `/api/v1/users/{id}/role` | owner | badilisha role |
| GET | `/api/v1/subscriptions/plans` | wazi | vifurushi vyote na bei |
| GET | `/api/v1/subscriptions/me` | token | kifurushi cha org, huduma, mipaka |
| POST | `/api/v1/subscriptions/checkout` | owner | anzisha malipo |
| GET | `/api/v1/subscriptions/payments` | token | historia ya malipo |
| POST | `/api/v1/subscriptions/payments/{ref}/cancel` | owner | ghairi malipo |

Kila request yenye auth inahitaji header:

```
Authorization: Bearer <firebaseIdToken>
```

`/auth/session` ina rate limit ya maombi 10 kwa dakika kwa kila IP.

## Vifurushi

Bei na huduma ziko `app/core/plans.py`, ndicho chanzo pekee cha ukweli.
`frontend/src/lib/plans.ts` ni nakala ya kuonyesha UI, ukibadilisha kimoja
badilisha na kingine.

| Kifurushi | Bei / mwezi | Devices | Retention | Huduma |
|---|---|---|---|---|
| Free | 0 | 2 | siku 1 | 6 |
| Home | TSh 15,000 | 5 | siku 7 | 13 |
| Pro | TSh 50,000 | 25 | siku 30 | 20 |
| Business | TSh 150,000 | bila kikomo | siku 365 | 25 |

## Malipo

`app/core/payments.py` ina adapter moja, `ManualGateway`, inayorekodi nia ya
kulipa bila kupiga mtandao. ClickPesa itaingizwa hapo hapo: ongeza
`ClickPesaGateway` yenye method `charge()` ile ile na uibadilishe kwenye
`get_gateway()`. Endpoints hazitahitaji mabadiliko.

Kifurushi **hakibadiliki** wakati wa checkout. Kinabadilika pale tu
`confirm_payment()` itakapoitwa (webhook ya gateway au admin), ili mtu asipate
Business kwa kubonyeza kitufe tu.

**Card**: `payments` table haihifadhi namba kamili, expiry wala CVV, na
haitawahi. Inabaki na `card_last4` + `card_brand` pekee. Namba kamili
inapaswa kwenda kwa gateway moja kwa moja, na endpoint hii inahitaji HTTPS
kwenye production.

## Dev bypass

Ikiwa `AUTH_DEV_BYPASS=true` na `ENV != production`, token ya bandia inakubalika:

```
Authorization: Bearer dev:hans@example.com
Authorization: Bearer dev:hans@example.com:Hans Richard
```

Ni kwa kujaribu endpoints kwa curl. Kwenye `ENV=production` inapuuzwa kabisa
hata kama `.env` inasema `true`.

## Tests

```bash
.venv\Scripts\python.exe -m pip install pytest pytest-asyncio
```

```bash
.venv\Scripts\python.exe -m pytest
```

Tests zinatumia container ile ile ya Postgres lakini kwenye schema ya muda
inayofutwa mwishoni, hivyo data ya development haiguswi.

## Kuunganisha na frontend

Baada ya Firebase login kufanikiwa upande wa React:

```ts
const idToken = await firebaseUser.getIdToken()
const res = await fetch('http://localhost:8000/api/v1/auth/session', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${idToken}` },
  body: JSON.stringify({ name }),   // `name` mara ya kwanza tu (signup form)
})
const { user, isNewUser } = await res.json()
```

Hii tayari imefanyika kwenye `frontend/src/lib/api.ts` na
`frontend/src/context/AuthContext.tsx`.
