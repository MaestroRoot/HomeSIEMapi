# Schema ya Postgres

`001_init.sql` ni nakala kamili ya schema iliyotengenezwa na alembic
(`alembic upgrade head`), imetolewa kwa `pg_dump --schema-only`.

## Ni ya nini

- Kusoma muundo wa DB bila kufungua Python.
- Kutengeneza DB kwenye mazingira yasiyo na alembic (mfano deploy ya haraka,
  au DB ya majaribio).

**Alembic ndiye mwenye mamlaka.** Ukibadilisha models, tengeneza migration mpya,
kisha safisha faili hii upya. Usiandike SQL hapa kwa mkono.

## Kuitengeneza upya

```powershell
docker exec homesiem-postgres pg_dump -U homesiem -d homesiem --schema-only --no-owner --no-privileges | Out-File -Encoding utf8 backend\schema\001_init.sql
```

Kisha ondoa mistari ya `\restrict` / `\unrestrict` (ni meta-commands za psql,
haziendeshwi na clients wengine).

## Kuitumia moja kwa moja

```powershell
docker exec -i homesiem-postgres psql -U homesiem -d homesiem < backend\schema\001_init.sql
```

## Tables

| Table | Kazi |
| --- | --- |
| `organizations` | Workspace. Kila mtu anayejisajili anaundiwa yake. |
| `users` | Wanachama. Hakuna password hapa, `firebase_uid` ndio kiungo. |
| `subscriptions` | Kifurushi kinachotumika sasa, kimoja kwa kila org. |
| `payments` | Kila jaribio la malipo. Hakuna namba kamili ya card. |
| `alembic_version` | Alembic inaitumia kufuatilia migration iliyofika. |

## Enum types

`plan`, `user_role`, `subscription_status`, `payment_method`,
`payment_channel`, `payment_status`.

`plan` inatumika kwenye tables nne, ndio maana migration inaiunda mara moja juu
badala ya kuiacha kila `CREATE TABLE` ijaribu kuiunda.
