"""Detection library: rules za "library" (zinazokuja nayo system) + seeding.

Kila rule ina MITRE ATT&CK mapping. `seed_library` inahakikisha kila org
inapata rules hizi (zilizowashwa au la) bila kurudia.

Correlation rules zinatumia `window_seconds` + `group_by` + `threshold`:
matukio kadhaa yanayofanana ndani ya dirisha ndipo yanapoleta alert.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.monitoring import DetectionRule

#: [(name, description, condition_type, value, severity, action,
#:   tactic, technique, window_seconds, group_by, threshold)]
LIBRARY: tuple[tuple, ...] = (
    (
        "Malicious indicator contacted",
        "A device contacted a domain or IP flagged malicious by threat intelligence.",
        "verdict_is", "malicious", "high", "alert",
        "Command and Control", "T1071", 0, "", 1,
    ),
    (
        "Suspicious indicator contacted",
        "A device contacted an indicator that appears in threat reports (not confirmed malicious).",
        "verdict_is", "suspicious", "medium", "alert",
        "Discovery", "T1595", 0, "", 1,
    ),
    (
        "Cryptomining domain",
        "A device resolved a domain associated with cryptocurrency mining pools.",
        "domain_contains", "pool", "low", "alert",
        "Impact", "T1496", 0, "", 1,
    ),
    (
        "Threat intel heavy pulse",
        "An indicator with many independent threat reports (pulse count >= 10) was contacted.",
        "pulse_count_gte", "10", "high", "alert",
        "Resource Development", "T1583", 0, "", 1,
    ),
    (
        "High-risk country contact",
        "A device contacted a destination in a country that appears frequently in threat feeds.",
        "country_is", "RU", "low", "alert",
        "Command and Control", "T1071", 0, "", 1,
    ),
    (
        "Repeated contact to same destination",
        "Correlation: more than 20 events to the same external destination within 5 minutes, a beaconing pattern.",
        "verdict_is", "suspicious", "medium", "alert",
        "Command and Control", "T1071.001", 300, "dst_ip", 20,
    ),
    (
        "Destination scan pattern",
        "Correlation: more than 40 flow events from the same source within 1 minute, consistent with scanning.",
        "kind_is", "flow", "low", "alert",
        "Discovery", "T1046", 60, "src_ip", 40,
    ),
)


async def seed_library(db: AsyncSession, organization_id: uuid.UUID) -> int:
    """Ingiza library rules ambazo org hii bado hainazo (kwa jina). Inarudisha
    idadi ya rules mpya zilizoongezwa. Hazi-commit — mwitaji ndiye ana-commit."""
    existing = set(
        (await db.scalars(select(DetectionRule.name).where(DetectionRule.organization_id == organization_id)))
    )
    added = 0
    for (
        name, description, condition_type, value, severity, action,
        tactic, technique, window, group_by, threshold,
    ) in LIBRARY:
        if name in existing:
            continue
        db.add(
            DetectionRule(
                organization_id=organization_id,
                name=name,
                description=description,
                condition_type=condition_type,
                value=value,
                severity=severity,
                action=action,
                source="library",
                mitre_tactic=tactic,
                mitre_technique=technique,
                window_seconds=window,
                group_by=group_by,
                threshold=threshold,
            )
        )
        added += 1
    return added


async def seed_library_committed(db: AsyncSession, organization_id: uuid.UUID) -> int:
    """Toleo la `seed_library` linalo-commit (kwa call sites rahisi)."""
    added = await seed_library(db, organization_id)
    if added:
        await db.commit()
    return added
