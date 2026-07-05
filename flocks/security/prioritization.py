"""Vulnerability prioritization helpers for the Security Extension."""

from __future__ import annotations

from flocks.security.models import VulnerabilityPriority
from flocks.security.schemas import SecurityListFilters
from flocks.security.scoring import calculate_vulnerability_priority
from flocks.security.store import SecurityStore, default_store


async def prioritize_vulnerabilities(
    filters: SecurityListFilters | None = None,
    store: SecurityStore | None = None,
) -> list[VulnerabilityPriority]:
    store = store or default_store
    filters = filters or SecurityListFilters(limit=100)
    vulnerabilities = await store.list_vulnerabilities(filters)

    priorities: list[VulnerabilityPriority] = []
    for vulnerability in vulnerabilities:
        asset = await store.get_asset(vulnerability.asset_id)
        alerts = await store.list_alerts(SecurityListFilters(asset_id=vulnerability.asset_id, limit=100))
        honeypot_events = []
        if asset and asset.ip:
            honeypot_events = await store.list_honeypot_events(SecurityListFilters(ip=asset.ip, limit=100))

        risk_score = calculate_vulnerability_priority(vulnerability, asset, alerts, honeypot_events)
        priorities.append(
            VulnerabilityPriority(
                vulnerability=vulnerability,
                asset=asset,
                related_alerts=alerts,
                honeypot_events=honeypot_events,
                risk_score=risk_score,
                priority=risk_score.level,
                factors=risk_score.reasons,
                recommended_actions=risk_score.recommendations,
            )
        )

    priorities.sort(
        key=lambda item: (
            item.risk_score.score,
            item.vulnerability.updated_at or item.vulnerability.created_at,
        ),
        reverse=True,
    )
    return priorities[: filters.limit]
