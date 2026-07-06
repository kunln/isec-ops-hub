"""Storage-backed CRUD for Security Extension objects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from typing import Any, TypeVar

from pydantic import BaseModel

from flocks.security.models import (
    Alert,
    AnalysisCase,
    Asset,
    HoneypotEvent,
    Incident,
    Vulnerability,
)
from flocks.security.schemas import (
    AlertCreate,
    AlertUpdate,
    AnalysisCaseCreate,
    AnalysisCaseUpdate,
    AssetCreate,
    AssetUpdate,
    HoneypotEventCreate,
    HoneypotEventUpdate,
    IncidentCreate,
    IncidentUpdate,
    SecurityListFilters,
    VulnerabilityCreate,
    VulnerabilityUpdate,
)
from flocks.storage.storage import Storage
from flocks.utils.id import Identifier


SecurityObject = TypeVar("SecurityObject", Asset, Vulnerability, Alert, Incident, AnalysisCase, HoneypotEvent)


@dataclass(frozen=True)
class CollectionSpec:
    name: str
    prefix: str
    model: type[SecurityObject]
    id_prefix: str


ASSETS = CollectionSpec("assets", "security/assets/", Asset, "asset")
VULNERABILITIES = CollectionSpec(
    "vulnerabilities",
    "security/vulnerabilities/",
    Vulnerability,
    "vulnerability",
)
ALERTS = CollectionSpec("alerts", "security/alerts/", Alert, "alert")
INCIDENTS = CollectionSpec("incidents", "security/incidents/", Incident, "incident")
ANALYSIS_CASES = CollectionSpec("analysis_cases", "security/analysis-cases/", AnalysisCase, "analysis_case")
HONEYPOT_EVENTS = CollectionSpec(
    "honeypot_events",
    "security/honeypot-events/",
    HoneypotEvent,
    "honeypot",
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _dump(data: BaseModel | dict[str, Any]) -> dict[str, Any]:
    if isinstance(data, BaseModel):
        return data.model_dump(mode="json", exclude_unset=True)
    return dict(data)


def _key(spec: CollectionSpec, object_id: str) -> str:
    return f"{spec.prefix}{object_id}"


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _contains(value: Any, expected: str | None) -> bool:
    if not expected:
        return True
    needle = expected.lower()
    if isinstance(value, list):
        return any(needle in _text(item).lower() for item in value)
    return needle in _text(value).lower()


def _compact_dict(data: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    return {field: data.get(field) for field in fields if data.get(field) not in (None, "", [], {})}


def _ensure_analysis_case_children(data: dict[str, Any]) -> None:
    now = utc_now()
    for fact in data.get("facts") or []:
        if not fact.get("id"):
            fact["id"] = Identifier.create("analysis_fact")
        fact["created_at"] = fact.get("created_at") or now
    for evidence in data.get("evidence_items") or []:
        if not evidence.get("id"):
            evidence["id"] = Identifier.create("evidence")
        evidence["created_at"] = evidence.get("created_at") or now
    for gap in data.get("evidence_gaps") or []:
        if not gap.get("id"):
            gap["id"] = Identifier.create("evidence_gap")
        gap["created_at"] = gap.get("created_at") or now


def _default_normalized_data(spec: CollectionSpec, data: dict[str, Any]) -> dict[str, Any]:
    common = ["id", "created_at", "updated_at"]
    if spec is ASSETS:
        return _compact_dict(
            data,
            [
                "id",
                "name",
                "asset_type",
                "ip",
                "hostname",
                "domain",
                "business_system",
                "business_owner",
                "importance",
                "exposure_level",
                "environment",
                "open_ports",
                "services",
                "protocols",
                "security_controls",
                "tags",
            ],
        )
    if spec is VULNERABILITIES:
        return _compact_dict(
            data,
            [
                "id",
                "asset_id",
                "cve_id",
                "title",
                "severity",
                "cvss_score",
                "epss_score",
                "kev",
                "exploit_available",
                "affected_component",
                "status",
                "discovered_at",
            ],
        )
    if spec is ALERTS:
        return _compact_dict(
            data,
            [
                "id",
                "asset_id",
                "source",
                "title",
                "severity",
                "alert_type",
                "ioc",
                "mitre_technique",
                "status",
                "occurred_at",
            ],
        )
    if spec is INCIDENTS:
        return _compact_dict(
            data,
            [
                "id",
                "title",
                "severity",
                "status",
                "asset_ids",
                "vulnerability_ids",
                "alert_ids",
                "honeypot_event_ids",
                "confidence",
                "owner",
                "sla",
                "created_by",
            ],
        )
    if spec is ANALYSIS_CASES:
        return _compact_dict(
            data,
            [
                "id",
                "title",
                "case_status",
                "verdict",
                "severity",
                "confidence",
                "evidence_coverage",
                "analysis_mode",
                "notification_decision",
                "incident_decision",
                "disposition",
                "primary_asset_id",
                "related_asset_ids",
                "related_alert_ids",
                "related_vulnerability_ids",
                "related_incident_id",
            ],
        )
    if spec is HONEYPOT_EVENTS:
        return _compact_dict(
            data,
            [
                "id",
                "sensor_id",
                "source_ip",
                "target_ip",
                "protocol",
                "service",
                "event_type",
                "threat_label",
                "occurred_at",
            ],
        )
    return _compact_dict(data, common)


class SecurityStore:
    async def _put(self, spec: CollectionSpec, data: dict[str, Any]) -> SecurityObject:
        now = utc_now()
        if not data.get("id"):
            data["id"] = Identifier.create(spec.id_prefix)  # type: ignore[arg-type]
        data["created_at"] = data.get("created_at") or now
        data["updated_at"] = data.get("updated_at") or now
        if spec is ANALYSIS_CASES:
            _ensure_analysis_case_children(data)
        if spec is ALERTS and not data.get("raw_data") and data.get("raw_event"):
            data["raw_data"] = data["raw_event"]
        if not data.get("normalized_data"):
            data["normalized_data"] = _default_normalized_data(spec, data)
        obj = spec.model.model_validate(data)
        await Storage.set(_key(spec, obj.id), obj, f"security.{spec.name}")
        return obj

    async def _create(self, spec: CollectionSpec, payload: BaseModel | dict[str, Any]) -> SecurityObject:
        data = _dump(payload)
        data.pop("id", None)
        data.pop("created_at", None)
        data.pop("updated_at", None)
        return await self._put(spec, data)

    async def _upsert(self, spec: CollectionSpec, payload: BaseModel | dict[str, Any]) -> SecurityObject:
        data = _dump(payload)
        return await self._put(spec, data)

    async def _get(self, spec: CollectionSpec, object_id: str) -> SecurityObject | None:
        return await Storage.get(_key(spec, object_id), spec.model)

    async def _update(
        self,
        spec: CollectionSpec,
        object_id: str,
        payload: BaseModel | dict[str, Any],
    ) -> SecurityObject | None:
        current = await self._get(spec, object_id)
        if current is None:
            return None
        data = current.model_dump(mode="json")
        updates = _dump(payload)
        updates.pop("id", None)
        updates.pop("created_at", None)
        updates.pop("updated_at", None)
        for key, value in updates.items():
            data[key] = value
        data["updated_at"] = utc_now()
        if "normalized_data" not in updates:
            data["normalized_data"] = _default_normalized_data(spec, data)
        return await self._put(spec, data)

    async def _delete(self, spec: CollectionSpec, object_id: str) -> bool:
        return await Storage.delete(_key(spec, object_id))

    async def _list(self, spec: CollectionSpec, filters: SecurityListFilters | None = None) -> list[SecurityObject]:
        filters = filters or SecurityListFilters()
        entries = await Storage.list_entries(spec.prefix, spec.model)
        items = [value for _, value in entries if self._matches(value, filters)]
        items.sort(
            key=lambda item: getattr(item, "updated_at", None) or getattr(item, "created_at", ""),
            reverse=True,
        )
        return items[: filters.limit]

    def _matches(self, item: SecurityObject, filters: SecurityListFilters) -> bool:
        if filters.asset_id and getattr(item, "asset_id", None) != filters.asset_id:
            if not (
                (isinstance(item, Incident) and filters.asset_id in item.asset_ids)
                or (isinstance(item, AnalysisCase) and filters.asset_id in item.related_asset_ids)
            ):
                return False
        if filters.severity and getattr(item, "severity", None) != filters.severity:
            return False
        if filters.status and getattr(item, "status", None) != filters.status:
            return False
        if filters.source and getattr(item, "source", None) != filters.source:
            return False
        if filters.importance and getattr(item, "importance", None) != filters.importance:
            return False
        if filters.exposure_level and getattr(item, "exposure_level", None) != filters.exposure_level:
            return False
        if filters.ip:
            ip_fields = (
                getattr(item, "ip", None),
                getattr(item, "source_ip", None),
                getattr(item, "target_ip", None),
            )
            if not any(_contains(value, filters.ip) for value in ip_fields):
                return False
        if filters.domain and not _contains(getattr(item, "domain", None), filters.domain):
            return False
        if filters.hostname and not _contains(getattr(item, "hostname", None), filters.hostname):
            return False
        if filters.cve_id and not _contains(getattr(item, "cve_id", None), filters.cve_id):
            return False
        if filters.ioc and not _contains(getattr(item, "ioc", []), filters.ioc):
            return False
        if filters.mitre_technique and getattr(item, "mitre_technique", None) != filters.mitre_technique:
            return False
        if filters.keyword and not self._matches_keyword(item, filters.keyword):
            return False
        return True

    def _matches_keyword(self, item: SecurityObject, keyword: str) -> bool:
        fields = [
            "name",
            "title",
            "description",
            "summary",
            "analysis",
            "recommendation",
            "business_system",
            "business_owner",
            "hostname",
            "domain",
            "ip",
            "cve_id",
            "affected_component",
            "alert_type",
            "mitre_technique",
            "source_ip",
            "target_ip",
            "protocol",
            "service",
            "event_type",
            "threat_label",
        ]
        haystack = " ".join(_text(getattr(item, field, None)) for field in fields)
        haystack += " " + _text(getattr(item, "tags", []))
        haystack += " " + _text(getattr(item, "ioc", []))
        haystack += " " + _text(getattr(item, "raw_event", {}))
        haystack += " " + _text(getattr(item, "geo", {}))
        return keyword.lower() in haystack.lower()

    async def list_assets(self, filters: SecurityListFilters | None = None) -> list[Asset]:
        return await self._list(ASSETS, filters)

    async def get_asset(self, asset_id: str) -> Asset | None:
        return await self._get(ASSETS, asset_id)

    async def create_asset(self, payload: AssetCreate | dict[str, Any]) -> Asset:
        return await self._create(ASSETS, payload)

    async def upsert_asset(self, payload: Asset | dict[str, Any]) -> Asset:
        return await self._upsert(ASSETS, payload)

    async def update_asset(self, asset_id: str, payload: AssetUpdate | dict[str, Any]) -> Asset | None:
        return await self._update(ASSETS, asset_id, payload)

    async def delete_asset(self, asset_id: str) -> bool:
        return await self._delete(ASSETS, asset_id)

    async def list_vulnerabilities(self, filters: SecurityListFilters | None = None) -> list[Vulnerability]:
        return await self._list(VULNERABILITIES, filters)

    async def get_vulnerability(self, vulnerability_id: str) -> Vulnerability | None:
        return await self._get(VULNERABILITIES, vulnerability_id)

    async def create_vulnerability(self, payload: VulnerabilityCreate | dict[str, Any]) -> Vulnerability:
        return await self._create(VULNERABILITIES, payload)

    async def upsert_vulnerability(self, payload: Vulnerability | dict[str, Any]) -> Vulnerability:
        return await self._upsert(VULNERABILITIES, payload)

    async def update_vulnerability(
        self,
        vulnerability_id: str,
        payload: VulnerabilityUpdate | dict[str, Any],
    ) -> Vulnerability | None:
        return await self._update(VULNERABILITIES, vulnerability_id, payload)

    async def delete_vulnerability(self, vulnerability_id: str) -> bool:
        return await self._delete(VULNERABILITIES, vulnerability_id)

    async def list_alerts(self, filters: SecurityListFilters | None = None) -> list[Alert]:
        return await self._list(ALERTS, filters)

    async def get_alert(self, alert_id: str) -> Alert | None:
        return await self._get(ALERTS, alert_id)

    async def create_alert(self, payload: AlertCreate | dict[str, Any]) -> Alert:
        return await self._create(ALERTS, payload)

    async def upsert_alert(self, payload: Alert | dict[str, Any]) -> Alert:
        return await self._upsert(ALERTS, payload)

    async def update_alert(self, alert_id: str, payload: AlertUpdate | dict[str, Any]) -> Alert | None:
        return await self._update(ALERTS, alert_id, payload)

    async def delete_alert(self, alert_id: str) -> bool:
        return await self._delete(ALERTS, alert_id)

    async def list_incidents(self, filters: SecurityListFilters | None = None) -> list[Incident]:
        return await self._list(INCIDENTS, filters)

    async def get_incident(self, incident_id: str) -> Incident | None:
        return await self._get(INCIDENTS, incident_id)

    async def create_incident(self, payload: IncidentCreate | dict[str, Any]) -> Incident:
        return await self._create(INCIDENTS, payload)

    async def upsert_incident(self, payload: Incident | dict[str, Any]) -> Incident:
        return await self._upsert(INCIDENTS, payload)

    async def update_incident(self, incident_id: str, payload: IncidentUpdate | dict[str, Any]) -> Incident | None:
        return await self._update(INCIDENTS, incident_id, payload)

    async def delete_incident(self, incident_id: str) -> bool:
        return await self._delete(INCIDENTS, incident_id)


    async def list_analysis_cases(self, filters: SecurityListFilters | None = None) -> list[AnalysisCase]:
        return await self._list(ANALYSIS_CASES, filters)

    async def get_analysis_case(self, case_id: str) -> AnalysisCase | None:
        return await self._get(ANALYSIS_CASES, case_id)

    async def create_analysis_case(self, payload: AnalysisCaseCreate | dict[str, Any]) -> AnalysisCase:
        return await self._create(ANALYSIS_CASES, payload)

    async def upsert_analysis_case(self, payload: AnalysisCase | dict[str, Any]) -> AnalysisCase:
        return await self._upsert(ANALYSIS_CASES, payload)

    async def update_analysis_case(self, case_id: str, payload: AnalysisCaseUpdate | dict[str, Any]) -> AnalysisCase | None:
        return await self._update(ANALYSIS_CASES, case_id, payload)

    async def delete_analysis_case(self, case_id: str) -> bool:
        return await self._delete(ANALYSIS_CASES, case_id)

    async def list_honeypot_events(self, filters: SecurityListFilters | None = None) -> list[HoneypotEvent]:
        return await self._list(HONEYPOT_EVENTS, filters)

    async def get_honeypot_event(self, event_id: str) -> HoneypotEvent | None:
        return await self._get(HONEYPOT_EVENTS, event_id)

    async def create_honeypot_event(self, payload: HoneypotEventCreate | dict[str, Any]) -> HoneypotEvent:
        return await self._create(HONEYPOT_EVENTS, payload)

    async def upsert_honeypot_event(self, payload: HoneypotEvent | dict[str, Any]) -> HoneypotEvent:
        return await self._upsert(HONEYPOT_EVENTS, payload)

    async def update_honeypot_event(
        self,
        event_id: str,
        payload: HoneypotEventUpdate | dict[str, Any],
    ) -> HoneypotEvent | None:
        return await self._update(HONEYPOT_EVENTS, event_id, payload)

    async def delete_honeypot_event(self, event_id: str) -> bool:
        return await self._delete(HONEYPOT_EVENTS, event_id)


default_store = SecurityStore()
