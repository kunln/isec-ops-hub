"""Lightweight Mingyu APT connector v1.

The connector only converts temporary API responses into compact evidence events.
It must not persist full raw logs, full API response bodies, files, PCAPs, or reports.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any
from urllib.parse import urljoin

import requests

from flocks.security.evidence_ingestion import ingest_external_events
from flocks.security.store import SecurityStore

MINGYU_CONNECTOR_CONTEXT = {
    "connector_id": "mingyu-apt",
    "connector_name": "明御APT攻击预警平台",
    "vendor": "DBAPPSecurity",
    "product": "Mingyu APT",
    "source_type": "apt",
}

_ALLOWED_KEY_FIELDS = [
    "accessid", "poid", "sensorip", "name", "description", "alarmdesc", "attackgradeid",
    "attackStatusName", "attackstatus", "eventtypeStr", "incidentName", "sip", "dip",
    "victimip", "victimlist", "attackerip", "failedMachine", "domain", "filename",
    "md5value", "sha1value", "sha256value", "replycode", "dport", "sport", "firsttime",
    "lasttime", "count", "success", "tryCount", "fail", "processed", "flag", "policyid",
    "ruleID", "signame", "total",
]
_SENSITIVE_RAW_FIELDS = {
    "payload", "rawdata", "request", "requestHead", "requestParam", "response", "postContent",
    "payloaddata", "dataDetail",
}


class MingyuAptClient:
    """Small apikey-header client for Mingyu APT /openapi endpoints."""

    def __init__(self, base_url: str, apikey: str, verify_ssl: bool = False, timeout: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.apikey = apikey
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def _url(self, path: str) -> str:
        normalized = path if path.startswith("/openapi/") or path == "/openapi" else f"/openapi/{path.lstrip('/')}"
        return urljoin(f"{self.base_url}/", normalized.lstrip("/"))

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        response = requests.request(method, self._url(path), headers={"apikey": self.apikey}, verify=self.verify_ssl, timeout=self.timeout, **kwargs)
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else {"data": data}

    def get_version(self) -> dict[str, Any]:
        return self._request("GET", "/openapi/about")

    def fetch_risk_list(self, begin: str, end: str, offset: int = 0, limit: int = 20, combined: int = 1, flags: Any = None, sips: Any = None, dips: Any = None, eventypes: Any = None, attackstatuss: Any = None) -> dict[str, Any]:
        payload = {"begin": begin, "end": end, "offset": offset, "limit": limit, "combined": combined}
        payload.update({k: v for k, v in {"flags": flags, "sips": sips, "dips": dips, "eventypes": eventypes, "attackstatuss": attackstatuss}.items() if v is not None})
        return self._request("POST", "/openapi/risk/getList", json=payload)

    def fetch_important_events(self, begin: str, end: str, offset: int = 0, limit: int = 20, victimip: str | None = None, processed: Any = None) -> dict[str, Any]:
        params = {"begin": begin, "end": end, "offset": offset, "limit": limit}
        params.update({k: v for k, v in {"victimip": victimip, "processed": processed}.items() if v is not None})
        return self._request("GET", "/openapi/analyse/important/list", params=params)

    def fetch_safe_events(self, begin: str, end: str, offset: int = 0, limit: int = 20, sips: Any = None, dips: Any = None, siprange: Any = None, diprange: Any = None, incidentid: Any = None) -> dict[str, Any]:
        payload = {"begin": begin, "end": end, "offset": offset, "limit": limit}
        payload.update({k: v for k, v in {"sips": sips, "dips": dips, "siprange": siprange, "diprange": diprange, "incidentid": incidentid}.items() if v is not None})
        return self._request("POST", "/openapi/analyse/safe-event/list", json=payload)

    def fetch_incident_map(self) -> dict[str, Any]:
        return self._request("GET", "/openapi/analyse/safe-event/incident/map")


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value not in (None, "", [], {}):
            if isinstance(value, list):
                return ",".join(str(item) for item in value[:5])
            return str(value)
    return None


def parse_accessid_time(accessid: Any) -> str | None:
    text = str(accessid or "")[:12]
    if len(text) != 12 or not text.isdigit():
        return None
    try:
        return datetime.strptime(text, "%y%m%d%H%M%S").isoformat(sep=" ")
    except ValueError:
        return None


def _severity(item: dict[str, Any]) -> str:
    grade = str(item.get("attackgradeid") or "")
    if grade == "3":
        return "high"
    if grade == "2":
        return "medium"
    if grade == "1":
        return "low"
    events = item.get("event") if isinstance(item.get("event"), list) else [item]
    def total(name: str) -> int:
        value = 0
        for event in events:
            if isinstance(event, dict):
                try:
                    value += int(event.get(name) or 0)
                except (TypeError, ValueError):
                    pass
        return value
    if total("high") > 0:
        return "high"
    if total("middle") > 0:
        return "medium"
    if total("low") > 0:
        return "low"
    return "medium"


def _event_title(item: dict[str, Any]) -> str:
    event = item.get("event")
    event_name = None
    if isinstance(event, list) and event and isinstance(event[0], dict):
        event_name = _first_text(event[0].get("incidentName"), event[0].get("eventStr"), event[0].get("subeventname"))
    return _first_text(item.get("name"), item.get("description"), item.get("incidentName"), item.get("eventStr"), item.get("alarmdesc"), item.get("signame"), item.get("subeventname"), event_name, "Mingyu APT alert") or "Mingyu APT alert"


def _ioc(item: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ["sip", "dip", "attackerip", "victimip", "domain", "filename", "md5value", "sha1value", "sha256value"]:
        value = item.get(key)
        if isinstance(value, list):
            values.extend(str(v) for v in value if v not in (None, ""))
        elif value not in (None, ""):
            values.append(str(value))
    return list(dict.fromkeys(values))


def _payload_hash(item: dict[str, Any]) -> str:
    relevant = {k: v for k, v in item.items() if k in _SENSITIVE_RAW_FIELDS or k in _ALLOWED_KEY_FIELDS or k == "event"}
    return hashlib.sha256(json.dumps(relevant, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def map_mingyu_risk_to_evidence_event(item: dict, context: dict) -> dict:
    external_event_id = _first_text(item.get("accessid"), item.get("id"), item.get("lastaccessid"), item.get("scenekey"))
    title = _event_title(item)
    key_fields = {key: item[key] for key in _ALLOWED_KEY_FIELDS if key in item}
    if isinstance(item.get("event"), list):
        key_fields["eventSize"] = len(item["event"])
        key_fields["event"] = [{k: v for k, v in event.items() if k in {"incidentName", "high", "middle", "low", "success", "total"}} for event in item["event"][:5] if isinstance(event, dict)]
    event = {
        "external_event_id": external_event_id,
        "title": title,
        "description": _first_text(item.get("description"), item.get("alarmdesc"), item.get("name"), item.get("eventStr"), item.get("message"), title),
        "severity": _severity(item),
        "source": "other",
        "source_type": "apt",
        "asset_id": _first_text(item.get("victim_ip"), item.get("victimip"), item.get("victimlist"), item.get("dip"), item.get("failedMachine"), item.get("sip")),
        "ioc": _ioc(item),
        "occurred_at": _first_text(item.get("firsttime"), item.get("lasttime"), item.get("day"), parse_accessid_time(item.get("accessid"))),
        "alert_type": _first_text(item.get("type"), item.get("eventtypeStr"), item.get("incidentName"), item.get("attackStatusName"), item.get("subeventname"), item.get("categoryname")),
        "key_fields": key_fields,
        "payload_hash": _payload_hash(item),
        "query_hint": f"connector_id=mingyu-apt external_event_id={external_event_id or _payload_hash(item)}",
    }
    event.update({k: v for k, v in context.items() if k != "external_base_url"})
    return event


def _extract_items(response: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[Any] = [response.get("data"), response.get("import"), response.get("list"), response.get("rows")]
    if isinstance(response.get("data"), dict):
        data = response["data"]
        candidates.extend([data.get("data"), data.get("import"), data.get("list"), data.get("rows")])
    for candidate in candidates:
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
    return []


async def ingest_mingyu_apt_risks(base_url: str, apikey: str, begin: str, end: str, mode: str = "risk", limit: int = 100, max_pages: int = 1, create_analysis_cases: bool = True, run_initial_analysis: bool = True, deduplicate: bool = True, verify_ssl: bool = False, store: SecurityStore | None = None) -> dict:
    client = MingyuAptClient(base_url=base_url, apikey=apikey, verify_ssl=verify_ssl)
    context = {**MINGYU_CONNECTOR_CONTEXT, "external_base_url": f"{base_url.rstrip('/')}/openapi"}
    events: list[dict[str, Any]] = []
    for page in range(max(0, max_pages)):
        offset = page * limit
        if mode == "risk":
            response = client.fetch_risk_list(begin, end, offset=offset, limit=limit)
        elif mode == "important":
            response = client.fetch_important_events(begin, end, offset=offset, limit=limit)
        elif mode == "safe_event":
            response = client.fetch_safe_events(begin, end, offset=offset, limit=limit)
        else:
            raise ValueError("mode must be one of: risk, important, safe_event")
        items = _extract_items(response)
        events.extend(map_mingyu_risk_to_evidence_event(item, context) for item in items)
        if len(items) < limit:
            break
    summary = await ingest_external_events(events, connector_context=context, create_analysis_cases=create_analysis_cases, run_initial_analysis=run_initial_analysis, deduplicate=deduplicate, store=store)
    summary.update({"connector_id": "mingyu-apt", "mode": mode, "fetched_events": len(events)})
    return summary
