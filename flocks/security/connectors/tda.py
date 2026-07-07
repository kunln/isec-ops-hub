"""Lightweight Xinwei TDA connector v1.

Only temporary API responses are parsed into compact evidence events. This module
must not persist raw logs, full API responses, credentials, PCAPs, reports, or files.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import requests

from flocks.security.evidence_ingestion import ingest_external_events
from flocks.security.store import SecurityStore

TDA_CONNECTOR_CONTEXT = {
    "connector_id": "tda",
    "connector_name": "信桅高级威胁监测系统 TDA",
    "vendor": "Xinwei",
    "product": "TDA",
    "source_type": "tda",
}

_ALLOWED_MODES = {"alert", "event", "asset_risk", "weak_pwd", "plaintext", "attacker", "delivery"}
_ALLOWED_KEY_FIELDS = {
    "merge_key", "flow_id", "log_id", "event_time", "first_time", "latest_time", "detected_source",
    "threat_desc", "threat_class", "threat_tag", "severity", "confidence_level", "attack_res",
    "attack_direction", "attack_tac", "attack_tec", "attck_tac", "attck_tec", "rule_id", "rule_name",
    "rule_source", "cve", "cnnvd", "src", "dst", "src_port", "dst_port", "src_hostname", "dst_hostname",
    "attacker_addr", "victim_addr", "app_proto", "tran_proto", "domain", "url", "uri", "ioc_resource",
    "ioc_resource_type", "file_name", "file_hash_md5", "file_hash_sha1", "virus_name", "virus_family",
    "virus_type", "login_user", "login_path", "login_result", "asset_addr", "asset_name", "level", "count",
    "disposal", "disposal_name", "whitelisted", "labels", "orig_file_name", "file_type", "file_md5",
    "file_sha1", "risk_level", "process_status", "sandbox_source", "submit_source", "pwd_type", "num",
}
_SENSITIVE_OR_RAW_KEYS = {
    "http_req_body", "http_resp_body", "http_req_hdr", "http_resp_hdr", "login_password",
    "login_password_encrypted", "pcap_name", "payload", "packet", "body", "response", "request",
    "full_content", "raw", "raw_data", "raw_event", "api_key", "secret", "sign", "token", "password",
}
_TRUNCATE_KEYS = {"user_agent", "mail_subject"}


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value not in (None, "", [], {}):
            return str(value)
    return None


def _to_timestamp(value: str) -> int:
    text = str(value).strip()
    if text.isdigit():
        number = int(text)
        return number // 1000 if number > 10**12 else number
    normalized = text.replace("T", " ").replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.fromisoformat(normalized) if fmt is None else datetime.strptime(normalized, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            continue
    raise ValueError(f"Unsupported TDA time value: {value}")


def build_tda_time_query(begin: str | None, end: str | None, time_type: int = 1) -> dict[str, Any]:
    if begin or end:
        if not (begin and end):
            raise ValueError("begin and end must be provided together")
        return {"time_type": 5, "time_limit": f"{_to_timestamp(begin)},{_to_timestamp(end)}"}
    return {"time_type": time_type}


def parse_tda_time(value: Any) -> str | None:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, (int, float)) or str(value).strip().isdigit():
        number = float(value)
        if number > 10**12:
            number = number / 1000
        if number > 10**9:
            return datetime.fromtimestamp(number, tz=timezone.utc).isoformat()
    text = str(value).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return text


class TdaClient:
    def __init__(self, base_url: str, api_key: str, secret: str, verify_ssl: bool = False, timeout: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.secret = secret
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def _url(self, path: str) -> str:
        normalized = path if path.startswith("/ngtda/") or path == "/ngtda" else f"/ngtda/{path.lstrip('/')}"
        return urljoin(f"{self.base_url}/", normalized.lstrip("/"))

    def build_auth_headers(self, timestamp: int | None = None) -> dict[str, str]:
        auth_timestamp = int(time.time()) if timestamp is None else int(timestamp)
        sign_data = f"{auth_timestamp}{self.api_key}".encode("utf-8")
        digest = hmac.new(self.secret.encode("utf-8"), sign_data, hashlib.sha256).digest()
        return {
            "api_key": self.api_key,
            "auth_timestamp": str(auth_timestamp),
            "sign": base64.urlsafe_b64encode(digest).decode("ascii"),
        }

    def _request(self, method: str, path: str, json: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = requests.request(method, self._url(path), headers=self.build_auth_headers(), json=json, params=params, verify=self.verify_ssl, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else {"data": data}

    def test_connection(self) -> dict[str, Any]:
        return self._request("GET", "/ngtda/dashboard/system_resource_overview")

    def fetch_alert_list(self, begin: str | None = None, end: str | None = None, time_type: int = 1, page: int = 1, limit: int = 20) -> dict[str, Any]:
        payload = {**build_tda_time_query(begin, end, time_type), "page": page, "limit": limit, "order": "event_time", "order_direction": "desc"}
        return self._request("POST", "/ngtda/diagnosis/alert_list", json=payload)

    def fetch_event_list(self, begin: str | None = None, end: str | None = None, time_type: int = 1, page: int = 1, limit: int = 20) -> dict[str, Any]:
        payload = {**build_tda_time_query(begin, end, time_type), "page": page, "limit": limit, "order": "event_time", "order_direction": "desc"}
        return self._request("POST", "/ngtda/diagnosis/event_list", json=payload)

    def fetch_asset_risk(self, begin: str | None = None, end: str | None = None, time_type: int = 1, page: int = 1, limit: int = 20) -> dict[str, Any]:
        payload = {**build_tda_time_query(begin, end, time_type), "page": page, "limit": limit, "order": "latest_time", "order_direction": "desc"}
        return self._request("POST", "/ngtda/asset_rating_v3/list", json=payload)

    def fetch_attacker_list(self, begin: str | None = None, end: str | None = None, time_type: int = 1, page: int = 1, limit: int = 20) -> dict[str, Any]:
        payload = {**build_tda_time_query(begin, end, time_type), "page": page, "limit": limit}
        return self._request("POST", "/ngtda/attacker/list", json=payload)

    def fetch_delivery_records(self, begin: str | None = None, end: str | None = None, time_type: int = 1, page: int = 1, limit: int = 20) -> dict[str, Any]:
        payload = {**build_tda_time_query(begin, end, time_type), "page": page, "limit": limit}
        return self._request("POST", "/ngtda/sandbox/internal/va_result", json=payload)

    def fetch_password_risks(self, mode: str, begin: str | None = None, end: str | None = None, time_type: int = 1, page: int = 1, limit: int = 20) -> dict[str, Any]:
        if mode not in {"weak_pwd", "plaintext"}:
            raise ValueError("password risk mode must be weak_pwd or plaintext")
        payload = {**build_tda_time_query(begin, end, time_type), "pwd_type": mode, "page": page, "limit": limit}
        return self._request("POST", "/ngtda/asset/list", json=payload)


def extract_tda_items(response: dict[str, Any], mode: str) -> list[dict[str, Any]]:
    key_by_mode = {"alert": "alarm_list", "event": "alarm_list", "asset_risk": "ar_list", "attacker": "ar_list", "weak_pwd": "asset_list", "plaintext": "asset_list", "delivery": "data", "asset": "result"}
    data = response.get("data") if isinstance(response, dict) else None
    candidates: list[Any] = []
    if isinstance(data, dict):
        candidates.extend([data.get(key_by_mode.get(mode, "")), data.get("data"), data.get("list"), data.get("result"), data.get("rows")])
    candidates.extend([data, response.get(key_by_mode.get(mode, "")), response.get("result"), response.get("rows"), response.get("list")])
    for candidate in candidates:
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
    return []


def _severity(item: dict[str, Any], mode: str) -> str:
    value = item.get("level") if mode == "asset_risk" else item.get("risk_level", item.get("severity"))
    text = str(value or "").lower()
    mapping = {"超危": "critical", "失陷": "critical", "高危": "high", "中危": "medium", "可疑": "medium", "低危": "low", "信息": "info", "正常": "info", "0x4": "critical", "0x3": "high", "0x2": "medium", "0x1": "low", "3": "high", "2": "medium", "1": "low", "0": "info", "99": "medium"}
    return mapping.get(text, mapping.get(str(value), "medium"))


def _clean_value(key: str, value: Any) -> Any:
    if isinstance(value, str) and (key in _TRUNCATE_KEYS or len(value) > 1000):
        return value[:1000] + "…[truncated]"
    return value


def _safe_key_fields(item: dict[str, Any]) -> dict[str, Any]:
    return {key: _clean_value(key, item[key]) for key in _ALLOWED_KEY_FIELDS if key in item and key not in _SENSITIVE_OR_RAW_KEYS}


def _payload_hash(item: dict[str, Any]) -> str:
    safe = _safe_key_fields(item)
    return hashlib.sha256(json.dumps(safe, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _ioc(item: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ["attacker_addr", "victim_addr", "src", "dst", "ioc_resource", "domain", "url", "file_hash_md5", "file_hash_sha1", "file_md5", "file_sha1", "mine_addr", "mine_pool", "login_user", "src_ip", "dst_ip"]:
        value = item.get(key)
        if isinstance(value, list):
            values.extend(str(v) for v in value if v not in (None, ""))
        elif value not in (None, ""):
            values.append(str(value))
    return list(dict.fromkeys(values))


def _external_event_id(item: dict[str, Any], mode: str) -> str:
    if mode == "alert":
        return _first_text(item.get("merge_key"), item.get("flow_id"), item.get("log_id"), f"{item.get('rule_id')}:{item.get('latest_time')}", _payload_hash(item)) or _payload_hash(item)
    if mode == "event":
        return _first_text(item.get("flow_id"), item.get("log_id"), item.get("merge_key"), f"{item.get('rule_id')}:{item.get('event_time')}", _payload_hash(item)) or _payload_hash(item)
    if mode in {"weak_pwd", "plaintext"}:
        return _first_text(f"{item.get('dst')}:{item.get('login_user')}:{item.get('latest_time')}:{item.get('rule_id')}", _payload_hash(item)) or _payload_hash(item)
    if mode == "delivery":
        return _first_text(item.get("file_sha1"), item.get("file_md5"), f"{item.get('orig_file_name')}:{item.get('report_ts')}", _payload_hash(item)) or _payload_hash(item)
    return _first_text(f"{item.get('asset_addr')}:{item.get('latest_time')}", _payload_hash(item)) or _payload_hash(item)


def map_tda_item_to_evidence_event(item: dict, mode: str, context: dict) -> dict:
    key_fields = _safe_key_fields(item)
    title = _first_text(item.get("threat_desc"), item.get("rule_name"), f"{item.get('threat_class')} {item.get('threat_desc')}" if item.get("threat_class") and item.get("threat_desc") else None, f"{item.get('asset_addr')} {item.get('level')}" if item.get("asset_addr") else None, f"{item.get('orig_file_name')} {item.get('risk_level')}" if item.get("orig_file_name") else None, "TDA alert") or "TDA alert"
    desc_parts = []
    for key in ["threat_desc", "rule_name", "src", "dst", "attacker_addr", "victim_addr", "severity", "level", "attack_res", "attack_direction", "confidence_level", "login_user", "login_path", "login_result", "orig_file_name", "file_md5", "file_sha1"]:
        if key in key_fields and key_fields[key] not in (None, ""):
            desc_parts.append(f"{key}={key_fields[key]}")
    occurred_at = _first_text(parse_tda_time(item.get("event_time")), parse_tda_time(item.get("first_time")), parse_tda_time(item.get("latest_time")), parse_tda_time(item.get("report_ts")), parse_tda_time(item.get("analyze_ts")))
    event = {
        "external_event_id": _external_event_id(item, mode),
        "title": title,
        "description": "; ".join(desc_parts[:12]) or title,
        "severity": _severity(item, mode),
        "source": "other",
        "source_type": "tda",
        "asset_id": _first_text(item.get("victim_addr"), item.get("dst"), item.get("asset_addr"), item.get("dst_ip"), item.get("mine_host"), item.get("dst_hostname"), re.search(r"@([^/@]+)$", str(item.get("login_path") or "")).group(1) if re.search(r"@([^/@]+)$", str(item.get("login_path") or "")) else None),
        "ioc": _ioc(item),
        "occurred_at": occurred_at,
        "alert_type": _first_text(item.get("threat_class"), item.get("threat_tag"), item.get("sub_threat_type"), item.get("rule_name"), item.get("attack_tac"), item.get("attack_tec"), item.get("virus_type"), item.get("pwd_type"), f"TDA {mode}"),
        "key_fields": key_fields,
        "payload_hash": _payload_hash(item),
        "query_hint": f"connector_id=tda external_event_id={_external_event_id(item, mode)}",
    }
    event.update({k: v for k, v in context.items() if k != "external_base_url"})
    return event


def _total(response: dict[str, Any]) -> int | None:
    for obj in [response, response.get("data") if isinstance(response, dict) else None]:
        if isinstance(obj, dict):
            for key in ("total", "count", "total_count"):
                try:
                    if obj.get(key) is not None:
                        return int(obj[key])
                except (TypeError, ValueError):
                    pass
    return None


async def ingest_tda_events(base_url: str, api_key: str, secret: str, begin: str | None = None, end: str | None = None, time_type: int = 1, mode: str = "alert", limit: int = 20, max_pages: int = 1, create_analysis_cases: bool = True, run_initial_analysis: bool = True, deduplicate: bool = True, verify_ssl: bool = False, store: SecurityStore | None = None) -> dict:
    if mode not in _ALLOWED_MODES:
        raise ValueError("mode must be one of: alert, event, asset_risk, weak_pwd, plaintext, attacker, delivery")
    client = TdaClient(base_url=base_url, api_key=api_key, secret=secret, verify_ssl=verify_ssl)
    context = {**TDA_CONNECTOR_CONTEXT, "external_base_url": f"{base_url.rstrip('/')}/ngtda"}
    events: list[dict[str, Any]] = []
    for page in range(1, max(1, max_pages) + 1):
        if mode == "alert":
            response = client.fetch_alert_list(begin, end, time_type, page, limit)
        elif mode == "event":
            response = client.fetch_event_list(begin, end, time_type, page, limit)
        elif mode == "asset_risk":
            response = client.fetch_asset_risk(begin, end, time_type, page, limit)
        elif mode in {"weak_pwd", "plaintext"}:
            response = client.fetch_password_risks(mode, begin, end, time_type, page, limit)
        elif mode == "attacker":
            response = client.fetch_attacker_list(begin, end, time_type, page, limit)
        else:
            response = client.fetch_delivery_records(begin, end, time_type, page, limit)
        items = extract_tda_items(response, mode)
        if not items:
            break
        events.extend(map_tda_item_to_evidence_event(item, mode, context) for item in items)
        total = _total(response)
        if len(items) < limit or (total is not None and total <= page * limit):
            break
    summary = await ingest_external_events(events, connector_context=context, create_analysis_cases=create_analysis_cases, run_initial_analysis=run_initial_analysis, deduplicate=deduplicate, store=store)
    summary.update({"connector_id": "tda", "mode": mode, "fetched_events": len(events)})
    return summary
