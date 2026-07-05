"""Asset identity extraction and matching helpers.

Security products report observations, not authoritative assets.  This module
keeps the matching rules explicit so DHCP and reused private IPs do not become
silent asset merges.
"""

from __future__ import annotations

from datetime import datetime
import json
from typing import Any


ASSET_IDENTITY_VERSION = "security.asset.identity.v1"
UNKNOWN_VALUES = {"", "unknown", "none", "null", "n/a", "-"}

STRONG_GLOBAL_FIELDS = (
    "cmdb_asset_id",
    "asset_uuid",
    "endpoint_uuid",
    "device_guid",
    "cloud_instance_id",
    "cloud_resource_id",
    "instance_id",
    "serial_number",
    "serial",
)
STRONG_SCOPED_FIELDS = ("mac_address", "mac")
STRONG_CONNECTOR_SCOPED_FIELDS = ("agent_id", "endpoint_id")
AUXILIARY_FIELDS = (
    "hostname",
    "fqdn",
    "domain",
    "asset_name",
    "name",
    "logged_in_user",
    "user",
    "dhcp_client_id",
)
IP_FIELDS = ("ip", "asset_ip", "host_ip", "private_ip", "public_ip")
NETWORK_SCOPE_FIELDS = ("network_scope", "networkScope", "site", "zone", "vlan", "subnet", "network")
ALLOCATION_MODE_FIELDS = ("allocation_mode", "allocationMode", "ip_allocation_mode", "ipAllocationMode")
FIRST_SEEN_FIELDS = ("first_seen", "firstSeen", "discovered_at", "discoveredAt", "observed_at", "observedAt")
LAST_SEEN_FIELDS = ("last_seen", "lastSeen", "updated_at", "updatedAt", "observed_at", "observedAt")


def build_asset_identity(
    payload: dict[str, Any],
    *,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a normalized identity document for an asset-like payload."""

    evidence = evidence if isinstance(evidence, dict) else {}
    connector_id = _string(evidence.get("connector_id") or _field_value(payload, "connector_id"))
    source_instance_id = _string(evidence.get("source_instance_id"))
    network_scope = _normalize_identity_value(_first_field(payload, NETWORK_SCOPE_FIELDS)) or "default"
    allocation_mode = _normalize_allocation_mode(_first_field(payload, ALLOCATION_MODE_FIELDS))
    ip = _normalize_ip(_first_field(payload, IP_FIELDS))
    first_seen = _first_time(payload, FIRST_SEEN_FIELDS) or _string(evidence.get("source_timestamp"))
    last_seen = _first_time(payload, LAST_SEEN_FIELDS) or _string(evidence.get("source_timestamp")) or first_seen
    if first_seen and not last_seen:
        last_seen = first_seen

    strong_keys = _strong_keys(payload, connector_id=connector_id, network_scope=network_scope)
    auxiliary_keys = _auxiliary_keys(payload)
    weak_keys = []
    if ip:
        weak_keys.append(f"weak:ip:{network_scope}:{ip}")

    source_observation = {
        "connector_id": connector_id or None,
        "source_system": evidence.get("source_system"),
        "source_instance_id": source_instance_id or None,
        "credential_profile_id": evidence.get("credential_profile_id"),
        "device_id": evidence.get("device_id"),
        "source_object_id": evidence.get("source_object_id"),
        "source_fingerprint": evidence.get("source_fingerprint"),
        "observed_at": evidence.get("source_timestamp") or first_seen or last_seen,
        "first_seen": first_seen or None,
        "last_seen": last_seen or None,
    }
    source_observation = {key: value for key, value in source_observation.items() if value not in (None, "", [], {})}

    ip_observations = []
    if ip:
        ip_observations.append(
            {
                "ip": ip,
                "network_scope": network_scope,
                "allocation_mode": allocation_mode,
                "first_seen": first_seen or None,
                "last_seen": last_seen or None,
                "source_instance_id": source_instance_id or None,
            }
        )

    identity_keys = sorted(set([*strong_keys, *auxiliary_keys, *weak_keys]))
    return {
        "version": ASSET_IDENTITY_VERSION,
        "connector_id": connector_id or None,
        "source_instance_id": source_instance_id or None,
        "network_scope": network_scope,
        "allocation_mode": allocation_mode,
        "ip": ip or None,
        "observation_window": {
            "first_seen": first_seen or None,
            "last_seen": last_seen or None,
        },
        "strong_keys": strong_keys,
        "auxiliary_keys": auxiliary_keys,
        "weak_keys": weak_keys,
        "identity_keys": identity_keys,
        "auto_merge_keys": strong_keys,
        "source_observation": source_observation,
        "ip_observations": ip_observations,
    }


def identity_for_asset_data(data: dict[str, Any]) -> dict[str, Any]:
    """Return stored asset identity metadata, filling gaps from top-level fields."""

    normalized_data = data.get("normalized_data") if isinstance(data.get("normalized_data"), dict) else {}
    stored = normalized_data.get("asset_identity") if isinstance(normalized_data.get("asset_identity"), dict) else {}
    evidence = normalized_data.get("connector_evidence") if isinstance(normalized_data.get("connector_evidence"), dict) else {}
    built = build_asset_identity(data, evidence=evidence)
    if not stored:
        return built

    merged = dict(built)
    merged.update({key: value for key, value in stored.items() if value not in (None, "", [], {})})
    for key in ("strong_keys", "auxiliary_keys", "weak_keys", "identity_keys", "auto_merge_keys"):
        merged[key] = sorted(set([*_as_list(built.get(key)), *_as_list(stored.get(key))]))
    if not isinstance(merged.get("observation_window"), dict):
        merged["observation_window"] = built["observation_window"]
    return merged


def compare_asset_identity(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Score whether two asset identity documents should refer to one asset."""

    left_strong = set(_as_list(left.get("strong_keys")))
    right_strong = set(_as_list(right.get("strong_keys")))
    left_aux = set(_as_list(left.get("auxiliary_keys")))
    right_aux = set(_as_list(right.get("auxiliary_keys")))
    strong_matches = sorted(left_strong & right_strong)
    auxiliary_matches = sorted(left_aux & right_aux)
    weak_matches = sorted(set(_as_list(left.get("weak_keys"))) & set(_as_list(right.get("weak_keys"))))

    score = 0
    reasons: list[str] = []
    matching_keys: list[dict[str, Any]] = []
    if strong_matches:
        score += 100
        reasons.append("strong_identity_match")
        matching_keys.extend({"key": key, "type": "strong"} for key in strong_matches)

    same_scope = str(left.get("network_scope") or "default") == str(right.get("network_scope") or "default")
    left_ip = _normalize_ip(left.get("ip"))
    right_ip = _normalize_ip(right.get("ip"))
    same_ip = bool(left_ip and right_ip and left_ip == right_ip and same_scope)
    if left_ip and right_ip and left_ip == right_ip and not same_scope:
        score -= 80
        reasons.append("same_ip_different_network_scope")
    if same_ip:
        score += 20
        reasons.append("same_ip_same_scope")
        matching_keys.extend({"key": key, "type": "weak"} for key in weak_matches or [f"weak:ip:{left.get('network_scope') or 'default'}:{left_ip}"])

    overlap = observation_windows_overlap(left, right)
    if same_ip and overlap is True:
        score += 20
        reasons.append("time_window_overlap")
    elif same_ip and overlap is False and not strong_matches:
        score -= 60
        reasons.append("time_window_not_overlapping")

    if auxiliary_matches:
        score += 40
        reasons.append("auxiliary_identity_match")
        matching_keys.extend({"key": key, "type": "auxiliary"} for key in auxiliary_matches)
    elif same_ip and not strong_matches:
        score -= 10
        reasons.append("missing_auxiliary_identity")

    if _hostname_conflict(left, right):
        score -= 30
        reasons.append("hostname_conflict")

    dhcp_single_ip = (
        same_ip
        and not strong_matches
        and not auxiliary_matches
        and (
            _is_dhcp(left.get("allocation_mode"))
            or _is_dhcp(right.get("allocation_mode"))
        )
    )
    if dhcp_single_ip:
        reasons.append("dhcp_single_ip_not_auto_merge")

    auto_merge = bool(strong_matches) or (
        score >= 80
        and same_ip
        and bool(auxiliary_matches)
        and overlap is not False
        and not dhcp_single_ip
    )
    candidate = bool(auto_merge or strong_matches or (same_ip and overlap is not False) or score >= 50)
    if same_ip and overlap is False and not strong_matches and not auxiliary_matches:
        candidate = False

    confidence = "high" if auto_merge else "medium" if score >= 50 else "low"
    return {
        "score": score,
        "confidence": confidence,
        "auto_merge": auto_merge,
        "candidate": candidate,
        "matching_keys": matching_keys,
        "reasons": reasons,
        "same_ip": same_ip,
        "time_overlap": overlap,
    }


def observation_windows_overlap(left: dict[str, Any], right: dict[str, Any]) -> bool | None:
    left_start, left_end = _window_bounds(left)
    right_start, right_end = _window_bounds(right)
    if not any((left_start, left_end, right_start, right_end)):
        return None
    if left_start is None:
        left_start = left_end
    if left_end is None:
        left_end = left_start
    if right_start is None:
        right_start = right_end
    if right_end is None:
        right_end = right_start
    if not all((left_start, left_end, right_start, right_end)):
        return None
    return left_start <= right_end and right_start <= left_end


def source_instance_id(
    connector_id: str,
    source: str,
    *,
    credential_profile_id: str | None = None,
    adapter_request: dict[str, Any] | None = None,
) -> str:
    metadata = adapter_request.get("metadata") if isinstance(adapter_request, dict) else {}
    device_id = metadata.get("device_id") if isinstance(metadata, dict) else None
    parts = [f"connector:{connector_id}"]
    if credential_profile_id:
        parts.append(f"profile:{credential_profile_id}")
    if device_id:
        parts.append(f"device:{device_id}")
    parts.append(f"source:{source}")
    return "|".join(parts)


def source_device_id(adapter_request: dict[str, Any] | None) -> str | None:
    metadata = adapter_request.get("metadata") if isinstance(adapter_request, dict) else {}
    value = metadata.get("device_id") if isinstance(metadata, dict) else None
    return str(value) if value not in (None, "", [], {}) else None


def _strong_keys(payload: dict[str, Any], *, connector_id: str, network_scope: str) -> list[str]:
    keys = []
    for field in STRONG_GLOBAL_FIELDS:
        value = _normalize_identity_value(_field_value(payload, field))
        if value and value not in UNKNOWN_VALUES:
            canonical_field = "cloud_instance_id" if field in {"cloud_resource_id", "instance_id"} else field
            keys.append(f"strong:{canonical_field}:{value}")
    for field in STRONG_SCOPED_FIELDS:
        value = _normalize_mac(_field_value(payload, field))
        if value and value not in UNKNOWN_VALUES:
            keys.append(f"strong:mac_address:{network_scope}:{value}")
    for field in STRONG_CONNECTOR_SCOPED_FIELDS:
        value = _normalize_identity_value(_field_value(payload, field))
        if value and value not in UNKNOWN_VALUES:
            namespace = connector_id or "unknown_connector"
            keys.append(f"strong:{field}:{namespace}:{value}")
    return sorted(set(keys))


def _auxiliary_keys(payload: dict[str, Any]) -> list[str]:
    keys = []
    for field in AUXILIARY_FIELDS:
        value = _normalize_identity_value(_field_value(payload, field))
        if value and value not in UNKNOWN_VALUES:
            canonical_field = "hostname" if field in {"fqdn", "asset_name", "name"} else field
            keys.append(f"aux:{canonical_field}:{value}")
    return sorted(set(keys))


def _first_field(payload: dict[str, Any], fields: tuple[str, ...]) -> Any:
    for field in fields:
        value = _field_value(payload, field)
        if value not in (None, "", [], {}):
            return value
    return None


def _first_time(payload: dict[str, Any], fields: tuple[str, ...]) -> str:
    for field in fields:
        value = _string(_field_value(payload, field))
        if value:
            return value
    return ""


def _field_value(payload: dict[str, Any], field: str) -> Any:
    if not isinstance(payload, dict):
        return None
    if payload.get(field) not in (None, "", [], {}):
        return payload.get(field)
    normalized_data = payload.get("normalized_data")
    if isinstance(normalized_data, dict) and normalized_data.get(field) not in (None, "", [], {}):
        return normalized_data.get(field)
    raw_data = payload.get("raw_data")
    if isinstance(raw_data, dict):
        if raw_data.get(field) not in (None, "", [], {}):
            return raw_data.get(field)
        response = raw_data.get("response")
        if isinstance(response, dict) and response.get(field) not in (None, "", [], {}):
            return response.get(field)
    return None


def _window_bounds(identity: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    window = identity.get("observation_window") if isinstance(identity.get("observation_window"), dict) else {}
    return _parse_datetime(window.get("first_seen")), _parse_datetime(window.get("last_seen"))


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _hostname_conflict(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_hosts = {key for key in _as_list(left.get("auxiliary_keys")) if key.startswith("aux:hostname:")}
    right_hosts = {key for key in _as_list(right.get("auxiliary_keys")) if key.startswith("aux:hostname:")}
    return bool(left_hosts and right_hosts and not (left_hosts & right_hosts))


def _normalize_allocation_mode(value: Any) -> str:
    normalized = _normalize_identity_value(value)
    if normalized in {"dhcp", "dynamic"}:
        return "dhcp"
    if normalized in {"static", "fixed", "reserved"}:
        return "static"
    return "unknown"


def _normalize_ip(value: Any) -> str:
    return _normalize_identity_value(value)


def _normalize_mac(value: Any) -> str:
    text = _normalize_identity_value(value)
    if not text:
        return ""
    return text.replace("-", ":")


def _normalize_identity_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True).strip().lower()
    return str(value).strip().lower()


def _string(value: Any) -> str:
    return str(value).strip() if value not in (None, "", [], {}) else ""


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "", [], {})]
    return []


def _is_dhcp(value: Any) -> bool:
    return _normalize_identity_value(value) == "dhcp"
