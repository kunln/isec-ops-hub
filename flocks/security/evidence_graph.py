"""Cross-connector entity resolution and evidence graph for Security Store."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from flocks.config.config import Config
from flocks.security.asset_identity import compare_asset_identity, identity_for_asset_data
from flocks.security.models import Alert, Asset, HoneypotEvent, Incident, Vulnerability
from flocks.security.schemas import SecurityListFilters
from flocks.security.store import SecurityStore, default_store


EVIDENCE_GRAPH_VERSION = "connector.evidence.graph.v1"
EVIDENCE_GRAPH_RELATIVE_PATH = Path("security") / "connector-evidence-graph.json"
DEFAULT_GRAPH_LIMIT = 500
ASSET_CONFLICT_FIELDS = (
    "importance",
    "exposure_level",
    "environment",
    "business_owner",
    "business_system",
)
UNKNOWN_VALUES = {"", "unknown", "none", "null", "n/a"}


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, item: str) -> None:
        self.parent.setdefault(item, item)

    def find(self, item: str) -> str:
        self.add(item)
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != item:
            item, self.parent[item] = self.parent[item], root
        return root

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def default_evidence_graph_path() -> Path:
    return Config.get_data_path() / EVIDENCE_GRAPH_RELATIVE_PATH


def evidence_graph_path_or_default(path: Path | None = None) -> Path:
    return (path or default_evidence_graph_path()).expanduser()


def empty_evidence_graph() -> dict[str, Any]:
    return {
        "version": EVIDENCE_GRAPH_VERSION,
        "updated_at": None,
        "summary": _empty_summary(),
        "nodes": [],
        "edges": [],
        "entities": [],
        "merge_candidates": [],
        "conflicts": [],
        "indexes": {
            "asset_entity_by_asset_id": {},
            "nodes_by_kind": {},
        },
    }


def load_evidence_graph(path: Path | None = None) -> dict[str, Any]:
    graph_path = evidence_graph_path_or_default(path)
    if not graph_path.is_file():
        graph = empty_evidence_graph()
        graph["summary"]["path"] = str(graph_path)
        return graph
    data = json.loads(graph_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Evidence graph registry must be an object: {graph_path}")
    graph = empty_evidence_graph()
    graph.update(data)
    graph["version"] = str(graph.get("version") or EVIDENCE_GRAPH_VERSION)
    graph["summary"] = graph.get("summary") if isinstance(graph.get("summary"), dict) else _empty_summary()
    graph["summary"]["path"] = str(graph_path)
    for key in ("nodes", "edges", "entities", "merge_candidates", "conflicts"):
        graph[key] = graph.get(key) if isinstance(graph.get(key), list) else []
    graph["indexes"] = graph.get("indexes") if isinstance(graph.get("indexes"), dict) else {}
    return graph


def save_evidence_graph(graph: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    graph_path = evidence_graph_path_or_default(path)
    graph_path.parent.mkdir(parents=True, exist_ok=True)
    graph["version"] = EVIDENCE_GRAPH_VERSION
    graph["updated_at"] = utc_now()
    graph.setdefault("summary", {})["path"] = str(graph_path)
    payload = json.dumps(graph, ensure_ascii=False, indent=2, sort_keys=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=graph_path.parent,
        prefix=f".{graph_path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        tmp_path = Path(handle.name)
        handle.write(payload)
    os.replace(tmp_path, graph_path)
    return graph


def evidence_graph_summary(path: Path | None = None) -> dict[str, Any]:
    graph = load_evidence_graph(path)
    summary = dict(graph.get("summary") or {})
    summary.setdefault("version", graph.get("version"))
    summary.setdefault("updated_at", graph.get("updated_at"))
    summary.setdefault("nodes", len(graph.get("nodes") or []))
    summary.setdefault("edges", len(graph.get("edges") or []))
    summary.setdefault("asset_entities", len(graph.get("entities") or []))
    summary.setdefault("merge_candidates", len(graph.get("merge_candidates") or []))
    summary.setdefault("conflicts", len(graph.get("conflicts") or []))
    return summary


async def rebuild_evidence_graph(
    *,
    store: SecurityStore | None = None,
    path: Path | None = None,
    limit: int = DEFAULT_GRAPH_LIMIT,
    annotate_store: bool = True,
) -> dict[str, Any]:
    store = store or default_store
    limit = max(1, min(DEFAULT_GRAPH_LIMIT, int(limit)))
    filters = SecurityListFilters(limit=limit)
    assets = await store.list_assets(filters)
    vulnerabilities = await store.list_vulnerabilities(filters)
    alerts = await store.list_alerts(filters)
    incidents = await store.list_incidents(filters)
    honeypot_events = await store.list_honeypot_events(filters)

    built_at = utc_now()
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    annotations: dict[tuple[str, str], dict[str, Any]] = {}

    asset_profiles = {
        asset.id: identity_for_asset_data(asset.model_dump(mode="json"))
        for asset in assets
    }
    asset_keys = {asset_id: _asset_identity_keys(profile) for asset_id, profile in asset_profiles.items()}
    asset_groups = _resolve_asset_groups(assets, asset_profiles)
    asset_to_entity: dict[str, str] = {}
    entity_records: list[dict[str, Any]] = []
    merge_candidates: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []

    key_to_assets: dict[str, list[str]] = defaultdict(list)
    for asset_id, keys in asset_keys.items():
        for key in keys:
            key_to_assets[key].append(asset_id)

    for group_assets in asset_groups:
        entity = _build_asset_entity(group_assets, asset_keys)
        entity_records.append(entity)
        nodes[entity["id"]] = entity
        for asset in group_assets:
            asset_to_entity[asset.id] = entity["id"]

        if len(group_assets) > 1:
            matching_keys = [
                {"key": key, "asset_ids": sorted(ids)}
                for key, ids in sorted(key_to_assets.items())
                if len(ids) > 1 and set(ids) & {asset.id for asset in group_assets}
            ]
            candidate = _merge_candidate(
                entity,
                group_assets,
                matching_keys,
                status="auto_merged",
                confidence="high",
                reason="auto_asset_identity_match",
            )
            merge_candidates.append(candidate)
            for asset in group_assets:
                _annotation(annotations, "asset", asset.id)["merge_candidate_ids"].add(candidate["id"])

            for conflict in _asset_conflicts(entity, group_assets):
                conflicts.append(conflict)
                for value_record in conflict["values"]:
                    for asset_id in value_record["asset_ids"]:
                        _annotation(annotations, "asset", asset_id)["conflict_ids"].add(conflict["id"])

    for candidate in _candidate_asset_pairs(assets, asset_profiles, asset_to_entity):
        merge_candidates.append(candidate)
        for asset_id in candidate.get("asset_ids", []):
            _annotation(annotations, "asset", str(asset_id))["merge_candidate_ids"].add(candidate["id"])
        pair_assets = [asset for asset in assets if asset.id in set(candidate.get("asset_ids") or [])]
        for conflict in _asset_conflicts({"id": candidate["id"]}, pair_assets):
            conflicts.append(conflict)
            for value_record in conflict["values"]:
                for asset_id in value_record["asset_ids"]:
                    _annotation(annotations, "asset", asset_id)["conflict_ids"].add(conflict["id"])

    for asset in assets:
        node_id = _object_node_id("asset", asset.id)
        entity_id = asset_to_entity.get(asset.id)
        nodes[node_id] = _object_node("asset", asset.id, asset.name, asset)
        annotation = _annotation(annotations, "asset", asset.id)
        annotation["node_id"] = node_id
        if entity_id:
            annotation["entity_id"] = entity_id
            annotation["entity_ids"].add(entity_id)
            edge = _edge(
                node_id,
                entity_id,
                "same_entity_as",
                confidence=_asset_entity_confidence(asset_keys.get(asset.id, [])),
                evidence=_object_evidence(asset),
                properties={
                    "identity_keys": asset_keys.get(asset.id, []),
                    "asset_identity": asset_profiles.get(asset.id, {}),
                },
            )
            edges[edge["id"]] = edge

    asset_ip_index = _asset_identity_index(asset_to_entity, "ip", asset_profiles)
    asset_hostname_index = _asset_identity_index(asset_to_entity, "hostname", asset_profiles)
    asset_domain_index = _asset_identity_index(asset_to_entity, "domain", asset_profiles)

    for vulnerability in vulnerabilities:
        node_id = _object_node_id("vulnerability", vulnerability.id)
        nodes[node_id] = _object_node(
            "vulnerability",
            vulnerability.id,
            vulnerability.cve_id or vulnerability.title,
            vulnerability,
        )
        _annotation(annotations, "vulnerability", vulnerability.id)["node_id"] = node_id
        entity_id = asset_to_entity.get(vulnerability.asset_id)
        if entity_id:
            edge = _edge(node_id, entity_id, "affects", evidence=_object_evidence(vulnerability))
            edges[edge["id"]] = edge

    for alert in alerts:
        node_id = _object_node_id("alert", alert.id)
        nodes[node_id] = _object_node("alert", alert.id, alert.title, alert)
        _annotation(annotations, "alert", alert.id)["node_id"] = node_id
        entity_id = asset_to_entity.get(alert.asset_id or "")
        if entity_id:
            edge = _edge(node_id, entity_id, "observed_on", evidence=_object_evidence(alert))
            edges[edge["id"]] = edge
        for indicator in alert.ioc:
            indicator_node_id = _indicator_node_id(indicator)
            nodes.setdefault(indicator_node_id, _indicator_node(indicator))
            edge = _edge(node_id, indicator_node_id, "contains_ioc", evidence=_object_evidence(alert))
            edges[edge["id"]] = edge
            for resolved_entity in _resolve_indicator_entities(indicator, asset_ip_index, asset_hostname_index, asset_domain_index):
                resolved_edge = _edge(indicator_node_id, resolved_entity, "resolves_to", confidence="medium")
                edges[resolved_edge["id"]] = resolved_edge

    for event in honeypot_events:
        node_id = _object_node_id("honeypot_event", event.id)
        label = event.event_type or event.threat_label or event.id
        nodes[node_id] = _object_node("honeypot_event", event.id, label, event)
        _annotation(annotations, "honeypot_event", event.id)["node_id"] = node_id
        for relation, value in (("source_ip", event.source_ip), ("target_ip", event.target_ip)):
            if not value:
                continue
            indicator_node_id = _indicator_node_id(value)
            nodes.setdefault(indicator_node_id, _indicator_node(value))
            edge = _edge(node_id, indicator_node_id, relation, evidence=_object_evidence(event))
            edges[edge["id"]] = edge
            for resolved_entity in _resolve_indicator_entities(value, asset_ip_index, asset_hostname_index, asset_domain_index):
                resolved_edge = _edge(indicator_node_id, resolved_entity, "resolves_to", confidence="medium")
                edges[resolved_edge["id"]] = resolved_edge

    for incident in incidents:
        node_id = _object_node_id("incident", incident.id)
        nodes[node_id] = _object_node("incident", incident.id, incident.title, incident)
        _annotation(annotations, "incident", incident.id)["node_id"] = node_id
        for asset_id in incident.asset_ids:
            entity_id = asset_to_entity.get(asset_id)
            if entity_id:
                edge = _edge(node_id, entity_id, "involves", evidence=_object_evidence(incident))
                edges[edge["id"]] = edge
        for object_type, object_ids in (
            ("vulnerability", incident.vulnerability_ids),
            ("alert", incident.alert_ids),
            ("honeypot_event", incident.honeypot_event_ids),
        ):
            for object_id in object_ids:
                target_node = _object_node_id(object_type, object_id)
                if target_node in nodes:
                    edge = _edge(node_id, target_node, "uses_evidence", evidence=_object_evidence(incident))
                    edges[edge["id"]] = edge

    _derive_annotations(annotations, nodes, edges, asset_to_entity, merge_candidates, conflicts, built_at)
    if annotate_store:
        await _annotate_store(store, annotations)

    graph = {
        "version": EVIDENCE_GRAPH_VERSION,
        "updated_at": built_at,
        "summary": _build_summary(
            nodes=nodes,
            edges=edges,
            entities=entity_records,
            merge_candidates=merge_candidates,
            conflicts=conflicts,
            assets=assets,
            vulnerabilities=vulnerabilities,
            alerts=alerts,
            incidents=incidents,
            honeypot_events=honeypot_events,
            path=path,
        ),
        "nodes": sorted(nodes.values(), key=lambda item: str(item.get("id") or "")),
        "edges": sorted(edges.values(), key=lambda item: str(item.get("id") or "")),
        "entities": sorted(entity_records, key=lambda item: str(item.get("id") or "")),
        "merge_candidates": sorted(merge_candidates, key=lambda item: str(item.get("id") or "")),
        "conflicts": sorted(conflicts, key=lambda item: str(item.get("id") or "")),
        "indexes": {
            "asset_entity_by_asset_id": asset_to_entity,
            "nodes_by_kind": _nodes_by_kind(nodes),
        },
    }
    return save_evidence_graph(graph, path)


def _empty_summary() -> dict[str, Any]:
    return {
        "version": EVIDENCE_GRAPH_VERSION,
        "path": str(evidence_graph_path_or_default()),
        "updated_at": None,
        "nodes": 0,
        "edges": 0,
        "asset_entities": 0,
        "merge_candidates": 0,
        "conflicts": 0,
        "objects": {
            "assets": 0,
            "vulnerabilities": 0,
            "alerts": 0,
            "incidents": 0,
            "honeypot_events": 0,
        },
        "connector_sources": [],
    }


def _build_summary(
    *,
    nodes: dict[str, dict[str, Any]],
    edges: dict[str, dict[str, Any]],
    entities: list[dict[str, Any]],
    merge_candidates: list[dict[str, Any]],
    conflicts: list[dict[str, Any]],
    assets: list[Asset],
    vulnerabilities: list[Vulnerability],
    alerts: list[Alert],
    incidents: list[Incident],
    honeypot_events: list[HoneypotEvent],
    path: Path | None,
) -> dict[str, Any]:
    connector_sources = sorted(
        {
            str(evidence.get("connector_id"))
            for item in [*assets, *vulnerabilities, *alerts, *incidents, *honeypot_events]
            for evidence in [_object_evidence(item)]
            if evidence.get("connector_id")
        }
    )
    return {
        "version": EVIDENCE_GRAPH_VERSION,
        "path": str(evidence_graph_path_or_default(path)),
        "updated_at": utc_now(),
        "nodes": len(nodes),
        "edges": len(edges),
        "asset_entities": len(entities),
        "merge_candidates": len(merge_candidates),
        "conflicts": len(conflicts),
        "objects": {
            "assets": len(assets),
            "vulnerabilities": len(vulnerabilities),
            "alerts": len(alerts),
            "incidents": len(incidents),
            "honeypot_events": len(honeypot_events),
        },
        "connector_sources": connector_sources,
    }


def _resolve_asset_groups(assets: list[Asset], asset_profiles: dict[str, dict[str, Any]]) -> list[list[Asset]]:
    union = _UnionFind()
    asset_by_id = {asset.id: asset for asset in assets}
    for asset in assets:
        union.add(asset.id)
    for index, left in enumerate(assets):
        left_profile = asset_profiles.get(left.id, {})
        for right in assets[index + 1:]:
            right_profile = asset_profiles.get(right.id, {})
            comparison = compare_asset_identity(left_profile, right_profile)
            if comparison.get("auto_merge"):
                union.union(left.id, right.id)
    groups: dict[str, list[Asset]] = defaultdict(list)
    for asset_id in asset_by_id:
        groups[union.find(asset_id)].append(asset_by_id[asset_id])
    return [sorted(items, key=lambda asset: asset.id) for items in groups.values()]


def _build_asset_entity(group_assets: list[Asset], asset_keys: dict[str, list[str]]) -> dict[str, Any]:
    keys = sorted({key for asset in group_assets for key in asset_keys.get(asset.id, [])})
    basis = keys or [f"asset_id:{asset.id}" for asset in group_assets]
    entity_id = f"entity:asset:{_hash({'type': 'asset', 'keys': basis})[:16]}"
    label_asset = _preferred_asset(group_assets)
    return {
        "id": entity_id,
        "kind": "entity",
        "entity_type": "asset",
        "label": label_asset.name,
        "asset_ids": [asset.id for asset in group_assets],
        "object_ids": [asset.id for asset in group_assets],
        "identity_keys": keys,
        "confidence": "high" if len(group_assets) > 1 and keys else "medium" if keys else "low",
        "sources": _sources_for_objects(group_assets),
        "properties": {
            "primary_asset_id": label_asset.id,
            "asset_count": len(group_assets),
            "ips": sorted({asset.ip for asset in group_assets if asset.ip}),
            "hostnames": sorted({asset.hostname for asset in group_assets if asset.hostname}),
            "domains": sorted({asset.domain for asset in group_assets if asset.domain}),
        },
    }


def _preferred_asset(assets: list[Asset]) -> Asset:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return sorted(assets, key=lambda item: (rank.get(str(item.importance), 0), item.updated_at or item.created_at), reverse=True)[0]


def _candidate_asset_pairs(
    assets: list[Asset],
    asset_profiles: dict[str, dict[str, Any]],
    asset_to_entity: dict[str, str],
) -> list[dict[str, Any]]:
    candidates = []
    for index, left in enumerate(assets):
        left_profile = asset_profiles.get(left.id, {})
        for right in assets[index + 1:]:
            if asset_to_entity.get(left.id) == asset_to_entity.get(right.id):
                continue
            comparison = compare_asset_identity(left_profile, asset_profiles.get(right.id, {}))
            if not comparison.get("candidate"):
                continue
            candidates.append(
                _merge_candidate(
                    {"id": f"candidate:{left.id}:{right.id}"},
                    [left, right],
                    list(comparison.get("matching_keys") or []),
                    status="candidate",
                    confidence=str(comparison.get("confidence") or "low"),
                    reason="asset_identity_candidate",
                    score=int(comparison.get("score") or 0),
                    rules=list(comparison.get("reasons") or []),
                    entity_ids=sorted({asset_to_entity.get(left.id, ""), asset_to_entity.get(right.id, "")} - {""}),
                )
            )
    return candidates


def _merge_candidate(
    entity: dict[str, Any],
    assets: list[Asset],
    matching_keys: list[dict[str, Any]],
    *,
    status: str = "candidate",
    confidence: str | None = None,
    reason: str = "shared_asset_identity_key",
    score: int | None = None,
    rules: list[str] | None = None,
    entity_ids: list[str] | None = None,
) -> dict[str, Any]:
    asset_ids = [asset.id for asset in assets]
    payload = {
        "id": f"merge-candidate:{_hash({'entity_id': entity['id'], 'assets': asset_ids, 'status': status})[:16]}",
        "entity_id": entity["id"],
        "object_type": "asset",
        "asset_ids": asset_ids,
        "matching_keys": matching_keys,
        "confidence": confidence or ("high" if matching_keys else "medium"),
        "sources": _sources_for_objects(assets),
        "status": status,
        "reason": reason,
    }
    if score is not None:
        payload["score"] = score
    if rules:
        payload["rules"] = rules
    if entity_ids:
        payload["entity_ids"] = entity_ids
    return payload


def _asset_conflicts(entity: dict[str, Any], assets: list[Asset]) -> list[dict[str, Any]]:
    conflicts = []
    for field in ASSET_CONFLICT_FIELDS:
        values: dict[str, dict[str, Any]] = {}
        for asset in assets:
            value = getattr(asset, field, None)
            normalized = _normalize_identity_value(value)
            if normalized in UNKNOWN_VALUES:
                continue
            values.setdefault(str(value), {"value": value, "asset_ids": [], "sources": []})
            values[str(value)]["asset_ids"].append(asset.id)
            values[str(value)]["sources"].extend(_sources_for_objects([asset]))
        if len(values) <= 1:
            continue
        value_records = []
        for record in values.values():
            value_records.append(
                {
                    "value": record["value"],
                    "asset_ids": sorted(set(record["asset_ids"])),
                    "sources": sorted(set(record["sources"])),
                }
            )
        conflicts.append(
            {
                "id": f"conflict:{_hash({'entity_id': entity['id'], 'field': field, 'values': value_records})[:16]}",
                "entity_id": entity["id"],
                "object_type": "asset",
                "field": field,
                "values": sorted(value_records, key=lambda item: str(item["value"])),
                "severity": "high" if field in {"importance", "exposure_level"} else "medium",
                "status": "open",
            }
        )
    return conflicts


def _asset_identity_keys(profile: dict[str, Any]) -> list[str]:
    keys = profile.get("identity_keys")
    if isinstance(keys, list):
        return sorted({str(key) for key in keys if key not in (None, "", [], {})})
    return []


def _asset_identity_index(
    asset_to_entity: dict[str, str],
    field: str,
    asset_profiles: dict[str, dict[str, Any]],
) -> dict[str, set[str]]:
    index: dict[str, set[str]] = defaultdict(set)
    for asset_id, entity_id in asset_to_entity.items():
        profile = asset_profiles.get(asset_id, {})
        if field == "ip":
            value = _normalize_identity_value(profile.get("ip"))
            if value:
                index[value].add(entity_id)
            continue
        prefix = f"aux:{field}:"
        for key in profile.get("auxiliary_keys") or []:
            key_text = str(key)
            if key_text.startswith(prefix):
                index[key_text.removeprefix(prefix)].add(entity_id)
    return index


def _resolve_indicator_entities(
    indicator: Any,
    ip_index: dict[str, set[str]],
    hostname_index: dict[str, set[str]],
    domain_index: dict[str, set[str]],
) -> list[str]:
    value = _normalize_identity_value(indicator)
    if not value:
        return []
    entity_ids = set(ip_index.get(value, set()))
    entity_ids.update(hostname_index.get(value, set()))
    entity_ids.update(domain_index.get(value, set()))
    return sorted(entity_ids)


def _object_node(object_type: str, object_id: str, label: str, obj: Any) -> dict[str, Any]:
    evidence = _object_evidence(obj)
    return {
        "id": _object_node_id(object_type, object_id),
        "kind": "object",
        "object_type": object_type,
        "object_id": object_id,
        "label": label,
        "sources": _sources_for_objects([obj]),
        "evidence": evidence,
        "properties": _object_properties(object_type, obj),
    }


def _object_properties(object_type: str, obj: Any) -> dict[str, Any]:
    data = obj.model_dump(mode="json") if hasattr(obj, "model_dump") else {}
    allowed = {
        "asset": ["ip", "hostname", "domain", "importance", "exposure_level", "environment"],
        "vulnerability": ["asset_id", "cve_id", "severity", "status", "discovered_at"],
        "alert": ["asset_id", "source", "severity", "status", "ioc", "mitre_technique", "occurred_at"],
        "honeypot_event": ["source_ip", "target_ip", "protocol", "service", "event_type", "occurred_at"],
        "incident": ["severity", "status", "asset_ids", "vulnerability_ids", "alert_ids", "honeypot_event_ids"],
    }.get(object_type, [])
    return {key: data.get(key) for key in allowed if data.get(key) not in (None, "", [], {})}


def _indicator_node(value: Any) -> dict[str, Any]:
    text = str(value)
    return {
        "id": _indicator_node_id(text),
        "kind": "indicator",
        "indicator_type": _indicator_type(text),
        "label": text,
        "value": text,
        "properties": {},
    }


def _indicator_type(value: str) -> str:
    normalized = _normalize_identity_value(value)
    if normalized.count(".") == 3 and all(part.isdigit() for part in normalized.split(".")):
        return "ip"
    if "." in normalized:
        return "domain"
    if len(normalized) in {32, 40, 64} and all(ch in "0123456789abcdef" for ch in normalized):
        return "hash"
    return "unknown"


def _edge(
    from_node: str,
    to_node: str,
    relation: str,
    *,
    confidence: str = "high",
    evidence: dict[str, Any] | None = None,
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "from": from_node,
        "to": to_node,
        "relation": relation,
        "evidence": evidence or {},
        "properties": properties or {},
    }
    return {
        "id": f"edge:{_hash(payload)[:20]}",
        "from": from_node,
        "to": to_node,
        "relation": relation,
        "confidence": confidence,
        "evidence": evidence or {},
        "properties": properties or {},
    }


def _derive_annotations(
    annotations: dict[tuple[str, str], dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    edges: dict[str, dict[str, Any]],
    asset_to_entity: dict[str, str],
    merge_candidates: list[dict[str, Any]],
    conflicts: list[dict[str, Any]],
    rebuilt_at: str,
) -> None:
    for edge in edges.values():
        for side, other_side in (("from", "to"), ("to", "from")):
            object_ref = _object_ref(nodes.get(str(edge.get(side))))
            if not object_ref:
                continue
            annotation = _annotation(annotations, object_ref[0], object_ref[1])
            annotation["edge_ids"].add(edge["id"])
            annotation["related_node_ids"].add(str(edge.get(other_side)))
            other_node = nodes.get(str(edge.get(other_side))) or {}
            if other_node.get("kind") == "entity":
                annotation["entity_ids"].add(str(other_node["id"]))
    for asset_id, entity_id in asset_to_entity.items():
        annotation = _annotation(annotations, "asset", asset_id)
        annotation["entity_id"] = entity_id
        annotation["entity_ids"].add(entity_id)
    for candidate in merge_candidates:
        for asset_id in candidate.get("asset_ids", []):
            _annotation(annotations, "asset", str(asset_id))["merge_candidate_ids"].add(candidate["id"])
    for conflict in conflicts:
        for record in conflict.get("values", []):
            for asset_id in record.get("asset_ids", []):
                _annotation(annotations, "asset", str(asset_id))["conflict_ids"].add(conflict["id"])
    for annotation in annotations.values():
        annotation["version"] = EVIDENCE_GRAPH_VERSION
        annotation["rebuilt_at"] = rebuilt_at
        for key in ("entity_ids", "edge_ids", "related_node_ids", "merge_candidate_ids", "conflict_ids"):
            annotation[key] = sorted(annotation[key])


async def _annotate_store(store: SecurityStore, annotations: dict[tuple[str, str], dict[str, Any]]) -> None:
    for (object_type, object_id), annotation in annotations.items():
        if not object_id:
            continue
        obj = await _get_object(store, object_type, object_id)
        if obj is None:
            continue
        data = obj.model_dump(mode="json")
        normalized_data = data.get("normalized_data") if isinstance(data.get("normalized_data"), dict) else {}
        normalized_data["evidence_graph"] = annotation
        data["normalized_data"] = normalized_data
        await _upsert_object(store, object_type, data)


async def _get_object(store: SecurityStore, object_type: str, object_id: str) -> Any | None:
    if object_type == "asset":
        return await store.get_asset(object_id)
    if object_type == "vulnerability":
        return await store.get_vulnerability(object_id)
    if object_type == "alert":
        return await store.get_alert(object_id)
    if object_type == "incident":
        return await store.get_incident(object_id)
    if object_type == "honeypot_event":
        return await store.get_honeypot_event(object_id)
    return None


async def _upsert_object(store: SecurityStore, object_type: str, data: dict[str, Any]) -> None:
    if object_type == "asset":
        await store.upsert_asset(data)
    elif object_type == "vulnerability":
        await store.upsert_vulnerability(data)
    elif object_type == "alert":
        await store.upsert_alert(data)
    elif object_type == "incident":
        await store.upsert_incident(data)
    elif object_type == "honeypot_event":
        await store.upsert_honeypot_event(data)


def _annotation(annotations: dict[tuple[str, str], dict[str, Any]], object_type: str, object_id: str) -> dict[str, Any]:
    return annotations.setdefault(
        (object_type, object_id),
        {
            "version": EVIDENCE_GRAPH_VERSION,
            "node_id": _object_node_id(object_type, object_id),
            "entity_id": None,
            "entity_ids": set(),
            "edge_ids": set(),
            "related_node_ids": set(),
            "merge_candidate_ids": set(),
            "conflict_ids": set(),
            "rebuilt_at": None,
        },
    )


def _object_ref(node: dict[str, Any] | None) -> tuple[str, str] | None:
    if not node or node.get("kind") != "object":
        return None
    object_type = node.get("object_type")
    object_id = node.get("object_id")
    if not object_type or not object_id:
        return None
    return str(object_type), str(object_id)


def _object_node_id(object_type: str, object_id: str) -> str:
    return f"{object_type}:{object_id}"


def _indicator_node_id(value: Any) -> str:
    return f"ioc:{_hash(_normalize_identity_value(value))[:16]}"


def _nodes_by_kind(nodes: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    by_kind: dict[str, list[str]] = defaultdict(list)
    for node in nodes.values():
        by_kind[str(node.get("kind") or "unknown")].append(str(node["id"]))
    return {key: sorted(value) for key, value in by_kind.items()}


def _object_evidence(obj: Any) -> dict[str, Any]:
    data = obj.model_dump(mode="json") if hasattr(obj, "model_dump") else {}
    raw_data = data.get("raw_data") if isinstance(data.get("raw_data"), dict) else {}
    normalized_data = data.get("normalized_data") if isinstance(data.get("normalized_data"), dict) else {}
    for envelope in (normalized_data.get("connector_evidence"), raw_data.get("connector_evidence")):
        if isinstance(envelope, dict):
            return {
                "connector_id": envelope.get("connector_id"),
                "capability": envelope.get("capability"),
                "sync_run_id": envelope.get("sync_run_id"),
                "credential_profile_id": envelope.get("credential_profile_id"),
                "device_id": envelope.get("device_id"),
                "source_instance_id": envelope.get("source_instance_id"),
                "source_system": envelope.get("source_system"),
                "source_object_id": envelope.get("source_object_id"),
                "source_fingerprint": envelope.get("source_fingerprint"),
                "source_timestamp": envelope.get("source_timestamp"),
                "quality_status": envelope.get("quality_status"),
                "confidence": envelope.get("confidence"),
            }
    return {}


def _sources_for_objects(objects: list[Any]) -> list[str]:
    sources = []
    for obj in objects:
        evidence = _object_evidence(obj)
        source = evidence.get("source_system") or evidence.get("connector_id")
        if source:
            sources.append(str(source))
    return sorted(set(sources))


def _asset_entity_confidence(keys: list[str]) -> str:
    if any(key.startswith("strong:") for key in keys):
        return "high"
    if any(key.startswith("aux:") for key in keys):
        return "medium"
    return "low"


def _nested_value(data: dict[str, Any], field: str) -> Any:
    if not isinstance(data, dict):
        return None
    if field in data:
        return data[field]
    response = data.get("response")
    if isinstance(response, dict) and field in response:
        return response[field]
    return None


def _normalize_identity_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True).strip().lower()
    return str(value).strip().lower()


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()
