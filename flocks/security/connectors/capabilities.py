"""Connector capability helpers."""

from __future__ import annotations

from flocks.security.connectors.models import ConnectorCapability


READ_ONLY_CAPABILITIES = {
    ConnectorCapability.ASSET_SEARCH,
    ConnectorCapability.ASSET_GET,
    ConnectorCapability.VULNERABILITY_SEARCH,
    ConnectorCapability.VULNERABILITY_GET,
    ConnectorCapability.ALERT_SEARCH,
    ConnectorCapability.ALERT_GET,
    ConnectorCapability.ALERT_TRIAGE_CONTEXT,
    ConnectorCapability.EVENT_SEARCH,
    ConnectorCapability.EVENT_TIMELINE,
    ConnectorCapability.ENDPOINT_QUERY,
    ConnectorCapability.TRAFFIC_QUERY,
    ConnectorCapability.FLOW_QUERY,
    ConnectorCapability.THREAT_INTEL_LOOKUP,
    ConnectorCapability.HONEYPOT_EVENT_SEARCH,
}

WRITE_CAPABILITIES = {
    ConnectorCapability.ASSET_SYNC,
    ConnectorCapability.VULNERABILITY_SYNC,
    ConnectorCapability.CASE_CREATE,
    ConnectorCapability.CASE_UPDATE,
    ConnectorCapability.NOTIFICATION_SEND,
    ConnectorCapability.REPORT_GENERATE,
}


def missing_capabilities(
    available: list[ConnectorCapability] | list[str],
    required: list[ConnectorCapability] | list[str],
) -> list[str]:
    available_values = {str(item) for item in available}
    return [str(item) for item in required if str(item) not in available_values]


def capability_downgrade_message(
    available: list[ConnectorCapability] | list[str],
    required: list[ConnectorCapability] | list[str],
) -> str | None:
    missing = missing_capabilities(available, required)
    if not missing:
        return None
    return f"Connector missing capabilities: {', '.join(missing)}. Workflow should continue with available evidence."
