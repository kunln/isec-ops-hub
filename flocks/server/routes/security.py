"""Security Extension HTTP API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, Response, UploadFile, status
from pydantic import BaseModel

from flocks.commercial.access_control import require_capability
from flocks.server.auth import get_optional_user
from flocks.security.analysis import apply_confirmation_to_case, build_analysis_case_from_alert, build_notification_for_case, run_initial_analysis
from flocks.security.analysis_report import generate_analysis_case_brief
from flocks.security.analysis_sample_data import clear_analysis_sample_data, load_analysis_sample_data
from flocks.security.correlation import correlate_alert
from flocks.security.connector_runs import (
    record_connector_run,
    sanitize_connector_request_summary,
)
from flocks.security.connectors import connector_registry
from flocks.security.evidence_ingestion import ingest_external_events, summarize_external_event
from flocks.security.fact_ledger import summarize_fact_ledger
from flocks.security.integrations import create_default_integration_registry
from flocks.security.integrations.evidence_dispatcher import (
    EvidenceDispatchRequest,
    dispatch_evidence_events as dispatch_integration_evidence_events,
)
from flocks.security.integrations.instance_store import default_integration_instance_store
from flocks.security.integrations.instances import IntegrationInstance, IntegrationInstanceCreate, IntegrationInstanceUpdate
from flocks.security.integrations.models import IntegrationCapability, IntegrationPackageManifest
from flocks.security.connectors.mingyu_apt import MingyuAptClient, ingest_mingyu_apt_risks
from flocks.security.connectors.tda import TdaClient, ingest_tda_events
from flocks.security.connectors.expiry_monitor import connector_credential_expiry_monitor_scheduler
from flocks.security.connectors.package_staging import MAX_UPLOAD_BYTES
from flocks.security.connectors.scheduler import connector_sync_scheduler
from flocks.security.models import (
    AnalysisCase,
    AnalysisCaseSeverity,
    AnalysisCaseStatus,
    AnalysisDisposition,
    Confidence,
    FactStrength,
    Incident,
    IncidentDecision,
    IncidentSeverity,
)
from flocks.security.prioritization import prioritize_vulnerabilities
from flocks.security.profile import build_asset_risk_profile
from flocks.security.report import generate_incident_report
from flocks.security.sample_data import clear_sample_data, load_sample_data
from flocks.security.schemas import (
    AlertCreate,
    AlertUpdate,
    AnalysisCaseCreate,
    AnalysisCaseUpdate,
    AnalysisConfirmationCreate,
    AnalysisNotificationCreate,
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
from flocks.security.store import default_store, utc_now
from flocks.security.triage import triage_alert



class MingyuAptIngestRequest(BaseModel):
    base_url: str
    apikey: str
    begin: str
    end: str
    mode: str = "risk"
    limit: int = 20
    max_pages: int = 1
    create_analysis_cases: bool = True
    run_initial_analysis: bool = True
    deduplicate: bool = True
    verify_ssl: bool = False


class MingyuAptTestRequest(BaseModel):
    base_url: str
    apikey: str
    verify_ssl: bool = False

class TdaIngestRequest(BaseModel):
    base_url: str
    api_key: str
    secret: str
    begin: str | None = None
    end: str | None = None
    time_type: int = 1
    mode: str = "alert"
    limit: int = 20
    max_pages: int = 1
    create_analysis_cases: bool = True
    run_initial_analysis: bool = True
    deduplicate: bool = True
    verify_ssl: bool = False


class TdaTestRequest(BaseModel):
    base_url: str
    api_key: str
    secret: str
    verify_ssl: bool = False


class EvidenceIngestionRequest(BaseModel):
    connector_context: dict[str, Any] | None = None
    events: list[dict[str, Any]]
    create_analysis_cases: bool = True
    run_initial_analysis: bool = True
    deduplicate: bool = True


class EvidenceDispatchAPIRequest(BaseModel):
    events: list[dict[str, Any]]
    connector_context: dict[str, Any] | None = None
    create_analysis_cases: bool = False
    run_initial_analysis: bool = False
    deduplicate: bool = True
    preview_only: bool = True


def _analysis_case_incident_severity(severity: str) -> IncidentSeverity:
    mapping = {
        AnalysisCaseSeverity.CRITICAL.value: IncidentSeverity.CRITICAL,
        AnalysisCaseSeverity.HIGH.value: IncidentSeverity.HIGH,
        AnalysisCaseSeverity.MEDIUM.value: IncidentSeverity.MEDIUM,
        AnalysisCaseSeverity.LOW.value: IncidentSeverity.LOW,
        AnalysisCaseSeverity.INFORMATIONAL.value: IncidentSeverity.LOW,
    }
    return mapping.get(str(severity), IncidentSeverity.MEDIUM)


def _analysis_case_asset_ids(case: AnalysisCase) -> list[str]:
    seen: set[str] = set()
    asset_ids: list[str] = []
    for asset_id in [case.primary_asset_id, *case.related_asset_ids]:
        if asset_id and asset_id not in seen:
            seen.add(asset_id)
            asset_ids.append(asset_id)
    return asset_ids


def _analysis_case_evidence(case: AnalysisCase) -> list[str]:
    evidence: list[str] = []
    for fact in case.facts:
        evidence.append(f"Fact[{fact.id or fact.fact_type}] {fact.statement} (source: {fact.source_ref})")
    for item in case.evidence_items:
        evidence.append(f"Evidence[{item.id or item.title}] {item.title}: {item.description} (source: {item.source_ref})")
    for gap in case.evidence_gaps:
        impact = f" impact: {gap.impact}" if gap.impact else ""
        evidence.append(f"EvidenceGap[{gap.id or gap.gap_type}] {gap.description}{impact}")
    return evidence


def _analysis_case_timeline(case: AnalysisCase) -> list[dict[str, Any]]:
    if case.timeline:
        return case.timeline
    return [
        {
            "timestamp": fact.observed_at,
            "title": fact.fact_type,
            "description": fact.statement,
            "source_ref": fact.source_ref,
        }
        for fact in case.facts
        if fact.observed_at
    ]


def _summarize_facts(facts: list[Any], limit: int = 5) -> list[str]:
    return [getattr(fact, "statement", str(fact)) for fact in facts[:limit]]


def _summarize_gaps(gaps: list[Any], limit: int = 5) -> list[str]:
    return [getattr(gap, "description", str(gap)) for gap in gaps[:limit]]


def _analysis_case_analysis(case: AnalysisCase) -> str:
    lines = [
        f"Verdict: {case.verdict}",
        f"Confidence: {case.confidence}",
        f"Evidence coverage: {case.evidence_coverage}",
        f"Analysis mode: {case.analysis_mode}",
    ]
    facts = _summarize_facts(case.facts)
    gaps = _summarize_gaps(case.evidence_gaps)
    if facts:
        lines.append("Key facts:")
        lines.extend(f"- {fact}" for fact in facts)
    if gaps:
        lines.append("Evidence gaps:")
        lines.extend(f"- {gap}" for gap in gaps)
    return "\n".join(lines)


def _analysis_case_summary(case: AnalysisCase) -> str:
    if case.summary:
        return case.summary
    return f"Analysis case {case.id} was manually escalated to an incident for {case.title}."


def _analysis_case_recommendation(case: AnalysisCase) -> str:
    return "\n".join(f"- {item}" for item in case.recommendations)

router = APIRouter(dependencies=[Depends(require_capability("security.ops.read"))])


class ConnectorPackageInstallRequest(BaseModel):
    package_root: str
    enabled: bool = False


class ConnectorPackageStagingInstallRequest(BaseModel):
    enabled: bool = False


class ConnectorCredentialBindRequest(BaseModel):
    values: dict[str, str]
    secret_keys: list[str] = []
    profile_id: str = "default"
    profile_name: str | None = None
    make_active: bool = True
    expires_at: str | None = None
    recover_policy_paused_schedules: str = "preview"


class ConnectorCredentialRotateRequest(BaseModel):
    values: dict[str, str]
    secret_keys: list[str] = []
    make_active: bool = True
    expires_at: str | None = None
    recover_policy_paused_schedules: str = "preview"


class ConnectorPolicyPauseRecoveryRequest(BaseModel):
    mode: str = "preview"


class ConnectorCustomerTestRequest(BaseModel):
    profile_id: str | None = None


class ConnectorCustomerCredentialUpdateRequest(BaseModel):
    values: dict[str, str]
    secret_keys: list[str] = []
    profile_id: str = "default"
    profile_name: str | None = None
    make_active: bool = True
    expires_at: str | None = None


class ConnectorCustomerDeviceSyncRequest(BaseModel):
    device_id: str
    profile_id: str | None = None
    enabled: bool = True
    interval_seconds: int = 3600
    mode: str = "incremental"
    capabilities: list[str] | None = None


class ConnectorCredentialExpiryMonitorRequest(BaseModel):
    days: int | None = None
    notify: bool | None = None


class ConnectorOperationEventsBulkAckRequest(BaseModel):
    event_ids: list[str]


class ConnectorOperationsSettingsUpdate(BaseModel):
    retention: dict[str, Any] | None = None
    expiry_monitor: dict[str, Any] | None = None
    notifications: dict[str, Any] | None = None


class ConnectorBulkCredentialItem(BaseModel):
    connector_id: str
    profile_id: str


class ConnectorBulkRemediationRequest(BaseModel):
    items: list[ConnectorBulkCredentialItem]
    action: str
    recovery_mode: str = "enable"
    notify: bool = True


class ConnectorSyncRequest(BaseModel):
    capability: str
    mode: str = "full"
    reset_cursor: bool = False
    credential_profile_id: str | None = None


class ConnectorSyncCancelRequest(BaseModel):
    capability: str | None = None


class ConnectorSyncDeadLetterReplayRequest(BaseModel):
    ids: list[str] = []
    connector_id: str | None = None
    limit: int = 50
    payload_updates: dict[str, dict[str, Any]] = {}


class ConnectorSyncCursorResetRequest(BaseModel):
    capability: str | None = None


class ConnectorSyncScheduleRequest(BaseModel):
    capability: str
    enabled: bool = False
    interval_seconds: int = 3600
    mode: str = "incremental"
    full_interval_seconds: int | None = None
    retry_max_attempts: int = 1
    retry_backoff_seconds: int = 60
    timeout_seconds: int = 300
    credential_profile_id: str | None = None


class ConnectorSyncScheduleRunRequest(BaseModel):
    mode: str | None = None


def _filters(
    asset_id: str | None = None,
    severity: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    source: str | None = None,
    keyword: str | None = None,
    ip: str | None = None,
    domain: str | None = None,
    hostname: str | None = None,
    importance: str | None = None,
    exposure_level: str | None = None,
    cve_id: str | None = None,
    ioc: str | None = None,
    mitre_technique: str | None = None,
    limit: int = Query(100, ge=1, le=500),
) -> SecurityListFilters:
    return SecurityListFilters(
        asset_id=asset_id,
        severity=severity,
        status=status_filter,
        source=source,
        keyword=keyword,
        ip=ip,
        domain=domain,
        hostname=hostname,
        importance=importance,
        exposure_level=exposure_level,
        cve_id=cve_id,
        ioc=ioc,
        mitre_technique=mitre_technique,
        limit=limit,
    )


def _not_found(kind: str, object_id: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{kind} not found: {object_id}")


def _connector_package_error(exc: ValueError, package_id: str | None = None) -> HTTPException:
    detail = str(exc)
    if "not installed" in detail.lower() and package_id:
        return _not_found("Connector package", package_id)
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _actor_from_request(request: Request) -> dict[str, Any]:
    user = get_optional_user(request)
    if user is None:
        return {"type": "system", "id": "system", "username": "system", "role": "system"}
    return {"type": "user", "id": user.id, "username": user.username, "role": user.role}


@router.get("/health")
async def health():
    assets = await default_store.list_assets(SecurityListFilters(limit=500))
    vulnerabilities = await default_store.list_vulnerabilities(SecurityListFilters(limit=500))
    alerts = await default_store.list_alerts(SecurityListFilters(limit=500))
    incidents = await default_store.list_incidents(SecurityListFilters(limit=500))
    analysis_cases = await default_store.list_analysis_cases(SecurityListFilters(limit=500))
    honeypot_events = await default_store.list_honeypot_events(SecurityListFilters(limit=500))
    return {
        "status": "ok",
        "extension": "security",
        "storage_prefixes": [
            "security/assets/",
            "security/vulnerabilities/",
            "security/alerts/",
            "security/incidents/",
            "security/analysis-cases/",
            "security/honeypot-events/",
        ],
        "counts": {
            "assets": len(assets),
            "vulnerabilities": len(vulnerabilities),
            "alerts": len(alerts),
            "incidents": len(incidents),
            "analysis_cases": len(analysis_cases),
            "honeypot_events": len(honeypot_events),
            "connectors": len(connector_registry.list()),
        },
    }


@router.get("/evidence-graph")
async def get_evidence_graph_route():
    return connector_registry.evidence_graph()


@router.post("/evidence-graph/rebuild", dependencies=[Depends(require_capability("security.ops.write"))])
async def rebuild_evidence_graph_route():
    return await connector_registry.rebuild_evidence_graph()




def _integration_registry():
    return create_default_integration_registry()


def _integration_package_manifest(package_id: str) -> IntegrationPackageManifest:
    package = _integration_registry().get_package(package_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Integration package not found")
    return package.manifest


@router.get("/integrations/packages", response_model=list[IntegrationPackageManifest])
async def list_integration_packages():
    """List built-in Integration Package metadata without runtime side effects."""

    return [package.manifest for package in _integration_registry().list_packages()]


@router.get("/integrations/packages/{package_id}", response_model=IntegrationPackageManifest)
async def get_integration_package(package_id: str):
    """Return one built-in Integration Package manifest by id."""

    return _integration_package_manifest(package_id)




def _instance_validation_error(exc: ValueError) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


@router.get("/integrations/instances", response_model=list[IntegrationInstance])
async def list_integration_instances(package_id: str | None = None, enabled: bool | None = None):
    """List Integration Instance metadata without connector side effects."""

    return await default_integration_instance_store.list_instances(package_id=package_id, enabled=enabled)


@router.post(
    "/integrations/instances",
    response_model=IntegrationInstance,
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def create_integration_instance(payload: IntegrationInstanceCreate):
    """Create Integration Instance metadata only.

    Credential values, connection tests, sync, connector calls, and Security
    object creation are intentionally out of scope for this skeleton.
    """

    try:
        return await default_integration_instance_store.create_instance(payload)
    except ValueError as exc:
        raise _instance_validation_error(exc) from exc


@router.get("/integrations/instances/{instance_id}", response_model=IntegrationInstance)
async def get_integration_instance(instance_id: str):
    instance = await default_integration_instance_store.get_instance(instance_id)
    if instance is None:
        raise HTTPException(status_code=404, detail="Integration instance not found")
    return instance


@router.patch(
    "/integrations/instances/{instance_id}",
    response_model=IntegrationInstance,
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def update_integration_instance(instance_id: str, payload: IntegrationInstanceUpdate):
    try:
        instance = await default_integration_instance_store.update_instance(instance_id, payload)
    except ValueError as exc:
        raise _instance_validation_error(exc) from exc
    if instance is None:
        raise HTTPException(status_code=404, detail="Integration instance not found")
    return instance


@router.delete("/integrations/instances/{instance_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def delete_integration_instance(instance_id: str):
    if not await default_integration_instance_store.delete_instance(instance_id):
        raise HTTPException(status_code=404, detail="Integration instance not found")
    return {"status": "deleted", "instance_id": instance_id}


@router.get("/integrations/capabilities", response_model=list[IntegrationCapability])
async def list_integration_capabilities():
    """List built-in Integration Package capability metadata."""

    return _integration_registry().list_capabilities()

@router.get("/connectors")
async def list_connectors():
    return connector_registry.list()


@router.get("/connectors/package-diagnostics")
async def connector_package_diagnostics():
    return await connector_registry.package_diagnostics()


@router.get("/connectors/customer-summary")
async def connector_customer_summary(trend_days: int = Query(14, ge=1, le=14)):
    return await connector_registry.customer_summary(trend_days=trend_days)


@router.post("/connectors/packages/install", dependencies=[Depends(require_capability("security.ops.write"))])
async def install_connector_package_route(payload: ConnectorPackageInstallRequest):
    try:
        return await connector_registry.install_package(payload.package_root, enabled=payload.enabled)
    except ValueError as exc:
        raise _connector_package_error(exc) from exc


@router.get("/connectors/packages/staging")
async def list_connector_package_staging_route():
    return {"items": connector_registry.list_staging_packages()}


@router.post("/connectors/packages/staging/upload", dependencies=[Depends(require_capability("security.ops.write"))])
async def upload_connector_package_staging_route(file: UploadFile = File(...)):
    content = bytearray()
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        content.extend(chunk)
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Connector package artifact is too large: {len(content)} bytes",
            )
    try:
        return await connector_registry.upload_package_artifact(file.filename or "connector-package", bytes(content))
    except ValueError as exc:
        raise _connector_package_error(exc) from exc


@router.post(
    "/connectors/packages/staging/{staging_id}/validate",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def validate_connector_package_staging_route(staging_id: str):
    try:
        return await connector_registry.validate_staging_package(staging_id)
    except ValueError as exc:
        raise _connector_package_error(exc, staging_id) from exc


@router.post(
    "/connectors/packages/staging/{staging_id}/install",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def install_connector_package_staging_route(staging_id: str, payload: ConnectorPackageStagingInstallRequest):
    try:
        return await connector_registry.install_staging_package(staging_id, enabled=payload.enabled)
    except ValueError as exc:
        raise _connector_package_error(exc, staging_id) from exc


@router.delete(
    "/connectors/packages/staging/{staging_id}",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def discard_connector_package_staging_route(staging_id: str):
    try:
        return connector_registry.discard_staging_package(staging_id)
    except ValueError as exc:
        raise _connector_package_error(exc, staging_id) from exc


@router.post("/connectors/packages/{package_id}/enable", dependencies=[Depends(require_capability("security.ops.write"))])
async def enable_connector_package_route(package_id: str):
    try:
        return await connector_registry.enable_package(package_id)
    except ValueError as exc:
        raise _connector_package_error(exc, package_id) from exc


@router.post("/connectors/packages/{package_id}/disable", dependencies=[Depends(require_capability("security.ops.write"))])
async def disable_connector_package_route(package_id: str):
    try:
        return connector_registry.disable_package(package_id)
    except ValueError as exc:
        raise _connector_package_error(exc, package_id) from exc


@router.delete("/connectors/packages/{package_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def uninstall_connector_package_route(package_id: str):
    try:
        return connector_registry.uninstall_package(package_id)
    except ValueError as exc:
        raise _connector_package_error(exc, package_id) from exc


@router.post("/connectors/packages/{package_id}/rollback", dependencies=[Depends(require_capability("security.ops.write"))])
async def rollback_connector_package_route(package_id: str):
    try:
        return await connector_registry.rollback_package(package_id)
    except ValueError as exc:
        raise _connector_package_error(exc, package_id) from exc


@router.get("/connectors/credential-bindings")
async def list_connector_credential_bindings_route():
    return {"items": connector_registry.list_credential_bindings()}


@router.get("/connectors/operations/events")
async def list_connector_operation_events_route(
    status_filter: str | None = Query(None, alias="status"),
    kind: str | None = None,
    severity: str | None = None,
    connector_id: str | None = None,
    profile_id: str | None = None,
    schedule_id: str | None = None,
    reason_code: str | None = None,
    keyword: str | None = None,
    limit: int = Query(100, ge=1, le=500),
):
    return {
        "items": connector_registry.list_operation_events(
            status=status_filter,
            kind=kind,
            severity=severity,
            connector_id=connector_id,
            profile_id=profile_id,
            schedule_id=schedule_id,
            reason_code=reason_code,
            keyword=keyword,
            limit=limit,
        )
    }


@router.get("/connectors/operations/settings")
async def get_connector_operations_settings_route():
    return connector_registry.operation_settings()


@router.patch(
    "/connectors/operations/settings",
    dependencies=[Depends(require_capability("security.ops.configure"))],
)
async def update_connector_operations_settings_route(payload: ConnectorOperationsSettingsUpdate, request: Request):
    return connector_registry.update_operation_settings(
        payload.model_dump(exclude_none=True),
        actor=_actor_from_request(request),
    )


@router.post(
    "/connectors/operations/events/ack",
    dependencies=[Depends(require_capability("security.events.ack"))],
)
async def acknowledge_connector_operation_events_route(payload: ConnectorOperationEventsBulkAckRequest, request: Request):
    return connector_registry.acknowledge_operation_events(payload.event_ids, actor=_actor_from_request(request))


@router.get("/connectors/operations/events/{event_id}")
async def get_connector_operation_event_route(event_id: str):
    event = connector_registry.get_operation_event(event_id)
    if event is None:
        raise _not_found("Connector operation event", event_id)
    return event


@router.post(
    "/connectors/operations/events/{event_id}/ack",
    dependencies=[Depends(require_capability("security.events.ack"))],
)
async def acknowledge_connector_operation_event_route(event_id: str, request: Request):
    try:
        return connector_registry.acknowledge_operation_event(event_id, actor=_actor_from_request(request))
    except ValueError as exc:
        raise _not_found("Connector operation event", event_id) from exc


@router.post(
    "/connectors/operations/events/{event_id}/notify",
    dependencies=[Depends(require_capability("security.ops.notify"))],
)
async def notify_connector_operation_event_route(event_id: str):
    try:
        return {"items": connector_registry.notify_operation_event(event_id, force=True)}
    except ValueError as exc:
        raise _not_found("Connector operation event", event_id) from exc


@router.post(
    "/connectors/credentials/expiry-monitor",
    dependencies=[Depends(require_capability("security.ops.configure"))],
)
async def monitor_connector_credential_expiry_route(payload: ConnectorCredentialExpiryMonitorRequest, request: Request):
    return connector_registry.monitor_credential_expiry(
        days=payload.days,
        notify=payload.notify,
        actor=_actor_from_request(request),
    )


@router.get("/connectors/credentials/expiry-monitor/status")
async def connector_credential_expiry_monitor_status_route():
    return connector_credential_expiry_monitor_scheduler.status()


@router.post(
    "/connectors/credentials/expiry-monitor/tick",
    dependencies=[Depends(require_capability("security.ops.configure"))],
)
async def connector_credential_expiry_monitor_tick_route():
    return await connector_credential_expiry_monitor_scheduler.tick(force=True)


@router.post(
    "/connectors/credentials/bulk-remediation",
    dependencies=[Depends(require_capability("security.bulk.manage"))],
)
async def bulk_remediate_connector_credentials_route(payload: ConnectorBulkRemediationRequest, request: Request):
    try:
        return await connector_registry.bulk_remediate_credentials(
            [item.model_dump() for item in payload.items],
            action=payload.action,
            recovery_mode=payload.recovery_mode,
            notify=payload.notify,
            actor=_actor_from_request(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.put("/connectors/{connector_id}/credentials", dependencies=[Depends(require_capability("security.credentials.manage"))])
async def bind_connector_credentials_route(connector_id: str, payload: ConnectorCredentialBindRequest, request: Request):
    try:
        return await connector_registry.bind_credentials_and_test(
            connector_id,
            payload.values,
            secret_keys=payload.secret_keys,
            profile_id=payload.profile_id,
            profile_name=payload.profile_name,
            make_active=payload.make_active,
            expires_at=payload.expires_at,
            recover_policy_paused_schedules=payload.recover_policy_paused_schedules,
            actor=_actor_from_request(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/connectors/{connector_id}/credentials")
async def get_connector_credentials_route(connector_id: str):
    binding = connector_registry.get_credential_binding(connector_id)
    if binding is None:
        raise _not_found("Connector credential binding", connector_id)
    return binding


@router.get("/connectors/{connector_id}/credentials/health")
async def get_connector_credential_health_route(connector_id: str, profile_id: str | None = None):
    return connector_registry.credential_health(connector_id, profile_id)


@router.post(
    "/connectors/{connector_id}/credentials/profiles/{profile_id}/rotate",
    dependencies=[Depends(require_capability("security.credentials.rotate"))],
)
async def rotate_connector_credentials_route(
    connector_id: str,
    profile_id: str,
    payload: ConnectorCredentialRotateRequest,
    request: Request,
):
    try:
        return await connector_registry.rotate_credentials(
            connector_id,
            profile_id,
            payload.values,
            secret_keys=payload.secret_keys,
            expires_at=payload.expires_at,
            make_active=payload.make_active,
            recover_policy_paused_schedules=payload.recover_policy_paused_schedules,
            actor=_actor_from_request(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/connectors/{connector_id}/credentials/profiles/{profile_id}/activate",
    dependencies=[Depends(require_capability("security.credentials.manage"))],
)
async def activate_connector_credential_profile_route(connector_id: str, profile_id: str, request: Request):
    try:
        return connector_registry.activate_credential_profile(connector_id, profile_id, actor=_actor_from_request(request))
    except ValueError as exc:
        raise _not_found("Connector credential profile", f"{connector_id}/{profile_id}") from exc


@router.post(
    "/connectors/{connector_id}/credentials/profiles/{profile_id}/test",
    dependencies=[Depends(require_capability("security.connectors.test"))],
)
async def test_connector_credential_profile_route(connector_id: str, profile_id: str, request: Request):
    try:
        return await connector_registry.test_credential_profile(connector_id, profile_id, actor=_actor_from_request(request))
    except ValueError as exc:
        detail = str(exc)
        if "not found" in detail.lower():
            raise _not_found("Connector credential profile", f"{connector_id}/{profile_id}") from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc


@router.post(
    "/connectors/{connector_id}/credentials/profiles/{profile_id}/policy-pauses/recover",
    dependencies=[Depends(require_capability("security.schedules.manage"))],
)
async def recover_connector_credential_policy_pauses_route(
    connector_id: str,
    profile_id: str,
    request: Request,
    payload: ConnectorPolicyPauseRecoveryRequest | None = None,
):
    try:
        return connector_registry.recover_policy_paused_schedules(
            connector_id,
            profile_id,
            mode=payload.mode if payload else "preview",
            actor=_actor_from_request(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.delete(
    "/connectors/{connector_id}/credentials/profiles/{profile_id}",
    dependencies=[Depends(require_capability("security.credentials.manage"))],
)
async def delete_connector_credential_profile_route(connector_id: str, profile_id: str, request: Request):
    try:
        return connector_registry.delete_credentials(connector_id, profile_id=profile_id, actor=_actor_from_request(request))
    except ValueError as exc:
        raise _not_found("Connector credential profile", f"{connector_id}/{profile_id}") from exc


@router.delete("/connectors/{connector_id}/credentials", dependencies=[Depends(require_capability("security.credentials.manage"))])
async def delete_connector_credentials_route(connector_id: str, request: Request):
    try:
        return connector_registry.delete_credentials(connector_id, actor=_actor_from_request(request))
    except ValueError as exc:
        raise _not_found("Connector credential binding", connector_id) from exc


@router.get("/connectors/sync-runs")
async def list_connector_sync_runs_route(
    connector_id: str | None = None,
    limit: int = Query(50, ge=1, le=200),
):
    return {"items": connector_registry.list_sync_runs(connector_id, limit=limit)}


@router.get("/connectors/sync-runs/active")
async def list_active_connector_sync_runs_route(
    connector_id: str | None = None,
    capability: str | None = None,
):
    return {"items": connector_registry.list_active_sync_runs(connector_id, capability)}


@router.post("/connectors/sync-runs/{run_id}/cancel", dependencies=[Depends(require_capability("security.schedules.manage"))])
async def cancel_connector_sync_run_route(run_id: str):
    return connector_registry.cancel_sync_run(run_id)


@router.get("/connectors/sync-cursors")
async def list_connector_sync_cursors_route(connector_id: str | None = None):
    return {"items": connector_registry.list_sync_cursors(connector_id)}


@router.get("/connectors/sync-dead-letters")
async def list_connector_sync_dead_letters_route(
    connector_id: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
):
    return {"items": connector_registry.list_sync_dead_letters(connector_id, status=status_filter, limit=limit)}


@router.post("/connectors/sync-dead-letters/replay", dependencies=[Depends(require_capability("security.schedules.manage"))])
async def replay_connector_sync_dead_letters_route(payload: ConnectorSyncDeadLetterReplayRequest):
    return await connector_registry.replay_sync_dead_letters(
        ids=payload.ids,
        connector_id=payload.connector_id,
        limit=payload.limit,
        payload_updates=payload.payload_updates,
    )


@router.get("/connectors/sync-schedules")
async def list_connector_sync_schedules_route(connector_id: str | None = None):
    return {"items": connector_registry.list_sync_schedules(connector_id)}


@router.get("/connectors/scheduler/status")
async def connector_sync_scheduler_status_route():
    return connector_sync_scheduler.status()


@router.post("/connectors/scheduler/tick", dependencies=[Depends(require_capability("security.schedules.manage"))])
async def connector_sync_scheduler_tick_route():
    return await connector_registry.run_due_sync_schedules()


@router.get("/connectors/sync-schedules/{schedule_id}")
async def get_connector_sync_schedule_route(schedule_id: str):
    schedule = connector_registry.get_sync_schedule(schedule_id)
    if schedule is None:
        raise _not_found("Connector sync schedule", schedule_id)
    return schedule


@router.post("/connectors/sync-schedules/{schedule_id}/enable", dependencies=[Depends(require_capability("security.schedules.manage"))])
async def enable_connector_sync_schedule_route(schedule_id: str, request: Request):
    try:
        return connector_registry.enable_sync_schedule(schedule_id, actor=_actor_from_request(request))
    except ValueError as exc:
        raise _not_found("Connector sync schedule", schedule_id) from exc


@router.post(
    "/connectors/sync-schedules/{schedule_id}/customer-enable",
    dependencies=[Depends(require_capability("security.schedules.manage"))],
)
async def customer_enable_connector_sync_schedule_route(schedule_id: str, request: Request):
    try:
        schedule = connector_registry.enable_sync_schedule(schedule_id, actor=_actor_from_request(request))
        return {
            "status": "enabled",
            "message": "同步调度已启用。",
            "schedule_id": schedule_id,
            "schedule": {
                "id": schedule.get("id"),
                "connector_id": schedule.get("connector_id"),
                "capability": schedule.get("capability"),
                "enabled": schedule.get("enabled"),
                "next_run_at": schedule.get("next_run_at"),
            },
        }
    except ValueError as exc:
        raise _not_found("Connector sync schedule", schedule_id) from exc


@router.post("/connectors/sync-schedules/{schedule_id}/disable", dependencies=[Depends(require_capability("security.schedules.manage"))])
async def disable_connector_sync_schedule_route(schedule_id: str, request: Request):
    try:
        return connector_registry.disable_sync_schedule(schedule_id, actor=_actor_from_request(request))
    except ValueError as exc:
        raise _not_found("Connector sync schedule", schedule_id) from exc


@router.post(
    "/connectors/sync-schedules/{schedule_id}/customer-disable",
    dependencies=[Depends(require_capability("security.schedules.manage"))],
)
async def customer_disable_connector_sync_schedule_route(schedule_id: str, request: Request):
    try:
        schedule = connector_registry.disable_sync_schedule(schedule_id, actor=_actor_from_request(request))
        return {
            "status": "disabled",
            "message": "同步调度已暂停。",
            "schedule_id": schedule_id,
            "schedule": {
                "id": schedule.get("id"),
                "connector_id": schedule.get("connector_id"),
                "capability": schedule.get("capability"),
                "enabled": schedule.get("enabled"),
                "next_run_at": schedule.get("next_run_at"),
            },
        }
    except ValueError as exc:
        raise _not_found("Connector sync schedule", schedule_id) from exc


@router.delete("/connectors/sync-schedules/{schedule_id}", dependencies=[Depends(require_capability("security.schedules.manage"))])
async def delete_connector_sync_schedule_route(schedule_id: str, request: Request):
    try:
        return connector_registry.delete_sync_schedule(schedule_id, actor=_actor_from_request(request))
    except ValueError as exc:
        raise _not_found("Connector sync schedule", schedule_id) from exc


@router.post("/connectors/sync-schedules/{schedule_id}/run", dependencies=[Depends(require_capability("security.schedules.manage"))])
async def run_connector_sync_schedule_route(
    schedule_id: str,
    request: Request,
    payload: ConnectorSyncScheduleRunRequest | None = None,
):
    try:
        return await connector_registry.run_sync_schedule(
            schedule_id,
            trigger="manual",
            mode=payload.mode if payload else None,
            actor=_actor_from_request(request),
        )
    except ValueError as exc:
        detail = str(exc)
        if "not found" in detail.lower():
            raise _not_found("Connector sync schedule", schedule_id) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc


@router.put("/connectors/{connector_id}/sync-schedule", dependencies=[Depends(require_capability("security.schedules.manage"))])
async def upsert_connector_sync_schedule_route(connector_id: str, payload: ConnectorSyncScheduleRequest, request: Request):
    try:
        return connector_registry.upsert_sync_schedule(
            connector_id,
            payload.capability,
            enabled=payload.enabled,
            interval_seconds=payload.interval_seconds,
            mode=payload.mode,
            full_interval_seconds=payload.full_interval_seconds,
            retry_max_attempts=payload.retry_max_attempts,
            retry_backoff_seconds=payload.retry_backoff_seconds,
            timeout_seconds=payload.timeout_seconds,
            credential_profile_id=payload.credential_profile_id,
            actor=_actor_from_request(request),
        )
    except ValueError as exc:
        detail = str(exc)
        if "not found" in detail.lower():
            raise _not_found("Connector", connector_id) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc


@router.post("/connectors/{connector_id}/sync", dependencies=[Depends(require_capability("security.schedules.manage"))])
async def sync_connector_route(connector_id: str, payload: ConnectorSyncRequest):
    try:
        return await connector_registry.sync(
            connector_id,
            payload.capability,
            mode=payload.mode,
            reset_cursor=payload.reset_cursor,
            credential_profile_id=payload.credential_profile_id,
        )
    except ValueError as exc:
        detail = str(exc)
        if "not found" in detail.lower():
            raise _not_found("Connector", connector_id) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc


@router.post("/connectors/{connector_id}/sync/cancel", dependencies=[Depends(require_capability("security.schedules.manage"))])
async def cancel_connector_sync_route(connector_id: str, payload: ConnectorSyncCancelRequest | None = None):
    return connector_registry.cancel_sync(connector_id, capability=payload.capability if payload else None)


@router.post(
    "/connectors/{connector_id}/customer-test",
    dependencies=[Depends(require_capability("security.connectors.test"))],
)
async def customer_test_connector_route(
    connector_id: str,
    request: Request,
    payload: ConnectorCustomerTestRequest | None = None,
):
    try:
        return await connector_registry.customer_test_connection(
            connector_id,
            credential_profile_id=payload.profile_id if payload else None,
            actor=_actor_from_request(request),
        )
    except ValueError as exc:
        raise _not_found("Connector", connector_id) from exc


@router.put(
    "/connectors/{connector_id}/customer-credentials",
    dependencies=[Depends(require_capability("security.credentials.manage"))],
)
async def customer_update_connector_credentials_route(
    connector_id: str,
    payload: ConnectorCustomerCredentialUpdateRequest,
    request: Request,
):
    try:
        binding = await connector_registry.bind_credentials_and_test(
            connector_id,
            payload.values,
            secret_keys=payload.secret_keys,
            profile_id=payload.profile_id,
            profile_name=payload.profile_name,
            make_active=payload.make_active,
            expires_at=payload.expires_at,
            recover_policy_paused_schedules="preview",
            actor=_actor_from_request(request),
        )
        health = connector_registry.credential_health(connector_id, payload.profile_id)
        return {
            "connector_id": connector_id,
            "profile_id": health.get("profile_id"),
            "status": "updated",
            "message": "凭据已更新，请确认连通测试结果后恢复同步调度。",
            "credential": {
                "state": health.get("reason_code"),
                "healthy": health.get("healthy"),
                "blocking": health.get("blocking"),
                "message": health.get("message"),
                "expires_at": (health.get("profile") or {}).get("expires_at") if isinstance(health.get("profile"), dict) else None,
            },
            "policy_recovery": {
                "matched": (binding.get("policy_recovery") or {}).get("matched"),
                "recovered": (binding.get("policy_recovery") or {}).get("recovered"),
                "requires_confirmation": (binding.get("policy_recovery") or {}).get("requires_confirmation"),
            },
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/connectors/{connector_id}/customer-device-sync",
    dependencies=[Depends(require_capability("security.schedules.manage"))],
)
async def customer_enable_connector_device_sync_route(
    connector_id: str,
    payload: ConnectorCustomerDeviceSyncRequest,
    request: Request,
):
    manifest = connector_registry.get(connector_id)
    if manifest is None:
        raise _not_found("Connector", connector_id)

    device_id = payload.device_id.strip()
    if not device_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="device_id is required")

    try:
        from flocks.tool.device.store import fetch_device

        device_row = await fetch_device(device_id)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Device lookup failed: {exc}") from exc
    if device_row is None:
        raise _not_found("Device", device_id)
    if not bool(device_row["enabled"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device is disabled")

    actor = _actor_from_request(request)
    profile_id = payload.profile_id or f"device-{device_id}"
    profile_name = str(device_row["name"] or device_id)
    try:
        binding = await connector_registry.bind_credentials_and_test(
            connector_id,
            {"FLOCKS_CONNECTOR_DEVICE_ID": device_id},
            secret_keys=[],
            profile_id=profile_id,
            profile_name=profile_name,
            make_active=True,
            recover_policy_paused_schedules="preview",
            actor=actor,
        )
        bound_profile_id = str((binding or {}).get("active_profile_id") or profile_id)
        declared_capabilities = [
            str(item.value if hasattr(item, "value") else item)
            for item in connector_registry.list_capabilities(connector_id)
        ]
        requested_capabilities = [
            str(item)
            for item in (payload.capabilities or declared_capabilities)
            if str(item) in declared_capabilities
        ]
        schedules = [
            connector_registry.upsert_sync_schedule(
                connector_id,
                capability,
                enabled=payload.enabled,
                interval_seconds=max(60, int(payload.interval_seconds or 3600)),
                mode=payload.mode or "incremental",
                credential_profile_id=bound_profile_id,
                actor=actor,
            )
            for capability in requested_capabilities
        ]
        health = connector_registry.credential_health(connector_id, bound_profile_id)
        return {
            "connector_id": connector_id,
            "device_id": device_id,
            "profile_id": bound_profile_id,
            "status": "enabled" if payload.enabled else "configured",
            "message": "数据同步已绑定到当前设备。",
            "capabilities": requested_capabilities,
            "schedules": schedules,
            "credential": {
                "healthy": health.get("healthy"),
                "blocking": health.get("blocking"),
                "state": health.get("reason_code"),
                "message": health.get("message"),
            },
            "policy_recovery": binding.get("policy_recovery") if isinstance(binding, dict) else None,
        }
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/connectors/{connector_id}/sync-cursor/reset", dependencies=[Depends(require_capability("security.schedules.manage"))])
async def reset_connector_sync_cursor_route(connector_id: str, payload: ConnectorSyncCursorResetRequest):
    return connector_registry.reset_sync_cursor(connector_id, capability=payload.capability)


@router.get("/connectors/{connector_id}")
async def get_connector(connector_id: str):
    connector = connector_registry.get(connector_id)
    if connector is None:
        raise _not_found("Connector", connector_id)
    return connector


@router.post(
    "/connectors/mingyu-apt/test",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def test_mingyu_apt_connector(payload: MingyuAptTestRequest):
    client = MingyuAptClient(base_url=payload.base_url, apikey=payload.apikey, verify_ssl=payload.verify_ssl)
    return {"connector_id": "mingyu-apt", "version": client.get_version()}


@router.post(
    "/connectors/mingyu-apt/ingest",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def ingest_mingyu_apt_connector(payload: MingyuAptIngestRequest, request: Request):
    actor = _actor_from_request(request)
    run = await default_store.create_connector_sync_run({
        "connector_id": "mingyu-apt",
        "connector_name": "明御APT攻击预警平台",
        "vendor": "DBAPPSecurity",
        "product": "Mingyu APT",
        "mode": payload.mode,
        "status": "running",
        "requested_by": actor.get("username") or actor.get("id"),
        "request_summary": sanitize_connector_request_summary(payload.model_dump(mode="json")),
        "started_at": utc_now(),
    })
    try:
        result = await ingest_mingyu_apt_risks(
            base_url=payload.base_url,
            apikey=payload.apikey,
            begin=payload.begin,
            end=payload.end,
            mode=payload.mode,
            limit=payload.limit,
            max_pages=payload.max_pages,
            create_analysis_cases=payload.create_analysis_cases,
            run_initial_analysis=payload.run_initial_analysis,
            deduplicate=payload.deduplicate,
            verify_ssl=payload.verify_ssl,
        )
    except Exception as exc:
        await record_connector_run(default_store, run.id, error=exc)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Mingyu APT ingestion failed") from exc
    await record_connector_run(default_store, run.id, result=result)
    return {"run_id": run.id, **result}


@router.post(
    "/connectors/tda/test",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def test_tda_connector(payload: TdaTestRequest):
    client = TdaClient(base_url=payload.base_url, api_key=payload.api_key, secret=payload.secret, verify_ssl=payload.verify_ssl)
    return {"connector_id": "tda", "result": client.test_connection()}


@router.post(
    "/connectors/tda/ingest",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def ingest_tda_connector(payload: TdaIngestRequest, request: Request):
    actor = _actor_from_request(request)
    run = await default_store.create_connector_sync_run({
        "connector_id": "tda",
        "connector_name": "信桅高级威胁监测系统 TDA",
        "vendor": "Xinwei",
        "product": "TDA",
        "mode": payload.mode,
        "status": "running",
        "requested_by": actor.get("username") or actor.get("id"),
        "request_summary": sanitize_connector_request_summary(payload.model_dump(mode="json")),
        "started_at": utc_now(),
    })
    try:
        result = await ingest_tda_events(
            base_url=payload.base_url,
            api_key=payload.api_key,
            secret=payload.secret,
            begin=payload.begin,
            end=payload.end,
            time_type=payload.time_type,
            mode=payload.mode,
            limit=payload.limit,
            max_pages=payload.max_pages,
            create_analysis_cases=payload.create_analysis_cases,
            run_initial_analysis=payload.run_initial_analysis,
            deduplicate=payload.deduplicate,
            verify_ssl=payload.verify_ssl,
        )
    except Exception as exc:
        await record_connector_run(default_store, run.id, error=exc)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="TDA ingestion failed") from exc
    await record_connector_run(default_store, run.id, result=result)
    return {"run_id": run.id, **result}


@router.get("/connector-runs", dependencies=[Depends(require_capability("security.ops.read"))])
async def list_connector_runs(
    connector_id: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    mode: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    return await default_store.list_connector_sync_runs(
        connector_id=connector_id,
        status=status_filter,
        mode=mode,
        limit=limit,
        offset=offset,
    )


@router.get("/connector-runs/{run_id}", dependencies=[Depends(require_capability("security.ops.read"))])
async def get_connector_run(run_id: str):
    run = await default_store.get_connector_sync_run(run_id)
    if run is None:
        raise _not_found("Connector sync run", run_id)
    return run


@router.post("/connectors/{connector_id}/test", dependencies=[Depends(require_capability("security.connectors.test"))])
async def test_connector(connector_id: str, request: Request):
    try:
        return await connector_registry.test_connection(connector_id, actor=_actor_from_request(request))
    except ValueError as exc:
        raise _not_found("Connector", connector_id) from exc


@router.post("/connectors/{connector_id}/preview")
async def preview_connector(
    connector_id: str,
    capability: str = Query(...),
):
    try:
        return await connector_registry.preview(connector_id, capability)
    except ValueError as exc:
        detail = str(exc)
        if "not found" in detail.lower():
            raise _not_found("Connector", connector_id) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc


@router.post("/connectors/{connector_id}/validate", dependencies=[Depends(require_capability("security.connectors.test"))])
async def validate_connector(connector_id: str):
    try:
        return await connector_registry.validate(connector_id)
    except ValueError as exc:
        detail = str(exc)
        if "not found" in detail.lower() or "not available" in detail.lower():
            raise _not_found("Connector", connector_id) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc


@router.get("/connectors/{connector_id}/capabilities")
async def list_connector_capabilities(connector_id: str):
    try:
        return {"connector_id": connector_id, "capabilities": connector_registry.list_capabilities(connector_id)}
    except ValueError as exc:
        raise _not_found("Connector", connector_id) from exc


@router.get("/assets")
async def list_assets(filters: SecurityListFilters = Depends(_filters)):
    return await default_store.list_assets(filters)


@router.post(
    "/assets",
    dependencies=[Depends(require_capability("security.ops.write"))],
    status_code=status.HTTP_201_CREATED,
)
async def create_asset(payload: AssetCreate):
    return await default_store.create_asset(payload)


@router.get("/assets/{asset_id}")
async def get_asset(asset_id: str):
    asset = await default_store.get_asset(asset_id)
    if asset is None:
        raise _not_found("Asset", asset_id)
    return asset


@router.get("/assets/{asset_id}/risk-profile")
async def asset_risk_profile(asset_id: str):
    try:
        return await build_asset_risk_profile(asset_id)
    except ValueError as exc:
        raise _not_found("Asset", asset_id) from exc


@router.patch("/assets/{asset_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def update_asset(asset_id: str, payload: AssetUpdate):
    asset = await default_store.update_asset(asset_id, payload)
    if asset is None:
        raise _not_found("Asset", asset_id)
    return asset


@router.delete("/assets/{asset_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def delete_asset(asset_id: str):
    return {"deleted": await default_store.delete_asset(asset_id)}


@router.get("/vulnerabilities")
async def list_vulnerabilities(filters: SecurityListFilters = Depends(_filters)):
    return await default_store.list_vulnerabilities(filters)


@router.post(
    "/vulnerabilities",
    dependencies=[Depends(require_capability("security.ops.write"))],
    status_code=status.HTTP_201_CREATED,
)
async def create_vulnerability(payload: VulnerabilityCreate):
    return await default_store.create_vulnerability(payload)


@router.get("/vulnerabilities/prioritized")
async def prioritized_vulnerabilities(filters: SecurityListFilters = Depends(_filters)):
    return await prioritize_vulnerabilities(filters)


@router.get("/vulnerabilities/{vuln_id}")
async def get_vulnerability(vuln_id: str):
    vuln = await default_store.get_vulnerability(vuln_id)
    if vuln is None:
        raise _not_found("Vulnerability", vuln_id)
    return vuln


@router.patch("/vulnerabilities/{vuln_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def update_vulnerability(vuln_id: str, payload: VulnerabilityUpdate):
    vuln = await default_store.update_vulnerability(vuln_id, payload)
    if vuln is None:
        raise _not_found("Vulnerability", vuln_id)
    return vuln


@router.delete("/vulnerabilities/{vuln_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def delete_vulnerability(vuln_id: str):
    return {"deleted": await default_store.delete_vulnerability(vuln_id)}





@router.post(
    "/integrations/evidence-dispatch/preview",
    dependencies=[Depends(require_capability("security.ops.read"))],
)
async def preview_integration_evidence_dispatch(payload: EvidenceDispatchAPIRequest):
    request = EvidenceDispatchRequest(
        events=payload.events,
        connector_context=payload.connector_context,
        create_analysis_cases=False,
        run_initial_analysis=False,
        deduplicate=payload.deduplicate,
        preview_only=True,
    )
    return await dispatch_integration_evidence_events(request)


@router.post(
    "/evidence-ingestion/ingest",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def ingest_evidence_events(payload: EvidenceIngestionRequest):
    return await ingest_external_events(
        payload.events,
        connector_context=payload.connector_context,
        create_analysis_cases=payload.create_analysis_cases,
        run_initial_analysis=payload.run_initial_analysis,
        deduplicate=payload.deduplicate,
    )


@router.post(
    "/evidence-ingestion/preview",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def preview_evidence_events(payload: EvidenceIngestionRequest):
    return {"summaries": [summarize_external_event(event, connector_context=payload.connector_context) for event in payload.events]}

@router.get("/alerts")
async def list_alerts(filters: SecurityListFilters = Depends(_filters)):
    return await default_store.list_alerts(filters)


@router.post(
    "/alerts",
    dependencies=[Depends(require_capability("security.ops.write"))],
    status_code=status.HTTP_201_CREATED,
)
async def create_alert(payload: AlertCreate):
    return await default_store.create_alert(payload)


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    alert = await default_store.get_alert(alert_id)
    if alert is None:
        raise _not_found("Alert", alert_id)
    return alert


@router.patch("/alerts/{alert_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def update_alert(alert_id: str, payload: AlertUpdate):
    alert = await default_store.update_alert(alert_id, payload)
    if alert is None:
        raise _not_found("Alert", alert_id)
    return alert


@router.delete("/alerts/{alert_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def delete_alert(alert_id: str):
    return {"deleted": await default_store.delete_alert(alert_id)}


@router.get("/analysis-cases")
async def list_analysis_cases(filters: SecurityListFilters = Depends(_filters)):
    return await default_store.list_analysis_cases(filters)


@router.post(
    "/analysis-cases",
    dependencies=[Depends(require_capability("security.ops.write"))],
    status_code=status.HTTP_201_CREATED,
)
async def create_analysis_case(payload: AnalysisCaseCreate):
    return await default_store.create_analysis_case(payload)


@router.post(
    "/analysis-cases/sample-data/load",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def load_analysis_case_sample_data_route():
    return await load_analysis_sample_data()


@router.delete(
    "/analysis-cases/sample-data",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def clear_analysis_case_sample_data_route():
    return await clear_analysis_sample_data()


@router.get("/analysis-cases/{case_id}/brief")
async def get_analysis_case_brief(case_id: str):
    case = await default_store.get_analysis_case(case_id)
    if case is None:
        raise _not_found("AnalysisCase", case_id)
    return {"case_id": case.id, "markdown": generate_analysis_case_brief(case)}


@router.get("/analysis-cases/{case_id}/fact-ledger-summary")
async def get_analysis_case_fact_ledger_summary(case_id: str):
    case = await default_store.get_analysis_case(case_id)
    if case is None:
        raise _not_found("AnalysisCase", case_id)
    return summarize_fact_ledger(case)


@router.get("/analysis-cases/{case_id}")
async def get_analysis_case(case_id: str):
    case = await default_store.get_analysis_case(case_id)
    if case is None:
        raise _not_found("AnalysisCase", case_id)
    return case


@router.patch("/analysis-cases/{case_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def update_analysis_case(case_id: str, payload: AnalysisCaseUpdate):
    case = await default_store.update_analysis_case(case_id, payload)
    if case is None:
        raise _not_found("AnalysisCase", case_id)
    return case


@router.delete("/analysis-cases/{case_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def delete_analysis_case(case_id: str):
    return {"deleted": await default_store.delete_analysis_case(case_id)}


@router.post(
    "/analysis-cases/from-alert/{alert_id}",
    dependencies=[Depends(require_capability("security.ops.write"))],
    status_code=status.HTTP_201_CREATED,
)
async def create_analysis_case_from_alert(alert_id: str):
    alert = await default_store.get_alert(alert_id)
    if alert is None:
        raise _not_found("Alert", alert_id)
    return await default_store.create_analysis_case(build_analysis_case_from_alert(alert))


@router.post(
    "/analysis-cases/{case_id}/run-initial-analysis",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def run_analysis_case_initial_analysis(case_id: str):
    case = await default_store.get_analysis_case(case_id)
    if case is None:
        raise _not_found("AnalysisCase", case_id)
    related_alerts = []
    for alert_id in case.related_alert_ids:
        alert = await default_store.get_alert(alert_id)
        if alert is not None:
            related_alerts.append(alert)
    updated = await default_store.update_analysis_case(case.id, run_initial_analysis(case, related_alerts))
    return updated or case




@router.post(
    "/analysis-cases/{case_id}/notifications",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def create_analysis_case_notification(case_id: str, payload: AnalysisNotificationCreate):
    case = await default_store.get_analysis_case(case_id)
    if case is None:
        raise _not_found("AnalysisCase", case_id)
    now = utc_now()
    generated = build_notification_for_case(case, payload.notification_type, payload.created_by)
    data = generated.model_dump(mode="json")
    provided = payload.model_dump(mode="json", exclude_unset=True)
    for key, value in provided.items():
        if value not in (None, "", [], {}):
            data[key] = value
    data["channel"] = data.get("channel") or "in_app"
    if data["channel"] not in {"in_app", "manual"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only in_app and manual channels are supported")
    data["status"] = "sent"
    data["sent_at"] = now
    records = [record.model_dump(mode="json") for record in case.notification_records]
    records.append(data)
    updated = await default_store.update_analysis_case(case.id, AnalysisCaseUpdate(notification_records=records, last_notified_at=now))
    if updated is None:
        raise _not_found("AnalysisCase", case_id)
    return updated


@router.post(
    "/analysis-cases/{case_id}/confirmations",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def create_analysis_case_confirmation(case_id: str, payload: AnalysisConfirmationCreate):
    case = await default_store.get_analysis_case(case_id)
    if case is None:
        raise _not_found("AnalysisCase", case_id)
    now = utc_now()
    data = payload.model_dump(mode="json")
    data["created_at"] = data.get("created_at") or now
    records = [record.model_dump(mode="json") for record in case.confirmation_records]
    records.append(data)
    update = apply_confirmation_to_case(case, payload).model_dump(mode="json", exclude_unset=True)
    update["confirmation_records"] = records
    update["last_confirmed_at"] = now
    updated = await default_store.update_analysis_case(case.id, AnalysisCaseUpdate(**update))
    if updated is None:
        raise _not_found("AnalysisCase", case_id)
    return updated


@router.post(
    "/analysis-cases/{case_id}/notifications/{notification_id}/ack",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def acknowledge_analysis_case_notification(case_id: str, notification_id: str, payload: dict[str, Any] | None = None):
    case = await default_store.get_analysis_case(case_id)
    if case is None:
        raise _not_found("AnalysisCase", case_id)
    now = utc_now()
    records = [record.model_dump(mode="json") for record in case.notification_records]
    found = False
    for record in records:
        if record.get("id") == notification_id:
            record["status"] = "acknowledged"
            record["acknowledged_at"] = now
            if payload:
                record.setdefault("metadata", {})["ack"] = payload
            found = True
            break
    if not found:
        raise _not_found("AnalysisNotification", notification_id)
    updated = await default_store.update_analysis_case(case.id, AnalysisCaseUpdate(notification_records=records))
    if updated is None:
        raise _not_found("AnalysisCase", case_id)
    return updated


@router.post(
    "/analysis-cases/{case_id}/escalate-to-incident",
    dependencies=[Depends(require_capability("security.ops.write"))],
)
async def escalate_analysis_case_to_incident(case_id: str, response: Response):
    case = await default_store.get_analysis_case(case_id)
    if case is None:
        raise _not_found("AnalysisCase", case_id)

    if case.related_incident_id:
        incident = await default_store.get_incident(case.related_incident_id)
        if incident is not None:
            response.status_code = status.HTTP_200_OK
            return {"case": case, "incident": incident, "created": False}

    incident = await default_store.create_incident(
        IncidentCreate(
            title=case.title,
            severity=_analysis_case_incident_severity(case.severity),
            summary=_analysis_case_summary(case),
            analysis=_analysis_case_analysis(case),
            recommendation=_analysis_case_recommendation(case),
            asset_ids=_analysis_case_asset_ids(case),
            vulnerability_ids=case.related_vulnerability_ids,
            alert_ids=case.related_alert_ids,
            evidence=_analysis_case_evidence(case),
            timeline=_analysis_case_timeline(case),
            confidence=case.confidence,
            created_by="analysis_case_manual_escalation",
            raw_data={"analysis_case_id": case.id},
            normalized_data={
                "source": "analysis_case",
                "analysis_case_id": case.id,
                "verdict": case.verdict,
                "evidence_coverage": case.evidence_coverage,
                "analysis_mode": case.analysis_mode,
            },
        )
    )
    updated_case = await default_store.update_analysis_case(
        case.id,
        AnalysisCaseUpdate(
            related_incident_id=incident.id,
            incident_decision=IncidentDecision.ESCALATE_TO_INCIDENT,
            disposition=AnalysisDisposition.ESCALATED_TO_INCIDENT,
            case_status=AnalysisCaseStatus.ESCALATED,
        ),
    )
    response.status_code = status.HTTP_201_CREATED
    return {"case": updated_case or case, "incident": incident, "created": True}


@router.get("/incidents")
async def list_incidents(filters: SecurityListFilters = Depends(_filters)):
    return await default_store.list_incidents(filters)


@router.post(
    "/incidents",
    dependencies=[Depends(require_capability("security.ops.write"))],
    status_code=status.HTTP_201_CREATED,
)
async def create_incident(payload: IncidentCreate):
    return await default_store.create_incident(payload)


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    incident = await default_store.get_incident(incident_id)
    if incident is None:
        raise _not_found("Incident", incident_id)
    return incident


@router.patch("/incidents/{incident_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def update_incident(incident_id: str, payload: IncidentUpdate):
    incident = await default_store.update_incident(incident_id, payload)
    if incident is None:
        raise _not_found("Incident", incident_id)
    return incident


@router.delete("/incidents/{incident_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def delete_incident(incident_id: str):
    return {"deleted": await default_store.delete_incident(incident_id)}


@router.get("/honeypot-events")
async def list_honeypot_events(filters: SecurityListFilters = Depends(_filters)):
    return await default_store.list_honeypot_events(filters)


@router.post(
    "/honeypot-events",
    dependencies=[Depends(require_capability("security.ops.write"))],
    status_code=status.HTTP_201_CREATED,
)
async def create_honeypot_event(payload: HoneypotEventCreate):
    return await default_store.create_honeypot_event(payload)


@router.get("/honeypot-events/{event_id}")
async def get_honeypot_event(event_id: str):
    event = await default_store.get_honeypot_event(event_id)
    if event is None:
        raise _not_found("HoneypotEvent", event_id)
    return event


@router.patch("/honeypot-events/{event_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def update_honeypot_event(event_id: str, payload: HoneypotEventUpdate):
    event = await default_store.update_honeypot_event(event_id, payload)
    if event is None:
        raise _not_found("HoneypotEvent", event_id)
    return event


@router.delete("/honeypot-events/{event_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def delete_honeypot_event(event_id: str):
    return {"deleted": await default_store.delete_honeypot_event(event_id)}


@router.post("/correlate/alert/{alert_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def correlate_alert_route(alert_id: str):
    try:
        return await correlate_alert(alert_id)
    except ValueError as exc:
        raise _not_found("Alert", alert_id) from exc


@router.post("/triage/alert/{alert_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def triage_alert_route(
    alert_id: str,
    create_incident: bool = Query(True, alias="createIncident"),
):
    try:
        return await triage_alert(alert_id, create_incident=create_incident)
    except ValueError as exc:
        raise _not_found("Alert", alert_id) from exc


@router.post("/incidents/from-alert/{alert_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def create_incident_from_alert(alert_id: str):
    try:
        triage = await triage_alert(alert_id, create_incident=True)
    except ValueError as exc:
        raise _not_found("Alert", alert_id) from exc

    incident: Incident | None = None
    if triage.incident_id:
        incident = await default_store.get_incident(triage.incident_id)
    if incident is None:
        incident = await default_store.create_incident(
            IncidentCreate(
                title=f"来自告警的安全事件：{alert_id}",
                severity=triage.severity,
                summary=triage.summary,
                analysis=triage.analysis,
                recommendation="\n".join(triage.recommended_actions),
                asset_ids=triage.linked_asset_ids,
                vulnerability_ids=triage.linked_vulnerability_ids,
                alert_ids=triage.linked_alert_ids,
                evidence=triage.evidence,
                confidence=triage.confidence,
                created_by="security_manual_from_alert",
            )
        )
        await default_store.update_alert(alert_id, AlertUpdate(status="incident_created"))  # type: ignore[arg-type]
        triage.incident_id = incident.id
    return {"incident": incident, "triage": triage}


@router.post("/reports/incident/{incident_id}", dependencies=[Depends(require_capability("security.ops.write"))])
async def incident_report(incident_id: str):
    try:
        content = await generate_incident_report(incident_id, default_store)
    except ValueError as exc:
        raise _not_found("Incident", incident_id) from exc
    return {"incident_id": incident_id, "format": "markdown", "content": content}


@router.post("/sample-data/load", dependencies=[Depends(require_capability("security.ops.write"))])
async def load_sample_data_route():
    return await load_sample_data()


@router.delete("/sample-data/clear", dependencies=[Depends(require_capability("security.ops.write"))])
async def clear_sample_data_route():
    return await clear_sample_data()
