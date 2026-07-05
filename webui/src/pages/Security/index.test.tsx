import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import '@/i18n.commercial-admin';
import i18n from '@/i18n';
import SecurityPage from './index';

const mocks = vi.hoisted(() => ({
  listAssets: vi.fn(),
  listVulnerabilities: vi.fn(),
  listAlerts: vi.fn(),
  listIncidents: vi.fn(),
  listHoneypotEvents: vi.fn(),
  listConnectors: vi.fn(),
  connectorPackageDiagnostics: vi.fn(),
  getEvidenceGraph: vi.fn(),
  listConnectorOperationEvents: vi.fn(),
  getConnectorOperationsSettings: vi.fn(),
  updateConnectorOperationsSettings: vi.fn(),
  getConnectorCredentialExpiryMonitorStatus: vi.fn(),
  rotateConnectorCredentials: vi.fn(),
  testConnectorCredentialProfile: vi.fn(),
  enableConnectorSyncSchedule: vi.fn(),
  runConnectorSyncSchedule: vi.fn(),
  monitorConnectorCredentialExpiry: vi.fn(),
  acknowledgeConnectorOperationEvent: vi.fn(),
  acknowledgeConnectorOperationEvents: vi.fn(),
  notifyConnectorOperationEvent: vi.fn(),
  bulkRemediateConnectorCredentials: vi.fn(),
}));

vi.mock('@/api/security', () => ({
  securityAPI: {
    listAssets: mocks.listAssets,
    listVulnerabilities: mocks.listVulnerabilities,
    listAlerts: mocks.listAlerts,
    listIncidents: mocks.listIncidents,
    listHoneypotEvents: mocks.listHoneypotEvents,
    listConnectors: mocks.listConnectors,
    connectorPackageDiagnostics: mocks.connectorPackageDiagnostics,
    getEvidenceGraph: mocks.getEvidenceGraph,
    listConnectorOperationEvents: mocks.listConnectorOperationEvents,
    getConnectorOperationsSettings: mocks.getConnectorOperationsSettings,
    updateConnectorOperationsSettings: mocks.updateConnectorOperationsSettings,
    getConnectorCredentialExpiryMonitorStatus: mocks.getConnectorCredentialExpiryMonitorStatus,
    rotateConnectorCredentials: mocks.rotateConnectorCredentials,
    testConnectorCredentialProfile: mocks.testConnectorCredentialProfile,
    enableConnectorSyncSchedule: mocks.enableConnectorSyncSchedule,
    runConnectorSyncSchedule: mocks.runConnectorSyncSchedule,
    monitorConnectorCredentialExpiry: mocks.monitorConnectorCredentialExpiry,
    acknowledgeConnectorOperationEvent: mocks.acknowledgeConnectorOperationEvent,
    acknowledgeConnectorOperationEvents: mocks.acknowledgeConnectorOperationEvents,
    notifyConnectorOperationEvent: mocks.notifyConnectorOperationEvent,
    bulkRemediateConnectorCredentials: mocks.bulkRemediateConnectorCredentials,
  },
}));

const connectorId = 'mock-security-demo';
const capability = 'asset.search';
const profileId = 'expired_ui_check';
const scheduleId = `${connectorId}:${capability}`;
const expiredAt = '2000-01-01T00:00:00+00:00';
const recoveredAt = '2999-01-01T00:00:00+00:00';
const blockedRunId = 'connector-sync-blocked-expired-ui-check';
const recoveredRunId = 'connector-sync-recovered';
const operationEventId = 'connector-operation-event-sync-blocked';

type Phase = 'blocked' | 'rotated' | 'enabled' | 'recovered';

let phase: Phase = 'blocked';

const operationSettings = {
  retention: {
    events_max: 1000,
    events_days: 180,
    bulk_runs_max: 200,
    bulk_runs_days: 90,
    notification_deliveries_max: 1000,
    notification_deliveries_days: 90,
    audit_max: 1000,
    audit_days: 730,
  },
  expiry_monitor: {
    enabled: true,
    days: 14,
    interval_seconds: 86400,
    notify: true,
    last_run_at: null,
    next_run_at: '2026-06-03T00:00:00Z',
    last_result: null,
  },
  notifications: {
    enabled: true,
    notify_on_repeat: false,
    sinks: [],
  },
};

const connector = {
  id: connectorId,
  name: 'Mock Security Demo',
  vendor: 'Flocks',
  product: 'Replay Fixture',
  capabilities: [capability],
  auth: { type: 'api_key' },
  pagination: {},
  rate_limit: {},
  permissions: [],
  risk_level: 'medium',
  description: 'Replay connector for policy pause recovery tests.',
  enabled: true,
};

const evidenceGraph = {
  version: 'connector.evidence.graph.v1',
  updated_at: '2026-06-02T00:00:00Z',
  summary: {
    version: 'connector.evidence.graph.v1',
    nodes: 0,
    edges: 0,
    asset_entities: 1,
    merge_candidates: 1,
    conflicts: 1,
  },
  nodes: [],
  edges: [],
  entities: [],
  merge_candidates: [],
  conflicts: [],
  indexes: {},
};

const asset = {
  id: 'asset-finance-portal',
  name: 'Finance Portal',
  asset_type: 'web_app',
  ip: '192.168.31.10',
  hostname: 'finance-web-01',
  domain: 'finance.local',
  business_system: 'Finance',
  business_owner: 'SOC',
  importance: 'critical',
  exposure_level: 'external',
  environment: 'production',
  open_ports: [443, 8443],
  services: ['https'],
  protocols: ['tcp'],
  security_controls: { waf: true, edr: true },
  tags: ['prod'],
  description: null,
  raw_data: {},
  normalized_data: {
    asset_identity: {
      strong_keys: ['global:asset_uuid:finance-portal-uuid'],
      auxiliary_keys: ['aux:hostname:finance-web-01'],
      weak_keys: ['weak:ip:default:192.168.31.10'],
      allocation_mode: 'dhcp',
      observation_window: {
        first_seen: '2026-06-01T00:00:00Z',
        last_seen: '2026-06-02T00:00:00Z',
      },
    },
    source_observation: {
      connector_id: 'dbappsecurity-mingyu-apt',
      source_instance_id: 'dbappsecurity-mingyu-apt:device-a',
      device_id: 'device-a',
      last_seen: '2026-06-02T00:00:00Z',
    },
    ip_observations: [
      {
        ip: '192.168.31.10',
        network_scope: 'default',
        allocation_mode: 'dhcp',
        first_seen: '2026-06-01T00:00:00Z',
        last_seen: '2026-06-02T00:00:00Z',
      },
    ],
    evidence_graph: {
      entity_id: 'asset_entity_finance',
      entity_ids: ['asset_entity_finance'],
      merge_candidate_ids: ['candidate-finance'],
      conflict_ids: ['conflict-finance'],
    },
  },
  created_at: '2026-06-01T00:00:00Z',
  updated_at: '2026-06-02T00:00:00Z',
};

const vulnerability = {
  id: 'vuln-finance-critical',
  asset_id: asset.id,
  cve_id: 'CVE-2026-0001',
  title: 'Critical web exposure',
  severity: 'critical',
  cvss_score: 9.8,
  epss_score: 0.9,
  kev: true,
  exploit_available: true,
  description: null,
  affected_component: 'nginx',
  remediation: null,
  status: 'open',
  raw_data: {},
  normalized_data: {},
  created_at: '2026-06-01T00:00:00Z',
  updated_at: '2026-06-02T00:00:00Z',
};

const alert = {
  id: 'alert-finance-high',
  asset_id: asset.id,
  source: 'xdr',
  title: 'Suspicious login',
  severity: 'high',
  alert_type: 'auth',
  description: null,
  raw_event: {},
  raw_data: {},
  ioc: [],
  mitre_technique: 'T1110',
  status: 'new',
  occurred_at: '2026-06-02T00:00:00Z',
  normalized_data: {},
  created_at: '2026-06-02T00:00:00Z',
  updated_at: '2026-06-02T00:00:00Z',
};

const incident = {
  id: 'incident-finance-open',
  title: 'Finance portal investigation',
  severity: 'high',
  status: 'open',
  summary: 'Investigate public portal signals.',
  analysis: '',
  recommendation: '',
  asset_ids: [asset.id],
  vulnerability_ids: [vulnerability.id],
  alert_ids: [alert.id],
  honeypot_event_ids: [],
  evidence: [],
  timeline: [],
  owner: null,
  sla: null,
  close_reason: null,
  confidence: 'high',
  created_by: 'system',
  raw_data: {},
  normalized_data: {},
  created_at: '2026-06-02T00:00:00Z',
  updated_at: '2026-06-02T00:00:00Z',
};

const honeypotEvent = {
  id: 'honeypot-finance-hit',
  sensor_id: 'sensor-a',
  source_ip: '198.51.100.10',
  target_ip: asset.ip,
  protocol: 'tcp',
  service: 'https',
  event_type: 'probe',
  payload: null,
  geo: {},
  threat_label: 'scan',
  occurred_at: '2026-06-02T00:00:00Z',
  raw_data: {},
  normalized_data: {},
  created_at: '2026-06-02T00:00:00Z',
  updated_at: '2026-06-02T00:00:00Z',
};

function policyActions() {
  return [
    {
      id: 'rotate_credentials',
      kind: 'rotate_credentials',
      label: 'Rotate credentials',
      connector_id: connectorId,
      profile_id: profileId,
      profile_expires_at: expiredAt,
    },
    {
      id: 'test_profile',
      kind: 'test_profile',
      label: 'Test profile',
      connector_id: connectorId,
      profile_id: profileId,
      profile_expires_at: expiredAt,
    },
  ];
}

function buildCredentialBinding(currentPhase: Phase) {
  const expired = currentPhase === 'blocked';
  const synced = currentPhase === 'recovered';
  return {
    connector_id: connectorId,
    active_profile_id: profileId,
    profile_count: 1,
    env: {
      VENDOR_BASE_URL: { kind: 'value', configured: true, masked: 'https://api.vendor.local' },
      VENDOR_TOKEN: { kind: 'secret', configured: true, masked: 'rot********' },
    },
    env_keys: ['VENDOR_BASE_URL', 'VENDOR_TOKEN'],
    profiles: [
      {
        id: profileId,
        name: profileId,
        status: expired ? 'expired' : 'ok',
        active: true,
        expired,
        expires_at: expired ? expiredAt : recoveredAt,
        env: {
          VENDOR_BASE_URL: { kind: 'value', configured: true, masked: 'https://api.vendor.local' },
          VENDOR_TOKEN: { kind: 'secret', configured: true, masked: 'rot********' },
        },
        env_keys: ['VENDOR_BASE_URL', 'VENDOR_TOKEN'],
        rotation_count: expired ? 0 : 1,
        last_test_status: expired ? null : 'success',
        last_test_message: expired ? 'Credential profile expired' : 'Connection OK',
        last_failure_reason: expired ? `Credential profile expired at ${expiredAt}` : null,
        last_sync_run_id: synced ? recoveredRunId : blockedRunId,
        last_successful_sync_at: synced ? '2026-06-02T00:05:00Z' : null,
      },
    ],
  };
}

function buildRun(status: 'blocked' | 'partial') {
  const isBlocked = status === 'blocked';
  return {
    id: isBlocked ? blockedRunId : recoveredRunId,
    connector_id: connectorId,
    capability,
    schedule_id: scheduleId,
    credential_profile_id: profileId,
    sync_mode: 'full',
    status,
    started_at: isBlocked ? '2026-06-02T00:00:00Z' : '2026-06-02T00:05:00Z',
    finished_at: isBlocked ? '2026-06-02T00:00:01Z' : '2026-06-02T00:05:02Z',
    duration_ms: isBlocked ? 100 : 250,
    source: isBlocked ? 'credential_health_gate' : 'replay_fixture',
    input_counts: isBlocked ? {} : { assets: 1 },
    counts: isBlocked ? {} : { assets: 1 },
    object_ids: isBlocked ? {} : { assets: ['asset-1'] },
    skipped_counts: {},
    quality: isBlocked ? {} : { score: 1 },
    dead_letter_count: 0,
    run_policy: isBlocked
      ? {
          version: 'connector.run.policy.v1',
          decision: 'block',
          state: 'blocked',
          reason: 'credential_profile_expired',
          message: `Credential profile expired at ${expiredAt}`,
          actions: policyActions(),
        }
      : undefined,
    warnings: [],
    errors: isBlocked ? [`Credential profile expired at ${expiredAt}`] : [],
  };
}

function buildSchedule(currentPhase: Phase) {
  const paused = currentPhase === 'blocked' || currentPhase === 'rotated';
  const recovered = currentPhase === 'recovered';
  return {
    id: scheduleId,
    connector_id: connectorId,
    capability,
    enabled: !paused,
    interval_seconds: 60,
    mode: 'full',
    retry_max_attempts: 3,
    retry_backoff_seconds: 5,
    timeout_seconds: 30,
    credential_profile_id: profileId,
    runtime_status: paused ? 'policy_paused' : 'enabled',
    due: false,
    next_run_at: paused ? null : '2026-06-02T00:06:00Z',
    last_run_id: recovered ? recoveredRunId : blockedRunId,
    last_run_at: recovered ? '2026-06-02T00:05:00Z' : '2026-06-02T00:00:00Z',
    last_successful_run_at: recovered ? '2026-06-02T00:05:00Z' : null,
    last_failed_run_at: paused ? '2026-06-02T00:00:00Z' : null,
    last_status: recovered ? 'partial' : 'blocked',
    last_error: paused ? `Credential profile expired at ${expiredAt}` : null,
    last_trigger: 'manual',
    last_duration_ms: recovered ? 250 : 100,
    last_mode: 'full',
    consecutive_failures: paused ? 1 : 0,
    policy_state: paused ? 'paused' : null,
    policy_reason: paused ? 'credential_profile_expired' : null,
    policy_message: paused ? `Credential profile expired at ${expiredAt}` : null,
    policy_actions: paused ? policyActions() : [],
    policy_paused_at: paused ? '2026-06-02T00:00:00Z' : null,
    created_at: '2026-06-02T00:00:00Z',
    updated_at: '2026-06-02T00:00:00Z',
  };
}

function buildOperationEvents(currentPhase: Phase) {
  if (currentPhase === 'recovered') return [];
  return [
    {
      id: operationEventId,
      version: 'connector.operation.event.v1',
      kind: 'sync_blocked',
      status: 'open',
      severity: 'critical',
      connector_id: connectorId,
      profile_id: profileId,
      schedule_id: scheduleId,
      run_id: blockedRunId,
      reason_code: 'expired',
      title: 'Connector sync blocked',
      message: `Credential profile expired at ${expiredAt}`,
      created_at: '2026-06-02T00:00:00Z',
      last_seen_at: '2026-06-02T00:00:00Z',
      acknowledged_at: null,
      acknowledged_by: null,
      created_by: { id: 'system', username: 'system' },
      updated_by: { id: 'system', username: 'system' },
      seen_count: 1,
      dedupe_key: 'sync_blocked:mock-security-demo:expired_ui_check',
      metadata: {},
      notifications: [],
    },
  ];
}

function buildDiagnostics(currentPhase: Phase) {
  const runs = currentPhase === 'recovered'
    ? [buildRun('partial'), buildRun('blocked')]
    : [buildRun('blocked')];
  const operationEvents = buildOperationEvents(currentPhase);
  return {
    checked_at: '2026-06-02T00:00:00Z',
    version: 'connector.package.diagnostics.v1',
    summary: {
      roots: 0,
      packages: 0,
      active_packages: 0,
      installed_packages: 0,
      enabled_packages: 0,
      staging_packages: 0,
      validated_staging_packages: 0,
      invalid_staging_packages: 0,
      credential_bindings: 1,
      sync_runs: runs.length,
      active_sync_runs: 0,
      sync_cursors: 0,
      sync_dead_letters: 0,
      pending_sync_dead_letters: 0,
      replayed_sync_dead_letters: 0,
      blocked_sync_runs: 1,
      connector_operation_events: operationEvents.length,
      open_connector_operation_events: operationEvents.filter((event) => event.status === 'open').length,
      sync_schedules: 1,
      enabled_sync_schedules: currentPhase === 'blocked' || currentPhase === 'rotated' ? 0 : 1,
      due_sync_schedules: 0,
      policy_paused_sync_schedules: currentPhase === 'blocked' || currentPhase === 'rotated' ? 1 : 0,
      evidence_graph_nodes: 0,
      evidence_graph_edges: 0,
      evidence_graph_entities: 0,
      evidence_graph_conflicts: 0,
      valid_packages: 0,
      invalid_packages: 0,
      errors: 0,
      warnings: 0,
    },
    roots: [],
    packages: [],
    staging_packages: [],
    credential_bindings: [buildCredentialBinding(currentPhase)],
    sync_runs: runs,
    active_sync_runs: [],
    sync_cursors: [],
    sync_dead_letters: [],
    sync_schedules: [buildSchedule(currentPhase)],
    connector_operations: {
      version: 'connector.operations.v1',
      events: operationEvents.length,
      open_events: operationEvents.filter((event) => event.status === 'open').length,
      events_by_kind: { sync_blocked: operationEvents.length },
      open_events_by_kind: { sync_blocked: operationEvents.length },
      bulk_runs: 0,
      last_event: operationEvents[0] || null,
    },
    operation_events: operationEvents,
    sync_run_registry: {
      version: 'connector.sync.runtime.v1',
      runs: runs.length,
      blocked_runs: 1,
      blocked_run_retention: {
        retained: true,
        reason: 'audit_history',
        message: 'Blocked connector sync runs are retained as audit history.',
      },
      last_blocked_run: buildRun('blocked'),
      last_run: runs[0],
    },
    evidence_graph: evidenceGraph.summary,
  };
}

function renderSecurityConnectors() {
  return render(
    <MemoryRouter initialEntries={['/security-admin/connectors']}>
      <Routes>
        <Route
          path="/security-admin/*"
          element={<SecurityPage basePath="/security-admin" mode="admin" />}
        />
      </Routes>
    </MemoryRouter>,
  );
}

function renderSecurityAssets() {
  return render(
    <MemoryRouter initialEntries={['/security/assets']}>
      <Routes>
        <Route
          path="/security/*"
          element={<SecurityPage basePath="/security" mode="expert" />}
        />
      </Routes>
    </MemoryRouter>,
  );
}

describe('SecurityPage asset module', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    await i18n.changeLanguage('en-US');
    mocks.listAssets.mockResolvedValue({ data: [asset] });
    mocks.listVulnerabilities.mockResolvedValue({ data: [vulnerability] });
    mocks.listAlerts.mockResolvedValue({ data: [alert] });
    mocks.listIncidents.mockResolvedValue({ data: [incident] });
    mocks.listHoneypotEvents.mockResolvedValue({ data: [honeypotEvent] });
    mocks.getEvidenceGraph.mockResolvedValue({ data: evidenceGraph });
  });

  it('shows customer-facing asset risk, security status, and identity evidence', async () => {
    renderSecurityAssets();

    expect(await screen.findByText('Asset Risk + Security Status')).toBeInTheDocument();
    expect(screen.getByText('Finance Portal')).toBeInTheDocument();
    expect(screen.getAllByText('Needs Attention').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Public Exposure').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Identity Review').length).toBeGreaterThan(0);
    expect(screen.getByText('Critical Risk')).toBeInTheDocument();
    expect(screen.getByText('Identity Conflict')).toBeInTheDocument();
    expect(screen.getByText('IP allocation dhcp')).toBeInTheDocument();
    expect(screen.getByText('1 asset entities')).toBeInTheDocument();
    expect(mocks.getEvidenceGraph).toHaveBeenCalled();
  });
});

describe('SecurityPage connector recovery', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    phase = 'blocked';
    await i18n.changeLanguage('en-US');

    vi.spyOn(window, 'prompt').mockImplementation(() => null);
    vi.spyOn(window, 'confirm').mockReturnValue(true);

    mocks.listAssets.mockResolvedValue({ data: [] });
    mocks.listVulnerabilities.mockResolvedValue({ data: [] });
    mocks.listAlerts.mockResolvedValue({ data: [] });
    mocks.listIncidents.mockResolvedValue({ data: [] });
    mocks.listHoneypotEvents.mockResolvedValue({ data: [] });
    mocks.listConnectors.mockResolvedValue({ data: [connector] });
    mocks.connectorPackageDiagnostics.mockImplementation(() => Promise.resolve({ data: buildDiagnostics(phase) }));
    mocks.getEvidenceGraph.mockResolvedValue({ data: evidenceGraph });
    mocks.listConnectorOperationEvents.mockImplementation(() => (
      Promise.resolve({ data: { items: buildOperationEvents(phase) } })
    ));
    mocks.getConnectorOperationsSettings.mockResolvedValue({ data: operationSettings });
    mocks.updateConnectorOperationsSettings.mockImplementation((settings) => (
      Promise.resolve({ data: { ...operationSettings, ...settings } })
    ));
    mocks.getConnectorCredentialExpiryMonitorStatus.mockResolvedValue({
      data: {
        running: true,
        poll_interval_seconds: 60,
        settings: operationSettings.expiry_monitor,
        last_tick: null,
      },
    });
    mocks.rotateConnectorCredentials.mockImplementation(() => {
      phase = 'rotated';
      return Promise.resolve({ data: buildCredentialBinding(phase) });
    });
    mocks.testConnectorCredentialProfile.mockResolvedValue({
      data: {
        connector_id: connectorId,
        success: true,
        status: 'success',
        message: 'Connection OK',
        health_check: {},
        capabilities: [capability],
        raw_response: {},
        normalized_data: {},
        warnings: [],
      },
    });
    mocks.enableConnectorSyncSchedule.mockImplementation(() => {
      phase = 'enabled';
      return Promise.resolve({ data: buildSchedule(phase) });
    });
    mocks.runConnectorSyncSchedule.mockImplementation(() => {
      phase = 'recovered';
      return Promise.resolve({
        data: {
          status: 'partial',
          schedule: buildSchedule(phase),
          run: buildRun('partial'),
        },
      });
    });
    mocks.monitorConnectorCredentialExpiry.mockResolvedValue({ data: { matched: 1, events: buildOperationEvents(phase) } });
    mocks.acknowledgeConnectorOperationEvent.mockResolvedValue({
      data: { ...buildOperationEvents(phase)[0], status: 'acknowledged' },
    });
    mocks.acknowledgeConnectorOperationEvents.mockResolvedValue({
      data: { requested: 1, acknowledged: 1 },
    });
    mocks.notifyConnectorOperationEvent.mockResolvedValue({
      data: { items: [] },
    });
    mocks.bulkRemediateConnectorCredentials.mockResolvedValue({
      data: { requested: 1, succeeded: 1, failed: 0, results: [], bulk_run: {} },
    });
  });

  it('recovers a policy-paused schedule after rotating an expired credential profile', async () => {
    const user = userEvent.setup();
    const promptSpy = vi.spyOn(window, 'prompt').mockImplementationOnce(() => (
      'VENDOR_BASE_URL=https://api.vendor.local\nVENDOR_TOKEN=rotated-token'
    )).mockImplementationOnce(() => recoveredAt);

    renderSecurityConnectors();

    expect(await screen.findByText('Blocked History Retention')).toBeInTheDocument();
    expect(screen.getAllByText(profileId).length).toBeGreaterThan(0);
    expect(screen.getByText('Policy Paused')).toBeInTheDocument();
    expect(screen.getAllByText(blockedRunId).length).toBeGreaterThan(0);

    await user.click(screen.getAllByTitle('Rotate Credentials')[0]);

    await waitFor(() => {
      expect(mocks.rotateConnectorCredentials).toHaveBeenCalledWith(
        connectorId,
        profileId,
        {
          VENDOR_BASE_URL: 'https://api.vendor.local',
          VENDOR_TOKEN: 'rotated-token',
        },
        [],
        true,
        recoveredAt,
      );
    });
    expect(promptSpy.mock.calls[1]?.[1]).not.toBe(expiredAt);
    expect(await screen.findByText((content) => content.includes(recoveredAt))).toBeInTheDocument();

    await user.click(screen.getAllByTitle('Test Credential Profile')[0]);

    await waitFor(() => {
      expect(mocks.testConnectorCredentialProfile).toHaveBeenCalledWith(connectorId, profileId);
    });

    await user.click(screen.getByTitle('Enable Schedule'));

    await waitFor(() => {
      expect(mocks.enableConnectorSyncSchedule).toHaveBeenCalledWith(scheduleId);
    });
    await waitFor(() => {
      expect(screen.queryByText('Policy Paused')).not.toBeInTheDocument();
    });

    await user.click(screen.getByTitle('Run Schedule Now'));

    await waitFor(() => {
      expect(mocks.runConnectorSyncSchedule).toHaveBeenCalledWith(scheduleId, 'incremental');
    });
    await waitFor(() => {
      expect(screen.getAllByText(recoveredRunId).length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText('Partial').length).toBeGreaterThan(0);
    expect(screen.getByText('Blocked History Retention')).toBeInTheDocument();
    expect(screen.getAllByText(blockedRunId).length).toBeGreaterThan(0);
  });

  it('runs connector operation event and bulk remediation actions', async () => {
    const user = userEvent.setup();
    vi.spyOn(window, 'prompt').mockReturnValue('14');

    renderSecurityConnectors();

    expect((await screen.findAllByText('Operational Events')).length).toBeGreaterThan(0);
    expect(screen.getAllByText('Sync Blocked').length).toBeGreaterThan(0);

    await user.click(screen.getByTitle('Monitor Expiry'));
    await waitFor(() => {
      expect(mocks.monitorConnectorCredentialExpiry).toHaveBeenCalledWith(14, true);
    });

    await user.click(screen.getByTitle('Acknowledge Event'));
    await waitFor(() => {
      expect(mocks.acknowledgeConnectorOperationEvent).toHaveBeenCalledWith(operationEventId);
    });

    await user.click(screen.getByTitle('Resend Notification'));
    await waitFor(() => {
      expect(mocks.notifyConnectorOperationEvent).toHaveBeenCalledWith(operationEventId);
    });

    await user.click(screen.getByTitle('Event Details'));
    expect(await screen.findByText(operationEventId)).toBeInTheDocument();
    await user.click(screen.getByText('Close'));

    await user.click(screen.getByTitle('Select Event'));
    await user.click(screen.getByTitle('Batch Acknowledge'));
    await waitFor(() => {
      expect(mocks.acknowledgeConnectorOperationEvents).toHaveBeenCalledWith([operationEventId]);
    });

    vi.spyOn(window, 'prompt').mockImplementationOnce(() => '21').mockImplementationOnce(() => '3600');
    await user.click(screen.getByTitle('Configure Monitor'));
    await waitFor(() => {
      expect(mocks.updateConnectorOperationsSettings).toHaveBeenCalledWith({
        expiry_monitor: {
          enabled: true,
          days: 21,
          interval_seconds: 3600,
          notify: true,
        },
      });
    });

    await user.click(screen.getByTitle('Bulk Notify'));
    await waitFor(() => {
      expect(mocks.bulkRemediateConnectorCredentials).toHaveBeenCalledWith(
        [{ connector_id: connectorId, profile_id: profileId }],
        'notify',
        'enable',
        true,
      );
    });

    await user.click(screen.getByTitle('Bulk Test'));
    await waitFor(() => {
      expect(mocks.bulkRemediateConnectorCredentials).toHaveBeenCalledWith(
        [{ connector_id: connectorId, profile_id: profileId }],
        'test',
        'preview',
        true,
      );
    });

    await user.click(screen.getByTitle('Bulk Enable'));
    expect(await screen.findByText('Confirm Schedule Recovery')).toBeInTheDocument();
    await user.click(screen.getByText('Confirm'));
    await waitFor(() => {
      expect(mocks.bulkRemediateConnectorCredentials).toHaveBeenCalledWith(
        [{ connector_id: connectorId, profile_id: profileId }],
        'enable_schedules',
        'enable',
        true,
      );
    });
  });
});
