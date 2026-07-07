import client from './client';

export type SecuritySeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';

export type AnalysisCaseStatus = 'new' | 'collecting_evidence' | 'analyzing' | 'awaiting_confirmation' | 'monitoring' | 'resolved' | 'escalated' | 'merged' | 'reopened';
export type AnalysisCaseVerdict = 'confirmed_incident' | 'confirmed_attack_attempt_blocked' | 'suspicious_true_positive' | 'false_positive_rule_noise' | 'benign_business_activity' | 'insufficient_evidence';
export type AnalysisCaseSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type EvidenceCoverage = 'ec0_signal' | 'ec1_single_source' | 'ec2_enriched_single_source' | 'ec3_cross_source' | 'ec4_full_investigation';
export type AnalysisMode = 'single_source' | 'enriched_single_source' | 'cross_source' | 'full_investigation';
export type NotificationDecision = 'realtime_notify' | 'confirmation_request' | 'daily_digest' | 'no_notify_store_only' | 'escalation_reminder';
export type AnalysisNotificationType = 'realtime_notify' | 'confirmation_request' | 'daily_digest' | 'escalation_reminder' | 'manual_note';
export type AnalysisNotificationChannel = 'in_app' | 'manual';
export type AnalysisNotificationStatus = 'pending' | 'sent' | 'acknowledged' | 'canceled';
export type AnalysisConfirmationType = 'confirm_incident' | 'confirm_blocked_attempt' | 'confirm_false_positive' | 'confirm_benign' | 'request_more_evidence' | 'continue_monitoring' | 'escalate_to_incident' | 'close_case';
export type AnalysisConfirmationDecision = 'confirmed' | 'rejected' | 'needs_more_evidence' | 'monitoring' | 'escalated' | 'closed';
export type IncidentDecision = 'escalate_to_incident' | 'do_not_escalate' | 'needs_human_confirmation' | 'continue_monitoring';
export type AnalysisDisposition = 'open' | 'closed_blocked_attempt' | 'closed_false_positive' | 'closed_benign' | 'closed_insufficient_evidence' | 'closed_duplicate' | 'merged_into_case' | 'merged_into_incident' | 'escalated_to_incident' | 'monitoring';
export type FactStrength = 'weak' | 'medium' | 'strong' | 'critical';

export interface SecurityAsset {
  id: string;
  name: string;
  asset_type: string;
  ip?: string | null;
  hostname?: string | null;
  domain?: string | null;
  business_system?: string | null;
  business_owner?: string | null;
  importance: string;
  exposure_level: string;
  environment: string;
  open_ports: number[];
  services: string[];
  protocols: string[];
  security_controls: Record<string, boolean>;
  tags: string[];
  description?: string | null;
  raw_data: Record<string, any>;
  normalized_data: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface SecurityVulnerability {
  id: string;
  asset_id: string;
  cve_id?: string | null;
  title: string;
  severity: SecuritySeverity;
  cvss_score?: number | null;
  epss_score?: number | null;
  kev: boolean;
  exploit_available: boolean;
  description?: string | null;
  affected_component?: string | null;
  remediation?: string | null;
  status: string;
  discovered_at?: string | null;
  raw_data: Record<string, any>;
  normalized_data: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface SecurityAlert {
  id: string;
  asset_id?: string | null;
  source: string;
  title: string;
  severity: SecuritySeverity;
  alert_type?: string | null;
  description?: string | null;
  raw_event: Record<string, any>;
  raw_data: Record<string, any>;
  ioc: string[];
  mitre_technique?: string | null;
  status: string;
  occurred_at?: string | null;
  normalized_data: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface SecurityIncident {
  id: string;
  title: string;
  severity: IncidentSeverity;
  status: string;
  summary: string;
  analysis: string;
  recommendation: string;
  asset_ids: string[];
  vulnerability_ids: string[];
  alert_ids: string[];
  honeypot_event_ids: string[];
  evidence: string[];
  timeline: Record<string, any>[];
  owner?: string | null;
  sla?: string | null;
  close_reason?: string | null;
  confidence: Confidence;
  created_by: string;
  raw_data: Record<string, any>;
  normalized_data: Record<string, any>;
  created_at: string;
  updated_at: string;
}


export interface AnalysisFact {
  id: string;
  fact_type: string;
  statement: string;
  source_ref: string;
  source_connector_id?: string | null;
  source_device_type?: string | null;
  raw_event_ref?: string | null;
  related_asset_id?: string | null;
  related_alert_id?: string | null;
  related_ioc?: string | null;
  confidence: Confidence;
  strength: FactStrength;
  supports: string[];
  contradicts: string[];
  limitations: string[];
  observed_at?: string | null;
  created_at: string;
  metadata: Record<string, any>;
}

export interface AnalysisEvidenceItem {
  id: string;
  title: string;
  description: string;
  source_ref: string;
  related_fact_ids: string[];
  created_at: string;
  metadata: Record<string, any>;
}

export interface AnalysisEvidenceGap {
  id: string;
  gap_type: string;
  description: string;
  missing_source_type?: string | null;
  impact?: string | null;
  suggested_connector_capability?: string | null;
  created_at: string;
  metadata: Record<string, any>;
}


export interface AnalysisNotificationRecord {
  id: string;
  notification_type: AnalysisNotificationType;
  channel: AnalysisNotificationChannel;
  title: string;
  message: string;
  status: AnalysisNotificationStatus;
  recipients: string[];
  related_fact_ids: string[];
  related_evidence_gap_ids: string[];
  created_by: string;
  created_at: string;
  sent_at?: string | null;
  acknowledged_at?: string | null;
  metadata: Record<string, any>;
}

export interface AnalysisConfirmationRecord {
  id: string;
  confirmation_type: AnalysisConfirmationType;
  decision: AnalysisConfirmationDecision;
  comment: string;
  reviewer: string;
  reviewer_role: string;
  related_notification_id?: string | null;
  created_at: string;
  metadata: Record<string, any>;
}

export type AnalysisNotificationCreate = Partial<Omit<AnalysisNotificationRecord, 'id' | 'created_at'>> & { id?: string; created_at?: string };
export type AnalysisConfirmationCreate = Partial<Omit<AnalysisConfirmationRecord, 'id' | 'created_at'>> & {
  confirmation_type: AnalysisConfirmationType;
  decision: AnalysisConfirmationDecision;
  id?: string;
  created_at?: string;
};

export interface AnalysisCase {
  id: string;
  title: string;
  description: string;
  case_status: AnalysisCaseStatus;
  verdict: AnalysisCaseVerdict;
  severity: AnalysisCaseSeverity;
  confidence: Confidence;
  evidence_coverage: EvidenceCoverage;
  analysis_mode: AnalysisMode;
  notification_decision: NotificationDecision;
  incident_decision: IncidentDecision;
  disposition: AnalysisDisposition;
  primary_asset_id?: string | null;
  related_asset_ids: string[];
  related_alert_ids: string[];
  related_vulnerability_ids: string[];
  related_incident_id?: string | null;
  facts: AnalysisFact[];
  evidence_items: AnalysisEvidenceItem[];
  evidence_gaps: AnalysisEvidenceGap[];
  notification_records: AnalysisNotificationRecord[];
  confirmation_records: AnalysisConfirmationRecord[];
  owner?: string | null;
  assignees: string[];
  last_notified_at?: string | null;
  last_confirmed_at?: string | null;
  hypotheses: Record<string, any>[];
  timeline: Record<string, any>[];
  summary: string;
  recommendations: string[];
  created_at: string;
  updated_at: string;
}

export interface AnalysisCaseEscalationResponse {
  case: AnalysisCase;
  incident: SecurityIncident;
  created: boolean;
}

export interface SecurityHoneypotEvent {
  id: string;
  sensor_id?: string | null;
  source_ip?: string | null;
  target_ip?: string | null;
  protocol?: string | null;
  service?: string | null;
  event_type?: string | null;
  payload?: string | null;
  geo: Record<string, any>;
  threat_label?: string | null;
  occurred_at?: string | null;
  raw_data: Record<string, any>;
  normalized_data: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface SecurityFilters {
  asset_id?: string;
  severity?: string;
  status?: string;
  source?: string;
  keyword?: string;
  ip?: string;
  domain?: string;
  hostname?: string;
  importance?: string;
  exposure_level?: string;
  cve_id?: string;
  ioc?: string;
  mitre_technique?: string;
  limit?: number;
}

export interface SecurityReportResponse {
  incident_id: string;
  format: 'markdown';
  content: string;
}

export interface SecurityConnectorHealth {
  status: string;
  message: string;
  checked_at: string;
  latency_ms?: number | null;
  details: Record<string, any>;
}

export interface SecurityConnectorManifest {
  id: string;
  name: string;
  vendor: string;
  product: string;
  product_version?: string | null;
  deployment: string;
  auth_methods: string[];
  capabilities: string[];
  field_mapping: Record<string, Record<string, string>>;
  severity_mapping: Record<string, string>;
  status_mapping: Record<string, string>;
  mapping_contracts: Record<string, any>;
  adapter_contracts: Record<string, any>;
  pagination: Record<string, any>;
  rate_limit: Record<string, any>;
  permissions: string[];
  risk_level: string;
  description: string;
  enabled: boolean;
  raw_response: Record<string, any>;
  normalized_data: Record<string, any>;
  health_check?: SecurityConnectorHealth | null;
}

export interface SecurityConnectorTestResult {
  connector_id: string;
  success: boolean;
  status: string;
  message: string;
  health_check: SecurityConnectorHealth;
  capabilities: string[];
  raw_response: Record<string, any>;
  normalized_data: Record<string, any>;
  warnings: string[];
}

export interface SecurityConnectorValidateResult {
  connector_id: string;
  success: boolean;
  status: string;
  message: string;
  capabilities: string[];
  adapter_contracts: Record<string, any>;
  mapping_contracts: Record<string, any>;
  warnings: string[];
  errors: string[];
}

export interface SecurityConnectorPreviewResult {
  connector_id: string;
  capability: string;
  success: boolean;
  source: string;
  raw_response: Record<string, any>;
  normalized_data: Record<string, any>;
  mapping_result: Record<string, any>;
  adapter_contract: Record<string, any>;
  adapter_request: Record<string, any>;
  mapping_contract: Record<string, any>;
  warnings: string[];
  missing_fields: string[];
  missing_required_fields: string[];
  unmapped_fields: string[];
  transform_warnings: string[];
  missing_capabilities: string[];
}

export interface SecurityConnectorPackageRootDiagnostic {
  source: string;
  root: string;
  exists: boolean;
  manifest_count: number;
}

export interface SecurityConnectorPackageDiagnostic {
  id: string;
  name?: string | null;
  vendor?: string | null;
  product?: string | null;
  version?: string | null;
  package_version?: string | null;
  source: string;
  root: string;
  manifest: string;
  active: boolean;
  discovery_active?: boolean;
  valid: boolean;
  status: 'ok' | 'warning' | 'error' | string;
  enabled: boolean;
  manifest_enabled?: boolean | null;
  installed: boolean;
  installed_version?: string | null;
  installed_hash?: string | null;
  installed_at?: string | null;
  package_hash?: string | null;
  runtime_status: string;
  rollback_available?: boolean;
  last_validation_result?: Record<string, any> | null;
  last_validation_at?: string | null;
  capabilities: string[];
  adapter_count: number;
  mapping_count: number;
  adapters: Record<string, any>;
  mappings: Record<string, any>;
  runtime_validation: Record<string, any>;
  release?: Record<string, any>;
  compatibility?: Record<string, any>;
  warnings: string[];
  errors: string[];
}

export interface SecurityConnectorPackageStagingRecord {
  id: string;
  status: string;
  source?: string;
  filename: string;
  original_filename?: string;
  archive_format?: string;
  artifact_size?: number;
  artifact_hash?: string;
  staging_root?: string;
  extract_root?: string;
  package_root?: string;
  package_id?: string;
  name?: string | null;
  vendor?: string | null;
  product?: string | null;
  version?: string | null;
  package_version?: string | null;
  manifest_path?: string | null;
  package_hash?: string | null;
  uploaded_at?: string;
  validated_at?: string | null;
  installed_at?: string | null;
  installed_package_id?: string | null;
  installed_version?: string | null;
  validation_result?: Record<string, any> | null;
  capabilities?: string[];
  release?: Record<string, any>;
  compatibility?: Record<string, any>;
  warnings?: string[];
  errors?: string[];
}

export interface SecurityConnectorCredentialBinding {
  connector_id: string;
  active_profile_id?: string | null;
  active_profile?: SecurityConnectorCredentialProfile | null;
  profiles?: SecurityConnectorCredentialProfile[];
  profile_count?: number;
  policy_recovery?: SecurityConnectorPolicyRecovery;
  env: Record<string, { kind?: string; configured?: boolean; masked?: string | null; updated_at?: string | null }>;
  env_keys: string[];
  created_at?: string | null;
  updated_at?: string | null;
}

export interface SecurityConnectorCredentialProfile {
  id: string;
  name?: string | null;
  status?: string | null;
  env: Record<string, { kind?: string; configured?: boolean; masked?: string | null; updated_at?: string | null }>;
  env_keys: string[];
  active?: boolean;
  expires_at?: string | null;
  expired?: boolean;
  rotation_count?: number;
  last_rotated_at?: string | null;
  last_test_at?: string | null;
  last_test_status?: string | null;
  last_test_message?: string | null;
  last_sync_at?: string | null;
  last_successful_sync_at?: string | null;
  last_failed_sync_at?: string | null;
  last_sync_run_id?: string | null;
  last_failure_reason?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface SecurityConnectorPolicyAction {
  id: string;
  kind: string;
  label?: string;
  method?: string;
  path?: string;
  connector_id?: string;
  profile_id?: string;
  profile_expires_at?: string | null;
  expires_at?: string | null;
}

export interface SecurityConnectorCredentialHealth {
  version: string;
  connector_id: string;
  profile_id: string;
  status: string;
  healthy: boolean;
  blocking: boolean;
  reason: string;
  reason_code?: string;
  reason_taxonomy?: string;
  severity?: string;
  message: string;
  checked_at: string;
  profile_active?: boolean | null;
  profile?: Record<string, any> | null;
  actions: SecurityConnectorPolicyAction[];
}

export interface SecurityConnectorPolicyRecovery {
  version: string;
  mode: string;
  connector_id: string;
  profile_id: string;
  matched: number;
  recovered: number;
  requires_confirmation: boolean;
  schedules: SecurityConnectorSyncSchedule[];
  credential_health?: SecurityConnectorCredentialHealth;
  healthy?: boolean;
  blocked_reason_code?: string | null;
  blocked_reason?: string | null;
}

export interface SecurityConnectorOperationEvent {
  id: string;
  version: string;
  kind: string;
  status: string;
  severity: string;
  connector_id?: string | null;
  profile_id?: string | null;
  schedule_id?: string | null;
  run_id?: string | null;
  reason_code?: string | null;
  title: string;
  message: string;
  created_at: string;
  last_seen_at: string;
  acknowledged_at?: string | null;
  acknowledged_by?: Record<string, any> | null;
  seen_count: number;
  dedupe_key?: string;
  metadata: Record<string, any>;
  created_by?: Record<string, any> | null;
  updated_by?: Record<string, any> | null;
  notifications?: Record<string, any>[];
}

export interface SecurityConnectorOperationsSettings {
  retention: {
    events_max: number;
    events_days: number;
    bulk_runs_max: number;
    bulk_runs_days: number;
    notification_deliveries_max: number;
    notification_deliveries_days: number;
    audit_max: number;
    audit_days: number;
  };
  expiry_monitor: {
    enabled: boolean;
    days: number;
    interval_seconds: number;
    notify: boolean;
    last_run_at?: string | null;
    next_run_at?: string | null;
    last_result?: Record<string, any> | null;
  };
  notifications: {
    enabled: boolean;
    notify_on_repeat: boolean;
    sinks: Array<Record<string, any>>;
  };
}

export interface SecurityConnectorExpiryMonitorSchedulerStatus {
  running: boolean;
  poll_interval_seconds: number;
  settings: SecurityConnectorOperationsSettings['expiry_monitor'];
  last_tick?: Record<string, any> | null;
}

export interface SecurityCredentialExpiryMonitorResult {
  version: string;
  checked_at: string;
  days: number;
  notify: boolean;
  matched: number;
  expired: number;
  expiring_soon: number;
  profiles: Record<string, any>[];
  events: SecurityConnectorOperationEvent[];
}

export interface SecurityConnectorBulkRemediationItem {
  connector_id: string;
  profile_id: string;
}

export interface SecurityConnectorBulkRemediationResult {
  version: string;
  action: string;
  requested: number;
  succeeded: number;
  failed: number;
  results: Record<string, any>[];
  bulk_run: Record<string, any>;
}

export interface SecurityConnectorRunPolicy {
  version: string;
  decision: string;
  state: string;
  reason: string;
  message: string;
  checked_at?: string;
  actions: SecurityConnectorPolicyAction[];
  credential_health?: SecurityConnectorCredentialHealth;
}

export type SecurityConnectorSyncMode = 'full' | 'incremental';

export interface SecurityConnectorSyncRun {
  id: string;
  connector_id: string;
  capability: string;
  operation?: string;
  trigger?: string;
  schedule_id?: string | null;
  credential_profile_id?: string | null;
  package?: Record<string, any>;
  sync_mode?: SecurityConnectorSyncMode | string;
  cursor_before?: string | null;
  cursor_after?: string | null;
  cursor_updated?: boolean;
  reset_cursor?: boolean;
  status: string;
  started_at: string;
  finished_at?: string | null;
  duration_ms?: number | null;
  source?: string;
  input_counts?: Record<string, number>;
  counts: Record<string, number>;
  object_ids: Record<string, string[]>;
  skipped_counts?: Record<string, number>;
  quality?: Record<string, any>;
  dead_letter_count?: number;
  evidence_graph?: Record<string, any>;
  evidence_impact?: Record<string, any>;
  run_control?: Record<string, any>;
  run_policy?: SecurityConnectorRunPolicy;
  credential_health?: SecurityConnectorCredentialHealth;
  replay?: Record<string, any>;
  orchestration?: Record<string, any>;
  warnings: string[];
  errors: string[];
}

export interface SecurityConnectorSyncCursor {
  key: string;
  connector_id: string;
  capability: string;
  cursor: string;
  updated_at?: string | null;
  last_run_id?: string | null;
  source?: string | null;
}

export interface SecurityConnectorSyncDeadLetter {
  id: string;
  run_id: string;
  connector_id: string;
  capability: string;
  target: string;
  index: number;
  status: string;
  errors: string[];
  warnings: string[];
  evidence: Record<string, any>;
  payload: Record<string, any>;
  replay_count?: number;
  last_replay_at?: string | null;
  last_replay_run_id?: string | null;
  last_replay_status?: string | null;
  last_replay_errors?: string[];
  replayed_at?: string | null;
  replayed_object_id?: string | null;
  created_at: string;
}

export interface SecurityConnectorSyncSchedule {
  id: string;
  connector_id: string;
  capability: string;
  enabled: boolean;
  interval_seconds: number;
  mode: SecurityConnectorSyncMode | string;
  full_interval_seconds?: number | null;
  retry_max_attempts: number;
  retry_backoff_seconds: number;
  timeout_seconds: number;
  credential_profile_id?: string | null;
  runtime_status?: string;
  due?: boolean;
  next_run_at?: string | null;
  next_full_run_at?: string | null;
  last_run_id?: string | null;
  last_run_at?: string | null;
  last_successful_run_at?: string | null;
  last_failed_run_at?: string | null;
  last_status?: string | null;
  last_error?: string | null;
  last_trigger?: string | null;
  last_duration_ms?: number | null;
  last_mode?: string | null;
  consecutive_failures?: number;
  policy_state?: string | null;
  policy_reason?: string | null;
  policy_reason_code?: string | null;
  policy_message?: string | null;
  policy_actions?: SecurityConnectorPolicyAction[];
  policy_paused_at?: string | null;
  run_policy?: SecurityConnectorRunPolicy;
  run_count?: number;
  manual_run_count?: number;
  scheduled_run_count?: number;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface SecurityConnectorSyncScheduleRun {
  status: string;
  schedule: SecurityConnectorSyncSchedule;
  run?: SecurityConnectorSyncRun | Record<string, any> | null;
}

export interface SecurityConnectorSyncRunRegistrySummary {
  path?: string;
  version?: string;
  runs?: number;
  cursors?: number;
  dead_letters?: number;
  pending_dead_letters?: number;
  replayed_dead_letters?: number;
  blocked_runs?: number;
  audit_events?: number;
  blocked_run_retention?: {
    retained: boolean;
    reason: string;
    message: string;
  };
  last_blocked_run?: SecurityConnectorSyncRun | null;
  active_runs?: number;
  controls?: number;
  last_run?: SecurityConnectorSyncRun | null;
}

export interface SecurityConnectorOperationsSummary {
  path?: string;
  version?: string;
  events?: number;
  open_events?: number;
  events_by_kind?: Record<string, number>;
  open_events_by_kind?: Record<string, number>;
  bulk_runs?: number;
  last_event?: SecurityConnectorOperationEvent | null;
}

export interface SecurityConnectorOperationsDashboardTrendBucket {
  date: string;
  expiry_risks: number;
  blocked_runs: number;
  policy_paused_schedules: number;
  recoveries: number;
  bulk_requested: number;
  bulk_succeeded: number;
  bulk_failed: number;
  operation_events: number;
}

export interface SecurityConnectorOperationsDashboardBulkAction {
  runs: number;
  requested: number;
  succeeded: number;
  failed: number;
  success_rate: number | null;
}

export interface SecurityConnectorOperationsDashboard {
  version: string;
  checked_at: string;
  window_days: number;
  expiry_warning_days: number;
  current: {
    expiry_risks: number;
    expired_profiles: number;
    expiring_profiles: number;
    blocked_runs: number;
    policy_paused_schedules: number;
    open_events: number;
    bulk_runs: number;
    average_recovery_seconds?: number | null;
  };
  mttr: {
    seconds?: number | null;
    samples: number;
    event_samples: number;
    schedule_samples: number;
  };
  bulk: {
    runs: number;
    requested: number;
    succeeded: number;
    failed: number;
    success_rate: number | null;
    latest_run?: Record<string, any> | null;
    by_action: Record<string, SecurityConnectorOperationsDashboardBulkAction>;
  };
  trend: SecurityConnectorOperationsDashboardTrendBucket[];
}

export interface SecurityConnectorPackageDiagnostics {
  checked_at: string;
  version: string;
  installed_registry?: Record<string, any> | null;
  staging_registry?: Record<string, any> | null;
  sync_run_registry?: SecurityConnectorSyncRunRegistrySummary;
  summary: {
    roots: number;
    packages: number;
    active_packages: number;
    installed_packages?: number;
    enabled_packages?: number;
    staging_packages?: number;
    validated_staging_packages?: number;
    invalid_staging_packages?: number;
    credential_bindings?: number;
    sync_runs?: number;
    active_sync_runs?: number;
    sync_cursors?: number;
    sync_dead_letters?: number;
    pending_sync_dead_letters?: number;
    replayed_sync_dead_letters?: number;
    blocked_sync_runs?: number;
    sync_schedules?: number;
    enabled_sync_schedules?: number;
    due_sync_schedules?: number;
    policy_paused_sync_schedules?: number;
    connector_operation_events?: number;
    open_connector_operation_events?: number;
    expiry_risks?: number;
    average_recovery_seconds?: number | null;
    bulk_remediation_runs?: number;
    bulk_remediation_failed?: number;
    evidence_graph_nodes?: number;
    evidence_graph_edges?: number;
    evidence_graph_entities?: number;
    evidence_graph_conflicts?: number;
    valid_packages: number;
    invalid_packages: number;
    errors: number;
    warnings: number;
  };
  roots: SecurityConnectorPackageRootDiagnostic[];
  packages: SecurityConnectorPackageDiagnostic[];
  staging_packages?: SecurityConnectorPackageStagingRecord[];
  credential_bindings?: SecurityConnectorCredentialBinding[];
  sync_runs?: SecurityConnectorSyncRun[];
  active_sync_runs?: SecurityConnectorSyncRun[];
  sync_cursors?: SecurityConnectorSyncCursor[];
  sync_dead_letters?: SecurityConnectorSyncDeadLetter[];
  sync_schedules?: SecurityConnectorSyncSchedule[];
  connector_operations?: SecurityConnectorOperationsSummary;
  operation_events?: SecurityConnectorOperationEvent[];
  operations_dashboard?: SecurityConnectorOperationsDashboard;
  evidence_graph?: SecurityEvidenceGraphSummary;
}

export interface SecurityConnectorCustomerAction {
  id: string;
  kind: string;
  label: string;
  connector_id?: string;
  profile_id?: string | null;
  schedule_id?: string | null;
  requires_confirmation?: boolean;
}

export interface SecurityConnectorCustomerCredential {
  profile_id?: string | null;
  profile_name?: string | null;
  state: string;
  healthy: boolean;
  blocking: boolean;
  expires_at?: string | null;
  last_test_at?: string | null;
  last_sync_at?: string | null;
  last_successful_sync_at?: string | null;
  fields?: Array<{ key: string; kind: 'secret' | 'value' | string; configured: boolean }>;
  message: string;
  recommended_action: string;
}

export interface SecurityConnectorCustomerSync {
  status: string;
  last_sync_at?: string | null;
  last_successful_sync_at?: string | null;
  counts: {
    assets: number;
    vulnerabilities: number;
    alerts: number;
    honeypot_events: number;
  };
  failure_reason?: string | null;
  recommended_action: string;
}

export interface SecurityConnectorCustomerSchedule {
  id: string;
  connector_id?: string;
  capability?: string;
  enabled: boolean;
  status: string;
  mode?: string;
  interval_seconds?: number;
  full_interval_seconds?: number | null;
  retry_max_attempts?: number | null;
  retry_backoff_seconds?: number | null;
  timeout_seconds?: number | null;
  credential_profile_id?: string | null;
  next_run_at?: string | null;
  last_run_at?: string | null;
  last_successful_run_at?: string | null;
  last_status?: string | null;
  last_error?: string | null;
  message: string;
  recommended_action: string;
}

export interface SecurityConnectorCustomerDataSource {
  id: string;
  type: 'connector';
  name: string;
  vendor?: string | null;
  product?: string | null;
  product_version?: string | null;
  enabled: boolean;
  connection_status: string;
  sync_status: string;
  risk_level: string;
  message: string;
  capabilities: string[];
  sync_targets: string[];
  credential: SecurityConnectorCustomerCredential;
  sync: SecurityConnectorCustomerSync;
  schedules: SecurityConnectorCustomerSchedule[];
  actions: SecurityConnectorCustomerAction[];
}

export interface SecurityConnectorCustomerEvent {
  id: string;
  kind: string;
  label: string;
  severity: string;
  connector_id?: string | null;
  connector_name?: string | null;
  profile_id?: string | null;
  schedule_id?: string | null;
  created_at?: string | null;
  last_seen_at?: string | null;
  message: string;
  recommended_action: string;
}

export interface SecurityConnectorCustomerTrendBucket {
  date: string;
  expiry_risks: number;
  sync_blocked: number;
  paused_schedules: number;
  recoveries: number;
}

export interface SecurityConnectorCustomerSummary {
  version: string;
  checked_at: string;
  trend_window_days: number;
  summary: {
    device_api_note?: string;
    data_sources: number;
    connected_data_sources: number;
    attention_data_sources: number;
    sync_schedules: number;
    enabled_sync_schedules: number;
    expiry_risks: number;
    sync_blocked: number;
    paused_schedules: number;
    recent_anomalies: number;
  };
  data_sources: SecurityConnectorCustomerDataSource[];
  recent_events: SecurityConnectorCustomerEvent[];
  trend: SecurityConnectorCustomerTrendBucket[];
}

export interface SecurityConnectorCustomerActionResult {
  connector_id?: string;
  schedule_id?: string;
  success?: boolean;
  status: string;
  message: string;
  checked_at?: string;
  latency_ms?: number | null;
  schedule?: Record<string, any>;
  credential?: Record<string, any>;
  policy_recovery?: Record<string, any>;
}

export interface SecurityConnectorCustomerDeviceSyncResult {
  connector_id: string;
  device_id: string;
  profile_id: string;
  status: string;
  message: string;
  capabilities: string[];
  schedules: SecurityConnectorSyncSchedule[];
  credential?: {
    healthy?: boolean;
    blocking?: boolean;
    state?: string;
    message?: string;
  };
  policy_recovery?: Record<string, any> | null;
}

export interface SecurityEvidenceGraphSummary {
  version?: string;
  path?: string;
  updated_at?: string | null;
  nodes: number;
  edges: number;
  asset_entities: number;
  merge_candidates: number;
  conflicts: number;
  objects?: Record<string, number>;
  connector_sources?: string[];
}

export interface SecurityEvidenceGraph {
  version: string;
  updated_at?: string | null;
  summary: SecurityEvidenceGraphSummary;
  nodes: Record<string, any>[];
  edges: Record<string, any>[];
  entities: Record<string, any>[];
  merge_candidates: Record<string, any>[];
  conflicts: Record<string, any>[];
  indexes: Record<string, any>;
}

export interface SecurityRiskScore {
  score: number;
  level: string;
  reasons: string[];
  recommendations: string[];
}

export interface SecurityAssetRiskProfile {
  asset: SecurityAsset;
  vulnerabilities: SecurityVulnerability[];
  alerts: SecurityAlert[];
  incidents: SecurityIncident[];
  honeypot_events: SecurityHoneypotEvent[];
  risk_score: SecurityRiskScore;
  confirmed_facts: string[];
  evidence: string[];
  inferences: string[];
  uncertainties: string[];
  recommended_actions: string[];
  normalized_data: Record<string, any>;
}

export interface SecurityVulnerabilityPriority {
  vulnerability: SecurityVulnerability;
  asset?: SecurityAsset | null;
  related_alerts: SecurityAlert[];
  honeypot_events: SecurityHoneypotEvent[];
  risk_score: SecurityRiskScore;
  priority: string;
  factors: string[];
  recommended_actions: string[];
}

export const securityAPI = {
  health: () => client.get('/api/security/health'),
  getEvidenceGraph: () => client.get<SecurityEvidenceGraph>('/api/security/evidence-graph'),
  rebuildEvidenceGraph: () => client.post<SecurityEvidenceGraph>('/api/security/evidence-graph/rebuild'),

  listConnectors: () => client.get<SecurityConnectorManifest[]>('/api/security/connectors'),
  connectorPackageDiagnostics: () =>
    client.get<SecurityConnectorPackageDiagnostics>('/api/security/connectors/package-diagnostics'),
  customerConnectorSummary: (trendDays = 14) =>
    client.get<SecurityConnectorCustomerSummary>('/api/security/connectors/customer-summary', {
      params: { trend_days: trendDays },
    }),
  installConnectorPackage: (packageRoot: string, enabled = false) =>
    client.post<Record<string, any>>('/api/security/connectors/packages/install', { package_root: packageRoot, enabled }),
  enableConnectorPackage: (packageId: string) =>
    client.post<Record<string, any>>(`/api/security/connectors/packages/${packageId}/enable`),
  disableConnectorPackage: (packageId: string) =>
    client.post<Record<string, any>>(`/api/security/connectors/packages/${packageId}/disable`),
  uninstallConnectorPackage: (packageId: string) =>
    client.delete<Record<string, any>>(`/api/security/connectors/packages/${packageId}`),
  rollbackConnectorPackage: (packageId: string) =>
    client.post<Record<string, any>>(`/api/security/connectors/packages/${packageId}/rollback`),
  bindConnectorCredentials: (
    connectorId: string,
    values: Record<string, string>,
    secretKeys: string[] = [],
    profileId = 'default',
    profileName?: string | null,
    makeActive = true,
    expiresAt?: string | null,
    recoverPolicyPausedSchedules = 'preview',
  ) =>
    client.put<SecurityConnectorCredentialBinding>(`/api/security/connectors/${connectorId}/credentials`, {
      values,
      secret_keys: secretKeys,
      profile_id: profileId,
      profile_name: profileName || null,
      make_active: makeActive,
      expires_at: expiresAt || null,
      recover_policy_paused_schedules: recoverPolicyPausedSchedules,
    }),
  rotateConnectorCredentials: (
    connectorId: string,
    profileId: string,
    values: Record<string, string>,
    secretKeys: string[] = [],
    makeActive = true,
    expiresAt?: string | null,
    recoverPolicyPausedSchedules = 'preview',
  ) =>
    client.post<SecurityConnectorCredentialBinding>(`/api/security/connectors/${connectorId}/credentials/profiles/${profileId}/rotate`, {
      values,
      secret_keys: secretKeys,
      make_active: makeActive,
      expires_at: expiresAt || null,
      recover_policy_paused_schedules: recoverPolicyPausedSchedules,
    }),
  activateConnectorCredentialProfile: (connectorId: string, profileId: string) =>
    client.post<SecurityConnectorCredentialBinding>(`/api/security/connectors/${connectorId}/credentials/profiles/${profileId}/activate`),
  testConnectorCredentialProfile: (connectorId: string, profileId: string) =>
    client.post<SecurityConnectorTestResult>(`/api/security/connectors/${connectorId}/credentials/profiles/${profileId}/test`),
  deleteConnectorCredentialProfile: (connectorId: string, profileId: string) =>
    client.delete<SecurityConnectorCredentialBinding>(`/api/security/connectors/${connectorId}/credentials/profiles/${profileId}`),
  getConnectorCredentialHealth: (connectorId: string, profileId?: string | null) =>
    client.get<SecurityConnectorCredentialHealth>(`/api/security/connectors/${connectorId}/credentials/health`, {
      params: profileId ? { profile_id: profileId } : undefined,
    }),
  recoverConnectorCredentialPolicyPauses: (connectorId: string, profileId: string, mode = 'preview') =>
    client.post<SecurityConnectorPolicyRecovery>(`/api/security/connectors/${connectorId}/credentials/profiles/${profileId}/policy-pauses/recover`, {
      mode,
    }),
  listConnectorOperationEvents: (params?: {
    status?: string;
    kind?: string;
    severity?: string;
    connector_id?: string;
    profile_id?: string;
    schedule_id?: string;
    reason_code?: string;
    keyword?: string;
    limit?: number;
  }) =>
    client.get<{ items: SecurityConnectorOperationEvent[] }>('/api/security/connectors/operations/events', { params }),
  getConnectorOperationEvent: (eventId: string) =>
    client.get<SecurityConnectorOperationEvent>(`/api/security/connectors/operations/events/${eventId}`),
  acknowledgeConnectorOperationEvent: (eventId: string) =>
    client.post<SecurityConnectorOperationEvent>(`/api/security/connectors/operations/events/${eventId}/ack`),
  acknowledgeConnectorOperationEvents: (eventIds: string[]) =>
    client.post<Record<string, any>>('/api/security/connectors/operations/events/ack', { event_ids: eventIds }),
  notifyConnectorOperationEvent: (eventId: string) =>
    client.post<{ items: Record<string, any>[] }>(`/api/security/connectors/operations/events/${eventId}/notify`),
  getConnectorOperationsSettings: () =>
    client.get<SecurityConnectorOperationsSettings>('/api/security/connectors/operations/settings'),
  updateConnectorOperationsSettings: (settings: Partial<SecurityConnectorOperationsSettings>) =>
    client.patch<SecurityConnectorOperationsSettings>('/api/security/connectors/operations/settings', settings),
  monitorConnectorCredentialExpiry: (days?: number | null, notify?: boolean | null) =>
    client.post<SecurityCredentialExpiryMonitorResult>('/api/security/connectors/credentials/expiry-monitor', {
      days: days ?? null,
      notify: notify ?? null,
    }),
  getConnectorCredentialExpiryMonitorStatus: () =>
    client.get<SecurityConnectorExpiryMonitorSchedulerStatus>('/api/security/connectors/credentials/expiry-monitor/status'),
  tickConnectorCredentialExpiryMonitor: () =>
    client.post<Record<string, any>>('/api/security/connectors/credentials/expiry-monitor/tick'),
  bulkRemediateConnectorCredentials: (
    items: SecurityConnectorBulkRemediationItem[],
    action: 'test' | 'enable_schedules' | 'notify' | string,
    recoveryMode = 'enable',
    notify = true,
  ) =>
    client.post<SecurityConnectorBulkRemediationResult>('/api/security/connectors/credentials/bulk-remediation', {
      items,
      action,
      recovery_mode: recoveryMode,
      notify,
    }),
  syncConnector: (
    connectorId: string,
    capability: string,
    mode: SecurityConnectorSyncMode | string = 'full',
    resetCursor = false,
    credentialProfileId?: string | null,
  ) =>
    client.post<SecurityConnectorSyncRun>(`/api/security/connectors/${connectorId}/sync`, {
      capability,
      mode,
      reset_cursor: resetCursor,
      credential_profile_id: credentialProfileId || null,
    }),
  listConnectorSyncRuns: (connectorId?: string) =>
    client.get<{ items: SecurityConnectorSyncRun[] }>('/api/security/connectors/sync-runs', {
      params: connectorId ? { connector_id: connectorId } : undefined,
    }),
  listActiveConnectorSyncRuns: (connectorId?: string, capability?: string) =>
    client.get<{ items: SecurityConnectorSyncRun[] }>('/api/security/connectors/sync-runs/active', {
      params: {
        ...(connectorId ? { connector_id: connectorId } : {}),
        ...(capability ? { capability } : {}),
      },
    }),
  cancelConnectorSyncRun: (runId: string) =>
    client.post<Record<string, any>>(`/api/security/connectors/sync-runs/${runId}/cancel`),
  listConnectorSyncCursors: (connectorId?: string) =>
    client.get<{ items: SecurityConnectorSyncCursor[] }>('/api/security/connectors/sync-cursors', {
      params: connectorId ? { connector_id: connectorId } : undefined,
    }),
  listConnectorSyncDeadLetters: (connectorId?: string, status?: string) =>
    client.get<{ items: SecurityConnectorSyncDeadLetter[] }>('/api/security/connectors/sync-dead-letters', {
      params: {
        ...(connectorId ? { connector_id: connectorId } : {}),
        ...(status ? { status } : {}),
      },
    }),
  replayConnectorSyncDeadLetters: (
    ids: string[] = [],
    connectorId?: string | null,
    payloadUpdates: Record<string, Record<string, any>> = {},
    limit = 50,
  ) =>
    client.post<SecurityConnectorSyncRun>('/api/security/connectors/sync-dead-letters/replay', {
      ids,
      connector_id: connectorId || null,
      payload_updates: payloadUpdates,
      limit,
    }),
  resetConnectorSyncCursor: (connectorId: string, capability?: string) =>
    client.post<Record<string, any>>(`/api/security/connectors/${connectorId}/sync-cursor/reset`, {
      capability: capability || null,
    }),
  cancelConnectorSync: (connectorId: string, capability?: string) =>
    client.post<Record<string, any>>(`/api/security/connectors/${connectorId}/sync/cancel`, {
      capability: capability || null,
    }),
  customerTestConnector: (connectorId: string, profileId?: string | null) =>
    client.post<SecurityConnectorCustomerActionResult>(`/api/security/connectors/${connectorId}/customer-test`, {
      profile_id: profileId || null,
    }),
  customerEnableConnectorSchedule: (scheduleId: string) =>
    client.post<SecurityConnectorCustomerActionResult>(`/api/security/connectors/sync-schedules/${scheduleId}/customer-enable`),
  customerDisableConnectorSchedule: (scheduleId: string) =>
    client.post<SecurityConnectorCustomerActionResult>(`/api/security/connectors/sync-schedules/${scheduleId}/customer-disable`),
  customerUpdateConnectorCredentials: (
    connectorId: string,
    values: Record<string, string>,
    secretKeys: string[] = [],
    profileId = 'default',
    profileName?: string | null,
    makeActive = true,
    expiresAt?: string | null,
  ) =>
    client.put<SecurityConnectorCustomerActionResult>(`/api/security/connectors/${connectorId}/customer-credentials`, {
      values,
      secret_keys: secretKeys,
      profile_id: profileId,
      profile_name: profileName || null,
      make_active: makeActive,
      expires_at: expiresAt || null,
    }),
  customerEnableDeviceSync: (
    connectorId: string,
    deviceId: string,
    options?: {
      profile_id?: string | null;
      enabled?: boolean;
      interval_seconds?: number;
      mode?: string;
      capabilities?: string[] | null;
    },
  ) =>
    client.post<SecurityConnectorCustomerDeviceSyncResult>(`/api/security/connectors/${connectorId}/customer-device-sync`, {
      device_id: deviceId,
      profile_id: options?.profile_id || null,
      enabled: options?.enabled ?? true,
      interval_seconds: options?.interval_seconds ?? 3600,
      mode: options?.mode || 'incremental',
      capabilities: options?.capabilities || null,
    }),
  upsertConnectorSyncSchedule: (
    connectorId: string,
    payload: {
      capability: string;
      enabled?: boolean;
      interval_seconds?: number;
      mode?: string;
      full_interval_seconds?: number | null;
      retry_max_attempts?: number;
      retry_backoff_seconds?: number;
      timeout_seconds?: number;
      credential_profile_id?: string | null;
    },
  ) => client.put<SecurityConnectorSyncSchedule>(`/api/security/connectors/${connectorId}/sync-schedule`, payload),
  runConnectorSyncSchedule: (scheduleId: string, mode?: string) =>
    client.post<SecurityConnectorSyncScheduleRun>(`/api/security/connectors/sync-schedules/${scheduleId}/run`, { mode: mode || null }),
  enableConnectorSyncSchedule: (scheduleId: string) =>
    client.post<SecurityConnectorSyncSchedule>(`/api/security/connectors/sync-schedules/${scheduleId}/enable`),
  disableConnectorSyncSchedule: (scheduleId: string) =>
    client.post<SecurityConnectorSyncSchedule>(`/api/security/connectors/sync-schedules/${scheduleId}/disable`),
  listStagedConnectorPackages: () =>
    client.get<{ items: SecurityConnectorPackageStagingRecord[] }>('/api/security/connectors/packages/staging'),
  uploadConnectorPackageArtifact: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return client.post<SecurityConnectorPackageStagingRecord>('/api/security/connectors/packages/staging/upload', formData);
  },
  validateStagedConnectorPackage: (stagingId: string) =>
    client.post<SecurityConnectorPackageStagingRecord>(`/api/security/connectors/packages/staging/${stagingId}/validate`),
  installStagedConnectorPackage: (stagingId: string, enabled = false) =>
    client.post<Record<string, any>>(`/api/security/connectors/packages/staging/${stagingId}/install`, { enabled }),
  discardStagedConnectorPackage: (stagingId: string) =>
    client.delete<SecurityConnectorPackageStagingRecord>(`/api/security/connectors/packages/staging/${stagingId}`),
  getConnector: (id: string) => client.get<SecurityConnectorManifest>(`/api/security/connectors/${id}`),
  testConnector: (id: string) => client.post<SecurityConnectorTestResult>(`/api/security/connectors/${id}/test`),
  validateConnector: (id: string) => client.post<SecurityConnectorValidateResult>(`/api/security/connectors/${id}/validate`),
  previewConnector: (id: string, capability: string) =>
    client.post<SecurityConnectorPreviewResult>(`/api/security/connectors/${id}/preview`, null, { params: { capability } }),
  listConnectorCapabilities: (id: string) =>
    client.get<{ connector_id: string; capabilities: string[] }>(`/api/security/connectors/${id}/capabilities`),

  listAssets: (params?: SecurityFilters) => client.get<SecurityAsset[]>('/api/security/assets', { params }),
  getAsset: (id: string) => client.get<SecurityAsset>(`/api/security/assets/${id}`),
  getAssetRiskProfile: (id: string) => client.get<SecurityAssetRiskProfile>(`/api/security/assets/${id}/risk-profile`),
  createAsset: (data: Partial<SecurityAsset>) => client.post<SecurityAsset>('/api/security/assets', data),
  updateAsset: (id: string, data: Partial<SecurityAsset>) => client.patch<SecurityAsset>(`/api/security/assets/${id}`, data),
  deleteAsset: (id: string) => client.delete(`/api/security/assets/${id}`),

  listVulnerabilities: (params?: SecurityFilters) =>
    client.get<SecurityVulnerability[]>('/api/security/vulnerabilities', { params }),
  prioritizeVulnerabilities: (params?: SecurityFilters) =>
    client.get<SecurityVulnerabilityPriority[]>('/api/security/vulnerabilities/prioritized', { params }),
  createVulnerability: (data: Partial<SecurityVulnerability>) =>
    client.post<SecurityVulnerability>('/api/security/vulnerabilities', data),
  updateVulnerability: (id: string, data: Partial<SecurityVulnerability>) =>
    client.patch<SecurityVulnerability>(`/api/security/vulnerabilities/${id}`, data),
  deleteVulnerability: (id: string) => client.delete(`/api/security/vulnerabilities/${id}`),

  listAlerts: (params?: SecurityFilters) => client.get<SecurityAlert[]>('/api/security/alerts', { params }),
  createAlert: (data: Partial<SecurityAlert>) => client.post<SecurityAlert>('/api/security/alerts', data),
  updateAlert: (id: string, data: Partial<SecurityAlert>) => client.patch<SecurityAlert>(`/api/security/alerts/${id}`, data),
  deleteAlert: (id: string) => client.delete(`/api/security/alerts/${id}`),
  triageAlert: (id: string, createIncident = true) =>
    client.post(`/api/security/triage/alert/${id}`, null, { params: { createIncident } }),
  createIncidentFromAlert: (id: string) => client.post(`/api/security/incidents/from-alert/${id}`),


  listAnalysisCases: (params?: SecurityFilters) => client.get<AnalysisCase[]>('/api/security/analysis-cases', { params }),
  getAnalysisCase: (id: string) => client.get<AnalysisCase>(`/api/security/analysis-cases/${id}`),
  createAnalysisCase: (data: Partial<AnalysisCase>) => client.post<AnalysisCase>('/api/security/analysis-cases', data),
  updateAnalysisCase: (id: string, data: Partial<AnalysisCase>) =>
    client.patch<AnalysisCase>(`/api/security/analysis-cases/${id}`, data),
  deleteAnalysisCase: (id: string) => client.delete(`/api/security/analysis-cases/${id}`),
  createAnalysisCaseFromAlert: (id: string) => client.post<AnalysisCase>(`/api/security/analysis-cases/from-alert/${id}`),
  runInitialAnalysis: (id: string) => client.post<AnalysisCase>(`/api/security/analysis-cases/${id}/run-initial-analysis`),
  escalateAnalysisCaseToIncident: (id: string) =>
    client.post<AnalysisCaseEscalationResponse>(`/api/security/analysis-cases/${id}/escalate-to-incident`),
  createAnalysisCaseNotification: (caseId: string, data: AnalysisNotificationCreate) =>
    client.post<AnalysisCase>(`/api/security/analysis-cases/${caseId}/notifications`, data),
  createAnalysisCaseConfirmation: (caseId: string, data: AnalysisConfirmationCreate) =>
    client.post<AnalysisCase>(`/api/security/analysis-cases/${caseId}/confirmations`, data),
  ackAnalysisCaseNotification: (caseId: string, notificationId: string, data?: { reviewer?: string; comment?: string }) =>
    client.post<AnalysisCase>(`/api/security/analysis-cases/${caseId}/notifications/${notificationId}/ack`, data || {}),

  listIncidents: (params?: SecurityFilters) => client.get<SecurityIncident[]>('/api/security/incidents', { params }),
  createIncident: (data: Partial<SecurityIncident>) => client.post<SecurityIncident>('/api/security/incidents', data),
  updateIncident: (id: string, data: Partial<SecurityIncident>) =>
    client.patch<SecurityIncident>(`/api/security/incidents/${id}`, data),
  deleteIncident: (id: string) => client.delete(`/api/security/incidents/${id}`),
  generateIncidentReport: (id: string) =>
    client.post<SecurityReportResponse>(`/api/security/reports/incident/${id}`),

  listHoneypotEvents: (params?: SecurityFilters) =>
    client.get<SecurityHoneypotEvent[]>('/api/security/honeypot-events', { params }),
  createHoneypotEvent: (data: Partial<SecurityHoneypotEvent>) =>
    client.post<SecurityHoneypotEvent>('/api/security/honeypot-events', data),
  updateHoneypotEvent: (id: string, data: Partial<SecurityHoneypotEvent>) =>
    client.patch<SecurityHoneypotEvent>(`/api/security/honeypot-events/${id}`, data),
  deleteHoneypotEvent: (id: string) => client.delete(`/api/security/honeypot-events/${id}`),

  loadSampleData: () => client.post('/api/security/sample-data/load'),
  clearSampleData: () => client.delete('/api/security/sample-data/clear'),
};
