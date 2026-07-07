import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Activity,
  AlertTriangle,
  Bell,
  Brain,
  Bug,
  CheckCircle2,
  Clock,
  Database,
  Download,
  Edit3,
  Eraser,
  Eye,
  FileText,
  KeyRound,
  Plug,
  Plus,
  Power,
  PowerOff,
  PlayCircle,
  Radar,
  RefreshCw,
  RotateCcw,
  Send,
  SlidersHorizontal,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UploadCloud,
  XCircle,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import PageHeader from '@/components/common/PageHeader';
import LoadingSpinner from '@/components/common/LoadingSpinner';
import {
  securityAPI,
  type AnalysisCase,
  type SecurityAlert,
  type SecurityAssetRiskProfile,
  type SecurityAsset,
  type SecurityConnectorManifest,
  type SecurityConnectorCredentialProfile,
  type SecurityConnectorBulkRemediationItem,
  type SecurityConnectorOperationEvent,
  type SecurityConnectorOperationsSettings,
  type SecurityConnectorExpiryMonitorSchedulerStatus,
  type SecurityConnectorPackageDiagnostics,
  type SecurityConnectorPolicyAction,
  type SecurityConnectorPackageStagingRecord,
  type SecurityConnectorPreviewResult,
  type SecurityConnectorTestResult,
  type SecurityConnectorValidateResult,
  type SecurityEvidenceGraph,
  type SecurityHoneypotEvent,
  type SecurityIncident,
  type SecurityVulnerability,
  type EvidenceIngestionContext,
  type EvidenceIngestionResponse,
} from '@/api/security';

type Section = 'dashboard' | 'assets' | 'vulnerabilities' | 'alerts' | 'analysis-cases' | 'evidence-ingestion' | 'incidents' | 'honeypot-events' | 'connectors';
type DataSection = Exclude<Section, 'dashboard' | 'connectors' | 'evidence-ingestion'>;
type Entity = Record<string, any> & { id: string };
type SecurityMode = 'expert' | 'admin';
type AssetRiskLevel = 'critical' | 'high' | 'medium' | 'low';
type AssetRiskFilter = 'all' | 'attention' | 'critical' | 'exposed' | 'identity';

interface SecurityPageProps {
  basePath?: string;
  mode?: SecurityMode;
}

interface FieldConfig {
  name: string;
  labelKey: string;
  type?: 'text' | 'textarea' | 'select' | 'checkbox' | 'number' | 'json' | 'array';
  options?: string[];
  required?: boolean;
}

interface TableColumn {
  key: string;
  labelKey: string;
}

const navItems: Array<{ section: Section; icon: LucideIcon; adminOnly?: boolean }> = [
  { section: 'dashboard', icon: ShieldCheck },
  { section: 'assets', icon: Database },
  { section: 'vulnerabilities', icon: Bug },
  { section: 'alerts', icon: Bell },
  { section: 'analysis-cases', icon: FileText },
  { section: 'evidence-ingestion', icon: UploadCloud },
  { section: 'incidents', icon: ShieldAlert },
  { section: 'honeypot-events', icon: Radar },
  { section: 'connectors', icon: Plug, adminOnly: true },
];

const supportedSections: Section[] = ['assets', 'vulnerabilities', 'alerts', 'analysis-cases', 'evidence-ingestion', 'incidents', 'honeypot-events', 'connectors'];
const severityOptions = ['info', 'low', 'medium', 'high', 'critical'];
const incidentSeverityOptions = ['low', 'medium', 'high', 'critical'];
const analysisCaseSeverityOptions = ['informational', 'low', 'medium', 'high', 'critical'];
const importanceOptions = ['low', 'medium', 'high', 'critical'];
const exposureOptions = ['internal', 'external', 'unknown'];
const environmentOptions = ['production', 'staging', 'testing', 'development', 'unknown'];
const emptyOperationEvents: SecurityConnectorOperationEvent[] = [];

interface AssetIdentitySummary {
  strongCount: number;
  auxiliaryCount: number;
  weakCount: number;
  entityIds: string[];
  mergeCandidateIds: string[];
  conflictIds: string[];
  ipObservations: Record<string, any>[];
  sourceLabel?: string | null;
  allocationMode?: string | null;
  firstSeen?: string | null;
  lastSeen?: string | null;
}

interface AssetRiskContext {
  asset: SecurityAsset;
  level: AssetRiskLevel;
  score: number;
  reasons: string[];
  vulnerabilities: SecurityVulnerability[];
  alerts: SecurityAlert[];
  incidents: SecurityIncident[];
  honeypotEvents: SecurityHoneypotEvent[];
  identity: AssetIdentitySummary;
  lastSeenAt?: string | null;
}

const fields: Record<DataSection, FieldConfig[]> = {
  assets: [
    { name: 'name', labelKey: 'fields.name', required: true },
    { name: 'asset_type', labelKey: 'fields.asset_type', type: 'select', options: ['server', 'endpoint', 'network_device', 'security_device', 'web_app', 'api', 'database', 'cloud_resource', 'other'] },
    { name: 'ip', labelKey: 'fields.ip' },
    { name: 'hostname', labelKey: 'fields.hostname' },
    { name: 'domain', labelKey: 'fields.domain' },
    { name: 'business_system', labelKey: 'fields.business_system' },
    { name: 'business_owner', labelKey: 'fields.business_owner' },
    { name: 'importance', labelKey: 'fields.importance', type: 'select', options: importanceOptions },
    { name: 'exposure_level', labelKey: 'fields.exposure_level', type: 'select', options: exposureOptions },
    { name: 'environment', labelKey: 'fields.environment', type: 'select', options: environmentOptions },
    { name: 'open_ports', labelKey: 'fields.open_ports', type: 'array' },
    { name: 'services', labelKey: 'fields.services', type: 'array' },
    { name: 'protocols', labelKey: 'fields.protocols', type: 'array' },
    { name: 'security_controls', labelKey: 'fields.security_controls', type: 'json' },
    { name: 'tags', labelKey: 'fields.tags', type: 'array' },
    { name: 'description', labelKey: 'fields.description', type: 'textarea' },
  ],
  vulnerabilities: [
    { name: 'asset_id', labelKey: 'fields.asset_id', required: true },
    { name: 'cve_id', labelKey: 'fields.cve_id' },
    { name: 'title', labelKey: 'fields.title', required: true },
    { name: 'severity', labelKey: 'fields.severity', type: 'select', options: severityOptions },
    { name: 'cvss_score', labelKey: 'fields.cvss_score', type: 'number' },
    { name: 'epss_score', labelKey: 'fields.epss_score', type: 'number' },
    { name: 'kev', labelKey: 'fields.kev', type: 'checkbox' },
    { name: 'exploit_available', labelKey: 'fields.exploit_available', type: 'checkbox' },
    { name: 'affected_component', labelKey: 'fields.affected_component' },
    { name: 'status', labelKey: 'fields.status', type: 'select', options: ['open', 'confirmed', 'mitigated', 'fixed', 'accepted', 'false_positive'] },
    { name: 'description', labelKey: 'fields.description', type: 'textarea' },
    { name: 'remediation', labelKey: 'fields.remediation', type: 'textarea' },
  ],
  alerts: [
    { name: 'asset_id', labelKey: 'fields.asset_id' },
    { name: 'source', labelKey: 'fields.source', type: 'select', options: ['xdr', 'edr', 'ndr', 'waf', 'siem', 'honeypot', 'scanner', 'manual', 'other'] },
    { name: 'title', labelKey: 'fields.title', required: true },
    { name: 'severity', labelKey: 'fields.severity', type: 'select', options: severityOptions },
    { name: 'alert_type', labelKey: 'fields.alert_type' },
    { name: 'ioc', labelKey: 'fields.ioc', type: 'array' },
    { name: 'mitre_technique', labelKey: 'fields.mitre_technique' },
    { name: 'status', labelKey: 'fields.status', type: 'select', options: ['new', 'triaging', 'confirmed', 'false_positive', 'incident_created', 'closed'] },
    { name: 'description', labelKey: 'fields.description', type: 'textarea' },
    { name: 'raw_event', labelKey: 'fields.raw_event', type: 'json' },
  ],

  'analysis-cases': [
    { name: 'title', labelKey: 'fields.title', required: true },
    { name: 'description', labelKey: 'fields.description', type: 'textarea' },
    { name: 'case_status', labelKey: 'fields.case_status', type: 'select', options: ['new', 'collecting_evidence', 'analyzing', 'awaiting_confirmation', 'monitoring', 'resolved', 'escalated', 'merged', 'reopened'] },
    { name: 'verdict', labelKey: 'fields.verdict', type: 'select', options: ['confirmed_incident', 'confirmed_attack_attempt_blocked', 'suspicious_true_positive', 'false_positive_rule_noise', 'benign_business_activity', 'insufficient_evidence'] },
    { name: 'severity', labelKey: 'fields.severity', type: 'select', options: analysisCaseSeverityOptions },
    { name: 'confidence', labelKey: 'fields.confidence', type: 'select', options: ['low', 'medium', 'high'] },
    { name: 'evidence_coverage', labelKey: 'fields.evidence_coverage', type: 'select', options: ['ec0_signal', 'ec1_single_source', 'ec2_enriched_single_source', 'ec3_cross_source', 'ec4_full_investigation'] },
    { name: 'analysis_mode', labelKey: 'fields.analysis_mode', type: 'select', options: ['single_source', 'enriched_single_source', 'cross_source', 'full_investigation'] },
    { name: 'notification_decision', labelKey: 'fields.notification_decision', type: 'select', options: ['realtime_notify', 'confirmation_request', 'daily_digest', 'no_notify_store_only', 'escalation_reminder'] },
    { name: 'incident_decision', labelKey: 'fields.incident_decision', type: 'select', options: ['escalate_to_incident', 'do_not_escalate', 'needs_human_confirmation', 'continue_monitoring'] },
    { name: 'disposition', labelKey: 'fields.disposition', type: 'select', options: ['open', 'closed_blocked_attempt', 'closed_false_positive', 'closed_benign', 'closed_insufficient_evidence', 'closed_duplicate', 'merged_into_case', 'merged_into_incident', 'escalated_to_incident', 'monitoring'] },
    { name: 'primary_asset_id', labelKey: 'fields.primary_asset_id' },
    { name: 'related_asset_ids', labelKey: 'fields.related_asset_ids', type: 'array' },
    { name: 'related_alert_ids', labelKey: 'fields.related_alert_ids', type: 'array' },
    { name: 'summary', labelKey: 'fields.summary', type: 'textarea' },
    { name: 'recommendations', labelKey: 'fields.recommendations', type: 'array' },
  ],
  incidents: [
    { name: 'title', labelKey: 'fields.title', required: true },
    { name: 'severity', labelKey: 'fields.severity', type: 'select', options: incidentSeverityOptions },
    { name: 'status', labelKey: 'fields.status', type: 'select', options: ['open', 'investigating', 'confirmed', 'contained', 'resolved', 'closed', 'false_positive'] },
    { name: 'confidence', labelKey: 'fields.confidence', type: 'select', options: ['low', 'medium', 'high'] },
    { name: 'asset_ids', labelKey: 'fields.asset_ids', type: 'array' },
    { name: 'vulnerability_ids', labelKey: 'fields.vulnerability_ids', type: 'array' },
    { name: 'alert_ids', labelKey: 'fields.alert_ids', type: 'array' },
    { name: 'honeypot_event_ids', labelKey: 'fields.honeypot_event_ids', type: 'array' },
    { name: 'evidence', labelKey: 'fields.evidence', type: 'array' },
    { name: 'timeline', labelKey: 'fields.timeline', type: 'json' },
    { name: 'owner', labelKey: 'fields.owner' },
    { name: 'sla', labelKey: 'fields.sla' },
    { name: 'close_reason', labelKey: 'fields.close_reason' },
    { name: 'summary', labelKey: 'fields.summary', type: 'textarea' },
    { name: 'analysis', labelKey: 'fields.analysis', type: 'textarea' },
    { name: 'recommendation', labelKey: 'fields.recommendation', type: 'textarea' },
  ],
  'honeypot-events': [
    { name: 'sensor_id', labelKey: 'fields.sensor_id' },
    { name: 'source_ip', labelKey: 'fields.source_ip' },
    { name: 'target_ip', labelKey: 'fields.target_ip' },
    { name: 'protocol', labelKey: 'fields.protocol' },
    { name: 'service', labelKey: 'fields.service' },
    { name: 'event_type', labelKey: 'fields.event_type' },
    { name: 'threat_label', labelKey: 'fields.threat_label' },
    { name: 'payload', labelKey: 'fields.payload', type: 'textarea' },
    { name: 'geo', labelKey: 'fields.geo', type: 'json' },
  ],
};

const columns: Record<DataSection, TableColumn[]> = {
  assets: [
    { key: 'name', labelKey: 'fields.name' },
    { key: 'ip', labelKey: 'fields.ip' },
    { key: 'domain', labelKey: 'fields.domain' },
    { key: 'importance', labelKey: 'fields.importance' },
    { key: 'exposure_level', labelKey: 'fields.exposure_level' },
  ],
  vulnerabilities: [
    { key: 'title', labelKey: 'fields.title' },
    { key: 'cve_id', labelKey: 'fields.cve_id' },
    { key: 'severity', labelKey: 'fields.severity' },
    { key: 'status', labelKey: 'fields.status' },
    { key: 'asset_id', labelKey: 'fields.asset_id' },
  ],
  alerts: [
    { key: 'title', labelKey: 'fields.title' },
    { key: 'source', labelKey: 'fields.source' },
    { key: 'severity', labelKey: 'fields.severity' },
    { key: 'status', labelKey: 'fields.status' },
    { key: 'mitre_technique', labelKey: 'fields.mitre_technique' },
  ],

  'analysis-cases': [
    { key: 'title', labelKey: 'fields.title' },
    { key: 'case_status', labelKey: 'fields.case_status' },
    { key: 'verdict', labelKey: 'fields.verdict' },
    { key: 'severity', labelKey: 'fields.severity' },
    { key: 'confidence', labelKey: 'fields.confidence' },
    { key: 'evidence_coverage', labelKey: 'fields.evidence_coverage' },
    { key: 'notification_decision', labelKey: 'fields.notification_decision' },
    { key: 'incident_decision', labelKey: 'fields.incident_decision' },
    { key: 'disposition', labelKey: 'fields.disposition' },
    { key: 'primary_asset_id', labelKey: 'fields.primary_asset_id' },
    { key: 'related_alert_ids', labelKey: 'fields.related_alert_ids' },
    { key: 'facts', labelKey: 'fields.facts' },
    { key: 'evidence_gaps', labelKey: 'fields.evidence_gaps' },
    { key: 'notification_records', labelKey: 'fields.notification_records' },
    { key: 'confirmation_records', labelKey: 'fields.confirmation_records' },
    { key: 'last_notified_at', labelKey: 'fields.last_notified_at' },
    { key: 'last_confirmed_at', labelKey: 'fields.last_confirmed_at' },
    { key: 'created_at', labelKey: 'fields.created_at' },
    { key: 'updated_at', labelKey: 'fields.updated_at' },
  ],
  incidents: [
    { key: 'title', labelKey: 'fields.title' },
    { key: 'severity', labelKey: 'fields.severity' },
    { key: 'status', labelKey: 'fields.status' },
    { key: 'confidence', labelKey: 'fields.confidence' },
    { key: 'created_by', labelKey: 'fields.created_by' },
  ],
  'honeypot-events': [
    { key: 'source_ip', labelKey: 'fields.source_ip' },
    { key: 'target_ip', labelKey: 'fields.target_ip' },
    { key: 'protocol', labelKey: 'fields.protocol' },
    { key: 'service', labelKey: 'fields.service' },
    { key: 'event_type', labelKey: 'fields.event_type' },
  ],
};

function sectionFromPath(pathname: string, basePath = '/security'): Section {
  const normalizedBasePath = (basePath.replace(/\/+$/, '') || '/');
  const normalizedPath = (pathname.replace(/\/+$/, '') || '/');
  const sectionPath = normalizedBasePath !== '/' && (
    normalizedPath === normalizedBasePath || normalizedPath.startsWith(`${normalizedBasePath}/`)
  )
    ? normalizedPath.slice(normalizedBasePath.length).replace(/^\/+/, '')
    : normalizedPath.replace(/^\/+/, '');
  const part = sectionPath.split('/')[0] as Section | undefined;
  if (!part) return 'dashboard';
  return supportedSections.includes(part) ? part : 'dashboard';
}

function isDataSection(section: Section): section is DataSection {
  return !['dashboard', 'connectors'].includes(section);
}

type PolicyActionHandlers = {
  onCredentialBind: (connectorId: string) => Promise<void>;
  onCredentialActivate: (connectorId: string, profileId: string) => Promise<void>;
  onCredentialTest: (connectorId: string, profileId: string) => Promise<void>;
  onCredentialRotate: (connectorId: string, profileId: string, currentExpiresAt?: string | null) => Promise<void>;
};

function handlePolicyAction(handlers: PolicyActionHandlers) {
  return async (action: SecurityConnectorPolicyAction) => {
    const connectorId = action.connector_id;
    const profileId = action.profile_id;
    if (!connectorId) return;
    if (action.kind === 'bind_credentials') {
      await handlers.onCredentialBind(connectorId);
      return;
    }
    if (!profileId) return;
    if (action.kind === 'activate_profile') {
      await handlers.onCredentialActivate(connectorId, profileId);
    } else if (action.kind === 'test_profile') {
      await handlers.onCredentialTest(connectorId, profileId);
    } else if (action.kind === 'rotate_credentials') {
      await handlers.onCredentialRotate(connectorId, profileId, action.profile_expires_at || action.expires_at);
    }
  };
}

function policyActionTitle(t: (key: string, options?: Record<string, any>) => string, action: SecurityConnectorPolicyAction) {
  if (action.kind === 'bind_credentials') return t('actions.bindCredentials');
  if (action.kind === 'activate_profile') return t('actions.activateProfile');
  if (action.kind === 'test_profile') return t('actions.testProfile');
  if (action.kind === 'rotate_credentials') return t('actions.rotateCredentials');
  return action.label || action.kind;
}

function apiErrorMessage(err: any, fallback: string): string {
  return err?.response?.data?.detail || err?.response?.data?.message || err?.message || fallback;
}

function isNotFoundAPIError(err: any): boolean {
  return err?.response?.status === 404 || apiErrorMessage(err, '').toLowerCase() === 'not found';
}

function badgeClass(value?: string | null): string {
  if (value === 'critical') return 'bg-red-100 text-red-700';
  if (value === 'high') return 'bg-orange-100 text-orange-700';
  if (value === 'medium') return 'bg-yellow-100 text-yellow-700';
  if (value === 'low') return 'bg-green-100 text-green-700';
  return 'bg-gray-100 text-gray-700';
}

function renderValue(value: any, formatOption?: (value: string) => string): string {
  if (Array.isArray(value)) return value.join(', ');
  if (value && typeof value === 'object') return JSON.stringify(value);
  if (typeof value === 'string' && value) return formatOption ? formatOption(value) : value;
  return value ?? '-';
}

function toFormValue(value: any, field: FieldConfig): any {
  if (field.type === 'array') return Array.isArray(value) ? value.join(', ') : '';
  if (field.type === 'json') return value ? JSON.stringify(value, null, 2) : '{}';
  if (field.type === 'checkbox') return Boolean(value);
  return value ?? '';
}

function parseFormValue(value: any, field: FieldConfig): any {
  if (field.type === 'checkbox') return Boolean(value);
  if (field.type === 'number') return value === '' ? undefined : Number(value);
  if (field.type === 'array') {
    const values = String(value || '').split(',').map((item) => item.trim()).filter(Boolean);
    if (field.name === 'open_ports') {
      return values.map((item) => Number(item)).filter((item) => Number.isFinite(item));
    }
    return values;
  }
  if (field.type === 'json') {
    if (!value) return {};
    return JSON.parse(String(value));
  }
  return value === '' && !field.required ? undefined : value;
}

function parseCredentialInput(value: string): Record<string, string> {
  const entries: Record<string, string> = {};
  for (const rawLine of value.split(/\n|,/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim();
    const entryValue = line.slice(separator + 1).trim();
    if (key && entryValue) entries[key] = entryValue;
  }
  return entries;
}

function defaultCredentialExpiry(): string {
  const expiresAt = new Date();
  expiresAt.setFullYear(expiresAt.getFullYear() + 1);
  return expiresAt.toISOString();
}

function uniqueCredentialTargets(items: SecurityConnectorBulkRemediationItem[]): SecurityConnectorBulkRemediationItem[] {
  const seen = new Set<string>();
  const result: SecurityConnectorBulkRemediationItem[] = [];
  for (const item of items) {
    const key = `${item.connector_id}:${item.profile_id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(item);
  }
  return result;
}

function asRecord(value: any): Record<string, any> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function asStringArray(value: any): string[] {
  if (Array.isArray(value)) return value.map((item) => String(item)).filter(Boolean);
  if (typeof value === 'string' && value) return [value];
  return [];
}

function severityRank(value?: string | null): number {
  if (value === 'critical') return 5;
  if (value === 'high') return 4;
  if (value === 'medium') return 3;
  if (value === 'low') return 2;
  if (value === 'info') return 1;
  return 0;
}

function severityScore(value?: string | null): number {
  if (value === 'critical') return 42;
  if (value === 'high') return 28;
  if (value === 'medium') return 14;
  if (value === 'low') return 6;
  if (value === 'info') return 2;
  return 0;
}

function isResolvedStatus(value?: string | null): boolean {
  return ['fixed', 'mitigated', 'resolved', 'closed', 'false_positive'].includes(String(value || '').toLowerCase());
}

function maxSeverity(items: Array<{ severity?: string | null }>): string | null {
  let selected: string | null = null;
  for (const item of items) {
    if (severityRank(item.severity) > severityRank(selected)) selected = item.severity || null;
  }
  return selected;
}

function assetIpSet(asset: SecurityAsset): Set<string> {
  const values = new Set<string>();
  if (asset.ip) values.add(asset.ip);
  const normalizedData = asRecord(asset.normalized_data);
  const identity = asRecord(normalizedData.asset_identity);
  if (typeof identity.ip === 'string' && identity.ip) values.add(identity.ip);
  const observations = Array.isArray(normalizedData.ip_observations)
    ? normalizedData.ip_observations
    : Array.isArray(identity.ip_observations)
      ? identity.ip_observations
      : [];
  for (const observation of observations) {
    const ip = asRecord(observation).ip;
    if (typeof ip === 'string' && ip) values.add(ip);
  }
  return values;
}

function extractAssetIdentitySummary(asset: SecurityAsset): AssetIdentitySummary {
  const normalizedData = asRecord(asset.normalized_data);
  const identity = asRecord(normalizedData.asset_identity);
  const graph = asRecord(normalizedData.evidence_graph);
  const sourceObservation = asRecord(normalizedData.source_observation || identity.source_observation);
  const connectorEvidence = asRecord(normalizedData.connector_evidence);
  const connectorSync = asRecord(normalizedData.connector_sync);
  const ipObservations = Array.isArray(normalizedData.ip_observations)
    ? normalizedData.ip_observations.map(asRecord)
    : Array.isArray(identity.ip_observations)
      ? identity.ip_observations.map(asRecord)
      : [];
  const entityIds = [
    ...asStringArray(graph.entity_id),
    ...asStringArray(graph.entity_ids),
  ].filter((value, index, self) => self.indexOf(value) === index);
  const firstObservation = ipObservations[0] || {};
  const observationWindow = asRecord(identity.observation_window);
  return {
    strongCount: asStringArray(identity.strong_keys).length,
    auxiliaryCount: asStringArray(identity.auxiliary_keys).length,
    weakCount: asStringArray(identity.weak_keys).length,
    entityIds,
    mergeCandidateIds: asStringArray(graph.merge_candidate_ids),
    conflictIds: asStringArray(graph.conflict_ids),
    ipObservations,
    sourceLabel: sourceObservation.source_instance_id
      || connectorEvidence.source_instance_id
      || connectorSync.source_instance_id
      || sourceObservation.connector_id
      || connectorEvidence.connector_id
      || connectorSync.connector_id
      || sourceObservation.source_system
      || null,
    allocationMode: identity.allocation_mode || firstObservation.allocation_mode || null,
    firstSeen: sourceObservation.first_seen || observationWindow.first_seen || firstObservation.first_seen || null,
    lastSeen: sourceObservation.last_seen
      || sourceObservation.observed_at
      || observationWindow.last_seen
      || firstObservation.last_seen
      || asset.updated_at
      || null,
  };
}

function buildAssetRiskContext(
  asset: SecurityAsset,
  vulnerabilities: SecurityVulnerability[],
  alerts: SecurityAlert[],
  incidents: SecurityIncident[],
  honeypotEvents: SecurityHoneypotEvent[],
): AssetRiskContext {
  const ips = assetIpSet(asset);
  const relatedVulnerabilities = vulnerabilities.filter((item) => item.asset_id === asset.id && !isResolvedStatus(item.status));
  const relatedAlerts = alerts.filter((item) => item.asset_id === asset.id && !isResolvedStatus(item.status));
  const relatedIncidents = incidents.filter((item) => item.asset_ids?.includes(asset.id) && !isResolvedStatus(item.status));
  const relatedHoneypotEvents = honeypotEvents.filter((item) => (
    Boolean(item.source_ip && ips.has(item.source_ip)) || Boolean(item.target_ip && ips.has(item.target_ip))
  ));
  const identity = extractAssetIdentitySummary(asset);

  let score = 0;
  const reasons: string[] = [];
  if (asset.importance === 'critical') {
    score += 18;
    reasons.push('importanceCritical');
  } else if (asset.importance === 'high') {
    score += 10;
    reasons.push('importanceHigh');
  }
  if (asset.exposure_level === 'external') {
    score += 18;
    reasons.push('externalExposure');
  }
  for (const vulnerability of relatedVulnerabilities) {
    score += severityScore(vulnerability.severity);
    if (vulnerability.kev || vulnerability.exploit_available) score += 14;
  }
  for (const alert of relatedAlerts) score += severityScore(alert.severity);
  for (const incident of relatedIncidents) score += Math.max(18, severityScore(incident.severity));
  if (relatedHoneypotEvents.length) score += Math.min(24, relatedHoneypotEvents.length * 8);
  if (identity.conflictIds.length) {
    score += 28;
    reasons.push('identityConflict');
  }
  if (identity.mergeCandidateIds.length) {
    score += 8;
    reasons.push('mergeCandidate');
  }
  if (identity.weakCount > 0 && identity.strongCount === 0) {
    score += 4;
    reasons.push('weakIdentityOnly');
  }
  if (relatedVulnerabilities.length) reasons.push('activeVulnerabilities');
  if (relatedAlerts.length) reasons.push('activeAlerts');
  if (relatedIncidents.length) reasons.push('activeIncidents');
  if (relatedHoneypotEvents.length) reasons.push('honeypotSignal');

  const cappedScore = Math.min(100, score);
  let level: AssetRiskLevel = 'low';
  if (cappedScore >= 80) level = 'critical';
  else if (cappedScore >= 50) level = 'high';
  else if (cappedScore >= 20) level = 'medium';

  return {
    asset,
    level,
    score: cappedScore,
    reasons: [...new Set(reasons)],
    vulnerabilities: relatedVulnerabilities,
    alerts: relatedAlerts,
    incidents: relatedIncidents,
    honeypotEvents: relatedHoneypotEvents,
    identity,
    lastSeenAt: identity.lastSeen || asset.updated_at,
  };
}

function assetRiskTone(level: AssetRiskLevel): { border: string; bg: string; text: string; badge: string; icon: string } {
  if (level === 'critical') {
    return {
      border: 'border-red-200',
      bg: 'bg-red-50',
      text: 'text-red-800',
      badge: 'bg-red-100 text-red-700 border-red-200',
      icon: 'text-red-600',
    };
  }
  if (level === 'high') {
    return {
      border: 'border-orange-200',
      bg: 'bg-orange-50',
      text: 'text-orange-800',
      badge: 'bg-orange-100 text-orange-700 border-orange-200',
      icon: 'text-orange-600',
    };
  }
  if (level === 'medium') {
    return {
      border: 'border-amber-200',
      bg: 'bg-amber-50',
      text: 'text-amber-800',
      badge: 'bg-amber-100 text-amber-700 border-amber-200',
      icon: 'text-amber-600',
    };
  }
  return {
    border: 'border-emerald-200',
    bg: 'bg-emerald-50',
    text: 'text-emerald-800',
    badge: 'bg-emerald-100 text-emerald-700 border-emerald-200',
    icon: 'text-emerald-600',
  };
}

function formatDateTime(value?: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export default function SecurityPage({ basePath = '/security', mode = 'expert' }: SecurityPageProps = {}) {
  const { t } = useTranslation('security');
  const tRef = useRef(t);
  const location = useLocation();
  const navigate = useNavigate();
  const rawSection = sectionFromPath(location.pathname, basePath);
  const section = mode === 'admin' || rawSection !== 'connectors' ? rawSection : 'dashboard';
  const [assets, setAssets] = useState<SecurityAsset[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<SecurityVulnerability[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [analysisCases, setAnalysisCases] = useState<AnalysisCase[]>([]);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [honeypotEvents, setHoneypotEvents] = useState<SecurityHoneypotEvent[]>([]);
  const [connectors, setConnectors] = useState<SecurityConnectorManifest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [keyword, setKeyword] = useState('');
  const [analysisCaseFilters, setAnalysisCaseFilters] = useState({ severity: '', status: '', asset_id: '', verdict: '' });
  const [selected, setSelected] = useState<Entity | null>(null);
  const [editing, setEditing] = useState<Entity | null>(null);
  const [form, setForm] = useState<Record<string, any>>({});
  const [triageResult, setTriageResult] = useState<any>(null);
  const [riskProfile, setRiskProfile] = useState<SecurityAssetRiskProfile | null>(null);
  const [connectorTestResult, setConnectorTestResult] = useState<SecurityConnectorTestResult | null>(null);
  const [connectorPreviewResult, setConnectorPreviewResult] = useState<SecurityConnectorPreviewResult | null>(null);
  const [connectorValidateResult, setConnectorValidateResult] = useState<SecurityConnectorValidateResult | null>(null);
  const [connectorPackageDiagnostics, setConnectorPackageDiagnostics] = useState<SecurityConnectorPackageDiagnostics | null>(null);
  const [connectorOperationEvents, setConnectorOperationEvents] = useState<SecurityConnectorOperationEvent[]>([]);
  const [connectorOperationsSettings, setConnectorOperationsSettings] = useState<SecurityConnectorOperationsSettings | null>(null);
  const [connectorExpiryMonitorStatus, setConnectorExpiryMonitorStatus] = useState<SecurityConnectorExpiryMonitorSchedulerStatus | null>(null);
  const [evidenceGraph, setEvidenceGraph] = useState<SecurityEvidenceGraph | null>(null);
  const [connectorRuntimeError, setConnectorRuntimeError] = useState<string | null>(null);
  const [report, setReport] = useState<string>('');
  const [analysisCaseBrief, setAnalysisCaseBrief] = useState<string>('');
  const [ingestionContext, setIngestionContext] = useState<EvidenceIngestionContext>({ connector_id: 'demo-waf', connector_name: 'Demo WAF', vendor: 'Generic', product: 'WAF', source_type: 'waf', external_base_url: 'https://waf.example.local/events' });
  const [ingestionEventsJson, setIngestionEventsJson] = useState('[\n  {\n    "id": "evt-001",\n    "title": "SQL injection blocked",\n    "severity": "high",\n    "action": "block",\n    "src_ip": "1.1.1.1",\n    "dst_ip": "10.0.0.10",\n    "url": "/login?id=1 union select",\n    "timestamp": "2026-07-07T10:00:00+00:00"\n  }\n]');
  const [ingestionOptions, setIngestionOptions] = useState({ create_analysis_cases: true, run_initial_analysis: true, deduplicate: true });
  const [ingestionResult, setIngestionResult] = useState<EvidenceIngestionResponse | null>(null);
  const [ingestionLoading, setIngestionLoading] = useState(false);
  useEffect(() => {
    tRef.current = t;
  }, [t]);
  const formatOption = useCallback(
    (value: string) => t(`options.${value}`, { defaultValue: value }),
    [t],
  );
  const pageTitle = section === 'dashboard'
    ? t(`modes.${mode}.title`)
    : `${t(`modes.${mode}.title`)} · ${t(`sections.${section}.title`)}`;

  const listData = useMemo<Record<DataSection, Entity[]>>(() => ({
    assets: assets as Entity[],
    vulnerabilities: vulnerabilities as Entity[],
    alerts: alerts as Entity[],
    'analysis-cases': analysisCases as Entity[],
    incidents: incidents as Entity[],
    'honeypot-events': honeypotEvents as Entity[],
  }), [alerts, analysisCases, assets, honeypotEvents, incidents, vulnerabilities]);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    setConnectorRuntimeError(null);
    try {
      const params = { limit: 500 };
      const [assetRes, vulnRes, alertRes, analysisCaseRes, incidentRes, honeypotRes] = await Promise.all([
        securityAPI.listAssets(params),
        securityAPI.listVulnerabilities(params),
        securityAPI.listAlerts(params),
        securityAPI.listAnalysisCases(params),
        securityAPI.listIncidents(params),
        securityAPI.listHoneypotEvents(params),
      ]);
      setAssets(assetRes.data);
      setVulnerabilities(vulnRes.data);
      setAlerts(alertRes.data);
      setAnalysisCases(analysisCaseRes.data);
      setIncidents(incidentRes.data);
      setHoneypotEvents(honeypotRes.data);

      if (mode === 'admin') {
        const [connectorRes, packageDiagnosticsRes, evidenceGraphRes, operationEventsRes, operationSettingsRes, expiryStatusRes] = await Promise.allSettled([
          securityAPI.listConnectors(),
          securityAPI.connectorPackageDiagnostics(),
          securityAPI.getEvidenceGraph(),
          securityAPI.listConnectorOperationEvents({ limit: 500 }),
          securityAPI.getConnectorOperationsSettings(),
          securityAPI.getConnectorCredentialExpiryMonitorStatus(),
        ]);
        const optionalFailures: string[] = [];

        if (connectorRes.status === 'fulfilled') {
          setConnectors(connectorRes.value.data);
        } else {
          setConnectors([]);
          optionalFailures.push(apiErrorMessage(connectorRes.reason, 'connectors'));
        }

        if (packageDiagnosticsRes.status === 'fulfilled') {
          setConnectorPackageDiagnostics(packageDiagnosticsRes.value.data);
        } else {
          setConnectorPackageDiagnostics(null);
          optionalFailures.push(apiErrorMessage(packageDiagnosticsRes.reason, 'package diagnostics'));
        }

        if (evidenceGraphRes.status === 'fulfilled') {
          setEvidenceGraph(evidenceGraphRes.value.data);
        } else {
          setEvidenceGraph(null);
          if (!isNotFoundAPIError(evidenceGraphRes.reason)) {
            optionalFailures.push(apiErrorMessage(evidenceGraphRes.reason, 'evidence graph'));
          }
        }

        if (operationEventsRes.status === 'fulfilled') {
          setConnectorOperationEvents(operationEventsRes.value.data.items);
        } else {
          setConnectorOperationEvents([]);
          optionalFailures.push(apiErrorMessage(operationEventsRes.reason, 'operation events'));
        }

        if (operationSettingsRes.status === 'fulfilled') {
          setConnectorOperationsSettings(operationSettingsRes.value.data);
        } else {
          setConnectorOperationsSettings(null);
          optionalFailures.push(apiErrorMessage(operationSettingsRes.reason, 'operation settings'));
        }

        if (expiryStatusRes.status === 'fulfilled') {
          setConnectorExpiryMonitorStatus(expiryStatusRes.value.data);
        } else {
          setConnectorExpiryMonitorStatus(null);
          optionalFailures.push(apiErrorMessage(expiryStatusRes.reason, 'expiry monitor status'));
        }

        if (optionalFailures.length) {
          setConnectorRuntimeError(tRef.current('error.connectorRuntimeLoadFailed', { message: optionalFailures.join(' | ') }));
        }
      } else {
        setConnectors([]);
        setConnectorPackageDiagnostics(null);
        setConnectorOperationEvents([]);
        setConnectorOperationsSettings(null);
        setConnectorExpiryMonitorStatus(null);
        try {
          const graphRes = await securityAPI.getEvidenceGraph();
          setEvidenceGraph(graphRes.data);
        } catch {
          setEvidenceGraph(null);
        }
      }
    } catch (err: any) {
      setError(apiErrorMessage(err, tRef.current('error.loadFailed')));
    } finally {
      setLoading(false);
    }
  }, [mode]);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const filteredItems = useMemo(() => {
    if (!isDataSection(section)) return [];
    const items = listData[section];
    const q = keyword.trim().toLowerCase();
    let nextItems = q ? items.filter((item) => JSON.stringify(item).toLowerCase().includes(q)) : items;
    if (section === 'analysis-cases') {
      nextItems = nextItems.filter((item) => {
        const matchesSeverity = !analysisCaseFilters.severity || item.severity === analysisCaseFilters.severity;
        const matchesStatus = !analysisCaseFilters.status || item.case_status === analysisCaseFilters.status;
        const matchesVerdict = !analysisCaseFilters.verdict || item.verdict === analysisCaseFilters.verdict;
        const assetId = analysisCaseFilters.asset_id;
        const matchesAsset = !assetId || item.primary_asset_id === assetId || item.related_asset_ids?.includes(assetId);
        return matchesSeverity && matchesStatus && matchesVerdict && matchesAsset;
      });
    }
    return nextItems;
  }, [analysisCaseFilters, keyword, listData, section]);

  const filteredConnectors = useMemo(() => {
    const q = keyword.trim().toLowerCase();
    if (!q) return connectors;
    return connectors.filter((item) => JSON.stringify(item).toLowerCase().includes(q));
  }, [connectors, keyword]);

  const stats = useMemo(() => ({
    assets: assets.length,
    vulnerabilities: vulnerabilities.length,
    alerts: alerts.length,
    analysisCases: analysisCases.length,
    incidents: incidents.length,
    highAssets: assets.filter((item) => ['high', 'critical'].includes(item.importance)).length,
    highVulnerabilities: vulnerabilities.filter((item) => ['high', 'critical'].includes(item.severity)).length,
    highAlerts: alerts.filter((item) => ['high', 'critical'].includes(item.severity)).length,
    highAnalysisCases: analysisCases.filter((item) => ['high', 'critical'].includes(item.severity)).length,
  }), [alerts, analysisCases, assets, incidents, vulnerabilities]);

  const openCreate = () => {
    if (!isDataSection(section)) return;
    const next: Record<string, any> = {};
    for (const field of fields[section]) {
      if (field.type === 'checkbox') next[field.name] = false;
      else if (field.type === 'json') next[field.name] = field.name === 'timeline' ? '[]' : '{}';
      else if (field.type === 'array') next[field.name] = '';
      else if (field.options?.length) next[field.name] = field.options[0];
      else next[field.name] = '';
    }
    setEditing({ id: '' });
    setForm(next);
  };

  const openEdit = (item: Entity) => {
    if (!isDataSection(section)) return;
    const next: Record<string, any> = {};
    for (const field of fields[section]) {
      next[field.name] = toFormValue(item[field.name], field);
    }
    setEditing(item);
    setForm(next);
  };

  const closeForm = () => {
    setEditing(null);
    setForm({});
  };

  const saveForm = async () => {
    if (!isDataSection(section) || !editing) return;
    const payload: Record<string, any> = {};
    for (const field of fields[section]) {
      const parsed = parseFormValue(form[field.name], field);
      if (parsed !== undefined) payload[field.name] = parsed;
    }

    if (editing.id) {
      if (section === 'assets') await securityAPI.updateAsset(editing.id, payload);
      if (section === 'vulnerabilities') await securityAPI.updateVulnerability(editing.id, payload);
      if (section === 'alerts') await securityAPI.updateAlert(editing.id, payload);
      if (section === 'analysis-cases') await securityAPI.updateAnalysisCase(editing.id, payload);
      if (section === 'incidents') await securityAPI.updateIncident(editing.id, payload);
      if (section === 'honeypot-events') await securityAPI.updateHoneypotEvent(editing.id, payload);
    } else {
      if (section === 'assets') await securityAPI.createAsset(payload);
      if (section === 'vulnerabilities') await securityAPI.createVulnerability(payload);
      if (section === 'alerts') await securityAPI.createAlert(payload);
      if (section === 'analysis-cases') await securityAPI.createAnalysisCase(payload);
      if (section === 'incidents') await securityAPI.createIncident(payload);
      if (section === 'honeypot-events') await securityAPI.createHoneypotEvent(payload);
    }
    closeForm();
    await loadAll();
  };

  const deleteItem = async (item: Entity) => {
    if (!isDataSection(section)) return;
    if (!window.confirm(t('confirm.delete', { id: item.id }))) return;
    if (section === 'assets') await securityAPI.deleteAsset(item.id);
    if (section === 'vulnerabilities') await securityAPI.deleteVulnerability(item.id);
    if (section === 'alerts') await securityAPI.deleteAlert(item.id);
    if (section === 'analysis-cases') await securityAPI.deleteAnalysisCase(item.id);
    if (section === 'incidents') await securityAPI.deleteIncident(item.id);
    if (section === 'honeypot-events') await securityAPI.deleteHoneypotEvent(item.id);
    setSelected(null);
    await loadAll();
  };

  const runTriage = async (alertId: string) => {
    const res = await securityAPI.triageAlert(alertId, true);
    setTriageResult(res.data);
    await loadAll();
    navigate(`${basePath}/alerts`);
  };



  const ingestEvidenceEvents = async () => {
    setIngestionLoading(true);
    setError(null);
    try {
      const parsed = JSON.parse(ingestionEventsJson);
      if (!Array.isArray(parsed)) throw new Error('Events JSON must be an array.');
      const res = await securityAPI.ingestEvidenceEvents({
        connector_context: ingestionContext,
        events: parsed,
        ...ingestionOptions,
      });
      setIngestionResult(res.data);
      await loadAll();
    } catch (err: any) {
      setError(err?.message || 'Evidence ingestion failed');
    } finally {
      setIngestionLoading(false);
    }
  };

  const createAnalysisCaseFromAlert = async (alertId: string) => {
    const res = await securityAPI.createAnalysisCaseFromAlert(alertId);
    await loadAll();
    setSelected(res.data as Entity);
    navigate(`${basePath}/analysis-cases`);
  };

  const escalateAnalysisCase = async (caseId: string) => {
    const res = await securityAPI.escalateAnalysisCaseToIncident(caseId);
    await loadAll();
    setSelected(res.data.case as Entity);
    window.alert(t('analysisCases.escalated', { defaultValue: '已升级为 Incident' }));
  };

  const runInitialAnalysis = async (caseId: string) => {
    const res = await securityAPI.runInitialAnalysis(caseId);
    await loadAll();
    setSelected(res.data as Entity);
    window.alert(t('analysisCases.initialAnalysisComplete', { defaultValue: '自动初判已完成' }));
  };



  const createConfirmationRequest = async (caseId: string) => {
    const res = await securityAPI.createAnalysisCaseNotification(caseId, {
      notification_type: 'confirmation_request',
      channel: 'in_app',
      recipients: ['security_team'],
      created_by: 'user',
    });
    await loadAll();
    setSelected(res.data as Entity);
  };

  const createAnalysisConfirmation = async (caseId: string, confirmationType: any, decision: any) => {
    const comment = window.prompt(t('analysisCases.confirmationComment', { defaultValue: 'Comment (optional)' })) || '';
    const res = await securityAPI.createAnalysisCaseConfirmation(caseId, {
      confirmation_type: confirmationType,
      decision,
      comment,
      reviewer: 'operator',
      reviewer_role: 'security_analyst',
    });
    await loadAll();
    setSelected(res.data as Entity);
  };

  const viewAnalysisCaseBrief = async (caseId: string) => {
    const res = await securityAPI.getAnalysisCaseBrief(caseId);
    setAnalysisCaseBrief(res.data.markdown);
  };

  const loadAnalysisDemoData = async () => {
    const res = await securityAPI.loadAnalysisCaseSampleData();
    await loadAll();
    window.alert(`Loaded ${res.data.loaded} new demo cases (${res.data.total_demo_cases} demo cases available).`);
  };

  const ackAnalysisNotification = async (caseId: string, notificationId: string) => {
    const comment = window.prompt(t('analysisCases.ackComment', { defaultValue: 'Acknowledgement comment (optional)' })) || '';
    const res = await securityAPI.ackAnalysisCaseNotification(caseId, notificationId, { reviewer: 'operator', comment });
    await loadAll();
    setSelected(res.data as Entity);
  };

  const buildRiskProfile = async (assetId: string) => {
    const res = await securityAPI.getAssetRiskProfile(assetId);
    setRiskProfile(res.data);
  };

  const testConnector = async (connectorId: string) => {
    const res = await securityAPI.testConnector(connectorId);
    setConnectorTestResult(res.data);
  };

  const previewConnector = async (connectorId: string, capability: string) => {
    const res = await securityAPI.previewConnector(connectorId, capability);
    setConnectorPreviewResult(res.data);
  };

  const validateConnector = async (connectorId: string) => {
    const res = await securityAPI.validateConnector(connectorId);
    setConnectorValidateResult(res.data);
  };

  const installConnectorPackage = async (packageRoot: string) => {
    setError(null);
    try {
      await securityAPI.installConnectorPackage(packageRoot, false);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const enableConnectorPackage = async (packageId: string) => {
    setError(null);
    try {
      await securityAPI.enableConnectorPackage(packageId);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const disableConnectorPackage = async (packageId: string) => {
    setError(null);
    try {
      await securityAPI.disableConnectorPackage(packageId);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const uninstallConnectorPackage = async (packageId: string) => {
    if (!window.confirm(t('confirm.uninstallPackage', { id: packageId }))) return;
    setError(null);
    try {
      await securityAPI.uninstallConnectorPackage(packageId);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const rollbackConnectorPackage = async (packageId: string) => {
    if (!window.confirm(t('confirm.rollbackPackage', { id: packageId }))) return;
    setError(null);
    try {
      await securityAPI.rollbackConnectorPackage(packageId);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const uploadConnectorPackageArtifact = async (file: File) => {
    setError(null);
    try {
      await securityAPI.uploadConnectorPackageArtifact(file);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const validateStagedConnectorPackage = async (stagingId: string) => {
    setError(null);
    try {
      await securityAPI.validateStagedConnectorPackage(stagingId);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const installStagedConnectorPackage = async (stagingId: string) => {
    setError(null);
    try {
      await securityAPI.installStagedConnectorPackage(stagingId, false);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const discardStagedConnectorPackage = async (stagingId: string) => {
    if (!window.confirm(t('confirm.discardStagedPackage', { id: stagingId }))) return;
    setError(null);
    try {
      await securityAPI.discardStagedConnectorPackage(stagingId);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const bindConnectorCredentials = async (connectorId: string) => {
    const profileId = window.prompt(t('prompt.connectorCredentialProfileId'), 'default') || 'default';
    const profileName = window.prompt(t('prompt.connectorCredentialProfileName'), profileId);
    const raw = window.prompt(t('prompt.connectorCredentials'), 'VENDOR_BASE_URL=https://api.vendor.local\nVENDOR_TOKEN=');
    if (!raw) return;
    const values = parseCredentialInput(raw);
    if (Object.keys(values).length === 0) return;
    setError(null);
    try {
      await securityAPI.bindConnectorCredentials(connectorId, values, [], profileId, profileName || profileId, true);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const rotateConnectorCredentials = async (connectorId: string, profileId: string, currentExpiresAt?: string | null) => {
    const raw = window.prompt(t('prompt.connectorCredentialRotationValues'), 'VENDOR_BASE_URL=https://api.vendor.local\nVENDOR_TOKEN=');
    if (!raw) return;
    const values = parseCredentialInput(raw);
    if (Object.keys(values).length === 0) return;
    const expiresAt = window.prompt(
      t('prompt.connectorCredentialExpiresAt'),
      currentExpiresAt && new Date(currentExpiresAt).getTime() > Date.now() ? currentExpiresAt : defaultCredentialExpiry(),
    );
    setError(null);
    try {
      await securityAPI.rotateConnectorCredentials(connectorId, profileId, values, [], true, expiresAt || null);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const activateConnectorCredentialProfile = async (connectorId: string, profileId: string) => {
    setError(null);
    try {
      await securityAPI.activateConnectorCredentialProfile(connectorId, profileId);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const testConnectorCredentialProfile = async (connectorId: string, profileId: string) => {
    setError(null);
    try {
      const res = await securityAPI.testConnectorCredentialProfile(connectorId, profileId);
      setConnectorTestResult(res.data);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const deleteConnectorCredentialProfile = async (connectorId: string, profileId: string) => {
    if (!window.confirm(t('confirm.deleteCredentialProfile', { id: `${connectorId}/${profileId}` }))) return;
    setError(null);
    try {
      await securityAPI.deleteConnectorCredentialProfile(connectorId, profileId);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const syncConnector = async (
    connectorId: string,
    capability: string,
    mode = 'full',
    resetCursor = false,
    credentialProfileId?: string | null,
  ) => {
    setError(null);
    try {
      await securityAPI.syncConnector(connectorId, capability, mode, resetCursor, credentialProfileId);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const resetConnectorSyncCursor = async (connectorId: string, capability: string) => {
    setError(null);
    try {
      await securityAPI.resetConnectorSyncCursor(connectorId, capability);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const configureConnectorSyncSchedule = async (
    connectorId: string,
    capability: string,
    mode: string,
    credentialProfileId?: string | null,
  ) => {
    const raw = window.prompt(t('prompt.connectorScheduleInterval'), '3600');
    if (!raw) return;
    const intervalSeconds = Number.parseInt(raw, 10);
    if (!Number.isFinite(intervalSeconds) || intervalSeconds < 1) return;
    setError(null);
    try {
      await securityAPI.upsertConnectorSyncSchedule(connectorId, {
        capability,
        enabled: true,
        interval_seconds: intervalSeconds,
        mode,
        retry_max_attempts: 2,
        retry_backoff_seconds: 60,
        timeout_seconds: 300,
        credential_profile_id: credentialProfileId || null,
      });
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const runConnectorSyncSchedule = async (scheduleId: string, mode?: string) => {
    setError(null);
    try {
      await securityAPI.runConnectorSyncSchedule(scheduleId, mode);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const enableConnectorSyncSchedule = async (scheduleId: string) => {
    setError(null);
    try {
      await securityAPI.enableConnectorSyncSchedule(scheduleId);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const disableConnectorSyncSchedule = async (scheduleId: string) => {
    setError(null);
    try {
      await securityAPI.disableConnectorSyncSchedule(scheduleId);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const cancelConnectorSyncRun = async (runId: string) => {
    setError(null);
    try {
      await securityAPI.cancelConnectorSyncRun(runId);
      await loadAll();
    } catch (err: any) {
      setError(apiErrorMessage(err, t('error.packageActionFailed')));
    }
  };

  const replayConnectorDeadLetter = async (deadLetterId: string) => {
    const rawPatch = window.prompt(t('prompt.deadLetterReplayPatch'), '{}');
    if (rawPatch === null) return;
    let patch: Record<string, any> = {};
    try {
      patch = rawPatch.trim() ? JSON.parse(rawPatch) : {};
    } catch (err: any) {
      setError(apiErrorMessage(err, t('error.packageActionFailed')));
      return;
    }
    setError(null);
    try {
      await securityAPI.replayConnectorSyncDeadLetters([deadLetterId], null, { [deadLetterId]: patch });
      await loadAll();
    } catch (err: any) {
      setError(apiErrorMessage(err, t('error.packageActionFailed')));
    }
  };

  const monitorConnectorCredentialExpiry = async () => {
    const rawDays = window.prompt(
      t('prompt.credentialExpiryMonitorDays'),
      String(connectorOperationsSettings?.expiry_monitor?.days || 14),
    );
    if (rawDays === null) return;
    const days = Number.parseInt(rawDays, 10);
    if (!Number.isFinite(days) || days < 0) return;
    setError(null);
    try {
      await securityAPI.monitorConnectorCredentialExpiry(days, true);
      await loadAll();
    } catch (err: any) {
      setError(apiErrorMessage(err, t('error.packageActionFailed')));
    }
  };

  const acknowledgeConnectorOperationEvent = async (eventId: string) => {
    setError(null);
    try {
      await securityAPI.acknowledgeConnectorOperationEvent(eventId);
      await loadAll();
    } catch (err: any) {
      setError(apiErrorMessage(err, t('error.packageActionFailed')));
    }
  };

  const acknowledgeConnectorOperationEvents = async (eventIds: string[]) => {
    if (eventIds.length === 0) return;
    setError(null);
    try {
      await securityAPI.acknowledgeConnectorOperationEvents(eventIds);
      await loadAll();
    } catch (err: any) {
      setError(apiErrorMessage(err, t('error.packageActionFailed')));
    }
  };

  const notifyConnectorOperationEvent = async (eventId: string) => {
    setError(null);
    try {
      await securityAPI.notifyConnectorOperationEvent(eventId);
      await loadAll();
    } catch (err: any) {
      setError(apiErrorMessage(err, t('error.packageActionFailed')));
    }
  };

  const configureConnectorExpiryMonitor = async () => {
    const current = connectorOperationsSettings?.expiry_monitor;
    const rawDays = window.prompt(t('prompt.credentialExpiryMonitorDays'), String(current?.days || 14));
    if (rawDays === null) return;
    const days = Number.parseInt(rawDays, 10);
    if (!Number.isFinite(days) || days < 0) return;
    const rawInterval = window.prompt(t('prompt.credentialExpiryMonitorInterval'), String(current?.interval_seconds || 86400));
    if (rawInterval === null) return;
    const intervalSeconds = Number.parseInt(rawInterval, 10);
    if (!Number.isFinite(intervalSeconds) || intervalSeconds < 60) return;
    setError(null);
    try {
      const res = await securityAPI.updateConnectorOperationsSettings({
        expiry_monitor: {
          enabled: true,
          days,
          interval_seconds: intervalSeconds,
          notify: current?.notify ?? true,
        },
      } as Partial<SecurityConnectorOperationsSettings>);
      setConnectorOperationsSettings(res.data);
      await loadAll();
    } catch (err: any) {
      setError(apiErrorMessage(err, t('error.packageActionFailed')));
    }
  };

  const bulkRemediateConnectorCredentials = async (
    action: string,
    items: SecurityConnectorBulkRemediationItem[],
    recoveryMode = 'enable',
  ) => {
    if (items.length === 0) return;
    setError(null);
    try {
      await securityAPI.bulkRemediateConnectorCredentials(items, action, recoveryMode, true);
      await loadAll();
    } catch (err: any) {
      setError(apiErrorMessage(err, t('error.packageActionFailed')));
    }
  };

  const rebuildEvidenceGraph = async () => {
    setError(null);
    try {
      const res = await securityAPI.rebuildEvidenceGraph();
      setEvidenceGraph(res.data);
      await loadAll();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || t('error.packageActionFailed'));
    }
  };

  const createIncidentFromAlert = async (alertId: string) => {
    const res = await securityAPI.createIncidentFromAlert(alertId);
    setTriageResult(res.data);
    await loadAll();
  };

  const generateReport = async (incidentId: string) => {
    const res = await securityAPI.generateIncidentReport(incidentId);
    setReport(res.data.content);
  };

  const loadSample = async () => {
    setError(null);
    try {
      await securityAPI.loadSampleData();
      await loadAll();
    } catch (err: any) {
      setError(apiErrorMessage(err, t('error.sampleActionFailed')));
    }
  };

  const clearSample = async () => {
    if (!window.confirm(t('confirm.clearSample'))) return;
    setError(null);
    try {
      await securityAPI.clearSampleData();
      setSelected(null);
      setTriageResult(null);
      setRiskProfile(null);
      setConnectorTestResult(null);
      setConnectorPreviewResult(null);
      setConnectorValidateResult(null);
      setReport('');
      await loadAll();
    } catch (err: any) {
      setError(apiErrorMessage(err, t('error.sampleActionFailed')));
    }
  };

  return (
    <div className="h-full overflow-y-auto">
      <PageHeader
        title={pageTitle}
        description={t(`modes.${mode}.description`)}
        icon={<ShieldCheck className="w-8 h-8" />}
        action={(
          <div className="flex gap-2">
            <button onClick={() => void loadAll()} className="inline-flex items-center gap-2 rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm text-gray-700 hover:bg-gray-50">
              <RefreshCw className="h-4 w-4" /> {t('actions.refresh')}
            </button>
            <button onClick={() => void loadSample()} className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm text-white hover:bg-slate-800">
              <UploadCloud className="h-4 w-4" /> {t('actions.loadSample')}
            </button>
            <button onClick={() => void clearSample()} className="inline-flex items-center gap-2 rounded-lg border border-red-200 bg-white px-3 py-2 text-sm text-red-700 hover:bg-red-50">
              <Eraser className="h-4 w-4" /> {t('actions.clearSample')}
            </button>
          </div>
        )}
      />

      <div className="mb-5 flex flex-wrap gap-2">
        {navItems.filter((item) => mode === 'admin' || !item.adminOnly).map((item) => {
          const Icon = item.icon;
          const active = section === item.section;
          const href = item.section === 'dashboard' ? basePath : `${basePath}/${item.section}`;
          return (
            <Link
              key={href}
              to={href}
              className={`inline-flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium ${
                active ? 'bg-slate-900 text-white' : 'border border-gray-200 bg-white text-gray-700 hover:bg-gray-50'
              }`}
            >
              <Icon className="h-4 w-4" />
              {t(`sections.${item.section}.nav`)}
            </Link>
          );
        })}
      </div>

      {error && (
        <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {loading ? (
        <div className="flex h-64 items-center justify-center"><LoadingSpinner /></div>
      ) : section === 'dashboard' ? (
        <Dashboard
          stats={stats}
          alerts={alerts}
          incidents={incidents}
          onTriage={runTriage}
        />
      ) : section === 'connectors' ? (
        <ConnectorPanel
          connectors={filteredConnectors}
          keyword={keyword}
          setKeyword={setKeyword}
          selected={selected}
          setSelected={setSelected}
          packageDiagnostics={connectorPackageDiagnostics}
          evidenceGraph={evidenceGraph}
          runtimeError={connectorRuntimeError}
          testResult={connectorTestResult}
          previewResult={connectorPreviewResult}
          validateResult={connectorValidateResult}
          onTest={testConnector}
          onPreview={previewConnector}
          onValidate={validateConnector}
          onPackageInstall={installConnectorPackage}
          onPackageEnable={enableConnectorPackage}
          onPackageDisable={disableConnectorPackage}
          onPackageUninstall={uninstallConnectorPackage}
          onPackageRollback={rollbackConnectorPackage}
          onPackageUpload={uploadConnectorPackageArtifact}
          onStagingValidate={validateStagedConnectorPackage}
          onStagingInstall={installStagedConnectorPackage}
          onStagingDiscard={discardStagedConnectorPackage}
          onCredentialBind={bindConnectorCredentials}
          onCredentialRotate={rotateConnectorCredentials}
          onCredentialActivate={activateConnectorCredentialProfile}
          onCredentialTest={testConnectorCredentialProfile}
          onCredentialDelete={deleteConnectorCredentialProfile}
          onSync={syncConnector}
          onCursorReset={resetConnectorSyncCursor}
          onScheduleConfigure={configureConnectorSyncSchedule}
          onScheduleRun={runConnectorSyncSchedule}
          onScheduleEnable={enableConnectorSyncSchedule}
          onScheduleDisable={disableConnectorSyncSchedule}
          onRunCancel={cancelConnectorSyncRun}
          onDeadLetterReplay={replayConnectorDeadLetter}
          onExpiryMonitor={monitorConnectorCredentialExpiry}
          operationEvents={connectorOperationEvents}
          operationSettings={connectorOperationsSettings}
          expiryMonitorStatus={connectorExpiryMonitorStatus}
          onExpiryMonitorConfigure={configureConnectorExpiryMonitor}
          onOperationEventAck={acknowledgeConnectorOperationEvent}
          onOperationEventsAck={acknowledgeConnectorOperationEvents}
          onOperationEventNotify={notifyConnectorOperationEvent}
          onBulkRemediation={bulkRemediateConnectorCredentials}
          onEvidenceGraphRebuild={rebuildEvidenceGraph}
        />
      ) : section === 'evidence-ingestion' ? (
        <EvidenceIngestionPanel
          context={ingestionContext}
          setContext={setIngestionContext}
          eventsJson={ingestionEventsJson}
          setEventsJson={setIngestionEventsJson}
          options={ingestionOptions}
          setOptions={setIngestionOptions}
          result={ingestionResult}
          loading={ingestionLoading}
          onIngest={() => void ingestEvidenceEvents()}
        />
      ) : section === 'assets' ? (
        <AssetRiskModule
          assets={assets}
          vulnerabilities={vulnerabilities}
          alerts={alerts}
          incidents={incidents}
          honeypotEvents={honeypotEvents}
          evidenceGraph={evidenceGraph}
          keyword={keyword}
          setKeyword={setKeyword}
          onCreate={openCreate}
          onSelect={(asset) => setSelected(asset as Entity)}
          onEdit={(asset) => openEdit(asset as Entity)}
          onDelete={(asset) => void deleteItem(asset as Entity)}
          onRiskProfile={(assetId) => void buildRiskProfile(assetId)}
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
          <div className="rounded-lg border border-gray-200 bg-white">
            <div className="flex flex-col gap-3 border-b border-gray-200 p-4 md:flex-row md:items-center md:justify-between">
              <input
                value={keyword}
                onChange={(event) => setKeyword(event.target.value)}
                placeholder={t('search.placeholder')}
                className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm md:max-w-sm"
              />

              {section === 'analysis-cases' && (
                <div className="grid w-full gap-2 md:grid-cols-4">
                  <select value={analysisCaseFilters.severity} onChange={(event) => setAnalysisCaseFilters({ ...analysisCaseFilters, severity: event.target.value })} className="rounded-lg border border-gray-200 px-3 py-2 text-sm">
                    <option value="">Severity</option>
                    {analysisCaseSeverityOptions.map((value) => <option key={value} value={value}>{value}</option>)}
                  </select>
                  <select value={analysisCaseFilters.status} onChange={(event) => setAnalysisCaseFilters({ ...analysisCaseFilters, status: event.target.value })} className="rounded-lg border border-gray-200 px-3 py-2 text-sm">
                    <option value="">Status</option>
                    {fields['analysis-cases'].find((field) => field.name === 'case_status')?.options?.map((value) => <option key={value} value={value}>{value}</option>)}
                  </select>
                  <input value={analysisCaseFilters.asset_id} onChange={(event) => setAnalysisCaseFilters({ ...analysisCaseFilters, asset_id: event.target.value })} placeholder="asset_id" className="rounded-lg border border-gray-200 px-3 py-2 text-sm" />
                  <select value={analysisCaseFilters.verdict} onChange={(event) => setAnalysisCaseFilters({ ...analysisCaseFilters, verdict: event.target.value })} className="rounded-lg border border-gray-200 px-3 py-2 text-sm">
                    <option value="">Verdict</option>
                    {fields['analysis-cases'].find((field) => field.name === 'verdict')?.options?.map((value) => <option key={value} value={value}>{value}</option>)}
                  </select>
                </div>
              )}
              {section === 'analysis-cases' && (
                <button onClick={() => void loadAnalysisDemoData()} className="inline-flex items-center justify-center gap-2 rounded-lg border border-blue-200 px-3 py-2 text-sm text-blue-700 hover:bg-blue-50">
                  <PlayCircle className="h-4 w-4" /> 加载演示数据
                </button>
              )}
              <button onClick={openCreate} className="inline-flex items-center justify-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm text-white hover:bg-slate-800">
                <Plus className="h-4 w-4" /> {t('actions.new')}
              </button>
            </div>

            {section === 'analysis-cases' && (
              <div className="grid gap-3 border-b border-gray-100 p-4 text-xs md:grid-cols-3 xl:grid-cols-6">
                {[
                  ['总研判单', analysisCases.length],
                  ['High/Critical', analysisCases.filter((item) => ['high', 'critical'].includes(item.severity)).length],
                  ['待确认/监控/分析中', analysisCases.filter((item) => ['awaiting_confirmation', 'monitoring', 'analyzing'].includes(item.case_status)).length],
                  ['Confirmed Incident', analysisCases.filter((item) => item.verdict === 'confirmed_incident').length],
                  ['Suspicious TP', analysisCases.filter((item) => item.verdict === 'suspicious_true_positive').length],
                  ['Insufficient Evidence', analysisCases.filter((item) => item.verdict === 'insufficient_evidence').length],
                  ['Notifications', analysisCases.reduce((sum, item) => sum + (item.notification_records || []).length, 0)],
                  ['Confirmations', analysisCases.reduce((sum, item) => sum + (item.confirmation_records || []).length, 0)],
                  ['Escalated', analysisCases.filter((item) => item.case_status === 'escalated').length],
                ].map(([label, value]) => (
                  <div key={String(label)} className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2">
                    <div className="text-gray-500">{label}</div>
                    <div className="text-lg font-semibold text-gray-900">{value}</div>
                  </div>
                ))}
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 text-sm">
                <thead className="bg-gray-50">
                  <tr>
                    {columns[section].map((column) => (
                      <th key={column.key} className="px-4 py-3 text-left font-semibold text-gray-600">{t(column.labelKey)}</th>
                    ))}
                    <th className="px-4 py-3 text-right font-semibold text-gray-600">{t('table.actions')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {filteredItems.map((item) => (
                    <tr key={item.id} className="hover:bg-gray-50">
                      {columns[section].map((column) => {
                        const rawValue = item[column.key];
                        const value = section === 'analysis-cases' && ['related_alert_ids', 'facts', 'evidence_gaps', 'notification_records', 'confirmation_records'].includes(column.key) && Array.isArray(rawValue) ? rawValue.length : rawValue;
                        const isBadge = ['severity', 'importance', 'confidence'].includes(column.key);
                        return (
                          <td key={column.key} onClick={() => setSelected(item)} className="cursor-pointer px-4 py-3 text-gray-700">
                            {isBadge ? (
                              <span className={`rounded-full px-2 py-1 text-xs font-medium ${badgeClass(value)}`}>{renderValue(value, formatOption)}</span>
                            ) : renderValue(value, formatOption)}
                          </td>
                        );
                      })}
                      <td className="px-4 py-3">
                        <div className="flex justify-end gap-2">
                          {section === 'alerts' && (
                            <>
                              <button title={t('actions.aiTriage')} onClick={() => void runTriage(item.id)} className="rounded p-1.5 text-purple-600 hover:bg-purple-50">
                                <Brain className="h-4 w-4" />
                              </button>
                              <button title={t('actions.createAnalysisCase', { defaultValue: '生成研判单' })} onClick={() => void createAnalysisCaseFromAlert(item.id)} className="rounded p-1.5 text-indigo-600 hover:bg-indigo-50">
                                <FileText className="h-4 w-4" />
                              </button>
                              <button title={t('actions.createIncident')} onClick={() => void createIncidentFromAlert(item.id)} className="rounded p-1.5 text-red-600 hover:bg-red-50">
                                <ShieldAlert className="h-4 w-4" />
                              </button>
                            </>
                          )}
                          {section === 'analysis-cases' && (
                            <>
                              <button title={t('actions.runInitialAnalysis', { defaultValue: '运行初判 / Run Initial Analysis' })} onClick={() => void runInitialAnalysis(item.id)} className="rounded p-1.5 text-purple-600 hover:bg-purple-50">
                                <Brain className="h-4 w-4" />
                              </button>
                              <button title={t('actions.escalateToIncident', { defaultValue: '升级为事件' })} onClick={() => void escalateAnalysisCase(item.id)} className="rounded p-1.5 text-red-600 hover:bg-red-50">
                                <ShieldAlert className="h-4 w-4" />
                              </button>
                            </>
                          )}
                          {section === 'incidents' && (
                            <button title={t('actions.generateReport')} onClick={() => void generateReport(item.id)} className="rounded p-1.5 text-blue-600 hover:bg-blue-50">
                              <FileText className="h-4 w-4" />
                            </button>
                          )}
                          <button title={t('actions.edit')} onClick={() => openEdit(item)} className="rounded p-1.5 text-gray-600 hover:bg-gray-100">
                            <Edit3 className="h-4 w-4" />
                          </button>
                          <button title={t('actions.delete')} onClick={() => void deleteItem(item)} className="rounded p-1.5 text-red-600 hover:bg-red-50">
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {filteredItems.length === 0 && (
                    <tr>
                      <td colSpan={columns[section].length + 1} className="px-4 py-8 text-center text-gray-500">{t('table.noData')}</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="space-y-4">
            <DetailPanel selected={selected} triageResult={triageResult} riskProfile={riskProfile} report={report} analysisCaseBrief={analysisCaseBrief} onViewAnalysisCaseBrief={(caseId) => void viewAnalysisCaseBrief(caseId)} onEscalateAnalysisCase={(caseId) => void escalateAnalysisCase(caseId)} onRunInitialAnalysis={(caseId) => void runInitialAnalysis(caseId)} onCreateConfirmationRequest={(caseId) => void createConfirmationRequest(caseId)} onCreateAnalysisConfirmation={(caseId, confirmationType, decision) => void createAnalysisConfirmation(caseId, confirmationType, decision)} onAckAnalysisNotification={(caseId, notificationId) => void ackAnalysisNotification(caseId, notificationId)} />
          </div>
        </div>
      )}

      {editing && isDataSection(section) && (
        <FormModal
          title={editing.id ? t('modal.editTitle', { id: editing.id }) : t('modal.newTitle', { section: t(`sections.${section}.title`) })}
          fields={fields[section]}
          form={form}
          setForm={setForm}
          onClose={closeForm}
          onSave={() => void saveForm()}
        />
      )}
    </div>
  );
}

function AssetRiskModule({
  assets,
  vulnerabilities,
  alerts,
  incidents,
  honeypotEvents,
  evidenceGraph,
  keyword,
  setKeyword,
  onCreate,
  onSelect,
  onEdit,
  onDelete,
  onRiskProfile,
}: {
  assets: SecurityAsset[];
  vulnerabilities: SecurityVulnerability[];
  alerts: SecurityAlert[];
  incidents: SecurityIncident[];
  honeypotEvents: SecurityHoneypotEvent[];
  evidenceGraph: SecurityEvidenceGraph | null;
  keyword: string;
  setKeyword: (value: string) => void;
  onCreate: () => void;
  onSelect: (asset: SecurityAsset) => void;
  onEdit: (asset: SecurityAsset) => void;
  onDelete: (asset: SecurityAsset) => void;
  onRiskProfile: (assetId: string) => void;
}) {
  const { t } = useTranslation('security');
  const [riskFilter, setRiskFilter] = useState<AssetRiskFilter>('all');
  const formatOption = useCallback(
    (value: string) => t(`options.${value}`, { defaultValue: value }),
    [t],
  );
  const contexts = useMemo(() => (
    assets
      .map((asset) => buildAssetRiskContext(asset, vulnerabilities, alerts, incidents, honeypotEvents))
      .sort((left, right) => right.score - left.score || left.asset.name.localeCompare(right.asset.name))
  ), [alerts, assets, honeypotEvents, incidents, vulnerabilities]);
  const needsAttention = useCallback((context: AssetRiskContext) => (
    ['critical', 'high'].includes(context.level)
    || context.vulnerabilities.length > 0
    || context.alerts.length > 0
    || context.incidents.length > 0
    || context.honeypotEvents.length > 0
    || context.identity.conflictIds.length > 0
    || context.identity.mergeCandidateIds.length > 0
  ), []);
  const filteredContexts = useMemo(() => {
    const q = keyword.trim().toLowerCase();
    return contexts.filter((context) => {
      if (riskFilter === 'attention' && !needsAttention(context)) return false;
      if (riskFilter === 'critical' && !['critical', 'high'].includes(context.level)) return false;
      if (riskFilter === 'exposed' && context.asset.exposure_level !== 'external') return false;
      if (
        riskFilter === 'identity'
        && context.identity.conflictIds.length === 0
        && context.identity.mergeCandidateIds.length === 0
        && !(context.identity.weakCount > 0 && context.identity.strongCount === 0)
      ) return false;
      if (!q) return true;
      return JSON.stringify({
        asset: context.asset,
        identity: context.identity,
        reasons: context.reasons,
      }).toLowerCase().includes(q);
    });
  }, [contexts, keyword, needsAttention, riskFilter]);
  const summary = useMemo(() => ({
    total: contexts.length,
    attention: contexts.filter(needsAttention).length,
    high: contexts.filter((context) => ['critical', 'high'].includes(context.level)).length,
    exposed: contexts.filter((context) => context.asset.exposure_level === 'external').length,
    identity: contexts.filter((context) => (
      context.identity.conflictIds.length > 0
      || context.identity.mergeCandidateIds.length > 0
      || (context.identity.weakCount > 0 && context.identity.strongCount === 0)
    )).length,
  }), [contexts, needsAttention]);
  const filters: Array<{ key: AssetRiskFilter; label: string; value: number }> = [
    { key: 'all', label: t('assets.filters.all'), value: summary.total },
    { key: 'attention', label: t('assets.filters.attention'), value: summary.attention },
    { key: 'critical', label: t('assets.filters.critical'), value: summary.high },
    { key: 'exposed', label: t('assets.filters.exposed'), value: summary.exposed },
    { key: 'identity', label: t('assets.filters.identity'), value: summary.identity },
  ];
  const summaryCards: Array<{ key: string; label: string; value: number; icon: LucideIcon; tone: string; detail: string }> = [
    {
      key: 'total',
      label: t('assets.summary.total'),
      value: summary.total,
      icon: Database,
      tone: 'border-slate-200 bg-white text-slate-700',
      detail: t('assets.summary.totalDetail'),
    },
    {
      key: 'attention',
      label: t('assets.summary.attention'),
      value: summary.attention,
      icon: AlertTriangle,
      tone: 'border-amber-200 bg-amber-50 text-amber-800',
      detail: t('assets.summary.attentionDetail'),
    },
    {
      key: 'high',
      label: t('assets.summary.highRisk'),
      value: summary.high,
      icon: ShieldAlert,
      tone: 'border-red-200 bg-red-50 text-red-800',
      detail: t('assets.summary.highRiskDetail'),
    },
    {
      key: 'exposed',
      label: t('assets.summary.exposed'),
      value: summary.exposed,
      icon: Eye,
      tone: 'border-blue-200 bg-blue-50 text-blue-800',
      detail: t('assets.summary.exposedDetail'),
    },
    {
      key: 'identity',
      label: t('assets.summary.identity'),
      value: summary.identity,
      icon: KeyRound,
      tone: 'border-violet-200 bg-violet-50 text-violet-800',
      detail: t('assets.summary.identityDetail'),
    },
  ];
  const graphSummary = evidenceGraph?.summary || null;

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <h2 className="text-lg font-semibold text-gray-900">{t('assets.title')}</h2>
          <p className="mt-1 max-w-3xl text-sm text-gray-500">{t('assets.subtitle')}</p>
          {graphSummary && (
            <div className="mt-2 flex flex-wrap gap-2 text-xs text-gray-500">
              <span>{t('assets.graph.entities', { count: graphSummary.asset_entities || 0 })}</span>
              <span>{t('assets.graph.mergeCandidates', { count: graphSummary.merge_candidates || 0 })}</span>
              <span>{t('assets.graph.conflicts', { count: graphSummary.conflicts || 0 })}</span>
            </div>
          )}
        </div>
        <button onClick={onCreate} className="inline-flex items-center justify-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm text-white hover:bg-slate-800">
          <Plus className="h-4 w-4" /> {t('actions.new')}
        </button>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
        {summaryCards.map(({ key, label, value, icon: Icon, tone, detail }) => (
          <div key={key} className={`rounded-lg border p-4 ${tone}`}>
            <div className="flex items-center justify-between gap-3">
              <span className="text-sm font-medium">{label}</span>
              <Icon className="h-5 w-5" />
            </div>
            <div className="mt-3 text-3xl font-semibold">{value}</div>
            <div className="mt-1 text-xs opacity-80">{detail}</div>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-gray-200 bg-white p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <input
            value={keyword}
            onChange={(event) => setKeyword(event.target.value)}
            placeholder={t('assets.searchPlaceholder')}
            className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm lg:max-w-sm"
          />
          <div className="flex flex-wrap gap-2">
            {filters.map((filter) => (
              <button
                key={filter.key}
                onClick={() => setRiskFilter(filter.key)}
                className={`inline-flex items-center gap-2 rounded-lg px-3 py-2 text-sm ${
                  riskFilter === filter.key
                    ? 'bg-slate-900 text-white'
                    : 'border border-gray-200 bg-white text-gray-700 hover:bg-gray-50'
                }`}
              >
                {filter.label}
                <span className={`rounded px-1.5 py-0.5 text-xs ${riskFilter === filter.key ? 'bg-white/20 text-white' : 'bg-gray-100 text-gray-600'}`}>
                  {filter.value}
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 2xl:grid-cols-2">
        {filteredContexts.map((context) => {
          const asset = context.asset;
          const tone = assetRiskTone(context.level);
          const identityState = context.identity.conflictIds.length
            ? { label: t('assets.identity.conflict'), className: 'border-red-200 bg-red-50 text-red-700' }
            : context.identity.mergeCandidateIds.length
              ? { label: t('assets.identity.review'), className: 'border-amber-200 bg-amber-50 text-amber-700' }
              : context.identity.strongCount > 0
                ? { label: t('assets.identity.strong'), className: 'border-emerald-200 bg-emerald-50 text-emerald-700' }
                : context.identity.weakCount > 0
                  ? { label: t('assets.identity.weak'), className: 'border-gray-200 bg-gray-50 text-gray-700' }
                  : { label: t('assets.identity.missing'), className: 'border-gray-200 bg-gray-50 text-gray-700' };
          const topSeverity = maxSeverity([
            ...context.vulnerabilities,
            ...context.alerts,
            ...context.incidents,
          ]);
          const facts = [
            { label: t('fields.asset_type'), value: formatOption(asset.asset_type) },
            { label: t('fields.importance'), value: formatOption(asset.importance) },
            { label: t('fields.exposure_level'), value: formatOption(asset.exposure_level) },
            { label: t('fields.environment'), value: formatOption(asset.environment) },
          ];
          const counts = [
            { label: t('assets.metrics.vulnerabilities'), value: context.vulnerabilities.length, icon: Bug },
            { label: t('assets.metrics.alerts'), value: context.alerts.length, icon: Bell },
            { label: t('assets.metrics.incidents'), value: context.incidents.length, icon: ShieldAlert },
            { label: t('assets.metrics.honeypot'), value: context.honeypotEvents.length, icon: Radar },
          ];

          return (
            <article key={asset.id} className={`rounded-lg border bg-white p-4 ${tone.border}`}>
              <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div className="min-w-0">
                  <div className="flex min-w-0 items-center gap-3">
                    <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${tone.bg}`}>
                      <Database className={`h-5 w-5 ${tone.icon}`} />
                    </div>
                    <div className="min-w-0">
                      <h3 className="truncate text-base font-semibold text-gray-900">{asset.name}</h3>
                      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-gray-500">
                        <span>{asset.ip || asset.hostname || asset.domain || asset.id}</span>
                        {asset.business_system && <span>{asset.business_system}</span>}
                        {context.identity.sourceLabel && <span>{context.identity.sourceLabel}</span>}
                      </div>
                    </div>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2 md:justify-end">
                  <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${tone.badge}`}>
                    {t(`assets.risk.${context.level}`)}
                  </span>
                  {topSeverity && (
                    <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${badgeClass(topSeverity)}`}>
                      {t('assets.highestSignal', { severity: formatOption(topSeverity) })}
                    </span>
                  )}
                  <span className={`rounded-full border px-2.5 py-1 text-xs font-medium ${identityState.className}`}>
                    {identityState.label}
                  </span>
                </div>
              </div>

              <div className={`mt-4 rounded-lg border px-3 py-3 ${tone.bg} ${tone.border}`}>
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className={`text-sm font-semibold ${tone.text}`}>{t('assets.securityStatus')}</div>
                    <div className="mt-1 text-xs text-gray-600">
                      {context.reasons.length
                        ? context.reasons.slice(0, 4).map((reason) => t(`assets.reasons.${reason}`)).join(' · ')
                        : t('assets.reasons.noActiveSignals')}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`text-2xl font-semibold ${tone.text}`}>{context.score}</div>
                    <div className="text-xs text-gray-500">{t('assets.score')}</div>
                  </div>
                </div>
                <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/80">
                  <div className={`h-full rounded-full ${context.level === 'critical' ? 'bg-red-500' : context.level === 'high' ? 'bg-orange-500' : context.level === 'medium' ? 'bg-amber-500' : 'bg-emerald-500'}`} style={{ width: `${context.score}%` }} />
                </div>
              </div>

              <div className="mt-4 grid grid-cols-2 gap-2 md:grid-cols-4">
                {counts.map(({ label, value, icon: Icon }) => (
                  <div key={label} className="rounded-lg border border-gray-100 bg-gray-50 px-3 py-2">
                    <div className="flex items-center gap-2 text-xs text-gray-500">
                      <Icon className="h-3.5 w-3.5" /> {label}
                    </div>
                    <div className="mt-1 text-lg font-semibold text-gray-900">{value}</div>
                  </div>
                ))}
              </div>

              <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
                <div className="space-y-2 text-sm">
                  {facts.map((fact) => (
                    <div key={fact.label} className="flex items-center justify-between gap-3">
                      <span className="text-gray-500">{fact.label}</span>
                      <span className="font-medium text-gray-900">{fact.value || '-'}</span>
                    </div>
                  ))}
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-gray-500">{t('assets.lastSeen')}</span>
                    <span className="font-medium text-gray-900">{formatDateTime(context.lastSeenAt)}</span>
                  </div>
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-gray-500">{t('assets.identity.strongKeys')}</span>
                    <span className="font-medium text-gray-900">{context.identity.strongCount}</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-gray-500">{t('assets.identity.auxiliaryKeys')}</span>
                    <span className="font-medium text-gray-900">{context.identity.auxiliaryCount}</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-gray-500">{t('assets.identity.ipObservations')}</span>
                    <span className="font-medium text-gray-900">{context.identity.ipObservations.length}</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-gray-500">{t('assets.identity.entity')}</span>
                    <span className="max-w-[180px] truncate font-medium text-gray-900">
                      {context.identity.entityIds[0] || '-'}
                    </span>
                  </div>
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-2 text-xs">
                {context.identity.allocationMode && (
                  <span className="rounded-full bg-gray-100 px-2.5 py-1 text-gray-700">
                    {t('assets.identity.allocationMode', { mode: context.identity.allocationMode })}
                  </span>
                )}
                {context.identity.mergeCandidateIds.length > 0 && (
                  <span className="rounded-full bg-amber-100 px-2.5 py-1 text-amber-700">
                    {t('assets.identity.mergeCandidates', { count: context.identity.mergeCandidateIds.length })}
                  </span>
                )}
                {context.identity.conflictIds.length > 0 && (
                  <span className="rounded-full bg-red-100 px-2.5 py-1 text-red-700">
                    {t('assets.identity.conflicts', { count: context.identity.conflictIds.length })}
                  </span>
                )}
                {asset.open_ports?.slice(0, 4).map((port) => (
                  <span key={port} className="rounded-full bg-gray-100 px-2.5 py-1 text-gray-700">
                    {t('assets.openPort', { port })}
                  </span>
                ))}
              </div>

              <div className="mt-4 flex flex-wrap justify-end gap-2 border-t border-gray-100 pt-3">
                <button title={t('actions.riskProfile')} onClick={() => onRiskProfile(asset.id)} className="inline-flex items-center gap-1.5 rounded-lg border border-teal-200 px-3 py-2 text-sm text-teal-700 hover:bg-teal-50">
                  <Activity className="h-4 w-4" /> {t('actions.riskProfile')}
                </button>
                <button title={t('assets.actions.details')} onClick={() => onSelect(asset)} className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50">
                  <FileText className="h-4 w-4" /> {t('assets.actions.details')}
                </button>
                <button title={t('actions.edit')} onClick={() => onEdit(asset)} className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50">
                  <Edit3 className="h-4 w-4" /> {t('actions.edit')}
                </button>
                <button title={t('actions.delete')} onClick={() => onDelete(asset)} className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 px-3 py-2 text-sm text-red-700 hover:bg-red-50">
                  <Trash2 className="h-4 w-4" /> {t('actions.delete')}
                </button>
              </div>
            </article>
          );
        })}
      </div>

      {filteredContexts.length === 0 && (
        <div className="rounded-lg border border-gray-200 bg-white py-16 text-center">
          <Database className="mx-auto h-10 w-10 text-gray-300" />
          <div className="mt-3 text-sm font-medium text-gray-900">
            {assets.length ? t('assets.emptyFilteredTitle') : t('assets.emptyTitle')}
          </div>
          <div className="mt-1 text-sm text-gray-500">
            {assets.length ? t('assets.emptyFilteredDescription') : t('assets.emptyDescription')}
          </div>
        </div>
      )}
    </div>
  );
}

function ConnectorPanel({
  connectors,
  keyword,
  setKeyword,
  selected,
  setSelected,
  packageDiagnostics,
  evidenceGraph,
  runtimeError,
  testResult,
  previewResult,
  validateResult,
  onTest,
  onPreview,
  onValidate,
  onPackageInstall,
  onPackageEnable,
  onPackageDisable,
  onPackageUninstall,
  onPackageRollback,
  onPackageUpload,
  onStagingValidate,
  onStagingInstall,
  onStagingDiscard,
  onCredentialBind,
  onCredentialRotate,
  onCredentialActivate,
  onCredentialTest,
  onCredentialDelete,
  onSync,
  onCursorReset,
  onScheduleConfigure,
  onScheduleRun,
  onScheduleEnable,
  onScheduleDisable,
  onRunCancel,
  onDeadLetterReplay,
  onExpiryMonitor,
  operationEvents,
  operationSettings,
  expiryMonitorStatus,
  onExpiryMonitorConfigure,
  onOperationEventAck,
  onOperationEventsAck,
  onOperationEventNotify,
  onBulkRemediation,
  onEvidenceGraphRebuild,
}: {
  connectors: SecurityConnectorManifest[];
  keyword: string;
  setKeyword: (value: string) => void;
  selected: Entity | null;
  setSelected: (value: Entity | null) => void;
  packageDiagnostics: SecurityConnectorPackageDiagnostics | null;
  evidenceGraph: SecurityEvidenceGraph | null;
  runtimeError: string | null;
  testResult: SecurityConnectorTestResult | null;
  previewResult: SecurityConnectorPreviewResult | null;
  validateResult: SecurityConnectorValidateResult | null;
  onTest: (connectorId: string) => Promise<void>;
  onPreview: (connectorId: string, capability: string) => Promise<void>;
  onValidate: (connectorId: string) => Promise<void>;
  onPackageInstall: (packageRoot: string) => Promise<void>;
  onPackageEnable: (packageId: string) => Promise<void>;
  onPackageDisable: (packageId: string) => Promise<void>;
  onPackageUninstall: (packageId: string) => Promise<void>;
  onPackageRollback: (packageId: string) => Promise<void>;
  onPackageUpload: (file: File) => Promise<void>;
  onStagingValidate: (stagingId: string) => Promise<void>;
  onStagingInstall: (stagingId: string) => Promise<void>;
  onStagingDiscard: (stagingId: string) => Promise<void>;
  onCredentialBind: (connectorId: string) => Promise<void>;
  onCredentialRotate: (connectorId: string, profileId: string, currentExpiresAt?: string | null) => Promise<void>;
  onCredentialActivate: (connectorId: string, profileId: string) => Promise<void>;
  onCredentialTest: (connectorId: string, profileId: string) => Promise<void>;
  onCredentialDelete: (connectorId: string, profileId: string) => Promise<void>;
  onSync: (connectorId: string, capability: string, mode: string, resetCursor?: boolean, credentialProfileId?: string | null) => Promise<void>;
  onCursorReset: (connectorId: string, capability: string) => Promise<void>;
  onScheduleConfigure: (connectorId: string, capability: string, mode: string, credentialProfileId?: string | null) => Promise<void>;
  onScheduleRun: (scheduleId: string, mode?: string) => Promise<void>;
  onScheduleEnable: (scheduleId: string) => Promise<void>;
  onScheduleDisable: (scheduleId: string) => Promise<void>;
  onRunCancel: (runId: string) => Promise<void>;
  onDeadLetterReplay: (deadLetterId: string) => Promise<void>;
  onExpiryMonitor: () => Promise<void>;
  operationEvents: SecurityConnectorOperationEvent[];
  operationSettings: SecurityConnectorOperationsSettings | null;
  expiryMonitorStatus: SecurityConnectorExpiryMonitorSchedulerStatus | null;
  onExpiryMonitorConfigure: () => Promise<void>;
  onOperationEventAck: (eventId: string) => Promise<void>;
  onOperationEventsAck: (eventIds: string[]) => Promise<void>;
  onOperationEventNotify: (eventId: string) => Promise<void>;
  onBulkRemediation: (action: string, items: SecurityConnectorBulkRemediationItem[], recoveryMode?: string) => Promise<void>;
  onEvidenceGraphRebuild: () => Promise<void>;
}) {
  const { t } = useTranslation('security');
  const [capabilitySelections, setCapabilitySelections] = useState<Record<string, string>>({});
  const [syncModeSelections, setSyncModeSelections] = useState<Record<string, string>>({});
  const formatOption = useCallback(
    (value: string) => t(`options.${value}`, { defaultValue: value }),
    [t],
  );
  const selectedCapability = (connector: SecurityConnectorManifest) =>
    capabilitySelections[connector.id] || connector.capabilities[0] || '';
  const selectedSyncMode = (connector: SecurityConnectorManifest) =>
    syncModeSelections[connector.id] || 'incremental';
  const latestSyncByConnector = useMemo(() => {
    const result: Record<string, NonNullable<SecurityConnectorPackageDiagnostics['sync_runs']>[number]> = {};
    for (const run of packageDiagnostics?.sync_runs || []) {
      if (!result[run.connector_id]) result[run.connector_id] = run;
    }
    return result;
  }, [packageDiagnostics]);
  const cursorByConnectorCapability = useMemo(() => {
    const result: Record<string, NonNullable<SecurityConnectorPackageDiagnostics['sync_cursors']>[number]> = {};
    for (const cursor of packageDiagnostics?.sync_cursors || []) {
      result[`${cursor.connector_id}:${cursor.capability}`] = cursor;
    }
    return result;
  }, [packageDiagnostics]);
  const scheduleByConnectorCapability = useMemo(() => {
    const result: Record<string, NonNullable<SecurityConnectorPackageDiagnostics['sync_schedules']>[number]> = {};
    for (const schedule of packageDiagnostics?.sync_schedules || []) {
      result[`${schedule.connector_id}:${schedule.capability}`] = schedule;
    }
    return result;
  }, [packageDiagnostics]);
  const credentialBindingByConnector = useMemo(() => {
    const result: Record<string, NonNullable<SecurityConnectorPackageDiagnostics['credential_bindings']>[number]> = {};
    for (const binding of packageDiagnostics?.credential_bindings || []) {
      result[binding.connector_id] = binding;
    }
    return result;
  }, [packageDiagnostics]);
  const activeCredentialProfileId = (connectorId: string) =>
    credentialBindingByConnector[connectorId]?.active_profile_id || null;

  return (
    <div className="space-y-4">
      {runtimeError && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          {runtimeError}
        </div>
      )}
      <ConnectorPackageDiagnosticsPanel
        diagnostics={packageDiagnostics}
        onInstall={onPackageInstall}
        onEnable={onPackageEnable}
        onDisable={onPackageDisable}
        onUninstall={onPackageUninstall}
        onRollback={onPackageRollback}
        onUpload={onPackageUpload}
        onStagingValidate={onStagingValidate}
        onStagingInstall={onStagingInstall}
        onStagingDiscard={onStagingDiscard}
      />
      <EvidenceGraphPanel graph={evidenceGraph} diagnostics={packageDiagnostics} onRebuild={onEvidenceGraphRebuild} />
      <ConnectorOperationsPanel
        diagnostics={packageDiagnostics}
        events={operationEvents}
        settings={operationSettings}
        expiryMonitorStatus={expiryMonitorStatus}
        onExpiryMonitor={onExpiryMonitor}
        onExpiryMonitorConfigure={onExpiryMonitorConfigure}
        onOperationEventAck={onOperationEventAck}
        onOperationEventsAck={onOperationEventsAck}
        onOperationEventNotify={onOperationEventNotify}
        onBulkRemediation={onBulkRemediation}
      />
      <ConnectorRuntimeObservabilityPanel
        diagnostics={packageDiagnostics}
        onRunCancel={onRunCancel}
        onDeadLetterReplay={onDeadLetterReplay}
        onCredentialBind={onCredentialBind}
        onCredentialActivate={onCredentialActivate}
        onCredentialTest={onCredentialTest}
        onCredentialRotate={onCredentialRotate}
      />
      <ConnectorCredentialProfilesPanel
        diagnostics={packageDiagnostics}
        onActivate={onCredentialActivate}
        onTest={onCredentialTest}
        onRotate={onCredentialRotate}
        onDelete={onCredentialDelete}
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
        <div className="rounded-lg border border-gray-200 bg-white">
          <div className="flex flex-col gap-3 border-b border-gray-200 p-4 md:flex-row md:items-center md:justify-between">
            <input
              value={keyword}
              onChange={(event) => setKeyword(event.target.value)}
              placeholder={t('search.placeholder')}
              className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm md:max-w-sm"
            />
            <div className="text-sm text-gray-500">{t('connectors.count', { count: connectors.length })}</div>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left font-semibold text-gray-600">{t('fields.name')}</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-600">{t('fields.vendor')}</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-600">{t('fields.product')}</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-600">{t('fields.capabilities')}</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-600">{t('fields.preview_capability')}</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-600">{t('fields.sync_mode')}</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-600">{t('fields.schedule')}</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-600">{t('fields.last_sync')}</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-600">{t('fields.risk_level')}</th>
                  <th className="px-4 py-3 text-right font-semibold text-gray-600">{t('table.actions')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {connectors.map((connector) => (
                  <tr key={connector.id} className="hover:bg-gray-50">
                    <td onClick={() => setSelected(connector as unknown as Entity)} className="cursor-pointer px-4 py-3">
                      <div className="font-medium text-gray-900">{connector.name}</div>
                      <div className="text-xs text-gray-500">{connector.id}</div>
                    </td>
                    <td className="px-4 py-3 text-gray-700">{connector.vendor}</td>
                    <td className="px-4 py-3 text-gray-700">{connector.product}</td>
                    <td className="px-4 py-3 text-gray-700">{connector.capabilities.length}</td>
                    <td className="px-4 py-3">
                      <select
                        value={selectedCapability(connector)}
                        onChange={(event) => setCapabilitySelections({ ...capabilitySelections, [connector.id]: event.target.value })}
                        className="max-w-[220px] rounded border border-gray-200 px-2 py-1 text-xs text-gray-700"
                      >
                        {connector.capabilities.map((capability) => (
                          <option key={capability} value={capability}>{capability}</option>
                        ))}
                      </select>
                    </td>
                    <td className="px-4 py-3">
                      <select
                        value={selectedSyncMode(connector)}
                        onChange={(event) => setSyncModeSelections({ ...syncModeSelections, [connector.id]: event.target.value })}
                        className="max-w-[140px] rounded border border-gray-200 px-2 py-1 text-xs text-gray-700"
                      >
                        <option value="incremental">{t('options.incremental')}</option>
                        <option value="full">{t('options.full')}</option>
                      </select>
                    </td>
                    <td className="px-4 py-3">
                      <ConnectorScheduleSummary
                        schedule={scheduleByConnectorCapability[`${connector.id}:${selectedCapability(connector)}`]}
                        onPolicyAction={handlePolicyAction({
                          onCredentialBind,
                          onCredentialActivate,
                          onCredentialTest,
                          onCredentialRotate,
                        })}
                      />
                    </td>
                    <td className="px-4 py-3">
                      <ConnectorSyncSummary
                        run={latestSyncByConnector[connector.id]}
                        cursor={cursorByConnectorCapability[`${connector.id}:${selectedCapability(connector)}`]}
                      />
                    </td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full px-2 py-1 text-xs font-medium ${badgeClass(connector.risk_level)}`}>
                        {formatOption(connector.risk_level)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-2">
                        <button title={t('actions.bindCredentials')} onClick={() => void onCredentialBind(connector.id)} className="rounded p-1.5 text-slate-700 hover:bg-slate-50">
                          <KeyRound className="h-4 w-4" />
                        </button>
                        <button title={t('actions.testConnection')} onClick={() => void onTest(connector.id)} className="rounded p-1.5 text-teal-700 hover:bg-teal-50">
                          <Activity className="h-4 w-4" />
                        </button>
                        <button title={t('actions.validate')} onClick={() => void onValidate(connector.id)} className="rounded p-1.5 text-emerald-700 hover:bg-emerald-50">
                          <ShieldCheck className="h-4 w-4" />
                        </button>
                        <button
                          title={t('actions.configureSchedule')}
                          disabled={!selectedCapability(connector)}
                          onClick={() => void onScheduleConfigure(
                            connector.id,
                            selectedCapability(connector),
                            selectedSyncMode(connector),
                            activeCredentialProfileId(connector.id),
                          )}
                          className="rounded p-1.5 text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:text-gray-300"
                        >
                          <Clock className="h-4 w-4" />
                        </button>
                        <button
                          title={t('actions.runScheduleNow')}
                          disabled={!scheduleByConnectorCapability[`${connector.id}:${selectedCapability(connector)}`]}
                          onClick={() => {
                            const schedule = scheduleByConnectorCapability[`${connector.id}:${selectedCapability(connector)}`];
                            if (schedule) void onScheduleRun(schedule.id, selectedSyncMode(connector));
                          }}
                          className="rounded p-1.5 text-cyan-700 hover:bg-cyan-50 disabled:cursor-not-allowed disabled:text-gray-300"
                        >
                          <PlayCircle className="h-4 w-4" />
                        </button>
                        {scheduleByConnectorCapability[`${connector.id}:${selectedCapability(connector)}`]?.enabled ? (
                          <button
                            title={t('actions.pauseSchedule')}
                            onClick={() => void onScheduleDisable(scheduleByConnectorCapability[`${connector.id}:${selectedCapability(connector)}`].id)}
                            className="rounded p-1.5 text-amber-700 hover:bg-amber-50"
                          >
                            <PowerOff className="h-4 w-4" />
                          </button>
                        ) : (
                          <button
                            title={t('actions.enableSchedule')}
                            disabled={!scheduleByConnectorCapability[`${connector.id}:${selectedCapability(connector)}`]}
                            onClick={() => {
                              const schedule = scheduleByConnectorCapability[`${connector.id}:${selectedCapability(connector)}`];
                              if (schedule) void onScheduleEnable(schedule.id);
                            }}
                            className="rounded p-1.5 text-emerald-700 hover:bg-emerald-50 disabled:cursor-not-allowed disabled:text-gray-300"
                          >
                            <Power className="h-4 w-4" />
                          </button>
                        )}
                        <button
                          title={t('actions.syncConnector')}
                          disabled={!selectedCapability(connector)}
                          onClick={() => void onSync(
                            connector.id,
                            selectedCapability(connector),
                            selectedSyncMode(connector),
                            false,
                            activeCredentialProfileId(connector.id),
                          )}
                          className="rounded p-1.5 text-teal-700 hover:bg-teal-50 disabled:cursor-not-allowed disabled:text-gray-300"
                        >
                          <RefreshCw className="h-4 w-4" />
                        </button>
                        <button
                          title={t('actions.resetCursor')}
                          disabled={!selectedCapability(connector)}
                          onClick={() => void onCursorReset(connector.id, selectedCapability(connector))}
                          className="rounded p-1.5 text-indigo-700 hover:bg-indigo-50 disabled:cursor-not-allowed disabled:text-gray-300"
                        >
                          <RotateCcw className="h-4 w-4" />
                        </button>
                        <button
                          title={t('actions.preview')}
                          disabled={!selectedCapability(connector)}
                          onClick={() => void onPreview(connector.id, selectedCapability(connector))}
                          className="rounded p-1.5 text-blue-700 hover:bg-blue-50 disabled:cursor-not-allowed disabled:text-gray-300"
                        >
                          <FileText className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {connectors.length === 0 && (
                  <tr>
                    <td colSpan={10} className="px-4 py-8 text-center text-gray-500">{t('table.noData')}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-lg border border-gray-200 bg-white">
            <div className="border-b border-gray-200 px-4 py-3 font-semibold text-gray-900">{t('detail.title')}</div>
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words p-4 text-xs text-gray-700">
              {selected ? JSON.stringify(selected, null, 2) : t('detail.empty')}
            </pre>
          </div>
          {validateResult && (
            <div className="rounded-lg border border-emerald-200 bg-emerald-50">
              <div className="border-b border-emerald-100 px-4 py-3 font-semibold text-emerald-900">{t('detail.connectorValidateResult')}</div>
              <pre className="max-h-[520px] overflow-auto whitespace-pre-wrap break-words p-4 text-xs text-emerald-950">
                {JSON.stringify(validateResult, null, 2)}
              </pre>
            </div>
          )}
          {testResult && (
            <div className="rounded-lg border border-teal-200 bg-teal-50">
              <div className="border-b border-teal-100 px-4 py-3 font-semibold text-teal-900">{t('detail.connectorTestResult')}</div>
              <pre className="max-h-[520px] overflow-auto whitespace-pre-wrap break-words p-4 text-xs text-teal-950">
                {JSON.stringify(testResult, null, 2)}
              </pre>
            </div>
          )}
          {previewResult && (
            <div className="rounded-lg border border-blue-200 bg-blue-50">
              <div className="border-b border-blue-100 px-4 py-3 font-semibold text-blue-900">{t('detail.connectorPreviewResult')}</div>
              <ConnectorPreviewDiagnostics previewResult={previewResult} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function EvidenceGraphPanel({
  graph,
  diagnostics,
  onRebuild,
}: {
  graph: SecurityEvidenceGraph | null;
  diagnostics: SecurityConnectorPackageDiagnostics | null;
  onRebuild: () => Promise<void>;
}) {
  const { t } = useTranslation('security');
  const summary = graph?.summary || diagnostics?.evidence_graph || null;
  const statItems: Array<[string, number]> = [
    [t('fields.nodes'), summary?.nodes || 0],
    [t('fields.edges'), summary?.edges || 0],
    [t('fields.asset_entities'), summary?.asset_entities || 0],
    [t('fields.merge_candidates'), summary?.merge_candidates || 0],
    [t('fields.conflicts'), summary?.conflicts || 0],
  ];
  const mergeCandidates = graph?.merge_candidates || [];
  const conflicts = graph?.conflicts || [];

  return (
    <div className="rounded-lg border border-gray-200 bg-white">
      <div className="flex flex-col gap-3 border-b border-gray-200 px-4 py-3 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="font-semibold text-gray-900">{t('detail.evidenceGraph')}</div>
          <div className="text-xs text-gray-500">
            {summary?.version || graph?.version || 'connector.evidence.graph.v1'}
            {summary?.updated_at ? ` · ${summary.updated_at}` : ''}
          </div>
        </div>
        <button
          onClick={() => void onRebuild()}
          className="inline-flex items-center justify-center gap-2 rounded bg-slate-900 px-3 py-2 text-xs font-medium text-white hover:bg-slate-800"
        >
          <RefreshCw className="h-4 w-4" />
          {t('actions.rebuildEvidenceGraph')}
        </button>
      </div>
      <div className="grid gap-4 p-4 xl:grid-cols-[minmax(0,1fr)_420px]">
        <div className="grid grid-cols-2 gap-2 text-xs md:grid-cols-5">
          {statItems.map(([label, value]) => (
            <div key={label} className="rounded border border-gray-200 px-3 py-2">
              <div className="text-gray-500">{label}</div>
              <div className="font-mono text-lg font-semibold text-gray-900">{value}</div>
            </div>
          ))}
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-1">
          <EvidenceGraphList
            title={t('fields.merge_candidates')}
            empty={t('detail.noMergeCandidates')}
            items={mergeCandidates.slice(0, 3).map((item) => ({
              id: item.id,
              label: `${item.asset_ids?.length || 0} ${t('sections.assets.nav')} · ${item.confidence || '-'}`,
              detail: (item.matching_keys || []).map((key: any) => key.key).join(', ') || item.reason || item.entity_id,
            }))}
          />
          <EvidenceGraphList
            title={t('fields.conflicts')}
            empty={t('detail.noEvidenceConflicts')}
            items={conflicts.slice(0, 3).map((item) => ({
              id: item.id,
              label: `${item.field || '-'} · ${item.severity || '-'}`,
              detail: (item.values || []).map((value: any) => `${value.value}: ${(value.asset_ids || []).join(', ')}`).join(' | '),
            }))}
          />
        </div>
      </div>
    </div>
  );
}

function EvidenceGraphList({
  title,
  empty,
  items,
}: {
  title: string;
  empty: string;
  items: Array<{ id: string; label: string; detail: string }>;
}) {
  return (
    <div className="rounded border border-gray-200 px-3 py-2 text-xs">
      <div className="mb-2 font-semibold uppercase text-gray-500">{title}</div>
      <div className="space-y-2">
        {items.map((item) => (
          <div key={item.id} className="min-w-0">
            <div className="truncate font-medium text-gray-900">{item.label}</div>
            <div className="truncate font-mono text-[11px] text-gray-500">{item.detail || item.id}</div>
          </div>
        ))}
        {items.length === 0 && <div className="text-gray-400">{empty}</div>}
      </div>
    </div>
  );
}

function ConnectorOperationsPanel({
  diagnostics,
  events,
  settings,
  expiryMonitorStatus,
  onExpiryMonitor,
  onExpiryMonitorConfigure,
  onOperationEventAck,
  onOperationEventsAck,
  onOperationEventNotify,
  onBulkRemediation,
}: {
  diagnostics: SecurityConnectorPackageDiagnostics | null;
  events: SecurityConnectorOperationEvent[];
  settings: SecurityConnectorOperationsSettings | null;
  expiryMonitorStatus: SecurityConnectorExpiryMonitorSchedulerStatus | null;
  onExpiryMonitor: () => Promise<void>;
  onExpiryMonitorConfigure: () => Promise<void>;
  onOperationEventAck: (eventId: string) => Promise<void>;
  onOperationEventsAck: (eventIds: string[]) => Promise<void>;
  onOperationEventNotify: (eventId: string) => Promise<void>;
  onBulkRemediation: (action: string, items: SecurityConnectorBulkRemediationItem[], recoveryMode?: string) => Promise<void>;
}) {
  const { t } = useTranslation('security');
  const [statusFilter, setStatusFilter] = useState('open');
  const [kindFilter, setKindFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [eventKeyword, setEventKeyword] = useState('');
  const [selectedEventIds, setSelectedEventIds] = useState<Set<string>>(new Set());
  const [detailEvent, setDetailEvent] = useState<SecurityConnectorOperationEvent | null>(null);
  const [pendingBulk, setPendingBulk] = useState<{
    action: string;
    items: SecurityConnectorBulkRemediationItem[];
    recoveryMode?: string;
  } | null>(null);
  const sourceEvents = events.length ? events : diagnostics?.operation_events || emptyOperationEvents;
  const openEvents = sourceEvents.filter((event) => event.status === 'open');
  const profiles = (diagnostics?.credential_bindings || []).flatMap((binding) =>
    (binding.profiles || []).map((profile) => ({ connector_id: binding.connector_id, profile })),
  );
  const schedules = diagnostics?.sync_schedules || [];
  const unhealthyTargets = profiles
    .filter(({ profile }) => ['expired', 'failed', 'pending_test'].includes(String(profile.status || '')))
    .map(({ connector_id, profile }) => ({ connector_id, profile_id: profile.id }));
  const pausedTargets = schedules
    .filter((schedule) => schedule.policy_state === 'paused' && schedule.credential_profile_id)
    .map((schedule) => ({ connector_id: schedule.connector_id, profile_id: String(schedule.credential_profile_id) }));
  const remediationTargets = uniqueCredentialTargets([...unhealthyTargets, ...pausedTargets]);
  const pausedScheduleTargets = uniqueCredentialTargets(pausedTargets);
  const eventKinds = Array.from(new Set(sourceEvents.map((event) => event.kind).filter(Boolean))).sort();
  const eventSeverities = Array.from(new Set(sourceEvents.map((event) => event.severity).filter(Boolean))).sort();
  const filteredEvents = useMemo(() => {
    const keyword = eventKeyword.trim().toLowerCase();
    return sourceEvents.filter((event) => {
      if (statusFilter !== 'all' && event.status !== statusFilter) return false;
      if (kindFilter !== 'all' && event.kind !== kindFilter) return false;
      if (severityFilter !== 'all' && event.severity !== severityFilter) return false;
      if (keyword && !JSON.stringify(event).toLowerCase().includes(keyword)) return false;
      return true;
    });
  }, [eventKeyword, kindFilter, severityFilter, sourceEvents, statusFilter]);
  const selectedEvents = sourceEvents.filter((event) => selectedEventIds.has(event.id));
  const selectedTargets = uniqueCredentialTargets(
    selectedEvents
      .filter((event) => event.connector_id && event.profile_id)
      .map((event) => ({ connector_id: String(event.connector_id), profile_id: String(event.profile_id) })),
  );
  const selectedOpenEventIds = selectedEvents.filter((event) => event.status === 'open').map((event) => event.id);
  const bulkTargets = selectedTargets.length > 0 ? selectedTargets : remediationTargets;
  const bulkPausedTargets = selectedTargets.length > 0 ? selectedTargets : pausedScheduleTargets;
  const allVisibleSelected = filteredEvents.length > 0 && filteredEvents.every((event) => selectedEventIds.has(event.id));
  useEffect(() => {
    const available = new Set(sourceEvents.map((event) => event.id));
    setSelectedEventIds((current) => {
      const nextIds = Array.from(current).filter((id) => available.has(id));
      if (nextIds.length === current.size && nextIds.every((id) => current.has(id))) {
        return current;
      }
      return new Set(nextIds);
    });
  }, [sourceEvents]);
  const summaryItems: Array<[string, number]> = [
    [t('connectors.operationEvents'), diagnostics?.summary.connector_operation_events || sourceEvents.length],
    [t('connectors.openOperationEvents'), diagnostics?.summary.open_connector_operation_events || openEvents.length],
    [t('connectors.bulkTargets'), remediationTargets.length],
  ];
  const toggleSelected = (eventId: string) => {
    setSelectedEventIds((current) => {
      const next = new Set(current);
      if (next.has(eventId)) next.delete(eventId);
      else next.add(eventId);
      return next;
    });
  };
  const toggleAllVisible = () => {
    setSelectedEventIds((current) => {
      const next = new Set(current);
      if (allVisibleSelected) {
        filteredEvents.forEach((event) => next.delete(event.id));
      } else {
        filteredEvents.forEach((event) => next.add(event.id));
      }
      return next;
    });
  };
  const confirmBulk = async () => {
    if (!pendingBulk) return;
    await onBulkRemediation(pendingBulk.action, pendingBulk.items, pendingBulk.recoveryMode);
    setPendingBulk(null);
    setSelectedEventIds(new Set());
  };

  return (
    <div className="rounded-lg border border-gray-200 bg-white">
      <div className="flex flex-col gap-3 border-b border-gray-200 px-4 py-3 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="font-semibold text-gray-900">{t('connectors.operationEvents')}</div>
          <div className="text-xs text-gray-500">
            {t('connectors.operationEventsSubtitle')}
            {settings?.expiry_monitor && (
              <span className="ml-2 font-mono text-[11px]">
                N={settings.expiry_monitor.days} · {settings.expiry_monitor.enabled ? t('options.enabled') : t('options.disabled')}
              </span>
            )}
            {expiryMonitorStatus?.settings?.next_run_at && (
              <span className="ml-2 font-mono text-[11px]">{expiryMonitorStatus.settings.next_run_at}</span>
            )}
          </div>
        </div>
        <div className="grid grid-cols-3 gap-2 text-xs">
          {summaryItems.map(([label, value]) => (
            <div key={label} className="min-w-24 rounded border border-gray-200 px-2 py-1">
              <div className="text-gray-500">{label}</div>
              <div className="font-mono font-semibold text-gray-900">{value}</div>
            </div>
          ))}
        </div>
      </div>
      <ConnectorOperationsDashboard dashboard={diagnostics?.operations_dashboard} />
      <div className="border-b border-gray-100 px-4 py-3">
        <div className="grid gap-2 text-xs md:grid-cols-[150px_190px_150px_minmax(0,1fr)_auto]">
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="rounded border border-gray-200 bg-white px-2 py-2"
            title={t('fields.status')}
          >
            {['all', 'open', 'acknowledged'].map((status) => (
              <option key={status} value={status}>{t(`options.${status}`, { defaultValue: status })}</option>
            ))}
          </select>
          <select
            value={kindFilter}
            onChange={(event) => setKindFilter(event.target.value)}
            className="rounded border border-gray-200 bg-white px-2 py-2"
            title={t('fields.kind')}
          >
            <option value="all">{t('options.all')}</option>
            {eventKinds.map((kind) => (
              <option key={kind} value={kind}>{t(`options.${kind}`, { defaultValue: kind })}</option>
            ))}
          </select>
          <select
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
            className="rounded border border-gray-200 bg-white px-2 py-2"
            title={t('fields.severity')}
          >
            <option value="all">{t('options.all')}</option>
            {eventSeverities.map((severity) => (
              <option key={severity} value={severity}>{t(`options.${severity}`, { defaultValue: severity })}</option>
            ))}
          </select>
          <input
            value={eventKeyword}
            onChange={(event) => setEventKeyword(event.target.value)}
            placeholder={t('search.placeholder')}
            className="rounded border border-gray-200 px-2 py-2"
          />
          <button
            title={t('actions.batchAcknowledge')}
            disabled={selectedOpenEventIds.length === 0}
            onClick={() => void onOperationEventsAck(selectedOpenEventIds)}
            className="inline-flex items-center justify-center gap-2 rounded border border-emerald-200 bg-emerald-50 px-3 py-2 font-medium text-emerald-800 hover:bg-emerald-100 disabled:cursor-not-allowed disabled:border-gray-200 disabled:bg-gray-50 disabled:text-gray-300"
          >
            <CheckCircle2 className="h-4 w-4" />
            {t('actions.batchAcknowledge')}
          </button>
        </div>
        {selectedEventIds.size > 0 && (
          <div className="mt-2 text-xs text-gray-500">
            {t('connectors.selectedEvents', { count: selectedEventIds.size })}
          </div>
        )}
      </div>
      <div className="grid gap-4 p-4 xl:grid-cols-[minmax(0,1fr)_auto]">
        <div className="overflow-hidden rounded border border-gray-200">
          <div className="flex items-center gap-2 border-b border-gray-200 bg-gray-50 px-3 py-2 text-xs font-semibold uppercase text-gray-500">
            <input
              type="checkbox"
              checked={allVisibleSelected}
              onChange={toggleAllVisible}
              className="h-4 w-4 rounded border-gray-300"
              title={t('actions.selectAllEvents')}
            />
            {t('connectors.openOperationEvents')}
          </div>
          <div className="divide-y divide-gray-100">
            {filteredEvents.map((event) => (
              <ConnectorOperationEventRow
                key={event.id}
                event={event}
                selected={selectedEventIds.has(event.id)}
                onToggleSelected={toggleSelected}
                onAck={onOperationEventAck}
                onNotify={onOperationEventNotify}
                onDetail={setDetailEvent}
              />
            ))}
            {filteredEvents.length === 0 && (
              <div className="px-3 py-5 text-center text-xs text-gray-400">{t('connectors.noOperationEvents')}</div>
            )}
          </div>
        </div>
        <div className="grid min-w-52 gap-2 self-start text-xs sm:grid-cols-2 xl:grid-cols-1">
          <button
            title={t('actions.monitorCredentialExpiry')}
            onClick={() => void onExpiryMonitor()}
            className="inline-flex items-center justify-center gap-2 rounded border border-gray-200 bg-white px-3 py-2 font-medium text-gray-700 hover:bg-gray-50"
          >
            <Clock className="h-4 w-4" />
            {t('actions.monitorCredentialExpiry')}
          </button>
          <button
            title={t('actions.configureExpiryMonitor')}
            onClick={() => void onExpiryMonitorConfigure()}
            className="inline-flex items-center justify-center gap-2 rounded border border-gray-200 bg-white px-3 py-2 font-medium text-gray-700 hover:bg-gray-50"
          >
            <SlidersHorizontal className="h-4 w-4" />
            {t('actions.configureExpiryMonitor')}
          </button>
          <button
            title={t('actions.bulkNotify')}
            disabled={bulkTargets.length === 0}
            onClick={() => void onBulkRemediation('notify', bulkTargets)}
            className="inline-flex items-center justify-center gap-2 rounded border border-amber-200 bg-amber-50 px-3 py-2 font-medium text-amber-800 hover:bg-amber-100 disabled:cursor-not-allowed disabled:border-gray-200 disabled:bg-gray-50 disabled:text-gray-300"
          >
            <Bell className="h-4 w-4" />
            {t('actions.bulkNotify')}
          </button>
          <button
            title={t('actions.bulkTest')}
            disabled={bulkTargets.length === 0}
            onClick={() => void onBulkRemediation('test', bulkTargets, 'preview')}
            className="inline-flex items-center justify-center gap-2 rounded border border-teal-200 bg-teal-50 px-3 py-2 font-medium text-teal-800 hover:bg-teal-100 disabled:cursor-not-allowed disabled:border-gray-200 disabled:bg-gray-50 disabled:text-gray-300"
          >
            <Activity className="h-4 w-4" />
            {t('actions.bulkTest')}
          </button>
          <button
            title={t('actions.bulkEnableSchedules')}
            disabled={bulkPausedTargets.length === 0}
            onClick={() => setPendingBulk({ action: 'enable_schedules', items: bulkPausedTargets, recoveryMode: 'enable' })}
            className="inline-flex items-center justify-center gap-2 rounded border border-emerald-200 bg-emerald-50 px-3 py-2 font-medium text-emerald-800 hover:bg-emerald-100 disabled:cursor-not-allowed disabled:border-gray-200 disabled:bg-gray-50 disabled:text-gray-300"
          >
            <Power className="h-4 w-4" />
            {t('actions.bulkEnableSchedules')}
          </button>
        </div>
      </div>
      {detailEvent && <ConnectorOperationEventDetailModal event={detailEvent} onClose={() => setDetailEvent(null)} />}
      {pendingBulk && (
        <BulkRecoveryConfirmModal
          action={pendingBulk.action}
          items={pendingBulk.items}
          onClose={() => setPendingBulk(null)}
          onConfirm={() => void confirmBulk()}
        />
      )}
    </div>
  );
}

function ConnectorOperationsDashboard({
  dashboard,
}: {
  dashboard?: SecurityConnectorPackageDiagnostics['operations_dashboard'] | null;
}) {
  const { t } = useTranslation('security');
  if (!dashboard) return null;

  const current = dashboard.current;
  const trend = dashboard.trend || [];
  const bulk = dashboard.bulk;
  const metricItems: Array<{
    key: string;
    label: string;
    value: string | number;
    detail: string;
    icon: LucideIcon;
    tone: string;
  }> = [
    {
      key: 'expiry',
      label: t('connectors.expiryRisks'),
      value: current.expiry_risks || 0,
      detail: `${t('connectors.expiredProfiles')}: ${current.expired_profiles || 0} · ${t('connectors.expiringProfiles')}: ${current.expiring_profiles || 0}`,
      icon: ShieldAlert,
      tone: 'border-amber-200 bg-amber-50 text-amber-900',
    },
    {
      key: 'blocked',
      label: t('connectors.blockedSyncRuns'),
      value: current.blocked_runs || 0,
      detail: `${t('connectors.openOperationEvents')}: ${current.open_events || 0}`,
      icon: AlertTriangle,
      tone: 'border-red-200 bg-red-50 text-red-900',
    },
    {
      key: 'paused',
      label: t('connectors.pausedSchedules'),
      value: current.policy_paused_schedules || 0,
      detail: t('connectors.policyPausedSyncSchedules'),
      icon: PowerOff,
      tone: 'border-slate-200 bg-slate-50 text-slate-900',
    },
    {
      key: 'mttr',
      label: t('connectors.averageRecoveryTime'),
      value: formatMetricDuration(dashboard.mttr?.seconds),
      detail: t('connectors.mttrSamples', { count: dashboard.mttr?.samples || 0 }),
      icon: Clock,
      tone: 'border-sky-200 bg-sky-50 text-sky-900',
    },
    {
      key: 'bulk',
      label: t('connectors.bulkSuccessRate'),
      value: formatRate(bulk.success_rate),
      detail: `${t('connectors.bulkRuns')}: ${bulk.runs || 0}`,
      icon: CheckCircle2,
      tone: 'border-emerald-200 bg-emerald-50 text-emerald-900',
    },
  ];
  const trendMax = Math.max(
    1,
    ...trend.map((bucket) =>
      Math.max(
        bucket.expiry_risks || 0,
        bucket.blocked_runs || 0,
        bucket.policy_paused_schedules || 0,
        bucket.recoveries || 0,
        bucket.bulk_failed || 0,
      ),
    ),
  );
  const actionRows = Object.entries(bulk.by_action || {}).sort(([left], [right]) => left.localeCompare(right));

  return (
    <div className="border-b border-gray-100 px-4 py-4">
      <div className="mb-3 flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="font-semibold text-gray-900">{t('connectors.operationsDashboard')}</div>
          <div className="text-xs text-gray-500">{t('connectors.operationsDashboardSubtitle')}</div>
        </div>
        <div className="font-mono text-[11px] text-gray-400">
          N={dashboard.expiry_warning_days} · {dashboard.checked_at}
        </div>
      </div>

      <div className="grid gap-2 md:grid-cols-5">
        {metricItems.map((item) => {
          const Icon = item.icon;
          return (
            <div key={item.key} className={`min-w-0 rounded border px-3 py-2 ${item.tone}`}>
              <div className="flex items-center gap-2 text-[11px] font-semibold uppercase">
                <Icon className="h-4 w-4 shrink-0" />
                <span className="truncate">{item.label}</span>
              </div>
              <div className="mt-2 font-mono text-2xl font-semibold leading-none">{item.value}</div>
              <div className="mt-2 truncate text-[11px] opacity-75" title={item.detail}>{item.detail}</div>
            </div>
          );
        })}
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0 rounded border border-gray-200">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-100 px-3 py-2">
            <div className="text-xs font-semibold uppercase text-gray-500">{t('connectors.healthTrend')}</div>
            <div className="flex flex-wrap gap-2 text-[11px] text-gray-500">
              <TrendLegend color="bg-amber-500" label={t('connectors.expiryRisks')} />
              <TrendLegend color="bg-red-500" label={t('connectors.blockedSyncRuns')} />
              <TrendLegend color="bg-slate-500" label={t('connectors.pausedSchedules')} />
              <TrendLegend color="bg-emerald-500" label={t('connectors.recoveries')} />
            </div>
          </div>
          <div className="flex gap-2 overflow-x-auto px-3 py-3">
            {trend.map((bucket) => (
              <div key={bucket.date} className="min-w-[64px] flex-1">
                <div className="flex h-20 items-end justify-center gap-1 rounded bg-gray-50 px-1 py-1">
                  <TrendBar value={bucket.expiry_risks || 0} max={trendMax} color="bg-amber-500" title={t('connectors.expiryRisks')} />
                  <TrendBar value={bucket.blocked_runs || 0} max={trendMax} color="bg-red-500" title={t('connectors.blockedSyncRuns')} />
                  <TrendBar value={bucket.policy_paused_schedules || 0} max={trendMax} color="bg-slate-500" title={t('connectors.pausedSchedules')} />
                  <TrendBar value={bucket.recoveries || 0} max={trendMax} color="bg-emerald-500" title={t('connectors.recoveries')} />
                </div>
                <div className="mt-1 truncate text-center font-mono text-[11px] text-gray-500">{bucket.date.slice(5)}</div>
                <div className="text-center font-mono text-[10px] text-gray-400">
                  {bucket.bulk_requested > 0 && `${t('connectors.bulkRequested')}:${bucket.bulk_requested}`}
                </div>
              </div>
            ))}
            {trend.length === 0 && <div className="py-8 text-center text-xs text-gray-400">{t('connectors.noTrendData')}</div>}
          </div>
        </div>

        <div className="rounded border border-gray-200">
          <div className="border-b border-gray-100 px-3 py-2 text-xs font-semibold uppercase text-gray-500">
            {t('connectors.bulkRemediationResults')}
          </div>
          <div className="space-y-3 px-3 py-3 text-xs">
            <div className="grid grid-cols-3 gap-2">
              <BulkMetric label={t('connectors.bulkRequested')} value={bulk.requested || 0} />
              <BulkMetric label={t('connectors.bulkSucceeded')} value={bulk.succeeded || 0} />
              <BulkMetric label={t('connectors.bulkFailed')} value={bulk.failed || 0} />
            </div>
            {bulk.latest_run && (
              <div className="rounded border border-gray-100 bg-gray-50 px-3 py-2">
                <div className="font-semibold text-gray-700">{t('connectors.latestBulkRun')}</div>
                <div className="mt-1 truncate font-mono text-[11px] text-gray-500" title={String(bulk.latest_run.id || '')}>
                  {t(`actions.${bulk.latest_run.action}`, { defaultValue: bulk.latest_run.action })} · {bulk.latest_run.created_at}
                </div>
                <div className="mt-1 text-[11px] text-gray-500">
                  {bulk.latest_run.succeeded}/{bulk.latest_run.requested} · {t('connectors.bulkFailed')} {bulk.latest_run.failed}
                </div>
              </div>
            )}
            <div className="space-y-1">
              {actionRows.map(([action, stats]) => (
                <div key={action} className="flex items-center justify-between gap-3 rounded border border-gray-100 px-2 py-1.5">
                  <span className="truncate text-gray-600">{t(`actions.${action}`, { defaultValue: action })}</span>
                  <span className="shrink-0 font-mono text-gray-800">
                    {formatRate(stats.success_rate)} · {stats.succeeded}/{stats.requested}
                  </span>
                </div>
              ))}
              {actionRows.length === 0 && <div className="py-2 text-center text-gray-400">{t('connectors.noBulkRuns')}</div>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function TrendLegend({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className={`h-2 w-2 rounded-full ${color}`} />
      {label}
    </span>
  );
}

function TrendBar({ value, max, color, title }: { value: number; max: number; color: string; title: string }) {
  const height = value > 0 ? Math.max(8, Math.round((value / Math.max(1, max)) * 72)) : 0;
  return (
    <div
      className={`w-2 rounded-sm ${color}`}
      style={{ height }}
      title={`${title}: ${value}`}
    />
  );
}

function BulkMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-gray-100 px-2 py-1.5">
      <div className="truncate text-[11px] text-gray-500">{label}</div>
      <div className="font-mono font-semibold text-gray-900">{value}</div>
    </div>
  );
}

function ConnectorOperationEventRow({
  event,
  selected,
  onToggleSelected,
  onAck,
  onNotify,
  onDetail,
}: {
  event: SecurityConnectorOperationEvent;
  selected: boolean;
  onToggleSelected: (eventId: string) => void;
  onAck: (eventId: string) => Promise<void>;
  onNotify: (eventId: string) => Promise<void>;
  onDetail: (event: SecurityConnectorOperationEvent) => void;
}) {
  const { t } = useTranslation('security');
  return (
    <div className="grid gap-2 px-3 py-2 text-xs md:grid-cols-[auto_minmax(0,1fr)_auto]">
      <input
        type="checkbox"
        checked={selected}
        onChange={() => onToggleSelected(event.id)}
        className="mt-1 h-4 w-4 rounded border-gray-300"
        title={t('actions.selectEvent')}
      />
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <StatusPill status={event.status} />
          <span className={`rounded-full px-2 py-1 text-[11px] font-medium ${badgeClass(event.severity)}`}>
            {t(`options.${event.severity}`, { defaultValue: event.severity })}
          </span>
          <span className="font-medium text-gray-900">{t(`options.${event.kind}`, { defaultValue: event.kind })}</span>
        </div>
        <div className="mt-1 truncate font-mono text-[11px] text-gray-500">
          {event.connector_id || '-'}{event.profile_id ? ` / ${event.profile_id}` : ''}
        </div>
        <div className="mt-1 line-clamp-2 text-[11px] text-gray-600" title={event.message}>{event.message || event.title}</div>
        <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-gray-400">
          {event.reason_code && <span>{event.reason_code}</span>}
          <span>{t('fields.seen_count')}: {event.seen_count}</span>
          <span>{event.last_seen_at}</span>
        </div>
      </div>
      <div className="flex items-start justify-end gap-1">
        <button
          title={t('actions.eventDetails')}
          onClick={() => onDetail(event)}
          className="rounded p-1.5 text-slate-700 hover:bg-slate-50"
        >
          <Eye className="h-4 w-4" />
        </button>
        <button
          title={t('actions.resendNotification')}
          onClick={() => void onNotify(event.id)}
          className="rounded p-1.5 text-amber-700 hover:bg-amber-50"
        >
          <Send className="h-4 w-4" />
        </button>
        <button
          title={t('actions.acknowledgeEvent')}
          disabled={event.status !== 'open'}
          onClick={() => void onAck(event.id)}
          className="rounded p-1.5 text-emerald-700 hover:bg-emerald-50 disabled:cursor-not-allowed disabled:text-gray-300"
        >
          <CheckCircle2 className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

function ConnectorOperationEventDetailModal({
  event,
  onClose,
}: {
  event: SecurityConnectorOperationEvent;
  onClose: () => void;
}) {
  const { t } = useTranslation('security');
  const actor = event.acknowledged_by || event.updated_by || event.created_by;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-lg bg-white shadow-xl">
        <div className="flex items-center justify-between border-b border-gray-200 px-5 py-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">{event.title || event.kind}</h2>
            <div className="mt-1 font-mono text-xs text-gray-500">{event.id}</div>
          </div>
          <button onClick={onClose} className="text-sm text-gray-500 hover:text-gray-900">{t('actions.close')}</button>
        </div>
        <div className="grid gap-3 p-5 text-xs md:grid-cols-2">
          <DetailField label={t('fields.kind')} value={t(`options.${event.kind}`, { defaultValue: event.kind })} />
          <DetailField label={t('fields.status')} value={t(`options.${event.status}`, { defaultValue: event.status })} />
          <DetailField label={t('fields.severity')} value={t(`options.${event.severity}`, { defaultValue: event.severity })} />
          <DetailField label={t('fields.reason_code')} value={event.reason_code || '-'} />
          <DetailField label={t('fields.connector')} value={event.connector_id || '-'} />
          <DetailField label={t('fields.profile')} value={event.profile_id || '-'} />
          <DetailField label={t('fields.schedule')} value={event.schedule_id || '-'} />
          <DetailField label={t('fields.run')} value={event.run_id || '-'} />
          <DetailField label={t('fields.created_at')} value={event.created_at} />
          <DetailField label={t('fields.last_seen_at')} value={event.last_seen_at} />
          <DetailField label={t('fields.acknowledged_at')} value={event.acknowledged_at || '-'} />
          <DetailField label={t('fields.actor')} value={actor?.username || actor?.id || '-'} />
        </div>
        <div className="border-t border-gray-100 p-5">
          <div className="mb-2 text-xs font-semibold uppercase text-gray-500">{t('fields.message')}</div>
          <div className="rounded border border-gray-200 bg-gray-50 p-3 text-sm text-gray-700">{event.message || event.title}</div>
        </div>
        <div className="grid gap-4 border-t border-gray-100 p-5 md:grid-cols-2">
          <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded border border-gray-200 bg-white p-3 text-xs text-gray-700">
            {JSON.stringify(event.metadata || {}, null, 2)}
          </pre>
          <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded border border-gray-200 bg-white p-3 text-xs text-gray-700">
            {JSON.stringify(event.notifications || [], null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
}

function BulkRecoveryConfirmModal({
  action,
  items,
  onClose,
  onConfirm,
}: {
  action: string;
  items: SecurityConnectorBulkRemediationItem[];
  onClose: () => void;
  onConfirm: () => void;
}) {
  const { t } = useTranslation('security');
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-xl rounded-lg bg-white shadow-xl">
        <div className="border-b border-gray-200 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-900">{t('confirm.recoveryTitle')}</h2>
          <div className="mt-1 text-sm text-gray-500">{t('confirm.recoveryMessage', { count: items.length })}</div>
        </div>
        <div className="max-h-64 overflow-y-auto p-5">
          <div className="rounded border border-gray-200">
            {items.map((item) => (
              <div key={`${item.connector_id}:${item.profile_id}`} className="flex justify-between gap-3 border-b border-gray-100 px-3 py-2 text-xs last:border-b-0">
                <span className="font-medium text-gray-900">{item.connector_id}</span>
                <span className="font-mono text-gray-500">{item.profile_id}</span>
              </div>
            ))}
          </div>
          <div className="mt-3 text-xs text-gray-500">{t(`actions.${action}`, { defaultValue: action })}</div>
        </div>
        <div className="flex justify-end gap-2 border-t border-gray-200 px-5 py-4">
          <button onClick={onClose} className="rounded-lg border border-gray-200 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50">{t('actions.cancel')}</button>
          <button onClick={onConfirm} className="rounded-lg bg-slate-900 px-4 py-2 text-sm text-white hover:bg-slate-800">{t('actions.confirm')}</button>
        </div>
      </div>
    </div>
  );
}

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded border border-gray-200 px-3 py-2">
      <div className="text-[11px] font-semibold uppercase text-gray-500">{label}</div>
      <div className="mt-1 truncate font-mono text-gray-800" title={value}>{value}</div>
    </div>
  );
}

function ConnectorRuntimeObservabilityPanel({
  diagnostics,
  onRunCancel,
  onDeadLetterReplay,
  onCredentialBind,
  onCredentialActivate,
  onCredentialTest,
  onCredentialRotate,
}: {
  diagnostics: SecurityConnectorPackageDiagnostics | null;
  onRunCancel: (runId: string) => Promise<void>;
  onDeadLetterReplay: (deadLetterId: string) => Promise<void>;
  onCredentialBind: (connectorId: string) => Promise<void>;
  onCredentialActivate: (connectorId: string, profileId: string) => Promise<void>;
  onCredentialTest: (connectorId: string, profileId: string) => Promise<void>;
  onCredentialRotate: (connectorId: string, profileId: string, currentExpiresAt?: string | null) => Promise<void>;
}) {
  const { t } = useTranslation('security');
  if (!diagnostics) return null;
  const onPolicyAction = handlePolicyAction({
    onCredentialBind,
    onCredentialActivate,
    onCredentialTest,
    onCredentialRotate,
  });
  const activeRuns = diagnostics.active_sync_runs || [];
  const recentRuns = diagnostics.sync_runs || [];
  const deadLetters = diagnostics.sync_dead_letters || [];
  const impactRuns = recentRuns.filter((run) => run.evidence_impact).slice(0, 5);
  const blockedRetention = diagnostics.sync_run_registry?.blocked_run_retention;
  const lastBlockedRun = diagnostics.sync_run_registry?.last_blocked_run;
  const summaryItems: Array<[string, number]> = [
    [t('connectors.activeRuns'), diagnostics.summary.active_sync_runs || activeRuns.length],
    [t('connectors.syncRuns'), diagnostics.summary.sync_runs || recentRuns.length],
    [t('connectors.blockedSyncRuns'), diagnostics.summary.blocked_sync_runs || 0],
    [t('connectors.pendingDeadLetters'), diagnostics.summary.pending_sync_dead_letters || 0],
    [t('connectors.replayedDeadLetters'), diagnostics.summary.replayed_sync_dead_letters || 0],
  ];

  return (
    <div className="rounded-lg border border-gray-200 bg-white">
      <div className="flex flex-col gap-3 border-b border-gray-200 px-4 py-3 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="font-semibold text-gray-900">{t('connectors.runtimeObservability')}</div>
          <div className="text-xs text-gray-500">{t('connectors.runtimeObservabilitySubtitle')}</div>
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs md:grid-cols-5">
          {summaryItems.map(([label, value]) => (
            <div key={label} className="min-w-24 rounded border border-gray-200 px-2 py-1">
              <div className="text-gray-500">{label}</div>
              <div className="font-mono font-semibold text-gray-900">{value}</div>
            </div>
          ))}
        </div>
      </div>

      {blockedRetention?.retained && Number(diagnostics.summary.blocked_sync_runs || 0) > 0 && (
        <div className="border-b border-amber-100 bg-amber-50 px-4 py-3 text-xs text-amber-800">
          <div className="font-semibold">{t('connectors.blockedRunRetention')}</div>
          <div className="mt-1">
            {t('connectors.blockedRunRetentionDescription')}
            {lastBlockedRun?.id && (
              <span className="ml-2 font-mono text-[11px] text-amber-900">
                {lastBlockedRun.id}
              </span>
            )}
          </div>
        </div>
      )}

      <div className="grid gap-4 p-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <div className="space-y-4">
          <RuntimeRunTable title={t('connectors.activeRuns')} runs={activeRuns} onRunCancel={onRunCancel} onPolicyAction={onPolicyAction} />
          <RuntimeRunTable title={t('connectors.recentRuns')} runs={recentRuns.slice(0, 6)} onRunCancel={onRunCancel} onPolicyAction={onPolicyAction} />
        </div>
        <div className="space-y-4">
          <DeadLetterReplayTable letters={deadLetters.slice(0, 6)} onDeadLetterReplay={onDeadLetterReplay} />
          <EvidenceImpactList runs={impactRuns} />
        </div>
      </div>
    </div>
  );
}

function ConnectorCredentialProfilesPanel({
  diagnostics,
  onActivate,
  onTest,
  onRotate,
  onDelete,
}: {
  diagnostics: SecurityConnectorPackageDiagnostics | null;
  onActivate: (connectorId: string, profileId: string) => Promise<void>;
  onTest: (connectorId: string, profileId: string) => Promise<void>;
  onRotate: (connectorId: string, profileId: string, currentExpiresAt?: string | null) => Promise<void>;
  onDelete: (connectorId: string, profileId: string) => Promise<void>;
}) {
  const { t } = useTranslation('security');
  if (!diagnostics) return null;
  const bindings = diagnostics.credential_bindings || [];
  const profiles = bindings.flatMap((binding) =>
    (binding.profiles || []).map((profile) => ({ binding, profile })),
  );
  const failed = profiles.filter(({ profile }) => profile.status === 'failed' || profile.status === 'expired').length;
  const active = profiles.filter(({ profile }) => profile.active).length;
  const summaryItems: Array<[string, number]> = [
    [t('connectors.credentialBindings'), bindings.length],
    [t('connectors.credentialProfiles'), profiles.length],
    [t('connectors.activeCredentialProfiles'), active],
    [t('connectors.failedCredentialProfiles'), failed],
  ];

  return (
    <div className="rounded-lg border border-gray-200 bg-white">
      <div className="flex flex-col gap-3 border-b border-gray-200 px-4 py-3 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="font-semibold text-gray-900">{t('connectors.credentialProfiles')}</div>
          <div className="text-xs text-gray-500">{t('connectors.credentialProfilesSubtitle')}</div>
        </div>
        <div className="grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
          {summaryItems.map(([label, value]) => (
            <div key={label} className="min-w-24 rounded border border-gray-200 px-2 py-1">
              <div className="text-gray-500">{label}</div>
              <div className="font-mono font-semibold text-gray-900">{value}</div>
            </div>
          ))}
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 text-xs">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.connector')}</th>
              <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.profile')}</th>
              <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.status')}</th>
              <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.env_keys')}</th>
              <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.rotation_count')}</th>
              <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.last_test')}</th>
              <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.last_sync')}</th>
              <th className="px-3 py-2 text-right font-semibold text-gray-600">{t('table.actions')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {profiles.map(({ binding, profile }) => (
              <CredentialProfileRow
                key={`${binding.connector_id}:${profile.id}`}
                connectorId={binding.connector_id}
                profile={profile}
                onActivate={onActivate}
                onTest={onTest}
                onRotate={onRotate}
                onDelete={onDelete}
              />
            ))}
            {profiles.length === 0 && (
              <tr>
                <td colSpan={8} className="px-3 py-6 text-center text-gray-400">{t('connectors.noCredentialProfiles')}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function CredentialProfileRow({
  connectorId,
  profile,
  onActivate,
  onTest,
  onRotate,
  onDelete,
}: {
  connectorId: string;
  profile: SecurityConnectorCredentialProfile;
  onActivate: (connectorId: string, profileId: string) => Promise<void>;
  onTest: (connectorId: string, profileId: string) => Promise<void>;
  onRotate: (connectorId: string, profileId: string, currentExpiresAt?: string | null) => Promise<void>;
  onDelete: (connectorId: string, profileId: string) => Promise<void>;
}) {
  const { t } = useTranslation('security');
  const failure = profile.last_failure_reason || profile.last_test_message;
  return (
    <tr className="align-top">
      <td className="px-3 py-2">
        <div className="font-medium text-gray-900">{connectorId}</div>
        {profile.active && <div className="mt-1 text-[11px] text-emerald-700">{t('fields.active_profile')}</div>}
      </td>
      <td className="px-3 py-2">
        <div className="font-medium text-gray-900">{profile.name || profile.id}</div>
        <div className="font-mono text-[11px] text-gray-500">{profile.id}</div>
        {profile.expires_at && <div className="mt-1 text-[11px] text-gray-400">{t('fields.expires_at')}: {profile.expires_at}</div>}
      </td>
      <td className="px-3 py-2">
        <StatusPill status={profile.status || (profile.active ? 'enabled' : 'untested')} />
        {failure && <div className="mt-1 max-w-48 truncate text-[11px] text-red-600" title={failure}>{failure}</div>}
      </td>
      <td className="px-3 py-2">
        <div className="max-w-56 truncate font-mono text-[11px] text-gray-600" title={(profile.env_keys || []).join(', ')}>
          {(profile.env_keys || []).join(', ') || '-'}
        </div>
      </td>
      <td className="px-3 py-2 font-mono text-gray-700">{profile.rotation_count || 0}</td>
      <td className="px-3 py-2 text-gray-600">
        {profile.last_test_status ? t(`options.${profile.last_test_status}`, { defaultValue: profile.last_test_status }) : '-'}
        {profile.last_test_at && <div className="mt-1 max-w-40 truncate text-[11px] text-gray-400">{profile.last_test_at}</div>}
      </td>
      <td className="px-3 py-2 text-gray-600">
        {profile.last_sync_run_id ? <span className="font-mono text-[11px]">{profile.last_sync_run_id}</span> : '-'}
        {profile.last_sync_at && <div className="mt-1 max-w-40 truncate text-[11px] text-gray-400">{profile.last_sync_at}</div>}
      </td>
      <td className="px-3 py-2">
        <div className="flex justify-end gap-1">
          <button
            title={t('actions.activateProfile')}
            disabled={profile.active}
            onClick={() => void onActivate(connectorId, profile.id)}
            className="rounded p-1.5 text-emerald-700 hover:bg-emerald-50 disabled:cursor-not-allowed disabled:text-gray-300"
          >
            <Power className="h-4 w-4" />
          </button>
          <button
            title={t('actions.testProfile')}
            onClick={() => void onTest(connectorId, profile.id)}
            className="rounded p-1.5 text-teal-700 hover:bg-teal-50"
          >
            <Activity className="h-4 w-4" />
          </button>
          <button
            title={t('actions.rotateCredentials')}
            onClick={() => void onRotate(connectorId, profile.id, profile.expires_at)}
            className="rounded p-1.5 text-indigo-700 hover:bg-indigo-50"
          >
            <RotateCcw className="h-4 w-4" />
          </button>
          <button
            title={t('actions.deleteProfile')}
            onClick={() => void onDelete(connectorId, profile.id)}
            className="rounded p-1.5 text-red-700 hover:bg-red-50"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      </td>
    </tr>
  );
}

function RuntimeRunTable({
  title,
  runs,
  onRunCancel,
  onPolicyAction,
}: {
  title: string;
  runs: SecurityConnectorPackageDiagnostics['sync_runs'];
  onRunCancel: (runId: string) => Promise<void>;
  onPolicyAction: (action: SecurityConnectorPolicyAction) => Promise<void>;
}) {
  const { t } = useTranslation('security');
  const items = runs || [];
  return (
    <div className="overflow-hidden rounded border border-gray-200">
      <div className="border-b border-gray-200 bg-gray-50 px-3 py-2 text-xs font-semibold uppercase text-gray-500">{title}</div>
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-100 text-xs">
          <thead className="bg-white">
            <tr>
              <th className="px-3 py-2 text-left font-semibold text-gray-500">{t('fields.run')}</th>
              <th className="px-3 py-2 text-left font-semibold text-gray-500">{t('fields.status')}</th>
              <th className="px-3 py-2 text-left font-semibold text-gray-500">{t('fields.io')}</th>
              <th className="px-3 py-2 text-left font-semibold text-gray-500">{t('fields.quality')}</th>
              <th className="px-3 py-2 text-left font-semibold text-gray-500">{t('fields.duration')}</th>
              <th className="px-3 py-2 text-right font-semibold text-gray-500">{t('table.actions')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {items.map((run) => {
              const canCancel = run.status === 'running' || run.run_control?.cancellable;
              const policyActions = run.run_policy?.actions || [];
              return (
                <tr key={run.id} className="align-top">
                  <td className="px-3 py-2">
                    <div className="font-medium text-gray-900">{run.connector_id}</div>
                    <div className="font-mono text-[11px] text-gray-500">{run.capability}</div>
                    <div className="font-mono text-[11px] text-gray-400">{run.id}</div>
                    {run.credential_profile_id && <div className="text-[11px] text-gray-400">{t('fields.profile')}: {run.credential_profile_id}</div>}
                    {run.package?.version && <div className="text-[11px] text-gray-400">{t('fields.version')}: {run.package.version}</div>}
                  </td>
                  <td className="px-3 py-2">
                    <StatusPill status={run.status} />
                    <div className="mt-1 text-[11px] text-gray-500">{t(`options.${run.trigger || 'manual'}`, { defaultValue: run.trigger || 'manual' })}</div>
                    {run.run_policy?.message && (
                      <div className="mt-1 max-w-52 truncate text-[11px] text-red-600" title={run.run_policy.message}>
                        {run.run_policy.message}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-gray-600">
                    <div>{t('fields.input')}: {sumRecord(run.input_counts)}</div>
                    <div>{t('fields.output')}: {sumRecord(run.counts)}</div>
                    {sumRecord(run.skipped_counts) > 0 && <div>{t('fields.skipped')}: {sumRecord(run.skipped_counts)}</div>}
                  </td>
                  <td className="px-3 py-2 text-gray-600">
                    {typeof run.quality?.score === 'number' ? run.quality.score : '-'}
                    {Number(run.dead_letter_count || 0) > 0 && <div className="text-red-600">{t('fields.dead_letters')}: {run.dead_letter_count}</div>}
                  </td>
                  <td className="px-3 py-2 text-gray-600">
                    {formatMilliseconds(run.duration_ms)}
                    <div className="mt-1 max-w-36 truncate text-[11px] text-gray-400">{run.started_at}</div>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex justify-end gap-1">
                      {policyActions.slice(0, 3).map((action) => (
                        <button
                          key={`${run.id}:${action.kind}`}
                          title={policyActionTitle(t, action)}
                          onClick={() => void onPolicyAction(action)}
                          className="rounded p-1.5 text-slate-700 hover:bg-slate-50"
                        >
                          <PolicyActionIcon action={action} />
                        </button>
                      ))}
                      <button
                        title={t('actions.cancelRun')}
                        disabled={!canCancel}
                        onClick={() => void onRunCancel(run.id)}
                        className="rounded p-1.5 text-red-700 hover:bg-red-50 disabled:cursor-not-allowed disabled:text-gray-300"
                      >
                        <XCircle className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {items.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-5 text-center text-gray-400">{t('table.noData')}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DeadLetterReplayTable({
  letters,
  onDeadLetterReplay,
}: {
  letters: SecurityConnectorPackageDiagnostics['sync_dead_letters'];
  onDeadLetterReplay: (deadLetterId: string) => Promise<void>;
}) {
  const { t } = useTranslation('security');
  const items = letters || [];
  return (
    <div className="overflow-hidden rounded border border-gray-200">
      <div className="border-b border-gray-200 bg-gray-50 px-3 py-2 text-xs font-semibold uppercase text-gray-500">{t('connectors.syncDeadLetters')}</div>
      <div className="divide-y divide-gray-100">
        {items.map((letter) => {
          const canReplay = letter.status !== 'replayed';
          return (
            <div key={letter.id} className="grid gap-2 px-3 py-2 text-xs md:grid-cols-[minmax(0,1fr)_auto]">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusPill status={letter.status} />
                  <span className="font-medium text-gray-900">{letter.connector_id}</span>
                  <span className="font-mono text-[11px] text-gray-500">{letter.target}[{letter.index}]</span>
                </div>
                <div className="mt-1 truncate font-mono text-[11px] text-gray-500">{letter.id}</div>
                <div className="mt-1 line-clamp-2 text-[11px] text-red-600">{(letter.last_replay_errors?.length ? letter.last_replay_errors : letter.errors).join(' | ')}</div>
                {letter.replayed_object_id && <div className="mt-1 truncate text-[11px] text-emerald-700">{t('fields.object')}: {letter.replayed_object_id}</div>}
              </div>
              <button
                title={t('actions.replayDeadLetter')}
                disabled={!canReplay}
                onClick={() => void onDeadLetterReplay(letter.id)}
                className="self-start rounded p-1.5 text-indigo-700 hover:bg-indigo-50 disabled:cursor-not-allowed disabled:text-gray-300"
              >
                <RotateCcw className="h-4 w-4" />
              </button>
            </div>
          );
        })}
        {items.length === 0 && <div className="px-3 py-5 text-center text-xs text-gray-400">{t('table.noData')}</div>}
      </div>
    </div>
  );
}

function EvidenceImpactList({ runs }: { runs: SecurityConnectorPackageDiagnostics['sync_runs'] }) {
  const { t } = useTranslation('security');
  const items = runs || [];
  return (
    <div className="rounded border border-gray-200">
      <div className="border-b border-gray-200 bg-gray-50 px-3 py-2 text-xs font-semibold uppercase text-gray-500">{t('connectors.evidenceImpact')}</div>
      <div className="divide-y divide-gray-100">
        {items.map((run) => {
          const impact = run.evidence_impact || {};
          const delta = impact.graph_delta || {};
          return (
            <div key={run.id} className="px-3 py-2 text-xs">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate font-medium text-gray-900">{run.connector_id} · {run.capability}</div>
                  <div className="truncate font-mono text-[11px] text-gray-500">{run.id}</div>
                </div>
                <StatusPill status={run.status} />
              </div>
              <div className="mt-2 grid grid-cols-3 gap-2 text-[11px] text-gray-600">
                <div>{t('fields.nodes')}: {signedNumber(delta.nodes)}</div>
                <div>{t('fields.edges')}: {signedNumber(delta.edges)}</div>
                <div>{t('fields.conflicts')}: {signedNumber(delta.conflicts)}</div>
              </div>
            </div>
          );
        })}
        {items.length === 0 && <div className="px-3 py-5 text-center text-xs text-gray-400">{t('table.noData')}</div>}
      </div>
    </div>
  );
}

function StatusPill({ status }: { status?: string | null }) {
  const { t } = useTranslation('security');
  const value = status || 'unknown';
  const tone = ['success', 'replayed', 'enabled', 'ok'].includes(value)
    ? 'bg-emerald-50 text-emerald-700'
    : ['error', 'invalid', 'replay_failed', 'canceled', 'failed', 'expired', 'blocked', 'policy_paused'].includes(value)
      ? 'bg-red-50 text-red-700'
      : ['running', 'busy'].includes(value)
        ? 'bg-cyan-50 text-cyan-700'
        : 'bg-amber-50 text-amber-700';
  return <span className={`inline-flex rounded-full px-2 py-1 text-[11px] font-medium ${tone}`}>{t(`options.${value}`, { defaultValue: value })}</span>;
}

function PolicyActionIcon({ action }: { action: SecurityConnectorPolicyAction }) {
  if (action.kind === 'test_profile') return <Activity className="h-4 w-4" />;
  if (action.kind === 'rotate_credentials') return <RotateCcw className="h-4 w-4" />;
  if (action.kind === 'activate_profile') return <Power className="h-4 w-4" />;
  if (action.kind === 'bind_credentials') return <KeyRound className="h-4 w-4" />;
  return <ShieldCheck className="h-4 w-4" />;
}

function ConnectorPackageDiagnosticsPanel({
  diagnostics,
  onInstall,
  onEnable,
  onDisable,
  onUninstall,
  onRollback,
  onUpload,
  onStagingValidate,
  onStagingInstall,
  onStagingDiscard,
}: {
  diagnostics: SecurityConnectorPackageDiagnostics | null;
  onInstall: (packageRoot: string) => Promise<void>;
  onEnable: (packageId: string) => Promise<void>;
  onDisable: (packageId: string) => Promise<void>;
  onUninstall: (packageId: string) => Promise<void>;
  onRollback: (packageId: string) => Promise<void>;
  onUpload: (file: File) => Promise<void>;
  onStagingValidate: (stagingId: string) => Promise<void>;
  onStagingInstall: (stagingId: string) => Promise<void>;
  onStagingDiscard: (stagingId: string) => Promise<void>;
}) {
  const { t } = useTranslation('security');
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  if (!diagnostics) return null;
  const stagingPackages = diagnostics.staging_packages || [];

  const summaryItems: Array<[string, number]> = [
    [t('connectors.packageRoots'), diagnostics.summary.roots],
    [t('connectors.packages'), diagnostics.summary.packages],
    [t('connectors.installedPackages'), diagnostics.summary.installed_packages || 0],
    [t('connectors.enabledPackages'), diagnostics.summary.enabled_packages || 0],
    [t('connectors.stagingPackages'), diagnostics.summary.staging_packages || 0],
    [t('connectors.validatedStagingPackages'), diagnostics.summary.validated_staging_packages || 0],
    [t('connectors.syncCursors'), diagnostics.summary.sync_cursors || 0],
    [t('connectors.syncDeadLetters'), diagnostics.summary.sync_dead_letters || 0],
    [t('connectors.syncSchedules'), diagnostics.summary.sync_schedules || 0],
    [t('connectors.enabledSyncSchedules'), diagnostics.summary.enabled_sync_schedules || 0],
    [t('connectors.dueSyncSchedules'), diagnostics.summary.due_sync_schedules || 0],
    [t('connectors.policyPausedSyncSchedules'), diagnostics.summary.policy_paused_sync_schedules || 0],
    [t('connectors.activePackages'), diagnostics.summary.active_packages],
    [t('connectors.invalidPackages'), diagnostics.summary.invalid_packages],
    [t('connectors.errors'), diagnostics.summary.errors],
    [t('connectors.warnings'), diagnostics.summary.warnings],
  ];

  return (
    <div className="rounded-lg border border-gray-200 bg-white">
      <div className="flex flex-col gap-2 border-b border-gray-200 px-4 py-3 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="font-semibold text-gray-900">{t('detail.packageDiagnostics')}</div>
          <div className="text-xs text-gray-500">{diagnostics.version} · {diagnostics.checked_at}</div>
        </div>
        <div className="flex flex-col gap-2 md:items-end">
          <div className="flex justify-end">
            <input
              ref={fileInputRef}
              type="file"
              accept=".zip,.tar.gz,.tgz,application/zip,application/gzip"
              className="hidden"
              onChange={(event) => {
                const file = event.target.files?.[0];
                event.target.value = '';
                if (file) void onUpload(file);
              }}
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-2 rounded bg-slate-900 px-3 py-2 text-xs font-medium text-white hover:bg-slate-800"
            >
              <UploadCloud className="h-4 w-4" />
              {t('actions.uploadPackage')}
            </button>
          </div>
        <div className="grid grid-cols-4 gap-2 text-xs md:grid-cols-6 xl:grid-cols-12">
          {summaryItems.map(([label, value]) => (
            <div key={label} className="min-w-20 rounded border border-gray-200 px-2 py-1">
              <div className="text-gray-500">{label}</div>
              <div className="font-mono font-semibold text-gray-900">{value}</div>
            </div>
          ))}
        </div>
        </div>
      </div>

      <div className="grid gap-4 p-4 xl:grid-cols-[360px_minmax(0,1fr)]">
        <div className="space-y-2">
          <div className="text-xs font-semibold uppercase text-gray-500">{t('connectors.packageRoots')}</div>
          <div className="space-y-2">
            {diagnostics.roots.map((root) => (
              <div key={`${root.source}:${root.root}`} className="rounded border border-gray-200 px-3 py-2 text-xs">
                <div className="flex items-center justify-between gap-3">
                  <span className="font-medium text-gray-900">{root.source}</span>
                  <span className={root.exists ? 'text-emerald-700' : 'text-gray-400'}>
                    {root.exists ? t('options.enabled') : t('options.disabled')}
                  </span>
                </div>
                <div className="mt-1 break-all font-mono text-gray-600">{root.root}</div>
                <div className="mt-1 text-gray-500">{t('connectors.manifestCount', { count: root.manifest_count })}</div>
              </div>
            ))}
          </div>
          <div className="pt-2">
            <div className="text-xs font-semibold uppercase text-gray-500">{t('connectors.staging')}</div>
            <div className="mt-2 space-y-2">
              {stagingPackages.map((record) => (
                <StagedPackageCard
                  key={record.id}
                  record={record}
                  onValidate={onStagingValidate}
                  onInstall={onStagingInstall}
                  onDiscard={onStagingDiscard}
                />
              ))}
              {stagingPackages.length === 0 && (
                <div className="rounded border border-dashed border-gray-200 px-3 py-4 text-xs text-gray-400">
                  {t('table.noData')}
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 text-sm">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.package')}</th>
                <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.source')}</th>
                <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.status')}</th>
                <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.installed_version')}</th>
                <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.release')}</th>
                <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.runtime_status')}</th>
                <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.last_validation')}</th>
                <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.capabilities')}</th>
                <th className="px-3 py-2 text-left font-semibold text-gray-600">{t('fields.diagnostics')}</th>
                <th className="px-3 py-2 text-right font-semibold text-gray-600">{t('table.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {diagnostics.packages.map((pkg) => (
                <tr key={`${pkg.source}:${pkg.manifest}`} className="align-top">
                  <td className="px-3 py-2">
                    <div className="font-medium text-gray-900">{pkg.name || pkg.id}</div>
                    <div className="font-mono text-xs text-gray-500">{pkg.id}</div>
                    <div className="mt-1 max-w-72 break-all font-mono text-[11px] text-gray-400">{pkg.manifest}</div>
                  </td>
                  <td className="px-3 py-2 text-gray-700">{pkg.source}</td>
                  <td className="px-3 py-2">
                    <PackageStatusBadge status={pkg.status} />
                  </td>
                  <td className="px-3 py-2">
                    <div className="text-gray-700">{pkg.installed_version || '-'}</div>
                    {pkg.installed_at && <div className="text-[11px] text-gray-400">{pkg.installed_at}</div>}
                  </td>
                  <td className="px-3 py-2">
                    <PackageReleaseSummary
                      release={pkg.release}
                      compatibility={pkg.compatibility}
                      version={pkg.package_version || pkg.version || pkg.installed_version || undefined}
                    />
                  </td>
                  <td className="px-3 py-2">
                    <RuntimeStatusBadge status={pkg.runtime_status} />
                  </td>
                  <td className="px-3 py-2">
                    <PackageValidationStatus pkg={pkg} />
                  </td>
                  <td className="px-3 py-2 text-gray-700">{pkg.capabilities.length}</td>
                  <td className="px-3 py-2">
                    <PackageDiagnosticDetails pkg={pkg} />
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex justify-end gap-1">
                      <button
                        title={t(pkg.installed ? 'actions.installed' : 'actions.installPackage')}
                        disabled={!pkg.valid || pkg.installed}
                        onClick={() => void onInstall(pkg.root)}
                        className="rounded p-1.5 text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:text-gray-300"
                      >
                        <Download className="h-4 w-4" />
                      </button>
                      <button
                        title={t('actions.enablePackage')}
                        disabled={!pkg.installed || pkg.enabled || !pkg.valid || ['installed_missing', 'stale_source'].includes(pkg.runtime_status || '')}
                        onClick={() => void onEnable(pkg.id)}
                        className="rounded p-1.5 text-emerald-700 hover:bg-emerald-50 disabled:cursor-not-allowed disabled:text-gray-300"
                      >
                        <Power className="h-4 w-4" />
                      </button>
                      <button
                        title={t('actions.rollbackPackage')}
                        disabled={!pkg.rollback_available}
                        onClick={() => void onRollback(pkg.id)}
                        className="rounded p-1.5 text-indigo-700 hover:bg-indigo-50 disabled:cursor-not-allowed disabled:text-gray-300"
                      >
                        <RotateCcw className="h-4 w-4" />
                      </button>
                      <button
                        title={t('actions.disablePackage')}
                        disabled={!pkg.installed || !pkg.enabled}
                        onClick={() => void onDisable(pkg.id)}
                        className="rounded p-1.5 text-amber-700 hover:bg-amber-50 disabled:cursor-not-allowed disabled:text-gray-300"
                      >
                        <PowerOff className="h-4 w-4" />
                      </button>
                      <button
                        title={t('actions.uninstallPackage')}
                        disabled={!pkg.installed}
                        onClick={() => void onUninstall(pkg.id)}
                        className="rounded p-1.5 text-red-700 hover:bg-red-50 disabled:cursor-not-allowed disabled:text-gray-300"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {diagnostics.packages.length === 0 && (
                <tr>
                  <td colSpan={10} className="px-3 py-8 text-center text-gray-500">{t('table.noData')}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function PackageReleaseSummary({
  release,
  compatibility,
  version,
}: {
  release?: Record<string, any>;
  compatibility?: Record<string, any>;
  version?: string | null;
}) {
  const { t } = useTranslation('security');
  const releaseData = release || {};
  const compatibilityData = compatibility || releaseData.compatibility || {};
  const notes = typeof releaseData.notes === 'string' ? releaseData.notes : '';
  const changelog = Array.isArray(releaseData.changelog) ? releaseData.changelog.map(String) : [];
  const generated = releaseData.generated_summary && typeof releaseData.generated_summary === 'object'
    ? releaseData.generated_summary
    : {};
  const transports = Array.isArray(generated.adapter_transports) ? generated.adapter_transports.map(String) : [];
  const targets = Array.isArray(generated.mapping_targets) ? generated.mapping_targets.map(String) : [];
  const hasCompatibility = Object.values(compatibilityData).some(
    (value) => value !== undefined && value !== null && value !== '',
  );

  if (!notes && !version && !hasCompatibility && transports.length === 0 && changelog.length === 0) {
    return <span className="text-xs text-gray-400">{t('detail.notAvailable')}</span>;
  }

  return (
    <div className="max-w-72 space-y-1 text-xs">
      <div className="flex flex-wrap items-center gap-1">
        <span className="rounded bg-gray-100 px-2 py-0.5 font-medium text-gray-700">
          {t(`options.${releaseData.channel || 'stable'}`, { defaultValue: releaseData.channel || 'stable' })}
        </span>
        {version && <span className="font-mono text-gray-500">{version}</span>}
      </div>
      {notes && <div className="break-words text-gray-700">{notes}</div>}
      {(changelog.length > 0 || hasCompatibility || transports.length > 0 || targets.length > 0) && (
        <details>
          <summary className="cursor-pointer font-medium text-gray-600">{t('fields.release_notes')}</summary>
          <div className="mt-1 space-y-1 text-[11px] text-gray-600">
            {releaseData.published_at && <div>{t('fields.created_at')}: <span className="font-mono">{String(releaseData.published_at)}</span></div>}
            {transports.length > 0 && <div>{t('fields.transports')}: <span className="font-mono">{transports.join(', ')}</span></div>}
            {targets.length > 0 && <div>{t('fields.mappings')}: <span className="font-mono">{targets.join(', ')}</span></div>}
            {hasCompatibility && (
              <div>
                <div className="font-medium text-gray-700">{t('fields.compatibility')}</div>
                <div className="font-mono">
                  {t('fields.min_flocks_version')}: {String(compatibilityData.min_flocks_version || '-')}
                  {compatibilityData.max_flocks_version ? ` / ${t('fields.max_flocks_version')}: ${compatibilityData.max_flocks_version}` : ''}
                </div>
                <div className="font-mono">
                  {[
                    compatibilityData.connector_package_contract,
                    compatibilityData.adapter_contract,
                    compatibilityData.mapping_contract,
                  ].filter(Boolean).join(' / ')}
                </div>
              </div>
            )}
            {changelog.length > 0 && (
              <ul className="list-disc space-y-0.5 pl-4">
                {changelog.map((item) => <li key={item} className="break-words">{item}</li>)}
              </ul>
            )}
          </div>
        </details>
      )}
    </div>
  );
}

function StagedPackageCard({
  record,
  onValidate,
  onInstall,
  onDiscard,
}: {
  record: SecurityConnectorPackageStagingRecord;
  onValidate: (stagingId: string) => Promise<void>;
  onInstall: (stagingId: string) => Promise<void>;
  onDiscard: (stagingId: string) => Promise<void>;
}) {
  const { t } = useTranslation('security');
  const diagnostics = [...(record.errors || []), ...(record.warnings || [])];
  const packageLabel = record.package_id || record.name || record.id;
  const version = record.package_version || record.version || '-';
  const canInstall = record.status === 'validated' && record.validation_result?.success !== false;
  const canValidate = record.status !== 'installed';

  return (
    <div className="rounded border border-gray-200 px-3 py-2 text-xs">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate font-medium text-gray-900">{record.filename}</div>
          <div className="mt-0.5 font-mono text-[11px] text-gray-500">{packageLabel}</div>
        </div>
        <StagingStatusBadge status={record.status} />
      </div>
      <div className="mt-2 grid grid-cols-2 gap-2 text-[11px] text-gray-600">
        <div>
          <div className="text-gray-400">{t('fields.version')}</div>
          <div className="font-mono">{version}</div>
        </div>
        <div>
          <div className="text-gray-400">{t('fields.size')}</div>
          <div className="font-mono">{formatBytes(record.artifact_size || 0)}</div>
        </div>
      </div>
      {record.validated_at && <div className="mt-1 text-[11px] text-gray-400">{record.validated_at}</div>}
      {record.package_root && <div className="mt-1 break-all font-mono text-[11px] text-gray-400">{record.package_root}</div>}
      {(record.release || record.compatibility) && (
        <div className="mt-2">
          <PackageReleaseSummary
            release={record.release}
            compatibility={record.compatibility}
            version={record.package_version || record.version || undefined}
          />
        </div>
      )}
      {diagnostics.length > 0 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-[11px] font-medium text-gray-700">
            {t('connectors.diagnosticCount', { count: diagnostics.length })}
          </summary>
          <ul className="mt-1 max-h-24 space-y-1 overflow-auto">
            {diagnostics.map((item) => (
              <li key={item} className="break-words font-mono text-[11px] text-gray-700">{item}</li>
            ))}
          </ul>
        </details>
      )}
      <div className="mt-2 flex justify-end gap-1">
        <button
          title={t('actions.validate')}
          disabled={!canValidate}
          onClick={() => void onValidate(record.id)}
          className="rounded p-1.5 text-blue-700 hover:bg-blue-50 disabled:cursor-not-allowed disabled:text-gray-300"
        >
          <CheckCircle2 className="h-4 w-4" />
        </button>
        <button
          title={t('actions.installPackage')}
          disabled={!canInstall}
          onClick={() => void onInstall(record.id)}
          className="rounded p-1.5 text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:text-gray-300"
        >
          <Download className="h-4 w-4" />
        </button>
        <button
          title={t('actions.discardStagedPackage')}
          onClick={() => void onDiscard(record.id)}
          className="rounded p-1.5 text-red-700 hover:bg-red-50"
        >
          <Trash2 className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

function StagingStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('security');
  const isOk = status === 'validated' || status === 'installed';
  const isError = status === 'invalid';
  const Icon = isOk ? CheckCircle2 : isError ? XCircle : AlertTriangle;
  const tone = isOk
    ? 'bg-emerald-50 text-emerald-700'
    : isError
      ? 'bg-red-50 text-red-700'
      : 'bg-amber-50 text-amber-700';
  return (
    <span className={`inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-1 text-[11px] font-medium ${tone}`}>
      <Icon className="h-3.5 w-3.5" />
      {t(`options.${status}`, { defaultValue: status })}
    </span>
  );
}

function ConnectorScheduleSummary({
  schedule,
  onPolicyAction,
}: {
  schedule?: NonNullable<SecurityConnectorPackageDiagnostics['sync_schedules']>[number];
  onPolicyAction?: (action: SecurityConnectorPolicyAction) => Promise<void>;
}) {
  const { t } = useTranslation('security');
  if (!schedule) return <span className="text-xs text-gray-400">{t('detail.notAvailable')}</span>;
  const isEnabled = schedule.enabled;
  const isRunning = schedule.runtime_status === 'running';
  const isPolicyPaused = schedule.runtime_status === 'policy_paused';
  const hasFailures = Number(schedule.consecutive_failures || 0) > 0;
  const policyActions = schedule.policy_actions || [];
  const tone = isRunning
    ? 'bg-cyan-50 text-cyan-700'
    : isPolicyPaused || hasFailures
      ? 'bg-red-50 text-red-700'
      : isEnabled
        ? 'bg-emerald-50 text-emerald-700'
        : 'bg-gray-50 text-gray-500';
  return (
    <div className="space-y-1">
      <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${tone}`}>
        {t(`options.${schedule.runtime_status || (isEnabled ? 'enabled' : 'disabled')}`, { defaultValue: schedule.runtime_status || (isEnabled ? 'enabled' : 'disabled') })}
      </span>
      <div className="text-[11px] text-gray-500">
        {t(`options.${schedule.mode}`, { defaultValue: schedule.mode })} · {formatDuration(schedule.interval_seconds || 0)}
      </div>
      {schedule.credential_profile_id && <div className="max-w-52 truncate text-[11px] text-gray-400">{t('fields.profile')}: {schedule.credential_profile_id}</div>}
      {schedule.next_run_at && <div className="max-w-52 truncate text-[11px] text-gray-400">{t('fields.next_run')}: {schedule.next_run_at}</div>}
      {schedule.policy_message && <div className="max-w-52 truncate text-[11px] text-red-600" title={schedule.policy_message}>{schedule.policy_message}</div>}
      {policyActions.length > 0 && onPolicyAction && (
        <div className="flex flex-wrap gap-1">
          {policyActions.slice(0, 3).map((action) => (
            <button
              key={`${schedule.id}:${action.kind}`}
              title={policyActionTitle(t, action)}
              onClick={() => void onPolicyAction(action)}
              className="rounded p-1 text-slate-700 hover:bg-slate-50"
            >
              <PolicyActionIcon action={action} />
            </button>
          ))}
        </div>
      )}
      {hasFailures && <div className="text-[11px] text-red-600">{t('fields.failures')} {schedule.consecutive_failures}</div>}
    </div>
  );
}

function ConnectorSyncSummary({
  run,
  cursor,
}: {
  run?: NonNullable<SecurityConnectorPackageDiagnostics['sync_runs']>[number];
  cursor?: NonNullable<SecurityConnectorPackageDiagnostics['sync_cursors']>[number];
}) {
  const { t } = useTranslation('security');
  if (!run && !cursor) return <span className="text-xs text-gray-400">{t('detail.notAvailable')}</span>;
  const count = Object.values(run?.counts || {}).reduce((total, value) => total + Number(value || 0), 0);
  const skipped = Object.values(run?.skipped_counts || {}).reduce((total, value) => total + Number(value || 0), 0);
  const isOk = run?.status === 'success';
  const isError = run?.status === 'error' || run?.status === 'blocked';
  const tone = isOk
    ? 'bg-emerald-50 text-emerald-700'
    : isError
      ? 'bg-red-50 text-red-700'
      : 'bg-amber-50 text-amber-700';
  return (
    <div className="space-y-1">
      {run && <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${tone}`}>
        {t(`options.${run.status}`, { defaultValue: run.status })} · {count}
      </span>}
      {run && (
        <div className="text-[11px] text-gray-500">
          {t(`options.${run.sync_mode || 'full'}`, { defaultValue: run.sync_mode || 'full' })}
          {run.credential_profile_id && <> · {t('fields.profile')} {run.credential_profile_id}</>}
          {typeof run.quality?.score === 'number' && <> · {t('fields.quality')} {run.quality.score}</>}
          {Number(run.dead_letter_count || 0) > 0 && <> · {t('fields.dead_letters')} {run.dead_letter_count}</>}
          {skipped > 0 && <> · {t('fields.skipped')} {skipped}</>}
        </div>
      )}
      {run?.run_policy?.message && <div className="max-w-52 truncate text-[11px] text-red-600" title={run.run_policy.message}>{run.run_policy.message}</div>}
      {cursor && <div className="max-w-52 truncate text-[11px] text-gray-400">{t('fields.cursor')}: {cursor.cursor}</div>}
      {run && <div className="text-[11px] text-gray-400">{run.started_at}</div>}
    </div>
  );
}

function formatDuration(seconds: number) {
  if (!Number.isFinite(seconds) || seconds <= 0) return '0s';
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

function formatMetricDuration(value?: number | null) {
  if (!Number.isFinite(Number(value))) return '-';
  const seconds = Math.max(0, Math.round(Number(value)));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainderSeconds = seconds % 60;
  if (minutes < 60) return remainderSeconds ? `${minutes}m ${remainderSeconds}s` : `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remainderMinutes = minutes % 60;
  return remainderMinutes ? `${hours}h ${remainderMinutes}m` : `${hours}h`;
}

function formatRate(value?: number | null) {
  if (!Number.isFinite(Number(value))) return '-';
  return `${Math.round(Number(value) * 1000) / 10}%`;
}

function formatMilliseconds(value?: number | null) {
  if (!Number.isFinite(Number(value)) || Number(value) <= 0) return '0ms';
  const ms = Number(value);
  if (ms >= 1000) return `${(ms / 1000).toFixed(ms >= 10000 ? 0 : 1)}s`;
  return `${Math.round(ms)}ms`;
}

function sumRecord(record?: Record<string, number> | null) {
  return Object.values(record || {}).reduce((total, value) => total + Number(value || 0), 0);
}

function signedNumber(value: any) {
  const num = Number(value || 0);
  return num > 0 ? `+${num}` : String(num);
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let amount = value;
  let unitIndex = 0;
  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }
  return `${amount >= 10 || unitIndex === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unitIndex]}`;
}

function PackageStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('security');
  const Icon = status === 'error' ? XCircle : status === 'warning' ? AlertTriangle : CheckCircle2;
  const tone = status === 'error'
    ? 'bg-red-50 text-red-700'
    : status === 'warning'
      ? 'bg-amber-50 text-amber-700'
      : 'bg-emerald-50 text-emerald-700';
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-medium ${tone}`}>
      <Icon className="h-3.5 w-3.5" />
      {t(`options.${status}`, { defaultValue: status })}
    </span>
  );
}

function RuntimeStatusBadge({ status }: { status?: string | null }) {
  const { t } = useTranslation('security');
  const value = status || 'unknown';
  const isEnabled = value === 'enabled';
  const isError = ['invalid', 'missing', 'installed_missing', 'stale_source', 'stale_hash', 'installed_elsewhere'].includes(value);
  const Icon = isEnabled ? CheckCircle2 : isError ? XCircle : PowerOff;
  const tone = isEnabled
    ? 'bg-emerald-50 text-emerald-700'
    : isError
      ? 'bg-red-50 text-red-700'
      : 'bg-gray-100 text-gray-600';
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-medium ${tone}`}>
      <Icon className="h-3.5 w-3.5" />
      {t(`options.${value}`, { defaultValue: value })}
    </span>
  );
}

function PackageValidationStatus({ pkg }: { pkg: SecurityConnectorPackageDiagnostics['packages'][number] }) {
  const { t } = useTranslation('security');
  const result = pkg.last_validation_result;
  if (!result) {
    return <span className="text-xs text-gray-400">{t('detail.notAvailable')}</span>;
  }
  const ok = result.success !== false && (result.status === 'ok' || result.success === true);
  return (
    <div className="space-y-1">
      <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${ok ? 'bg-emerald-50 text-emerald-700' : 'bg-red-50 text-red-700'}`}>
        {t(`options.${result.status || (ok ? 'ok' : 'error')}`, { defaultValue: result.status || (ok ? 'ok' : 'error') })}
      </span>
      {pkg.last_validation_at && <div className="text-[11px] text-gray-400">{pkg.last_validation_at}</div>}
    </div>
  );
}

function PackageDiagnosticDetails({ pkg }: { pkg: SecurityConnectorPackageDiagnostics['packages'][number] }) {
  const { t } = useTranslation('security');
  const diagnostics = [...(pkg.errors || []), ...(pkg.warnings || [])];
  if (!diagnostics.length) {
    return <span className="text-xs text-gray-400">{t('detail.notAvailable')}</span>;
  }
  return (
    <details>
      <summary className="cursor-pointer text-xs font-medium text-gray-700">
        {t('connectors.diagnosticCount', { count: diagnostics.length })}
      </summary>
      <ul className="mt-2 max-h-32 space-y-1 overflow-auto text-xs">
        {diagnostics.map((item) => (
          <li key={item} className="break-words font-mono text-gray-700">{item}</li>
        ))}
      </ul>
    </details>
  );
}

function ConnectorPreviewDiagnostics({ previewResult }: { previewResult: SecurityConnectorPreviewResult }) {
  const { t } = useTranslation('security');
  const mappingResult = previewResult.mapping_result && Object.keys(previewResult.mapping_result).length > 0
    ? previewResult.mapping_result
    : previewResult.normalized_data;
  const missingRequired = previewResult.missing_required_fields?.length
    ? previewResult.missing_required_fields
    : previewResult.missing_fields || [];

  return (
    <div className="space-y-4 p-4 text-sm text-blue-950">
      <div className="grid grid-cols-2 gap-3 text-xs md:grid-cols-5">
        <PreviewStat label={t('detail.previewSource')} value={previewResult.source} />
        <PreviewStat label={t('detail.previewCapability')} value={previewResult.capability} />
        <PreviewStat label={t('detail.adapterTransport')} value={String(previewResult.adapter_contract?.transport || '-')} />
        <PreviewStat label={t('detail.missingRequiredFields')} value={String(missingRequired.length)} />
        <PreviewStat label={t('detail.unmappedFields')} value={String(previewResult.unmapped_fields?.length || 0)} />
      </div>

      <DiagnosticList title={t('detail.missingRequiredFields')} items={missingRequired} tone="amber" />
      <DiagnosticList title={t('detail.transformWarnings')} items={previewResult.transform_warnings || []} tone="red" />
      <DiagnosticList title={t('detail.unmappedFields')} items={previewResult.unmapped_fields || []} tone="slate" />

      <JsonBlock title={t('detail.mappingResult')} value={mappingResult} defaultOpen />
      <JsonBlock title={t('detail.adapterContract')} value={previewResult.adapter_contract} />
      <JsonBlock title={t('detail.adapterRequest')} value={previewResult.adapter_request} />
      <JsonBlock title={t('detail.rawResponse')} value={previewResult.raw_response} />
      <JsonBlock title={t('detail.mappingContract')} value={previewResult.mapping_contract} />
      <JsonBlock title={t('detail.fullPayload')} value={previewResult} />
    </div>
  );
}

function PreviewStat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[11px] font-medium uppercase text-blue-700">{label}</div>
      <div className="mt-1 truncate font-mono text-xs text-blue-950" title={value}>{value}</div>
    </div>
  );
}

function DiagnosticList({ title, items, tone }: { title: string; items: string[]; tone: 'amber' | 'red' | 'slate' }) {
  if (!items.length) return null;
  const toneClass = tone === 'red'
    ? 'text-red-900'
    : tone === 'amber'
      ? 'text-amber-900'
      : 'text-slate-800';
  return (
    <div>
      <div className={`mb-2 text-xs font-semibold uppercase ${toneClass}`}>{title}</div>
      <ul className="max-h-28 space-y-1 overflow-auto text-xs">
        {items.map((item) => (
          <li key={item} className="font-mono">{item}</li>
        ))}
      </ul>
    </div>
  );
}

function JsonBlock({ title, value, defaultOpen = false }: { title: string; value: unknown; defaultOpen?: boolean }) {
  return (
    <details open={defaultOpen}>
      <summary className="cursor-pointer text-xs font-semibold uppercase text-blue-900">{title}</summary>
      <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded border border-blue-100 bg-white/70 p-3 text-xs text-blue-950">
        {JSON.stringify(value || {}, null, 2)}
      </pre>
    </details>
  );
}

function Dashboard({
  stats,
  alerts,
  incidents,
  onTriage,
}: {
  stats: Record<string, number>;
  alerts: SecurityAlert[];
  incidents: SecurityIncident[];
  onTriage: (alertId: string) => Promise<void>;
}) {
  const { t } = useTranslation('security');
  const formatOption = useCallback(
    (value: string) => t(`options.${value}`, { defaultValue: value }),
    [t],
  );
  const cards: Array<[string, number, LucideIcon]> = [
    ['dashboard.cards.assets', stats.assets, Database],
    ['dashboard.cards.vulnerabilities', stats.vulnerabilities, Bug],
    ['dashboard.cards.alerts', stats.alerts, Bell],
    ['dashboard.cards.incidents', stats.incidents, ShieldAlert],
    ['dashboard.cards.highAssets', stats.highAssets, ShieldCheck],
    ['dashboard.cards.highVulnerabilities', stats.highVulnerabilities, Bug],
    ['dashboard.cards.highAlerts', stats.highAlerts, Bell],
  ];

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3 xl:grid-cols-7">
        {cards.map(([labelKey, value, Icon]) => (
          <div key={labelKey} className="rounded-lg border border-gray-200 bg-white p-4">
            <Icon className="mb-3 h-5 w-5 text-slate-600" />
            <div className="text-2xl font-semibold text-gray-900">{String(value)}</div>
            <div className="mt-1 text-xs font-medium uppercase text-gray-500">{t(labelKey)}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-gray-200 bg-white">
          <div className="border-b border-gray-200 px-4 py-3 font-semibold text-gray-900">{t('dashboard.recentAlerts')}</div>
          <div className="divide-y divide-gray-100">
            {alerts.slice(0, 6).map((alert) => (
              <div key={alert.id} className="flex items-center justify-between gap-3 px-4 py-3">
                <div>
                  <div className="font-medium text-gray-900">{alert.title}</div>
                  <div className="text-xs text-gray-500">
                    {formatOption(alert.source)} · {formatOption(alert.status)} · {alert.mitre_technique || t('detail.notAvailable')}
                  </div>
                </div>
                <button onClick={() => void onTriage(alert.id)} className="inline-flex items-center gap-1 rounded-lg border border-purple-200 px-2 py-1 text-xs text-purple-700 hover:bg-purple-50">
                  <Brain className="h-3.5 w-3.5" /> {t('actions.aiTriageShort')}
                </button>
              </div>
            ))}
            {alerts.length === 0 && <div className="px-4 py-6 text-sm text-gray-500">{t('dashboard.noAlerts')}</div>}
          </div>
        </div>
        <div className="rounded-lg border border-gray-200 bg-white">
          <div className="border-b border-gray-200 px-4 py-3 font-semibold text-gray-900">{t('dashboard.recentIncidents')}</div>
          <div className="divide-y divide-gray-100">
            {incidents.slice(0, 6).map((incident) => (
              <div key={incident.id} className="px-4 py-3">
                <div className="font-medium text-gray-900">{incident.title}</div>
                <div className="text-xs text-gray-500">
                  {formatOption(incident.severity)} · {formatOption(incident.status)} · {formatOption(incident.confidence)}
                </div>
              </div>
            ))}
            {incidents.length === 0 && <div className="px-4 py-6 text-sm text-gray-500">{t('dashboard.noIncidents')}</div>}
          </div>
        </div>
      </div>
    </div>
  );
}

function EvidenceIngestionPanel({
  context,
  setContext,
  eventsJson,
  setEventsJson,
  options,
  setOptions,
  result,
  loading,
  onIngest,
}: {
  context: EvidenceIngestionContext;
  setContext: (value: EvidenceIngestionContext) => void;
  eventsJson: string;
  setEventsJson: (value: string) => void;
  options: { create_analysis_cases: boolean; run_initial_analysis: boolean; deduplicate: boolean };
  setOptions: (value: { create_analysis_cases: boolean; run_initial_analysis: boolean; deduplicate: boolean }) => void;
  result: EvidenceIngestionResponse | null;
  loading: boolean;
  onIngest: () => void;
}) {
  const contextFields: Array<keyof EvidenceIngestionContext> = ['connector_id', 'connector_name', 'vendor', 'product', 'source_type', 'external_base_url'];
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm text-blue-800">
        仅用于轻量证据接入测试。系统只保存摘要、关键字段、hash 和外部引用，不保存完整原始日志。
      </div>
      <div className="rounded-lg border border-gray-200 bg-white p-4">
        <h2 className="mb-3 text-lg font-semibold text-gray-900">证据接入 / Evidence Ingestion</h2>
        <div className="grid gap-3 md:grid-cols-3">
          {contextFields.map((field) => (
            <label key={field} className="text-sm text-gray-600">
              <span className="mb-1 block font-medium">{field}</span>
              <input
                value={context[field] || ''}
                onChange={(event) => setContext({ ...context, [field]: event.target.value })}
                className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm"
              />
            </label>
          ))}
        </div>
      </div>
      <div className="rounded-lg border border-gray-200 bg-white p-4">
        <h3 className="mb-2 font-semibold text-gray-900">Events JSON array</h3>
        <textarea value={eventsJson} onChange={(event) => setEventsJson(event.target.value)} className="h-72 w-full rounded-lg border border-gray-200 p-3 font-mono text-xs" />
        <div className="mt-3 flex flex-wrap items-center gap-4 text-sm text-gray-700">
          {(['create_analysis_cases', 'run_initial_analysis', 'deduplicate'] as const).map((key) => (
            <label key={key} className="inline-flex items-center gap-2">
              <input type="checkbox" checked={options[key]} onChange={(event) => setOptions({ ...options, [key]: event.target.checked })} />
              {key}
            </label>
          ))}
          <button onClick={onIngest} disabled={loading} className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-4 py-2 text-sm text-white hover:bg-slate-800 disabled:opacity-50">
            <UploadCloud className="h-4 w-4" /> {loading ? 'Ingesting…' : 'Ingest'}
          </button>
        </div>
      </div>
      {result && (
        <div className="rounded-lg border border-gray-200 bg-white p-4">
          <div className="mb-3 grid gap-3 text-sm md:grid-cols-3">
            <div className="rounded bg-gray-50 p-3"><div className="text-gray-500">created_alerts</div><div className="text-xl font-semibold">{result.created_alerts}</div></div>
            <div className="rounded bg-gray-50 p-3"><div className="text-gray-500">skipped_duplicates</div><div className="text-xl font-semibold">{result.skipped_duplicates}</div></div>
            <div className="rounded bg-gray-50 p-3"><div className="text-gray-500">created_analysis_cases</div><div className="text-xl font-semibold">{result.created_analysis_cases}</div></div>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 text-xs">
              <thead><tr>{['status', 'alert_id', 'analysis_case_id', 'external_event_id', 'payload_hash', 'title', 'source', 'severity', 'error'].map((header) => <th key={header} className="px-3 py-2 text-left font-semibold text-gray-600">{header}</th>)}</tr></thead>
              <tbody className="divide-y divide-gray-100">
                {result.items.map((item, index) => (
                  <tr key={`${item.payload_hash || item.external_event_id || index}`}>
                    <td className="px-3 py-2">{item.status}</td><td className="px-3 py-2">{item.alert_id || '-'}</td><td className="px-3 py-2">{item.analysis_case_id || '-'}</td><td className="px-3 py-2">{item.external_event_id || '-'}</td><td className="px-3 py-2 font-mono">{item.payload_hash || '-'}</td><td className="px-3 py-2">{item.title || '-'}</td><td className="px-3 py-2">{item.source || '-'}</td><td className="px-3 py-2">{item.severity || '-'}</td><td className="px-3 py-2 text-red-600">{item.error || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function DetailPanel({
  selected,
  triageResult,
  riskProfile,
  report,
  analysisCaseBrief,
  onViewAnalysisCaseBrief,
  onEscalateAnalysisCase,
  onRunInitialAnalysis,
  onCreateConfirmationRequest,
  onCreateAnalysisConfirmation,
  onAckAnalysisNotification,
}: {
  selected: Entity | null;
  triageResult: any;
  riskProfile: SecurityAssetRiskProfile | null;
  report: string;
  analysisCaseBrief: string;
  onViewAnalysisCaseBrief: (caseId: string) => void;
  onEscalateAnalysisCase: (caseId: string) => void;
  onRunInitialAnalysis: (caseId: string) => void;
  onCreateConfirmationRequest: (caseId: string) => void;
  onCreateAnalysisConfirmation: (caseId: string, confirmationType: string, decision: string) => void;
  onAckAnalysisNotification: (caseId: string, notificationId: string) => void;
}) {
  const { t } = useTranslation('security');
  const isAnalysisCase = Boolean(selected && 'case_status' in selected && 'facts' in selected && 'evidence_gaps' in selected);
  return (
    <>
      {isAnalysisCase && selected ? (
        <div className="space-y-4">
          <div className="rounded-lg border border-gray-200 bg-white">
            <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
              <div className="font-semibold text-gray-900">{selected.title}</div>
              <div className="flex gap-2">
                <button onClick={() => onRunInitialAnalysis(selected.id)} className="inline-flex items-center gap-2 rounded bg-purple-600 px-3 py-1.5 text-xs text-white hover:bg-purple-700">
                  <Brain className="h-4 w-4" /> {t('actions.runInitialAnalysis', { defaultValue: '运行初判 / Run Initial Analysis' })}
                </button>

                <button onClick={() => onCreateConfirmationRequest(selected.id)} className="inline-flex items-center gap-2 rounded bg-blue-600 px-3 py-1.5 text-xs text-white hover:bg-blue-700">
                  <Bell className="h-4 w-4" /> Create Confirmation Request
                </button>
                <button onClick={() => onViewAnalysisCaseBrief(selected.id)} className="inline-flex items-center gap-2 rounded bg-slate-700 px-3 py-1.5 text-xs text-white hover:bg-slate-800">
                  <FileText className="h-4 w-4" /> View Brief
                </button>
                <button onClick={() => onEscalateAnalysisCase(selected.id)} className="inline-flex items-center gap-2 rounded bg-red-600 px-3 py-1.5 text-xs text-white hover:bg-red-700">
                  <ShieldAlert className="h-4 w-4" /> {t('actions.escalateToIncident', { defaultValue: '升级为事件' })}
                </button>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2 p-4 text-xs">
              {['verdict', 'severity', 'confidence', 'notification_decision', 'incident_decision', 'evidence_coverage', 'disposition'].map((key) => (
                <div key={key} className="rounded border border-gray-200 px-3 py-2">
                  <div className="text-gray-500">{t(`fields.${key}`, { defaultValue: key })}</div>
                  <div className="font-medium text-gray-900">{renderValue(selected[key], (value) => t(`options.${value}`, { defaultValue: value }))}</div>
                </div>
              ))}
            </div>
            <div className="px-4 pb-4 text-xs text-amber-700">自动初判是 rule-based initial analysis，仅供研判参考，不是最终人工确认；不会自动升级 Incident 或执行自动处置。Evidence gaps: {((selected as AnalysisCase).evidence_gaps || []).length}</div>
            <div className="flex flex-wrap gap-2 px-4 pb-4 text-xs">
              <button onClick={() => onCreateAnalysisConfirmation(selected.id, 'confirm_blocked_attempt', 'confirmed')} className="rounded border border-green-200 px-2 py-1 text-green-700 hover:bg-green-50">Confirm Blocked Attempt</button>
              <button onClick={() => onCreateAnalysisConfirmation(selected.id, 'confirm_false_positive', 'confirmed')} className="rounded border border-gray-200 px-2 py-1 text-gray-700 hover:bg-gray-50">Confirm False Positive</button>
              <button onClick={() => onCreateAnalysisConfirmation(selected.id, 'confirm_benign', 'confirmed')} className="rounded border border-teal-200 px-2 py-1 text-teal-700 hover:bg-teal-50">Confirm Benign</button>
              <button onClick={() => onCreateAnalysisConfirmation(selected.id, 'continue_monitoring', 'monitoring')} className="rounded border border-blue-200 px-2 py-1 text-blue-700 hover:bg-blue-50">Continue Monitoring</button>
              <button onClick={() => onCreateAnalysisConfirmation(selected.id, 'request_more_evidence', 'needs_more_evidence')} className="rounded border border-amber-200 px-2 py-1 text-amber-700 hover:bg-amber-50">Request More Evidence</button>
              <button onClick={() => onCreateAnalysisConfirmation(selected.id, 'escalate_to_incident', 'escalated')} className="rounded border border-red-200 px-2 py-1 text-red-700 hover:bg-red-50">Mark for Incident Escalation</button>
            </div>

          </div>
          {analysisCaseBrief && (
            <div className="rounded-lg border border-blue-200 bg-white">
              <div className="flex items-center justify-between border-b border-blue-100 px-4 py-3 font-semibold text-blue-900">
                <span>Markdown Brief</span>
                <button onClick={() => void navigator.clipboard?.writeText(analysisCaseBrief)} className="rounded border border-blue-200 px-2 py-1 text-xs text-blue-700 hover:bg-blue-50">Copy</button>
              </div>
              <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words p-4 text-xs text-blue-950">{analysisCaseBrief}</pre>
            </div>
          )}
          <AnalysisCaseDetail caseItem={selected as AnalysisCase} onAckNotification={onAckAnalysisNotification} />
        </div>
      ) : (
        <div className="rounded-lg border border-gray-200 bg-white">
          <div className="border-b border-gray-200 px-4 py-3 font-semibold text-gray-900">{t('detail.title')}</div>
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words p-4 text-xs text-gray-700">
            {selected ? JSON.stringify(selected, null, 2) : t('detail.empty')}
          </pre>
        </div>
      )}
      {triageResult && (
        <div className="rounded-lg border border-purple-200 bg-purple-50">
          <div className="border-b border-purple-100 px-4 py-3 font-semibold text-purple-900">{t('detail.triageResult')}</div>
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words p-4 text-xs text-purple-950">
            {JSON.stringify(triageResult, null, 2)}
          </pre>
        </div>
      )}
      {riskProfile && (
        <div className="rounded-lg border border-teal-200 bg-teal-50">
          <div className="border-b border-teal-100 px-4 py-3 font-semibold text-teal-900">{t('detail.riskProfile')}</div>
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words p-4 text-xs text-teal-950">
            {JSON.stringify(riskProfile, null, 2)}
          </pre>
        </div>
      )}
      {report && (
        <div className="rounded-lg border border-blue-200 bg-white">
          <div className="border-b border-blue-100 px-4 py-3 font-semibold text-blue-900">{t('detail.incidentReport')}</div>
          <pre className="max-h-[480px] overflow-auto whitespace-pre-wrap break-words p-4 text-xs text-gray-800">
            {report}
          </pre>
        </div>
      )}
    </>
  );
}


function AnalysisCaseDetail({ caseItem, onAckNotification }: { caseItem: AnalysisCase; onAckNotification: (caseId: string, notificationId: string) => void }) {
  const rows = [
    ['primary_asset_id', caseItem.primary_asset_id],
    ['related_asset_ids', caseItem.related_asset_ids],
    ['related_alert_ids', caseItem.related_alert_ids],
    ['related_vulnerability_ids', caseItem.related_vulnerability_ids],
    ['related_incident_id', caseItem.related_incident_id],
  ];
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-gray-200 bg-white p-4 text-xs">
        <div className="mb-2 font-semibold text-gray-900">关联对象</div>
        {rows.map(([key, value]) => <div key={key as string} className="mb-1"><span className="text-gray-500">{key as string}: </span>{renderValue(value)}</div>)}
      </div>
      <AnalysisCaseArray title="Fact Ledger" items={caseItem.facts} keys={['fact_type', 'statement', 'source_ref', 'related_asset_id', 'related_alert_id', 'confidence', 'strength', 'supports', 'contradicts', 'limitations', 'observed_at']} />
      <AnalysisCaseArray title="Evidence Items" items={caseItem.evidence_items} keys={['title', 'description', 'source_ref', 'connector_id', 'external_event_id', 'external_url', 'query_hint', 'payload_hash', 'key_fields', 'related_fact_ids']} />
      <AnalysisCaseArray title="Evidence Gaps" items={caseItem.evidence_gaps} keys={['gap_type', 'description', 'missing_source_type', 'impact', 'suggested_connector_capability']} />
      <AnalysisCaseArray title="Notification Records" items={caseItem.notification_records || []} keys={['notification_type', 'channel', 'status', 'title', 'message', 'recipients', 'created_by', 'created_at', 'sent_at', 'acknowledged_at', 'related_fact_ids', 'related_evidence_gap_ids']} action={(item) => item.status !== 'acknowledged' ? <button onClick={() => onAckNotification(caseItem.id, item.id)} className="rounded border border-blue-200 px-2 py-1 text-blue-700 hover:bg-blue-50">Ack</button> : null} />
      <AnalysisCaseArray title="Confirmation Records" items={caseItem.confirmation_records || []} keys={['confirmation_type', 'decision', 'reviewer', 'reviewer_role', 'comment', 'related_notification_id', 'created_at']} />
      <AnalysisCaseArray title="Hypotheses" items={caseItem.hypotheses} keys={[]} />
      <AnalysisCaseArray title="Timeline" items={caseItem.timeline} keys={[]} />
      <div className="rounded-lg border border-gray-200 bg-white p-4 text-xs">
        <div className="mb-2 font-semibold text-gray-900">Recommendations</div>
        {(caseItem.recommendations || []).map((item) => <div key={item} className="mb-1">- {item}</div>)}
        {caseItem.recommendations.length === 0 && <div className="text-gray-400">-</div>}
      </div>
      <details className="rounded-lg border border-gray-200 bg-white p-4 text-xs" open>
        <summary className="cursor-pointer font-semibold text-gray-900">Raw JSON</summary>
        <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap break-words text-gray-700">{JSON.stringify(caseItem, null, 2)}</pre>
      </details>
    </div>
  );
}

function AnalysisCaseArray({ title, items, keys, action }: { title: string; items: Record<string, any>[]; keys: string[]; action?: (item: Record<string, any>) => ReactNode }) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 text-xs">
      <div className="mb-2 font-semibold text-gray-900">{title}</div>
      <div className="space-y-2">
        {items.map((item, index) => (
          <div key={item.id || index} className="rounded border border-gray-100 p-2">
            {action?.(item)}
            {(keys.length ? keys : Object.keys(item)).map((key) => (
              <div key={key} className="mb-1"><span className="text-gray-500">{key}: </span>{renderValue(item[key])}</div>
            ))}
          </div>
        ))}
        {items.length === 0 && <div className="text-gray-400">-</div>}
      </div>
    </div>
  );
}

function FormModal({
  title,
  fields,
  form,
  setForm,
  onClose,
  onSave,
}: {
  title: string;
  fields: FieldConfig[];
  form: Record<string, any>;
  setForm: (value: Record<string, any>) => void;
  onClose: () => void;
  onSave: () => void;
}) {
  const { t } = useTranslation('security');
  const update = (name: string, value: any) => setForm({ ...form, [name]: value });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-lg bg-white shadow-xl">
        <div className="flex items-center justify-between border-b border-gray-200 px-5 py-4">
          <h2 className="text-lg font-semibold text-gray-900">{title}</h2>
          <button onClick={onClose} className="text-sm text-gray-500 hover:text-gray-900">{t('actions.close')}</button>
        </div>
        <div className="grid grid-cols-1 gap-4 p-5 md:grid-cols-2">
          {fields.map((field) => (
            <label key={field.name} className={`text-sm ${field.type === 'textarea' || field.type === 'json' ? 'md:col-span-2' : ''}`}>
              <span className="mb-1 block font-medium text-gray-700">{t(field.labelKey)}</span>
              {field.type === 'textarea' || field.type === 'json' ? (
                <textarea
                  value={form[field.name] ?? ''}
                  onChange={(event) => update(field.name, event.target.value)}
                  rows={field.type === 'json' ? 6 : 4}
                  className="w-full rounded-lg border border-gray-200 px-3 py-2 font-mono text-sm"
                />
              ) : field.type === 'select' ? (
                <select
                  value={form[field.name] ?? ''}
                  onChange={(event) => update(field.name, event.target.value)}
                  className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm"
                >
                  {field.options?.map((option) => (
                    <option key={option} value={option}>{t(`options.${option}`, { defaultValue: option })}</option>
                  ))}
                </select>
              ) : field.type === 'checkbox' ? (
                <input
                  type="checkbox"
                  checked={Boolean(form[field.name])}
                  onChange={(event) => update(field.name, event.target.checked)}
                  className="h-5 w-5 rounded border-gray-300"
                />
              ) : (
                <input
                  type={field.type === 'number' ? 'number' : 'text'}
                  value={form[field.name] ?? ''}
                  onChange={(event) => update(field.name, event.target.value)}
                  className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm"
                />
              )}
            </label>
          ))}
        </div>
        <div className="flex justify-end gap-2 border-t border-gray-200 px-5 py-4">
          <button onClick={onClose} className="rounded-lg border border-gray-200 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50">{t('actions.cancel')}</button>
          <button onClick={onSave} className="rounded-lg bg-slate-900 px-4 py-2 text-sm text-white hover:bg-slate-800">{t('actions.save')}</button>
        </div>
      </div>
    </div>
  );
}
