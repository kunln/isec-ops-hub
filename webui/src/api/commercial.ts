import client from './client';

export type TelemetryMode = 'off' | 'basic' | 'support';
export type CommercialPackageType = 'agent' | 'tool' | 'skill' | 'workflow' | 'runtime';
export type PackageRiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface CommercialBranding {
  product_name: string;
  company_name: string;
  logo_light?: string | null;
  logo_dark?: string | null;
  favicon?: string | null;
  support_url?: string | null;
  copyright: string;
  login_title?: string | null;
  login_subtitle?: string | null;
}

export interface LicenseInfo {
  status: string;
  edition: string;
  licensed_to?: string | null;
  license_id?: string | null;
  expires_at?: string | null;
  features: string[];
  imported_at?: string | null;
  source: string;
  license_key_hash?: string | null;
  license_key_tail?: string | null;
  message?: string | null;
}

export interface CommercialFeatureFlag {
  id: string;
  label: string;
  enabled: boolean;
  source: string;
  required_features: string[];
  message?: string | null;
}

export interface CommercialFeatureState {
  license_status: string;
  edition: string;
  licensed_features: string[];
  flags: Record<string, CommercialFeatureFlag>;
}

export interface UpdatePolicy {
  update_check_enabled: boolean;
  update_apply_enabled: boolean;
  legacy_flocks_update_sources_enabled: boolean;
  update_channel: string;
  require_manual_approval: boolean;
  signature_required: boolean;
  update_server_url?: string | null;
  channel: string;
  auto_check: boolean;
  auto_install: boolean;
  manual_approval: boolean;
  offline_package_import: boolean;
  rollback_enabled: boolean;
  last_checked_at?: string | null;
}

export interface NotificationPolicy {
  local_notifications_enabled: boolean;
  built_in_notifications_enabled: boolean;
  benefit_notifications_enabled: boolean;
  whats_new_notifications_enabled: boolean;
  vendor_notifications_enabled: boolean;
  announcement_notifications_enabled: boolean;
}

export interface ConnectivityConfig {
  outbound_enabled: boolean;
  allowed_hosts: string[];
  proxy_url?: string | null;
  tls_verify: boolean;
  update_server_url?: string | null;
  telemetry_server_url?: string | null;
  license_server_url?: string | null;
}

export interface TelemetryConfig {
  enabled: boolean;
  mode: TelemetryMode;
  include_logs: boolean;
  include_metrics: boolean;
  include_security_data: boolean;
  redaction_enabled: boolean;
  last_upload_at?: string | null;
}

export interface PackagePermissionDeclaration {
  id: string;
  label?: string | null;
  description?: string | null;
  scope?: string | null;
  reason?: string | null;
  risk: PackageRiskLevel;
}

export interface PackageInstallOptions {
  permissions_acknowledged?: boolean;
  risk_acknowledged?: boolean;
  signature_policy_acknowledged?: boolean;
}

export interface CommercialPackageManifest {
  id: string;
  type: CommercialPackageType;
  name: string;
  version: string;
  description?: string | null;
  publisher?: string | null;
  compatible_runtime?: string | null;
  permissions: PackagePermissionDeclaration[];
  risk_level: PackageRiskLevel;
  risk_summary?: string | null;
  hash?: string | null;
  signature?: string | null;
  installed_at?: string | null;
  enabled: boolean;
  source: string;
  rollback_version?: string | null;
}

export interface CommercialDiagnostics {
  generated_at: string;
  storage_prefixes: string[];
  outbound_enabled: boolean;
  allowed_hosts: string[];
  telemetry_enabled: boolean;
  telemetry_mode: TelemetryMode;
  include_security_data: boolean;
  package_count: number;
  license_status: string;
  update_channel: string;
  warnings: string[];
}

export interface DiagnosticsExportResponse {
  filename: string;
  format: 'json';
  content: Record<string, any>;
}

export interface CommercialAuditEvent {
  id: string;
  action: string;
  target: string;
  status: 'success' | 'denied' | 'failed';
  actor_id?: string | null;
  actor_username?: string | null;
  actor_role?: string | null;
  request_ip?: string | null;
  user_agent?: string | null;
  summary?: string | null;
  metadata: Record<string, any>;
  created_at: string;
}

export interface CommercialAccessControl {
  role: string;
  capabilities: string[];
  matrix: Record<string, string[]>;
  routes: Record<string, string>;
  feature_flags?: CommercialFeatureState;
}

export const defaultBranding: CommercialBranding = {
  product_name: 'Flocks',
  company_name: 'Flocks Team',
  logo_light: null,
  logo_dark: null,
  favicon: null,
  support_url: null,
  copyright: 'Copyright Flocks Team',
  login_title: null,
  login_subtitle: null,
};

export const commercialAPI = {
  getBranding: () => client.get<CommercialBranding>('/api/commercial/branding'),
  getAccessControl: () => client.get<CommercialAccessControl>('/api/commercial/access-control'),
  updateBranding: (data: Partial<CommercialBranding>) =>
    client.patch<CommercialBranding>('/api/commercial/branding', data),

  getLicense: () => client.get<LicenseInfo>('/api/commercial/license'),
  getFeatureFlags: () => client.get<CommercialFeatureState>('/api/commercial/feature-flags'),
  importLicense: (data: { license_key?: string; manifest?: Record<string, any> }) =>
    client.post<LicenseInfo>('/api/commercial/license/import', data),

  getUpdatePolicy: () => client.get<UpdatePolicy>('/api/commercial/update-policy'),
  updateUpdatePolicy: (data: Partial<UpdatePolicy>) =>
    client.patch<UpdatePolicy>('/api/commercial/update-policy', data),

  getNotificationPolicy: () => client.get<NotificationPolicy>('/api/commercial/notification-policy'),
  updateNotificationPolicy: (data: Partial<NotificationPolicy>) =>
    client.patch<NotificationPolicy>('/api/commercial/notification-policy', data),

  getConnectivity: () => client.get<ConnectivityConfig>('/api/commercial/connectivity'),
  updateConnectivity: (data: Partial<ConnectivityConfig>) =>
    client.patch<ConnectivityConfig>('/api/commercial/connectivity', data),

  getTelemetry: () => client.get<TelemetryConfig>('/api/commercial/telemetry'),
  updateTelemetry: (data: Partial<TelemetryConfig>) =>
    client.patch<TelemetryConfig>('/api/commercial/telemetry', data),

  listPackages: () => client.get<CommercialPackageManifest[]>('/api/commercial/packages'),
  installPackage: (manifest: CommercialPackageManifest, options: PackageInstallOptions = {}) =>
    client.post<CommercialPackageManifest>('/api/commercial/packages/install', {
      manifest,
      permissions_acknowledged: options.permissions_acknowledged ?? false,
      risk_acknowledged: options.risk_acknowledged ?? false,
      signature_policy_acknowledged: options.signature_policy_acknowledged ?? false,
    }),
  rollbackPackage: (id: string) =>
    client.post<CommercialPackageManifest>('/api/commercial/packages/rollback', { id }),

  getDiagnostics: () => client.get<CommercialDiagnostics>('/api/commercial/diagnostics'),
  exportDiagnostics: () =>
    client.post<DiagnosticsExportResponse>('/api/commercial/diagnostics/export'),

  listAuditEvents: (limit = 100) =>
    client.get<CommercialAuditEvent[]>('/api/commercial/audit', { params: { limit } }),
};
