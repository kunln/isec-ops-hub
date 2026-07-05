import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useLocation } from 'react-router-dom';
import {
  BadgeCheck,
  Bell,
  Boxes,
  Building2,
  CloudOff,
  Download,
  FileJson,
  Gauge,
  Globe2,
  History,
  KeyRound,
  PackageCheck,
  RefreshCw,
  RotateCcw,
  Save,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  UploadCloud,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import PageHeader from '@/components/common/PageHeader';
import LoadingSpinner from '@/components/common/LoadingSpinner';
import {
  commercialAPI,
  defaultBranding,
  type CommercialBranding,
  type CommercialAuditEvent,
  type CommercialDiagnostics,
  type CommercialFeatureState,
  type CommercialPackageManifest,
  type CommercialPackageType,
  type ConnectivityConfig,
  type LicenseInfo,
  type NotificationPolicy,
  type PackagePermissionDeclaration,
  type PackageRiskLevel,
  type TelemetryConfig,
  type TelemetryMode,
  type UpdatePolicy,
} from '@/api/commercial';
import { setCachedCommercialBranding } from '@/hooks/useCommercialBranding';

type Section = 'overview' | 'branding' | 'license' | 'features' | 'update' | 'connectivity' | 'notifications' | 'telemetry' | 'packages' | 'diagnostics' | 'audit';

const defaultLicense: LicenseInfo = {
  status: 'unlicensed',
  edition: 'community',
  licensed_to: null,
  license_id: null,
  expires_at: null,
  features: [],
  imported_at: null,
  source: 'local',
  license_key_hash: null,
  license_key_tail: null,
  message: null,
};

const defaultUpdatePolicy: UpdatePolicy = {
  update_check_enabled: false,
  update_apply_enabled: false,
  legacy_flocks_update_sources_enabled: false,
  update_channel: 'stable',
  require_manual_approval: true,
  signature_required: true,
  update_server_url: null,
  channel: 'stable',
  auto_check: false,
  auto_install: false,
  manual_approval: true,
  offline_package_import: true,
  rollback_enabled: true,
  last_checked_at: null,
};

const defaultNotificationPolicy: NotificationPolicy = {
  local_notifications_enabled: true,
  built_in_notifications_enabled: false,
  benefit_notifications_enabled: false,
  whats_new_notifications_enabled: false,
  vendor_notifications_enabled: false,
  announcement_notifications_enabled: true,
};

const defaultConnectivity: ConnectivityConfig = {
  outbound_enabled: false,
  allowed_hosts: [],
  proxy_url: null,
  tls_verify: true,
  update_server_url: null,
  telemetry_server_url: null,
  license_server_url: null,
};

const defaultTelemetry: TelemetryConfig = {
  enabled: false,
  mode: 'off',
  include_logs: false,
  include_metrics: false,
  include_security_data: false,
  redaction_enabled: true,
  last_upload_at: null,
};

const defaultDiagnostics: CommercialDiagnostics = {
  generated_at: '',
  storage_prefixes: [],
  outbound_enabled: false,
  allowed_hosts: [],
  telemetry_enabled: false,
  telemetry_mode: 'off',
  include_security_data: false,
  package_count: 0,
  license_status: 'unlicensed',
  update_channel: 'stable',
  warnings: [],
};

const defaultFeatureState: CommercialFeatureState = {
  license_status: 'unlicensed',
  edition: 'community',
  licensed_features: [],
  flags: {},
};

const emptyPackageDraft: CommercialPackageManifest = {
  id: '',
  type: 'skill',
  name: '',
  version: '',
  description: '',
  publisher: '',
  compatible_runtime: '',
  permissions: [],
  risk_level: 'low',
  risk_summary: '',
  hash: '',
  signature: '',
  installed_at: null,
  enabled: true,
  source: 'local',
  rollback_version: null,
};

const navItems: Array<{ section: Section; href: string; icon: LucideIcon }> = [
  { section: 'overview', href: '/admin', icon: Gauge },
  { section: 'branding', href: '/admin/branding', icon: Building2 },
  { section: 'license', href: '/admin/license', icon: KeyRound },
  { section: 'features', href: '/admin/features', icon: ShieldCheck },
  { section: 'update', href: '/admin/update', icon: RefreshCw },
  { section: 'connectivity', href: '/admin/connectivity', icon: Globe2 },
  { section: 'notifications', href: '/admin/notifications', icon: Bell },
  { section: 'telemetry', href: '/admin/telemetry', icon: CloudOff },
  { section: 'packages', href: '/admin/packages', icon: Boxes },
  { section: 'diagnostics', href: '/admin/diagnostics', icon: FileJson },
  { section: 'audit', href: '/admin/audit', icon: History },
];

const inputClass = 'w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100';
const buttonClass = 'inline-flex items-center gap-2 rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60';
const secondaryButtonClass = 'inline-flex items-center gap-2 rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-60';

function sectionFromPath(pathname: string): Section {
  const part = pathname.split('/')[2] as Section | undefined;
  if (!part) return 'overview';
  return navItems.some((item) => item.section === part) ? part : 'overview';
}

function splitList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function joinList(value: string[]): string {
  return value.join('\n');
}

const packageRiskLevels: PackageRiskLevel[] = ['low', 'medium', 'high', 'critical'];
const riskRank: Record<PackageRiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function isPackageRiskLevel(value: string | undefined): value is PackageRiskLevel {
  return packageRiskLevels.includes(value as PackageRiskLevel);
}

function normalizePermission(permission: PackagePermissionDeclaration | string): PackagePermissionDeclaration {
  if (typeof permission === 'string') {
    return { id: permission, label: permission, risk: 'medium' };
  }
  return {
    ...permission,
    label: permission.label || permission.id,
    risk: permission.risk || 'low',
  };
}

function parsePermissions(value: string): PackagePermissionDeclaration[] {
  const lines = value.includes('\n') ? value.split('\n') : value.split(/[\n,]/);
  return lines
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [id, riskCandidate, scope, reason] = line.split('|').map((part) => part.trim());
      return {
        id,
        label: id,
        risk: isPackageRiskLevel(riskCandidate) ? riskCandidate : 'medium',
        scope: scope || null,
        reason: reason || null,
      };
    });
}

type Translate = (key: string, options?: any) => string;

function permissionSummary(t: Translate, permissions: Array<PackagePermissionDeclaration | string>): string {
  return permissions.map((permission) => {
    const normalized = normalizePermission(permission);
    return t('packages.permissionSummary', {
      label: normalized.label || normalized.id,
      risk: riskLabel(t, normalized.risk),
    });
  }).join(', ');
}

function typeBaseRisk(type: CommercialPackageType): PackageRiskLevel {
  if (type === 'tool' || type === 'runtime') return 'high';
  if (type === 'agent' || type === 'workflow') return 'medium';
  return 'low';
}

function maxRiskLevel(levels: PackageRiskLevel[]): PackageRiskLevel {
  return levels.reduce((max, item) => (riskRank[item] > riskRank[max] ? item : max), 'low');
}

function effectivePackageRisk(manifest: CommercialPackageManifest): PackageRiskLevel {
  return maxRiskLevel([
    manifest.risk_level || 'low',
    typeBaseRisk(manifest.type),
    ...manifest.permissions.map((permission) => normalizePermission(permission).risk),
  ]);
}

function formatDate(value?: string | null, locale = 'en-US'): string {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(locale);
}

function statusClass(value: boolean | string): string {
  if (value === true || value === 'imported' || value === 'active' || value === 'success') return 'bg-green-100 text-green-700';
  if (value === 'denied') return 'bg-amber-100 text-amber-700';
  if (value === 'failed') return 'bg-red-100 text-red-700';
  if (value === false || value === 'off' || value === 'unlicensed') return 'bg-gray-100 text-gray-700';
  return 'bg-blue-100 text-blue-700';
}

function riskClass(value: PackageRiskLevel): string {
  if (value === 'critical') return 'bg-red-100 text-red-700';
  if (value === 'high') return 'bg-amber-100 text-amber-800';
  if (value === 'medium') return 'bg-blue-100 text-blue-700';
  return 'bg-green-100 text-green-700';
}

const featureMessageKeys: Record<string, string> = {
  'Available without a commercial license.': 'availableWithoutLicense',
  'Enabled by the current commercial license.': 'enabledByLicense',
  'Disabled because the current license is inactive, expired, or missing.': 'disabledInactiveLicense',
  'Disabled because the current license does not include this feature.': 'disabledMissingFeature',
};

const featureLabelKeys: Record<string, string> = {
  'telemetry.security_data': 'telemetrySecurityData',
};

function statusLabel(t: Translate, value: boolean | string): string {
  if (value === true) return t('status.true');
  if (value === false) return t('status.false');
  return t(`status.${value}`, { defaultValue: value });
}

function riskLabel(t: Translate, value: PackageRiskLevel): string {
  return t(`risk.${value}`, { defaultValue: value });
}

function packageTypeLabel(t: Translate, value: CommercialPackageType): string {
  return t(`packageTypes.${value}`, { defaultValue: value });
}

function telemetryModeLabel(t: Translate, value: TelemetryMode): string {
  return t(`telemetryModes.${value}`, { defaultValue: value });
}

function featureLabel(t: Translate, value: string): string {
  return t(`features.${featureLabelKeys[value] || value}`, { defaultValue: value });
}

function apiErrorMessage(t: Translate, err: any): string {
  const detail = err?.response?.data?.detail || err?.response?.data?.message || err?.message;
  if (detail === 'Not Found') return t('errors.notFound');
  if (detail === 'Unauthorized' || detail === 'Not authenticated') return t('errors.unauthorized');
  if (detail === 'Forbidden') return t('errors.forbidden');
  return detail || t('errors.requestFailed');
}

function featureEnabled(featureState: CommercialFeatureState, featureID: string): boolean {
  return featureState.flags[featureID]?.enabled ?? false;
}

function featureMessage(t: Translate, featureState: CommercialFeatureState, featureID: string): string {
  const message = featureState.flags[featureID]?.message;
  const messageKey = message ? featureMessageKeys[message] : null;
  return (messageKey && t(`featureMessages.${messageKey}`)) || message || t('featureMessages.defaultDisabled');
}

function TextField({
  label,
  value,
  onChange,
  placeholder,
  required,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  required?: boolean;
  disabled?: boolean;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-gray-700">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        required={required}
        disabled={disabled}
        className={inputClass}
      />
    </label>
  );
}

function TextAreaField({
  label,
  value,
  onChange,
  rows = 4,
  placeholder,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  rows?: number;
  placeholder?: string;
  disabled?: boolean;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-gray-700">{label}</span>
      <textarea
        value={value}
        onChange={(event) => onChange(event.target.value)}
        rows={rows}
        placeholder={placeholder}
        disabled={disabled}
        className={`${inputClass} resize-y`}
      />
    </label>
  );
}

function ToggleField({
  label,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label className={`flex items-center justify-between gap-4 rounded-lg border border-gray-200 bg-white px-3 py-2 ${disabled ? 'opacity-60' : ''}`}>
      <span className="text-sm font-medium text-gray-700">{label}</span>
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        disabled={disabled}
        className="h-4 w-4 rounded border-gray-300 text-slate-900"
      />
    </label>
  );
}

function SelectField<T extends string>({
  label,
  value,
  options,
  onChange,
  disabled,
  formatOption,
}: {
  label: string;
  value: T;
  options: T[];
  onChange: (value: T) => void;
  disabled?: boolean;
  formatOption?: (value: T) => string;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-gray-700">{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value as T)} disabled={disabled} className={inputClass}>
        {options.map((option) => (
          <option key={option} value={option}>{formatOption ? formatOption(option) : option}</option>
        ))}
      </select>
    </label>
  );
}

function SaveButton({ saving, saved, disabled }: { saving: boolean; saved: boolean; disabled?: boolean }) {
  const { t } = useTranslation('adminConsole');

  return (
    <button type="submit" disabled={saving || disabled} className={buttonClass}>
      <Save className="h-4 w-4" />
      {saving ? t('actions.saving') : saved ? t('actions.saved') : t('actions.save')}
    </button>
  );
}

export default function AdminConsolePage() {
  const { t, i18n } = useTranslation('adminConsole');
  const location = useLocation();
  const section = sectionFromPath(location.pathname);
  const dateLocale = i18n.language?.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en-US';
  const [branding, setBranding] = useState<CommercialBranding>(defaultBranding);
  const [license, setLicense] = useState<LicenseInfo>(defaultLicense);
  const [updatePolicy, setUpdatePolicy] = useState<UpdatePolicy>(defaultUpdatePolicy);
  const [connectivity, setConnectivity] = useState<ConnectivityConfig>(defaultConnectivity);
  const [notificationPolicy, setNotificationPolicy] = useState<NotificationPolicy>(defaultNotificationPolicy);
  const [telemetry, setTelemetry] = useState<TelemetryConfig>(defaultTelemetry);
  const [packages, setPackages] = useState<CommercialPackageManifest[]>([]);
  const [diagnostics, setDiagnostics] = useState<CommercialDiagnostics>(defaultDiagnostics);
  const [featureState, setFeatureState] = useState<CommercialFeatureState>(defaultFeatureState);
  const [auditEvents, setAuditEvents] = useState<CommercialAuditEvent[]>([]);
  const [packageDraft, setPackageDraft] = useState<CommercialPackageManifest>(emptyPackageDraft);
  const [packagePermissionsText, setPackagePermissionsText] = useState('');
  const [licenseText, setLicenseText] = useState('');
  const [acknowledgePermissions, setAcknowledgePermissions] = useState(false);
  const [acknowledgeRisk, setAcknowledgeRisk] = useState(false);
  const [acknowledgeSignaturePolicy, setAcknowledgeSignaturePolicy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadWarning, setLoadWarning] = useState<string | null>(null);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    setLoadWarning(null);
    const failures: string[] = [];
    const captureLoadFailure = (label: string, err: any) => {
      failures.push(t('messages.loadFailureItem', { section: label, message: apiErrorMessage(t, err) }));
    };
    await Promise.all([
      commercialAPI.getBranding()
        .then((response) => {
          setBranding(response.data);
          setCachedCommercialBranding(response.data);
        })
        .catch((err) => captureLoadFailure(t('loadSections.branding'), err)),
      commercialAPI.getLicense()
        .then((response) => setLicense(response.data))
        .catch((err) => captureLoadFailure(t('loadSections.license'), err)),
      commercialAPI.getUpdatePolicy()
        .then((response) => setUpdatePolicy(response.data))
        .catch((err) => captureLoadFailure(t('loadSections.update'), err)),
      commercialAPI.getConnectivity()
        .then((response) => setConnectivity(response.data))
        .catch((err) => captureLoadFailure(t('loadSections.connectivity'), err)),
      commercialAPI.getNotificationPolicy()
        .then((response) => setNotificationPolicy(response.data))
        .catch((err) => captureLoadFailure(t('loadSections.notifications'), err)),
      commercialAPI.getTelemetry()
        .then((response) => setTelemetry(response.data))
        .catch((err) => captureLoadFailure(t('loadSections.telemetry'), err)),
      commercialAPI.listPackages()
        .then((response) => setPackages(response.data))
        .catch((err) => captureLoadFailure(t('loadSections.packages'), err)),
      commercialAPI.getDiagnostics()
        .then((response) => setDiagnostics(response.data))
        .catch((err) => captureLoadFailure(t('loadSections.diagnostics'), err)),
      commercialAPI.getFeatureFlags()
        .then((response) => setFeatureState(response.data))
        .catch((err) => captureLoadFailure(t('loadSections.features'), err)),
      commercialAPI.listAuditEvents()
        .then((response) => setAuditEvents(response.data))
        .catch((err) => captureLoadFailure(t('loadSections.audit'), err)),
    ]);
    if (failures.length > 0) {
      setLoadWarning(t('messages.partialLoadFailed', { details: failures.join(t('format.itemSeparator')) }));
    }
    setLoading(false);
  }, [t]);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const refreshDiagnostics = useCallback(async () => {
    const failures: string[] = [];
    const captureLoadFailure = (label: string, err: any) => {
      failures.push(t('messages.loadFailureItem', { section: label, message: apiErrorMessage(t, err) }));
    };
    await Promise.all([
      commercialAPI.getDiagnostics()
        .then((response) => setDiagnostics(response.data))
        .catch((err) => captureLoadFailure(t('loadSections.diagnostics'), err)),
      commercialAPI.getFeatureFlags()
        .then((response) => setFeatureState(response.data))
        .catch((err) => captureLoadFailure(t('loadSections.features'), err)),
      commercialAPI.listAuditEvents()
        .then((response) => setAuditEvents(response.data))
        .catch((err) => captureLoadFailure(t('loadSections.audit'), err)),
    ]);
    if (failures.length > 0) {
      setLoadWarning(t('messages.partialRefreshFailed', { details: failures.join(t('format.itemSeparator')) }));
    } else {
      setLoadWarning(null);
    }
  }, [t]);

  const runSave = useCallback(async (key: string, fn: () => Promise<void>) => {
    setSaving(key);
    setSaved(null);
    setError(null);
    try {
      await fn();
      setSaved(key);
      window.setTimeout(() => setSaved((current) => (current === key ? null : current)), 1600);
      await refreshDiagnostics();
    } catch (err: any) {
      setError(t('messages.saveFailed', { message: apiErrorMessage(t, err) }));
    } finally {
      setSaving(null);
    }
  }, [refreshDiagnostics, t]);

  const overviewStats = useMemo(() => [
    { label: t('overview.cards.license'), value: license.status, icon: KeyRound },
    { label: t('overview.cards.outbound'), value: connectivity.outbound_enabled ? 'enabled' : 'disabled', icon: Globe2 },
    { label: t('overview.cards.telemetry'), value: telemetry.enabled ? telemetry.mode : 'off', icon: CloudOff },
    { label: t('overview.cards.packages'), value: String(packages.length), icon: Boxes },
  ], [connectivity.outbound_enabled, license.status, packages.length, t, telemetry.enabled, telemetry.mode]);

  const featureFlags = useMemo(() => Object.values(featureState.flags), [featureState.flags]);
  const enabledFeatureCount = featureFlags.filter((flag) => flag.enabled).length;
  const brandingFeatureEnabled = featureEnabled(featureState, 'branding');
  const updatesFeatureEnabled = featureEnabled(featureState, 'updates');
  const connectivityFeatureEnabled = featureEnabled(featureState, 'connectivity');
  const telemetryFeatureEnabled = featureEnabled(featureState, 'telemetry');
  const packageFeatureEnabled = featureEnabled(featureState, 'packages');
  const diagnosticsFeatureEnabled = featureEnabled(featureState, 'diagnostics');

  const updatePackageDraft = (patch: Partial<CommercialPackageManifest>) => {
    setPackageDraft((prev) => ({ ...prev, ...patch }));
    if ('type' in patch || 'permissions' in patch || 'risk_level' in patch || 'signature' in patch || 'source' in patch) {
      setAcknowledgePermissions(false);
      setAcknowledgeRisk(false);
      setAcknowledgeSignaturePolicy(false);
    }
  };

  const packagePermissions = useMemo(
    () => packageDraft.permissions.map((permission) => normalizePermission(permission)),
    [packageDraft.permissions],
  );
  const packageEffectiveRisk = useMemo(() => effectivePackageRisk(packageDraft), [packageDraft]);
  const packageIsHighRisk = riskRank[packageEffectiveRisk] >= riskRank.high;
  const packageRequiresPermissionReview = packageDraft.type === 'tool' || packagePermissions.length > 0;
  const packageSourceIsLocal = ['local', 'offline', 'file'].includes((packageDraft.source || 'local').toLowerCase());
  const packagePreflightIssues = useMemo(() => {
    const issues: string[] = [];
    if (!packageFeatureEnabled) {
      issues.push(featureMessage(t, featureState, 'packages'));
    }
    if (packageSourceIsLocal && !updatePolicy.offline_package_import) {
      issues.push(t('packages.preflight.offlineImportDisabled'));
    }
    if (packageRequiresPermissionReview && !acknowledgePermissions) {
      issues.push(t('packages.preflight.permissionReviewRequired'));
    }
    if (packageIsHighRisk && !acknowledgeRisk) {
      issues.push(t('packages.preflight.highRiskReviewRequired'));
    }
    if (packageIsHighRisk && !packageDraft.hash?.trim()) {
      issues.push(t('packages.preflight.hashRequired'));
    }
    if (packageIsHighRisk && updatePolicy.signature_required && !packageDraft.signature?.trim()) {
      issues.push(t('packages.preflight.signatureRequired'));
    }
    if (
      packageIsHighRisk
      && !updatePolicy.signature_required
      && !packageDraft.signature?.trim()
      && !acknowledgeSignaturePolicy
    ) {
      issues.push(t('packages.preflight.unsignedHighRiskAcknowledgementRequired'));
    }
    return issues;
  }, [
    acknowledgePermissions,
    acknowledgeRisk,
    acknowledgeSignaturePolicy,
    packageDraft.hash,
    packageDraft.signature,
    packageFeatureEnabled,
    packageIsHighRisk,
    packageRequiresPermissionReview,
    packageSourceIsLocal,
    featureState,
    t,
    updatePolicy.offline_package_import,
    updatePolicy.signature_required,
  ]);
  const packageInstallBlocked = saving === 'packages' || packagePreflightIssues.length > 0;

  const installPackage = async (event: FormEvent) => {
    event.preventDefault();
    await runSave('packages', async () => {
      const response = await commercialAPI.installPackage(
        {
          ...packageDraft,
          risk_level: packageEffectiveRisk,
          permissions: packagePermissions,
        },
        {
          permissions_acknowledged: acknowledgePermissions,
          risk_acknowledged: acknowledgeRisk,
          signature_policy_acknowledged: acknowledgeSignaturePolicy,
        },
      );
      setPackages((prev) => {
        const rest = prev.filter((item) => item.id !== response.data.id);
        return [...rest, response.data].sort((a, b) => a.name.localeCompare(b.name));
      });
      setPackageDraft(emptyPackageDraft);
      setPackagePermissionsText('');
      setAcknowledgePermissions(false);
      setAcknowledgeRisk(false);
      setAcknowledgeSignaturePolicy(false);
    });
  };

  const rollbackPackage = async (id: string) => {
    await runSave('packages', async () => {
      const response = await commercialAPI.rollbackPackage(id);
      setPackages((prev) => prev.map((item) => (item.id === id ? response.data : item)));
    });
  };

  const exportDiagnostics = async () => {
    await runSave('diagnostics', async () => {
      const response = await commercialAPI.exportDiagnostics();
      const blob = new Blob([JSON.stringify(response.data.content, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = response.data.filename;
      anchor.click();
      window.URL.revokeObjectURL(url);
    });
  };

  const importLicense = async (event: FormEvent) => {
    event.preventDefault();
    await runSave('license', async () => {
      const trimmed = licenseText.trim();
      const response = await commercialAPI.importLicense({ license_key: trimmed });
      setLicense(response.data);
      setLicenseText('');
    });
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('title')}
        description={t('description', { productName: branding.product_name })}
        icon={<Settings2 className="h-8 w-8" />}
        action={(
          <button type="button" onClick={() => void loadAll()} className={secondaryButtonClass}>
            <RefreshCw className="h-4 w-4" />
            {t('actions.refresh')}
          </button>
        )}
      />

      {loadWarning && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
          {loadWarning}
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[220px_minmax(0,1fr)]">
        <aside className="rounded-lg border border-gray-200 bg-white p-2 shadow-sm">
          <nav className="space-y-1">
            {navItems.map((item) => {
              const active = item.section === section;
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium ${
                    active ? 'bg-slate-900 text-white' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                  }`}
                >
                  <item.icon className="h-4 w-4" />
                  <span className="truncate">{t(`nav.${item.section}`)}</span>
                </Link>
              );
            })}
          </nav>
        </aside>

        <section className="min-w-0">
          {section === 'overview' && (
            <div className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                {overviewStats.map((stat) => (
                  <div key={stat.label} className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-gray-500">{stat.label}</span>
                      <stat.icon className="h-5 w-5 text-gray-400" />
                    </div>
                    <div className="mt-4">
                      <span className={`inline-flex rounded-full px-2.5 py-1 text-sm font-semibold ${statusClass(stat.value)}`}>
                        {statusLabel(t, stat.value)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
              <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
                <h2 className="text-lg font-semibold text-gray-900">{t('overview.controlStatus')}</h2>
                <dl className="mt-4 grid gap-4 md:grid-cols-2">
                  <div>
                    <dt className="text-sm text-gray-500">{t('overview.updateChannel')}</dt>
                    <dd className="mt-1 text-sm font-medium text-gray-900">{statusLabel(t, updatePolicy.update_channel)}</dd>
                  </div>
                  <div>
                    <dt className="text-sm text-gray-500">{t('overview.allowedHostCount')}</dt>
                    <dd className="mt-1 text-sm font-medium text-gray-900">{connectivity.allowed_hosts.length || 0}</dd>
                  </div>
                  <div>
                    <dt className="text-sm text-gray-500">{t('overview.featureFlags')}</dt>
                    <dd className="mt-1 text-sm font-medium text-gray-900">
                      {t('overview.enabledFeatureCount', { enabled: enabledFeatureCount, total: featureFlags.length || 0 })}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-sm text-gray-500">{t('overview.signatureRequired')}</dt>
                    <dd className="mt-1 text-sm font-medium text-gray-900">{updatePolicy.signature_required ? t('values.yes') : t('values.no')}</dd>
                  </div>
                  <div>
                    <dt className="text-sm text-gray-500">{t('overview.securityTelemetry')}</dt>
                    <dd className="mt-1 text-sm font-medium text-gray-900">{telemetry.include_security_data ? t('values.included') : t('values.excluded')}</dd>
                  </div>
                </dl>
              </div>
            </div>
          )}

          {section === 'branding' && (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                if (!brandingFeatureEnabled) return;
                void runSave('branding', async () => {
                  const response = await commercialAPI.updateBranding(branding);
                  setBranding(response.data);
                  setCachedCommercialBranding(response.data);
                });
              }}
              className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm"
            >
              {!brandingFeatureEnabled && (
                <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
                  {featureMessage(t, featureState, 'branding')}
                </div>
              )}
              <div className="grid gap-4 md:grid-cols-2">
                <TextField label={t('fields.productName')} value={branding.product_name} onChange={(value) => setBranding({ ...branding, product_name: value })} required disabled={!brandingFeatureEnabled} />
                <TextField label={t('fields.companyName')} value={branding.company_name} onChange={(value) => setBranding({ ...branding, company_name: value })} required disabled={!brandingFeatureEnabled} />
                <TextField label={t('fields.logoLight')} value={branding.logo_light || ''} onChange={(value) => setBranding({ ...branding, logo_light: value || null })} disabled={!brandingFeatureEnabled} />
                <TextField label={t('fields.logoDark')} value={branding.logo_dark || ''} onChange={(value) => setBranding({ ...branding, logo_dark: value || null })} disabled={!brandingFeatureEnabled} />
                <TextField label={t('fields.favicon')} value={branding.favicon || ''} onChange={(value) => setBranding({ ...branding, favicon: value || null })} disabled={!brandingFeatureEnabled} />
                <TextField label={t('fields.supportUrl')} value={branding.support_url || ''} onChange={(value) => setBranding({ ...branding, support_url: value || null })} disabled={!brandingFeatureEnabled} />
                <TextField label={t('fields.loginTitle')} value={branding.login_title || ''} onChange={(value) => setBranding({ ...branding, login_title: value || null })} disabled={!brandingFeatureEnabled} />
                <TextField label={t('fields.loginSubtitle')} value={branding.login_subtitle || ''} onChange={(value) => setBranding({ ...branding, login_subtitle: value || null })} disabled={!brandingFeatureEnabled} />
                <div className="md:col-span-2">
                  <TextField label={t('fields.copyright')} value={branding.copyright || ''} onChange={(value) => setBranding({ ...branding, copyright: value })} disabled={!brandingFeatureEnabled} />
                </div>
              </div>
              <div className="mt-5 flex justify-end">
                <SaveButton saving={saving === 'branding'} saved={saved === 'branding'} disabled={!brandingFeatureEnabled} />
              </div>
            </form>
          )}

          {section === 'license' && (
            <div className="space-y-6">
              <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h2 className="text-lg font-semibold text-gray-900">{t('license.title')}</h2>
                    <p className="mt-1 text-sm text-gray-500">{statusLabel(t, license.edition)} / {statusLabel(t, license.status)}</p>
                  </div>
                  <BadgeCheck className="h-6 w-6 text-gray-400" />
                </div>
                <dl className="mt-4 grid gap-4 md:grid-cols-2">
                  <div><dt className="text-sm text-gray-500">{t('license.licensedTo')}</dt><dd className="mt-1 text-sm font-medium text-gray-900">{license.licensed_to || '-'}</dd></div>
                  <div><dt className="text-sm text-gray-500">{t('license.licenseId')}</dt><dd className="mt-1 text-sm font-medium text-gray-900">{license.license_id || '-'}</dd></div>
                  <div><dt className="text-sm text-gray-500">{t('license.expiresAt')}</dt><dd className="mt-1 text-sm font-medium text-gray-900">{license.expires_at || '-'}</dd></div>
                  <div><dt className="text-sm text-gray-500">{t('license.importedAt')}</dt><dd className="mt-1 text-sm font-medium text-gray-900">{formatDate(license.imported_at, dateLocale)}</dd></div>
                </dl>
                <div className="mt-4">
                  <div className="text-sm font-medium text-gray-700">{t('license.licensedFeatures')}</div>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {featureState.licensed_features.length === 0 ? (
                      <span className="text-sm text-gray-500">{t('license.noLicensedFeatures')}</span>
                    ) : featureState.licensed_features.map((feature) => (
                      <span key={feature} className="inline-flex rounded-full bg-blue-50 px-2.5 py-1 text-xs font-semibold text-blue-700">
                        {featureLabel(t, feature)}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
              <form onSubmit={importLicense} className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
                <TextAreaField label={t('license.importLabel')} value={licenseText} onChange={setLicenseText} rows={6} placeholder={t('license.importPlaceholder')} />
                <div className="mt-5 flex justify-end">
                  <button type="submit" disabled={saving === 'license' || !licenseText.trim()} className={buttonClass}>
                    <UploadCloud className="h-4 w-4" />
                    {saving === 'license' ? t('actions.importing') : saved === 'license' ? t('actions.imported') : t('actions.import')}
                  </button>
                </div>
              </form>
            </div>
          )}

          {section === 'features' && (
            <div className="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
              <div className="border-b border-gray-200 px-5 py-4">
                <h2 className="text-lg font-semibold text-gray-900">{t('featuresTable.title')}</h2>
                <p className="mt-1 text-sm text-gray-500">
                  {statusLabel(t, featureState.edition)} / {statusLabel(t, featureState.license_status)}
                </p>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200 text-sm">
                  <thead className="bg-gray-50 text-left text-xs font-semibold uppercase text-gray-500">
                    <tr>
                      <th className="px-4 py-3">{t('featuresTable.columns.capability')}</th>
                      <th className="px-4 py-3">{t('featuresTable.columns.requiredFeatures')}</th>
                      <th className="px-4 py-3">{t('featuresTable.columns.status')}</th>
                      <th className="px-4 py-3">{t('featuresTable.columns.source')}</th>
                      <th className="px-4 py-3">{t('featuresTable.columns.description')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {featureFlags.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-4 py-8 text-center text-gray-500">{t('featuresTable.empty')}</td>
                      </tr>
                    ) : featureFlags.map((flag) => (
                      <tr key={flag.id}>
                        <td className="px-4 py-3">
                          <div className="font-medium text-gray-900">{featureLabel(t, flag.id) || flag.label}</div>
                          <div className="text-xs text-gray-500">{flag.id}</div>
                        </td>
                        <td className="px-4 py-3 text-gray-700">{flag.required_features.length ? flag.required_features.map((feature) => featureLabel(t, feature)).join(', ') : '-'}</td>
                        <td className="px-4 py-3">
                          <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${statusClass(flag.enabled)}`}>
                            {statusLabel(t, flag.enabled)}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-gray-700">{statusLabel(t, flag.source)}</td>
                        <td className="px-4 py-3 text-gray-600">{flag.message ? featureMessage(t, featureState, flag.id) : '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {section === 'update' && (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void runSave('update', async () => {
                  const response = await commercialAPI.updateUpdatePolicy(updatePolicy);
                  setUpdatePolicy(response.data);
                });
              }}
              className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm"
            >
              {!updatesFeatureEnabled && (
                <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
                  {featureMessage(t, featureState, 'updates')}
                </div>
              )}
              <div className="grid gap-4 md:grid-cols-2">
                <TextField label={t('update.fields.updateServerUrl')} value={updatePolicy.update_server_url || ''} onChange={(value) => setUpdatePolicy({ ...updatePolicy, update_server_url: value || null })} />
                <TextField label={t('update.fields.updateChannel')} value={updatePolicy.update_channel} onChange={(value) => setUpdatePolicy({ ...updatePolicy, update_channel: value || 'stable', channel: value || 'stable' })} />
                <ToggleField label={t('update.fields.updateCheckEnabled')} checked={updatePolicy.update_check_enabled} onChange={(value) => setUpdatePolicy({ ...updatePolicy, update_check_enabled: value, auto_check: value })} />
                <ToggleField label={t('update.fields.updateApplyEnabled')} checked={updatePolicy.update_apply_enabled} onChange={(value) => setUpdatePolicy({ ...updatePolicy, update_apply_enabled: value, auto_install: value })} />
                <ToggleField label={t('update.fields.legacySourcesEnabled')} checked={updatePolicy.legacy_flocks_update_sources_enabled} onChange={(value) => setUpdatePolicy({ ...updatePolicy, legacy_flocks_update_sources_enabled: value })} />
                <ToggleField label={t('update.fields.requireManualApproval')} checked={updatePolicy.require_manual_approval} onChange={(value) => setUpdatePolicy({ ...updatePolicy, require_manual_approval: value, manual_approval: value })} />
                <ToggleField label={t('update.fields.offlinePackageImport')} checked={updatePolicy.offline_package_import} onChange={(value) => setUpdatePolicy({ ...updatePolicy, offline_package_import: value })} />
                <ToggleField label={t('update.fields.signatureRequired')} checked={updatePolicy.signature_required} onChange={(value) => setUpdatePolicy({ ...updatePolicy, signature_required: value })} />
                <ToggleField label={t('update.fields.rollbackEnabled')} checked={updatePolicy.rollback_enabled} onChange={(value) => setUpdatePolicy({ ...updatePolicy, rollback_enabled: value })} />
              </div>
              <div className="mt-5 flex justify-end">
                <SaveButton saving={saving === 'update'} saved={saved === 'update'} />
              </div>
            </form>
          )}

          {section === 'connectivity' && (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void runSave('connectivity', async () => {
                  const response = await commercialAPI.updateConnectivity(connectivity);
                  setConnectivity(response.data);
                });
              }}
              className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm"
            >
              {!connectivityFeatureEnabled && (
                <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
                  {featureMessage(t, featureState, 'connectivity')}
                </div>
              )}
              <div className="grid gap-4 md:grid-cols-2">
                <ToggleField label={t('connectivity.fields.outboundEnabled')} checked={connectivity.outbound_enabled} onChange={(value) => setConnectivity({ ...connectivity, outbound_enabled: value })} />
                <ToggleField label={t('connectivity.fields.tlsVerify')} checked={connectivity.tls_verify} onChange={(value) => setConnectivity({ ...connectivity, tls_verify: value })} />
                <TextField label={t('connectivity.fields.proxyUrl')} value={connectivity.proxy_url || ''} onChange={(value) => setConnectivity({ ...connectivity, proxy_url: value || null })} />
                <TextField label={t('connectivity.fields.updateServerUrl')} value={connectivity.update_server_url || ''} onChange={(value) => setConnectivity({ ...connectivity, update_server_url: value || null })} />
                <TextField label={t('connectivity.fields.telemetryServerUrl')} value={connectivity.telemetry_server_url || ''} onChange={(value) => setConnectivity({ ...connectivity, telemetry_server_url: value || null })} />
                <TextField label={t('connectivity.fields.licenseServerUrl')} value={connectivity.license_server_url || ''} onChange={(value) => setConnectivity({ ...connectivity, license_server_url: value || null })} />
                <div className="md:col-span-2">
                  <TextAreaField label={t('connectivity.fields.allowedHosts')} value={joinList(connectivity.allowed_hosts)} onChange={(value) => setConnectivity({ ...connectivity, allowed_hosts: splitList(value) })} />
                </div>
              </div>
              <div className="mt-5 flex justify-end">
                <SaveButton saving={saving === 'connectivity'} saved={saved === 'connectivity'} />
              </div>
            </form>
          )}

          {section === 'notifications' && (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void runSave('notifications', async () => {
                  const response = await commercialAPI.updateNotificationPolicy(notificationPolicy);
                  setNotificationPolicy(response.data);
                });
              }}
              className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm"
            >
              <div className="grid gap-4 md:grid-cols-2">
                <ToggleField label={t('notifications.fields.localNotificationsEnabled')} checked={notificationPolicy.local_notifications_enabled} onChange={(value) => setNotificationPolicy({ ...notificationPolicy, local_notifications_enabled: value })} />
                <ToggleField label={t('notifications.fields.builtInNotificationsEnabled')} checked={notificationPolicy.built_in_notifications_enabled} onChange={(value) => setNotificationPolicy({ ...notificationPolicy, built_in_notifications_enabled: value })} />
                <ToggleField label={t('notifications.fields.benefitNotificationsEnabled')} checked={notificationPolicy.benefit_notifications_enabled} onChange={(value) => setNotificationPolicy({ ...notificationPolicy, benefit_notifications_enabled: value })} />
                <ToggleField label={t('notifications.fields.whatsNewNotificationsEnabled')} checked={notificationPolicy.whats_new_notifications_enabled} onChange={(value) => setNotificationPolicy({ ...notificationPolicy, whats_new_notifications_enabled: value })} />
                <ToggleField label={t('notifications.fields.vendorNotificationsEnabled')} checked={notificationPolicy.vendor_notifications_enabled} onChange={(value) => setNotificationPolicy({ ...notificationPolicy, vendor_notifications_enabled: value })} />
                <ToggleField label={t('notifications.fields.announcementNotificationsEnabled')} checked={notificationPolicy.announcement_notifications_enabled} onChange={(value) => setNotificationPolicy({ ...notificationPolicy, announcement_notifications_enabled: value })} />
              </div>
              <div className="mt-5 flex justify-end">
                <SaveButton saving={saving === 'notifications'} saved={saved === 'notifications'} />
              </div>
            </form>
          )}

          {section === 'telemetry' && (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void runSave('telemetry', async () => {
                  const response = await commercialAPI.updateTelemetry(telemetry);
                  setTelemetry(response.data);
                });
              }}
              className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm"
            >
              {!telemetryFeatureEnabled && (
                <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
                  {featureMessage(t, featureState, 'telemetry')}
                </div>
              )}
              <div className="grid gap-4 md:grid-cols-2">
                <ToggleField label={t('telemetry.fields.enabled')} checked={telemetry.enabled} onChange={(value) => setTelemetry({ ...telemetry, enabled: value })} />
                <SelectField<TelemetryMode> label={t('telemetry.fields.mode')} value={telemetry.mode} options={['off', 'basic', 'support']} onChange={(value) => setTelemetry({ ...telemetry, mode: value })} formatOption={(value) => telemetryModeLabel(t, value)} />
                <ToggleField label={t('telemetry.fields.includeLogs')} checked={telemetry.include_logs} onChange={(value) => setTelemetry({ ...telemetry, include_logs: value })} />
                <ToggleField label={t('telemetry.fields.includeMetrics')} checked={telemetry.include_metrics} onChange={(value) => setTelemetry({ ...telemetry, include_metrics: value })} />
                <ToggleField label={t('telemetry.fields.includeSecurityData')} checked={telemetry.include_security_data} onChange={(value) => setTelemetry({ ...telemetry, include_security_data: value })} />
                <ToggleField label={t('telemetry.fields.redactionEnabled')} checked={telemetry.redaction_enabled} onChange={(value) => setTelemetry({ ...telemetry, redaction_enabled: value })} />
              </div>
              <div className="mt-5 flex justify-end">
                <SaveButton saving={saving === 'telemetry'} saved={saved === 'telemetry'} />
              </div>
            </form>
          )}

          {section === 'packages' && (
            <div className="space-y-6">
              <form onSubmit={installPackage} className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
                <h2 className="text-lg font-semibold text-gray-900">{t('packages.installTitle')}</h2>
                <div className="mt-4 grid gap-4 md:grid-cols-2">
                  <TextField label={t('packages.fields.id')} value={packageDraft.id} onChange={(value) => updatePackageDraft({ id: value })} required />
                  <SelectField<CommercialPackageType> label={t('packages.fields.type')} value={packageDraft.type} options={['agent', 'tool', 'skill', 'workflow', 'runtime']} onChange={(value) => updatePackageDraft({ type: value })} formatOption={(value) => packageTypeLabel(t, value)} />
                  <TextField label={t('packages.fields.name')} value={packageDraft.name} onChange={(value) => updatePackageDraft({ name: value })} required />
                  <TextField label={t('packages.fields.version')} value={packageDraft.version} onChange={(value) => updatePackageDraft({ version: value })} required />
                  <TextField label={t('packages.fields.publisher')} value={packageDraft.publisher || ''} onChange={(value) => updatePackageDraft({ publisher: value || null })} />
                  <TextField label={t('packages.fields.compatibleRuntime')} value={packageDraft.compatible_runtime || ''} onChange={(value) => updatePackageDraft({ compatible_runtime: value || null })} />
                  <TextField label={t('packages.fields.source')} value={packageDraft.source || 'local'} onChange={(value) => updatePackageDraft({ source: value || 'local' })} />
                  <SelectField<PackageRiskLevel> label={t('packages.fields.declaredRisk')} value={packageDraft.risk_level || 'low'} options={packageRiskLevels} onChange={(value) => updatePackageDraft({ risk_level: value })} formatOption={(value) => riskLabel(t, value)} />
                  <TextField label={t('packages.fields.hash')} value={packageDraft.hash || ''} onChange={(value) => updatePackageDraft({ hash: value || null })} />
                  <TextField label={t('packages.fields.signature')} value={packageDraft.signature || ''} onChange={(value) => updatePackageDraft({ signature: value || null })} />
                  <div className="md:col-span-2">
                    <TextAreaField
                      label={t('packages.fields.permissions')}
                      value={packagePermissionsText}
                      onChange={(value) => {
                        setPackagePermissionsText(value);
                        updatePackageDraft({ permissions: parsePermissions(value) });
                      }}
                      placeholder={t('packages.permissionsPlaceholder')}
                    />
                  </div>
                  <div className="md:col-span-2">
                    <TextAreaField label={t('packages.fields.riskSummary')} value={packageDraft.risk_summary || ''} onChange={(value) => updatePackageDraft({ risk_summary: value || null })} rows={3} />
                  </div>
                  <div className="md:col-span-2">
                    <TextAreaField label={t('packages.fields.description')} value={packageDraft.description || ''} onChange={(value) => updatePackageDraft({ description: value || null })} />
                  </div>
                </div>
                <div className={`mt-4 rounded-lg border p-4 ${
                  packageIsHighRisk ? 'border-amber-200 bg-amber-50' : 'border-gray-200 bg-gray-50'
                }`}>
                  <div className="flex items-start gap-3">
                    <ShieldAlert className={`mt-0.5 h-5 w-5 ${packageIsHighRisk ? 'text-amber-700' : 'text-gray-500'}`} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-sm font-semibold text-gray-900">{t('packages.preflight.title')}</h3>
                        <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${riskClass(packageEffectiveRisk)}`}>
                          {riskLabel(t, packageEffectiveRisk)}
                        </span>
                        <span className="inline-flex rounded-full bg-white px-2 py-0.5 text-xs font-medium text-gray-600">
                          {t('packages.preflight.signaturePolicy', {
                            requirement: updatePolicy.signature_required ? t('status.required') : t('status.optional'),
                          })}
                        </span>
                      </div>
                      <div className="mt-3 grid gap-3 text-sm md:grid-cols-3">
                        <div>
                          <div className="text-xs font-medium uppercase text-gray-500">{t('packages.preflight.baseRisk')}</div>
                          <div className="mt-1 text-gray-800">{riskLabel(t, typeBaseRisk(packageDraft.type))}</div>
                        </div>
                        <div>
                          <div className="text-xs font-medium uppercase text-gray-500">{t('packages.preflight.permissions')}</div>
                          <div className="mt-1 text-gray-800">{packagePermissions.length ? permissionSummary(t, packagePermissions) : t('values.notDeclared')}</div>
                        </div>
                        <div>
                          <div className="text-xs font-medium uppercase text-gray-500">{t('packages.preflight.integrity')}</div>
                          <div className="mt-1 text-gray-800">
                            {t('packages.preflight.integrityValue', {
                              hash: packageDraft.hash ? t('values.set') : t('values.missing'),
                              signature: packageDraft.signature ? t('values.set') : t('values.missing'),
                            })}
                          </div>
                        </div>
                      </div>
                      {packagePreflightIssues.length > 0 && (
                        <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-amber-900">
                          {packagePreflightIssues.map((issue) => (
                            <li key={issue}>{issue}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </div>
                  <div className="mt-4 space-y-2">
                    {packageRequiresPermissionReview && (
                      <label className="flex items-center gap-2 text-sm text-gray-800">
                        <input
                          type="checkbox"
                          checked={acknowledgePermissions}
                          onChange={(event) => setAcknowledgePermissions(event.target.checked)}
                          className="h-4 w-4 rounded border-gray-300"
                        />
                        <span>{t('packages.acknowledge.permissions')}</span>
                      </label>
                    )}
                    {packageIsHighRisk && (
                      <label className="flex items-center gap-2 text-sm text-gray-800">
                        <input
                          type="checkbox"
                          checked={acknowledgeRisk}
                          onChange={(event) => setAcknowledgeRisk(event.target.checked)}
                          className="h-4 w-4 rounded border-gray-300"
                        />
                        <span>{t('packages.acknowledge.risk')}</span>
                      </label>
                    )}
                    {packageIsHighRisk && !updatePolicy.signature_required && !packageDraft.signature?.trim() && (
                      <label className="flex items-center gap-2 text-sm text-gray-800">
                        <input
                          type="checkbox"
                          checked={acknowledgeSignaturePolicy}
                          onChange={(event) => setAcknowledgeSignaturePolicy(event.target.checked)}
                          className="h-4 w-4 rounded border-gray-300"
                        />
                        <span>{t('packages.acknowledge.signaturePolicy')}</span>
                      </label>
                    )}
                  </div>
                </div>
                {packageInstallBlocked && packagePreflightIssues.length > 0 && (
                  <div className="mt-3 rounded-lg border border-amber-200 bg-white px-3 py-2 text-sm text-amber-800">
                    {t('packages.preflight.blocked')}
                  </div>
                )}
                <div className="mt-5 flex justify-end">
                  <button type="submit" disabled={packageInstallBlocked} className={buttonClass}>
                    <PackageCheck className="h-4 w-4" />
                    {saving === 'packages' ? t('actions.installing') : t('actions.install')}
                  </button>
                </div>
              </form>

              <div className="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
                <div className="border-b border-gray-200 px-5 py-4">
                  <h2 className="text-lg font-semibold text-gray-900">{t('packages.listTitle')}</h2>
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 text-sm">
                    <thead className="bg-gray-50 text-left text-xs font-semibold uppercase text-gray-500">
                      <tr>
                        <th className="px-4 py-3">{t('packages.columns.name')}</th>
                        <th className="px-4 py-3">{t('packages.columns.type')}</th>
                        <th className="px-4 py-3">{t('packages.columns.version')}</th>
                        <th className="px-4 py-3">{t('packages.columns.risk')}</th>
                        <th className="px-4 py-3">{t('packages.columns.permissions')}</th>
                        <th className="px-4 py-3">{t('packages.columns.installedAt')}</th>
                        <th className="px-4 py-3 text-right">{t('packages.columns.actions')}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {packages.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="px-4 py-8 text-center text-gray-500">{t('packages.empty')}</td>
                        </tr>
                      ) : packages.map((item) => (
                        <tr key={item.id}>
                          <td className="px-4 py-3">
                            <div className="font-medium text-gray-900">{item.name}</div>
                            <div className="text-xs text-gray-500">{item.id}</div>
                          </td>
                          <td className="px-4 py-3">{packageTypeLabel(t, item.type)}</td>
                          <td className="px-4 py-3">{item.version}</td>
                          <td className="px-4 py-3">
                            <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${riskClass(item.risk_level || 'low')}`}>
                              {riskLabel(t, item.risk_level || 'low')}
                            </span>
                          </td>
                          <td className="px-4 py-3">{item.permissions.length ? permissionSummary(t, item.permissions) : '-'}</td>
                          <td className="px-4 py-3">{formatDate(item.installed_at, dateLocale)}</td>
                          <td className="px-4 py-3 text-right">
                            <button
                              type="button"
                              disabled={!item.rollback_version || saving === 'packages'}
                              onClick={() => void rollbackPackage(item.id)}
                              className={secondaryButtonClass}
                            >
                              <RotateCcw className="h-4 w-4" />
                              {t('actions.rollback')}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {section === 'diagnostics' && (
            <div className="space-y-6">
              <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <h2 className="text-lg font-semibold text-gray-900">{t('diagnostics.title')}</h2>
                    <p className="mt-1 text-sm text-gray-500">
                      {t('diagnostics.generatedAt', { time: formatDate(diagnostics.generated_at, dateLocale) })}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <button type="button" onClick={() => void refreshDiagnostics()} className={secondaryButtonClass}>
                      <RefreshCw className="h-4 w-4" />
                      {t('actions.refresh')}
                    </button>
                    <button type="button" onClick={() => void exportDiagnostics()} disabled={!diagnosticsFeatureEnabled} className={buttonClass}>
                      <Download className="h-4 w-4" />
                      {t('actions.export')}
                    </button>
                  </div>
                </div>
                {!diagnosticsFeatureEnabled && (
                  <div className="mt-4 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                    {featureMessage(t, featureState, 'diagnostics')}
                  </div>
                )}
                {diagnostics.warnings.length > 0 && (
                  <div className="mt-4 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                    {diagnostics.warnings.join(', ')}
                  </div>
                )}
                <pre className="mt-4 max-h-[560px] overflow-auto rounded-lg bg-slate-950 p-4 text-xs text-slate-100">
                  {JSON.stringify(diagnostics, null, 2)}
                </pre>
              </div>
            </div>
          )}

          {section === 'audit' && (
            <div className="overflow-hidden rounded-lg border border-gray-200 bg-white shadow-sm">
              <div className="flex items-center justify-between gap-4 border-b border-gray-200 px-5 py-4">
                <div>
                  <h2 className="text-lg font-semibold text-gray-900">{t('audit.title')}</h2>
                  <p className="mt-1 text-sm text-gray-500">{t('audit.description')}</p>
                </div>
                <button type="button" onClick={() => void refreshDiagnostics()} className={secondaryButtonClass}>
                  <RefreshCw className="h-4 w-4" />
                  {t('actions.refresh')}
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200 text-sm">
                  <thead className="bg-gray-50 text-left text-xs font-semibold uppercase text-gray-500">
                    <tr>
                      <th className="px-4 py-3">{t('audit.columns.time')}</th>
                      <th className="px-4 py-3">{t('audit.columns.actor')}</th>
                      <th className="px-4 py-3">{t('audit.columns.action')}</th>
                      <th className="px-4 py-3">{t('audit.columns.target')}</th>
                      <th className="px-4 py-3">{t('audit.columns.status')}</th>
                      <th className="px-4 py-3">{t('audit.columns.summary')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {auditEvents.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="px-4 py-8 text-center text-gray-500">{t('audit.empty')}</td>
                      </tr>
                    ) : auditEvents.map((event) => (
                      <tr key={event.id}>
                        <td className="whitespace-nowrap px-4 py-3 text-gray-600">{formatDate(event.created_at, dateLocale)}</td>
                        <td className="px-4 py-3">
                          <div className="font-medium text-gray-900">{event.actor_username || '-'}</div>
                          <div className="text-xs text-gray-500">{event.actor_role || '-'}</div>
                        </td>
                        <td className="px-4 py-3 font-medium text-gray-900">{event.action}</td>
                        <td className="px-4 py-3 text-gray-600">{event.target}</td>
                        <td className="px-4 py-3">
                          <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${statusClass(event.status)}`}>
                            {statusLabel(t, event.status)}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="text-gray-700">{event.summary || '-'}</div>
                          {Object.keys(event.metadata || {}).length > 0 && (
                            <details className="mt-1 text-xs text-gray-500">
                              <summary className="cursor-pointer">{t('audit.metadata')}</summary>
                              <pre className="mt-2 max-w-xl overflow-auto rounded bg-gray-50 p-2">
                                {JSON.stringify(event.metadata, null, 2)}
                              </pre>
                            </details>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      </div>

      <div className="rounded-lg border border-gray-200 bg-white p-4 text-sm text-gray-600 shadow-sm">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-gray-400" />
          <span>
            {t('footer.summary', {
              outbound: connectivity.outbound_enabled ? t('status.enabled') : t('status.disabled'),
              telemetry: telemetry.include_security_data ? t('values.included') : t('values.excluded'),
            })}
          </span>
        </div>
      </div>
    </div>
  );
}
