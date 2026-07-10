import { useState, useEffect, useCallback, useMemo, useRef, type ReactNode } from 'react';
import {
  Shield, CheckCircle, XCircle, AlertTriangle, RefreshCw,
  Plug, PlugZap, WifiOff, Plus, Settings, Loader2,
  Eye, EyeOff, Save, Trash2, Activity, X, Server, Pencil, Check,
  Wrench, ChevronRight, ChevronLeft, Database, KeyRound, PauseCircle,
  PlayCircle, Clock, BarChart3,
} from 'lucide-react';
import PageHeader from '@/components/common/PageHeader';
import LoadingSpinner from '@/components/common/LoadingSpinner';
import { useToast } from '@/components/common/Toast';
import { useConfirm } from '@/components/common/ConfirmDialog';
import { providerAPI } from '@/api/provider';
import { deviceAPI, type DeviceIntegration, type DeviceGroup } from '@/api/device';
import { mcpAPI } from '@/api/mcp';
import {
  securityAPI,
  type SecurityConnectorCustomerDataSource,
  type SecurityConnectorCustomerEvent,
  type SecurityConnectorCustomerSchedule,
  type SecurityConnectorCustomerSummary,
  type IntegrationPackageSummary,
  type IntegrationCapabilityPlanResponse,
  type SyncEnginePlanResult,
  type ManualSyncPreviewResult,
  type IntegrationInstance,
  type CredentialProfile,
  type SyncProfile,
  type IntegrationRun,
} from '@/api/security';
import type { APIServiceSummary, APIServiceCredentialField, Tool, MCPCatalogEntry } from '@/types';
import { toolAPI } from '@/api/tool';
import ToolDetailModal from '../Tool/components/ToolDetailModal';

// ============================================================================
// Vendor catalog
//
// Vendor identity comes from the backend: each `_provider.yaml` declares a
// `vendor` field that propagates into `APIServiceSummary.vendor`. The frontend
// only owns the *presentation* (Chinese/English labels and color theme). When
// a brand-new vendor key appears (i.e. one not in `VENDOR_PRESENTATION` below),
// we still render it with a generic neutral label so the device is never
// silently misclassified — see `vendorPresentation` for the fallback path.
// ============================================================================

interface DeviceVendor {
  id: string;
  nameCn: string;
  nameEn: string;
  color: string;
}

type IntegrationKind = 'device' | 'mcp';

type IntegrationTemplate = APIServiceSummary & {
  integration_kind: IntegrationKind;
  mcp_entry?: MCPCatalogEntry;
};

type McpConnectionStatus = 'connected' | 'disconnected' | 'error' | 'connecting' | 'failed' | 'needs_auth' | 'disabled';

interface McpStatusSummary {
  status: McpConnectionStatus;
  error?: string;
  connected_at?: number;
  tools_count?: number;
  resources_count?: number;
  metadata?: Record<string, any>;
}

interface ConfiguredMcpIntegration {
  id: string;
  template: IntegrationTemplate & { mcp_entry: MCPCatalogEntry };
  status: McpStatusSummary;
}

type CustomerIntegrationKind = 'device' | 'mcp' | 'sync';

interface CustomerIntegrationRow {
  id: string;
  kind: CustomerIntegrationKind;
  device: DeviceIntegration | null;
  mcp: ConfiguredMcpIntegration | null;
  sync: DeviceSyncBinding;
  vendorKey?: string;
}

const VENDOR_PRESENTATION: Record<string, Omit<DeviceVendor, 'id'>> = {
  sangfor:    { nameCn: '深信服', nameEn: 'Sangfor',    color: 'bg-blue-100 text-blue-800' },
  qianxin:    { nameCn: '奇安信', nameEn: 'Qi-AnXin',   color: 'bg-purple-100 text-purple-800' },
  threatbook: { nameCn: '微步',   nameEn: 'ThreatBook', color: 'bg-orange-100 text-orange-800' },
  qingteng:   { nameCn: '青藤',   nameEn: 'Qingteng',   color: 'bg-teal-100 text-teal-800' },
  nsfocus:    { nameCn: '绿盟',   nameEn: 'NSFOCUS',    color: 'bg-green-100 text-green-800' },
  asiainfo:   { nameCn: '亚信安全', nameEn: 'AsiaInfo Security', color: 'bg-cyan-100 text-cyan-800' },
  亚信安全:    { nameCn: '亚信安全', nameEn: 'AsiaInfo Security', color: 'bg-cyan-100 text-cyan-800' },
  安恒信息:    { nameCn: '安恒信息', nameEn: 'DBAPPSecurity', color: 'bg-red-100 text-red-800' },
  dbappsecurity: { nameCn: '安恒信息', nameEn: 'DBAPPSecurity', color: 'bg-red-100 text-red-800' },
};

function vendorPresentation(vendorKey: string): DeviceVendor {
  const preset = VENDOR_PRESENTATION[vendorKey];
  if (preset) return { id: vendorKey, ...preset };
  // Unknown vendor key: surface it as-is so the operator notices the gap
  // instead of inheriting a wrong-but-pretty bucket.
  return {
    id: vendorKey,
    nameCn: vendorKey,
    nameEn: vendorKey,
    color: 'bg-zinc-100 text-zinc-700',
  };
}

function isMcpTemplate(template: IntegrationTemplate): template is IntegrationTemplate & { mcp_entry: MCPCatalogEntry } {
  return template.integration_kind === 'mcp' && !!template.mcp_entry;
}

function mcpVendorKey(entry: MCPCatalogEntry): string {
  const text = `${entry.id} ${entry.name} ${entry.description} ${entry.description_cn || ''}`.toLowerCase();
  if (text.includes('asiainfo') || text.includes('亚信')) return '亚信安全';
  if (text.includes('qianxin') || text.includes('奇安信')) return 'qianxin';
  if (text.includes('threatbook') || text.includes('微步')) return 'threatbook';
  if (text.includes('nsfocus') || text.includes('绿盟')) return 'nsfocus';
  return entry.name.split(/\s+/)[0] || 'mcp';
}

function mcpCatalogEntryToTemplate(entry: MCPCatalogEntry): IntegrationTemplate {
  return {
    id: entry.id,
    name: entry.name,
    enabled: false,
    status: 'catalog',
    tool_count: 0,
    verify_ssl: true,
    integration_type: 'mcp',
    integration_kind: 'mcp',
    vendor: mcpVendorKey(entry),
    description: entry.description,
    description_cn: entry.description_cn,
    builtin: true,
    mcp_entry: entry,
  };
}

function deviceServiceToTemplate(service: APIServiceSummary): IntegrationTemplate {
  return {
    ...service,
    integration_kind: 'device',
  };
}


function syncPlanResultFromError(error: unknown): SyncEnginePlanResult | null {
  if (!error || typeof error !== 'object') return null;
  const err = error as { response?: { data?: unknown } };
  const data = err.response?.data;
  const detail = data && typeof data === 'object' && 'detail' in data
    ? (data as { detail?: unknown }).detail
    : data;
  if (!detail || typeof detail !== 'object') return null;
  const payload = detail as Partial<SyncEnginePlanResult>;
  if (!payload.status && !payload.sync_profile_id && !payload.errors && !payload.limitations) return null;
  return {
    status: String(payload.status || 'validation_failed'),
    dry_run: payload.dry_run ?? true,
    sync_profile_id: String(payload.sync_profile_id || ''),
    run_id: payload.run_id ?? null,
    package_id: payload.package_id ?? null,
    instance_id: payload.instance_id ?? null,
    capability: payload.capability ?? null,
    request_summary: payload.request_summary || {},
    plan_summary: payload.plan_summary || {},
    safety_summary: payload.safety_summary || {},
    limitations: Array.isArray(payload.limitations) ? payload.limitations : [],
    errors: Array.isArray(payload.errors) ? payload.errors : [],
  };
}

function syncPreviewResultFromError(error: unknown): ManualSyncPreviewResult | null {
  if (!error || typeof error !== 'object') return null;
  const err = error as { response?: { data?: unknown } };
  const data = err.response?.data;
  const detail = data && typeof data === 'object' && 'detail' in data
    ? (data as { detail?: unknown }).detail
    : data;
  if (!detail || typeof detail !== 'object') return null;
  const payload = detail as Partial<ManualSyncPreviewResult>;
  if (!payload.status && !payload.sync_profile_id && !payload.errors && !payload.limitations) return null;
  return {
    status: String(payload.status || 'validation_failed'),
    dry_run: payload.dry_run ?? true,
    preview_only: payload.preview_only ?? true,
    sync_profile_id: String(payload.sync_profile_id || ''),
    run_id: payload.run_id ?? null,
    package_id: payload.package_id ?? null,
    instance_id: payload.instance_id ?? null,
    capability: payload.capability ?? null,
    adapter_id: payload.adapter_id ?? null,
    fetched_count: Number(payload.fetched_count || 0),
    mapped_count: Number(payload.mapped_count || 0),
    preview_count: Number(payload.preview_count || 0),
    item_refs: Array.isArray(payload.item_refs) ? payload.item_refs : [],
    event_summaries: Array.isArray(payload.event_summaries) ? payload.event_summaries : [],
    request_summary: payload.request_summary || {},
    adapter_summary: payload.adapter_summary || {},
    mapping_summary: payload.mapping_summary || {},
    dispatch_summary: payload.dispatch_summary || {},
    safety_summary: payload.safety_summary || {},
    limitations: Array.isArray(payload.limitations) ? payload.limitations : [],
    warnings: Array.isArray(payload.warnings) ? payload.warnings : [],
    errors: Array.isArray(payload.errors) ? payload.errors : [],
  };
}

function apiErrorMessage(error: unknown, fallback: string): string {
  if (!error || typeof error !== 'object') return fallback;
  const err = error as {
    message?: string;
    response?: { data?: unknown };
  };
  const data = err.response?.data;
  if (typeof data === 'string' && data.trim()) return data;
  if (data && typeof data === 'object') {
    const payload = data as { detail?: unknown; message?: unknown; error?: unknown };
    for (const value of [payload.detail, payload.message, payload.error]) {
      if (typeof value === 'string' && value.trim()) return value;
    }
  }
  return err.message || fallback;
}

// ============================================================================
// Status helpers
// ============================================================================

function StatusBadge({ status, enabled }: { status: string; enabled: boolean }) {
  if (!enabled) return (
    <span className="inline-flex items-center gap-1 text-xs text-zinc-400"><WifiOff className="w-3 h-3" />已禁用</span>
  );
  if (status === 'ok' || status === 'connected') return (
    <span className="inline-flex items-center gap-1 text-xs text-green-600"><CheckCircle className="w-3 h-3" />已连接</span>
  );
  if (status === 'error') return (
    <span className="inline-flex items-center gap-1 text-xs text-red-500"><XCircle className="w-3 h-3" />连接失败</span>
  );
  return (
    <span className="inline-flex items-center gap-1 text-xs text-zinc-400"><AlertTriangle className="w-3 h-3" />未检测</span>
  );
}

function operationKindLabel(kind?: string | null) {
  if (kind === 'credential_expiring_soon') return '凭据即将过期';
  if (kind === 'credential_expired') return '凭据已过期';
  if (kind === 'sync_blocked') return '同步被阻断';
  if (kind === 'schedule_policy_paused') return '调度已暂停';
  if (kind === 'credential_remediation_requested') return '已请求处置';
  return kind || '运营事件';
}

function IntegrationHealthPanel({
  integrations,
  connectorSummary,
}: {
  integrations: CustomerIntegrationRow[];
  connectorSummary: SecurityConnectorCustomerSummary | null;
}) {
  const [trendWindow, setTrendWindow] = useState<7 | 14>(7);
  const productRows = buildProductHealthRows(integrations);
  const devices = productRows.filter((row) => row.kind === 'device' && row.device).map((row) => row.device as DeviceIntegration);
  const mcps = productRows.filter((row) => row.kind === 'mcp' && row.mcp).map((row) => row.mcp as ConfiguredMcpIntegration);
  const connectedDevices = devices.filter((device) => device.enabled && ['ok', 'connected'].includes(device.status)).length;
  const connectedMcps = mcps.filter((mcp) => mcpApiStatus(mcp) === 'connected').length;
  const deviceTotal = devices.length;
  const summary = connectorSummary?.summary;
  const activeConnectors = Number(summary?.connected_data_sources ?? 0);
  const connectorCount = Number(summary?.data_sources ?? 0);
  const expiryRisks = Number(summary?.expiry_risks ?? 0);
  const blockedRuns = Number(summary?.sync_blocked ?? 0);
  const pausedSchedules = Number(summary?.paused_schedules ?? 0);
  const productsNeedingAttention = productRows.filter(({ device, mcp, sync }) => productNeedsAttention(device, sync, mcp)).length;
  const mappedProducts = productRows.filter(({ sync }) => sync.source).length;
  const matchedSourceKeys = new Set(
    productRows
      .map((row) => row.sync.source ? sourceRowId(row.sync.source) : null)
      .filter((key): key is string => Boolean(key)),
  );
  const unboundSyncSources = (connectorSummary?.data_sources || [])
    .filter((source) => !matchedSourceKeys.has(sourceRowId(source)))
    .length;
  const productTotal = productRows.length;
  const openEvents = (connectorSummary?.recent_events || []).slice(0, 3);
  const trend = (connectorSummary?.trend || []).slice(-trendWindow);
  const trendMax = Math.max(
    1,
    ...trend.map((bucket) =>
      Math.max(bucket.expiry_risks || 0, bucket.sync_blocked || 0, bucket.paused_schedules || 0, bucket.recoveries || 0),
    ),
  );
  const cards = [
    {
      key: 'devices',
      label: '安全产品接入',
      value: `${connectedDevices + connectedMcps}/${productTotal}`,
      detail: `${deviceTotal} 个设备 · ${mcps.length} 个 MCP · ${unboundSyncSources} 个同步源待绑定 · ${productsNeedingAttention} 个需关注`,
      tone: 'border-blue-200 bg-blue-50 text-blue-900',
      icon: PlugZap,
    },
    {
      key: 'connectors',
      label: '数据源同步',
      value: `${activeConnectors}/${mappedProducts || connectorCount}`,
      detail: `${Number(summary?.enabled_sync_schedules ?? 0)}/${Number(summary?.sync_schedules ?? 0)} 个同步调度启用`,
      tone: 'border-emerald-200 bg-emerald-50 text-emerald-900',
      icon: Database,
    },
    {
      key: 'expiry',
      label: '凭据风险',
      value: expiryRisks,
      detail: '影响产品同步与 API 调用',
      tone: 'border-amber-200 bg-amber-50 text-amber-900',
      icon: AlertTriangle,
    },
    {
      key: 'blocked',
      label: '阻断与暂停',
      value: blockedRuns + pausedSchedules,
      detail: `${pausedSchedules} 个暂停调度`,
      tone: 'border-red-200 bg-red-50 text-red-900',
      icon: Activity,
    },
  ];

  return (
    <section className="mb-6">
      <div className="mb-3 flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 className="text-sm font-semibold text-zinc-800">数据接入健康</h2>
          <p className="text-xs text-zinc-400">按安全产品统一展示设备 API、工具调用与数据同步状态</p>
        </div>
        <div className="font-mono text-[11px] text-zinc-400">
          {connectorSummary?.checked_at || '数据接入健康数据暂不可用'}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <div key={card.key} className={`rounded-lg border px-3 py-3 ${card.tone}`}>
              <div className="flex items-center gap-2 text-[11px] font-semibold uppercase">
                <Icon className="h-4 w-4 shrink-0" />
                <span className="truncate">{card.label}</span>
              </div>
              <div className="mt-2 font-mono text-2xl font-semibold leading-none">{card.value}</div>
              <div className="mt-2 truncate text-[11px] opacity-75">{card.detail}</div>
            </div>
          );
        })}
      </div>

      <div className="mt-3 rounded-lg border border-zinc-200 bg-white">
        <div className="flex items-center justify-between border-b border-zinc-100 px-3 py-2">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase text-zinc-500">
            <Shield className="h-3.5 w-3.5" />
            安全产品状态
          </div>
          <span className="rounded-md bg-zinc-100 px-2 py-0.5 text-[11px] text-zinc-500">
            {productTotal} 个产品
          </span>
        </div>
        {productTotal === 0 ? (
          <div className="px-3 py-6 text-center text-xs text-zinc-400">暂无已接入安全产品</div>
        ) : (
          <div className="grid grid-cols-1 gap-3 p-3 xl:grid-cols-2">
            {productRows.map(({ id, device, mcp, sync }) => (
              <ProductHealthCard key={id} device={device} mcp={mcp} sync={sync} />
            ))}
          </div>
        )}
      </div>

      <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div className="rounded-lg border border-zinc-200 bg-white">
          <div className="flex items-center justify-between border-b border-zinc-100 px-3 py-2">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase text-zinc-500">
              <BarChart3 className="h-3.5 w-3.5" />
              同步趋势
            </div>
            <div className="flex rounded-md border border-zinc-200 p-0.5">
              {[7, 14].map((days) => (
                <button
                  key={days}
                  type="button"
                  onClick={() => setTrendWindow(days as 7 | 14)}
                  className={`px-2 py-0.5 text-[11px] ${trendWindow === days ? 'rounded bg-zinc-900 text-white' : 'text-zinc-500 hover:text-zinc-800'}`}
                >
                  {days} 天
                </button>
              ))}
            </div>
          </div>
          <div className="flex gap-2 overflow-x-auto px-3 py-3">
            {trend.length > 0 ? trend.map((bucket) => (
              <div key={bucket.date} className="min-w-[64px] flex-1">
                <div className="flex h-16 items-end justify-center gap-1 rounded bg-zinc-50 px-1 py-1">
                  <TrendColumn value={bucket.expiry_risks || 0} max={trendMax} color="bg-amber-500" title="过期风险" />
                  <TrendColumn value={bucket.sync_blocked || 0} max={trendMax} color="bg-red-500" title="同步阻断" />
                  <TrendColumn value={bucket.paused_schedules || 0} max={trendMax} color="bg-zinc-500" title="暂停调度" />
                  <TrendColumn value={bucket.recoveries || 0} max={trendMax} color="bg-green-500" title="恢复" />
                </div>
                <div className="mt-1 text-center font-mono text-[11px] text-zinc-500">{bucket.date.slice(5)}</div>
              </div>
            )) : (
              <div className="w-full py-6 text-center text-xs text-zinc-400">暂无同步趋势</div>
            )}
          </div>
        </div>

        <div className="rounded-lg border border-zinc-200 bg-white">
          <div className="border-b border-zinc-100 px-3 py-2 text-xs font-semibold uppercase text-zinc-500">
            需要关注
          </div>
          <div className="divide-y divide-zinc-100">
            {openEvents.map((event) => (
              <OperationEventSummary key={event.id} event={event} />
            ))}
            {openEvents.length === 0 && (
              <div className="px-3 py-5 text-center text-xs text-zinc-400">
                {connectorSummary ? '暂无待关注事件' : '数据同步健康数据暂不可用'}
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

function TrendColumn({ value, max, color, title }: { value: number; max: number; color: string; title: string }) {
  const height = value > 0 ? Math.max(6, Math.round((value / Math.max(1, max)) * 56)) : 0;
  return <div className={`w-2 rounded-sm ${color}`} style={{ height }} title={`${title}: ${value}`} />;
}

function OperationEventSummary({ event }: { event: SecurityConnectorCustomerEvent }) {
  return (
    <div className="px-3 py-2 text-xs">
      <div className="flex items-center justify-between gap-2">
        <span className="font-medium text-zinc-800">{event.label || operationKindLabel(event.kind)}</span>
        <span className="shrink-0 rounded-full bg-zinc-100 px-2 py-0.5 text-[10px] text-zinc-500">{event.severity}</span>
      </div>
      <div className="mt-1 truncate text-[11px] text-zinc-500" title={event.message}>
        {event.message || '-'}
      </div>
      <div className="mt-1 truncate text-[10px] text-zinc-400">
        {event.connector_name || event.connector_id || '-'} · {event.recommended_action}
      </div>
    </div>
  );
}

function statusTone(status: string) {
  if (['connected', 'ok', 'healthy', 'enabled'].includes(status)) return 'bg-green-50 text-green-700 border-green-100';
  if (['blocked', 'failed', 'expired'].includes(status)) return 'bg-red-50 text-red-700 border-red-100';
  if (['paused', 'partial', 'attention', 'expiring_soon', 'pending_test', 'pending_sync', 'disconnected', 'connecting', 'needs_auth'].includes(status)) return 'bg-amber-50 text-amber-700 border-amber-100';
  if (['disabled', 'not_synced', 'not_configured', 'unbound_device'].includes(status)) return 'bg-zinc-50 text-zinc-600 border-zinc-100';
  return 'bg-blue-50 text-blue-700 border-blue-100';
}

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    connected: '已连接',
    attention: '需关注',
    blocked: '已阻断',
    disabled: '已停用',
    not_configured: '未配置',
    ok: '正常',
    syncing: '同步中',
    paused: '已暂停',
    partial: '部分成功',
    failed: '失败',
    error: '失败',
    disconnected: '未连接',
    connecting: '连接中',
    needs_auth: '需认证',
    not_synced: '未同步',
    unbound_device: '未绑定',
    healthy: '正常',
    enabled: '已启用',
    expired: '已过期',
    expiring_soon: '即将过期',
    pending_test: '待测试',
    pending_sync: '待验证',
  };
  return labels[status] || status || '-';
}

function deviceApiStatus(device?: DeviceIntegration | null) {
  if (!device) return 'unbound_device';
  if (!device.enabled) return 'disabled';
  if (['connected', 'ok'].includes(device.status)) return 'connected';
  if (['error', 'failed'].includes(device.status)) return 'failed';
  return device.status || 'pending_test';
}

function mcpApiStatus(mcp?: ConfiguredMcpIntegration | null) {
  if (!mcp) return 'unbound_device';
  if (mcp.status.status === 'connected') return 'connected';
  if (mcp.status.status === 'disabled') return 'disabled';
  if (['failed', 'error'].includes(mcp.status.status)) return 'failed';
  return mcp.status.status || 'disconnected';
}

function syncStatusFromBinding(sync: DeviceSyncBinding) {
  if (sync.source) return sync.source.sync_status || 'not_synced';
  if (sync.state === 'available') return 'not_synced';
  return 'not_configured';
}

function unavailableSyncBinding(): DeviceSyncBinding {
  return {
    source: null,
    state: 'unavailable',
    label: '暂无同步映射',
    message: '当前设备包暂未提供标准化数据同步映射。',
    capabilities: [],
  };
}

function sourceSyncBinding(source: SecurityConnectorCustomerDataSource): DeviceSyncBinding {
  const enabledSchedules = source.schedules.filter((schedule) => schedule.enabled).length;
  const hasSchedules = source.schedules.length > 0;
  return {
    source,
    state: enabledSchedules > 0 || hasSchedules || source.sync_status !== 'not_synced' ? 'active' : 'available',
    label: enabledSchedules > 0 || hasSchedules ? `同步 ${statusLabel(source.sync_status)}` : '可启用同步',
    message: source.message,
    capabilities: source.capabilities || [],
  };
}

function productNeedsAttention(device: DeviceIntegration | null, sync: DeviceSyncBinding, mcp?: ConfiguredMcpIntegration | null) {
  if (mcp && ['failed', 'error', 'needs_auth'].includes(mcp.status.status)) return true;
  const apiStatus = deviceApiStatus(device);
  const source = sync.source;
  if (device && ['failed', 'disabled', 'error'].includes(apiStatus)) return true;
  if (!source) return false;
  if (source.credential?.blocking || ['blocked', 'failed', 'expired'].includes(source.sync_status)) return true;
  return source.schedules.some((schedule) => !schedule.enabled || ['paused', 'blocked', 'failed'].includes(schedule.status));
}

function productStatusMessage(device: DeviceIntegration | null, sync: DeviceSyncBinding, mcp?: ConfiguredMcpIntegration | null) {
  if (mcp) {
    if (mcp.status.error) return mcp.status.error;
    if (mcp.status.status === 'connected') return 'MCP 已连接，Agent 可以调用该服务暴露的工具。';
    if (mcp.status.status === 'disabled') return 'MCP 已保存但未启用，Agent 暂不会调用该服务。';
    if (mcp.status.status === 'needs_auth') return 'MCP 需要补充或更新认证信息。';
    if (mcp.status.status === 'connecting') return 'MCP 正在连接中。';
    return 'MCP 已保存，尚未建立连接。';
  }
  const source = sync.source;
  if (source?.sync.failure_reason) return source.sync.failure_reason;
  if (source?.message) return source.message;
  if (sync.message) return sync.message;
  if (!device && source) return '该数据源同步尚未绑定到 Device Integration 设备。';
  if (!device) return '该同步源尚未绑定到 Device Integration 设备。';
  if (!device.enabled) return '设备 API 已停用，工具调用和数据同步不会执行。';
  if (['error', 'failed'].includes(device.status)) return '设备 API 连接失败，请先完成连通性测试。';
  return '设备 API 已接入，等待启用标准化数据同步。';
}

function sourceRowId(source: SecurityConnectorCustomerDataSource) {
  return `source:${source.id}:${source.credential?.profile_id || 'default'}`;
}

function buildProductHealthRows(
  integrations: CustomerIntegrationRow[],
): CustomerIntegrationRow[] {
  return integrations.filter((row) => (
    (row.kind === 'device' && row.device)
    || (row.kind === 'mcp' && row.mcp)
  ));
}

function ProductHealthCard({ device, mcp, sync }: { device: DeviceIntegration | null; mcp: ConfiguredMcpIntegration | null; sync: DeviceSyncBinding }) {
  const source = sync.source;
  const apiStatus = mcp ? mcpApiStatus(mcp) : deviceApiStatus(device);
  const syncStatus = syncStatusFromBinding(sync);
  const enabledSchedules = source?.schedules.filter((schedule) => schedule.enabled).length ?? 0;
  const scheduleTotal = source?.schedules.length ?? 0;
  const displayName = device?.name || mcp?.template.name || source?.name || '未命名安全产品';
  const meta = [
    device?.fields.base_url,
    mcp ? 'MCP' : null,
    mcp?.id,
    source?.name,
    source ? [source.vendor, source.product, source.product_version].filter(Boolean).join(' · ') : null,
  ].filter(Boolean);
  return (
    <div className="rounded-lg border border-zinc-200 bg-white p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
            <div className="flex items-center gap-2">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-blue-50">
              {mcp ? <Plug className="h-4 w-4 text-slate-600" /> : device ? <PlugZap className="h-4 w-4 text-blue-600" /> : <Database className="h-4 w-4 text-emerald-600" />}
            </div>
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold text-zinc-900">{displayName}</div>
              <div className="truncate text-xs text-zinc-400">
                {meta.join(' · ') || device?.storage_key || source?.id || '-'}
              </div>
            </div>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <span className={`rounded-full border px-2 py-0.5 text-[11px] ${statusTone(apiStatus)}`}>
            {mcp ? 'MCP' : 'API'} {statusLabel(apiStatus)}
          </span>
          {!mcp && (
            <span className={`rounded-full border px-2 py-0.5 text-[11px] ${statusTone(syncStatus)}`}>
              同步 {statusLabel(syncStatus)}
            </span>
          )}
          {source && (
            <span className={`rounded-full border px-2 py-0.5 text-[11px] ${statusTone(source.credential.state)}`}>
              凭据 {statusLabel(source.credential.state)}
            </span>
          )}
        </div>
      </div>

      <div className="mt-3 rounded-lg border border-zinc-100 bg-zinc-50/60 px-3 py-2 text-xs text-zinc-600">
        <div className="font-medium text-zinc-800">{productStatusMessage(device, sync, mcp)}</div>
        {mcp?.status.error && (
          <div className="mt-1 text-[11px] text-zinc-400">请更新凭据或在厂商侧确认 Key 权限、出口 IP 白名单和 MCP endpoint。</div>
        )}
        {source?.sync.recommended_action && (
          <div className="mt-1 text-[11px] text-zinc-400">{source.sync.recommended_action}</div>
        )}
        {!device && source && (
          <div className="mt-1 text-[11px] text-zinc-400">请在对应设备详情中启用数据同步，或先添加该安全产品设备。</div>
        )}
      </div>

      {mcp ? (
        <>
          <div className="mt-3 flex flex-wrap gap-2">
            <SyncCountPill label="工具" value={mcp.status.tools_count ?? 0} />
            <SyncCountPill label="资源" value={mcp.status.resources_count ?? 0} />
          </div>
          <div className="mt-3 flex items-center gap-1.5 text-xs text-zinc-500">
            <Clock className="h-3.5 w-3.5 text-zinc-400" />
            最近连接 {mcp.status.connected_at ? formatDateTime(new Date(mcp.status.connected_at * 1000).toISOString()) : '-'}
          </div>
        </>
      ) : source ? (
        <>
          <div className="mt-3 flex flex-wrap gap-2">
            <SyncCountPill label="资产" value={source.sync.counts.assets} />
            <SyncCountPill label="漏洞" value={source.sync.counts.vulnerabilities} />
            <SyncCountPill label="告警" value={source.sync.counts.alerts} />
            <SyncCountPill label="蜜罐" value={source.sync.counts.honeypot_events} />
          </div>
          <div className="mt-3 grid grid-cols-1 gap-2 text-xs text-zinc-500 sm:grid-cols-2">
            <div className="flex items-center gap-1.5">
              <Clock className="h-3.5 w-3.5 text-zinc-400" />
              最近同步 {formatDateTime(source.sync.last_sync_at)}
            </div>
            <div className="flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-zinc-400" />
              调度 {enabledSchedules}/{scheduleTotal} 启用 · {scheduleFrequencySummary(source.schedules)}
            </div>
          </div>
        </>
      ) : (
        <div className="mt-3 flex flex-wrap gap-2">
          <span className="inline-flex items-center gap-1 rounded-md border border-zinc-100 bg-zinc-50 px-2 py-1 text-[11px] text-zinc-500">
            <Database className="h-3 w-3" />
            标准同步未配置
          </span>
        </div>
      )}
    </div>
  );
}

function formatDateTime(value?: string | null) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

const SYNC_INTERVAL_OPTIONS = [300, 900, 1800, 3600, 21600, 43200, 86400];

function formatSyncInterval(seconds?: number | null) {
  const value = Number(seconds || 0);
  if (!Number.isFinite(value) || value <= 0) return '未设置';
  if (value % 86400 === 0) return `${value / 86400} 天`;
  if (value % 3600 === 0) return `${value / 3600} 小时`;
  if (value % 60 === 0) return `${value / 60} 分钟`;
  return `${value} 秒`;
}

function scheduleIntervalOptions(current?: number | null) {
  const currentValue = Number(current || 0);
  const options = [...SYNC_INTERVAL_OPTIONS];
  if (currentValue > 0 && !options.includes(currentValue)) options.push(currentValue);
  return options.sort((a, b) => a - b);
}

function scheduleFrequencySummary(schedules: SecurityConnectorCustomerSchedule[]) {
  const enabled = schedules.filter((schedule) => schedule.enabled && Number(schedule.interval_seconds || 0) > 0);
  if (enabled.length === 0) return '频率未启用';
  const values = Array.from(new Set(enabled.map((schedule) => Number(schedule.interval_seconds || 0)))).sort((a, b) => a - b);
  if (values.length === 1) return `每 ${formatSyncInterval(values[0])}`;
  return `最短每 ${formatSyncInterval(values[0])}`;
}

function SyncCountPill({ label, value }: { label: string; value: number }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-md border border-zinc-100 bg-zinc-50 px-2 py-1 text-[11px] text-zinc-600">
      <span>{label}</span>
      <span className="font-mono text-zinc-900">{value}</span>
    </span>
  );
}

interface DeviceSyncBinding {
  source: SecurityConnectorCustomerDataSource | null;
  state: 'active' | 'available' | 'unavailable';
  label: string;
  message: string;
  capabilities: string[];
}

function deviceSyncProfileId(deviceId: string) {
  return `device-${deviceId}`;
}

function normalizeIdentity(value?: string | null) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function sourceMatchesDevice(
  source: SecurityConnectorCustomerDataSource,
  device: DeviceIntegration,
  template?: APIServiceSummary,
) {
  const product = normalizeIdentity(source.product || source.name || source.id);
  if (!product || product.length < 2) return false;
  const candidates = [
    template?.name,
    template?.id,
    template?.description,
    template?.description_cn,
    device.storage_key,
    device.service_id,
    device.name,
  ].map(normalizeIdentity).filter(Boolean);
  return candidates.some((candidate) => candidate.includes(product) || product.includes(candidate));
}

function capabilityLabel(value: string) {
  const labels: Record<string, string> = {
    'asset.search': '资产',
    'asset.sync': '资产',
    'vulnerability.search': '漏洞',
    'vulnerability.sync': '漏洞',
    'alert.search': '告警',
    'event.search': '事件',
    'honeypot.event.search': '蜜罐',
  };
  return labels[value] || value;
}

function buildDeviceSyncBinding(
  device: DeviceIntegration,
  connectorSummary: SecurityConnectorCustomerSummary | null,
  template?: APIServiceSummary,
): DeviceSyncBinding {
  const sources = connectorSummary?.data_sources || [];
  const profileId = deviceSyncProfileId(device.id);
  const boundSource = sources.find((source) => source.credential?.profile_id === profileId);
  const source = boundSource || sources.find((candidate) => sourceMatchesDevice(candidate, device, template)) || null;
  if (!source) {
    return {
      source: null,
      state: 'unavailable',
      label: '暂无同步映射',
      message: '当前设备包暂未提供标准化数据同步映射。',
      capabilities: [],
    };
  }
  const enabledSchedules = source.schedules.filter((schedule) => schedule.enabled).length;
  const hasSchedules = source.schedules.length > 0;
  return {
    source,
    state: enabledSchedules > 0 || hasSchedules || source.sync_status !== 'not_synced' ? 'active' : 'available',
    label: enabledSchedules > 0 || hasSchedules ? `同步 ${statusLabel(source.sync_status)}` : '可启用同步',
    message: source.message,
    capabilities: source.capabilities || [],
  };
}

function isSystemCredentialField(key: string) {
  return key.startsWith('FLOCKS_CONNECTOR_');
}

function editableCredentialFields(source: SecurityConnectorCustomerDataSource) {
  return (source.credential.fields || []).filter((field) => !isSystemCredentialField(field.key));
}

function hasEditableCredentialFields(source: SecurityConnectorCustomerDataSource) {
  return editableCredentialFields(source).length > 0;
}

function DataSourceConnectorSection({
  connectorSummary,
  actionLoading,
  onTest,
  onPauseSchedule,
  onResumeSchedule,
  onUpdateCredentials,
}: {
  connectorSummary: SecurityConnectorCustomerSummary | null;
  actionLoading: string | null;
  onTest: (source: SecurityConnectorCustomerDataSource) => Promise<void>;
  onPauseSchedule: (source: SecurityConnectorCustomerDataSource, schedule: SecurityConnectorCustomerSchedule) => Promise<void>;
  onResumeSchedule: (source: SecurityConnectorCustomerDataSource, schedule: SecurityConnectorCustomerSchedule) => Promise<void>;
  onUpdateCredentials: (source: SecurityConnectorCustomerDataSource) => void;
}) {
  const sources = connectorSummary?.data_sources || [];

  return (
    <section className="mb-6">
      <div className="mb-3 flex items-center gap-2">
        <Database className="h-4 w-4 text-emerald-600" />
        <h3 className="text-sm font-semibold text-zinc-800">数据源同步</h3>
        <span className="rounded-md bg-zinc-100 px-1.5 py-0.5 text-xs text-zinc-400">{sources.length}</span>
      </div>

      {sources.length === 0 ? (
        <div className="rounded-lg border border-zinc-200 bg-white px-4 py-8 text-center text-sm text-zinc-400">
          {connectorSummary ? '暂无已接入的数据源同步' : '数据同步健康数据暂不可用'}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
          {sources.map((source) => (
            <div key={source.id} className="rounded-lg border border-zinc-200 bg-white p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-emerald-50">
                      <Database className="h-4 w-4 text-emerald-600" />
                    </div>
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold text-zinc-900">{source.name}</div>
                      <div className="truncate text-xs text-zinc-400">
                        {[source.vendor, source.product, source.product_version].filter(Boolean).join(' · ') || source.id}
                      </div>
                    </div>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  <span className={`rounded-full border px-2 py-0.5 text-[11px] ${statusTone(source.connection_status)}`}>
                    连接 {statusLabel(source.connection_status)}
                  </span>
                  <span className={`rounded-full border px-2 py-0.5 text-[11px] ${statusTone(source.sync_status)}`}>
                    同步 {statusLabel(source.sync_status)}
                  </span>
                </div>
              </div>

              <div className="mt-3 rounded-lg border border-zinc-100 bg-zinc-50/60 px-3 py-2 text-xs text-zinc-600">
                <div className="font-medium text-zinc-800">{source.message}</div>
                {source.sync.failure_reason && (
                  <div className="mt-1 text-zinc-500">{source.sync.failure_reason}</div>
                )}
                <div className="mt-1 text-[11px] text-zinc-400">{source.sync.recommended_action}</div>
              </div>

              <div className="mt-3 flex flex-wrap gap-2">
                <SyncCountPill label="资产" value={source.sync.counts.assets} />
                <SyncCountPill label="漏洞" value={source.sync.counts.vulnerabilities} />
                <SyncCountPill label="告警" value={source.sync.counts.alerts} />
                <SyncCountPill label="蜜罐" value={source.sync.counts.honeypot_events} />
              </div>

              <div className="mt-3 grid grid-cols-1 gap-2 text-xs text-zinc-500 sm:grid-cols-2">
                <div className="flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5 text-zinc-400" />
                  最近同步 {formatDateTime(source.sync.last_sync_at)}
                </div>
                <div className="flex items-center gap-1.5">
                  <KeyRound className="h-3.5 w-3.5 text-zinc-400" />
                  {source.credential.message}
                </div>
              </div>

              {source.schedules.length > 0 && (
                <div className="mt-3 rounded-lg border border-zinc-100">
                  {source.schedules.map((schedule) => (
                    <div key={schedule.id} className="flex flex-col gap-2 border-b border-zinc-100 px-3 py-2 last:border-b-0 sm:flex-row sm:items-center sm:justify-between">
                      <div className="min-w-0">
                        <div className="truncate text-xs font-medium text-zinc-700">{schedule.capability || '同步调度'}</div>
                        <div className="truncate text-[11px] text-zinc-400">{schedule.message}</div>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] ${statusTone(schedule.status)}`}>
                          {statusLabel(schedule.status)}
                        </span>
                        {schedule.status === 'paused' || !schedule.enabled ? (
                          <button
                            type="button"
                            onClick={() => void onResumeSchedule(source, schedule)}
                            disabled={actionLoading === `resume:${schedule.id}`}
                            className="inline-flex items-center gap-1 rounded-md border border-zinc-200 px-2 py-1 text-[11px] text-zinc-600 hover:bg-zinc-50 disabled:opacity-50"
                          >
                            {actionLoading === `resume:${schedule.id}` ? <Loader2 className="h-3 w-3 animate-spin" /> : <PlayCircle className="h-3 w-3" />}
                            恢复
                          </button>
                        ) : (
                          <button
                            type="button"
                            onClick={() => void onPauseSchedule(source, schedule)}
                            disabled={actionLoading === `pause:${schedule.id}`}
                            className="inline-flex items-center gap-1 rounded-md border border-zinc-200 px-2 py-1 text-[11px] text-zinc-600 hover:bg-zinc-50 disabled:opacity-50"
                          >
                            {actionLoading === `pause:${schedule.id}` ? <Loader2 className="h-3 w-3 animate-spin" /> : <PauseCircle className="h-3 w-3" />}
                            暂停
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div className="mt-3 flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => void onTest(source)}
                  disabled={actionLoading === `test:${source.id}`}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-200 px-3 py-1.5 text-xs text-zinc-600 hover:bg-zinc-50 disabled:opacity-50"
                >
                  {actionLoading === `test:${source.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Activity className="h-3.5 w-3.5" />}
                  测试连接
                </button>
                {source.actions.some((action) => action.kind === 'update_credentials') && hasEditableCredentialFields(source) && (
                  <button
                    type="button"
                    onClick={() => onUpdateCredentials(source)}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-zinc-900 px-3 py-1.5 text-xs text-white hover:bg-zinc-800"
                  >
                    <KeyRound className="h-3.5 w-3.5" />
                    更新凭据
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function DataSourceCredentialDialog({
  source,
  saving,
  onClose,
  onSubmit,
}: {
  source: SecurityConnectorCustomerDataSource;
  saving: boolean;
  onClose: () => void;
  onSubmit: (payload: { values: Record<string, string>; secretKeys: string[]; profileId: string; expiresAt?: string | null }) => Promise<void>;
}) {
  const toast = useToast();
  const fields = source.credential.fields || [];
  const editableFields = editableCredentialFields(source);
  const hiddenSystemFieldCount = fields.length - editableFields.length;
  const [values, setValues] = useState<Record<string, string>>({});
  const [profileId, setProfileId] = useState(source.credential.profile_id || 'default');
  const [expiresAt, setExpiresAt] = useState(() => source.credential.expires_at ? source.credential.expires_at.slice(0, 16) : '');
  const hasEditableValue = Object.values(values).some((value) => value.trim());
  const metadataChanged =
    (profileId || 'default') !== (source.credential.profile_id || 'default') ||
    (expiresAt || '') !== (source.credential.expires_at ? source.credential.expires_at.slice(0, 16) : '');
  const canSubmit = hasEditableValue || metadataChanged;

  const submit = async () => {
    const cleaned = Object.fromEntries(Object.entries(values).filter(([, value]) => value.trim()));
    if (!canSubmit) {
      toast.error('请至少填写一个需要更新的凭据字段');
      return;
    }
    await onSubmit({
      values: cleaned,
      secretKeys: editableFields.filter((field) => field.kind === 'secret' && cleaned[field.key]).map((field) => field.key),
      profileId: profileId || 'default',
      expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/35 px-4">
      <div className="w-full max-w-lg rounded-lg bg-white shadow-xl">
        <div className="flex items-start justify-between border-b border-zinc-100 px-5 py-4">
          <div>
            <h3 className="text-sm font-semibold text-zinc-900">更新数据源凭据</h3>
            <p className="mt-1 text-xs text-zinc-400">{source.name}</p>
          </div>
          <button type="button" onClick={onClose} className="rounded-md p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-4 px-5 py-4">
          <div>
            <label className="mb-1 block text-xs font-medium text-zinc-600">凭据 Profile</label>
            <input
              value={profileId}
              onChange={(event) => setProfileId(event.target.value)}
              className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-100"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-zinc-600">过期时间</label>
            <input
              type="datetime-local"
              value={expiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
              className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-100"
            />
          </div>
          {editableFields.length === 0 ? (
            <div className="rounded-lg border border-blue-100 bg-blue-50 px-3 py-2 text-xs text-blue-700">
              {hiddenSystemFieldCount > 0
                ? '设备绑定由系统自动维护；请在当前设备配置中更新 API Key、Base URL 等凭据。这里只能调整 Profile 元数据。'
                : '当前数据源没有可编辑的凭据字段；这里只能调整 Profile 元数据。'}
            </div>
          ) : (
            <div className="space-y-3">
              {editableFields.map((field) => (
                <div key={field.key}>
                  <label className="mb-1 block text-xs font-medium text-zinc-600">
                    {field.key}
                    <span className="ml-1 text-[10px] text-zinc-400">{field.kind === 'secret' ? '密钥' : '配置'}</span>
                  </label>
                  <input
                    type={field.kind === 'secret' ? 'password' : 'text'}
                    value={values[field.key] || ''}
                    onChange={(event) => setValues((prev) => ({ ...prev, [field.key]: event.target.value }))}
                    placeholder={field.configured ? '留空表示不修改' : '请输入'}
                    className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-100"
                  />
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="flex justify-end gap-2 border-t border-zinc-100 px-5 py-4">
          <button type="button" onClick={onClose} className="rounded-lg border border-zinc-200 px-4 py-2 text-sm text-zinc-600 hover:bg-zinc-50">
            取消
          </button>
          <button
            type="button"
            onClick={() => void submit()}
            disabled={saving || !canSubmit}
            className="inline-flex items-center gap-1.5 rounded-lg bg-zinc-900 px-4 py-2 text-sm text-white hover:bg-zinc-800 disabled:opacity-50"
          >
            {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
            保存并测试
          </button>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Active device card
// ============================================================================

function ActiveCard({ device, vendorKey, sync, selected, onClick }: {
  device: DeviceIntegration;
  vendorKey?: string;
  sync: DeviceSyncBinding;
  selected: boolean;
  onClick: () => void;
}) {
  const vendor = vendorKey ? vendorPresentation(vendorKey) : undefined;
  const apiStatus = deviceApiStatus(device);
  const syncStatus = syncStatusFromBinding(sync);
  const source = sync.source;
  const attention = productNeedsAttention(device, sync);
  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-xl border p-4 transition-all duration-150 group ${
        selected
          ? 'border-blue-300 bg-blue-50 shadow-sm ring-1 ring-blue-200'
          : attention
            ? 'border-amber-200 bg-amber-50/40 hover:border-amber-300 hover:shadow-sm'
            : 'border-zinc-200 bg-white hover:border-zinc-300 hover:shadow-sm'
      }`}
    >
      <div className="flex items-start gap-3">
        <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${
          selected ? 'bg-blue-100' : 'bg-zinc-50 group-hover:bg-zinc-100'
        }`}>
          <PlugZap className={`w-4 h-4 ${selected ? 'text-blue-600' : 'text-zinc-500'}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <p className="text-sm font-semibold text-zinc-800 truncate">{device.name}</p>
            <Settings className={`w-3.5 h-3.5 flex-shrink-0 ${selected ? 'text-blue-400' : 'text-zinc-300 group-hover:text-zinc-400'}`} />
          </div>
          <p className="text-xs text-zinc-400 mt-0.5 truncate">{device.storage_key}</p>
          {device.fields.base_url && (
            <p className="text-xs text-zinc-400 truncate">{device.fields.base_url}</p>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <span className={`rounded-full border px-2 py-0.5 text-[10px] ${statusTone(apiStatus)}`}>
              API {statusLabel(apiStatus)}
            </span>
            <span className={`rounded-full border px-2 py-0.5 text-[10px] ${statusTone(syncStatus)}`}>
              同步 {statusLabel(syncStatus)}
            </span>
            {vendor && (
              <>
                <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded-md ${vendor.color}`}>{vendor.nameCn}</span>
              </>
            )}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-[10px] text-zinc-400">
            <Database className="h-3 w-3 shrink-0 text-zinc-300" />
            <span className="truncate">{source?.name || sync.label}</span>
          </div>
        </div>
      </div>
    </button>
  );
}

function McpActiveCard({ mcp, selected, onClick }: {
  mcp: ConfiguredMcpIntegration;
  selected?: boolean;
  onClick?: () => void;
}) {
  const vendor = mcp.template.vendor ? vendorPresentation(mcp.template.vendor) : undefined;
  const status = mcpApiStatus(mcp);
  const attention = productNeedsAttention(null, unavailableSyncBinding(), mcp);
  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-xl border p-4 transition-all duration-150 group ${
        selected
          ? 'border-blue-300 bg-blue-50 shadow-sm ring-1 ring-blue-200'
          : attention
            ? 'border-amber-200 bg-amber-50/40 hover:border-amber-300 hover:shadow-sm'
            : 'border-zinc-200 bg-white hover:border-zinc-300 hover:shadow-sm'
      }`}
    >
      <div className="flex items-start gap-3">
        <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${
          selected ? 'bg-blue-100' : 'bg-zinc-50 group-hover:bg-zinc-100'
        }`}>
          <Plug className={`w-4 h-4 ${selected ? 'text-blue-600' : 'text-zinc-500'}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <p className="text-sm font-semibold text-zinc-800 truncate">{mcp.template.name}</p>
            {onClick && <Settings className={`w-3.5 h-3.5 flex-shrink-0 ${selected ? 'text-blue-400' : 'text-zinc-300 group-hover:text-zinc-400'}`} />}
          </div>
          <p className="text-xs text-zinc-400 mt-0.5 truncate">{mcp.id}</p>
          {mcp.status.error && (
            <p className="text-xs text-zinc-400 truncate">{mcp.status.error}</p>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <span className={`rounded-full border px-2 py-0.5 text-[10px] ${statusTone(status)}`}>
              MCP {statusLabel(status)}
            </span>
            <span className="rounded-full border border-zinc-100 bg-zinc-50 px-2 py-0.5 text-[10px] text-zinc-600">
              工具 {mcp.status.tools_count ?? 0}
            </span>
            {vendor && (
              <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded-md ${vendor.color}`}>{vendor.nameCn}</span>
            )}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-[10px] text-zinc-400">
            <Database className="h-3 w-3 shrink-0 text-zinc-300" />
            <span className="truncate">MCP 服务配置</span>
          </div>
        </div>
      </div>
    </button>
  );
}

// ============================================================================
// Add integration wizard panel (step 1: vendor, step 2: product)
// ============================================================================

function AddDeviceWizardPanel({ templates, instanceCounts, initialVendor, onSelect, onClose }: {
  templates: IntegrationTemplate[];
  instanceCounts: Record<string, number>;
  initialVendor?: DeviceVendor;
  onSelect: (template: IntegrationTemplate) => void;
  onClose: () => void;
}) {
  const [selectedVendor, setSelectedVendor] = useState<DeviceVendor | null>(initialVendor ?? null);

  // Distinct vendor keys from the live template list. Templates whose YAML
  // omits `vendor` are bucketed under the special "(未指定)" key so they
  // remain visible (and obviously misconfigured) instead of disappearing.
  //
  // Order: pinned vendors first (threatbook 微步 is our default), then any
  // other known vendor in catalog order, then unknown/unspecified last.
  const availableVendors = useMemo<DeviceVendor[]>(() => {
    const seen: string[] = [];
    for (const t of templates) {
      const key = t.vendor || '__unspecified__';
      if (!seen.includes(key)) seen.push(key);
    }
    seen.sort((a, b) => {
      const rank = (k: string) => {
        if (k === 'threatbook') return 0;
        if (k === '__unspecified__') return 99;
        return 1;
      };
      const ra = rank(a);
      const rb = rank(b);
      if (ra !== rb) return ra - rb;
      return a.localeCompare(b);
    });
    return seen.map((key) =>
      key === '__unspecified__'
        ? { id: '__unspecified__', nameCn: '未指定厂商', nameEn: 'Unspecified', color: 'bg-zinc-100 text-zinc-600' }
        : vendorPresentation(key),
    );
  }, [templates]);

  const vendorTotalCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const t of templates) {
      const key = t.vendor || '__unspecified__';
      counts[key] = (counts[key] ?? 0) + (instanceCounts[t.id] ?? 0);
    }
    return counts;
  }, [templates, instanceCounts]);

  const vendorTemplates = useMemo(() => {
    if (!selectedVendor) return [];
    return templates.filter((t) => (t.vendor || '__unspecified__') === selectedVendor.id);
  }, [templates, selectedVendor]);

  return (
    <div className="fixed inset-0 z-40 pointer-events-none">
      <button
        type="button"
          aria-label="关闭添加接入面板"
        onClick={onClose}
        className="pointer-events-auto absolute left-0 bottom-0 bg-transparent"
        style={{ top: 64, right: 440 }}
      />
      <div
        className="pointer-events-auto absolute right-0 bottom-0 bg-white shadow-2xl border-l border-zinc-200 flex flex-col"
        style={{ width: 440, top: 64 }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-100 flex-shrink-0">
          <div className="flex items-center gap-2.5">
            {selectedVendor && (
              <button
                onClick={() => setSelectedVendor(null)}
                className="p-1.5 rounded-lg hover:bg-zinc-100 text-zinc-500 hover:text-zinc-700 transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
            )}
            <div>
              <h3 className="text-sm font-semibold text-zinc-900">
                {selectedVendor ? `选择 ${selectedVendor.nameCn} 产品` : '添加接入'}
              </h3>
              <div className="flex items-center gap-1.5 mt-0.5">
                {/* Breadcrumb */}
                <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded-full ${!selectedVendor ? 'bg-blue-100 text-blue-700' : 'bg-zinc-100 text-zinc-500'}`}>
                  1 选择厂商
                </span>
                <ChevronRight className="w-2.5 h-2.5 text-zinc-300" />
                <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded-full ${selectedVendor ? 'bg-blue-100 text-blue-700' : 'bg-zinc-100 text-zinc-400'}`}>
                  2 选择产品
                </span>
                <ChevronRight className="w-2.5 h-2.5 text-zinc-300" />
                <span className="text-[10px] font-medium px-1.5 py-0.5 rounded-full bg-zinc-100 text-zinc-400">
                  3 填写连接
                </span>
              </div>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-zinc-100 text-zinc-400 hover:text-zinc-600">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5">
          {!selectedVendor ? (
            /* Step 1: Vendor selection */
            <>
              <p className="text-xs text-zinc-400 mb-4">选择安全产品所属厂商，共 {availableVendors.length} 家</p>
              <div className="grid grid-cols-2 gap-3">
                {availableVendors.map((vendor) => {
                  const count = vendorTotalCounts[vendor.id] ?? 0;
                  const productCount = templates.filter(
                    (t) => (t.vendor || '__unspecified__') === vendor.id,
                  ).length;
                  return (
                    <button
                      key={vendor.id}
                      onClick={() => setSelectedVendor(vendor)}
                      className="flex flex-col items-center gap-2.5 p-5 rounded-xl border border-zinc-200 bg-white hover:border-blue-300 hover:bg-blue-50/40 transition-all duration-150 group"
                    >
                      <div className={`w-12 h-12 rounded-2xl flex items-center justify-center text-lg font-bold ${vendor.color}`}>
                        {vendor.nameCn[0]}
                      </div>
                      <div className="text-center">
                        <p className="text-sm font-semibold text-zinc-800">{vendor.nameCn}</p>
                        <p className="text-xs text-zinc-400">{vendor.nameEn}</p>
                        <p className="text-[10px] text-zinc-400 mt-0.5">
                          {productCount} 种产品
                          {count > 0 && <span className="text-blue-600 font-medium"> · 已接入 {count} 台</span>}
                        </p>
                      </div>
                      <ChevronRight className="w-3.5 h-3.5 text-zinc-300 group-hover:text-blue-400 transition-colors" />
                    </button>
                  );
                })}
              </div>
            </>
          ) : (
            /* Step 2: Product selection */
            <>
              <p className="text-xs text-zinc-400 mb-4">
                共 {vendorTemplates.length} 款产品，同款产品可多次接入
              </p>
              <div className="space-y-2">
                {vendorTemplates.map((tpl) => {
                  const count = instanceCounts[tpl.id] ?? 0;
                  const isMcp = isMcpTemplate(tpl);
                  return (
                    <button
                      key={tpl.id}
                      onClick={() => onSelect(tpl)}
                      className="w-full text-left flex items-start gap-3 px-4 py-3.5 rounded-xl border border-zinc-100 bg-white hover:border-blue-200 hover:bg-blue-50/30 transition-all group"
                    >
                      <div className="w-9 h-9 rounded-xl bg-zinc-50 group-hover:bg-blue-50 flex items-center justify-center flex-shrink-0 transition-colors">
                        <Plug className="w-4 h-4 text-zinc-400 group-hover:text-blue-500 transition-colors" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between gap-2">
                          <p className="text-sm font-medium text-zinc-800 leading-snug">{tpl.name}</p>
                          {isMcp ? (
                            <span className="text-[10px] text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded-md flex-shrink-0 mt-0.5 font-medium">
                              MCP
                            </span>
                          ) : tpl.version && (
                            <span className="text-[10px] text-zinc-400 bg-zinc-100 px-1.5 py-0.5 rounded-md flex-shrink-0 mt-0.5">
                              v{tpl.version}
                            </span>
                          )}
                        </div>
                        {(tpl.description_cn || tpl.description) && (
                          <p className="text-xs text-zinc-400 mt-0.5 line-clamp-2 leading-relaxed">
                            {tpl.description_cn || tpl.description}
                          </p>
                        )}
                        {count > 0 && (
                          <span className="inline-block mt-1.5 text-[10px] text-blue-600 bg-blue-50 px-1.5 py-0.5 rounded-md font-medium">
                            已接入 {count} 台
                          </span>
                        )}
                      </div>
                      <ChevronRight className="w-4 h-4 text-zinc-300 group-hover:text-blue-400 flex-shrink-0 mt-2 transition-colors" />
                    </button>
                  );
                })}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Device config panel (add / edit)
// ============================================================================

type PanelTab = 'config' | 'tools' | 'sync' | 'overview';

function Toggle({ on, onToggle }: { on: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${on ? 'bg-blue-500' : 'bg-zinc-300'}`}
    >
      <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${on ? 'translate-x-4' : 'translate-x-0.5'}`} />
    </button>
  );
}

function humanizeMcpEnvKey(key: string): string {
  return key
    .replace(/^FLOCKS_/, '')
    .replace(/_/g, ' ')
    .replace(/\bMCP\b/g, 'MCP')
    .replace(/\bURL\b/g, 'URL')
    .replace(/\bAPI\b/g, 'API');
}

function mcpEnvValueForSecret(
  secretKey: string,
  values: Record<string, string>,
  configuredSecrets: Record<string, string> = {},
): string {
  const normalized = secretKey.toLowerCase();
  const envKey = Object.keys(values).find((key) => key.toLowerCase() === normalized);
  if (!envKey) return '';
  return values[envKey] || configuredSecrets[envKey] || '';
}

function resolveMcpTemplateString(
  value: string | undefined,
  values: Record<string, string>,
  configuredSecrets: Record<string, string> = {},
): string {
  if (!value) return '';
  return value
    .replace(/\{secret:([^}]+)\}/g, (_match, secretKey: string) => mcpEnvValueForSecret(secretKey, values, configuredSecrets))
    .replace(/\$\{([^}]+)\}/g, (_match, envKey: string) => values[envKey] || '');
}

function buildMcpRuntimeConfig(
  entry: MCPCatalogEntry,
  values: Record<string, string>,
  enabled: boolean,
  configuredSecrets: Record<string, string> = {},
): Record<string, any> {
  const remote = entry.remote || {};
  const url = remote.url_env
    ? values[remote.url_env] || remote.url || ''
    : resolveMcpTemplateString(remote.url, values);
  const config: Record<string, any> = {
    type: 'remote',
    url,
    enabled,
    transport: remote.transport || 'auto',
  };
  if (remote.headers) {
    const headers = Object.fromEntries(
      Object.entries(remote.headers).map(([key, value]) => [
        key,
        resolveMcpTemplateString(value, values, configuredSecrets),
      ]),
    );
    if (Object.keys(headers).length > 0) config.headers = headers;
  }
  if (remote.auth) {
    config.auth = {
      ...remote.auth,
      value: resolveMcpTemplateString(remote.auth.value, values, configuredSecrets),
    };
  }
  if (remote.oauth !== undefined) config.oauth = remote.oauth;
  if (remote.timeout !== undefined) config.timeout = remote.timeout;
  return config;
}

function splitMcpInstallValues(entry: MCPCatalogEntry, values: Record<string, string>) {
  const credentials: Record<string, string> = {};
  const env_overrides: Record<string, string> = {};
  Object.entries(entry.env_vars || {}).forEach(([key, spec]) => {
    const value = String(values[key] || '').trim();
    if (!value) return;
    if (spec.secret) credentials[key] = value;
    else env_overrides[key] = value;
  });
  return {
    credentials: Object.keys(credentials).length ? credentials : undefined,
    env_overrides: Object.keys(env_overrides).length ? env_overrides : undefined,
  };
}

function validateMcpRequiredFields(
  entry: MCPCatalogEntry,
  values: Record<string, string>,
  configuredSecrets: Record<string, string> = {},
): boolean {
  return !Object.entries(entry.env_vars || {}).some(([key, spec]) => (
    spec.required
    && !String(values[key] || '').trim()
    && !(spec.secret && configuredSecrets[key])
  ));
}

function McpConfigPanel({
  template,
  vendorKey,
  configured,
  onSave,
  onTest,
  onClose,
  onBack,
}: {
  template: IntegrationTemplate & { mcp_entry: MCPCatalogEntry };
  vendorKey?: string;
  configured?: boolean;
  onSave: (
    entry: MCPCatalogEntry,
    values: Record<string, string>,
    enabled: boolean,
    configuredSecrets?: Record<string, string>,
  ) => Promise<{ connectError?: string | null } | void>;
  onTest: (entry: MCPCatalogEntry, values: Record<string, string>, enabled: boolean, configuredSecrets?: Record<string, string>) => Promise<{ success: boolean; message: string }>;
  onClose: () => void;
  onBack?: () => void;
}) {
  const toast = useToast();
  const entry = template.mcp_entry;
  const vendor = vendorKey ? vendorPresentation(vendorKey) : undefined;
  const [values, setValues] = useState<Record<string, string>>(() => {
    const initial: Record<string, string> = {};
    Object.entries(entry.env_vars || {}).forEach(([key, spec]) => {
      initial[key] = spec.default || '';
    });
    return initial;
  });
  const [visibility, setVisibility] = useState<Record<string, boolean>>({});
  const [enabled, setEnabled] = useState(true);
  const [configuredSecrets, setConfiguredSecrets] = useState<Record<string, string>>({});
  const [loadingExisting, setLoadingExisting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const fields = Object.entries(entry.env_vars || {});

  const requireFields = () => {
    if (validateMcpRequiredFields(entry, values, configuredSecrets)) return true;
    toast.error('请填写必填连接参数');
    return false;
  };

  useEffect(() => {
    if (!configured) return;
    let cancelled = false;
    const loadExisting = async () => {
      setLoadingExisting(true);
      try {
        const res = await mcpAPI.get(entry.id);
        if (cancelled) return;
        const detail = res.data;
        const config = detail.config;
        const nextValues: Record<string, string> = {};
        Object.entries(entry.env_vars || {}).forEach(([key, spec]) => {
          nextValues[key] = spec.default || '';
        });
        if (entry.remote?.url_env && typeof config?.url === 'string') {
          nextValues[entry.remote.url_env] = config.url;
        }

        const nextConfiguredSecrets: Record<string, string> = {};
        const headers = config?.headers || {};
        Object.entries(entry.remote?.headers || {}).forEach(([headerName, headerTemplate]) => {
          const configuredValue = headers[headerName];
          if (!configuredValue) return;
          const matches = String(headerTemplate).match(/\{secret:([^}]+)\}/g) || [];
          matches.forEach((match) => {
            const secretKey = match.slice(8, -1).toLowerCase();
            const envKey = Object.keys(entry.env_vars || {}).find((key) => key.toLowerCase() === secretKey);
            if (envKey) nextConfiguredSecrets[envKey] = configuredValue;
          });
        });
        const configuredAuthValue = config?.auth?.value;
        const authTemplate = entry.remote?.auth?.value;
        if (configuredAuthValue && authTemplate) {
          const matches = String(authTemplate).match(/\{secret:([^}]+)\}/g) || [];
          matches.forEach((match) => {
            const secretKey = match.slice(8, -1).toLowerCase();
            const envKey = Object.keys(entry.env_vars || {}).find((key) => key.toLowerCase() === secretKey);
            if (envKey) nextConfiguredSecrets[envKey] = configuredAuthValue;
          });
        }

        setValues(nextValues);
        setConfiguredSecrets(nextConfiguredSecrets);
        setEnabled(detail.status?.status !== 'disabled');
      } catch {
        if (!cancelled) {
          setConfiguredSecrets({});
        }
      } finally {
        if (!cancelled) setLoadingExisting(false);
      }
    };
    void loadExisting();
    return () => { cancelled = true; };
  }, [configured, entry]);

  const handleTest = async () => {
    if (!requireFields()) return;
    setTesting(true);
    setTestResult(null);
    try {
      setTestResult(await onTest(entry, values, enabled, configuredSecrets));
    } catch (error) {
      setTestResult({ success: false, message: apiErrorMessage(error, '连接测试失败') });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    if (!requireFields()) return;
    setSaving(true);
    try {
      const saveResult = await onSave(entry, values, enabled, configuredSecrets);
      if (saveResult?.connectError) {
        toast.warning('MCP 接入已保存，但连接失败', saveResult.connectError);
      } else {
        toast.success('MCP 接入已保存');
      }
    } catch (error) {
      toast.error('保存失败', apiErrorMessage(error, '保存失败'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-40 pointer-events-none">
      <button
        type="button"
        aria-label="关闭 MCP 配置面板"
        onClick={onClose}
        className="pointer-events-auto absolute left-0 bottom-0 bg-transparent"
        style={{ top: 64, right: 480 }}
      />
      <div
        className="pointer-events-auto absolute right-0 bottom-0 bg-white shadow-2xl border-l border-zinc-200 flex flex-col"
        style={{ width: 480, top: 64 }}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-100 flex-shrink-0">
          <div className="flex items-center gap-2.5 min-w-0">
            {onBack && (
              <button onClick={onBack} className="p-1.5 rounded-lg hover:bg-zinc-100 text-zinc-500 hover:text-zinc-700 transition-colors flex-shrink-0">
                <ChevronLeft className="w-4 h-4" />
              </button>
            )}
            <div className="w-9 h-9 rounded-xl bg-zinc-50 flex items-center justify-center flex-shrink-0">
              <Plug className="w-4 h-4 text-zinc-500" />
            </div>
            <div className="min-w-0">
              <h3 className="text-sm font-semibold text-zinc-900 truncate">填写连接</h3>
              <div className="flex items-center gap-1.5 mt-0.5">
                {vendor && <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded-md ${vendor.color}`}>{vendor.nameCn}</span>}
                <span className="rounded-md bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium text-slate-600">MCP</span>
                <span className="text-xs text-zinc-400 truncate">{entry.id}</span>
              </div>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-zinc-100 text-zinc-400 hover:text-zinc-600 flex-shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
          <div>
            <p className="text-sm font-semibold text-zinc-900">{entry.name}</p>
            {(entry.description_cn || entry.description) && (
              <p className="mt-1 text-xs leading-relaxed text-zinc-500">{entry.description_cn || entry.description}</p>
            )}
          </div>

          <div className="space-y-3">
            <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">连接参数</p>
            {loadingExisting && (
              <div className="rounded-lg border border-blue-100 bg-blue-50 px-3 py-2 text-xs text-blue-700">
                正在读取已保存配置...
              </div>
            )}
            {fields.map(([key, spec]) => {
              const isSecret = !!spec.secret;
              const show = !!visibility[key];
              const inputType = isSecret && !show ? 'password' : key.toLowerCase().includes('url') ? 'url' : 'text';
              const hasConfiguredSecret = isSecret && !!configuredSecrets[key] && !values[key];
              return (
                <div key={key}>
                  <label className="block text-xs font-medium text-zinc-600 mb-1">
                    {humanizeMcpEnvKey(key)}
                    {spec.required && <span className="text-red-500 ml-0.5">*</span>}
                  </label>
                  <div className="relative">
                    <input
                      aria-label={key}
                      type={inputType}
                      value={values[key] ?? ''}
                      onChange={(e) => setValues((prev) => ({ ...prev, [key]: e.target.value }))}
                      placeholder={hasConfiguredSecret ? '已保存，留空表示不修改' : spec.description || key}
                      disabled={loadingExisting}
                      className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 pr-10 text-sm text-zinc-900 focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-100"
                    />
                    {isSecret && (
                      <button
                        type="button"
                        onClick={() => setVisibility((prev) => ({ ...prev, [key]: !prev[key] }))}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600"
                      >
                        {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    )}
                  </div>
                  {hasConfiguredSecret ? (
                    <p className="mt-0.5 text-xs text-zinc-400">凭据已保存；输入新值会覆盖原凭据。</p>
                  ) : spec.description && <p className="mt-0.5 text-xs text-zinc-400">{spec.description}</p>}
                </div>
              );
            })}
          </div>

          <div className="rounded-xl border border-zinc-100 divide-y divide-zinc-100">
            <div className="flex items-center justify-between px-4 py-3">
              <div>
                <p className="text-sm font-medium text-zinc-700">启用 MCP</p>
                <p className="text-[11px] text-zinc-400 mt-0.5">启用后 Agent 可以调用该 MCP 暴露的工具</p>
              </div>
              <Toggle on={enabled} onToggle={() => setEnabled((prev) => !prev)} />
            </div>
          </div>

          {testResult && (
            <div className={`rounded-lg px-4 py-3 text-sm flex items-start gap-2 ${
              testResult.success ? 'bg-green-50 text-green-700 border border-green-100' : 'bg-red-50 text-red-600 border border-red-100'
            }`}>
              {testResult.success
                ? <CheckCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                : <XCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />}
              <span>{testResult.message}</span>
            </div>
          )}

          <div className="flex gap-2 pt-1">
            <button
              onClick={handleTest}
              disabled={testing}
              className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-sm rounded-lg border border-zinc-200 text-zinc-600 hover:bg-zinc-50 disabled:opacity-50 transition-colors"
            >
              {testing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
              连通测试
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-sm rounded-lg bg-red-600 text-white hover:bg-red-700 disabled:opacity-50 transition-colors"
            >
              {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
              确认接入
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function DeviceConfigPanel({
  device,
  template,
  vendorKey,
  sync,
  actionLoading,
  onSave,
  onDelete,
  onClose,
  onTest,
  onToggleVerifySsl,
  onToggleEnabled,
  onBack,
  onEnableSync,
  onTestSync,
  onPauseSchedule,
  onResumeSchedule,
  onUpdateScheduleInterval,
  onUpdateSyncCredentials,
}: {
  device?: DeviceIntegration;
  template?: APIServiceSummary;
  vendorKey?: string;
  sync?: DeviceSyncBinding;
  actionLoading?: string | null;
  onSave: (data: { name: string; fields: Record<string, string>; enabled: boolean; verify_ssl: boolean }) => Promise<void>;
  onDelete?: () => Promise<void>;
  onClose: () => void;
  /** Receives the current (unsaved) form values so the probe reflects the
   *  on-screen toggle state instead of whatever was last persisted. */
  onTest?: (overrides: { verify_ssl: boolean; base_url?: string }) => Promise<{ success: boolean; message: string }>;
  /** Persist the SSL toggle immediately (without requiring "保存"). Only
   *  meaningful when editing an existing device — for the "Add device"
   *  wizard the value is held in local state until the row is created. */
  onToggleVerifySsl?: (next: boolean) => Promise<void>;
  onToggleEnabled?: (next: boolean) => Promise<void>;
  onBack?: () => void;
  onEnableSync?: (device: DeviceIntegration, sync: DeviceSyncBinding) => Promise<void>;
  onTestSync?: (source: SecurityConnectorCustomerDataSource) => Promise<void>;
  onPauseSchedule?: (source: SecurityConnectorCustomerDataSource, schedule: SecurityConnectorCustomerSchedule) => Promise<void>;
  onResumeSchedule?: (source: SecurityConnectorCustomerDataSource, schedule: SecurityConnectorCustomerSchedule) => Promise<void>;
  onUpdateScheduleInterval?: (source: SecurityConnectorCustomerDataSource, schedule: SecurityConnectorCustomerSchedule, intervalSeconds: number) => Promise<void>;
  onUpdateSyncCredentials?: (source: SecurityConnectorCustomerDataSource) => void;
}) {
  const toast = useToast();
  const confirm = useConfirm();
  const [tab, setTab] = useState<PanelTab>('config');
  const [name, setName] = useState(device?.name ?? '');
  const [fields, setFields] = useState<Record<string, string>>(() => device ? { ...device.fields } : {});
  const [enabled, setEnabled] = useState(device?.enabled ?? true);
  const [verifySsl, setVerifySsl] = useState(device?.verify_ssl ?? false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [credFields, setCredFields] = useState<APIServiceCredentialField[]>([]);
  const [visibility, setVisibility] = useState<Record<string, boolean>>({});
  const [serviceTools, setServiceTools] = useState<Tool[]>([]);
  const [toolModal, setToolModal] = useState<Tool | null>(null);
  const [metadata, setMetadata] = useState<{ name?: string; version?: string; description?: string; description_cn?: string; docs_url?: string } | null>(null);
  const [toolEnabled, setToolEnabled] = useState<Record<string, boolean>>({});
  const originalMasked = useRef<Record<string, string>>({});

  const serviceId = device?.service_id ?? template?.id ?? '';
  // ``storage_key`` is the versioned, unambiguous identifier
  // (e.g. ``onesig_api_v2_5_3_D20260321``) that tool registrations
  // surface as ``ToolInfoResponse.source_name``. Use it directly for
  // tool filtering so two devices that happen to share a service_id
  // prefix (``onesig`` vs ``onesig_pro``) — or a plugin whose
  // ``service_id`` already contains a ``_v…`` token — never bleed each
  // other's tools into the device-edit panel. ``template?.id`` is also
  // the storage_key (set by the wizard), so the create-mode form
  // resolves to the right key too.
  const storageKey = device?.storage_key ?? template?.id ?? '';
  const vendor = vendorKey ? vendorPresentation(vendorKey) : undefined;

  useEffect(() => {
    if (!serviceId) return;
    providerAPI.getServiceMetadata(serviceId)
      .then((res) => {
        const meta = res.data;
        setMetadata(meta ?? null);
        const schema: APIServiceCredentialField[] = meta?.credential_schema ?? [];
        setCredFields(schema);
        if (device) {
          const masked: Record<string, string> = {};
          schema.forEach((f) => {
            if (f.storage === 'secret' || f.input_type === 'password') {
              masked[f.key] = device.fields?.[f.key] ?? '';
            }
          });
          originalMasked.current = masked;
          setFields({ ...device.fields });
        } else {
          const defaults: Record<string, string> = {};
          schema.forEach((f) => { if (f.default_value) defaults[f.key] = f.default_value; });
          setFields((prev) => ({ ...defaults, ...prev }));
        }
      })
      .catch(() => {});

    toolAPI.list()
      .then((res) => {
        // Match against the device's storage_key exactly. The tool
        // listing endpoint sets ``source_name = tool.provider``, which
        // in turn equals the plugin's storage_key (see
        // ``flocks/tool/tool_loader.py``). An exact comparison keeps
        // multi-version installs of the same product cleanly isolated.
        const matched = (res.data || []).filter(
          (t) => !!storageKey && t.source_name === storageKey,
        );
        setServiceTools(matched);
        const initEnabled: Record<string, boolean> = {};
        matched.forEach((t) => { initEnabled[t.name] = t.enabled; });
        setToolEnabled(initEnabled);
      })
      .catch(() => {});
  }, [device, serviceId, storageKey]);

  const handleSave = async () => {
    if (!name.trim()) { toast.error('请填写设备名称'); return; }
    setSaving(true);
    try {
      const payload: Record<string, string> = { ...fields };
      Object.entries(originalMasked.current).forEach(([k, masked]) => {
        if (payload[k] === masked) payload[k] = '';
      });
      await onSave({ name: name.trim(), fields: payload, enabled, verify_ssl: verifySsl });
      toast.success(device ? '配置已保存' : '设备已添加');
    } catch {
      toast.error('保存失败');
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    if (!onTest) return;
    setTesting(true);
    setTestResult(null);
    try {
      // Probe with the form's current SSL toggle / base_url so the user can
      // validate unsaved changes immediately. Empty base_url means "fall
      // back to whatever is already in the DB".
      // For providers that use host + port (e.g. Sangfor SIP) instead of
      // base_url, construct the URL from those fields when available.
      // If the operator already typed a scheme into ``host``, respect it
      // instead of double-prefixing.
      let candidateBaseUrl = (fields.base_url ?? fields.baseUrl ?? '').trim();
      if (!candidateBaseUrl) {
        const host = (fields.host ?? '').trim();
        const port = (fields.port ?? '').trim();
        if (host) {
          const hasScheme = host.includes('://');
          const prefix = hasScheme ? host : `https://${host}`;
          candidateBaseUrl = port ? `${prefix}:${port}` : prefix;
        }
      }
      setTestResult(await onTest({
        verify_ssl: verifySsl,
        base_url: candidateBaseUrl || undefined,
      }));
    } finally {
      setTesting(false);
    }
  };

  // Toggle SSL on/off and persist immediately (no need to click 保存).
  // Optimistic update with rollback on failure so the UI stays in sync
  // with the backend even when the request errors out.
  const handleToggleSsl = async () => {
    const next = !verifySsl;
    setVerifySsl(next);
    if (!device || !onToggleVerifySsl) {
      return;
    }
    try {
      await onToggleVerifySsl(next);
      toast.success(next ? '已开启 SSL 验证' : '已关闭 SSL 验证');
    } catch {
      setVerifySsl(!next);
      toast.error('保存失败，已回滚');
    }
  };

  // Same immediate-persist pattern for the "启用设备" toggle.
  const handleToggleEnabled = async () => {
    const next = !enabled;
    if (device && onToggleEnabled) {
      const ok = await confirm({
        title: next ? '启用设备' : '停用设备',
        description: next
          ? '启用后 Agent 可以重新调用此设备 API。'
          : '停用后 Agent 将不会调用此设备 API，相关自动化能力会暂停。',
        confirmText: next ? '确认启用' : '确认停用',
        variant: next ? 'default' : 'warning',
      });
      if (!ok) return;
    }
    setEnabled(next);
    if (!device || !onToggleEnabled) {
      return;
    }
    try {
      await onToggleEnabled(next);
      toast.success(next ? '设备已启用' : '设备已停用');
    } catch {
      setEnabled(!next);
      toast.error('保存失败，已回滚');
    }
  };

  const handleDelete = async () => {
    if (!onDelete) return;
    const ok = await confirm({
      title: '删除设备配置',
      description: '删除后 Agent 将无法再调用此设备 API，已保存的连接参数也会移除。',
      confirmText: '确认删除',
      variant: 'danger',
    });
    if (!ok) return;
    setDeleting(true);
    try { await onDelete(); toast.success('已删除设备'); }
    catch { toast.error('删除失败'); }
    finally { setDeleting(false); }
  };

  const handleToggleTool = async (toolName: string, next: boolean) => {
    try {
      await toolAPI.setEnabled(toolName, next);
      setToolEnabled((p) => ({ ...p, [toolName]: next }));
      setServiceTools((prev) => prev.map((t) => t.name === toolName ? { ...t, enabled: next } : t));
    } catch {
      toast.error('操作失败');
    }
  };

  const TABS: { key: PanelTab; label: string; icon: React.ReactNode }[] = [
    { key: 'config', label: '配置', icon: <Settings className="w-3.5 h-3.5" /> },
    { key: 'tools',  label: `工具${serviceTools.length ? ` (${serviceTools.length})` : ''}`, icon: <Wrench className="w-3.5 h-3.5" /> },
    ...(device ? [{ key: 'sync' as const, label: '同步', icon: <Database className="w-3.5 h-3.5" /> }] : []),
    { key: 'overview', label: '概览', icon: <AlertTriangle className="w-3.5 h-3.5 opacity-60" /> },
  ];

  return (
    <>
      <div className="fixed inset-0 z-40 pointer-events-none">
        <button
          type="button"
          aria-label="关闭设备配置面板"
          onClick={onClose}
          className="pointer-events-auto absolute left-0 bottom-0 bg-transparent"
          style={{ top: 64, right: 480 }}
        />
        <div
          className="pointer-events-auto absolute right-0 bottom-0 bg-white shadow-2xl border-l border-zinc-200 flex flex-col"
          style={{ width: 480, top: 64 }}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-100 flex-shrink-0">
            <div className="flex items-center gap-2.5 min-w-0">
              {onBack && (
                <button onClick={onBack} className="p-1.5 rounded-lg hover:bg-zinc-100 text-zinc-500 hover:text-zinc-700 transition-colors flex-shrink-0">
                  <ChevronLeft className="w-4 h-4" />
                </button>
              )}
              <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${device ? 'bg-blue-50' : 'bg-zinc-50'}`}>
                {device ? <PlugZap className="w-4 h-4 text-blue-500" /> : <Plus className="w-4 h-4 text-zinc-400" />}
              </div>
              <div className="min-w-0">
                <h3 className="text-sm font-semibold text-zinc-900 truncate">{device ? device.name : '填写连接'}</h3>
                <div className="flex items-center gap-1.5 mt-0.5">
                  {vendor && <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded-md ${vendor.color}`}>{vendor.nameCn}</span>}
                  <span className="text-xs text-zinc-400 truncate">{device?.storage_key ?? template?.id}</span>
                </div>
              </div>
            </div>
            <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-zinc-100 text-zinc-400 hover:text-zinc-600 flex-shrink-0">
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Tab bar */}
          <div className="flex border-b border-zinc-100 flex-shrink-0 px-1">
            {TABS.map(({ key, label, icon }) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                  tab === key
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-zinc-500 hover:text-zinc-700'
                }`}
              >
                {icon}{label}
              </button>
            ))}
          </div>

          {/* Tab body */}
          <div className="flex-1 overflow-y-auto">

            {/* ── 配置 tab ── */}
            {tab === 'config' && (
              <div className="px-5 py-4 space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-zinc-500 mb-1.5">
                    设备名称 <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="例如：总部 AF 防火墙"
                    className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-100"
                  />
                </div>

                {credFields.length > 0 && (
                  <div className="space-y-3">
                    <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">连接参数</p>
                    {credFields.map((f) => {
                      const isSecret = f.storage === 'secret' || f.input_type === 'password';
                      const show = !!visibility[f.key];
                      const hasExisting = !!device?.fields_set?.[f.key];
                      return (
                        <div key={f.key}>
                          <label className="block text-xs font-medium text-zinc-600 mb-1">
                            {f.label}
                            {f.required && !hasExisting && <span className="text-red-500 ml-0.5">*</span>}
                          </label>
                          <div className="relative">
                            <input
                              type={isSecret && !show ? 'password' : 'text'}
                              value={fields[f.key] ?? ''}
                              onChange={(e) => setFields((p) => ({ ...p, [f.key]: e.target.value }))}
                              placeholder={f.default_value ?? ''}
                              className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-100 pr-10"
                            />
                            {isSecret && (
                              <button
                                type="button"
                                onClick={() => setVisibility((p) => ({ ...p, [f.key]: !p[f.key] }))}
                                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600"
                              >
                                {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                              </button>
                            )}
                          </div>
                          {isSecret && device && hasExisting && (
                            <p className="mt-0.5 text-[11px] text-zinc-400">已配置 · 保持不变请勿修改，清空则删除</p>
                          )}
                          {f.description && <p className="mt-0.5 text-xs text-zinc-400">{f.description}</p>}
                        </div>
                      );
                    })}
                  </div>
                )}

                <div className="rounded-xl border border-zinc-100 divide-y divide-zinc-100">
                  <div className="flex items-center justify-between px-4 py-3">
                    <div>
                      <p className="text-sm font-medium text-zinc-700">SSL 验证</p>
                      <p className="text-[11px] text-zinc-400 mt-0.5">关闭可访问自签名证书的内网设备</p>
                    </div>
                    <Toggle on={verifySsl} onToggle={handleToggleSsl} />
                  </div>
                  <div className="flex items-center justify-between px-4 py-3">
                    <div>
                      <p className="text-sm font-medium text-zinc-700">启用设备</p>
                      <p className="text-[11px] text-zinc-400 mt-0.5">关闭后 Agent 不会调用此设备的工具</p>
                    </div>
                    <Toggle on={enabled} onToggle={handleToggleEnabled} />
                  </div>
                </div>

                {testResult && (
                  <div className={`rounded-lg px-4 py-3 text-sm flex items-start gap-2 ${
                    testResult.success ? 'bg-green-50 text-green-700 border border-green-100' : 'bg-red-50 text-red-600 border border-red-100'
                  }`}>
                    {testResult.success
                      ? <CheckCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                      : <XCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />}
                    <span>{testResult.message}</span>
                  </div>
                )}

                <div className="space-y-2 pt-1">
                  <div className="flex gap-2">
                    {device && onTest && (
                      <button
                        onClick={handleTest}
                        disabled={testing}
                        className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-sm rounded-lg border border-zinc-200 text-zinc-600 hover:bg-zinc-50 disabled:opacity-50 transition-colors"
                      >
                        {testing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
                        连通测试
                      </button>
                    )}
                    <button
                      onClick={handleSave}
                      disabled={saving}
                      className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-sm rounded-lg bg-red-600 text-white hover:bg-red-700 disabled:opacity-50 transition-colors"
                    >
                      {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
                      {device ? '保存配置' : '确认接入'}
                    </button>
                  </div>
                  {device && onDelete && (
                    <button
                      onClick={handleDelete}
                      disabled={deleting}
                      className="w-full flex items-center justify-center gap-1.5 py-2 text-sm rounded-lg border border-red-100 text-red-500 hover:bg-red-50 disabled:opacity-50 transition-colors"
                    >
                      {deleting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                      删除设备
                    </button>
                  )}
                </div>
              </div>
            )}

            {/* ── 工具 tab ── */}
            {tab === 'tools' && (
              <div className="px-5 py-4">
                {serviceTools.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-400 gap-2">
                    <Wrench className="w-8 h-8 opacity-30" />
                    <p className="text-sm">暂无关联工具</p>
                  </div>
                ) : (
                  <div className="rounded-xl border border-zinc-100 overflow-hidden">
                    <table className="w-full table-fixed divide-y divide-zinc-100">
                      <thead className="bg-zinc-50">
                        <tr>
                          <th className="w-[38%] px-4 py-2.5 text-left text-xs font-medium text-zinc-500">工具名称</th>
                          <th className="px-4 py-2.5 text-left text-xs font-medium text-zinc-500">描述</th>
                          <th className="w-[72px] px-4 py-2.5 text-left text-xs font-medium text-zinc-500">状态</th>
                          <th className="w-[80px] px-4 py-2.5 text-right text-xs font-medium text-zinc-500">操作</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-100 bg-white">
                        {serviceTools.map((tool) => {
                          const isOn = toolEnabled[tool.name] ?? tool.enabled;
                          return (
                            <tr key={tool.name} className="hover:bg-zinc-50 transition-colors">
                              <td className="px-4 py-3 truncate">
                                <span className="text-xs font-mono text-zinc-800">{tool.name}</span>
                              </td>
                              <td className="px-4 py-3">
                                <span className="text-xs text-zinc-500 line-clamp-2 leading-relaxed">
                                  {tool.description_cn || tool.description}
                                </span>
                              </td>
                              <td className="px-4 py-3">
                                <Toggle on={isOn} onToggle={() => handleToggleTool(tool.name, !isOn)} />
                              </td>
                              <td className="px-4 py-3 text-right">
                                <button
                                  onClick={() => setToolModal(tool)}
                                  className="text-xs text-blue-600 hover:text-blue-800 font-medium"
                                >
                                  测试 / 详情
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* ── 同步 tab ── */}
            {tab === 'sync' && device && sync && (
              <div className="px-5 py-4 space-y-4">
                {sync.source ? (
                  <>
                    <div className="rounded-xl border border-zinc-100 bg-white px-4 py-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-sm font-semibold text-zinc-900">{sync.source.name}</p>
                          <p className="mt-1 text-xs text-zinc-500">{sync.message}</p>
                        </div>
                        <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[11px] ${statusTone(sync.source.sync_status)}`}>
                          {statusLabel(sync.source.sync_status)}
                        </span>
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {sync.capabilities.map((capability) => (
                          <span key={capability} className="rounded-md bg-zinc-50 px-2 py-1 text-[11px] text-zinc-600">
                            {capabilityLabel(capability)}
                          </span>
                        ))}
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={() => onEnableSync?.(device, sync)}
                          disabled={actionLoading === `enable-sync:${device.id}:${sync.source.id}`}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-zinc-900 px-3 py-1.5 text-xs text-white hover:bg-zinc-800 disabled:opacity-50"
                        >
                          {actionLoading === `enable-sync:${device.id}:${sync.source.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Database className="h-3.5 w-3.5" />}
                          {sync.state === 'active' ? '重新绑定同步' : '启用数据同步'}
                        </button>
                        <button
                          type="button"
                          onClick={() => onTestSync?.(sync.source!)}
                          disabled={actionLoading === `test:${sync.source.id}`}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-200 px-3 py-1.5 text-xs text-zinc-600 hover:bg-zinc-50 disabled:opacity-50"
                        >
                          {actionLoading === `test:${sync.source.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Activity className="h-3.5 w-3.5" />}
                          测试同步连接
                        </button>
                        {sync.source.actions.some((action) => action.kind === 'update_credentials') && hasEditableCredentialFields(sync.source) && (
                          <button
                            type="button"
                            onClick={() => onUpdateSyncCredentials?.(sync.source!)}
                            className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-200 px-3 py-1.5 text-xs text-zinc-600 hover:bg-zinc-50"
                          >
                            <KeyRound className="h-3.5 w-3.5" />
                            更新同步凭据
                          </button>
                        )}
                      </div>
                    </div>

                    {sync.source.schedules.length > 0 ? (
                      <div className="rounded-xl border border-zinc-100 overflow-hidden">
                        {sync.source.schedules.map((schedule) => (
                          <div key={schedule.id} className="flex flex-col gap-2 border-b border-zinc-100 px-4 py-3 last:border-b-0 sm:flex-row sm:items-center sm:justify-between">
                            <div className="min-w-0">
                              <div className="text-xs font-medium text-zinc-800">{capabilityLabel(schedule.capability || '')}</div>
                              <div className="mt-0.5 text-[11px] text-zinc-400">
                                {(schedule.mode === 'full' ? '全量' : '增量')} · 每 {formatSyncInterval(schedule.interval_seconds)}
                                {schedule.message ? ` · ${schedule.message}` : ''}
                              </div>
                            </div>
                            <div className="flex shrink-0 flex-wrap items-center gap-2">
                              <span className={`rounded-full border px-2 py-0.5 text-[10px] ${statusTone(schedule.status)}`}>
                                {statusLabel(schedule.status)}
                              </span>
                              <select
                                aria-label={`${capabilityLabel(schedule.capability || '')} 同步频率`}
                                value={String(schedule.interval_seconds || 3600)}
                                onChange={(event) => {
                                  const next = Number(event.target.value);
                                  if (Number.isFinite(next) && next > 0) {
                                    void onUpdateScheduleInterval?.(sync.source!, schedule, next);
                                  }
                                }}
                                disabled={!schedule.capability || actionLoading === `frequency:${schedule.id}`}
                                className="h-7 rounded-md border border-zinc-200 bg-white px-2 text-[11px] text-zinc-600 hover:bg-zinc-50 disabled:opacity-50"
                              >
                                {scheduleIntervalOptions(schedule.interval_seconds).map((seconds) => (
                                  <option key={seconds} value={seconds}>每 {formatSyncInterval(seconds)}</option>
                                ))}
                              </select>
                              {schedule.status === 'paused' || !schedule.enabled ? (
                                <button
                                  type="button"
                                  onClick={() => onResumeSchedule?.(sync.source!, schedule)}
                                  disabled={actionLoading === `resume:${schedule.id}`}
                                  className="inline-flex items-center gap-1 rounded-md border border-zinc-200 px-2 py-1 text-[11px] text-zinc-600 hover:bg-zinc-50 disabled:opacity-50"
                                >
                                  {actionLoading === `resume:${schedule.id}` ? <Loader2 className="h-3 w-3 animate-spin" /> : <PlayCircle className="h-3 w-3" />}
                                  恢复
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => onPauseSchedule?.(sync.source!, schedule)}
                                  disabled={actionLoading === `pause:${schedule.id}`}
                                  className="inline-flex items-center gap-1 rounded-md border border-zinc-200 px-2 py-1 text-[11px] text-zinc-600 hover:bg-zinc-50 disabled:opacity-50"
                                >
                                  {actionLoading === `pause:${schedule.id}` ? <Loader2 className="h-3 w-3 animate-spin" /> : <PauseCircle className="h-3 w-3" />}
                                  暂停
                                </button>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="rounded-xl border border-blue-100 bg-blue-50 px-4 py-3 text-xs text-blue-700">
                        该安全产品已有标准化同步映射，但还没有创建同步调度。点击“启用数据同步”后会为当前设备创建调度。
                      </div>
                    )}
                  </>
                ) : (
                  <div className="rounded-xl border border-zinc-200 bg-zinc-50 px-4 py-6 text-center">
                    <Database className="mx-auto h-7 w-7 text-zinc-300" />
                    <p className="mt-3 text-sm font-semibold text-zinc-700">当前设备暂未提供数据同步</p>
                    <p className="mx-auto mt-1 max-w-sm text-xs leading-relaxed text-zinc-400">
                      设备 API 和工具调用仍可使用；要进入统一资产、告警、风险分析，需要为该产品补充 connector manifest、adapter 和字段 mapping。
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* ── 概览 tab ── */}
            {tab === 'overview' && (
              <div className="px-5 py-4 space-y-3">
                <div className="rounded-xl border border-zinc-100 divide-y divide-zinc-100 overflow-hidden">
                  {[
                    { label: '服务名称', value: metadata?.name || serviceId },
                    metadata?.version ? { label: '版本', value: metadata.version } : null,
                    { label: '工具数量', value: String(serviceTools.length) },
                    vendor ? { label: '厂商', value: vendor.nameCn } : null,
                    device?.storage_key ? { label: 'Storage Key', value: device.storage_key } : null,
                    device?.service_id ? { label: 'Service ID', value: device.service_id } : null,
                  ].filter(Boolean).map((row) => (
                    <div key={row!.label} className="flex justify-between items-center px-4 py-2.5 gap-4">
                      <span className="text-sm text-zinc-500 shrink-0">{row!.label}</span>
                      <span className="text-sm text-zinc-900 truncate text-right">{row!.value}</span>
                    </div>
                  ))}
                </div>

                {(metadata?.description_cn || metadata?.description) && (
                  <div className="rounded-xl border border-zinc-100 px-4 py-3">
                    <p className="text-xs font-semibold text-zinc-400 mb-1.5 uppercase tracking-wide">服务简介</p>
                    <p className="text-sm text-zinc-600 leading-relaxed whitespace-pre-wrap">
                      {metadata?.description_cn || metadata?.description}
                    </p>
                  </div>
                )}

                {metadata?.docs_url && (
                  <a
                    href={metadata.docs_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-800 px-1"
                  >
                    <ChevronRight className="w-4 h-4" />
                    查看 API 文档
                  </a>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {toolModal && (
        <ToolDetailModal
          tool={toolModal}
          initialSection="test"
          onClose={() => setToolModal(null)}
        />
      )}
    </>
  );
}

// ============================================================================
// Group banner (inline rename for the single default room)
// ============================================================================

function GroupBanner({ group, onRenamed }: {
  group: DeviceGroup | undefined;
  onRenamed: () => void;
}) {
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(group?.name ?? '');
  const [saving, setSaving] = useState(false);

  useEffect(() => { setDraft(group?.name ?? ''); }, [group?.name]);

  if (!group) return null;

  const startEdit = () => { setDraft(group.name); setEditing(true); };
  const cancelEdit = () => { setDraft(group.name); setEditing(false); };
  const saveEdit = async () => {
    const next = draft.trim();
    if (!next || next === group.name) { cancelEdit(); return; }
    setSaving(true);
    try {
      await deviceAPI.updateGroup(group.id, { name: next });
      toast.success('机房名称已更新');
      setEditing(false);
      onRenamed();
    } catch {
      toast.error('更新失败');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="px-6 py-2.5 border-b border-zinc-100 bg-zinc-50/60 flex items-center gap-2">
      <Server className="w-4 h-4 text-zinc-400 flex-shrink-0" />
      <span className="text-xs text-zinc-400">当前机房</span>
      {editing ? (
        <>
          <input
            autoFocus
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') void saveEdit();
              if (e.key === 'Escape') cancelEdit();
            }}
            disabled={saving}
            maxLength={40}
            className="text-sm font-medium text-zinc-800 bg-white border border-zinc-200 rounded-md px-2 py-1 focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-100 w-48"
          />
          <button
            onClick={() => void saveEdit()}
            disabled={saving}
            className="p-1 rounded-md text-blue-600 hover:bg-blue-50 disabled:opacity-50"
            title="保存"
          >
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
          </button>
          <button
            onClick={cancelEdit}
            disabled={saving}
            className="p-1 rounded-md text-zinc-400 hover:bg-zinc-100"
            title="取消"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </>
      ) : (
        <>
          <span className="text-sm font-medium text-zinc-800 truncate">{group.name}</span>
          <button
            onClick={startEdit}
            className="p-1 rounded-md text-zinc-400 hover:text-zinc-600 hover:bg-zinc-100"
            title="重命名"
          >
            <Pencil className="w-3 h-3" />
          </button>
        </>
      )}
    </div>
  );
}


function groupIntegrationPackages(packages: IntegrationPackageSummary[]) {
  return packages.reduce<Record<string, IntegrationPackageSummary[]>>((groups, pkg) => {
    const key = `${pkg.vendor || 'Unknown'} / ${pkg.category || 'uncategorized'}`;
    groups[key] = groups[key] || [];
    groups[key].push(pkg);
    return groups;
  }, {});
}

function BuiltInIntegrationPackagesSection({ packages }: { packages: IntegrationPackageSummary[] }) {
  const grouped = useMemo(() => groupIntegrationPackages(packages), [packages]);
  const groups = Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b));
  const [planningKey, setPlanningKey] = useState<string | null>(null);
  const [planResult, setPlanResult] = useState<IntegrationCapabilityPlanResponse | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);

  const handleDryRunPlan = async (pkg: IntegrationPackageSummary, capability: string) => {
    const key = `${pkg.package_id}:${capability}`;
    setPlanningKey(key);
    setPlanError(null);
    try {
      const response = await securityAPI.planIntegrationCapability({
        package_id: pkg.package_id,
        capability,
        mode: 'manual',
        params: {},
        dry_run: true,
      });
      setPlanResult(response.data);
    } catch (error) {
      setPlanError(apiErrorMessage(error, '生成 dry-run plan 失败'));
    } finally {
      setPlanningKey(null);
    }
  };

  return (
    <section className="mt-6">
      <div className="flex items-center gap-2 mb-3">
        <Database className="w-4 h-4 text-indigo-600" />
        <h3 className="text-sm font-semibold text-zinc-800">Built-in Integration Packages</h3>
        <span className="text-xs text-zinc-400 bg-zinc-100 px-1.5 py-0.5 rounded-md">内置集成包</span>
        <span className="text-xs text-zinc-400 bg-zinc-100 px-1.5 py-0.5 rounded-md">{packages.length}</span>
      </div>
      <div className="mb-3 rounded-xl border border-indigo-100 bg-indigo-50 px-4 py-3 text-xs text-indigo-800">
        This is package metadata only. Dry-run Plan only generates an execution plan; it does not connect to devices, sync data, create alerts, or read credentials.<br />
        当前仅展示集成包元数据。“生成计划”只生成执行计划，不连接设备、不同步、不创建告警、不读取凭据。
      </div>
      {planError && (
        <div className="mb-3 rounded-xl border border-red-100 bg-red-50 px-4 py-3 text-xs text-red-700">
          {planError}
        </div>
      )}
      {planResult && (
        <div className="mb-3 rounded-xl border border-emerald-100 bg-emerald-50 px-4 py-3 text-xs text-emerald-900">
          <div className="mb-2 flex items-center justify-between gap-2">
            <div className="font-semibold">Dry-run Plan / 生成计划：{planResult.package_id} · {planResult.capability}</div>
            <button onClick={() => setPlanResult(null)} className="rounded-md p-1 text-emerald-700 hover:bg-emerald-100" title="关闭">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="grid gap-2 md:grid-cols-2">
            <div><span className="font-medium">Status:</span> {planResult.status}</div>
            <div><span className="font-medium">Mode:</span> {String(planResult.mode || 'manual')} · <span className="font-medium">Dry-run:</span> {String(planResult.dry_run ?? planResult.request_summary?.dry_run ?? true)}</div>
          </div>
          <div className="mt-2 grid gap-2 lg:grid-cols-2">
            {[
              ['request_summary', planResult.request_summary],
              ['capability_summary', planResult.capability_summary],
              ['safety_summary', planResult.safety_summary],
              ['limitations', planResult.limitations],
            ].map(([label, value]) => (
              <div key={label as string} className="rounded-lg bg-white/70 p-2">
                <div className="mb-1 font-medium text-emerald-800">{label as string}</div>
                <pre className="max-h-44 overflow-auto whitespace-pre-wrap break-words text-[11px] text-zinc-700">{JSON.stringify(value || {}, null, 2)}</pre>
              </div>
            ))}
          </div>
        </div>
      )}
      {groups.length === 0 ? (
        <div className="rounded-xl border border-dashed border-zinc-200 bg-white p-4 text-sm text-zinc-500">
          暂无内置集成包元数据。
        </div>
      ) : (
        <div className="space-y-4">
          {groups.map(([group, items]) => (
            <div key={group}>
              <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-500">{group}</div>
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-2 xl:grid-cols-3">
                {items.map((pkg) => (
                  <div key={pkg.package_id} className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-sm font-semibold text-zinc-900">{pkg.name}</div>
                        <div className="mt-1 text-xs text-zinc-500">{pkg.vendor} · {pkg.product}</div>
                      </div>
                      <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-[11px] font-medium text-zinc-600">
                        {pkg.category}
                      </span>
                    </div>
                    {pkg.description && <p className="mt-2 line-clamp-2 text-xs text-zinc-500">{pkg.description}</p>}
                    <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-zinc-600">
                      <div><span className="text-zinc-400">Auth:</span> {pkg.auth_type}</div>
                      <div><span className="text-zinc-400">Capabilities:</span> {pkg.capabilities.length}</div>
                      <div><span className="text-zinc-400">Sensitive fields:</span> {pkg.sensitive_fields.length}</div>
                      <div><span className="text-zinc-400">Version:</span> {pkg.version}</div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {pkg.capabilities.map((capability) => {
                        const key = `${pkg.package_id}:${capability}`;
                        return (
                          <span key={capability} className="inline-flex items-center gap-1 rounded-full bg-blue-50 px-2 py-0.5 text-[11px] text-blue-700">
                            <span>{capability}</span>
                            <button
                              type="button"
                              onClick={() => handleDryRunPlan(pkg, capability)}
                              disabled={planningKey === key}
                              className="ml-1 rounded-full bg-white px-1.5 py-0.5 text-[10px] font-medium text-indigo-700 hover:bg-indigo-100 disabled:cursor-not-allowed disabled:opacity-60"
                              title="只生成执行计划，不连接设备、不同步、不创建告警、不读取凭据。"
                            >
                              {planningKey === key ? 'Planning...' : 'Dry-run Plan / 生成计划'}
                            </button>
                          </span>
                        );
                      })}
                    </div>
                    <div className="mt-3 space-y-1 text-xs text-zinc-600">
                      <div className="rounded-lg bg-emerald-50 px-2 py-1 text-emerald-700">
                        Raw response: {pkg.raw_response_policy === 'transient_only' ? 'transient only' : pkg.raw_response_policy}
                      </div>
                      <div className="rounded-lg bg-rose-50 px-2 py-1 text-rose-700">
                        Raw log storage: {pkg.raw_log_storage}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}


function maskSecretRef(ref?: string | null) {
  if (!ref) return '-';
  if (ref.startsWith('credprof_')) return ref;
  const parts = ref.split('/').filter(Boolean);
  if (parts.length >= 3) return `${parts[0]}/.../${parts[parts.length - 1]}`;
  return 'configured reference';
}

function valueOrDash(value?: string | number | boolean | null) {
  if (value === undefined || value === null || value === '') return '-';
  return String(value);
}

function SectionCard({
  title,
  subtitle,
  count,
  children,
}: {
  title: string;
  subtitle: string;
  count?: number | string;
  children: ReactNode;
}) {
  return (
    <section className="mt-6 rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-zinc-900">{title}</h3>
          <p className="mt-1 text-xs text-zinc-500">{subtitle}</p>
        </div>
        <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-xs font-medium text-zinc-600">{count ?? '-'}</span>
      </div>
      {children}
    </section>
  );
}

function EmptyState({ text }: { text: string }) {
  return <div className="rounded-xl border border-dashed border-zinc-200 bg-zinc-50 p-4 text-sm text-zinc-500">{text}</div>;
}

function LoadHint({ error }: { error?: string | null }) {
  if (!error) return null;
  return <div className="mb-3 rounded-xl border border-amber-100 bg-amber-50 px-4 py-3 text-xs text-amber-700">{error}</div>;
}

function IntegrationCenterOverview({
  counts,
}: {
  counts: Record<string, number | null>;
}) {
  const cards = [
    ['Integration Packages', '集成包', counts.packages],
    ['Integration Instances', '集成实例', counts.instances],
    ['Credential Profiles', '凭据配置引用', counts.credentials],
    ['Sync Profiles', '同步策略', counts.syncProfiles],
    ['Integration Runs', '运行记录', counts.runs],
  ];
  return (
    <SectionCard title="Overview / 概览" subtitle="只读汇总当前 Integration Center 元数据范围。" count="readonly">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {cards.map(([label, cn, value]) => (
          <div key={label as string} className="rounded-xl border border-zinc-100 bg-zinc-50 p-3">
            <div className="text-xs text-zinc-500">{label as string}</div>
            <div className="mt-1 text-2xl font-semibold text-zinc-900">{value === null ? '-' : value}</div>
            <div className="mt-1 text-[11px] text-zinc-400">{cn as string}</div>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}

function IntegrationInstancesSection({ instances, packages, error }: { instances: IntegrationInstance[]; packages: IntegrationPackageSummary[]; error?: string | null }) {
  const packageById = useMemo(() => Object.fromEntries(packages.map((pkg) => [pkg.package_id, pkg])), [packages]);
  return (
    <SectionCard title="Integration Instances / 集成实例" subtitle="集成实例仅保存连接目标和元数据，不保存凭据值，不执行连接测试。" count={error ? '-' : instances.length}>
      <LoadHint error={error} />
      {instances.length === 0 ? <EmptyState text="暂无集成实例元数据。" /> : (
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="text-zinc-400"><tr>{['display_name','package_id','vendor/product','base_url','enabled','health_status','credential_profile_id','environment','updated_at / created_at'].map((h) => <th key={h} className="px-2 py-2 font-medium">{h}</th>)}</tr></thead>
            <tbody className="divide-y divide-zinc-100">
              {instances.map((item) => {
                const pkg = packageById[item.package_id];
                return <tr key={item.instance_id} className="align-top text-zinc-700"><td className="px-2 py-2 font-medium">{item.display_name}</td><td className="px-2 py-2">{item.package_id}</td><td className="px-2 py-2">{item.vendor || pkg?.vendor || '-'} / {item.product || pkg?.product || '-'}</td><td className="px-2 py-2">{valueOrDash(item.base_url)}</td><td className="px-2 py-2">{String(item.enabled)}</td><td className="px-2 py-2">{item.health_status}</td><td className="px-2 py-2">{valueOrDash(item.credential_profile_id)}</td><td className="px-2 py-2">{item.environment}</td><td className="px-2 py-2">{valueOrDash(item.updated_at)} / {valueOrDash(item.created_at)}</td></tr>;
              })}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  );
}

function CredentialProfilesSection({ profiles, error }: { profiles: CredentialProfile[]; error?: string | null }) {
  return (
    <SectionCard title="Credential Profiles / 凭据配置引用" subtitle="仅展示凭据配置引用和字段名；不展示明文 secret，不读取 credential value。" count={error ? '-' : profiles.length}>
      <LoadHint error={error} />
      {profiles.length === 0 ? <EmptyState text="暂无凭据配置引用。" /> : <div className="grid gap-3 lg:grid-cols-2">{profiles.map((p) => <div key={p.credential_profile_id} className="rounded-xl border border-zinc-100 bg-zinc-50 p-3 text-xs text-zinc-700"><div className="font-semibold text-zinc-900">{p.display_name}</div><div className="mt-2 grid gap-1 sm:grid-cols-2"><div>profile_type: {p.profile_type}</div><div>status: {p.status}</div><div>package_id: {valueOrDash(p.package_id)}</div><div>instance_id: {valueOrDash(p.instance_id)}</div><div>configured_fields: {(p.configured_fields || []).join(', ') || '-'}</div><div>required_fields: {(p.required_fields || []).join(', ') || '-'}</div><div>secret_ref: {maskSecretRef(p.secret_ref)}</div><div>updated_at / created_at: {valueOrDash(p.updated_at)} / {valueOrDash(p.created_at)}</div></div></div>)}</div>}
    </SectionCard>
  );
}

function SyncPlanResultCard({ result, onClose }: { result: SyncEnginePlanResult; onClose: () => void }) {
  const summaryBlocks: Array<[string, unknown]> = [
    ['request_summary', result.request_summary],
    ['plan_summary', result.plan_summary],
    ['safety_summary', result.safety_summary],
  ];
  return (
    <div className="mt-3 rounded-xl border border-emerald-100 bg-emerald-50 px-4 py-3 text-xs text-emerald-900">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="font-semibold">Latest Plan Result / 最近生成计划：{result.sync_profile_id}</div>
        <button type="button" onClick={onClose} className="rounded-md p-1 text-emerald-700 hover:bg-emerald-100" title="关闭">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="grid gap-2 md:grid-cols-3">
        <div><span className="font-medium">status:</span> {result.status}</div>
        <div><span className="font-medium">run_id:</span> {valueOrDash(result.run_id)}</div>
        <div><span className="font-medium">dry_run:</span> {String(result.dry_run)}</div>
        <div><span className="font-medium">package_id:</span> {valueOrDash(result.package_id)}</div>
        <div><span className="font-medium">instance_id:</span> {valueOrDash(result.instance_id)}</div>
        <div><span className="font-medium">capability:</span> {valueOrDash(result.capability)}</div>
      </div>
      {(result.limitations.length > 0 || result.errors.length > 0) && (
        <div className="mt-2 grid gap-2 md:grid-cols-2">
          <div className="rounded-lg bg-white/70 p-2"><div className="mb-1 font-medium">limitations</div><ul className="list-disc pl-4 text-zinc-700">{result.limitations.length ? result.limitations.map((item, idx) => <li key={idx}>{item}</li>) : <li>-</li>}</ul></div>
          <div className="rounded-lg bg-white/70 p-2"><div className="mb-1 font-medium">errors</div><ul className="list-disc pl-4 text-zinc-700">{result.errors.length ? result.errors.map((item, idx) => <li key={idx}>{item}</li>) : <li>-</li>}</ul></div>
        </div>
      )}
      <div className="mt-2 grid gap-2 lg:grid-cols-3">
        {summaryBlocks.map(([label, value]) => (
          <details key={label} className="rounded-lg bg-white/70 p-2">
            <summary className="cursor-pointer font-medium text-emerald-800">{label}</summary>
            <pre className="mt-2 max-h-44 overflow-auto whitespace-pre-wrap break-words text-[11px] text-zinc-700">{JSON.stringify(value || {}, null, 2)}</pre>
          </details>
        ))}
      </div>
    </div>
  );
}

function SyncPreviewResultCard({ result, onClose }: { result: ManualSyncPreviewResult; onClose: () => void }) {
  const summaryBlocks: Array<[string, unknown]> = [
    ['item_refs', result.item_refs],
    ['event_summaries', result.event_summaries],
    ['request_summary', result.request_summary],
    ['adapter_summary', result.adapter_summary],
    ['mapping_summary', result.mapping_summary],
    ['dispatch_summary', result.dispatch_summary],
    ['safety_summary', result.safety_summary],
  ];
  return (
    <div className="mt-3 rounded-xl border border-sky-100 bg-sky-50 px-4 py-3 text-xs text-sky-900">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="font-semibold">Latest Preview Result / 最近预览结果：{result.sync_profile_id}</div>
        <button type="button" onClick={onClose} className="rounded-md p-1 text-sky-700 hover:bg-sky-100" title="关闭">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="grid gap-2 md:grid-cols-4">
        <div><span className="font-medium">status:</span> {result.status}</div>
        <div><span className="font-medium">run_id:</span> {valueOrDash(result.run_id)}</div>
        <div><span className="font-medium">dry_run:</span> {String(result.dry_run)}</div>
        <div><span className="font-medium">preview_only:</span> {String(result.preview_only)}</div>
        <div><span className="font-medium">package_id:</span> {valueOrDash(result.package_id)}</div>
        <div><span className="font-medium">instance_id:</span> {valueOrDash(result.instance_id)}</div>
        <div><span className="font-medium">capability:</span> {valueOrDash(result.capability)}</div>
        <div><span className="font-medium">adapter_id:</span> {valueOrDash(result.adapter_id)}</div>
        <div><span className="font-medium">fetched_count:</span> {result.fetched_count}</div>
        <div><span className="font-medium">mapped_count:</span> {result.mapped_count}</div>
        <div><span className="font-medium">preview_count:</span> {result.preview_count}</div>
      </div>
      {(result.limitations.length > 0 || result.warnings.length > 0 || result.errors.length > 0) && (
        <div className="mt-2 grid gap-2 md:grid-cols-3">
          <div className="rounded-lg bg-white/70 p-2"><div className="mb-1 font-medium">limitations</div><ul className="list-disc pl-4 text-zinc-700">{result.limitations.length ? result.limitations.map((item, idx) => <li key={idx}>{item}</li>) : <li>-</li>}</ul></div>
          <div className="rounded-lg bg-white/70 p-2"><div className="mb-1 font-medium">warnings</div><ul className="list-disc pl-4 text-zinc-700">{result.warnings.length ? result.warnings.map((item, idx) => <li key={idx}>{item}</li>) : <li>-</li>}</ul></div>
          <div className="rounded-lg bg-white/70 p-2"><div className="mb-1 font-medium">errors</div><ul className="list-disc pl-4 text-zinc-700">{result.errors.length ? result.errors.map((item, idx) => <li key={idx}>{item}</li>) : <li>-</li>}</ul></div>
        </div>
      )}
      <div className="mt-2 grid gap-2 lg:grid-cols-2">
        {summaryBlocks.map(([label, value]) => (
          <details key={label} className="rounded-lg bg-white/70 p-2">
            <summary className="cursor-pointer font-medium text-sky-800">{label}</summary>
            <pre className="mt-2 max-h-44 overflow-auto whitespace-pre-wrap break-words text-[11px] text-zinc-700">{JSON.stringify(value || (Array.isArray(value) ? [] : {}), null, 2)}</pre>
          </details>
        ))}
      </div>
    </div>
  );
}

function SyncProfilesSection({
  profiles,
  error,
  syncPlanLoadingId,
  syncPlanResult,
  syncPlanError,
  syncPreviewLoadingId,
  syncPreviewResult,
  syncPreviewError,
  onGeneratePlan,
  onClearPlanResult,
  onPreviewSync,
  onClearPreviewResult,
}: {
  profiles: SyncProfile[];
  error?: string | null;
  syncPlanLoadingId: string | null;
  syncPlanResult: SyncEnginePlanResult | null;
  syncPlanError: string | null;
  syncPreviewLoadingId: string | null;
  syncPreviewResult: ManualSyncPreviewResult | null;
  syncPreviewError: string | null;
  onGeneratePlan: (profile: SyncProfile) => void;
  onClearPlanResult: () => void;
  onPreviewSync: (profile: SyncProfile) => void;
  onClearPreviewResult: () => void;
}) {
  return (
    <SectionCard title="Sync Profiles / 同步策略" subtitle="同步策略当前仅表示同步意图和元数据；本页面不会执行同步。Generate Plan / 生成计划 仅调用 Sync Engine dry-run plan API，记录一次 planned/validation_failed IntegrationRun，不更新 cursor，不更新 last_run_id，不执行同步。Preview Sync / 预览同步 仅调用 Manual Sync Preview API，返回 preview-only 事件摘要和 IntegrationRun 引用，不创建 Evidence/Alert/Case/Incident，不更新 cursor，不更新 last_run_id。" count={error ? '-' : profiles.length}>
      <LoadHint error={error} />
      <div className="mb-3 rounded-xl border border-indigo-100 bg-indigo-50 px-4 py-3 text-xs text-indigo-800">
        Generate Plan / 生成计划仅生成 dry-run 执行计划，不连接设备、不同步、不读取凭据、不创建告警/事件。Preview Sync / 预览同步仅预览同步结果，不连接真实厂商、不读取凭据、不创建告警/事件、不执行处置。
      </div>
      {syncPlanError && <div className="mb-3 rounded-xl border border-red-100 bg-red-50 px-4 py-3 text-xs text-red-700">{syncPlanError}</div>}
      {syncPreviewError && <div className="mb-3 rounded-xl border border-red-100 bg-red-50 px-4 py-3 text-xs text-red-700">{syncPreviewError}</div>}
      {syncPlanResult && <SyncPlanResultCard result={syncPlanResult} onClose={onClearPlanResult} />}
      {syncPreviewResult && <SyncPreviewResultCard result={syncPreviewResult} onClose={onClearPreviewResult} />}
      {profiles.length === 0 ? <EmptyState text="暂无同步策略元数据。" /> : <div className="overflow-x-auto"><table className="min-w-full text-left text-xs"><thead className="text-zinc-400"><tr>{['display_name','sync_profile_id','instance_id','package_id','capability','mode','enabled','schedule','last_status','last_run_id','last_synced_at','deduplicate','create_analysis_cases','run_initial_analysis','plan','preview'].map((h) => <th key={h} className="px-2 py-2 font-medium">{h}</th>)}</tr></thead><tbody className="divide-y divide-zinc-100">{profiles.map((p) => <tr key={p.sync_profile_id} className="align-top text-zinc-700"><td className="px-2 py-2 font-medium">{p.display_name}</td><td className="px-2 py-2">{p.sync_profile_id}</td><td className="px-2 py-2">{p.instance_id}</td><td className="px-2 py-2">{p.package_id}</td><td className="px-2 py-2">{p.capability}</td><td className="px-2 py-2">{p.mode}</td><td className="px-2 py-2">{String(p.enabled)}</td><td className="px-2 py-2">{valueOrDash(p.schedule)}</td><td className="px-2 py-2">{p.last_status}</td><td className="px-2 py-2">{valueOrDash(p.last_run_id)}</td><td className="px-2 py-2">{valueOrDash(p.last_synced_at)}</td><td className="px-2 py-2">{String(p.deduplicate)}</td><td className="px-2 py-2">{String(p.create_analysis_cases)}</td><td className="px-2 py-2">{String(p.run_initial_analysis)}</td><td className="px-2 py-2"><button type="button" onClick={() => onGeneratePlan(p)} disabled={syncPlanLoadingId === p.sync_profile_id} className="inline-flex items-center gap-1 rounded-lg bg-indigo-600 px-2 py-1 text-[11px] font-medium text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60" title="只生成执行计划；不连接设备、不同步、不读取凭据、不创建告警/事件。">{syncPlanLoadingId === p.sync_profile_id && <Loader2 className="h-3 w-3 animate-spin" />}Generate Plan / 生成计划：只生成执行计划</button></td><td className="px-2 py-2"><button type="button" onClick={() => onPreviewSync(p)} disabled={syncPreviewLoadingId === p.sync_profile_id} className="inline-flex items-center gap-1 rounded-lg bg-sky-600 px-2 py-1 text-[11px] font-medium text-white hover:bg-sky-700 disabled:cursor-not-allowed disabled:opacity-60" title="仅预览同步结果，不连接真实厂商、不读取凭据、不创建告警/事件、不执行处置。">{syncPreviewLoadingId === p.sync_profile_id && <Loader2 className="h-3 w-3 animate-spin" />}Preview Sync / 预览同步：仅预览同步结果</button></td></tr>)}</tbody></table></div>}
    </SectionCard>
  );
}

function IntegrationRunsSection({ runs, error }: { runs: IntegrationRun[]; error?: string | null }) {
  return (
    <SectionCard title="Integration Runs / 运行记录" subtitle="只读运行历史；摘要使用安全导出，不展示 raw payload，不提供重跑入口。" count={error ? '-' : runs.length}>
      <LoadHint error={error} />
      {runs.length === 0 ? <EmptyState text="暂无运行记录。" /> : <div className="space-y-3">{runs.map((r) => <div key={r.run_id} className="rounded-xl border border-zinc-100 bg-zinc-50 p-3 text-xs text-zinc-700"><div className="flex flex-wrap items-center justify-between gap-2"><div className="font-semibold text-zinc-900">{r.run_id}</div><span className="rounded-full bg-white px-2 py-0.5 text-zinc-600">{r.status}</span></div><div className="mt-2 grid gap-1 md:grid-cols-3"><div>run_type: {r.run_type}</div><div>package_id: {valueOrDash(r.package_id)}</div><div>instance_id: {valueOrDash(r.instance_id)}</div><div>sync_profile_id: {valueOrDash(r.sync_profile_id)}</div><div>capability: {valueOrDash(r.capability)}</div><div>connector: {valueOrDash(r.connector_id)} / {valueOrDash(r.connector_name)}</div><div>mode: {r.mode}</div><div>started_at: {valueOrDash(r.started_at)}</div><div>finished_at: {valueOrDash(r.finished_at)}</div><div>requested_by: {valueOrDash(r.requested_by)}</div></div><details className="mt-2"><summary className="cursor-pointer text-zinc-500">request_summary / result_summary</summary><pre className="mt-2 max-h-56 overflow-auto rounded-lg bg-white p-2 text-[11px] text-zinc-600">{JSON.stringify({ request_summary: r.request_summary, result_summary: r.result_summary }, null, 2)}</pre></details></div>)}</div>}
    </SectionCard>
  );
}


type IntegrationCenterTab = 'setup' | 'sync' | 'runs' | 'legacy';

const INTEGRATION_CENTER_TABS: Array<{ id: IntegrationCenterTab; label: string; description: string }> = [
  { id: 'setup', label: 'Access Setup / 接入配置', description: '集成包、实例、凭据引用' },
  { id: 'sync', label: 'Sync Policies / 同步策略', description: '策略、Plan 与 Preview' },
  { id: 'runs', label: 'Run History / 运行记录', description: 'Runtime v2 操作审计' },
  { id: 'legacy', label: 'Legacy Connector / 旧版接入', description: '历史设备接入与旧同步' },
];

function IntegrationFlow() {
  const steps = [
    '选择集成包',
    '创建集成实例',
    '绑定凭据引用',
    '配置同步策略',
    '生成计划',
    '预览结果',
    '人工确认入库（后续）',
  ];
  return (
    <div className="rounded-2xl border border-zinc-200 bg-white p-4 shadow-sm">
      <div className="mb-3 flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 className="text-sm font-semibold text-zinc-900">Integration flow / 集成流程</h2>
          <p className="text-xs text-zinc-500">前六步用于安全预览；第 7 步为 disabled roadmap，不提供入口。</p>
        </div>
        <span className="rounded-full bg-zinc-100 px-2 py-1 text-[11px] font-medium text-zinc-500">Safe preview mode</span>
      </div>
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-7">
        {steps.map((step, index) => {
          const disabled = index === steps.length - 1;
          return (
            <div key={step} className={`rounded-xl border p-3 text-xs ${disabled ? 'border-dashed border-zinc-200 bg-zinc-50 text-zinc-400' : 'border-indigo-100 bg-indigo-50 text-indigo-900'}`}>
              <div className="mb-2 flex items-center justify-between gap-2">
                <span className={`flex h-6 w-6 items-center justify-center rounded-full text-[11px] font-semibold ${disabled ? 'bg-zinc-200 text-zinc-500' : 'bg-indigo-600 text-white'}`}>{index + 1}</span>
                {disabled && <span className="rounded-full bg-white px-2 py-0.5 text-[10px] text-zinc-400">Roadmap</span>}
              </div>
              <div className="font-medium">{step}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function IntegrationCenterTabs({ active, onChange }: { active: IntegrationCenterTab; onChange: (tab: IntegrationCenterTab) => void }) {
  return (
    <div className="rounded-2xl border border-zinc-200 bg-white p-2 shadow-sm">
      <div className="grid gap-2 md:grid-cols-4">
        {INTEGRATION_CENTER_TABS.map((tab) => {
          const selected = active === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => onChange(tab.id)}
              className={`rounded-xl px-3 py-3 text-left transition-colors ${selected ? 'bg-zinc-900 text-white shadow-sm' : 'text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900'}`}
            >
              <div className="text-sm font-semibold">{tab.label}</div>
              <div className={`mt-1 text-[11px] ${selected ? 'text-zinc-300' : 'text-zinc-400'}`}>{tab.description}</div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ============================================================================
// Main page
// ============================================================================

type PanelMode =
  | { kind: 'wizard'; initialVendor?: DeviceVendor }
  | { kind: 'add'; template: IntegrationTemplate }
  | { kind: 'edit'; device: DeviceIntegration }
  | null;

export default function DeviceIntegrationPage() {
  const toast = useToast();
  const confirm = useConfirm();
  const [devices, setDevices] = useState<DeviceIntegration[]>([]);
  const [templates, setTemplates] = useState<IntegrationTemplate[]>([]);
  const [mcpConfiguredIds, setMcpConfiguredIds] = useState<Set<string>>(new Set());
  const [mcpStatuses, setMcpStatuses] = useState<Record<string, McpStatusSummary>>({});
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [connectorSummary, setConnectorSummary] = useState<SecurityConnectorCustomerSummary | null>(null);
  const [integrationPackages, setIntegrationPackages] = useState<IntegrationPackageSummary[]>([]);
  const [integrationInstances, setIntegrationInstances] = useState<IntegrationInstance[]>([]);
  const [credentialProfiles, setCredentialProfiles] = useState<CredentialProfile[]>([]);
  const [syncProfiles, setSyncProfiles] = useState<SyncProfile[]>([]);
  const [integrationRuns, setIntegrationRuns] = useState<IntegrationRun[]>([]);
  const [integrationCenterErrors, setIntegrationCenterErrors] = useState<Record<string, string | null>>({});
  const [syncPlanLoadingId, setSyncPlanLoadingId] = useState<string | null>(null);
  const [syncPlanResult, setSyncPlanResult] = useState<SyncEnginePlanResult | null>(null);
  const [syncPlanError, setSyncPlanError] = useState<string | null>(null);
  const [syncPreviewLoadingId, setSyncPreviewLoadingId] = useState<string | null>(null);
  const [syncPreviewResult, setSyncPreviewResult] = useState<ManualSyncPreviewResult | null>(null);
  const [syncPreviewError, setSyncPreviewError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [panel, setPanel] = useState<PanelMode>(null);
  const [credentialSource, setCredentialSource] = useState<SecurityConnectorCustomerDataSource | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [credentialSaving, setCredentialSaving] = useState(false);
  const [activeIntegrationTab, setActiveIntegrationTab] = useState<IntegrationCenterTab>('setup');

  const currentGroup: DeviceGroup | undefined = groups[0];

  const fetchData = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);
    try {
      const [devRes, tplRes, grpRes, diagnosticsRes, mcpCatalogRes, mcpConfiguredRes, mcpStatusRes, packageRes, instanceRes, credentialProfileRes, syncProfileRes, integrationRunRes] = await Promise.allSettled([
        deviceAPI.list(),
        providerAPI.listApiServices(),
        deviceAPI.listGroups(),
        securityAPI.customerConnectorSummary(14),
        mcpAPI.catalogList(),
        mcpAPI.catalogConfigured(),
        mcpAPI.list(),
        securityAPI.listIntegrationPackages(),
        securityAPI.listIntegrationInstances(),
        securityAPI.listCredentialProfiles(),
        securityAPI.listSyncProfiles(),
        securityAPI.listIntegrationRuns({ limit: 50 }),
      ]);
      if (devRes.status !== 'fulfilled' || tplRes.status !== 'fulfilled' || grpRes.status !== 'fulfilled') {
        throw new Error('device integration load failed');
      }
      setDevices(devRes.value.data || []);
      const deviceTemplates = (tplRes.value.data || [])
        .filter((s) => s.integration_type === 'device')
        .map(deviceServiceToTemplate);
      const mcpTemplates = mcpCatalogRes.status === 'fulfilled'
        ? (mcpCatalogRes.value.data || [])
            .filter((entry) => entry.transport === 'remote' && entry.device_integration === true)
            .map(mcpCatalogEntryToTemplate)
        : [];
      setTemplates([...deviceTemplates, ...mcpTemplates]);
      setMcpConfiguredIds(new Set(mcpConfiguredRes.status === 'fulfilled' ? (mcpConfiguredRes.value.data || []) : []));
      setMcpStatuses(mcpStatusRes.status === 'fulfilled' ? (mcpStatusRes.value.data || {}) : {});
      setGroups(grpRes.value.data || []);
      setConnectorSummary(diagnosticsRes.status === 'fulfilled' ? diagnosticsRes.value.data : null);
      setIntegrationPackages(packageRes.status === 'fulfilled' ? packageRes.value.data || [] : []);
      setIntegrationInstances(instanceRes.status === 'fulfilled' ? instanceRes.value.data || [] : []);
      setCredentialProfiles(credentialProfileRes.status === 'fulfilled' ? credentialProfileRes.value.data || [] : []);
      setSyncProfiles(syncProfileRes.status === 'fulfilled' ? syncProfileRes.value.data || [] : []);
      setIntegrationRuns(integrationRunRes.status === 'fulfilled' ? integrationRunRes.value.data || [] : []);
      setIntegrationCenterErrors({
        packages: packageRes.status === 'fulfilled' ? null : '集成包暂不可用。',
        instances: instanceRes.status === 'fulfilled' ? null : '集成实例暂不可用。',
        credentials: credentialProfileRes.status === 'fulfilled' ? null : '凭据配置引用暂不可用。',
        syncProfiles: syncProfileRes.status === 'fulfilled' ? null : '同步策略暂不可用。',
        runs: integrationRunRes.status === 'fulfilled' ? null : '运行记录暂不可用。',
      });
    } catch {
      toast.error('加载失败');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { void fetchData(); }, [fetchData]);

  const handleGenerateSyncPlan = async (profile: SyncProfile) => {
    setSyncPlanLoadingId(profile.sync_profile_id);
    setSyncPlanError(null);
    try {
      const response = await securityAPI.planSyncEngine({
        sync_profile_id: profile.sync_profile_id,
        params_override: {},
        dry_run: true,
      });
      setSyncPlanResult(response.data);
      toast.success('dry-run 计划已生成');
      await fetchData(true);
    } catch (error) {
      const detailResult = syncPlanResultFromError(error);
      if (detailResult) setSyncPlanResult(detailResult);
      setSyncPlanError(apiErrorMessage(error, '生成计划失败'));
    } finally {
      setSyncPlanLoadingId(null);
    }
  };

  const handlePreviewSync = async (profile: SyncProfile) => {
    setSyncPreviewLoadingId(profile.sync_profile_id);
    setSyncPreviewError(null);
    try {
      const response = await securityAPI.previewSyncEngine({
        sync_profile_id: profile.sync_profile_id,
        params_override: {},
        dry_run: true,
        preview_only: true,
      });
      setSyncPreviewResult(response.data);
      toast.success('同步预览已生成');
      await fetchData(true);
    } catch (error) {
      const detailResult = syncPreviewResultFromError(error);
      if (detailResult) setSyncPreviewResult(detailResult);
      setSyncPreviewError(apiErrorMessage(error, '生成预览失败'));
    } finally {
      setSyncPreviewLoadingId(null);
    }
  };

  const openAddWizard = useCallback(async () => {
    await fetchData(true);
    setPanel({ kind: 'wizard' });
  }, [fetchData]);

  // Count instances per storage_key (for wizard display)
  const instanceCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    devices.forEach((d) => { counts[d.storage_key] = (counts[d.storage_key] || 0) + 1; });
    mcpConfiguredIds.forEach((id) => { counts[id] = (counts[id] || 0) + 1; });
    return counts;
  }, [devices, mcpConfiguredIds]);

  // storage_key (and bare service_id) → vendor key, sourced from the backend
  // template list. Used to resolve vendor for already-installed devices
  // (whose `DeviceIntegration` row does not carry the vendor field directly).
  //
  // Legacy devices may have been installed before api_versioning shipped, so
  // their `storage_key` is the bare service_id (e.g. "tdp_api") rather than
  // the versioned form ("tdp_api_v3_3_10"). We additionally index each
  // template by its bare service_id (regex matches the backend's
  // `storage_key_to_service_id`) so those rows still resolve correctly.
  const vendorByKey = useMemo(() => {
    const map: Record<string, string> = {};
    templates.forEach((t) => {
      if (!t.vendor) return;
      map[t.id] = t.vendor;
      const bareServiceId = t.id.replace(/_v[\w.]+$/i, '');
      if (bareServiceId !== t.id && !map[bareServiceId]) {
        map[bareServiceId] = t.vendor;
      }
    });
    return map;
  }, [templates]);

  const templateByKey = useMemo(() => {
    const map: Record<string, IntegrationTemplate> = {};
    templates.forEach((t) => {
      map[t.id] = t;
      const bareServiceId = t.id.replace(/_v[\w.]+$/i, '');
      if (bareServiceId !== t.id && !map[bareServiceId]) {
        map[bareServiceId] = t;
      }
    });
    return map;
  }, [templates]);

  const configuredMcps = useMemo(() => (
    templates
      .filter(isMcpTemplate)
      .filter((template) => mcpConfiguredIds.has(template.id))
      .map((template) => ({
        id: template.id,
        template,
        status: mcpStatuses[template.id] || { status: 'disconnected' as McpConnectionStatus },
      }))
  ), [templates, mcpConfiguredIds, mcpStatuses]);

  const vendorOf = useCallback(
    (device: DeviceIntegration): string | undefined =>
      vendorByKey[device.storage_key] ?? vendorByKey[device.service_id],
    [vendorByKey],
  );

  const templateOf = useCallback(
    (device: DeviceIntegration): APIServiceSummary | undefined =>
      templateByKey[device.storage_key] ?? templateByKey[device.service_id],
    [templateByKey],
  );

  const syncByDeviceId = useMemo(() => {
    const map: Record<string, DeviceSyncBinding> = {};
    devices.forEach((device) => {
      map[device.id] = buildDeviceSyncBinding(device, connectorSummary, templateOf(device));
    });
    return map;
  }, [devices, connectorSummary, templateOf]);

  const customerIntegrations = useMemo<CustomerIntegrationRow[]>(() => [
    ...devices.map((device) => ({
      id: `device:${device.id}`,
      kind: 'device' as const,
      device,
      mcp: null,
      sync: syncByDeviceId[device.id] || buildDeviceSyncBinding(device, connectorSummary, templateOf(device)),
      vendorKey: vendorOf(device),
    })),
    ...configuredMcps.map((mcp) => ({
      id: `mcp:${mcp.id}`,
      kind: 'mcp' as const,
      device: null,
      mcp,
      sync: unavailableSyncBinding(),
      vendorKey: mcp.template.vendor,
    })),
  ], [devices, syncByDeviceId, connectorSummary, templateOf, vendorOf, configuredMcps]);

  const connectedProductCount = customerIntegrations.filter((row) => (
    row.kind === 'device'
      ? deviceApiStatus(row.device) === 'connected'
      : row.kind === 'mcp' && row.mcp
        ? mcpApiStatus(row.mcp) === 'connected'
        : false
  )).length;
  const activeProductCount = customerIntegrations.length;
  const hasUnboundSyncSources = activeProductCount === 0 && (connectorSummary?.data_sources?.length || 0) > 0;

  const panelDeviceId = panel?.kind === 'edit' ? panel.device.id : null;

  const handleSave = async (data: { name: string; fields: Record<string, string>; enabled: boolean; verify_ssl: boolean }) => {
    if (panel?.kind === 'add') {
      await deviceAPI.create({
        name: data.name,
        storage_key: panel.template.id,
        group_id: currentGroup?.id,
        enabled: data.enabled,
        verify_ssl: data.verify_ssl,
        fields: data.fields,
      });
      setPanel(null);
    } else if (panel?.kind === 'edit') {
      await deviceAPI.update(panel.device.id, {
        name: data.name,
        enabled: data.enabled,
        verify_ssl: data.verify_ssl,
        fields: data.fields,
      });
    }
    await fetchData(true);
    if (panel?.kind === 'edit') {
      const updated = await deviceAPI.get(panel.device.id);
      setPanel({ kind: 'edit', device: updated.data });
    }
  };

  const handleDelete = async () => {
    if (panel?.kind !== 'edit') return;
    await deviceAPI.delete(panel.device.id);
    setPanel(null);
    await fetchData(true);
  };

  const handleTest = async (overrides: { verify_ssl: boolean; base_url?: string }) => {
    if (panel?.kind !== 'edit') return { success: false, message: '' };
    const res = await deviceAPI.test(panel.device.id, overrides);
    await fetchData(true);
    if (panel?.kind === 'edit') {
      const updated = await deviceAPI.get(panel.device.id);
      setPanel({ kind: 'edit', device: updated.data });
    }
    return res.data;
  };

  const handleSaveMcp = async (
    entry: MCPCatalogEntry,
    values: Record<string, string>,
    enabled: boolean,
    _configuredSecrets: Record<string, string> = {},
  ) => {
    const options = splitMcpInstallValues(entry, values);
    const res = await mcpAPI.catalogInstall(entry.id, {
      enabled,
      ...options,
    });
    setPanel(null);
    await fetchData(true);
    return { connectError: res.data.connect_error || null };
  };

  const handleTestMcp = async (
    entry: MCPCatalogEntry,
    values: Record<string, string>,
    enabled: boolean,
    configuredSecrets: Record<string, string> = {},
  ) => {
    const config = buildMcpRuntimeConfig(entry, values, enabled, configuredSecrets);
    const res = await mcpAPI.test(entry.id, config);
    return {
      success: !!res.data.success,
      message: res.data.message || (res.data.success ? '连接成功' : '连接失败'),
    };
  };

  // Persist the SSL toggle the moment it flips, without requiring 保存.
  // Re-fetches the device so the open panel reflects the freshly stored row.
  const handleToggleVerifySsl = async (next: boolean) => {
    if (panel?.kind !== 'edit') return;
    await deviceAPI.update(panel.device.id, { verify_ssl: next });
    const updated = await deviceAPI.get(panel.device.id);
    setPanel({ kind: 'edit', device: updated.data });
    await fetchData(true);
  };

  // Same pattern for enabled — persists immediately without needing 保存.
  const handleToggleEnabled = async (next: boolean) => {
    if (panel?.kind !== 'edit') return;
    await deviceAPI.update(panel.device.id, { enabled: next });
    const updated = await deviceAPI.get(panel.device.id);
    setPanel({ kind: 'edit', device: updated.data });
    await fetchData(true);
  };

  const handleTestDataSource = async (source: SecurityConnectorCustomerDataSource) => {
    setActionLoading(`test:${source.id}`);
    try {
      const res = await securityAPI.customerTestConnector(source.id, source.credential.profile_id);
      if (res.data.success) toast.success(res.data.message || '连接测试通过');
      else toast.error(res.data.message || '连接测试失败');
      await fetchData(true);
    } catch {
      toast.error('连接测试失败');
    } finally {
      setActionLoading(null);
    }
  };

  const handleEnableDeviceSync = async (device: DeviceIntegration, sync: DeviceSyncBinding) => {
    if (!sync.source) return;
    const ok = await confirm({
      title: sync.state === 'active' ? '重新绑定数据同步' : '启用数据同步',
      description: `将 ${sync.source.name} 的数据同步绑定到设备 ${device.name}，并为 ${sync.capabilities.map(capabilityLabel).join('、') || '已声明能力'} 创建同步调度。`,
      confirmText: sync.state === 'active' ? '确认重新绑定' : '确认启用',
      variant: 'default',
    });
    if (!ok) return;
    setActionLoading(`enable-sync:${device.id}:${sync.source.id}`);
    try {
      const res = await securityAPI.customerEnableDeviceSync(sync.source.id, device.id, {
        profile_id: deviceSyncProfileId(device.id),
        enabled: true,
        interval_seconds: 3600,
        mode: 'incremental',
        capabilities: sync.capabilities,
      });
      toast.success(res.data.message || '数据同步已启用');
      await fetchData(true);
    } catch {
      toast.error('启用数据同步失败');
    } finally {
      setActionLoading(null);
    }
  };

  const handleResumeSchedule = async (
    source: SecurityConnectorCustomerDataSource,
    schedule: SecurityConnectorCustomerSchedule,
  ) => {
    const ok = await confirm({
      title: '恢复同步调度',
      description: `恢复后 ${source.name} 会按计划继续同步 ${schedule.capability || '数据'}。请确认凭据和连接已恢复。`,
      confirmText: '确认恢复',
      variant: 'default',
    });
    if (!ok) return;
    setActionLoading(`resume:${schedule.id}`);
    try {
      const res = await securityAPI.customerEnableConnectorSchedule(schedule.id);
      toast.success(res.data.message || '同步调度已启用');
      await fetchData(true);
    } catch {
      toast.error('恢复调度失败');
    } finally {
      setActionLoading(null);
    }
  };

  const handlePauseSchedule = async (
    source: SecurityConnectorCustomerDataSource,
    schedule: SecurityConnectorCustomerSchedule,
  ) => {
    const ok = await confirm({
      title: '暂停同步调度',
      description: `暂停后 ${source.name} 将不再按计划同步 ${schedule.capability || '数据'}，直到手动恢复。`,
      confirmText: '确认暂停',
      variant: 'warning',
    });
    if (!ok) return;
    setActionLoading(`pause:${schedule.id}`);
    try {
      const res = await securityAPI.customerDisableConnectorSchedule(schedule.id);
      toast.success(res.data.message || '同步调度已暂停');
      await fetchData(true);
    } catch {
      toast.error('暂停调度失败');
    } finally {
      setActionLoading(null);
    }
  };

  const handleUpdateScheduleInterval = async (
    source: SecurityConnectorCustomerDataSource,
    schedule: SecurityConnectorCustomerSchedule,
    intervalSeconds: number,
  ) => {
    if (!schedule.capability) {
      toast.error('当前调度缺少同步能力标识，无法更新频率');
      return;
    }
    const currentInterval = Number(schedule.interval_seconds || 0);
    if (currentInterval === intervalSeconds) return;
    setActionLoading(`frequency:${schedule.id}`);
    try {
      await securityAPI.upsertConnectorSyncSchedule(source.id, {
        capability: schedule.capability,
        enabled: schedule.enabled,
        interval_seconds: intervalSeconds,
        mode: schedule.mode || 'incremental',
        full_interval_seconds: schedule.full_interval_seconds ?? null,
        retry_max_attempts: schedule.retry_max_attempts ?? 1,
        retry_backoff_seconds: schedule.retry_backoff_seconds ?? 60,
        timeout_seconds: schedule.timeout_seconds ?? 300,
        credential_profile_id: schedule.credential_profile_id || source.credential.profile_id || null,
      });
      toast.success(`${capabilityLabel(schedule.capability)}同步频率已更新为每 ${formatSyncInterval(intervalSeconds)}`);
      await fetchData(true);
    } catch {
      toast.error('更新同步频率失败');
    } finally {
      setActionLoading(null);
    }
  };

  const handleCredentialSubmit = async (payload: {
    values: Record<string, string>;
    secretKeys: string[];
    profileId: string;
    expiresAt?: string | null;
  }) => {
    if (!credentialSource) return;
    const ok = await confirm({
      title: '更新数据源凭据',
      description: '保存后会立即测试连接。若连接恢复，可再恢复暂停的同步调度。',
      confirmText: '保存并测试',
      variant: 'warning',
    });
    if (!ok) return;
    setCredentialSaving(true);
    try {
      const res = await securityAPI.customerUpdateConnectorCredentials(
        credentialSource.id,
        payload.values,
        payload.secretKeys,
        payload.profileId,
        credentialSource.credential.profile_name,
        true,
        payload.expiresAt,
      );
      toast.success(res.data.message || '凭据已更新');
      setCredentialSource(null);
      await fetchData(true);
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || '凭据更新失败');
    } finally {
      setCredentialSaving(false);
    }
  };

  return (
    <div className="h-full flex flex-col">
      <PageHeader
        title="Integration Center / 集成中心"
        description="集成中心用于统一管理安全产品接入、同步策略和运行审计。当前默认采用安全预览模式：生成计划与预览结果均不会连接真实厂商、不会读取明文凭据、不会自动创建事件、不会执行处置。"
        icon={<Shield className="w-5 h-5" />}
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => void fetchData(true)}
              disabled={refreshing}
              title="刷新"
              className="p-1.5 rounded-lg border border-zinc-200 text-zinc-500 hover:bg-zinc-50 hover:text-zinc-700 disabled:opacity-50 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            </button>
          </div>
        }
      />

      <GroupBanner group={currentGroup} onRenamed={() => void fetchData(true)} />

      {loading ? (
        <div className="flex-1 flex items-center justify-center"><LoadingSpinner /></div>
      ) : (
        <div className="flex-1 overflow-y-auto px-6 py-6">
          <div className="space-y-6">
            <div className="rounded-2xl border border-indigo-100 bg-indigo-50 p-4 text-sm text-indigo-900 shadow-sm">
              <div className="font-semibold">安全边界 / Safety boundary</div>
              <p className="mt-1 text-xs text-indigo-800">当前默认采用安全预览模式：生成计划与预览结果均不会连接真实厂商、不会读取明文凭据、不会自动创建事件、不会执行处置。Ingest 仅作为后续人工确认入库能力展示，不提供入口。</p>
            </div>

            <IntegrationFlow />
            <IntegrationCenterTabs active={activeIntegrationTab} onChange={setActiveIntegrationTab} />

            {activeIntegrationTab === 'setup' && (
              <div className="space-y-6">
                <div className="rounded-xl border border-blue-100 bg-blue-50 px-4 py-3 text-xs text-blue-800">
                  接入配置用于描述可接入的安全产品、实例目标和凭据引用。当前仅保存元数据和引用，不保存明文凭据，不执行连接测试。
                </div>
                <IntegrationCenterOverview counts={{ packages: integrationCenterErrors.packages ? null : integrationPackages.length, instances: integrationCenterErrors.instances ? null : integrationInstances.length, credentials: integrationCenterErrors.credentials ? null : credentialProfiles.length, syncProfiles: integrationCenterErrors.syncProfiles ? null : syncProfiles.length, runs: integrationCenterErrors.runs ? null : integrationRuns.length }} />
                <BuiltInIntegrationPackagesSection packages={integrationPackages} />
                <IntegrationInstancesSection instances={integrationInstances} packages={integrationPackages} error={integrationCenterErrors.instances} />
                <CredentialProfilesSection profiles={credentialProfiles} error={integrationCenterErrors.credentials} />
              </div>
            )}

            {activeIntegrationTab === 'sync' && (
              <div className="space-y-6">
                <div className="rounded-xl border border-indigo-100 bg-indigo-50 px-4 py-3 text-xs text-indigo-800">
                  <div className="font-semibold">同步策略用于描述从哪个集成实例同步什么能力。当前支持两个安全动作：</div>
                  <ul className="mt-2 list-disc space-y-1 pl-5">
                    <li><span className="font-medium">Plan：</span>只生成执行计划，不取数、不入库；</li>
                    <li><span className="font-medium">Preview：</span>只生成同步结果预览，不创建 Evidence/Alert/Case/Incident；</li>
                    <li><span className="font-medium">Ingest：</span>人工确认入库能力已在后端受控提供，但当前 UI 暂不开放，避免误操作。</li>
                  </ul>
                </div>
                <SyncProfilesSection
                  profiles={syncProfiles}
                  error={integrationCenterErrors.syncProfiles}
                  syncPlanLoadingId={syncPlanLoadingId}
                  syncPlanResult={syncPlanResult}
                  syncPlanError={syncPlanError}
                  syncPreviewLoadingId={syncPreviewLoadingId}
                  syncPreviewResult={syncPreviewResult}
                  syncPreviewError={syncPreviewError}
                  onGeneratePlan={(profile) => void handleGenerateSyncPlan(profile)}
                  onClearPlanResult={() => setSyncPlanResult(null)}
                  onPreviewSync={(profile) => void handlePreviewSync(profile)}
                  onClearPreviewResult={() => setSyncPreviewResult(null)}
                />
              </div>
            )}

            {activeIntegrationTab === 'runs' && (
              <div className="space-y-6">
                <div className="rounded-xl border border-zinc-200 bg-zinc-50 px-4 py-3 text-xs text-zinc-700">
                  运行记录用于审计计划生成、预览、未来人工确认入库等动作。当前记录的是 Integration Runtime v2 的操作轨迹，不代表已创建事件或已执行处置。
                </div>
                <IntegrationRunsSection runs={integrationRuns} error={integrationCenterErrors.runs} />
              </div>
            )}

            {activeIntegrationTab === 'legacy' && (
              <div className="space-y-6">
                <div className="rounded-xl border border-amber-100 bg-amber-50 px-4 py-3 text-xs text-amber-800">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <p>Legacy Connector 为历史设备接入与旧数据源同步能力，保留用于兼容现有环境。Integration Runtime v2 的集成包、实例、凭据引用、同步策略和运行记录已在前三个 Tab 中分层展示。</p>
                    <button
                      onClick={() => void openAddWizard()}
                      className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-amber-600 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-amber-700"
                    >
                      <Plus className="h-3.5 w-3.5" />
                      添加旧版接入
                    </button>
                  </div>
                </div>
                <IntegrationHealthPanel integrations={customerIntegrations} connectorSummary={connectorSummary} />

                {activeProductCount === 0 ? (
                  <div className="flex flex-col items-center justify-center gap-4 py-24">
                    <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-zinc-100">
                      <PlugZap className="h-7 w-7 text-zinc-300" />
                    </div>
                    <div className="text-center">
                      <p className="text-sm font-semibold text-zinc-700">
                        {hasUnboundSyncSources ? '暂无设备 API 接入' : '暂无已接入的设备'}
                      </p>
                      <p className="mt-1.5 text-xs text-zinc-400">
                        {hasUnboundSyncSources
                          ? '上方展示的是已启用的数据同步源；添加对应设备后可统一管理连接、工具调用和同步绑定'
                          : '添加后可管理连接、工具调用和标准化数据同步'}
                      </p>
                    </div>
                    <button
                      onClick={() => void openAddWizard()}
                      className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700"
                    >
                      <Plus className="h-3.5 w-3.5" />
                      立即添加旧版接入
                    </button>
                  </div>
                ) : (
                  <section>
                    <div className="mb-4 flex items-center gap-2">
                      <PlugZap className="h-4 w-4 text-blue-600" />
                      <h3 className="text-sm font-semibold text-zinc-800">已接入安全产品</h3>
                      <span className="rounded-md bg-zinc-100 px-1.5 py-0.5 text-xs text-zinc-400">{activeProductCount}</span>
                      {connectedProductCount > 0 && (
                        <span className="text-xs text-green-600">
                          {connectedProductCount} 已连接
                        </span>
                      )}
                    </div>
                    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                      {customerIntegrations.map((integration) => (
                        integration.kind === 'device' && integration.device ? (
                          <ActiveCard
                            key={integration.id}
                            device={integration.device}
                            vendorKey={integration.vendorKey}
                            sync={integration.sync}
                            selected={panelDeviceId === integration.device.id}
                            onClick={() => setPanel({ kind: 'edit', device: integration.device as DeviceIntegration })}
                          />
                        ) : integration.kind === 'mcp' && integration.mcp ? (
                          <McpActiveCard
                            key={integration.id}
                            mcp={integration.mcp}
                            onClick={() => setPanel({ kind: 'add', template: integration.mcp!.template })}
                          />
                        ) : null
                      ))}
                    </div>
                  </section>
                )}
              </div>
            )}
          </div>        </div>
      )}

      {credentialSource && (
        <DataSourceCredentialDialog
          source={credentialSource}
          saving={credentialSaving}
          onClose={() => setCredentialSource(null)}
          onSubmit={handleCredentialSubmit}
        />
      )}

      {/* Wizard panel (vendor → product selection) */}
      {panel?.kind === 'wizard' && (
        <AddDeviceWizardPanel
          templates={templates}
          instanceCounts={instanceCounts}
          initialVendor={panel.initialVendor}
          onSelect={(tpl) => setPanel({ kind: 'add', template: tpl })}
          onClose={() => setPanel(null)}
        />
      )}

      {/* Config panel (add or edit) */}
      {panel?.kind === 'add' && isMcpTemplate(panel.template) && (
        <McpConfigPanel
          key={panel.template.id}
          template={panel.template}
          vendorKey={panel.template.vendor}
          configured={mcpConfiguredIds.has(panel.template.id)}
          onSave={handleSaveMcp}
          onTest={handleTestMcp}
          onClose={() => setPanel(null)}
          onBack={() => setPanel({
            kind: 'wizard',
            initialVendor: panel.template.vendor ? vendorPresentation(panel.template.vendor) : undefined,
          })}
        />
      )}
      {((panel?.kind === 'add' && !isMcpTemplate(panel.template)) || panel?.kind === 'edit') && (() => {
        const panelVendorKey = panel.kind === 'edit'
          ? vendorOf(panel.device)
          : panel.template.vendor;
        return (
          <DeviceConfigPanel
            key={panel.kind === 'edit' ? panel.device.id : panel.template.id}
            device={panel.kind === 'edit' ? panel.device : undefined}
            template={panel.kind === 'add' ? panel.template : undefined}
            vendorKey={panelVendorKey}
            sync={panel.kind === 'edit' ? syncByDeviceId[panel.device.id] : undefined}
            actionLoading={actionLoading}
            onSave={handleSave}
            onDelete={panel.kind === 'edit' ? handleDelete : undefined}
            onClose={() => setPanel(null)}
            onTest={panel.kind === 'edit' ? handleTest : undefined}
            onToggleVerifySsl={panel.kind === 'edit' ? handleToggleVerifySsl : undefined}
            onToggleEnabled={panel.kind === 'edit' ? handleToggleEnabled : undefined}
            onEnableSync={handleEnableDeviceSync}
            onTestSync={handleTestDataSource}
            onPauseSchedule={handlePauseSchedule}
            onResumeSchedule={handleResumeSchedule}
            onUpdateScheduleInterval={handleUpdateScheduleInterval}
            onUpdateSyncCredentials={setCredentialSource}
            onBack={panel.kind === 'add'
              ? () => setPanel({
                  kind: 'wizard',
                  initialVendor: panelVendorKey ? vendorPresentation(panelVendorKey) : undefined,
                })
              : undefined
            }
          />
        );
      })()}
    </div>
  );
}
