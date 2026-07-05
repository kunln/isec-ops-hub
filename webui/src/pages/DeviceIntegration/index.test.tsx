import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';

import DeviceIntegrationPage from './index';

const mocks = vi.hoisted(() => ({
  listDevices: vi.fn(),
  getDevice: vi.fn(),
  createDevice: vi.fn(),
  updateDevice: vi.fn(),
  deleteDevice: vi.fn(),
  testDevice: vi.fn(),
  listGroups: vi.fn(),
  updateGroup: vi.fn(),
  listApiServices: vi.fn(),
  getServiceMetadata: vi.fn(),
  mcpList: vi.fn(),
  mcpGet: vi.fn(),
  mcpCatalogList: vi.fn(),
  mcpCatalogConfigured: vi.fn(),
  mcpCatalogInstall: vi.fn(),
  mcpTest: vi.fn(),
  listTools: vi.fn(),
  setToolEnabled: vi.fn(),
  customerConnectorSummary: vi.fn(),
  customerTestConnector: vi.fn(),
  customerEnableConnectorSchedule: vi.fn(),
  customerDisableConnectorSchedule: vi.fn(),
  customerUpdateConnectorCredentials: vi.fn(),
  customerEnableDeviceSync: vi.fn(),
  upsertConnectorSyncSchedule: vi.fn(),
  confirm: vi.fn(),
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
}));

vi.mock('@/api/device', () => ({
  deviceAPI: {
    list: mocks.listDevices,
    get: mocks.getDevice,
    create: mocks.createDevice,
    update: mocks.updateDevice,
    delete: mocks.deleteDevice,
    test: mocks.testDevice,
    listGroups: mocks.listGroups,
    updateGroup: mocks.updateGroup,
  },
}));

vi.mock('@/api/provider', () => ({
  providerAPI: {
    listApiServices: mocks.listApiServices,
    getServiceMetadata: mocks.getServiceMetadata,
  },
}));

vi.mock('@/api/mcp', () => ({
  mcpAPI: {
    list: mocks.mcpList,
    get: mocks.mcpGet,
    catalogList: mocks.mcpCatalogList,
    catalogConfigured: mocks.mcpCatalogConfigured,
    catalogInstall: mocks.mcpCatalogInstall,
    test: mocks.mcpTest,
  },
}));

vi.mock('@/api/tool', () => ({
  toolAPI: {
    list: mocks.listTools,
    setEnabled: mocks.setToolEnabled,
  },
}));

vi.mock('@/api/security', () => ({
  securityAPI: {
    customerConnectorSummary: mocks.customerConnectorSummary,
    customerTestConnector: mocks.customerTestConnector,
    customerEnableConnectorSchedule: mocks.customerEnableConnectorSchedule,
    customerDisableConnectorSchedule: mocks.customerDisableConnectorSchedule,
    customerUpdateConnectorCredentials: mocks.customerUpdateConnectorCredentials,
    customerEnableDeviceSync: mocks.customerEnableDeviceSync,
    upsertConnectorSyncSchedule: mocks.upsertConnectorSyncSchedule,
  },
}));

vi.mock('@/components/common/ConfirmDialog', () => ({
  useConfirm: () => mocks.confirm,
}));

vi.mock('@/components/common/Toast', () => ({
  useToast: () => ({
    success: mocks.toastSuccess,
    error: mocks.toastError,
    info: vi.fn(),
    warning: vi.fn(),
  }),
}));

vi.mock('@/components/common/PageHeader', () => ({
  default: ({ title, description, action }: { title: string; description?: string; action?: ReactNode }) => (
    <div>
      <h1>{title}</h1>
      {description ? <p>{description}</p> : null}
      {action}
    </div>
  ),
}));

vi.mock('@/components/common/LoadingSpinner', () => ({
  default: () => <div>loading...</div>,
}));

vi.mock('../Tool/components/ToolDetailModal', () => ({
  default: () => null,
}));

describe('DeviceIntegrationPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    mocks.listDevices.mockResolvedValue({
      data: [
        {
          id: 'device-1',
          group_id: 'group-1',
          name: 'TDP-test-02',
          storage_key: 'tdp_api_v3_3_10',
          service_id: 'tdp',
          enabled: true,
          verify_ssl: false,
          fields: { base_url: 'https://tdp.example.com' },
          fields_set: { api_key: true, secret: true, base_url: true },
          status: 'connected',
          created_at: 0,
          updated_at: 0,
        },
      ],
    });
    mocks.listApiServices.mockResolvedValue({
      data: [
        {
          id: 'tdp_api_v3_3_10',
          name: 'TDP',
          enabled: true,
          status: 'ready',
          tool_count: 21,
          verify_ssl: false,
          integration_type: 'device',
          vendor: 'threatbook',
        },
      ],
    });
    mocks.listGroups.mockResolvedValue({
      data: [
        {
          id: 'group-1',
          name: '默认机房',
          sort_order: 0,
          created_at: 0,
          updated_at: 0,
        },
      ],
    });
    mocks.customerConnectorSummary.mockResolvedValue({
      data: {
        version: 'connector.customer.summary.v1',
        checked_at: '2026-06-03T10:00:00+00:00',
        trend_window_days: 14,
        summary: {
          data_sources: 1,
          connected_data_sources: 0,
          attention_data_sources: 1,
          sync_schedules: 3,
          enabled_sync_schedules: 2,
          expiry_risks: 1,
          sync_blocked: 1,
          paused_schedules: 1,
          recent_anomalies: 1,
        },
        data_sources: [
          {
            id: 'tdp',
            type: 'connector',
            name: 'TDP 数据同步',
            vendor: 'ThreatBook',
            product: 'TDP',
            product_version: '3.3.10',
            enabled: true,
            connection_status: 'blocked',
            sync_status: 'blocked',
            risk_level: 'critical',
            message: '同步被阻断，因为凭据已过期。请更新凭据并重新测试连接。',
            capabilities: ['asset.search', 'vulnerability.search', 'alert.search', 'honeypot.event.search'],
            sync_targets: ['assets', 'vulnerabilities', 'alerts', 'honeypot_events'],
            credential: {
              profile_id: 'prod',
              profile_name: 'prod',
              state: 'expired',
              healthy: false,
              blocking: true,
              expires_at: '2026-06-04T00:00:00+00:00',
              last_test_at: '2026-06-03T09:00:00+00:00',
              last_sync_at: '2026-06-03T09:30:00+00:00',
              last_successful_sync_at: null,
              fields: [
                { key: 'VENDOR_TOKEN', kind: 'secret', configured: true },
                { key: 'TENANT_ID', kind: 'value', configured: true },
              ],
              message: '凭据即将过期，建议提前更新凭据。',
              recommended_action: '更新凭据并测试连接。',
            },
            sync: {
              status: 'blocked',
              last_sync_at: '2026-06-03T09:30:00+00:00',
              last_successful_sync_at: null,
              counts: { assets: 12, vulnerabilities: 3, alerts: 8, honeypot_events: 1 },
              failure_reason: '同步被阻断，因为凭据已过期。请更新凭据并重新测试连接。',
              recommended_action: '更新凭据并测试连接。',
            },
            schedules: [
              {
                id: 'schedule-1',
                connector_id: 'tdp',
                capability: 'asset.search',
                enabled: false,
                status: 'paused',
                mode: 'incremental',
                interval_seconds: 3600,
                full_interval_seconds: null,
                retry_max_attempts: 1,
                retry_backoff_seconds: 60,
                timeout_seconds: 300,
                credential_profile_id: 'prod',
                next_run_at: null,
                last_run_at: '2026-06-03T09:30:00+00:00',
                last_successful_run_at: null,
                last_status: 'blocked',
                message: '调度已暂停，因为同步凭据已过期。',
                recommended_action: '确认凭据恢复后重新启用调度。',
              },
            ],
            actions: [
              { id: 'test_connection', kind: 'test_connection', label: '测试连接', connector_id: 'tdp', requires_confirmation: false },
              { id: 'update_credentials', kind: 'update_credentials', label: '更新凭据', connector_id: 'tdp', profile_id: 'prod', requires_confirmation: true },
              { id: 'resume_schedule:schedule-1', kind: 'resume_schedule', label: '恢复调度', connector_id: 'tdp', schedule_id: 'schedule-1', requires_confirmation: true },
            ],
          },
        ],
        recent_events: [
          {
            id: 'event-1',
            kind: 'sync_blocked',
            label: '同步被阻断',
            severity: 'critical',
            connector_id: 'tdp',
            connector_name: 'TDP 数据同步',
            profile_id: 'prod',
            schedule_id: null,
            created_at: '2026-06-03T10:00:00+00:00',
            last_seen_at: '2026-06-03T10:00:00+00:00',
            message: 'TDP 同步被凭据阻断',
            recommended_action: '更新凭据并测试连接。',
          },
        ],
        trend: [
          {
            date: '2026-06-03',
            expiry_risks: 1,
            sync_blocked: 2,
            paused_schedules: 1,
            recoveries: 0,
          },
        ],
      },
    });
    mocks.getServiceMetadata.mockResolvedValue({
      data: {
        name: 'TDP',
        credential_schema: [
          {
            key: 'api_key',
            label: 'API Key',
            storage: 'secret',
            sensitive: true,
            required: true,
            input_type: 'password',
            config_key: 'api_key',
          },
          {
            key: 'secret',
            label: 'Secret',
            storage: 'secret',
            sensitive: true,
            required: true,
            input_type: 'password',
            config_key: 'secret',
          },
          {
            key: 'base_url',
            label: 'Base URL',
            storage: 'config',
            sensitive: false,
            required: true,
            input_type: 'url',
            config_key: 'base_url',
          },
        ],
      },
    });
    mocks.mcpCatalogList.mockResolvedValue({ data: [] });
    mocks.mcpCatalogConfigured.mockResolvedValue({ data: [] });
    mocks.mcpList.mockResolvedValue({ data: {} });
    mocks.mcpGet.mockRejectedValue({ response: { status: 404 } });
    mocks.mcpCatalogInstall.mockResolvedValue({ data: { config: { enabled: true } } });
    mocks.mcpTest.mockResolvedValue({ data: { success: true, message: '连接成功，找到 1 个工具。', tools_count: 1 } });
    mocks.listTools.mockResolvedValue({ data: [] });
    mocks.setToolEnabled.mockResolvedValue({ data: {} });
    mocks.customerTestConnector.mockResolvedValue({ data: { connector_id: 'tdp', success: true, status: 'connected', message: '连接测试通过。' } });
    mocks.customerEnableConnectorSchedule.mockResolvedValue({ data: { schedule_id: 'schedule-1', status: 'enabled', message: '同步调度已启用。' } });
    mocks.customerDisableConnectorSchedule.mockResolvedValue({ data: { schedule_id: 'schedule-1', status: 'disabled', message: '同步调度已暂停。' } });
    mocks.customerUpdateConnectorCredentials.mockResolvedValue({ data: { connector_id: 'tdp', status: 'updated', message: '凭据已更新' } });
    mocks.customerEnableDeviceSync.mockResolvedValue({ data: { connector_id: 'tdp', device_id: 'device-1', profile_id: 'device-device-1', status: 'enabled', message: '数据同步已绑定到当前设备。', capabilities: ['asset.search'], schedules: [] } });
    mocks.upsertConnectorSyncSchedule.mockResolvedValue({
      data: {
        id: 'schedule-1',
        connector_id: 'tdp',
        capability: 'asset.search',
        enabled: false,
        interval_seconds: 900,
        mode: 'incremental',
        retry_max_attempts: 1,
        retry_backoff_seconds: 60,
        timeout_seconds: 300,
      },
    });
    mocks.confirm.mockResolvedValue(true);
  });

  it('clicking the blank backdrop closes the config panel', async () => {
    const user = userEvent.setup();

    render(<DeviceIntegrationPage />);

    const productCard = await screen.findByRole('button', { name: /TDP-test-02/ });
    await user.click(productCard);

    expect(await screen.findByRole('button', { name: '关闭设备配置面板' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: '关闭设备配置面板' }));

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: '关闭设备配置面板' })).not.toBeInTheDocument();
    });
  });

  it('shows customer-facing data integration health', async () => {
    render(<DeviceIntegrationPage />);

    expect(await screen.findByText('Device Integration')).toBeInTheDocument();
    expect(await screen.findByText('数据接入健康')).toBeInTheDocument();
    expect(screen.getByText('安全产品接入')).toBeInTheDocument();
    expect(screen.getByText('安全产品状态')).toBeInTheDocument();
    expect(screen.getAllByText('数据源同步').length).toBeGreaterThan(0);
    expect(screen.getByText('TDP 数据同步')).toBeInTheDocument();
    expect(screen.getAllByText('API 已连接').length).toBeGreaterThan(0);
    expect(screen.getAllByText('同步 已阻断').length).toBeGreaterThan(0);
    expect(screen.getByText('凭据 已过期')).toBeInTheDocument();
    expect(screen.getByText('调度 0/1 启用 · 频率未启用')).toBeInTheDocument();
    expect(screen.getByText('凭据风险')).toBeInTheDocument();
    expect(screen.getByText('阻断与暂停')).toBeInTheDocument();
    expect(screen.getByText('TDP 同步被凭据阻断')).toBeInTheDocument();
  });

  it('updates one sync task interval without changing other schedule settings', async () => {
    const user = userEvent.setup();

    render(<DeviceIntegrationPage />);

    const productCard = await screen.findByRole('button', { name: /TDP-test-02/ });
    await user.click(productCard);
    await user.click(await screen.findByRole('button', { name: '同步' }));

    const frequency = await screen.findByLabelText('资产 同步频率');
    expect(frequency).toHaveValue('3600');

    await user.selectOptions(frequency, '900');

    await waitFor(() => {
      expect(mocks.upsertConnectorSyncSchedule).toHaveBeenCalledWith('tdp', expect.objectContaining({
        capability: 'asset.search',
        enabled: false,
        interval_seconds: 900,
        mode: 'incremental',
        full_interval_seconds: null,
        retry_max_attempts: 1,
        retry_backoff_seconds: 60,
        timeout_seconds: 300,
        credential_profile_id: 'prod',
      }));
    });
    expect(mocks.toastSuccess).toHaveBeenCalledWith('资产同步频率已更新为每 15 分钟');
  });

  it('shows sync options for an AsiaInfo TDA device when the connector package is available', async () => {
    const user = userEvent.setup();
    mocks.listDevices.mockResolvedValueOnce({
      data: [
        {
          id: 'tda-device-1',
          group_id: 'group-1',
          name: '测试TDA',
          storage_key: 'asiainfo_tda_api_v7_0',
          service_id: 'asiainfo_tda_api',
          enabled: true,
          verify_ssl: false,
          fields: { base_url: 'https://tda.example.com' },
          fields_set: { api_key: true, base_url: true },
          status: 'ok',
          message: 'HTTP 200',
          created_at: 0,
          updated_at: 0,
        },
      ],
    });
    mocks.listApiServices.mockResolvedValueOnce({
      data: [
        {
          id: 'asiainfo_tda_api_v7_0',
          name: '信桅高级威胁监测系统 TDA',
          enabled: true,
          status: 'ready',
          tool_count: 4,
          verify_ssl: false,
          integration_type: 'device',
          vendor: '亚信安全',
          description_cn: '亚信安全信桅 TDA 只读设备 API',
        },
      ],
    });
    mocks.customerConnectorSummary.mockResolvedValueOnce({
      data: {
        version: 'connector.customer.summary.v1',
        checked_at: '2026-06-09T10:00:00+00:00',
        trend_window_days: 14,
        summary: {
          data_sources: 1,
          connected_data_sources: 0,
          attention_data_sources: 0,
          sync_schedules: 0,
          enabled_sync_schedules: 0,
          expiry_risks: 0,
          sync_blocked: 0,
          paused_schedules: 0,
          recent_anomalies: 0,
        },
        data_sources: [
          {
            id: 'asiainfo-tda-v7-0',
            type: 'connector',
            name: 'AsiaInfo Xinwei TDA Connector',
            vendor: 'AsiaInfo Security',
            product: 'asiainfo_tda',
            product_version: '7.0',
            enabled: true,
            connection_status: 'not_configured',
            sync_status: 'not_synced',
            risk_level: 'medium',
            message: '当前数据源尚未绑定设备凭据。',
            capabilities: ['asset.search'],
            sync_targets: ['assets'],
            credential: {
              profile_id: null,
              profile_name: null,
              state: 'missing',
              healthy: false,
              blocking: false,
              expires_at: null,
              last_test_at: null,
              last_sync_at: null,
              last_successful_sync_at: null,
              fields: [],
              message: '当前数据源尚未绑定设备凭据。',
              recommended_action: '启用数据同步并绑定设备凭据。',
            },
            sync: {
              status: 'not_synced',
              last_sync_at: null,
              last_successful_sync_at: null,
              counts: { assets: 0, vulnerabilities: 0, alerts: 0, honeypot_events: 0 },
              failure_reason: null,
              recommended_action: '启用数据同步并绑定设备凭据。',
            },
            schedules: [],
            actions: [
              { id: 'test_connection', kind: 'test_connection', label: '测试连接', connector_id: 'asiainfo-tda-v7-0', requires_confirmation: false },
              { id: 'update_credentials', kind: 'update_credentials', label: '更新凭据', connector_id: 'asiainfo-tda-v7-0', profile_id: 'device_tda_device_1', requires_confirmation: true },
            ],
          },
        ],
        recent_events: [],
        trend: [],
      },
    });

    render(<DeviceIntegrationPage />);

    const productCard = await screen.findByRole('button', { name: /测试TDA/ });
    await user.click(productCard);
    await user.click(await screen.findByRole('button', { name: '同步' }));

    await screen.findByText('该安全产品已有标准化同步映射，但还没有创建同步调度。点击“启用数据同步”后会为当前设备创建调度。');
    expect(screen.getAllByText('AsiaInfo Xinwei TDA Connector').length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: '启用数据同步' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '更新同步凭据' })).not.toBeInTheDocument();
    expect(screen.queryByText('当前设备包暂未提供标准化数据同步映射。')).not.toBeInTheDocument();
  });

  it('does not show connector-only sync sources as security products', async () => {
    mocks.listDevices.mockResolvedValueOnce({ data: [] });

    render(<DeviceIntegrationPage />);

    expect(await screen.findByText('Device Integration')).toBeInTheDocument();
    expect(screen.getByText('安全产品状态')).toBeInTheDocument();
    expect(screen.getByText('0 个产品')).toBeInTheDocument();
    expect(screen.getByText('暂无已接入安全产品')).toBeInTheDocument();
    expect(screen.queryByText('API 未绑定')).not.toBeInTheDocument();
    expect(screen.queryByText('请在对应设备详情中启用数据同步，或先添加该安全产品设备。')).not.toBeInTheDocument();
    expect(screen.getByText('暂无设备 API 接入')).toBeInTheDocument();
    expect(screen.getByText('上方展示的是已启用的数据同步源；添加对应设备后可统一管理连接、工具调用和同步绑定')).toBeInTheDocument();
    expect(screen.queryByText('暂无已接入的设备')).not.toBeInTheDocument();
  });

  it('shows AsiaInfo Security as a first-class device vendor in the add wizard', async () => {
    const user = userEvent.setup();
    mocks.listApiServices.mockResolvedValue({
      data: [
        {
          id: 'tdp_api_v3_3_10',
          name: 'TDP',
          enabled: true,
          status: 'ready',
          tool_count: 21,
          verify_ssl: false,
          integration_type: 'device',
          vendor: 'threatbook',
        },
        {
          id: 'asiainfo_tda_api_v7_0',
          name: '信桅高级威胁监测系统 TDA',
          enabled: true,
          status: 'ready',
          tool_count: 4,
          verify_ssl: false,
          integration_type: 'device',
          vendor: '亚信安全',
          description_cn: '亚信安全信桅 TDA 只读设备 API',
        },
      ],
    });

    render(<DeviceIntegrationPage />);

    expect(await screen.findByText('Device Integration')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '添加接入' }));

    expect(await screen.findByText('亚信安全')).toBeInTheDocument();
    expect(screen.getByText('AsiaInfo Security')).toBeInTheDocument();
    expect(screen.queryByText('asiainfo')).not.toBeInTheDocument();

    await user.click(screen.getByText('亚信安全'));
    expect(await screen.findByText('信桅高级威胁监测系统 TDA')).toBeInTheDocument();
  });

  it('shows AsiaInfo threat intelligence MCP in the unified add wizard and saves via MCP APIs', async () => {
    const user = userEvent.setup();
    mocks.listApiServices.mockResolvedValue({
      data: [
        {
          id: 'asiainfo_tda_api_v7_0',
          name: '信桅高级威胁监测系统 TDA',
          enabled: true,
          status: 'ready',
          tool_count: 4,
          verify_ssl: false,
          integration_type: 'device',
          vendor: '亚信安全',
          description_cn: '亚信安全信桅 TDA 只读设备 API',
        },
      ],
    });
    mocks.mcpCatalogList.mockResolvedValue({
      data: [
        {
          id: 'asiainfo_threat_intel_mcp',
          name: 'AsiaInfo Security Threat Intelligence MCP',
          description: 'AsiaInfo Security vulnerability intelligence MCP service exposing query_vulnerability_by_id.',
          description_cn: '亚信安全威胁情报 MCP 服务，基于 HTTP Streamable 协议通过 query_vulnerability_by_id 提供漏洞情报查询。',
          category: 'vulnerability',
          tool_type: 'api',
          github: '',
          language: 'remote',
          license: 'Proprietary',
          stars: 0,
          transport: 'remote',
          install: {},
          remote: {
            url: '',
            url_env: 'ASIAINFO_THREAT_INTEL_MCP_URL',
            transport: 'http',
            headers: {
              'X-API-KEY': '{secret:asiainfo_threat_intel_mcp_key}',
            },
          },
          env_vars: {
            ASIAINFO_THREAT_INTEL_MCP_URL: {
              required: true,
              description: 'AsiaInfo Security HTTP Streamable MCP endpoint URL',
              secret: false,
            },
            ASIAINFO_THREAT_INTEL_MCP_KEY: {
              required: true,
              description: 'AsiaInfo Security MCP X-API-KEY',
              secret: true,
            },
          },
          system_deps: [],
          tags: ['threat-intelligence', 'vulnerability'],
          official: true,
          device_integration: true,
          requires_auth: true,
        },
      ],
    });

    render(<DeviceIntegrationPage />);

    expect(await screen.findByText('Device Integration')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '添加接入' }));

    expect(await screen.findByText('亚信安全')).toBeInTheDocument();
    expect(screen.getByText('2 种产品')).toBeInTheDocument();

    await user.click(screen.getByText('亚信安全'));
    expect(await screen.findByText('信桅高级威胁监测系统 TDA')).toBeInTheDocument();
    await user.click(screen.getByText('AsiaInfo Security Threat Intelligence MCP'));

    await user.type(screen.getByLabelText('ASIAINFO_THREAT_INTEL_MCP_URL'), 'https://ti.example.com/mcp');
    await user.type(screen.getByLabelText('ASIAINFO_THREAT_INTEL_MCP_KEY'), 'test-key');

    await user.click(screen.getByRole('button', { name: '连通测试' }));

    await waitFor(() => {
      expect(mocks.mcpTest).toHaveBeenCalledWith('asiainfo_threat_intel_mcp', expect.objectContaining({
        type: 'remote',
        url: 'https://ti.example.com/mcp',
        enabled: true,
        transport: 'http',
        headers: {
          'X-API-KEY': 'test-key',
        },
      }));
    });
    expect(await screen.findByText('连接成功，找到 1 个工具。')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: '确认接入' }));

    await waitFor(() => {
      expect(mocks.mcpCatalogInstall).toHaveBeenCalledWith('asiainfo_threat_intel_mcp', {
        enabled: true,
        credentials: {
          ASIAINFO_THREAT_INTEL_MCP_KEY: 'test-key',
        },
        env_overrides: {
          ASIAINFO_THREAT_INTEL_MCP_URL: 'https://ti.example.com/mcp',
        },
      });
    });
  });

  it('does not expose unmarked remote MCP catalog entries in the customer add wizard', async () => {
    const user = userEvent.setup();
    mocks.listApiServices.mockResolvedValue({ data: [] });
    mocks.mcpCatalogList.mockResolvedValue({
      data: [
        {
          id: 'nsfocus_mcp',
          name: 'NSFOCUS MCP',
          description: 'NSFOCUS threat analysis MCP service.',
          description_cn: '绿盟威胁分析 MCP 服务，提供安全能力调用、情报查询与分析辅助能力。',
          category: 'threat_intelligence',
          tool_type: 'api',
          github: '',
          language: 'remote',
          license: 'Proprietary',
          stars: 0,
          transport: 'remote',
          install: {},
          remote: {
            url: 'https://mcp.nsfocus.cn/mcp',
            transport: 'auto',
            auth: {
              type: 'apikey',
              location: 'query',
              param_name: 'apikey',
              value: '{secret:nsfocus_mcp_key}',
            },
          },
          env_vars: {
            NSFOCUS_MCP_KEY: {
              required: true,
              description: 'NSFOCUS MCP API Key',
              secret: true,
            },
          },
          system_deps: [],
          tags: ['threat-intelligence', 'analysis', 'secops'],
          official: true,
          requires_auth: true,
        },
      ],
    });

    render(<DeviceIntegrationPage />);

    expect(await screen.findByText('Device Integration')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '添加接入' }));

    expect(await screen.findByRole('heading', { name: '添加接入' })).toBeInTheDocument();
    expect(screen.queryByText('绿盟')).not.toBeInTheDocument();
    expect(screen.queryByText('NSFOCUS')).not.toBeInTheDocument();
    expect(screen.queryByText('NSFOCUS MCP')).not.toBeInTheDocument();
  });

  it('shows configured customer-facing MCP entries in health and active product sections', async () => {
    mocks.listDevices.mockResolvedValue({ data: [] });
    mocks.listApiServices.mockResolvedValue({ data: [] });
    mocks.customerConnectorSummary.mockResolvedValue({
      data: {
        version: 'connector.customer.summary.v1',
        checked_at: '2026-06-08T10:00:00+00:00',
        trend_window_days: 14,
        summary: {
          data_sources: 0,
          connected_data_sources: 0,
          attention_data_sources: 0,
          sync_schedules: 0,
          enabled_sync_schedules: 0,
          expiry_risks: 0,
          sync_blocked: 0,
          paused_schedules: 0,
          recent_anomalies: 0,
        },
        data_sources: [],
        recent_events: [],
        trend: [],
      },
    });
    mocks.mcpCatalogConfigured.mockResolvedValue({ data: ['asiainfo_threat_intel_mcp'] });
    mocks.mcpList.mockResolvedValue({
      data: {
        asiainfo_threat_intel_mcp: {
          status: 'disabled',
          tools_count: 0,
          resources_count: 0,
        },
      },
    });
    mocks.mcpCatalogList.mockResolvedValue({
      data: [
        {
          id: 'asiainfo_threat_intel_mcp',
          name: 'AsiaInfo Security Threat Intelligence MCP',
          description: 'AsiaInfo Security vulnerability intelligence MCP service exposing query_vulnerability_by_id.',
          description_cn: '亚信安全威胁情报 MCP 服务，基于 HTTP Streamable 协议通过 query_vulnerability_by_id 提供漏洞情报查询。',
          category: 'vulnerability',
          tool_type: 'api',
          github: '',
          language: 'remote',
          license: 'Proprietary',
          stars: 0,
          transport: 'remote',
          install: {},
          remote: {
            url: '',
            url_env: 'ASIAINFO_THREAT_INTEL_MCP_URL',
            transport: 'http',
            headers: {
              'X-API-KEY': '{secret:asiainfo_threat_intel_mcp_key}',
            },
          },
          env_vars: {},
          system_deps: [],
          tags: ['threat-intelligence', 'vulnerability'],
          official: true,
          device_integration: true,
          requires_auth: true,
        },
      ],
    });

    render(<DeviceIntegrationPage />);

    expect(await screen.findByText('Device Integration')).toBeInTheDocument();
    expect(screen.getByText('已接入安全产品')).toBeInTheDocument();
    expect(screen.queryByText('暂无已接入安全产品')).not.toBeInTheDocument();
    expect(screen.queryByText('暂无已接入的设备')).not.toBeInTheDocument();
    expect(screen.getByText('1 个产品')).toBeInTheDocument();
    expect(screen.getByText('0 个设备 · 1 个 MCP · 0 个同步源待绑定 · 0 个需关注')).toBeInTheDocument();
    expect(screen.getAllByText('AsiaInfo Security Threat Intelligence MCP').length).toBeGreaterThan(0);
    expect(screen.getAllByText('MCP 已停用').length).toBeGreaterThan(0);
  });

  it('counts configured MCPs in the connected over total product summary', async () => {
    mocks.customerConnectorSummary.mockResolvedValue({
      data: {
        version: 'connector.customer.summary.v1',
        checked_at: '2026-06-08T10:00:00+00:00',
        trend_window_days: 14,
        summary: {
          data_sources: 0,
          connected_data_sources: 0,
          attention_data_sources: 0,
          sync_schedules: 0,
          enabled_sync_schedules: 0,
          expiry_risks: 0,
          sync_blocked: 0,
          paused_schedules: 0,
          recent_anomalies: 0,
        },
        data_sources: [],
        recent_events: [],
        trend: [],
      },
    });
    mocks.mcpCatalogConfigured.mockResolvedValue({ data: ['asiainfo_threat_intel_mcp'] });
    mocks.mcpList.mockResolvedValue({
      data: {
        asiainfo_threat_intel_mcp: {
          status: 'disabled',
          tools_count: 0,
          resources_count: 0,
        },
      },
    });
    mocks.mcpCatalogList.mockResolvedValue({
      data: [
        {
          id: 'asiainfo_threat_intel_mcp',
          name: 'AsiaInfo Security Threat Intelligence MCP',
          description: 'AsiaInfo Security vulnerability intelligence MCP service exposing query_vulnerability_by_id.',
          description_cn: '亚信安全威胁情报 MCP 服务，基于 HTTP Streamable 协议通过 query_vulnerability_by_id 提供漏洞情报查询。',
          category: 'vulnerability',
          tool_type: 'api',
          github: '',
          language: 'remote',
          license: 'Proprietary',
          stars: 0,
          transport: 'remote',
          install: {},
          remote: {},
          env_vars: {},
          system_deps: [],
          tags: ['threat-intelligence', 'vulnerability'],
          official: true,
          device_integration: true,
          requires_auth: true,
        },
      ],
    });

    render(<DeviceIntegrationPage />);

    expect(await screen.findByText('Device Integration')).toBeInTheDocument();
    expect(screen.getByText('1/2')).toBeInTheDocument();
    expect(screen.getByText('1 个设备 · 1 个 MCP · 0 个同步源待绑定 · 0 个需关注')).toBeInTheDocument();
    expect(screen.getByText('2 个产品')).toBeInTheDocument();
    expect(screen.getAllByText('AsiaInfo Security Threat Intelligence MCP').length).toBeGreaterThan(0);
  });

  it('loads saved MCP URL and credential state when reopening a configured MCP', async () => {
    const user = userEvent.setup();
    mocks.listDevices.mockResolvedValue({ data: [] });
    mocks.listApiServices.mockResolvedValue({ data: [] });
    mocks.customerConnectorSummary.mockResolvedValue({
      data: {
        version: 'connector.customer.summary.v1',
        checked_at: '2026-06-08T10:00:00+00:00',
        trend_window_days: 14,
        summary: {
          data_sources: 0,
          connected_data_sources: 0,
          attention_data_sources: 0,
          sync_schedules: 0,
          enabled_sync_schedules: 0,
          expiry_risks: 0,
          sync_blocked: 0,
          paused_schedules: 0,
          recent_anomalies: 0,
        },
        data_sources: [],
        recent_events: [],
        trend: [],
      },
    });
    mocks.mcpCatalogConfigured.mockResolvedValue({ data: ['asiainfo_threat_intel_mcp'] });
    mocks.mcpList.mockResolvedValue({
      data: {
        asiainfo_threat_intel_mcp: {
          status: 'disabled',
          tools_count: 0,
          resources_count: 0,
        },
      },
    });
    mocks.mcpGet.mockResolvedValue({
      data: {
        name: 'asiainfo_threat_intel_mcp',
        status: {
          status: 'disabled',
          tools_count: 0,
          resources_count: 0,
        },
        tools: [],
        resources: [],
        config: {
          type: 'sse',
          url: 'https://llmsec.asiainfo-sec.com:8443/vulnquery/mcp',
          transport: 'http',
          headers: {
            'X-API-KEY': '{secret:asiainfo_threat_intel_mcp_key}',
          },
        },
      },
    });
    mocks.mcpCatalogList.mockResolvedValue({
      data: [
        {
          id: 'asiainfo_threat_intel_mcp',
          name: 'AsiaInfo Security Threat Intelligence MCP',
          description: 'AsiaInfo Security vulnerability intelligence MCP service exposing query_vulnerability_by_id.',
          description_cn: '亚信安全威胁情报 MCP 服务，基于 HTTP Streamable 协议通过 query_vulnerability_by_id 提供漏洞情报查询。',
          category: 'vulnerability',
          tool_type: 'api',
          github: '',
          language: 'remote',
          license: 'Proprietary',
          stars: 0,
          transport: 'remote',
          install: {},
          remote: {
            url: '',
            url_env: 'ASIAINFO_THREAT_INTEL_MCP_URL',
            transport: 'http',
            headers: {
              'X-API-KEY': '{secret:asiainfo_threat_intel_mcp_key}',
            },
          },
          env_vars: {
            ASIAINFO_THREAT_INTEL_MCP_URL: {
              required: true,
              description: 'AsiaInfo Security HTTP Streamable MCP endpoint URL',
              secret: false,
            },
            ASIAINFO_THREAT_INTEL_MCP_KEY: {
              required: true,
              description: 'AsiaInfo Security MCP X-API-KEY',
              secret: true,
            },
          },
          system_deps: [],
          tags: ['threat-intelligence', 'vulnerability'],
          official: true,
          device_integration: true,
          requires_auth: true,
        },
      ],
    });

    render(<DeviceIntegrationPage />);

    const productNames = await screen.findAllByText('AsiaInfo Security Threat Intelligence MCP');
    await user.click(productNames[productNames.length - 1]);

    expect(await screen.findByDisplayValue('https://llmsec.asiainfo-sec.com:8443/vulnquery/mcp')).toBeInTheDocument();
    const keyInput = screen.getByLabelText('ASIAINFO_THREAT_INTEL_MCP_KEY');
    expect(keyInput).toHaveValue('');
    expect(keyInput).toHaveAttribute('placeholder', '已保存，留空表示不修改');
    expect(screen.getByText('凭据已保存；输入新值会覆盖原凭据。')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: '确认接入' }));

    await waitFor(() => {
      expect(mocks.mcpCatalogInstall).toHaveBeenCalledWith('asiainfo_threat_intel_mcp', {
        enabled: false,
        env_overrides: {
          ASIAINFO_THREAT_INTEL_MCP_URL: 'https://llmsec.asiainfo-sec.com:8443/vulnquery/mcp',
        },
      });
    });
  });

  it('groups DBAPPSecurity APT and EDR devices under 安恒信息 in the add wizard', async () => {
    const user = userEvent.setup();
    mocks.listApiServices.mockResolvedValue({
      data: [
        {
          id: 'dbappsecurity_mingyu_apt_api_v2_0R77',
          name: '明御 APT 攻击预警平台',
          enabled: true,
          status: 'ready',
          tool_count: 6,
          verify_ssl: false,
          integration_type: 'device',
          vendor: '安恒信息',
        },
        {
          id: 'dbappsecurity_edr_api_v2_0_17',
          name: '明御主机安全及管理系统 EDR',
          enabled: true,
          status: 'ready',
          tool_count: 8,
          verify_ssl: false,
          integration_type: 'device',
          vendor: '安恒信息',
          description_cn: '安恒信息明御 EDR 只读设备 API',
        },
      ],
    });

    render(<DeviceIntegrationPage />);

    expect(await screen.findByText('Device Integration')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '添加接入' }));

    expect(await screen.findByText('安恒信息')).toBeInTheDocument();
    expect(screen.getByText('DBAPPSecurity')).toBeInTheDocument();
    expect(screen.getByText('2 种产品')).toBeInTheDocument();

    await user.click(screen.getByText('安恒信息'));
    expect(await screen.findByText('明御 APT 攻击预警平台')).toBeInTheDocument();
    expect(screen.getByText('明御主机安全及管理系统 EDR')).toBeInTheDocument();
  });

  it('shows DBAPPSecurity DAS-Gateway as an addable device integration', async () => {
    const user = userEvent.setup();
    mocks.listApiServices.mockResolvedValue({
      data: [
        {
          id: 'dbappsecurity_mingyu_apt_api_v2_0R77',
          name: '明御 APT 攻击预警平台',
          enabled: true,
          status: 'ready',
          tool_count: 6,
          verify_ssl: false,
          integration_type: 'device',
          vendor: '安恒信息',
        },
        {
          id: 'dbappsecurity_edr_api_v2_0_17',
          name: '明御主机安全及管理系统 EDR',
          enabled: true,
          status: 'ready',
          tool_count: 8,
          verify_ssl: false,
          integration_type: 'device',
          vendor: '安恒信息',
        },
        {
          id: 'dbappsecurity_das_gateway_api_v3_0_6_0r',
          name: '明御安全网关 DAS-Gateway（上网行为管理）',
          enabled: true,
          status: 'ready',
          tool_count: 9,
          verify_ssl: false,
          integration_type: 'device',
          vendor: '安恒信息',
          description_cn: '安恒信息明御安全网关客户侧低风险只读设备 API',
        },
      ],
    });

    render(<DeviceIntegrationPage />);

    expect(await screen.findByText('Device Integration')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '添加接入' }));

    expect(await screen.findByText('安恒信息')).toBeInTheDocument();
    expect(screen.getByText('3 种产品')).toBeInTheDocument();

    await user.click(screen.getByText('安恒信息'));
    expect(await screen.findByText('明御安全网关 DAS-Gateway（上网行为管理）')).toBeInTheDocument();
    expect(screen.getByText('安恒信息明御安全网关客户侧低风险只读设备 API')).toBeInTheDocument();
  });

  it('shows Mingjian scanner sync mapping after the device is saved', async () => {
    const user = userEvent.setup();
    mocks.listDevices.mockResolvedValue({
      data: [
        {
          id: 'mingjian-device-1',
          group_id: 'group-1',
          name: '明鉴漏洞扫描',
          storage_key: 'dbappsecurity_mingjian_vuln_scanner_api_v5_0',
          service_id: 'dbappsecurity_mingjian_vuln_scanner_api',
          enabled: true,
          verify_ssl: false,
          fields: { base_url: 'https://ras.example.com' },
          fields_set: { base_url: true, username: true, user_code: true },
          status: 'connected',
          created_at: 0,
          updated_at: 0,
        },
      ],
    });
    mocks.listApiServices.mockResolvedValue({
      data: [
        {
          id: 'dbappsecurity_mingjian_vuln_scanner_api_v5_0',
          name: '明鉴漏洞扫描系统',
          enabled: true,
          status: 'ready',
          tool_count: 7,
          verify_ssl: false,
          integration_type: 'device',
          vendor: '安恒信息',
          description_cn: '安恒信息明鉴漏洞扫描系统只读设备 API',
        },
      ],
    });
    mocks.customerConnectorSummary.mockResolvedValue({
      data: {
        version: 'connector.customer.summary.v1',
        checked_at: '2026-06-08T10:00:00+00:00',
        trend_window_days: 14,
        summary: {
          data_sources: 1,
          connected_data_sources: 0,
          attention_data_sources: 0,
          sync_schedules: 0,
          enabled_sync_schedules: 0,
          expiry_risks: 0,
          sync_blocked: 0,
          paused_schedules: 0,
          recent_anomalies: 0,
        },
        data_sources: [
          {
            id: 'dbappsecurity-mingjian-vuln-scanner-v5-0',
            type: 'connector',
            name: 'DBAPPSecurity Mingjian Vulnerability Scanner Connector',
            vendor: 'DBAPPSecurity',
            product: 'Mingjian Vuln Scanner',
            product_version: '5.0',
            enabled: true,
            connection_status: 'not_configured',
            sync_status: 'not_synced',
            risk_level: 'info',
            message: '设备 API 已接入，等待启用标准化数据同步。',
            capabilities: ['asset.search', 'vulnerability.search'],
            sync_targets: ['assets', 'vulnerabilities'],
            credential: {
              profile_id: null,
              profile_name: null,
              state: 'missing',
              healthy: false,
              blocking: false,
              expires_at: null,
              last_test_at: null,
              last_sync_at: null,
              last_successful_sync_at: null,
              fields: [],
              message: '未配置凭据。',
              recommended_action: '绑定设备后启用同步。',
            },
            sync: {
              status: 'not_synced',
              last_sync_at: null,
              last_successful_sync_at: null,
              counts: {},
              failure_reason: null,
              recommended_action: '启用数据同步。',
            },
            schedules: [],
            actions: [
              {
                id: 'test_connection',
                kind: 'test_connection',
                label: '测试连接',
                connector_id: 'dbappsecurity-mingjian-vuln-scanner-v5-0',
                requires_confirmation: false,
              },
            ],
          },
        ],
        recent_events: [],
        trend: [],
      },
    });

    render(<DeviceIntegrationPage />);

    const productCard = await screen.findByRole('button', { name: /明鉴漏洞扫描/ });
    await user.click(productCard);
    await user.click(await screen.findByRole('button', { name: '同步' }));

    expect(await screen.findAllByText('DBAPPSecurity Mingjian Vulnerability Scanner Connector')).not.toHaveLength(0);
    expect(screen.getAllByText('资产')).not.toHaveLength(0);
    expect(screen.getAllByText('漏洞')).not.toHaveLength(0);
    expect(screen.getByRole('button', { name: /启用数据同步/ })).toBeInTheDocument();
    expect(screen.queryByText('当前设备暂未提供数据同步')).not.toBeInTheDocument();
  });
});
