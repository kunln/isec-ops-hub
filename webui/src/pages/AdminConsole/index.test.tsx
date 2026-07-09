import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import '@/i18n.commercial-admin';
import i18n from '@/i18n';
import AdminConsolePage from './index';

const {
  commercialAPI,
  defaultBranding,
  setCachedCommercialBranding,
} = vi.hoisted(() => ({
  commercialAPI: {
    getBranding: vi.fn(),
    getLicense: vi.fn(),
    getFeatureFlags: vi.fn(),
    importLicense: vi.fn(),
    getUpdatePolicy: vi.fn(),
    updateUpdatePolicy: vi.fn(),
    getNotificationPolicy: vi.fn(),
    updateNotificationPolicy: vi.fn(),
    getConnectivity: vi.fn(),
    updateConnectivity: vi.fn(),
    getTelemetry: vi.fn(),
    updateTelemetry: vi.fn(),
    listPackages: vi.fn(),
    installPackage: vi.fn(),
    rollbackPackage: vi.fn(),
    getDiagnostics: vi.fn(),
    exportDiagnostics: vi.fn(),
    listAuditEvents: vi.fn(),
  },
  defaultBranding: {
    product_name: 'iSecOps Hub',
    company_name: 'iSecOps Hub Team',
    logo_light: null,
    logo_dark: null,
    favicon: null,
    support_url: null,
    copyright: 'Copyright iSecOps Hub Team',
    login_title: null,
    login_subtitle: null,
  },
  setCachedCommercialBranding: vi.fn(),
}));

vi.mock('@/api/commercial', () => ({
  commercialAPI,
  defaultBranding,
}));

vi.mock('@/hooks/useCommercialBranding', () => ({
  setCachedCommercialBranding,
}));

const baseLicense = {
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

const baseUpdatePolicy = {
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

const baseNotificationPolicy = {
  local_notifications_enabled: true,
  built_in_notifications_enabled: false,
  benefit_notifications_enabled: false,
  whats_new_notifications_enabled: false,
  vendor_notifications_enabled: false,
  announcement_notifications_enabled: true,
};

const baseConnectivity = {
  outbound_enabled: false,
  allowed_hosts: [],
  proxy_url: null,
  tls_verify: true,
  update_server_url: null,
  telemetry_server_url: null,
  license_server_url: null,
};

const baseTelemetry = {
  enabled: false,
  mode: 'off',
  include_logs: false,
  include_metrics: false,
  include_security_data: false,
  redaction_enabled: true,
  last_upload_at: null,
};

const baseDiagnostics = {
  generated_at: '2026-06-01T00:00:00Z',
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

function renderAdmin(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/admin" element={<AdminConsolePage />} />
        <Route path="/admin/:section" element={<AdminConsolePage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('AdminConsolePage', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    await i18n.changeLanguage('zh-CN');

    commercialAPI.getBranding.mockResolvedValue({ data: defaultBranding });
    commercialAPI.getLicense.mockResolvedValue({ data: baseLicense });
    commercialAPI.getUpdatePolicy.mockResolvedValue({ data: baseUpdatePolicy });
    commercialAPI.getNotificationPolicy.mockResolvedValue({ data: baseNotificationPolicy });
    commercialAPI.getConnectivity.mockResolvedValue({ data: baseConnectivity });
    commercialAPI.getTelemetry.mockResolvedValue({ data: baseTelemetry });
    commercialAPI.listPackages.mockResolvedValue({ data: [] });
    commercialAPI.getDiagnostics.mockResolvedValue({ data: baseDiagnostics });
    commercialAPI.getFeatureFlags.mockResolvedValue({
      data: {
        license_status: 'unlicensed',
        edition: 'community',
        licensed_features: [],
        flags: {},
      },
    });
    commercialAPI.listAuditEvents.mockResolvedValue({ data: [] });
    commercialAPI.updateUpdatePolicy.mockImplementation((data) => Promise.resolve({
      data: { ...baseUpdatePolicy, ...data },
    }));
    commercialAPI.updateNotificationPolicy.mockImplementation((data) => Promise.resolve({
      data: { ...baseNotificationPolicy, ...data },
    }));
    commercialAPI.updateConnectivity.mockImplementation((data) => Promise.resolve({
      data: { ...baseConnectivity, ...data },
    }));
  });

  it('saves update policy changes from the update page', async () => {
    const user = userEvent.setup();
    renderAdmin('/admin/update');

    const updateCheckToggle = await screen.findByLabelText('允许更新检查');
    await user.click(updateCheckToggle);
    await user.click(screen.getByRole('button', { name: '保存' }));

    await waitFor(() => {
      expect(commercialAPI.updateUpdatePolicy).toHaveBeenCalledWith(
        expect.objectContaining({
          update_check_enabled: true,
          auto_check: true,
        }),
      );
    });
  });

  it('saves notification policy changes from the notifications page', async () => {
    const user = userEvent.setup();
    renderAdmin('/admin/notifications');

    const benefitToggle = await screen.findByLabelText('允许福利提醒');
    await user.click(benefitToggle);
    await user.click(screen.getByRole('button', { name: '保存' }));

    await waitFor(() => {
      expect(commercialAPI.updateNotificationPolicy).toHaveBeenCalledWith(
        expect.objectContaining({
          benefit_notifications_enabled: true,
        }),
      );
    });
  });

  it('saves connectivity policy changes from the connectivity page', async () => {
    const user = userEvent.setup();
    renderAdmin('/admin/connectivity');

    const outboundToggle = await screen.findByLabelText('允许主动外联');
    await user.click(outboundToggle);
    await user.click(screen.getByRole('button', { name: '保存' }));

    await waitFor(() => {
      expect(commercialAPI.updateConnectivity).toHaveBeenCalledWith(
        expect.objectContaining({
          outbound_enabled: true,
        }),
      );
    });
  });

  it('renders admin console through the i18n namespace in English', async () => {
    await i18n.changeLanguage('en-US');
    const { container } = renderAdmin('/admin/update');

    expect(await screen.findByRole('heading', { name: 'Commercial Admin Console' })).toBeInTheDocument();
    expect(screen.getByLabelText('Allow Update Checks')).toBeInTheDocument();
    expect(screen.queryByText('本地管理员控制台')).not.toBeInTheDocument();
    expect(container.textContent).not.toContain('adminConsole.');
  });

  it.each([
    ['/admin/branding', () => screen.findByLabelText('产品名称')],
    ['/admin/diagnostics', () => screen.findByRole('heading', { name: '诊断信息' })],
    ['/admin/audit', () => screen.findByRole('heading', { name: '商业化审计' })],
  ])('opens commercial maintenance section %s', async (path, findExpectedControl) => {
    renderAdmin(path);

    expect(await findExpectedControl()).toBeInTheDocument();
  });
});
