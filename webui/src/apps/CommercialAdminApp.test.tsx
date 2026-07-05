import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@/i18n.commercial-admin';
import i18n from '@/i18n';
import CommercialAdminApp from './CommercialAdminApp';

const { commercialAdminAuthApi } = vi.hoisted(() => ({
  commercialAdminAuthApi: {
    login: vi.fn(),
    me: vi.fn(),
    logout: vi.fn(),
  },
}));

vi.mock('@/api/commercialAdminAuth', () => ({
  commercialAdminAuthApi,
}));

vi.mock('@/components/common/BackendStatusBanner', () => ({
  BackendStatusBanner: () => null,
}));

vi.mock('@/pages/AdminConsole', () => ({
  default: () => <h2>Commercial Admin Route Loaded</h2>,
}));

vi.mock('@/pages/Security/admin', () => ({
  default: () => <h2>Security Admin Route Loaded</h2>,
}));

const commercialAdminUser = {
  id: 'commercial-admin:admini',
  username: 'admini',
  role: 'commercial_admin',
  status: 'active',
  must_reset_password: false,
};

describe('CommercialAdminApp acceptance', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    await i18n.changeLanguage('zh-CN');
    window.history.pushState({}, '', '/login');

    commercialAdminAuthApi.me.mockRejectedValue({ response: { status: 401 } });
    commercialAdminAuthApi.login.mockResolvedValue(commercialAdminUser);
    commercialAdminAuthApi.logout.mockResolvedValue(undefined);
  });

  it('logs in with the commercial admin auth flow and opens maintenance routes', async () => {
    const user = userEvent.setup();
    render(<CommercialAdminApp />);

    await user.type(await screen.findByLabelText('用户名'), 'admini');
    await user.type(screen.getByLabelText('密码'), 'Mv7XTdJtLLeJ-sgD');
    await user.click(screen.getByRole('button', { name: '登录' }));

    await waitFor(() => {
      expect(commercialAdminAuthApi.login).toHaveBeenCalledWith({
        username: 'admini',
        password: 'Mv7XTdJtLLeJ-sgD',
      });
    });
    expect(await screen.findByText('Commercial Admin Route Loaded')).toBeInTheDocument();
    expect(window.location.pathname).toBe('/admin');

    await user.click(screen.getByRole('link', { name: '安全业务后台' }));

    expect(await screen.findByText('Security Admin Route Loaded')).toBeInTheDocument();
    expect(window.location.pathname).toBe('/security-admin');
  });
});
