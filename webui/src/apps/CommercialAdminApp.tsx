import { Suspense, lazy, useState, type FormEvent } from 'react';
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Building2, Gauge, LogOut, ShieldCheck } from 'lucide-react';
import { ToastProvider } from '@/components/common/Toast';
import { ConfirmProvider } from '@/components/common/ConfirmDialog';
import { BackendStatusBanner } from '@/components/common/BackendStatusBanner';
import RoutePageSkeleton from '@/components/common/RoutePageSkeleton';
import LoadingSpinner from '@/components/common/LoadingSpinner';
import LanguageSwitcher from '@/components/common/LanguageSwitcher';
import {
  CommercialAdminAuthProvider,
  useCommercialAdminAuth,
} from '@/contexts/CommercialAdminAuthContext';

const AdminConsolePage = lazy(() => import('@/pages/AdminConsole'));
const SecurityAdminPage = lazy(() => import('@/pages/Security/admin'));

function CommercialAdminLogin() {
  const { t } = useTranslation('adminConsole');
  const { login, error } = useCommercialAdminAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setSubmitError(null);
    try {
      await login(username, password);
    } catch (err: any) {
      setSubmitError(
        err?.response?.data?.detail ||
          err?.response?.data?.message ||
          err?.message ||
          t('commercialShell.errors.login'),
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 px-4 py-8 text-white">
      <div className="mx-auto flex min-h-[calc(100vh-4rem)] max-w-md items-center">
        <form onSubmit={onSubmit} className="w-full rounded-lg border border-white/10 bg-white p-6 text-slate-950 shadow-2xl">
          <div className="mb-6 flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-semibold">{t('commercialShell.login.title')}</h1>
              <p className="mt-1 text-sm text-slate-500">{t('commercialShell.login.subtitle')}</p>
            </div>
            <LanguageSwitcher />
          </div>

          {(submitError || error) && (
            <div className="mb-4 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {submitError || error}
            </div>
          )}

          <label className="block">
            <span className="mb-1 block text-sm font-medium text-slate-700">{t('commercialShell.login.username')}</span>
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-900 focus:ring-2 focus:ring-slate-100"
            />
          </label>

          <label className="mt-4 block">
            <span className="mb-1 block text-sm font-medium text-slate-700">{t('commercialShell.login.password')}</span>
            <input
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              type="password"
              autoComplete="current-password"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-900 focus:ring-2 focus:ring-slate-100"
            />
          </label>

          <button
            type="submit"
            disabled={submitting || !username.trim() || !password}
            className="mt-6 inline-flex w-full items-center justify-center rounded-lg bg-slate-900 px-4 py-2.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
          >
            {submitting ? t('commercialShell.login.signingIn') : t('commercialShell.login.signIn')}
          </button>
        </form>
      </div>
    </div>
  );
}

function CommercialAdminShell() {
  const { t } = useTranslation('adminConsole');
  const location = useLocation();
  const { user, logout } = useCommercialAdminAuth();
  const navItems = [
    { href: '/admin', label: t('commercialShell.nav.admin'), icon: Gauge },
    { href: '/security-admin', label: t('commercialShell.nav.securityAdmin'), icon: ShieldCheck },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="border-b border-gray-200 bg-white">
        <div className="flex h-14 items-center justify-between px-5">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-900 text-white">
              <Building2 className="h-5 w-5" />
            </div>
            <div>
              <div className="text-sm font-semibold text-gray-950">{t('commercialShell.title')}</div>
              <div className="text-xs text-gray-500">{t('commercialShell.subtitle')}</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <LanguageSwitcher />
            <span className="text-sm text-gray-600">{user?.username}</span>
            <button
              type="button"
              onClick={() => void logout()}
              className="inline-flex items-center gap-2 rounded-lg border border-gray-200 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50"
            >
              <LogOut className="h-4 w-4" />
              {t('commercialShell.logout')}
            </button>
          </div>
        </div>
      </header>

      <div className="grid min-h-[calc(100vh-3.5rem)] grid-cols-[220px_minmax(0,1fr)]">
        <aside className="border-r border-gray-200 bg-white p-3">
          <nav className="space-y-1">
            {navItems.map((item) => {
              const active = location.pathname === item.href || location.pathname.startsWith(`${item.href}/`);
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium ${
                    active ? 'bg-slate-900 text-white' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-950'
                  }`}
                >
                  <item.icon className="h-4 w-4" />
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </aside>

        <main className="min-w-0 p-6">
          <Suspense fallback={<RoutePageSkeleton />}>
            <Routes>
              <Route path="/" element={<Navigate to="/admin" replace />} />
              <Route path="/admin/*" element={<AdminConsolePage />} />
              <Route path="/security-admin/*" element={<SecurityAdminPage />} />
              <Route path="*" element={<Navigate to="/admin" replace />} />
            </Routes>
          </Suspense>
        </main>
      </div>
    </div>
  );
}

function CommercialAdminRoutes() {
  const { loading, user } = useCommercialAdminAuth();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <Routes>
      {!user ? (
        <>
          <Route path="/login" element={<CommercialAdminLogin />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </>
      ) : (
        <>
          <Route path="/login" element={<Navigate to="/admin" replace />} />
          <Route path="/*" element={<CommercialAdminShell />} />
        </>
      )}
    </Routes>
  );
}

export default function CommercialAdminApp() {
  return (
    <ToastProvider>
      <ConfirmProvider>
        <BrowserRouter>
          <CommercialAdminAuthProvider>
            <BackendStatusBanner />
            <CommercialAdminRoutes />
          </CommercialAdminAuthProvider>
        </BrowserRouter>
      </ConfirmProvider>
    </ToastProvider>
  );
}
