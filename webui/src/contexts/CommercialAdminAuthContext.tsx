import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import i18n from '@/i18n';
import { commercialAdminAuthApi } from '@/api/commercialAdminAuth';
import type { LocalUser } from '@/api/auth';

interface CommercialAdminAuthContextValue {
  loading: boolean;
  error: string | null;
  user: LocalUser | null;
  refresh: () => Promise<void>;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const CommercialAdminAuthContext = createContext<CommercialAdminAuthContextValue | null>(null);

export function CommercialAdminAuthProvider({ children }: { children: React.ReactNode }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [user, setUser] = useState<LocalUser | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const me = await commercialAdminAuthApi.me();
      setUser(me);
      setError(null);
    } catch (err: any) {
      if (err?.response?.status === 401) {
        setUser(null);
        setError(null);
      } else {
        setUser(null);
        setError(
          err?.response?.data?.message ||
            err?.response?.data?.detail ||
            err?.message ||
            i18n.t('adminConsole:commercialShell.errors.status'),
        );
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const onAuthExpired = () => {
      setError(null);
      setUser(null);
    };
    window.addEventListener('flocks:auth-expired', onAuthExpired);
    return () => window.removeEventListener('flocks:auth-expired', onAuthExpired);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const me = await commercialAdminAuthApi.login({ username, password });
    setError(null);
    setUser(me);
  }, []);

  const logout = useCallback(async () => {
    await commercialAdminAuthApi.logout();
    setError(null);
    setUser(null);
  }, []);

  const value = useMemo<CommercialAdminAuthContextValue>(() => ({
    loading,
    error,
    user,
    refresh,
    login,
    logout,
  }), [loading, error, user, refresh, login, logout]);

  return (
    <CommercialAdminAuthContext.Provider value={value}>
      {children}
    </CommercialAdminAuthContext.Provider>
  );
}

export function useCommercialAdminAuth() {
  const ctx = useContext(CommercialAdminAuthContext);
  if (!ctx) {
    throw new Error('useCommercialAdminAuth must be used within CommercialAdminAuthProvider');
  }
  return ctx;
}
