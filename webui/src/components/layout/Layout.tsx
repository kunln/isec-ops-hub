import { Outlet, Link, useLocation, matchPath } from 'react-router-dom';
import {
  Home,
  MessageSquare,
  Bot,
  Workflow,
  ListTodo,
  Wrench,
  Brain,
  BookOpen,
  X,
  ChevronLeft,
  ChevronRight,
  Menu,
  Radio,
  FolderOpen,
  Sparkles,
  ArrowUpCircle,
  UserCog,
  Archive,
  ServerCog,
  ScrollText,
  ShieldCheck,
} from 'lucide-react';
import { useState, useEffect, useLayoutEffect, useCallback, useMemo, useRef, lazy, Suspense } from 'react';
import { useTranslation } from 'react-i18next';
import LanguageSwitcher from '@/components/common/LanguageSwitcher';
// Modals are only rendered after the user clicks/triggers them; pulling them
// into the eager Layout chunk costs ~1.7k LOC + i18n keys + lucide icons that
// the home page never needs. To keep the lazy split effective, we don't
// re-import the dismissal helpers from the modal modules (a static named
// import would force Rollup to bundle the whole module eagerly), and instead
// inline the two localStorage keys here. Keep these in sync with the keys
// declared in OnboardingModal.tsx / UpdateModal.tsx.
const ONBOARDING_DISMISSED_KEY = 'flocks_onboarding_dismissed';
const UPDATE_DISMISSED_KEY = 'flocks-update-dismissed';
function isOnboardingDismissed(): boolean {
  return localStorage.getItem(ONBOARDING_DISMISSED_KEY) === 'true';
}
const OnboardingModal = lazy(() => import('@/components/common/OnboardingModal'));
const UpdateModal = lazy(() => import('@/components/common/UpdateModal'));
const NotificationModal = lazy(() => import('@/components/common/NotificationModal'));
import { checkUpdate, type VersionInfo } from '@/api/update';
import {
  ackNotification,
  getActiveNotifications,
  getNotificationAckStatus,
  type UserNotification,
} from '@/api/notifications';
import { useAuth } from '@/contexts/AuthContext';
import { getLocalizedReleaseNotes } from '@/utils/releaseNotes';
import { useCommercialBranding } from '@/hooks/useCommercialBranding';
import { canAccessPath } from '@/utils/accessControl';
import {
  commercialAPI,
  type ConnectivityConfig,
  type NotificationPolicy,
  type UpdatePolicy as CommercialUpdatePolicy,
} from '@/api/commercial';

const UPDATE_CHECK_INTERVAL_MS = 3_600_000;
const UPDATE_CHECK_MIN_GAP_MS = 600_000;
const DEFAULT_CONNECTIVITY_POLICY: ConnectivityConfig = {
  outbound_enabled: false,
  allowed_hosts: [],
  proxy_url: null,
  tls_verify: true,
  update_server_url: null,
  telemetry_server_url: null,
  license_server_url: null,
};
const DEFAULT_NOTIFICATION_POLICY: NotificationPolicy = {
  local_notifications_enabled: true,
  built_in_notifications_enabled: false,
  benefit_notifications_enabled: false,
  whats_new_notifications_enabled: false,
  vendor_notifications_enabled: false,
  announcement_notifications_enabled: true,
};
const DEFAULT_UPDATE_POLICY: CommercialUpdatePolicy = {
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

function buildUpdateNotification(info: VersionInfo | null, language: string, productName: string): UserNotification | null {
  const releaseNotes = getLocalizedReleaseNotes(info?.release_notes, language);
  if (!info || info.error || !releaseNotes) return null;

  const version = info.latest_version ?? info.current_version;
  if (!version || version === 'unknown') return null;

  const isZh = language.toLowerCase().startsWith('zh');
  return {
    id: `whats-new-${version}`,
    kind: 'whats_new',
    title: isZh ? `${productName} v${version} 更新内容` : `What's new in ${productName} v${version}`,
    summary: isZh ? '这里是本次版本值得关注的新功能和变化。' : 'Here are the highlights from this version.',
    body: releaseNotes,
    highlights: [],
    version,
    priority: 20,
  };
}

export default function Layout() {
  const location = useLocation();
  const { user } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const isHome = location.pathname === '/';
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [showUpdate, setShowUpdate] = useState(false);
  const { t, i18n } = useTranslation('nav');
  const { branding } = useCommercialBranding();
  const productName = branding.product_name;
  const [hasUpdate, setHasUpdate] = useState(false);
  const [latestVersion, setLatestVersion] = useState<string | null>(null);
  const [currentVersion, setCurrentVersion] = useState<string | null>(null);
  const [updateInfo, setUpdateInfo] = useState<VersionInfo | null>(null);
  const [hasCompletedUpdateCheck, setHasCompletedUpdateCheck] = useState(false);
  const lastUpdateCheckAtRef = useRef(0);
  const checkingUpdateRef = useRef(false);
  const lastPromptedVersionRef = useRef<string | null>(null);
  const [notifications, setNotifications] = useState<UserNotification[]>([]);
  const [updateNotification, setUpdateNotification] = useState<UserNotification | null>(null);
  const [backendNotificationsReady, setBackendNotificationsReady] = useState(false);
  const [updateNotificationReady, setUpdateNotificationReady] = useState(false);
  const [acknowledgingNotificationIds, setAcknowledgingNotificationIds] = useState<string[]>([]);
  const lastNotificationFetchKeyRef = useRef<string | null>(null);
  const [commercialPoliciesReady, setCommercialPoliciesReady] = useState(false);
  const [connectivityPolicy, setConnectivityPolicy] = useState<ConnectivityConfig>(DEFAULT_CONNECTIVITY_POLICY);
  const [notificationPolicy, setNotificationPolicy] = useState<NotificationPolicy>(DEFAULT_NOTIFICATION_POLICY);
  const [commercialUpdatePolicy, setCommercialUpdatePolicy] = useState<CommercialUpdatePolicy>(DEFAULT_UPDATE_POLICY);
  const updateCheckAllowed = commercialPoliciesReady
    && connectivityPolicy.outbound_enabled
    && commercialUpdatePolicy.update_check_enabled
    && commercialUpdatePolicy.legacy_flocks_update_sources_enabled;
  const updateApplyAllowed = commercialPoliciesReady
    && connectivityPolicy.outbound_enabled
    && commercialUpdatePolicy.update_apply_enabled
    && commercialUpdatePolicy.legacy_flocks_update_sources_enabled;
  const notificationFetchAllowed = commercialPoliciesReady
    && (
      notificationPolicy.local_notifications_enabled
      || notificationPolicy.built_in_notifications_enabled
    );
  const whatsNewNotificationsAllowed = updateCheckAllowed
    && notificationPolicy.whats_new_notifications_enabled;
  const vendorOnboardingAllowed = commercialPoliciesReady
    && connectivityPolicy.outbound_enabled
    && notificationPolicy.vendor_notifications_enabled;
  // useLayoutEffect runs synchronously before paint, so there's no flash on initial load.
  // It also re-runs when the user navigates back to /, covering both cases in one place.
  useLayoutEffect(() => {
    if (commercialPoliciesReady && isHome && !isOnboardingDismissed()) {
      setShowOnboarding(true);
    }
  }, [commercialPoliciesReady, isHome]);

  const handleOpenOnboarding = useCallback(() => setShowOnboarding(true), []);

  useEffect(() => {
    window.addEventListener('flocks:open-onboarding', handleOpenOnboarding);
    return () => window.removeEventListener('flocks:open-onboarding', handleOpenOnboarding);
  }, [handleOpenOnboarding]);

  useEffect(() => {
    let cancelled = false;
    setCommercialPoliciesReady(false);
    void Promise.all([
      commercialAPI.getConnectivity(),
      commercialAPI.getNotificationPolicy(),
      commercialAPI.getUpdatePolicy(),
    ])
      .then(([connectivityRes, notificationRes, updateRes]) => {
        if (cancelled) return;
        setConnectivityPolicy({ ...DEFAULT_CONNECTIVITY_POLICY, ...connectivityRes.data });
        setNotificationPolicy({ ...DEFAULT_NOTIFICATION_POLICY, ...notificationRes.data });
        setCommercialUpdatePolicy({ ...DEFAULT_UPDATE_POLICY, ...updateRes.data });
      })
      .catch(() => {
        if (cancelled) return;
        setConnectivityPolicy(DEFAULT_CONNECTIVITY_POLICY);
        setNotificationPolicy(DEFAULT_NOTIFICATION_POLICY);
        setCommercialUpdatePolicy(DEFAULT_UPDATE_POLICY);
      })
      .finally(() => {
        if (!cancelled) {
          setCommercialPoliciesReady(true);
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const refreshUpdateStatus = useCallback(async (force = false) => {
    if (!updateCheckAllowed) {
      setUpdateInfo(null);
      setHasUpdate(false);
      setLatestVersion(null);
      setHasCompletedUpdateCheck(true);
      return;
    }

    const now = Date.now();
    if (checkingUpdateRef.current) return;
    if (!force && now - lastUpdateCheckAtRef.current < UPDATE_CHECK_MIN_GAP_MS) return;

    checkingUpdateRef.current = true;
    lastUpdateCheckAtRef.current = now;

    try {
      const info = await checkUpdate(i18n.language);
      setUpdateInfo(info);

      if (info.current_version) {
        setCurrentVersion(info.current_version);
      }

      if (info.has_update && info.latest_version) {
        setHasUpdate(true);
        setLatestVersion(info.latest_version);

        if (
          lastPromptedVersionRef.current !== info.latest_version
          && localStorage.getItem(UPDATE_DISMISSED_KEY) !== info.current_version
        ) {
          lastPromptedVersionRef.current = info.latest_version;
          setShowUpdate(true);
        }
        return;
      }

      if (!info.error) {
        setHasUpdate(false);
        setLatestVersion(info.latest_version);
      }
    } catch {
      // Keep the last known update state on transient failures.
    } finally {
      checkingUpdateRef.current = false;
      setHasCompletedUpdateCheck(true);
    }
  }, [i18n.language, updateCheckAllowed]);

  useEffect(() => {
    if (!commercialPoliciesReady) return;
    if (!updateCheckAllowed) {
      setUpdateInfo(null);
      setHasUpdate(false);
      setLatestVersion(null);
      setHasCompletedUpdateCheck(true);
      return;
    }

    refreshUpdateStatus(true);

    const intervalId = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        refreshUpdateStatus();
      }
    }, UPDATE_CHECK_INTERVAL_MS);

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        refreshUpdateStatus();
      }
    };

    const handleWindowFocus = () => {
      refreshUpdateStatus();
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('focus', handleWindowFocus);

    return () => {
      window.clearInterval(intervalId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('focus', handleWindowFocus);
    };
  }, [commercialPoliciesReady, refreshUpdateStatus, updateCheckAllowed]);

  useEffect(() => {
    if (!user?.id) {
      setNotifications([]);
      setUpdateNotification(null);
      setBackendNotificationsReady(false);
      setUpdateNotificationReady(false);
      setAcknowledgingNotificationIds([]);
      lastNotificationFetchKeyRef.current = null;
      return;
    }
    if (!commercialPoliciesReady) return;
    if (!notificationFetchAllowed) {
      setNotifications([]);
      setBackendNotificationsReady(true);
      lastNotificationFetchKeyRef.current = null;
      return;
    }
    if (!hasCompletedUpdateCheck) return;

    const fetchKey = `${user.id}:${i18n.language}:${currentVersion ?? 'pending-version'}`;
    if (lastNotificationFetchKeyRef.current === fetchKey) return;
    const previousFetchKey = lastNotificationFetchKeyRef.current;
    lastNotificationFetchKeyRef.current = fetchKey;
    setBackendNotificationsReady(false);

    let cancelled = false;
    void getActiveNotifications(i18n.language, currentVersion)
      .then((items) => {
        if (cancelled) return;
        setNotifications((prev) => {
          const byId = new Map(prev.map((item) => [item.id, item]));
          for (const item of items) {
            byId.set(item.id, item);
          }
          return Array.from(byId.values()).sort((a, b) => a.priority - b.priority);
        });
        setBackendNotificationsReady(true);
      })
      .catch(() => {
        // Notification failures should never block the main product surface.
        if (lastNotificationFetchKeyRef.current === fetchKey) {
          lastNotificationFetchKeyRef.current = previousFetchKey;
        }
        if (!cancelled) {
          setBackendNotificationsReady(true);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [
    commercialPoliciesReady,
    currentVersion,
    hasCompletedUpdateCheck,
    i18n.language,
    notificationFetchAllowed,
    user?.id,
  ]);

  useEffect(() => {
    if (!user?.id) {
      setUpdateNotification(null);
      setUpdateNotificationReady(false);
      return;
    }
    if (!commercialPoliciesReady) return;
    if (!whatsNewNotificationsAllowed) {
      setUpdateNotification(null);
      setUpdateNotificationReady(true);
      return;
    }
    if (!hasCompletedUpdateCheck) return;

    setUpdateNotificationReady(false);
    const notification = buildUpdateNotification(updateInfo, i18n.language, productName);
    if (!notification) {
      setUpdateNotification(null);
      setUpdateNotificationReady(true);
      return;
    }

    let cancelled = false;
    void getNotificationAckStatus(notification.id)
      .then((status) => {
        if (cancelled) return;
        setUpdateNotification(status.acknowledged ? null : notification);
        setUpdateNotificationReady(true);
      })
      .catch(() => {
        if (cancelled) return;
        setUpdateNotification(notification);
        setUpdateNotificationReady(true);
      });

    return () => {
      cancelled = true;
    };
  }, [
    commercialPoliciesReady,
    hasCompletedUpdateCheck,
    i18n.language,
    productName,
    updateInfo,
    user?.id,
    whatsNewNotificationsAllowed,
  ]);

  const allNotifications = updateNotification
    ? [...notifications, updateNotification].sort((a, b) => a.priority - b.priority)
    : notifications;
  const visibleNotifications = backendNotificationsReady && updateNotificationReady && !showOnboarding && !showUpdate && allNotifications.length > 0
    ? allNotifications
    : [];

  const removeNotifications = useCallback((items: UserNotification[]) => {
    const visibleIds = new Set(items.map((item) => item.id));
    setNotifications((prev) => prev.filter((item) => !visibleIds.has(item.id)));
    setUpdateNotification((prev) => (prev && visibleIds.has(prev.id) ? null : prev));
  }, []);

  const closeVisibleNotification = useCallback((notification?: UserNotification) => {
    if (visibleNotifications.length === 0 || acknowledgingNotificationIds.length > 0) return;
    removeNotifications(notification ? [notification] : visibleNotifications);
  }, [acknowledgingNotificationIds.length, removeNotifications, visibleNotifications]);

  const dismissVisibleNotificationForever = useCallback(async () => {
    if (acknowledgingNotificationIds.length > 0) return;
    if (visibleNotifications.length === 0) return;
    setAcknowledgingNotificationIds(visibleNotifications.map((item) => item.id));
    try {
      await Promise.all(visibleNotifications.map((item) => ackNotification(item.id)));
    } catch {
      // Keep the UI moving; the server will retry visibility on the next login if dismiss failed.
    } finally {
      removeNotifications(visibleNotifications);
      setAcknowledgingNotificationIds([]);
    }
  }, [acknowledgingNotificationIds.length, removeNotifications, visibleNotifications]);


  // Stable across re-renders triggered by location changes (sidebar nav clicks)
  // — the array only depends on the i18n translation function, which itself is
  // stable as long as the language doesn't change. Without this, every route
  // switch rebuilt the whole nav structure and cascaded re-renders down to
  // every <Link>, contributing to perceptible navigation lag.
  const navigation = useMemo(
    () => {
      const sections = [
      {
        name: '',
        items: [
          { name: t('flocksHome'), href: '/', icon: Home },
        ],
      },
      {
        name: t('aiWorkbench'),
        items: [
          { name: t('sessions'), href: '/sessions', icon: MessageSquare },
          { name: t('workspace'), href: '/workspace', icon: FolderOpen },
          { name: t('tasks'), href: '/tasks', icon: ListTodo },
          { name: t('workflows'), href: '/workflows', icon: Workflow },
        ],
      },
      {
        name: t('agentHub'),
        items: [
          { name: t('agents'), href: '/agents', icon: Bot },
          { name: t('skills'), href: '/skills', icon: BookOpen },
          { name: t('tools'), href: '/tools', icon: Wrench },
          { name: t('deviceIntegration'), href: '/devices', icon: ServerCog },
          { name: t('hub'), href: '/hub', icon: Archive },
          { name: t('models'), href: '/models', icon: Brain },
          { name: t('channels'), href: '/channels', icon: Radio },
        ],
      },
      {
        name: t('securityCenter'),
        items: [
          { name: t('security'), href: '/security', icon: ShieldCheck },
        ],
      },
      {
        name: t('systemCenter'),
        items: [
          { name: t('accountManagement'), href: '/config', icon: UserCog },
          { name: t('systemLog'), href: '/system-logs', icon: ScrollText },
        ],
      },
      ];
      return sections
        .map((section) => ({
          ...section,
          items: section.items.filter((item) => canAccessPath(user, item.href)),
        }))
        .filter((section) => section.items.length > 0);
    },
    [t, user],
  );

  const isFullScreenPage =
    matchPath('/workflows/create', location.pathname) ||
    matchPath('/workflows/:id/edit', location.pathname) ||
    matchPath('/workflows/:id', location.pathname) ||
    matchPath('/sessions', location.pathname);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Modals render lazily — fallback={null} keeps the chunk download
          invisible to the user (they're already triggering an async UI). */}
      <Suspense fallback={null}>
        {showOnboarding && (
          <OnboardingModal
            productName={productName}
            vendorOnboardingAllowed={vendorOnboardingAllowed}
            onClose={() => setShowOnboarding(false)}
          />
        )}
        {showUpdate && updateCheckAllowed && (
          <UpdateModal
            initialInfo={updateInfo}
            updateCheckAllowed={updateCheckAllowed}
            updateApplyAllowed={updateApplyAllowed}
            onClose={() => setShowUpdate(false)}
            onDismiss={() => setShowUpdate(false)}
          />
        )}
        {visibleNotifications.length > 0 && (
          <NotificationModal
            notifications={visibleNotifications}
            acknowledgingIds={acknowledgingNotificationIds}
            onAcknowledge={closeVisibleNotification}
            onClose={closeVisibleNotification}
            onDismissForever={dismissVisibleNotificationForever}
          />
        )}
      </Suspense>

      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-gray-600 bg-opacity-75 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside
        className={`
          fixed inset-y-0 left-0 z-50 bg-zinc-100 border-r border-zinc-200
          transition-all duration-300 ease-in-out
          lg:translate-x-0
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
          ${collapsed ? 'w-16' : 'w-52'}
        `}
      >
        <div className="flex flex-col h-full overflow-hidden">
          {/* Logo */}
          <div className={`flex items-center h-16 border-b border-zinc-200 flex-shrink-0 ${collapsed ? 'justify-center px-2' : 'pl-6 pr-4'}`}>
            {collapsed ? (
              <div
                className="w-8 h-8 rounded-lg border border-zinc-200 bg-white flex items-center justify-center flex-shrink-0 shadow-sm"
                title={productName}
              >
                {branding.logo_light ? (
                  <img src={branding.logo_light} alt="" className="h-5 w-5 object-contain" />
                ) : (
                  <Sparkles className="w-4 h-4 text-zinc-500" />
                )}
              </div>
            ) : (
              <>
                {branding.logo_light && (
                  <img src={branding.logo_light} alt="" className="mr-2 h-8 w-8 flex-shrink-0 object-contain" />
                )}
                <span className="flex-1 min-w-0 truncate text-xl font-bold text-zinc-900 whitespace-nowrap">
                  {productName}
                </span>
                <button
                  onClick={() => setSidebarOpen(false)}
                  className="lg:hidden p-1 text-zinc-400 hover:text-zinc-600 rounded flex-shrink-0"
                >
                  <X className="w-5 h-5" />
                </button>
              </>
            )}
          </div>

          {/* Navigation */}
          <nav className={`flex-1 overflow-y-auto overflow-x-hidden py-4 ${collapsed ? 'px-2' : 'px-3'}`}>
            {navigation.map((section) => (
              <div key={section.name} className="mb-6">
                {!collapsed && section.name && (
                  <h3 className="px-3 mb-2 text-xs font-semibold text-zinc-400 uppercase tracking-wider whitespace-nowrap">
                    {section.name}
                  </h3>
                )}
                {collapsed && <div className="mb-1 border-t border-zinc-200 first:border-none" />}
                <div className="space-y-0.5">
                  {section.items.map((item) => {
                    const isActive = location.pathname === item.href
                      || (item.href !== '/' && location.pathname.startsWith(`${item.href}/`));
                    return (
                      <Link
                        key={item.href}
                        to={item.href}
                        onClick={() => setSidebarOpen(false)}
                        title={collapsed ? item.name : undefined}
                        className={`
                          flex items-center rounded-lg transition-all duration-150
                          ${collapsed ? 'justify-center p-2.5' : 'px-3 py-2 text-sm font-medium'}
                          ${isActive
                            ? 'bg-white text-zinc-900 shadow-sm'
                            : 'text-zinc-600 hover:bg-white/60 hover:text-zinc-900'
                          }
                        `}
                      >
                        <item.icon
                          className={`flex-shrink-0 w-5 h-5 ${collapsed ? '' : 'mr-3'} ${isActive ? 'text-zinc-700' : 'text-zinc-400'}`}
                        />
                        {!collapsed && (
                          <span className="truncate">{item.name}</span>
                        )}
                      </Link>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>

          {/* Bottom: Language switcher + version */}
          <div className={`border-t border-zinc-200 flex-shrink-0 ${collapsed ? 'p-2 flex flex-col items-center gap-2' : 'p-4'}`}>
            <LanguageSwitcher collapsed={collapsed} />
            {!collapsed && (
              <>
                {hasUpdate ? (
                  <button
                    onClick={() => {
                      if (updateCheckAllowed) setShowUpdate(true);
                    }}
                    className="mt-3 w-full rounded-xl border border-amber-200 bg-gradient-to-r from-amber-50 via-orange-50 to-rose-50 px-3 py-2 text-left shadow-sm transition-all hover:-translate-y-0.5 hover:shadow-md"
                  >
                    <div className="flex items-center gap-2 text-sm">
                      <span className="min-w-0 flex-1 truncate font-semibold text-amber-900">
                        {t('newVersion')} {latestVersion ? `v${latestVersion}` : ''}
                      </span>
                      <span className="inline-flex flex-shrink-0 items-center rounded-full bg-amber-500 px-2 py-0.5 text-xs font-semibold text-white shadow-sm">
                        {t('updateNow')}
                      </span>
                    </div>
                    <div className="mt-1 text-xs text-amber-700">
                      {currentVersion
                        ? t('currentVersionLabel', { version: currentVersion })
                        : productName}
                    </div>
                    <div className="mt-0.5 text-xs font-medium text-amber-900">
                      {branding.company_name}
                    </div>
                  </button>
                ) : (
                  <button
                    onClick={() => {
                      if (updateCheckAllowed) setShowUpdate(true);
                    }}
                    className="w-full text-left mt-3 group rounded-lg px-1 py-1 hover:bg-white/60 transition-colors"
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-medium text-zinc-500 group-hover:text-zinc-800 transition-colors">
                        {productName} {currentVersion ? `v${currentVersion}` : '...'}
                      </span>
                    </div>
                    <div className="mt-0.5 text-xs text-zinc-400">{branding.company_name}</div>
                  </button>
                )}
              </>
            )}
            {collapsed && (
              <button
                onClick={() => {
                  if (updateCheckAllowed) setShowUpdate(true);
                }}
                title={hasUpdate ? t('hasNewVersion', { version: latestVersion ? `v${latestVersion}` : '' }) : t('versionInfo', { productName })}
                className={`relative rounded-xl p-2 transition-colors ${
                  hasUpdate
                    ? 'bg-amber-50 text-amber-600 hover:bg-amber-100'
                    : 'text-zinc-400 hover:text-zinc-600 hover:bg-white/60'
                }`}
              >
                {hasUpdate ? <ArrowUpCircle className="w-4 h-4" /> : <Sparkles className="w-4 h-4" />}
                {hasUpdate && (
                  <>
                    <span className="absolute inset-0 rounded-xl border border-amber-200 animate-pulse" />
                    <span className="absolute top-1 right-1 w-2 h-2 bg-amber-400 rounded-full" />
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        {/* Collapse tab (desktop) */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="
            hidden lg:flex absolute top-1/2 -translate-y-1/2 right-0 z-10
            w-3 h-20 items-center justify-center
            bg-zinc-200 hover:bg-zinc-300 border border-r-0 border-zinc-200 rounded-l-lg
            text-zinc-400 hover:text-zinc-600
            transition-all duration-200
          "
          title={collapsed ? t('expandNav') : t('collapseNav')}
        >
          {collapsed ? <ChevronRight className="w-2.5 h-2.5" /> : <ChevronLeft className="w-2.5 h-2.5" />}
        </button>
      </aside>

      {/* Mobile top menu button */}
      <div className={`lg:hidden fixed top-0 left-0 z-30 flex items-center h-16 px-4 ${sidebarOpen ? 'hidden' : ''}`}>
        <button
          onClick={() => setSidebarOpen(true)}
          className="p-2 text-gray-500 hover:text-gray-700 bg-white rounded-lg shadow-sm border border-gray-200"
        >
          <Menu className="w-5 h-5" />
        </button>
      </div>

      {/* Main content area */}
      <div
        className={`flex flex-col h-screen transition-all duration-300 ${collapsed ? 'lg:pl-16' : 'lg:pl-52'}`}
      >
        <main className="flex-1 overflow-hidden bg-gray-50">
          {isFullScreenPage ? (
            <Outlet />
          ) : (
            <div className="h-full overflow-y-auto">
              <div className="min-h-full p-6">
                <Outlet />
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
