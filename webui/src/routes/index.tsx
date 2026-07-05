import { Suspense, lazy } from 'react';
import { Routes as RouterRoutes, Route, Navigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import Layout from '@/components/layout/Layout';
import RoutePageSkeleton from '@/components/common/RoutePageSkeleton';
import AuthLayout from '@/components/layout/AuthLayout';
import Home from '@/pages/Home';
import { useAuth } from '@/contexts/AuthContext';
import { canAccessPath } from '@/utils/accessControl';

// All non-Home pages are code-split. Home stays eager because it's the very
// first frame after auth and we don't want a Suspense flash on initial paint.
// In particular, Session/Agent and the auth screens are kept lazy so heavy
// transitive deps (SessionChat ~2.7k LOC + react-markdown + rehype/remark +
// highlight.js) are not pulled into the main entry chunk.
const SessionPage = lazy(() => import('@/pages/Session'));
const AgentPage = lazy(() => import('@/pages/Agent'));
const LoginPage = lazy(() => import('@/pages/Login'));
const SetupAdminPage = lazy(() => import('@/pages/SetupAdmin'));
const ForceChangePasswordPage = lazy(() => import('@/pages/ForceChangePassword'));
const WorkflowListPage = lazy(() => import('@/pages/Workflow'));
const WorkflowCreate = lazy(() => import('@/pages/WorkflowCreate'));
const WorkflowEditor = lazy(() => import('@/pages/WorkflowEditor'));
const WorkflowDetail = lazy(() => import('@/pages/WorkflowDetail'));
const TaskPage = lazy(() => import('@/pages/Task'));
const ToolPage = lazy(() => import('@/pages/Tool'));
const HubPage = lazy(() => import('@/pages/Hub'));
const ModelPage = lazy(() => import('@/pages/Model'));
const SkillPage = lazy(() => import('@/pages/Skill'));
const ConfigPage = lazy(() => import('@/pages/Config'));
const ChannelPage = lazy(() => import('@/pages/Channel'));
const PermissionPage = lazy(() => import('@/pages/Permission'));
const MonitoringPage = lazy(() => import('@/pages/Monitoring'));
const WorkspacePage = lazy(() => import('@/pages/Workspace'));
const DeviceIntegrationPage = lazy(() => import('@/pages/DeviceIntegration'));
const SystemLogPage = lazy(() => import('@/pages/SystemLog'));
const SecurityPage = lazy(() => import('@/pages/Security'));

function LazyRoute({ children }: { children: React.ReactNode }) {
  return (
    <Suspense fallback={<RoutePageSkeleton />}>
      {children}
    </Suspense>
  );
}

function CapabilityRoute({ path, children }: { path: string; children: React.ReactNode }) {
  const { user } = useAuth();
  if (!canAccessPath(user, path)) {
    return <Navigate to="/" replace />;
  }
  return <LazyRoute>{children}</LazyRoute>;
}

export function Routes() {
  const { t } = useTranslation('auth');
  const { loading, bootstrapped, error, user, refresh } = useAuth();

  if (loading) {
    return <RoutePageSkeleton />;
  }

  if (error) {
    return (
      <AuthLayout>
        <div className="w-full max-w-lg bg-white border border-gray-200 rounded-xl p-6 shadow-sm space-y-4">
          <div>
            <h1 className="text-xl font-semibold text-gray-900">{t('error.systemUnknownTitle')}</h1>
            <p className="text-sm text-gray-500 mt-1">{error}</p>
          </div>
          <button
            type="button"
            onClick={() => void refresh()}
            className="bg-slate-900 text-white rounded-lg px-4 py-2 font-medium hover:bg-slate-800"
          >
            {t('error.retry')}
          </button>
        </div>
      </AuthLayout>
    );
  }

  if (!bootstrapped) {
    return (
      <Suspense fallback={<RoutePageSkeleton />}>
        <RouterRoutes>
          <Route path="/setup-admin" element={<SetupAdminPage />} />
          <Route path="*" element={<Navigate to="/setup-admin" replace />} />
        </RouterRoutes>
      </Suspense>
    );
  }

  if (!user) {
    return (
      <Suspense fallback={<RoutePageSkeleton />}>
        <RouterRoutes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </RouterRoutes>
      </Suspense>
    );
  }

  if (user.must_reset_password) {
    return (
      <Suspense fallback={<RoutePageSkeleton />}>
        <ForceChangePasswordPage />
      </Suspense>
    );
  }

  return (
    <RouterRoutes>
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route path="/setup-admin" element={<Navigate to="/" replace />} />
      <Route path="/" element={<Layout />}>
        <Route index element={<Home />} />

        {/* AI 工作台 */}
        <Route path="sessions" element={<CapabilityRoute path="/sessions"><SessionPage /></CapabilityRoute>} />
        <Route path="agents" element={<CapabilityRoute path="/agents"><AgentPage /></CapabilityRoute>} />
        <Route path="workflows" element={<CapabilityRoute path="/workflows"><WorkflowListPage /></CapabilityRoute>} />
        <Route path="workflows/new" element={<CapabilityRoute path="/workflows/new"><WorkflowCreate /></CapabilityRoute>} />
        <Route path="workflows/:id" element={<CapabilityRoute path="/workflows"><WorkflowDetail /></CapabilityRoute>} />
        <Route path="workflows/:id/edit" element={<CapabilityRoute path="/workflows/new"><WorkflowEditor /></CapabilityRoute>} />
        <Route path="tasks" element={<CapabilityRoute path="/tasks"><TaskPage /></CapabilityRoute>} />
        <Route path="workspace" element={<CapabilityRoute path="/workspace"><WorkspacePage /></CapabilityRoute>} />

        {/* 设备接入 */}
        <Route path="devices" element={<CapabilityRoute path="/devices"><DeviceIntegrationPage /></CapabilityRoute>} />

        {/* Security Extension */}
        <Route path="security/*" element={<CapabilityRoute path="/security"><SecurityPage /></CapabilityRoute>} />

        {/* Agent Smith */}
        <Route path="tools" element={<CapabilityRoute path="/tools"><ToolPage /></CapabilityRoute>} />
        <Route path="hub" element={<CapabilityRoute path="/hub"><HubPage /></CapabilityRoute>} />
        <Route path="models" element={<CapabilityRoute path="/models"><ModelPage /></CapabilityRoute>} />
        <Route path="skills" element={<CapabilityRoute path="/skills"><SkillPage /></CapabilityRoute>} />
        {/* MCP 已整合到工具清单页面 */}
        <Route path="mcp" element={<Navigate to="/tools" replace />} />

        {/* 系统中心 */}
        <Route path="config" element={<CapabilityRoute path="/config"><ConfigPage /></CapabilityRoute>} />
        <Route path="config/*" element={<Navigate to="/config" replace />} />
        <Route path="system-logs" element={<CapabilityRoute path="/system-logs"><SystemLogPage /></CapabilityRoute>} />
        <Route path="channels" element={<CapabilityRoute path="/channels"><ChannelPage /></CapabilityRoute>} />
        <Route path="permissions" element={<CapabilityRoute path="/permissions"><PermissionPage /></CapabilityRoute>} />
        <Route path="monitoring" element={<CapabilityRoute path="/monitoring"><MonitoringPage /></CapabilityRoute>} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </RouterRoutes>
  );
}
