import type { LocalUser } from '@/api/auth';

export type Capability =
  | '*'
  | 'ai.sessions'
  | 'ai.workspace'
  | 'tasks.read'
  | 'tasks.write'
  | 'agents.read'
  | 'agents.write'
  | 'workflows.read'
  | 'workflows.write'
  | 'workflows.run'
  | 'skills.read'
  | 'skills.write'
  | 'tools.read'
  | 'tools.execute'
  | 'tools.manage'
  | 'devices.read'
  | 'devices.manage'
  | 'hub.read'
  | 'models.read'
  | 'models.manage'
  | 'providers.read'
  | 'providers.manage'
  | 'channels.read'
  | 'channels.send'
  | 'channels.manage'
  | 'security.ops.read'
  | 'security.ops.write'
  | 'security.admin'
  | 'system.config.read'
  | 'system.config.write'
  | 'system.logs.read'
  | 'system.permissions.read'
  | 'system.monitoring.read'
  | 'commercial.admin'
  | 'commercial.audit.read';

export const roleCapabilities: Record<string, Capability[]> = {
  admin: ['*'],
  commercial_admin: [
    'commercial.admin',
    'commercial.audit.read',
    'security.ops.read',
    'security.ops.write',
    'security.admin',
    'system.config.read',
    'system.config.write',
    'system.logs.read',
    'channels.read',
    'channels.manage',
    'channels.send',
    'tools.read',
    'tools.manage',
    'models.read',
    'models.manage',
    'providers.read',
    'providers.manage',
  ],
  security_admin: [
    'security.ops.read',
    'security.ops.write',
    'security.admin',
    'devices.read',
    'devices.manage',
    'channels.read',
    'tools.read',
    'tools.execute',
    'workflows.read',
    'workflows.run',
  ],
  operator: [
    'ai.sessions',
    'ai.workspace',
    'tasks.read',
    'tasks.write',
    'agents.read',
    'workflows.read',
    'workflows.run',
    'skills.read',
    'tools.read',
    'tools.execute',
    'channels.read',
    'channels.send',
    'security.ops.read',
    'security.ops.write',
    'devices.read',
    'hub.read',
    'models.read',
  ],
  member: [
    'ai.sessions',
    'ai.workspace',
    'tasks.read',
    'tasks.write',
    'agents.read',
    'workflows.read',
    'workflows.run',
    'skills.read',
    'tools.read',
    'tools.execute',
    'channels.read',
    'channels.send',
    'security.ops.read',
    'security.ops.write',
    'devices.read',
    'hub.read',
    'models.read',
  ],
  viewer: [
    'ai.sessions',
    'ai.workspace',
    'tasks.read',
    'agents.read',
    'workflows.read',
    'skills.read',
    'tools.read',
    'channels.read',
    'security.ops.read',
    'devices.read',
    'hub.read',
    'models.read',
  ],
};

export const routeCapabilities: Array<{ prefix: string; capability: Capability }> = [
  { prefix: '/workflows/new', capability: 'workflows.write' },
  { prefix: '/workflows/create', capability: 'workflows.write' },
  { prefix: '/workflows', capability: 'workflows.read' },
  { prefix: '/sessions', capability: 'ai.sessions' },
  { prefix: '/workspace', capability: 'ai.workspace' },
  { prefix: '/tasks', capability: 'tasks.read' },
  { prefix: '/agents', capability: 'agents.read' },
  { prefix: '/skills', capability: 'skills.read' },
  { prefix: '/tools', capability: 'tools.read' },
  { prefix: '/devices', capability: 'devices.read' },
  { prefix: '/hub', capability: 'hub.read' },
  { prefix: '/models', capability: 'models.read' },
  { prefix: '/channels', capability: 'channels.manage' },
  { prefix: '/security', capability: 'security.ops.read' },
  { prefix: '/config', capability: 'system.config.read' },
  { prefix: '/system-logs', capability: 'system.logs.read' },
  { prefix: '/permissions', capability: 'system.permissions.read' },
  { prefix: '/monitoring', capability: 'system.monitoring.read' },
];

export function capabilitiesForRole(role?: string | null): Set<Capability> {
  return new Set(roleCapabilities[role || ''] || []);
}

export function hasCapability(user: LocalUser | null | undefined, capability: Capability): boolean {
  if (!user) return false;
  const capabilities = capabilitiesForRole(user.role);
  return capabilities.has('*') || capabilities.has(capability);
}

export function capabilityForPath(pathname: string): Capability | null {
  const normalized = pathname === '/' ? '/' : pathname.replace(/\/+$/, '');
  if (normalized === '/') return null;
  const match = routeCapabilities.find(({ prefix }) => (
    normalized === prefix || normalized.startsWith(`${prefix}/`)
  ));
  return match?.capability || null;
}

export function canAccessPath(user: LocalUser | null | undefined, pathname: string): boolean {
  const capability = capabilityForPath(pathname);
  return !capability || hasCapability(user, capability);
}
