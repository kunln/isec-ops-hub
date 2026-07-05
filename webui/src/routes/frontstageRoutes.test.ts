import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const routesSource = readFileSync(join(process.cwd(), 'src/routes/index.tsx'), 'utf-8');
const commercialAppSource = readFileSync(join(process.cwd(), 'src/apps/CommercialAdminApp.tsx'), 'utf-8');
const frontstageEntrySource = readFileSync(join(process.cwd(), 'src/main.frontstage.tsx'), 'utf-8');
const commercialEntrySource = readFileSync(join(process.cwd(), 'src/main.commercial-admin.tsx'), 'utf-8');
const viteConfigSource = readFileSync(join(process.cwd(), 'vite.config.ts'), 'utf-8');
const baseI18nSource = readFileSync(join(process.cwd(), 'src/i18n.ts'), 'utf-8');
const baseI18nResourcesSource = readFileSync(join(process.cwd(), 'src/i18n.resources.ts'), 'utf-8');
const commercialI18nSource = readFileSync(join(process.cwd(), 'src/i18n.commercial-admin.ts'), 'utf-8');

describe('frontstage routes', () => {
  it('does not register commercial admin or security admin routes', () => {
    expect(routesSource).not.toContain('security-admin');
    expect(routesSource).not.toContain('path="admin');
    expect(routesSource).not.toContain("path='admin");
  });

  it('keeps commercial admin routing only in the commercial entry', () => {
    expect(commercialAppSource).toContain('path="/admin/*"');
    expect(commercialAppSource).toContain('path="/security-admin/*"');
    expect(commercialAppSource).toContain('@/pages/AdminConsole');
    expect(commercialAppSource).toContain('@/pages/Security/admin');
  });

  it('loads adminConsole i18n only from the commercial admin entry', () => {
    expect(frontstageEntrySource).toContain("import './i18n'");
    expect(frontstageEntrySource).not.toContain('i18n.commercial-admin');
    expect(commercialEntrySource).toContain("import './i18n.commercial-admin'");

    expect(baseI18nSource).not.toContain('adminConsole');
    expect(baseI18nResourcesSource).not.toContain('adminConsole');
    expect(baseI18nResourcesSource).not.toContain('securityAdmin.json');
    expect(commercialI18nSource).toContain('adminConsole.json');
    expect(commercialI18nSource).toContain('securityAdmin.json');
  });

  it('rewrites the Vite HTML entry before Vite scans the module graph', () => {
    expect(viteConfigSource).toContain("order: 'pre'");
    expect(viteConfigSource).toContain('rewriteIndexHtmlForEntry(html, entry)');
  });
});
