import i18n from './i18n';
import enAdminConsole from './locales/en-US/adminConsole.json';
import enSecurityAdmin from './locales/en-US/securityAdmin.json';
import zhAdminConsole from './locales/zh-CN/adminConsole.json';
import zhSecurityAdmin from './locales/zh-CN/securityAdmin.json';

const ADMIN_CONSOLE_NAMESPACE = 'adminConsole';
const SECURITY_NAMESPACE = 'security';

export function enableCommercialAdminI18n() {
  if (!i18n.hasResourceBundle('en-US', ADMIN_CONSOLE_NAMESPACE)) {
    i18n.addResourceBundle('en-US', ADMIN_CONSOLE_NAMESPACE, enAdminConsole, true, true);
  }
  if (!i18n.hasResourceBundle('zh-CN', ADMIN_CONSOLE_NAMESPACE)) {
    i18n.addResourceBundle('zh-CN', ADMIN_CONSOLE_NAMESPACE, zhAdminConsole, true, true);
  }
  i18n.addResourceBundle('en-US', SECURITY_NAMESPACE, enSecurityAdmin, true, true);
  i18n.addResourceBundle('zh-CN', SECURITY_NAMESPACE, zhSecurityAdmin, true, true);

  const namespaces = i18n.options.ns;
  const currentNamespaces = Array.isArray(namespaces)
    ? namespaces
    : namespaces
      ? [namespaces]
      : [];
  if (!currentNamespaces.includes(ADMIN_CONSOLE_NAMESPACE)) {
    i18n.options.ns = [...currentNamespaces, ADMIN_CONSOLE_NAMESPACE];
  }

  return i18n;
}

enableCommercialAdminI18n();

export default i18n;
