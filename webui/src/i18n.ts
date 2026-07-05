import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import { baseNamespaces, baseResources } from './i18n.resources';

if (!i18n.isInitialized) {
  i18n
    .use(LanguageDetector)
    .use(initReactI18next)
    .init({
      resources: baseResources,
      fallbackLng: 'en-US',
      defaultNS: 'common',
      ns: [...baseNamespaces],
      detection: {
        order: ['localStorage', 'navigator'],
        lookupLocalStorage: 'flocks-language',
        caches: ['localStorage'],
      },
      interpolation: {
        escapeValue: false,
      },
    });
}

export default i18n;
