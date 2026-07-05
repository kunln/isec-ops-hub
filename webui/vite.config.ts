import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import fs from 'fs'
import { createApiProxy, getApiProxyTarget } from './src/config/apiProxy'
import { getAdditionalAllowedHosts } from './src/config/viteHosts'

// Windows 8.3 短路径名（如 THREAT~1）会导致 Vite build-html 插件
// 内部 path.relative() 计算出错，需规范化为完整长路径
const root = fs.realpathSync.native(__dirname)

type WebuiEntry = 'frontstage' | 'commercial-admin'

function webuiEntryFromEnv(env: Record<string, string>, mode: string): WebuiEntry {
  const value = env.FLOCKS_WEBUI_ENTRY || env.VITE_FLOCKS_WEBUI_ENTRY || mode;
  return value === 'commercial-admin' ? 'commercial-admin' : 'frontstage';
}

function defaultPortForEntry(entry: WebuiEntry): number {
  return entry === 'commercial-admin' ? 51174 : 8080;
}

function entryScriptFor(entry: WebuiEntry): string {
  return `/src/main.${entry}.tsx`
}

function titleForEntry(entry: WebuiEntry): string {
  return entry === 'commercial-admin' ? 'Commercial Admin' : 'Flocks - AI Native SecOps Platform'
}

function rewriteIndexHtmlForEntry(html: string, entry: WebuiEntry): string {
  return html
    .replace(/\/src\/main(?:\.[^"]+)?\.tsx/g, entryScriptFor(entry))
    .replace(
      '<title>Flocks - AI Native SecOps Platform</title>',
      `<title>${titleForEntry(entry)}</title>`,
    )
}

export default defineConfig(({ mode }) => {
  const env = { ...process.env, ...loadEnv(mode, root, '') } as Record<string, string>
  const apiProxyTarget = getApiProxyTarget(env)
  const allowedHosts = getAdditionalAllowedHosts(env)
  const entry = webuiEntryFromEnv(env, mode)
  const port = Number(env.FLOCKS_WEBUI_PORT || env.VITE_PORT || defaultPortForEntry(entry))
  const outDir = entry === 'commercial-admin' ? 'dist-commercial-admin' : 'dist-frontstage'

  return {
    root,
    plugins: [
      react(),
      {
        name: 'flocks-html-entry',
        transformIndexHtml: {
          order: 'pre',
          handler(html) {
            return rewriteIndexHtmlForEntry(html, entry)
          },
        },
      },
    ],
    resolve: {
      alias: {
        '@': path.resolve(root, './src'),
      },
    },
    build: {
      outDir,
      emptyOutDir: true,
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (!id.includes('node_modules')) return;

            if (
              id.includes('/react/') ||
              id.includes('/react-dom/') ||
              id.includes('react-router-dom')
            ) {
              return 'react-vendor';
            }

            if (
              id.includes('/i18next/') ||
              id.includes('i18next-browser-languagedetector')
            ) {
              return 'i18n-vendor';
            }

            if (
              id.includes('/react-markdown/') ||
              id.includes('/remark-gfm/') ||
              id.includes('/rehype-raw/')
            ) {
              return 'markdown-vendor';
            }

            if (
              id.includes('/rehype-highlight/')
            ) {
              return 'highlight-vendor';
            }

            if (
              id.includes('/recharts/') ||
              id.includes('/date-fns/')
            ) {
              return 'charts-vendor';
            }

            if (id.includes('@xyflow/react')) {
              return 'flow-vendor';
            }

            if (id.includes('/lucide-react/')) {
              return 'icons-vendor';
            }
          },
        },
      },
    },
    server: {
      port,
      host: '127.0.0.1',
      ...(allowedHosts ? { allowedHosts } : {}),
      proxy: createApiProxy(apiProxyTarget),
    },
    preview: {
      port,
      host: '127.0.0.1',
      ...(allowedHosts ? { allowedHosts } : {}),
      proxy: createApiProxy(apiProxyTarget),
    },
  }
})
