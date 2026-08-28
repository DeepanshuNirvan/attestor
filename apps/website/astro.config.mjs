import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';

import { site } from './src/data/site.js';
import { securityHeaders } from './src/integrations/security-headers.js';

export default defineConfig({
  site: site.origin,
  output: 'static',
  trailingSlash: 'never',
  build: { format: 'file', inlineStylesheets: 'auto' },
  integrations: [
    mdx(),
    sitemap({ filter: (page) => !page.includes('/_') }),
    securityHeaders({
      // The only outbound request the site makes at runtime is the enquiry form, which posts to a
      // Pages Function on this origin. Cal.com is loaded as a link, not an embed.
      connectSources: ["'self'"],
      frameSources: ["'none'"],
    }),
  ],
  markdown: {
    shikiConfig: { theme: 'github-light', wrap: true },
  },
  vite: {
    build: { assetsInlineLimit: 1024 },
  },
});
