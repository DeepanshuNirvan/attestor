import { chromium, type Browser } from 'playwright';

/**
 * HTML to PDF.
 *
 * Chromium via Playwright, headless, with no network access: the HTML arrives with its CSS inlined
 * and its images as data URIs, so a report cannot phone home when it is rendered and cannot fail
 * because a font server was slow.
 *
 * One browser is reused across a batch. Launching Chromium per document is the difference between a
 * retainer month's paperwork taking seconds and taking minutes.
 */

export interface PdfOptions {
  /** A4 by default; US Letter for North American clients. */
  format?: 'A4' | 'Letter';
  landscape?: boolean;
  /** Watermark applied per download, with the recipient's identity. */
  watermarkText?: string;
}

let sharedBrowser: Browser | null = null;

/**
 * The image installs Alpine's own Chromium rather than Playwright's, because Playwright does not
 * publish a musl build. Playwright has no environment variable for that — it ignores
 * `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`, which the Dockerfile set — so the path has to be passed to
 * `launch` explicitly, and until it was, every report generated in a container failed with
 * "Executable doesn't exist" and the operator got a 500 with no report.
 */
async function browser(): Promise<Browser> {
  const executablePath = process.env.CHROMIUM_EXECUTABLE_PATH;
  sharedBrowser ??= await chromium.launch({
    args: ['--disable-dev-shm-usage'],
    ...(executablePath ? { executablePath } : {}),
  });
  return sharedBrowser;
}

export async function closePdfBrowser(): Promise<void> {
  await sharedBrowser?.close();
  sharedBrowser = null;
}

/**
 * The watermark is injected here rather than being rendered into the document, because it is
 * per-download: the same stored PDF source produces a differently marked file for each recipient.
 */
function watermarkStyle(text: string): string {
  const escaped = text.replace(/'/g, "\\'");
  return `
  <style>
    @media print {
      body::before {
        content: '${escaped}';
        position: fixed;
        inset: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        transform: rotate(-32deg);
        font-family: 'Public Sans', sans-serif;
        font-size: 26pt;
        letter-spacing: 0.08em;
        color: rgba(20, 22, 26, 0.07);
        white-space: pre-wrap;
        text-align: center;
        pointer-events: none;
        z-index: 9999;
      }
    }
  </style>`;
}

export async function renderPdf(html: string, options: PdfOptions = {}): Promise<Buffer> {
  const content = options.watermarkText
    ? html.replace('</head>', `${watermarkStyle(options.watermarkText)}</head>`)
    : html;

  const context = await (await browser()).newContext();
  // Nothing in a report should reach the network. Blocking it here makes that a property rather
  // than an expectation about how the HTML was built.
  await context.route('**/*', (route) => {
    const url = route.request().url();
    if (url.startsWith('data:') || url.startsWith('about:')) return route.continue();
    return route.abort();
  });

  const page = await context.newPage();
  try {
    await page.setContent(content, { waitUntil: 'domcontentloaded' });
    await page.emulateMedia({ media: 'print' });
    const pdf = await page.pdf({
      format: options.format ?? 'A4',
      landscape: options.landscape ?? false,
      printBackground: true,
      preferCSSPageSize: true,
      // Margins come from the stylesheet's @page rule; setting them here would fight it.
      margin: { top: '0', right: '0', bottom: '0', left: '0' },
    });
    return Buffer.from(pdf);
  } finally {
    await context.close();
  }
}

/**
 * Watermark text for a per-recipient download. Every page carries who took it and when, so a leaked
 * report identifies its source.
 */
export function watermarkFor(recipient: {
  name: string;
  email: string;
  organisation: string;
  at: Date;
}): string {
  return `${recipient.name} · ${recipient.email}\n${recipient.organisation} · ${recipient.at.toISOString()}`;
}
