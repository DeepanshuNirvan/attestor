import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import satori from 'satori';
import { Resvg } from '@resvg/resvg-js';
import { site } from '../../data/site';

/**
 * Open Graph images, generated at build time from a typographic template. No stock art, no gradient,
 * no logo soup — the same ground, ink and rule the site uses, and the page title set large.
 *
 * Satori takes React-element-shaped objects; constructing them as plain objects keeps JSX out of an
 * otherwise JSX-free project.
 */

interface Node {
  type: string;
  props: Record<string, unknown> & { children?: Node | Node[] | string };
}

function element(type: string, style: Record<string, unknown>, children?: Node | Node[] | string): Node {
  return { type, props: { style, children } };
}

/**
 * Satori's parameter is typed as a React element because that is how most callers build one. These
 * plain objects are the shape it actually consumes, and building them by hand is what keeps JSX and
 * a React dependency out of a static site that needs neither.
 */
function satoriTree(node: Node): Parameters<typeof satori>[0] {
  return node as unknown as Parameters<typeof satori>[0];
}

// Resolved from the package root rather than from import.meta.url: this module is bundled into
// dist/.prerender at build time, so a relative URL would point at the output tree, not the source.
const fontPath = (name: string) =>
  fileURLToPath(new URL(`src/fonts/${name}`, pathToFileURL(`${process.cwd()}/`)));

async function loadFonts() {
  const [serif, sans, sansBold] = await Promise.all([
    readFile(fontPath('source-serif-4-600.woff')),
    readFile(fontPath('public-sans-400.woff')),
    readFile(fontPath('public-sans-600.woff')),
  ]);
  return [
    { name: 'Source Serif 4', data: serif, weight: 600 as const, style: 'normal' as const },
    { name: 'Public Sans', data: sans, weight: 400 as const, style: 'normal' as const },
    { name: 'Public Sans', data: sansBold, weight: 600 as const, style: 'normal' as const },
  ];
}

interface Card {
  route: string;
  eyebrow: string;
  title: string;
  footnote: string;
}

export async function getStaticPaths() {
  const services = await getCollection('services');
  const insights = await getCollection('insights', ({ data }) => data.published);

  const cards: Card[] = [
    {
      route: 'default',
      eyebrow: 'Attestor Security',
      title: site.tagline,
      footnote: 'attestorsecurity.com',
    },
    {
      route: 'sample-report',
      eyebrow: 'Sample report',
      title: 'Read the report before you buy the engagement',
      footnote: 'attestorsecurity.com/sample-report',
    },
    {
      route: 'pricing',
      eyebrow: 'Pricing',
      title: 'Published prices, fixed dates, one free retest',
      footnote: 'attestorsecurity.com/pricing',
    },
    {
      route: 'what-we-test',
      eyebrow: 'Coverage',
      title: 'Every check we run, published',
      footnote: 'attestorsecurity.com/what-we-test',
    },
    ...services.map((service) => ({
      route: `services-${service.id}`,
      eyebrow: 'Service',
      title: service.data.title,
      footnote: `attestorsecurity.com/services/${service.id}`,
    })),
    ...insights.map((post) => ({
      route: `insights-${post.id}`,
      eyebrow: 'Insight',
      title: post.data.title,
      footnote: `attestorsecurity.com/insights/${post.id}`,
    })),
  ];

  return cards.map((card) => ({ params: { route: card.route }, props: { card } }));
}

export const GET: APIRoute = async ({ props }) => {
  const card = props.card as Card;
  const fonts = await loadFonts();

  const svg = await satori(
    satoriTree(
      element(
      'div',
      {
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        width: '1200px',
        height: '630px',
        backgroundColor: '#FBFAF8',
        padding: '72px',
        fontFamily: 'Public Sans',
        borderTop: '14px solid #1F5F47',
      },
      [
        element(
          'div',
          {
            display: 'flex',
            fontSize: '24px',
            letterSpacing: '0.14em',
            textTransform: 'uppercase',
            color: '#1F5F47',
            fontWeight: 600,
          },
          card.eyebrow,
        ),
        element(
          'div',
          {
            display: 'flex',
            fontFamily: 'Source Serif 4',
            fontSize: card.title.length > 68 ? '58px' : '72px',
            lineHeight: 1.12,
            letterSpacing: '-0.02em',
            color: '#14161A',
            maxWidth: '980px',
          },
          card.title,
        ),
        element(
          'div',
          {
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-end',
            borderTop: '1px solid #DFDBD3',
            paddingTop: '28px',
            fontSize: '26px',
            color: '#4A5058',
          },
          [
            element('div', { display: 'flex' }, card.footnote),
            element(
              'div',
              { display: 'flex', color: '#14161A', fontWeight: 600 },
              site.wordmark,
            ),
          ],
        ),
      ],
      ),
    ),
    { width: 1200, height: 630, fonts },
  );

  const png = new Resvg(svg, { fitTo: { mode: 'width', value: 1200 } }).render().asPng();

  return new Response(new Uint8Array(png), {
    headers: { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=31536000, immutable' },
  });
};
