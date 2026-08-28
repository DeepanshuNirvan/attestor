import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { site } from '../data/site';

/**
 * Hand-rolled rather than pulling in @astrojs/rss: the feed is twelve lines of XML and the escaping
 * is four replacements. A dependency for that would be a dependency to keep updated forever.
 */

function escapeXml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export const GET: APIRoute = async () => {
  const posts = (await getCollection('insights', ({ data }) => data.published)).sort(
    (a, b) => b.data.publishedAt.getTime() - a.data.publishedAt.getTime(),
  );

  const items = posts
    .map((post) => {
      const url = `${site.origin}/insights/${post.id}`;
      return `    <item>
      <title>${escapeXml(post.data.title)}</title>
      <link>${url}</link>
      <guid isPermaLink="true">${url}</guid>
      <description>${escapeXml(post.data.summary)}</description>
      <pubDate>${post.data.publishedAt.toUTCString()}</pubDate>
      ${post.data.tags.map((tag) => `<category>${escapeXml(tag)}</category>`).join('\n      ')}
    </item>`;
    })
    .join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${escapeXml(site.brandName)} — insights</title>
    <link>${site.origin}/insights</link>
    <description>${escapeXml(site.description)}</description>
    <language>en-IN</language>
    <atom:link href="${site.origin}/rss.xml" rel="self" type="application/rss+xml" />
${items}
  </channel>
</rss>
`;

  return new Response(xml, { headers: { 'Content-Type': 'application/rss+xml; charset=utf-8' } });
};
