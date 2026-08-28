import { defineCollection } from 'astro:content';
import { z } from 'zod';
import { glob } from 'astro/loaders';

const services = defineCollection({
  loader: glob({ base: './src/content/services', pattern: '**/*.mdx' }),
  schema: z.object({
    title: z.string(),
    navLabel: z.string(),
    order: z.number(),
    summary: z.string(),
    /** Ids from src/data/pricing.ts. Prices are never written in the copy. */
    packageIds: z.array(z.string()),
    /** Catalogue categories this service covers, used to filter the coverage explorer. */
    coverageCategories: z.array(z.string()),
    standards: z.array(z.string()),
    /** Who this is for, in one line. Used on the services index. */
    audience: z.string(),
    seoDescription: z.string(),
  }),
});

const insights = defineCollection({
  loader: glob({ base: './src/content/insights', pattern: '**/*.mdx' }),
  schema: z.object({
    title: z.string(),
    publishedAt: z.coerce.date(),
    updatedAt: z.coerce.date().optional(),
    summary: z.string(),
    tags: z.array(z.string()),
    /** Set false while drafting; drafts are excluded from the build. */
    published: z.boolean().default(true),
  }),
});

const legal = defineCollection({
  loader: glob({ base: './src/content/legal', pattern: '**/*.mdx' }),
  schema: z.object({
    title: z.string(),
    updatedAt: z.coerce.date(),
    /** Until a lawyer has reviewed the text, the page carries a visible draft notice. */
    lawyerReviewed: z.boolean().default(false),
    summary: z.string(),
  }),
});

export const collections = { services, insights, legal };
