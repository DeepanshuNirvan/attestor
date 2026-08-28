import { describe, expect, it } from 'vitest';
import { MODULES } from '@attestor/shared';
import { checkCatalogue, checksForModule, coveredWstgIds } from './index.ts';
import { CHECK_CATEGORIES } from './types.ts';
import {
  isApiTop10Category,
  isAsvsRequirement,
  isLlmTop10Category,
  isMasvsControl,
  isOwaspTop10Category,
  isWstgId,
} from '../standards/catalogues.ts';

describe('check catalogue', () => {
  it('has unique, kebab-case ids', () => {
    const ids = checkCatalogue.map((check) => check.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^[a-z][a-z0-9-]*[a-z0-9]$/);
  });

  it('names only real modules and categories', () => {
    for (const check of checkCatalogue) {
      expect(check.modules.length).toBeGreaterThan(0);
      for (const module of check.modules) expect(MODULES).toContain(module);
      expect(CHECK_CATEGORIES).toContain(check.category);
    }
  });

  it('references only identifiers that exist in the standards catalogues', () => {
    for (const check of checkCatalogue) {
      for (const id of check.standards.wstg ?? []) {
        expect(isWstgId(id), `${check.id} -> ${id}`).toBe(true);
      }
      for (const id of check.standards.asvs ?? []) {
        expect(isAsvsRequirement(id), `${check.id} -> ${id}`).toBe(true);
      }
      for (const id of check.standards.owaspTop10 ?? []) {
        expect(isOwaspTop10Category(id), `${check.id} -> ${id}`).toBe(true);
      }
      for (const id of check.standards.apiTop10 ?? []) {
        expect(isApiTop10Category(id), `${check.id} -> ${id}`).toBe(true);
      }
      for (const id of check.standards.masvs ?? []) {
        expect(isMasvsControl(id), `${check.id} -> ${id}`).toBe(true);
      }
      for (const id of check.standards.llmTop10 ?? []) {
        expect(isLlmTop10Category(id), `${check.id} -> ${id}`).toBe(true);
      }
    }
  });

  it('never emits a standalone SSRF top-ten category, which 2025 folded into A01', () => {
    for (const check of checkCatalogue) {
      expect(check.standards.owaspTop10 ?? []).not.toContain('A10:2021');
    }
  });

  it('gives every check an example distinct from its title', () => {
    for (const check of checkCatalogue) {
      expect(check.example.length).toBeGreaterThan(30);
      expect(check.example.toLowerCase()).not.toBe(check.title.toLowerCase());
    }
  });

  it('covers every module the platform can run', () => {
    for (const module of MODULES) {
      if (module === 'agentic') continue; // agentic runs the same checks under a different driver
      expect(checksForModule(module).length, module).toBeGreaterThan(0);
    }
  });

  it('claims a broad WSTG footprint rather than a token one', () => {
    const categories = new Set(coveredWstgIds().map((id) => id.split('-')[1]));
    expect(categories.size).toBeGreaterThanOrEqual(10);
  });

  it('lists a tool for every check that claims to be automated', () => {
    for (const check of checkCatalogue) {
      if (check.automation === 'automated') {
        expect(check.tools.length, check.id).toBeGreaterThan(0);
      }
    }
  });
});
