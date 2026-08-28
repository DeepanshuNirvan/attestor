import js from '@eslint/js';
import tseslint from 'typescript-eslint';

const namingRules = [
  { selector: 'default', format: ['camelCase'], leadingUnderscore: 'forbid', trailingUnderscore: 'forbid' },
  { selector: 'variable', format: ['camelCase', 'UPPER_CASE'], leadingUnderscore: 'forbid' },
  // Destructured names come from somebody else's module; we do not get to rename them.
  { selector: 'variable', modifiers: ['destructured'], format: null },
  { selector: 'parameter', format: ['camelCase'], leadingUnderscore: 'forbid' },
  { selector: 'typeLike', format: ['PascalCase'] },
  { selector: 'enumMember', format: ['camelCase', 'PascalCase'] },
  { selector: 'objectLiteralProperty', format: null },
  { selector: 'objectLiteralMethod', format: null },
  { selector: 'typeProperty', format: null },
  { selector: 'import', format: null },
];

export default tseslint.config(
  { ignores: ['**/dist/**', '**/.astro/**', '**/.next/**', '**/node_modules/**', '**/coverage/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/ban-ts-comment': ['error', { 'ts-ignore': 'allow-with-description' }],
      '@typescript-eslint/naming-convention': ['error', ...namingRules],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^unused' }],
      '@typescript-eslint/consistent-type-imports': 'error',
      'no-console': ['error', { allow: ['error'] }],
      eqeqeq: ['error', 'always'],
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'dockerode',
              message:
                'Container execution goes through packages/core/src/runner/run-tool-for-engagement.ts only. That is the single scope-guard choke point.',
            },
          ],
        },
      ],
    },
  },
  {
    // The choke point itself is the one place allowed to talk to Docker.
    files: ['packages/core/src/runner/container-runner.ts'],
    rules: { 'no-restricted-imports': 'off' },
  },
  {
    // React components are PascalCase by convention, and a route file exports one by default.
    files: ['apps/console/src/**/*.tsx', 'apps/console/src/**/page.ts', 'apps/console/src/**/route.ts'],
    rules: {
      '@typescript-eslint/naming-convention': [
        'error',
        ...namingRules.map((rule) =>
          rule.selector === 'function' || rule.selector === 'default'
            ? { ...rule, format: ['camelCase', 'PascalCase'] }
            : rule,
        ),
        { selector: 'function', format: ['camelCase', 'PascalCase'], leadingUnderscore: 'forbid' },
        { selector: 'variable', format: ['camelCase', 'PascalCase', 'UPPER_CASE'], leadingUnderscore: 'forbid' },
      ],
    },
  },
  {
    files: ['**/*.test.ts', '**/*.integration.test.ts', '**/scripts/**'],
    rules: { 'no-console': 'off', '@typescript-eslint/no-unsafe-assignment': 'off' },
  },
  {
    files: ['**/*.js', '**/*.mjs', '**/*.cjs'],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      parserOptions: { projectService: false, project: null },
      globals: {
        console: 'readonly',
        process: 'readonly',
        URL: 'readonly',
        Buffer: 'readonly',
        fetch: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
      },
    },
    // The spread above sets rules too; merge rather than replace, or typed rules come back on.
    rules: { ...tseslint.configs.disableTypeChecked.rules, 'no-console': 'off' },
  },
);
