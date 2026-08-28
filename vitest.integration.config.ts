import { defineConfig } from 'vitest/config';

// Integration suites drive the vulnerable targets in infra/docker-compose.test.yml.
// They refuse to start unless ATTESTOR_TEST_NETWORK_ONLY=1, which the runner reads as
// proof that no internet host can be reached from this process.
export default defineConfig({
  test: {
    include: ['**/*.integration.test.ts'],
    exclude: ['**/node_modules/**', '**/dist/**'],
    environment: 'node',
    testTimeout: 300_000,
    hookTimeout: 300_000,
    setupFiles: ['./infra/test-network-guard.ts'],
  },
});
