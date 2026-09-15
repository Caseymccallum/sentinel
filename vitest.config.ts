import { defineConfig } from 'vitest/config';
import { WxtVitest } from 'wxt/testing/vitest-plugin';

export default defineConfig({
  plugins: [WxtVitest()],
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    reporters: ['default'],
    coverage: {
      include: ['src/core/**', 'src/storage/**', 'src/modules/**'],
      exclude: ['**/*.test.ts'],
    },
  },
});
