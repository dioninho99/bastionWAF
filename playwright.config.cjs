const { defineConfig } = require('@playwright/test');
module.exports = defineConfig({
 testDir: './tests/browser',
 fullyParallel: false,
 workers: 1,
 use: { channel: 'chromium', baseURL: 'http://127.0.0.1:19091', trace: 'retain-on-failure' },
 reporter: [['list'], ['html', { open: 'never' }]],
 webServer: { command: 'node tests/browser/server.cjs', url: 'http://127.0.0.1:19091/healthz', reuseExistingServer: false, timeout: 120000 },
});
