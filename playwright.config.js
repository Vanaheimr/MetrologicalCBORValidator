'use strict';

const { defineConfig, devices } = require('@playwright/test');

const PORT = Number(process.env.PORT ?? 4173);

// Pull requests run Chromium; the nightly run sets BROWSERS=all and adds
// Firefox and WebKit, which cost a browser download each.
const engines = process.env.BROWSERS === 'all'
    ? ['chromium', 'firefox', 'webkit']
    : (process.env.BROWSERS ?? 'chromium').split(',');

const deviceFor = {
    chromium: devices['Desktop Chrome'],
    firefox:  devices['Desktop Firefox'],
    webkit:   devices['Desktop Safari'],
};

module.exports = defineConfig({

    testDir:       './tests',
    fullyParallel: true,
    forbidOnly:    !!process.env.CI,
    retries:       0,
    reporter:      process.env.CI ? [['github'], ['list']] : 'list',

    use: {
        baseURL: `http://localhost:${PORT}`,
        trace:   'retain-on-failure',
    },

    projects: engines.map((name) => ({ name, use: { ...deviceFor[name] } })),

    // The tests run against dist/ as it would be deployed, so build first:
    // `npm run verify` does that, and so does CI.
    webServer: {
        command:             `node scripts/serve.mjs ${PORT}`,
        url:                 `http://localhost:${PORT}/`,
        reuseExistingServer: !process.env.CI,
        timeout:             20_000,
    },

});
