// End-to-end tests of the built page, in a real browser, against dist/ as it
// would be deployed.
//
// The expected bytes are not taken from this project's own code: they are the
// worked examples of the @vanaheimr/metrological-cbor README, so a test fails
// when the page disagrees with the library's documented encoding rather than
// when it merely disagrees with itself.

import { test as base, expect } from '@playwright/test';
import { createRequire } from 'node:module';
import { bytesToHex, hexToBytes } from '@vanaheimr/metrological-cbor';
import { CoseSign1, CoseKey, CoseCurves, CoseAlgorithms } from '@vanaheimr/cose';

const require = createRequire(import.meta.url);

const README = {
    fiveMilliampere:  'D9ACDC83C4822018320422',                   // 5.0 mA
    certificate:      'D9ACDC84C482211959D80500A201C482210C0202', // (230.00 ±0.12) V, k=2
    kilowattHour:     'D9ACDC83C48221186E0203',                   // 1.10 kWh
};

const status  = (page) => page.locator('#status');
const input   = (page) => page.locator('#input');
const results = (page) => page.locator('#results');

/** The JSON panel's text, parsed. */
const shownJson = async (page) => JSON.parse(await page.locator('#jsonOut').textContent());

/** The hexadecimal the encoder produced, without the grouping spaces. */
const shownHex = async (page) => (await page.locator('#hexOut').textContent()).replace(/\s+/g, '');

const readingTexts = (page) => page.locator('.reading-chip code');


// Every test fails on an uncaught exception or a console error, whatever it
// was looking at: a page that renders correctly while throwing in the
// background is not working.
const test = base.extend({
    page: async ({ page }, use) => {
        const problems = [];
        page.on('pageerror', (error) => problems.push(`pageerror: ${error.message}`));
        page.on('console',   (message) => {
            if (message.type() === 'error')
                problems.push(`console.error: ${message.text()}`);
        });
        await page.goto('/');
        await use(page);
        expect(problems, 'no page errors or console errors').toEqual([]);
    },
});


test.describe('page', () => {

    test('loads and waits for input', async ({ page }) => {
        await expect(page).toHaveTitle('Metrological CBOR Validator');
        await expect(status(page)).toContainText('Waiting for input');
        await expect(results(page)).toBeHidden();
    });

    test('names the library versions it was built with', async ({ page }) => {
        const mcbor = require('@vanaheimr/metrological-cbor/package.json').version;
        const cose  = require('@vanaheimr/cose/package.json').version;
        await expect(page.locator('#mcborVersion')).toHaveText(`v${mcbor}`);
        await expect(page.locator('#coseVersion')).toHaveText(`v${cose}`);
    });

    test('fits a phone screen without horizontal scrolling', async ({ page }) => {
        await page.setViewportSize({ width: 375, height: 812 });
        await page.getByRole('button', { name: 'COSE-signed record' }).click();
        await expect(status(page)).toHaveClass(/\bok\b/);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        expect(overflow).toBeLessThanOrEqual(0);
    });

});


test.describe('CBOR → JSON', () => {

    test('decodes 5.0 mA from the README', async ({ page }) => {
        await input(page).fill('D9ACDC 83 C482201832 04 22');
        await expect(status(page)).toHaveClass(/\bok\b/);
        await expect(status(page)).toContainText('Valid CBOR — deterministic encoding · 11 bytes (hex) · 1 reading');
        await expect(readingTexts(page)).toHaveText(['5.0 mA']);
        await expect(page.locator('#diagOut')).toHaveText('44252([4([-1, 50]), 4, -3])');
        expect(await shownJson(page)).toBe('5.0 mA');
    });

    test('decodes a calibration certificate with its uncertainty', async ({ page }) => {
        await input(page).fill(README.certificate);
        await expect(status(page)).toHaveClass(/\bok\b/);
        await expect(readingTexts(page)).toHaveText(['(230.00 ±0.12) V, k=2']);
        const tree = page.locator('#tree');
        await expect(tree).toContainText('V — volt');
        await expect(tree).toContainText('coverage factor');
    });

    test('accepts the usual spellings of hexadecimal, and Base64', async ({ page }) => {
        const spellings = [
            README.fiveMilliampere.toLowerCase(),
            `h'${README.fiveMilliampere}'`,
            '0xD9 0xAC 0xDC 0x83 0xC4 0x82 0x20 0x18 0x32 0x04 0x22',
            'D9:AC:DC:83:C4:82:20:18:32:04:22',
            Buffer.from(hexToBytes(README.fiveMilliampere)).toString('base64'),
        ];
        for (const spelling of spellings) {
            await input(page).fill(spelling);
            await expect(readingTexts(page), spelling).toHaveText(['5.0 mA']);
            await expect(status(page), spelling).toHaveClass(/\bok\b/);
        }
    });

    test('warns about, but still shows, CBOR that is not deterministically encoded', async ({ page }) => {
        await input(page).fill('A2616201616101');   // {"b": 1, "a": 1} — keys out of order
        await expect(status(page)).toHaveClass(/\bwarn\b/);
        await expect(status(page)).toContainText('ERR_CBOR_UNSORTED_KEYS');
        await expect(results(page)).toBeVisible();
        expect(await shownJson(page)).toEqual({ a: 1, b: 1 });
    });

    test('rejects malformed input', async ({ page }) => {
        const cases = [
            ['0000',         'ERR_CBOR_TRAILING_DATA'],
            ['D9ACDC83C482', 'ERR_CBOR_UNEXPECTED_END'],
            ['D9ACD',        'odd number of digits'],
            ['hello world!', 'neither hexadecimal nor Base64'],
        ];
        for (const [text, message] of cases) {
            await input(page).fill(text);
            await expect(status(page), text).toContainText(message);
            await expect(status(page), text).toHaveClass(/\berror\b/);
            await expect(results(page), text).toBeHidden();
        }
    });

    test('fails well-formed CBOR whose tag 44252 is not a metrological value', async ({ page }) => {
        const cases = [
            ['D9ACDC82F93E0005', 'ERR_VALUE_FLOAT'],       // 44252([1.5, 5]) — a float reading
            ['D9ACDC820100',     'ERR_UNIT_ID_RESERVED'],  // 44252([1, 0])   — unit 0 is reserved
        ];
        for (const [hex, code] of cases) {
            await input(page).fill(hex);
            await expect(status(page), hex).toHaveClass(/\berror\b/);
            await expect(status(page), hex).toContainText('not a valid metrological value');
            await expect(status(page), hex).toContainText(code);
            await expect(page.locator('.reading-chip.reading-bad'), hex).toHaveCount(1);
            await expect(page.locator('#tree .badge-error'), hex).toHaveCount(1);
        }
    });

    test('reads the readings inside a COSE_Sign1 payload, and the signature is genuine', async ({ page }) => {
        await page.getByRole('button', { name: 'COSE-signed record' }).click();
        await expect(status(page)).toHaveClass(/\bok\b/);
        await expect(page.locator('#tree')).toContainText('ES256 · kid "meter-0042"');
        await expect(page.locator('.reading-path')).toHaveText([
            '$ » payload.energy', '$ » payload.current', '$ » payload.voltage', '$ » payload.temperature',
        ]);

        // The example on the page is signed in the browser. Verify it here,
        // in Node, with the published test key it was made from.
        const message = CoseSign1.parse(hexToBytes(await input(page).inputValue()));
        const key     = CoseKey.fromPrivateScalar(
            CoseCurves.P256,
            hexToBytes('6C1382765AEC5358F117733D281C1C7BDC39884D04A45A1E6C67C858BC206C19'),
            { algorithm: CoseAlgorithms.ES256 });
        expect(message.verify(key.publicKey()).verified).toBe(true);
    });

});


test.describe('JSON → CBOR', () => {

    test.beforeEach(async ({ page }) => {
        await page.locator('#modeEncode').click();
    });

    test('turns a reading-like string into tag 44252 and leaves prose alone', async ({ page }) => {
        await input(page).fill('{ "energy": "1.10 kWh" }');
        await expect(status(page)).toHaveClass(/\bok\b/);
        // {"energy": <1.10 kWh>}: the reading's bytes are the README's.
        await expect.poll(() => shownHex(page)).toBe('A166656E65726779' + README.kilowattHour);

        await input(page).fill('{ "note": "free text stays text" }');
        await expect(status(page)).toContainText('0 readings converted');
        await expect(page.locator('#diagOut')).toHaveText('{"note": "free text stays text"}');
    });

    test('converts no string when reading detection is off', async ({ page }) => {
        await page.locator('#detectReadings').uncheck();
        await input(page).fill('{ "energy": "1.10 kWh" }');
        await expect(status(page)).toContainText('reading detection off');
        await expect(page.locator('#diagOut')).toHaveText('{"energy": "1.10 kWh"}');
    });

    test('rejects input that is not JSON', async ({ page }) => {
        await input(page).fill('{ "a": ');
        await expect(status(page)).toHaveClass(/\berror\b/);
        await expect(status(page)).toContainText('Invalid JSON');
    });

    test('round-trips a document through CBOR and back', async ({ page }) => {
        const document = {
            meter:       '1ISA0000000042',
            time:        '2026-08-15T08:14:00Z',
            energy:      '(1234.567 ±12.3) kWh, k=2, p=0.95, dist=normal',
            voltage:     '230.0 V',
            current:     '16 A',
            temperature: '21.5 °C',
            plugged:     true,
            phases:      [1, 2, 3],
            tariff:      null,
        };
        await input(page).fill(JSON.stringify(document));
        await expect(status(page)).toContainText('4 readings converted');
        const hex = await shownHex(page);

        await page.locator('#modeDecode').click();
        await input(page).fill(hex);
        await expect(status(page)).toHaveClass(/\bok\b/);
        expect(await shownJson(page)).toEqual(document);
    });

});
