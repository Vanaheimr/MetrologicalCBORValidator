// End-to-end tests of the built page, in a real browser, against dist/ as it
// would be deployed.
//
// The expected bytes are not taken from this project's own code: they are the
// worked examples of the @vanaheimr/metrological-cbor README, so a test fails
// when the page disagrees with the library's documented encoding rather than
// when it merely disagrees with itself.

import { test as base, expect } from '@playwright/test';
import { createRequire } from 'node:module';
import { generateKeyPairSync } from 'node:crypto';
import { bytesToHex, hexToBytes, jsonTextToMcbor } from '@vanaheimr/metrological-cbor';
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

const verifyKey  = (page) => page.locator('#verifyKey');
const signatures = (page) => page.locator('#sigList .sig');

/** Flips the last hexadecimal digit of a message, which lies in its signature. */
const flipLastDigit = (hex) => hex.slice(0, -1) + (hex.endsWith('0') ? '1' : '0');


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

    test('states the standard uncertainty U/k, exactly where it is exact', async ({ page }) => {
        // The library's own example: U = 0.12 V with k = 2 is u = 0.060 V.
        await input(page).fill(README.certificate);
        await expect(page.locator('.reading-note')).toHaveText(['u = 0.060 V (U/k, k=2)']);

        // 1.0 V / 3 has no exact decimal form, and says so.
        await page.locator('#modeEncode').click();
        await input(page).fill('{ "u": "(10.0 ±1.0) V, k=3", "plain": "1.10 kWh" }');
        await expect(page.locator('.reading-note')).toHaveText(['u ≈ 0.333 V (U/k, k=3)']);
        await expect(page.locator('.reading-chip')).toHaveCount(2);
    });

    test('writes the JSON text of the specification, with every digit', async ({ page }) => {
        // {"n": 18446744073709551615}: beyond 2^53, where a JavaScript number
        // would already have rounded it.
        await input(page).fill('A1616E1BFFFFFFFFFFFFFFFF');
        await expect(page.locator('#jsonMeta')).toHaveText('metrological-text.md §3.1');
        await expect(page.locator('#jsonOut')).toHaveText('{\n  "n": 18446744073709551615\n}');

        // A decimal fraction is a number in that text, not a tagged array.
        await input(page).fill('A16178C482200A');   // {"x": 4([-1, 10])}
        await expect(page.locator('#jsonOut')).toHaveText('{\n  "x": 1.0\n}');
    });

    test('says so when a document has no JSON text, and shows it all the same', async ({ page }) => {
        await input(page).fill('A10102');            // {1: 2} — an integer key
        await expect(status(page)).toHaveClass(/\bok\b/);
        await expect(page.locator('#jsonMeta')).toHaveText('extended rendering');
        await expect(page.locator('#jsonNote')).toBeVisible();
        await expect(page.locator('#jsonNote')).not.toContainText('mapKeys');
        expect(await shownJson(page)).toEqual({ 1: 2 });

        await input(page).fill(README.certificate);
        await expect(page.locator('#jsonNote')).toBeHidden();
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
        await expect(page.locator('#tree')).toContainText('ESP256 · kid "meter-0042"');
        await expect(page.locator('#tree')).not.toContainText('deprecated');
        await expect(page.locator('.reading-path')).toHaveText([
            '$ » payload.energy', '$ » payload.current', '$ » payload.voltage', '$ » payload.temperature',
        ]);

        // The example on the page is signed in the browser. Verify it here,
        // in Node, with the published test key it was made from.
        const message = CoseSign1.parse(hexToBytes(await input(page).inputValue()));
        const key     = CoseKey.fromPrivateScalar(
            CoseCurves.P256,
            hexToBytes('6C1382765AEC5358F117733D281C1C7BDC39884D04A45A1E6C67C858BC206C19'),
            { algorithm: CoseAlgorithms.ESP256 });
        expect(message.verify(key.publicKey()).verified).toBe(true);

        // The example's key field holds exactly that public key, so the page
        // reaches the same verdict.
        expect(CoseKey.parse(hexToBytes(await verifyKey(page).inputValue())).isPrivate).toBe(false);
        await expect(signatures(page)).toHaveCount(1);
        await expect(signatures(page)).toHaveClass(/\bsig-verified\b/);
        await expect(signatures(page)).toContainText('Verified with the COSE_Key "meter-0042"');
        await expect(status(page)).toContainText('1 signature verified');
    });

    test('fails a COSE_Sign1 whose signature does not match the key', async ({ page }) => {
        await page.getByRole('button', { name: 'COSE-signed record' }).click();
        await input(page).fill(flipLastDigit(await input(page).inputValue()));
        await expect(status(page)).toHaveClass(/\berror\b/);
        await expect(status(page)).toContainText('a signature does not verify');
        await expect(signatures(page)).toHaveClass(/\bsig-failed\b/);

        // Without a key nothing is claimed either way.
        await verifyKey(page).fill('');
        await expect(status(page)).toHaveClass(/\bok\b/);
        await expect(signatures(page)).toHaveClass(/\bsig-pending\b/);
        await expect(signatures(page)).toContainText('Not checked: no key');
    });

    test('checks a countersignature on its own, with the countersigner\'s key', async ({ page }) => {
        await page.getByRole('button', { name: 'COSE with countersignature' }).click();
        await expect(signatures(page)).toHaveCount(2);
        await expect(signatures(page).nth(1)).toContainText('Countersignature · ESP256 · kid "operator-backend"');
        await expect(signatures(page).nth(1)).toContainText('$[1][11]');
        await expect(signatures(page)).toHaveClass([/\bsig-verified\b/, /\bsig-verified\b/]);
        await expect(page.locator('#keyStatus')).toContainText('COSE_Key "meter-0042" on P-256, and the COSE_Key "operator-backend" on P-256');
        await expect(status(page)).toContainText('2 signatures verified');

        // Checked in Node as well, with the key the page was given for it,
        // so that the page cannot be agreeing only with itself.
        const [meterKey, backendKey] = (await verifyKey(page).inputValue()).split('\n')
            .map((line) => CoseKey.parse(hexToBytes(line)));
        const message = CoseSign1.parse(hexToBytes(await input(page).inputValue()));
        expect(message.countersignatures).toHaveLength(1);
        expect(message.verifyCountersignature(message.countersignatures[0], backendKey).verified).toBe(true);
        expect(message.verifyCountersignature(message.countersignatures[0], meterKey).verified).toBe(false);

        // Without the countersigner's key, the countersignature is left
        // unchecked — not failed — and the meter's signature still verifies.
        await verifyKey(page).fill(bytesToHex(meterKey.toBytes()));
        await expect(signatures(page)).toHaveClass([/\bsig-verified\b/, /\bsig-pending\b/]);
        await expect(signatures(page).nth(1)).toContainText('none of the keys you supplied has its key identifier, "operator-backend"');
        await expect(status(page)).toHaveClass(/\bok\b/);

        // A key that claims the countersigner's identifier and is not its key.
        const impostor = CoseKey.fromPrivateScalar(
            CoseCurves.P256,
            hexToBytes('6C1382765AEC5358F117733D281C1C7BDC39884D04A45A1E6C67C858BC206C19'),
            { algorithm: CoseAlgorithms.ESP256, keyIdentifier: new TextEncoder().encode('operator-backend') });
        await verifyKey(page).fill(`${bytesToHex(meterKey.toBytes())}\n\n${bytesToHex(impostor.publicKey().toBytes())}`);
        await expect(signatures(page)).toHaveClass([/\bsig-verified\b/, /\bsig-failed\b/]);
        await expect(status(page)).toContainText('a signature does not verify');

        // A countersignature vouches for the meter's signature, so altering
        // that signature breaks both.
        await verifyKey(page).fill(`${bytesToHex(meterKey.toBytes())}\n${bytesToHex(backendKey.toBytes())}`);
        await input(page).fill(flipLastDigit(await input(page).inputValue()));
        await expect(signatures(page)).toHaveClass([/\bsig-failed\b/, /\bsig-failed\b/]);
    });

    test('checks the countersignature of RFC 8152 too, and says what it does not cover', async ({ page }) => {
        // countersign/signed1-01 of https://github.com/cose-wg/Examples: a
        // COSE_Sign1 signed with EdDSA on Ed25519 and countersigned at label
        // 7 with the same key, whose public half the working group publishes.
        const signed = 'D28445A201270300A2078343A10127A10442313158406DAED158AFE4032E8DD477D3D2B7F667E7957AA8302BB5E568B4DCBCCE3CF0ED5A90F831351C85D6155A42A17CA1F25F501CC13F67108AE53BDA92DB88272E000442313154546869732069732074686520636F6E74656E742E58407142FD2FF96D56DB85BEE905A76BA1D0B7321A95C8C4D3607C5781932B7AFB8711497DFA751BF40B58B3BCC32300B1487F3DB34085EEF013BF08F4A44D6FEF0D';
        const key    = CoseKey.fromOkpPublicKey(
            CoseCurves.Ed25519,
            hexToBytes('D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A'));

        await input(page).fill(signed);
        await verifyKey(page).fill(bytesToHex(key.toBytes()));
        await expect(signatures(page)).toHaveCount(2);
        await expect(signatures(page).nth(1)).toContainText('Countersignature (RFC 8152) · EdDSA · kid "11"');
        await expect(signatures(page).nth(1)).toContainText('$[1][7]');
        await expect(signatures(page).nth(1)).toContainText('covers the payload but not the signature');
        await expect(signatures(page)).toHaveClass([/\bsig-verified\b/, /\bsig-verified\b/]);
        await expect(page.locator('#sigMeta')).toHaveText('2 signatures · 2 verified');

        // The example writes label 7 before label 4, which the page flags —
        // RFC 8152 asked for no deterministic encoding.
        await expect(status(page)).toHaveClass(/\bwarn\b/);
        await expect(status(page)).toContainText('ERR_CBOR_UNSORTED_KEYS');

        // Which is exactly its weakness: with the body signature altered, the
        // countersignature of RFC 8152 still verifies.
        await input(page).fill(flipLastDigit(signed));
        await expect(signatures(page)).toHaveClass([/\bsig-failed\b/, /\bsig-verified\b/]);
    });

    test('checks an RSA signature against an RSA COSE_Key', async ({ page }) => {
        // A fresh key from Node's own RSA, so the page is held to a key that
        // neither it nor the library made.
        const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
        const jwk  = privateKey.export({ format: 'jwk' });
        const part = (name) => new Uint8Array(Buffer.from(jwk[name], 'base64url'));
        const key  = CoseKey.fromRsaPrivateKey(
            { n: part('n'), e: part('e'), d: part('d'), p: part('p'), q: part('q'),
              dP: part('dp'), dQ: part('dq'), qInv: part('qi') },
            { algorithm: CoseAlgorithms.PS256 });
        const signed = bytesToHex(CoseSign1.sign(hexToBytes(README.certificate), key).toBytes());

        await input(page).fill(signed);
        await verifyKey(page).fill(bytesToHex(key.publicKey().toBytes()));
        await expect(page.locator('#tree')).toContainText('PS256');
        await expect(signatures(page)).toHaveClass(/\bsig-verified\b/);
        await expect(status(page)).toContainText('1 signature verified');

        await input(page).fill(flipLastDigit(signed));
        await expect(status(page)).toContainText('a signature does not verify');
        await expect(signatures(page)).toHaveClass(/\bsig-failed\b/);
    });

    test('checks a COSE_Sign1 against the certificate it carries, and against a trusted one', async ({ page }) => {
        await page.getByRole('button', { name: 'COSE with certificate' }).click();
        await expect(verifyKey(page)).toHaveValue('');
        await expect(status(page)).toHaveClass(/\bok\b/);
        await expect(signatures(page)).toHaveClass(/\bsig-verified\b/);
        await expect(page.locator('#tree')).toContainText('ESP256');
        await expect(page.locator('#tree')).not.toContainText('deprecated');
        await expect(signatures(page)).toContainText('Matches the certificate it carries (x5chain): O=Example Meter Vendor,CN=meter-0042');
        await expect(signatures(page)).toContainText('not checked');

        // The certificate, read from the message in Node and handed back as
        // PEM, is the trust anchor the chain is then walked to.
        const message     = CoseSign1.parse(hexToBytes(await input(page).inputValue()));
        const certificate = message.certificateChain.endEntity.encoded;
        const pem         = '-----BEGIN CERTIFICATE-----\n'
                          + Buffer.from(certificate).toString('base64').match(/.{1,64}/g).join('\n')
                          + '\n-----END CERTIFICATE-----\n';
        await verifyKey(page).fill(pem);
        await expect(page.locator('#keyStatus')).toContainText('Using the certificate O=Example Meter Vendor,CN=meter-0042');
        await expect(signatures(page)).toContainText('its certificate chain leads to the certificate you supplied');

        // A message that was altered on the way fails against its own certificate.
        await verifyKey(page).fill('');
        await input(page).fill(flipLastDigit(await input(page).inputValue()));
        await expect(status(page)).toHaveClass(/\berror\b/);
        await expect(signatures(page)).toContainText('Does not verify with the key of the certificate it carries');
    });

    test('says which text in the key field is not a key', async ({ page }) => {
        await page.getByRole('button', { name: 'COSE-signed record' }).click();
        await verifyKey(page).fill('A101FF');
        await expect(page.locator('#keyStatus')).toContainText('Neither a COSE_Key nor an X.509 certificate');
        await expect(signatures(page)).toHaveClass(/\bsig-pending\b/);
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

    test('keeps every digit of every number, and refuses a key given twice', async ({ page }) => {
        // JSON.parse would make 9007199254740992 of the first and keep the
        // second "a" alone.
        const text = '{ "n": 9007199254740993, "big": 18446744073709551615, "price": 0.30 }';
        await input(page).fill(text);
        await expect(status(page)).toHaveClass(/\bok\b/);
        await expect.poll(() => shownHex(page)).toBe(bytesToHex(jsonTextToMcbor(text)));
        await expect(page.locator('#diagOut')).toHaveText(
            '{"n": 9007199254740993, "big": 18446744073709551615, "price": 4([-2, 30])}');

        await input(page).fill('{ "a": 1, "a": 2 }');
        await expect(status(page)).toHaveClass(/\berror\b/);
        await expect(status(page)).toContainText('the same key twice');
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
