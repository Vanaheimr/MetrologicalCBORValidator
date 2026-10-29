// The deployment promise of this project is "copy three files onto a web
// server". This checks that the build keeps it: exactly those three files,
// the page referencing the other two, and nothing fetched from elsewhere.

import { readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist     = fileURLToPath(new URL('../dist', import.meta.url));
const expected = ['index.html', 'styles.css', 'validator.js'];
const failures = [];

const files = (await readdir(dist)).sort();
if (files.join() !== expected.join())
    failures.push(`dist/ holds [${files.join(', ')}], expected exactly [${expected.join(', ')}]`);

for (const name of expected)
    if ((await stat(join(dist, name)).catch(() => ({ size: 0 }))).size === 0)
        failures.push(`dist/${name} is missing or empty`);

const html = await readFile(join(dist, 'index.html'), 'utf8').catch(() => '');

if (!/<link[^>]+href="styles\.css"/.test(html))
    failures.push('index.html does not load styles.css');
if (!/<script[^>]+src="validator\.js"/.test(html))
    failures.push('index.html does not load validator.js');

for (const [, attribute, url] of html.matchAll(/<(?:script|link)\b[^>]*\b(src|href)="([^"]+)"/g))
    if (/^(https?:)?\/\//i.test(url))
        failures.push(`index.html loads ${attribute}="${url}" from another host`);

// The licence notices of the bundled packages travel only inside the bundle,
// so a minifier setting that strips the banner would quietly break the
// licences of everything the page ships.
const bundle = await readFile(join(dist, 'validator.js'), 'utf8').catch(() => '');

if (!bundle.startsWith('/*!\n * Metrological CBOR Validator'))
    failures.push('validator.js does not start with its licence banner');
for (const name of ['@vanaheimr/metrological-cbor', '@vanaheimr/cose'])
    if (!bundle.slice(0, 4000).includes(` * ${name} `))
        failures.push(`the licence banner of validator.js does not name ${name}`);
if (/ \* @noble\/\S+ \S+ — MIT/.test(bundle.slice(0, 4000)) && !bundle.includes('Permission is hereby granted'))
    failures.push('validator.js bundles MIT-licensed code without the MIT permission notice');

if (failures.length > 0) {
    console.error(failures.map((failure) => `✕ ${failure}`).join('\n'));
    process.exit(1);
}

console.log(`✓ dist/ holds exactly ${expected.join(', ')} and loads nothing from elsewhere`);
