# Metrological CBOR Validator

[![CI](https://github.com/Vanaheimr/MetrologicalCBORValidator/actions/workflows/ci.yml/badge.svg)](https://github.com/Vanaheimr/MetrologicalCBORValidator/actions/workflows/ci.yml)
[![Nightly](https://github.com/Vanaheimr/MetrologicalCBORValidator/actions/workflows/nightly.yml/badge.svg)](https://github.com/Vanaheimr/MetrologicalCBORValidator/actions/workflows/nightly.yml)
[![metrological-cbor](https://img.shields.io/npm/v/@vanaheimr/metrological-cbor.svg?label=%40vanaheimr%2Fmetrological-cbor)](https://www.npmjs.com/package/@vanaheimr/metrological-cbor)
[![cose](https://img.shields.io/npm/v/@vanaheimr/cose.svg?label=%40vanaheimr%2Fcose)](https://www.npmjs.com/package/@vanaheimr/cose)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A static single-page validator for [Metrological CBOR](https://github.com/OpenChargingTechnology/Whitepapers/tree/master/MetrologicalCBOR)
(CBOR tag 44252), in the spirit of the classic JSON validator pages. Everything
runs locally in the browser; nothing is uploaded anywhere.

Two directions, switchable on the page:

- **CBOR → JSON** — paste CBOR as hexadecimal (or Base64) and get
  - a validation verdict (valid deterministic encoding / well-formed but
    lenient / invalid, with the error code and specification clause),
  - every tag-44252 reading, decoded and formatted (`(230.00 ±0.12) V, k=2`),
    COSE payloads included,
  - the structured parse tree, with mCBOR roles (value, unit, prefix,
    uncertainty), unit and SI-prefix names, and COSE_Sign1/COSE_Sign/… buckets
    annotated and their protected headers and payloads decoded inline,
  - a JSON rendering with every reading as one string (`"230 V"`), and
  - the diagnostic notation of RFC 8949 §8.
- **JSON → CBOR** — paste JSON and get deterministic CBOR as hexadecimal.
  Property values that read as metrological values (`"1.10 kWh"`,
  `"(1234.567 ±12.3) kWh, k=2, p=0.95, dist=normal"`) are converted to CBOR
  tag 44252; everything else maps one-to-one under the usual JSON→CBOR rules.

Built on [@vanaheimr/metrological-cbor](https://www.npmjs.com/package/@vanaheimr/metrological-cbor)
and [@vanaheimr/cose](https://www.npmjs.com/package/@vanaheimr/cose).

## Building

```
npm ci
npm run build
```

Webpack writes exactly three static assets to `dist/`:

```
dist/index.html
dist/styles.css
dist/validator.js
```

Deploying is copying those three files onto any web server (or opening them
from any static hosting). There is no backend and there are no further
runtime dependencies. Because the page is only those three files, the
copyright and license notices of everything bundled into `validator.js` —
the Vanaheimr packages (Apache-2.0) and the `@noble` cryptography (MIT) — are
generated into its head at build time, from the LICENSE and NOTICE files of
exactly the packages webpack bundled.

`npm run watch` rebuilds on change during development, and `npm run serve`
serves `dist/` at http://localhost:8137/ the way a web server would.

## Testing

```
npx playwright install chromium
npm run verify
```

`verify` builds, checks that `dist/` holds exactly the three deployable files,
loads nothing from another host and carries its license notices, and then drives the built page in a real
browser with [Playwright](https://playwright.dev): the worked examples of the
codec's README decode to the readings they document, malformed and
non-deterministic CBOR is refused or flagged, a tag 44252 that is not a valid
metrological value fails validation, JSON round-trips through CBOR unchanged,
and the COSE-signed example verifies with the key it was made from. Any page
error or console error fails the test it happened in. `BROWSERS=all` runs
Chromium, Firefox and WebKit.

**CI** runs `npm run verify` on every push and pull request — Node 20, 22 and
24 on Linux, Node 22 on Windows and macOS — and keeps the built files of each
green run as a downloadable artifact.

**Nightly** runs what nobody waits for: all three browser engines with every
dependency resolved afresh without the lock file, the newest published
`@vanaheimr/metrological-cbor` and `@vanaheimr/cose` even where their next
0.x minor lies outside the caret ranges, and `npm audit`.

## License

[Apache License 2.0](LICENSE) and [NOTICE](NOTICE), matching the libraries it
is built on.

Copyright 2026 GraphDefined GmbH
