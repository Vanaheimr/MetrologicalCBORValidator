# Metrological CBOR Validator

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
runtime dependencies; the license banners of the bundled libraries are kept
inside `validator.js`.

`npm run watch` rebuilds on change during development.

## License

Apache License 2.0, matching the libraries it is built on.
