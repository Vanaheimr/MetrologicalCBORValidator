/*
 * Metrological CBOR Validator
 *
 * Two directions, one page:
 *
 *   CBOR → JSON   Paste CBOR as hexadecimal (or Base64), get the parse tree,
 *                 a JSON rendering with every tag-44252 reading as one text
 *                 ("230 V", "(230.00 ±0.12) V, k=2", …) and the diagnostic
 *                 notation of RFC 8949 §8.
 *
 *   JSON → CBOR   Paste JSON, get deterministic CBOR. Strings that read as
 *                 metrological values become CBOR tag 44252; everything else
 *                 maps one-to-one under the usual JSON→CBOR rules.
 *
 * Everything runs locally in the browser.
 */

import {
    decode as decodeCbor, decodeHex, bytesToHex, hexToBytes, diagnostic, walk,
    mcborToJson, jsonToMcbor,
    metrologicalValueFromCbor, formatMetrologicalValue, parseMetrologicalValue,
    metrologicalValue, encodeMetrologicalValue,
    decimal, integer, unitById, uncertainty, prefixName, prefixSymbol,
    UnitRegistry, Units, SIPrefix, METROLOGICAL_VALUE_TAG, McborError,
    cbor,
} from '@vanaheimr/metrological-cbor';

import {
    CoseSign1, CoseKey, CoseCurves, CoseAlgorithms,
    algorithmById, headerLabelName,
} from '@vanaheimr/cose';

const { isTagged } = cbor;


//  ------------------------------------------------------------------
//  Static knowledge: tag names, COSE structure roles, uncertainty keys
//  ------------------------------------------------------------------

const TAG_NAMES = {
    0:     'standard date/time string',
    1:     'epoch-based date/time',
    2:     'unsigned bignum',
    3:     'negative bignum',
    4:     'decimal fraction',
    5:     'bigfloat',
    16:    'COSE_Encrypt0',
    17:    'COSE_Mac0',
    18:    'COSE_Sign1',
    21:    'expected base64url encoding',
    22:    'expected base64 encoding',
    23:    'expected base16 encoding',
    24:    'encoded CBOR data item',
    32:    'URI',
    36:    'MIME message',
    96:    'COSE_Encrypt',
    97:    'COSE_Mac',
    98:    'COSE_Sign',
    55799: 'self-described CBOR',
    44252: 'Metrological value (mCBOR)',
};

const COSE_TAGS = {
    16: { name: 'COSE_Encrypt0', roles: ['protected', 'unprotected', 'ciphertext'] },
    17: { name: 'COSE_Mac0',     roles: ['protected', 'unprotected', 'payload', 'tag'] },
    18: { name: 'COSE_Sign1',    roles: ['protected', 'unprotected', 'payload', 'signature'] },
    96: { name: 'COSE_Encrypt',  roles: ['protected', 'unprotected', 'ciphertext', 'recipients'] },
    97: { name: 'COSE_Mac',      roles: ['protected', 'unprotected', 'payload', 'tag', 'recipients'] },
    98: { name: 'COSE_Sign',     roles: ['protected', 'unprotected', 'payload', 'signatures'] },
};

const SIGNATURE_ROLES = ['protected', 'unprotected', 'signature'];
const RECIPIENT_ROLES = ['protected', 'unprotected', 'ciphertext', 'recipients'];

const MCBOR_ROLES = ['value', 'unit', 'prefix', 'uncertainty'];

const UNCERTAINTY_KEYS = {
    1: 'magnitude',
    2: 'coverage factor',
    3: 'coverage probability',
    4: 'distribution',
    5: 'degrees of freedom',
};

const DISTRIBUTION_NAMES = {
    1: 'normal',
    2: 'rectangular',
    3: 'triangular',
    4: 'u-shaped',
    5: 'student-t',
};

const MAX_TREE_NODES = 4000;


//  ------------------------------------------------------------------
//  Small helpers
//  ------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

function h(tag, className, ...children) {
    const element = document.createElement(tag);
    if (className)
        element.className = className;
    for (const child of children) {
        if (child == null)
            continue;
        element.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return element;
}

const escapeHtml = (text) =>
    text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');

function base64ToBytes(text) {
    const normalized = text.replaceAll('-', '+').replaceAll('_', '/');
    const padded     = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    const binary     = atob(padded);
    const bytes      = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++)
        bytes[i] = binary.charCodeAt(i);
    return bytes;
}

const utf8 = (text) => new TextEncoder().encode(text);

function printableBytes(bytes) {
    if (bytes.length === 0 || bytes.length > 64)
        return null;
    for (const b of bytes)
        if (b < 0x20 || b > 0x7E)
            return null;
    return new TextDecoder().decode(bytes);
}

/** `mantissa × 10^exponent` as an exact positional decimal string. */
function formatScaled(mantissa, exponent) {
    if (exponent === 0)
        return mantissa.toString();
    if (exponent > 0)
        return exponent > 40 ? `${mantissa}e+${exponent}` : mantissa.toString() + '0'.repeat(exponent);
    const scale = -exponent;
    if (scale > 40)
        return `${mantissa}e${exponent}`;
    const negative = mantissa < 0n;
    let digits = (negative ? -mantissa : mantissa).toString();
    if (digits.length <= scale)
        digits = '0'.repeat(scale - digits.length + 1) + digits;
    const point = digits.length - scale;
    return (negative ? '-' : '') + digits.slice(0, point) + '.' + digits.slice(point);
}

function formatFloat(value, width) {
    const text = Number.isFinite(value) && Number.isInteger(value) && Math.abs(value) < 1e15
        ? `${value}.0`
        : String(value);
    return { text, kind: `float${width * 8}` };
}

/** A CBOR path from walk() as a readable pointer, e.g. `$.energy[0]`. */
function formatPath(prefix, path) {
    let result = prefix;
    for (const segment of path) {
        if (segment.kind === 'index')
            result += `[${segment.index}]`;
        else if (segment.kind === 'key')
            result += segment.key.type === 'text'
                ? `.${segment.key.value}`
                : `[${diagnostic(segment.key)}]`;
        // tag segments add no name of their own
    }
    return result;
}


//  ------------------------------------------------------------------
//  Input parsing: hexadecimal first, Base64 as the fallback
//  ------------------------------------------------------------------

function parseBinaryInput(text) {

    let candidate = text.trim();

    // Accept the diagnostic spelling h'…' around plain hex.
    const wrapped = candidate.match(/^h'([\s\S]*)'$/i);
    if (wrapped)
        candidate = wrapped[1];

    // Hexadecimal, tolerating whitespace, 0x prefixes and , ; : separators.
    const hexish = candidate.replace(/0x/gi, ' ').replace(/[\s,;:]+/g, '');
    if (/^[0-9a-fA-F]+$/.test(hexish)) {
        if (hexish.length % 2 !== 0)
            throw new Error(`Hexadecimal input has an odd number of digits (${hexish.length}).`);
        return { bytes: hexToBytes(hexish), encoding: 'hex' };
    }

    // Base64 / base64url.
    const b64 = candidate.replace(/\s+/g, '');
    if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(b64)) {
        try {
            return { bytes: base64ToBytes(b64), encoding: 'Base64' };
        } catch {
            /* fall through to the error below */
        }
    }

    throw new Error('The input is neither hexadecimal nor Base64.');
}


//  ------------------------------------------------------------------
//  Collecting metrological readings, COSE payloads included
//  ------------------------------------------------------------------

function collectReadings(value, strict, list, prefix = '$') {
    walk(value, (item, path) => {

        if (isTagged(item, METROLOGICAL_VALUE_TAG)) {
            const where = formatPath(prefix, path);
            try {
                list.push({ ok: true, text: formatMetrologicalValue(metrologicalValueFromCbor(item, { strict })), path: where });
            } catch (error) {
                list.push({ ok: false, text: error.message, path: where, error });
            }
            return;
        }

        // Look inside COSE payloads, which are byte strings wrapping CBOR.
        if (item.type === 'tag' && COSE_TAGS[Number(item.tag)] && item.value.type === 'array') {
            const roles        = COSE_TAGS[Number(item.tag)].roles;
            const payloadIndex = roles.indexOf('payload');
            const payload      = payloadIndex >= 0 ? item.value.items[payloadIndex] : undefined;
            if (payload?.type === 'bytes' && payload.value.length > 0) {
                try {
                    collectReadings(decodeCbor(payload.value, { strict: false }), false, list,
                                    formatPath(prefix, path) + ' » payload');
                } catch {
                    /* not CBOR — nothing to collect */
                }
            }
        }

    });
    return list;
}


//  ------------------------------------------------------------------
//  The parse tree
//  ------------------------------------------------------------------

const chip  = (text, kind = '') => h('span', `chip ${kind}`.trim(), text);
const badge = (text, kind = 'badge-info') => h('span', `badge ${kind}`, text);

function keyElement(key, ctx) {
    const parts = [];
    if (key.type === 'text')
        parts.push(h('span', 'key', JSON.stringify(key.value)));
    else if (key.type === 'int')
        parts.push(h('span', 'key key-int', key.value.toString()));
    else
        parts.push(h('span', 'key key-complex', diagnostic(key)));

    if (ctx.headerMap && key.type === 'int') {
        const name = headerLabelName(key);
        if (name && !/^-?\d+$/.test(name))
            parts.push(badge(name, 'badge-cose'));
    }
    if (ctx.uncertaintyMap && key.type === 'int') {
        const name = UNCERTAINTY_KEYS[Number(key.value)];
        if (name)
            parts.push(badge(name, 'badge-role'));
    }

    parts.push(h('span', 'colon', ':'));
    return parts;
}

function roleBadgeFor(role) {
    if (!role)
        return null;
    const label = { signatures: 'signatures', recipients: 'recipients' }[role] ?? role;
    return badge(label, MCBOR_ROLES.includes(role) ? 'badge-role' : 'badge-cose');
}

function leafNode(ctx, parts, badges = []) {
    return h('div', 'node leaf',
        ...(ctx.label ?? []),
        ...parts,
        roleBadgeFor(ctx.role),
        ...badges);
}

function containerNode(ctx, summaryParts, badges, children, open = true) {
    const details = h('details', 'node');
    if (open)
        details.open = true;
    details.append(
        h('summary', null,
            ...(ctx.label ?? []),
            ...summaryParts,
            roleBadgeFor(ctx.role),
            ...badges),
        h('div', 'children', ...children));
    return details;
}

function annotateUnit(item) {
    try {
        if (item.type === 'int') {
            const unit = UnitRegistry.standard.tryById(Number(item.value));
            if (unit)
                return badge(`${unit.symbol} — ${unit.name}`, 'badge-reading');
            return badge('unknown unit id', 'badge-warn');
        }
        if (item.type === 'text') {
            const unit = UnitRegistry.standard.bySymbol(item.value);
            return badge(unit.name, 'badge-reading');
        }
    } catch {
        return badge('unknown unit symbol', 'badge-warn');
    }
    return null;
}

function annotatePrefix(item) {
    if (item.type !== 'int')
        return null;
    const exponent = Number(item.value);
    if (exponent === 0)
        return badge('no prefix', 'badge-role');
    try {
        const name   = prefixName(exponent);
        const symbol = prefixSymbol(exponent);
        return badge(`${name.toLowerCase()}${symbol ? ` (${symbol})` : ''} · 10^${exponent}`, 'badge-role');
    } catch {
        return badge('invalid prefix', 'badge-warn');
    }
}

function readingBadgeFor(tagValue, ctx) {
    try {
        const reading = metrologicalValueFromCbor(tagValue, { strict: ctx.state.strict });
        return badge(formatMetrologicalValue(reading), 'badge-reading');
    } catch (error) {
        return badge(error.message, 'badge-error');
    }
}

function coseSummaryFor(tagValue) {
    try {
        const message = CoseSign1.parse(tagValue);
        const parts   = [];
        parts.push(message.algorithm ? message.algorithm.name : 'unknown algorithm');
        const kid = message.keyIdentifier;
        if (kid) {
            const printable = printableBytes(kid);
            parts.push(`kid ${printable ? `"${printable}"` : bytesToHex(kid)}`);
        }
        parts.push(message.isDetached ? 'detached payload' : `payload ${message.payload.length} bytes`);
        return badge(parts.join(' · '), 'badge-cose');
    } catch (error) {
        return badge(`not a valid COSE_Sign1: ${error.message}`, 'badge-warn');
    }
}

function renderBytes(value, ctx) {

    const bytes     = value.value;
    const hex       = bytesToHex(bytes);
    const size      = chip(`${bytes.length} ${bytes.length === 1 ? 'byte' : 'bytes'}`, 'chip-size');
    const roleBadge = roleBadgeFor(ctx.role);
    const bareCtx   = { ...ctx, role: undefined };

    const tryDecodeInside =
        ctx.role === 'protected' || ctx.role === 'payload' || ctx.embeddedCbor;

    if (tryDecodeInside && bytes.length > 0) {
        try {
            const inner    = decodeCbor(bytes, { strict: false });
            const innerCtx = { state: ctx.state, headerMap: ctx.role === 'protected' };
            const child    = renderNode(inner, innerCtx);
            if (child) {
                return containerNode(bareCtx,
                    [chip('bytes', 'chip-type'), size, roleBadge, badge('contains CBOR', 'badge-info'),
                     h('span', 'bytes-preview', shortHex(hex))],
                    [],
                    [h('div', 'decoded-caption', 'decoded content:'), child]);
            }
        } catch {
            /* not CBOR after all — fall through to the plain rendering */
        }
    }

    const empty = bytes.length === 0
        ? badge(ctx.role === 'protected' ? 'empty bucket' : 'empty', 'badge-info')
        : null;

    return leafNode(bareCtx,
        [chip('bytes', 'chip-type'), size, roleBadge, empty, h('span', 'scalar mono bytes-hex', shortHex(hex))],
        []);
}

const shortHex = (hex) =>
    hex.length > 96 ? `${hex.slice(0, 96)}… (+${(hex.length - 96) / 2} bytes)` : hex;

function renderNode(value, ctx) {

    const state = ctx.state;
    if (state.count >= MAX_TREE_NODES) {
        state.truncated = true;
        return null;
    }
    state.count++;

    switch (value.type) {

        case 'int':
            return leafNode(ctx, [chip('int', 'chip-type'), h('span', 'scalar mono num', value.value.toString())]);

        case 'text':
            return leafNode(ctx, [chip('text', 'chip-type'), h('span', 'scalar mono str', JSON.stringify(value.value))]);

        case 'bool':
            return leafNode(ctx, [chip('bool', 'chip-type'), h('span', 'scalar mono kw', String(value.value))]);

        case 'null':
            return leafNode(ctx, [chip('null', 'chip-type'), h('span', 'scalar mono kw', 'null')],
                [ctx.role === 'payload' ? badge('detached payload', 'badge-warn') : null]);

        case 'undefined':
            return leafNode(ctx, [chip('undefined', 'chip-type'), h('span', 'scalar mono kw', 'undefined')]);

        case 'simple':
            return leafNode(ctx, [chip('simple', 'chip-type'), h('span', 'scalar mono num', `simple(${value.value})`)]);

        case 'float': {
            const { text, kind } = formatFloat(value.value, value.width);
            return leafNode(ctx, [chip(kind, 'chip-type'), h('span', 'scalar mono num', text)]);
        }

        case 'bytes':
            return renderBytes(value, ctx);

        case 'array': {
            const children = value.items.map((item, index) => {
                const childCtx = { state };
                if (ctx.listOf)
                    childCtx.roles = ctx.listOf;
                const role = ctx.roles?.[index];
                if (role) {
                    childCtx.role = role;
                    if (role === 'unprotected')
                        childCtx.headerMap = true;
                    if (role === 'uncertainty')
                        childCtx.uncertaintyMap = true;
                    if (role === 'signatures')
                        childCtx.listOf = SIGNATURE_ROLES;
                    if (role === 'recipients')
                        childCtx.listOf = RECIPIENT_ROLES;
                    if (role === 'unit' && item.type === 'array')
                        childCtx.unitProduct = true;
                }
                const element = renderNode(item, childCtx);
                if (element && role === 'unit') {
                    const annotation = annotateUnit(item);
                    if (annotation)
                        appendBadge(element, annotation);
                }
                if (element && role === 'prefix') {
                    const annotation = annotatePrefix(item);
                    if (annotation)
                        appendBadge(element, annotation);
                }
                return element;
            }).filter(Boolean);

            return containerNode(ctx,
                [chip('array', 'chip-type'), chip(`${value.items.length} ${value.items.length === 1 ? 'item' : 'items'}`, 'chip-size')],
                [], children, value.items.length <= 50);
        }

        case 'map': {
            const children = value.entries.map(([key, entryValue]) => {
                const childCtx = { state, label: keyElement(key, ctx) };

                if (ctx.uncertaintyMap && key.type === 'int' && Number(key.value) === 4 && entryValue.type === 'int') {
                    const name = DISTRIBUTION_NAMES[Number(entryValue.value)];
                    const element = renderNode(entryValue, childCtx);
                    if (element && name)
                        appendBadge(element, badge(name, 'badge-role'));
                    return element;
                }

                if (ctx.headerMap && key.type === 'int') {
                    const label = Number(key.value);
                    if (label === 1 && entryValue.type === 'int') {
                        const algorithm = algorithmById(Number(entryValue.value));
                        const element   = renderNode(entryValue, childCtx);
                        if (element && algorithm)
                            appendBadge(element, badge(algorithm.name + (algorithm.deprecated ? ' (deprecated)' : ''), 'badge-cose'));
                        return element;
                    }
                    if ((label === 7 || label === 11) && entryValue.type === 'array') {
                        if (entryValue.items[0]?.type === 'array')
                            childCtx.listOf = SIGNATURE_ROLES;      // several countersignatures
                        else
                            childCtx.roles = SIGNATURE_ROLES;       // a single one
                    }
                    if (label === 33 && entryValue.type === 'array')
                        childCtx.role = undefined;                  // x5chain: leave generic
                }

                return renderNode(entryValue, childCtx);
            }).filter(Boolean);

            return containerNode(ctx,
                [chip('map', 'chip-type'), chip(`${value.entries.length} ${value.entries.length === 1 ? 'entry' : 'entries'}`, 'chip-size')],
                [], children, value.entries.length <= 50);
        }

        case 'tag': {
            const tagNumber = Number(value.tag);
            const badges    = [];
            const name      = TAG_NAMES[tagNumber];
            if (name && tagNumber !== 44252)
                badges.push(badge(name, COSE_TAGS[tagNumber] ? 'badge-cose' : 'badge-info'));

            const childCtx = { state };

            if (tagNumber === 44252) {
                badges.push(badge('Metrological value', 'badge-mcbor'));
                badges.push(readingBadgeFor(value, ctx));
                if (value.value.type === 'array')
                    childCtx.roles = MCBOR_ROLES;
            }

            if (COSE_TAGS[tagNumber] && value.value.type === 'array')
                childCtx.roles = COSE_TAGS[tagNumber].roles;

            if (tagNumber === 18)
                badges.push(coseSummaryFor(value));

            if (tagNumber === 24)
                childCtx.embeddedCbor = true;

            if ((tagNumber === 4 || tagNumber === 5)
                && value.value.type === 'array'
                && value.value.items.length === 2
                && value.value.items[0].type === 'int'
                && value.value.items[1].type === 'int') {
                const exponent = Number(value.value.items[0].value);
                const mantissa = value.value.items[1].value;
                if (tagNumber === 4)
                    badges.push(badge(`= ${formatScaled(mantissa, exponent)}`, 'badge-role'));
                else
                    badges.push(badge(`= ${mantissa} × 2^${exponent}`, 'badge-role'));
            }

            const child = renderNode(value.value, childCtx);
            return containerNode(ctx,
                [chip(`tag ${value.tag}`, 'chip-type chip-tag')],
                badges,
                child ? [child] : []);
        }

        default:
            return leafNode(ctx, [chip(value.type ?? 'unknown', 'chip-type')]);
    }
}

function appendBadge(element, badgeElement) {
    const target = element.matches('details') ? element.querySelector(':scope > summary') : element;
    target.append(badgeElement);
}

function renderTree(value, strict) {
    const state     = { count: 0, truncated: false, strict };
    const container = $('tree');
    container.replaceChildren();
    const root = renderNode(value, { state });
    if (root)
        container.append(root);
    if (state.truncated)
        container.append(h('div', 'tree-truncated',
            `Rendering stopped after ${MAX_TREE_NODES} data items — the document continues.`));
    $('treeMeta').textContent = `${state.count}${state.truncated ? '+' : ''} data items`;
}


//  ------------------------------------------------------------------
//  JSON rendering with reading highlighting
//  ------------------------------------------------------------------

const readingCache = new Map();

function looksLikeReading(text) {
    if (readingCache.has(text))
        return readingCache.get(text);
    let result = false;
    try {
        parseMetrologicalValue(text);
        result = true;
    } catch {
        result = false;
    }
    if (readingCache.size > 5000)
        readingCache.clear();
    readingCache.set(text, result);
    return result;
}

function jsonHtml(value, depth) {

    const pad     = '  '.repeat(depth);
    const padNext = '  '.repeat(depth + 1);

    if (value === null)
        return '<span class="j-null">null</span>';

    switch (typeof value) {
        case 'string': {
            const cls = looksLikeReading(value) ? 'j-str j-reading' : 'j-str';
            return `<span class="${cls}" ${cls.includes('j-reading') ? 'title="metrological reading"' : ''}>${escapeHtml(JSON.stringify(value))}</span>`;
        }
        case 'number':
            return `<span class="j-num">${JSON.stringify(value)}</span>`;
        case 'boolean':
            return `<span class="j-bool">${value}</span>`;
    }

    if (Array.isArray(value)) {
        if (value.length === 0)
            return '[]';
        const items = value.map((item) => padNext + jsonHtml(item, depth + 1));
        return `[\n${items.join(',\n')}\n${pad}]`;
    }

    const keys = Object.keys(value);
    if (keys.length === 0)
        return '{}';
    const entries = keys.map((key) =>
        `${padNext}<span class="j-key">${escapeHtml(JSON.stringify(key))}</span>: ${jsonHtml(value[key], depth + 1)}`);
    return `{\n${entries.join(',\n')}\n${pad}}`;
}


//  ------------------------------------------------------------------
//  Status line
//  ------------------------------------------------------------------

function setStatus(kind, message, details = []) {
    const status = $('status');
    status.className = `status ${kind}`;
    status.replaceChildren(
        h('span', 'status-icon', { ok: '✓', warn: '△', error: '✕', idle: '·' }[kind] ?? ''),
        h('span', 'status-message', message),
        ...details.map((text) => h('span', 'status-chip', text)));
}

function errorDetails(error) {
    const details = [];
    if (error instanceof McborError) {
        details.push(error.code);
        if (error.clause)
            details.push(`§${error.clause}`);
    }
    return details;
}


//  ------------------------------------------------------------------
//  Reading chips
//  ------------------------------------------------------------------

function renderReadings(readings) {
    const panel = $('readingsPanel');
    const list  = $('readingChips');
    list.replaceChildren();
    if (readings.length === 0) {
        panel.hidden = true;
        return;
    }
    panel.hidden = false;
    $('readingsMeta').textContent = `${readings.length} × tag 44252`;
    for (const reading of readings) {
        list.append(h('span', reading.ok ? 'reading-chip' : 'reading-chip reading-bad',
            h('code', null, reading.text),
            h('span', 'reading-path', reading.path)));
    }
}


//  ------------------------------------------------------------------
//  The two pipelines
//  ------------------------------------------------------------------

const outputs = { hex: '', json: '', diag: '' };

const toJsonOptions = {
    bytes:        'hex',
    bigIntegers:  'string',
    mapKeys:      'stringify',
    floats:       'number',
    onUnknownTag: (tag, inner) => ({
        'cbor:tag':     Number(tag),
        'cbor:content': mcborToJson(inner, toJsonOptions),
    }),
};

function showResults(value, strict) {

    renderTree(value, strict);

    outputs.diag = diagnostic(value);
    $('diagOut').textContent = outputs.diag;

    const jsonPre = $('jsonOut');
    try {
        const json   = mcborToJson(value, toJsonOptions);
        outputs.json = JSON.stringify(json, null, 2) ?? '';
        jsonPre.innerHTML = jsonHtml(json, 0);
        $('jsonMeta').textContent = '';
    } catch (error) {
        outputs.json = '';
        jsonPre.textContent = '';
        $('jsonMeta').textContent = '';
        jsonPre.append(h('span', 'json-error', `No JSON representation: ${error.message}`));
    }

    const readings = collectReadings(value, strict, []);
    renderReadings(readings);

    $('results').hidden = false;
    return readings;
}

function runDecode(text) {

    $('hexPanel').hidden  = true;
    $('jsonPanel').hidden = false;

    let input;
    try {
        input = parseBinaryInput(text);
    } catch (error) {
        setStatus('error', error.message);
        $('results').hidden = true;
        return;
    }

    let value;
    let strict = true;
    let strictError;

    try {
        value = decodeCbor(input.bytes, { strict: true });
    } catch (error) {
        strictError = error;
        try {
            value  = decodeCbor(input.bytes, { strict: false });
            strict = false;
        } catch (lenientError) {
            setStatus('error', `Invalid CBOR: ${lenientError.message}`, errorDetails(lenientError));
            $('results').hidden = true;
            return;
        }
    }

    const readings = showResults(value, strict);
    const counts   = `${input.bytes.length} bytes (${input.encoding})`
                   + (readings.length > 0 ? ` · ${readings.length} reading${readings.length === 1 ? '' : 's'}` : '');

    const invalid = readings.filter((reading) => !reading.ok);

    if (invalid.length > 0)
        setStatus('error',
            `Well-formed CBOR, but ${invalid.length === 1 ? 'a tag-44252 item is not a valid metrological value'
                                                         : `${invalid.length} tag-44252 items are not valid metrological values`}`
            + ` — ${invalid[0].path}: ${invalid[0].text}`,
            errorDetails(invalid[0].error));
    else if (strict)
        setStatus('ok', `Valid CBOR — deterministic encoding · ${counts}`);
    else
        setStatus('warn',
            `Well-formed CBOR, but not the deterministic encoding: ${strictError.message}`,
            [...errorDetails(strictError), 'decoded leniently']);
}

function runEncode(text) {

    $('hexPanel').hidden  = false;
    $('jsonPanel').hidden = true;

    let json;
    try {
        json = JSON.parse(text);
    } catch (error) {
        setStatus('error', `Invalid JSON: ${error.message}`);
        $('results').hidden = true;
        return;
    }

    const detect = $('detectReadings').checked;

    let bytes;
    try {
        bytes = jsonToMcbor(json, { readings: detect ? 'auto' : 'none' });
    } catch (error) {
        setStatus('error', `Cannot express this document as CBOR: ${error.message}`, errorDetails(error));
        $('results').hidden = true;
        return;
    }

    outputs.hex = bytesToHex(bytes);
    $('hexOut').textContent = outputs.hex.replace(/(.{8})/g, '$1 ').trimEnd();
    $('hexMeta').textContent = `${bytes.length} bytes`;

    let value;
    try {
        value = decodeCbor(bytes, { strict: true });
    } catch (error) {
        setStatus('error', `Internal error while re-reading the encoded bytes: ${error.message}`, errorDetails(error));
        $('results').hidden = true;
        return;
    }
    const readings = showResults(value, true);

    setStatus('ok',
        `Encoded to ${bytes.length} bytes of deterministic CBOR`
        + (detect
            ? ` · ${readings.length} reading${readings.length === 1 ? '' : 's'} converted to tag 44252`
            : ' · reading detection off'));
}


//  ------------------------------------------------------------------
//  Examples
//  ------------------------------------------------------------------

const SESSION_JSON = {
    meter:       '1ISA0000000042',
    transaction: 'a4f1c9e2',
    context:     'Transaction.Begin',
    time:        '2026-08-15T08:14:00Z',
    energy:      '(1234.567 ±12.3) kWh, k=2, p=0.95, dist=normal',
    voltage:     '230.0 V',
    current:     '16 A',
    temperature: '21.5 °C',
};

function buildExamples() {

    const examples = { decode: [], encode: [] };

    try {
        const reading = metrologicalValue({
            value:  decimal(50, -1),
            unit:   unitById(Units.Ampere),
            prefix: SIPrefix.Milli,
        });
        examples.decode.push({ label: '5.0 mA', value: bytesToHex(encodeMetrologicalValue(reading)) });
    } catch { /* keep the page alive without this example */ }

    try {
        const calibrated = metrologicalValue({
            value:       decimal(23000, -2),
            unit:        unitById(Units.Volt),
            uncertainty: uncertainty({ magnitude: decimal(12, -2), coverageFactor: integer(2) }),
        });
        examples.decode.push({ label: '(230.00 ±0.12) V', value: bytesToHex(encodeMetrologicalValue(calibrated)) });
    } catch { /* see above */ }

    let sessionBytes;
    try {
        sessionBytes = jsonToMcbor(SESSION_JSON, { readings: 'auto' });
        examples.decode.push({ label: 'Charging session', value: bytesToHex(sessionBytes) });
    } catch { /* see above */ }

    try {
        if (sessionBytes) {
            const key = CoseKey.fromPrivateScalar(
                CoseCurves.P256,
                hexToBytes('6C1382765AEC5358F117733D281C1C7BDC39884D04A45A1E6C67C858BC206C19'),
                { algorithm: CoseAlgorithms.ES256, keyIdentifier: utf8('meter-0042') });
            const signed = CoseSign1.sign(sessionBytes, key);
            examples.decode.push({ label: 'COSE-signed record', value: bytesToHex(signed.toBytes()) });
        }
    } catch { /* see above */ }

    examples.encode.push({
        label: 'Simple readings',
        value: JSON.stringify({
            device:  'EVSE-01',
            voltage: '230.0 V',
            current: '16 A',
            power:   '3.68 kW',
            note:    'free text stays text',
        }, null, 2),
    });

    examples.encode.push({
        label: 'Charging session',
        value: JSON.stringify(SESSION_JSON, null, 2),
    });

    return examples;
}


//  ------------------------------------------------------------------
//  Wiring
//  ------------------------------------------------------------------

const state = {
    mode:   'decode',
    inputs: { decode: '', encode: '' },
};

let examples = { decode: [], encode: [] };

function renderExampleButtons() {
    const host = $('exampleButtons');
    host.replaceChildren();
    for (const example of examples[state.mode]) {
        const button = h('button', 'example', example.label);
        button.type = 'button';
        button.addEventListener('click', () => {
            $('input').value = example.value;
            state.inputs[state.mode] = example.value;
            run();
        });
        host.append(button);
    }
}

function applyMode() {

    const decode = state.mode === 'decode';

    $('modeDecode').classList.toggle('active', decode);
    $('modeEncode').classList.toggle('active', !decode);
    $('modeDecode').setAttribute('aria-selected', String(decode));
    $('modeEncode').setAttribute('aria-selected', String(!decode));

    $('inputLabel').textContent = decode
        ? 'CBOR input — hexadecimal or Base64'
        : 'JSON input';

    $('input').placeholder = decode
        ? 'Paste CBOR as hexadecimal, e.g.\n\nD9ACDC 83 C482201832 04 22'
        : 'Paste JSON, e.g.\n\n{\n  "voltage": "230.0 V",\n  "energy":  "1.10 kWh"\n}';

    $('readingsOption').hidden = decode;

    $('input').value = state.inputs[state.mode];
    renderExampleButtons();
    run();
}

function run() {
    const text = $('input').value;
    state.inputs[state.mode] = text;
    if (text.trim() === '') {
        setStatus('idle', 'Waiting for input …');
        $('results').hidden = true;
        return;
    }
    if (state.mode === 'decode')
        runDecode(text);
    else
        runEncode(text);
}

let debounce;

function init() {

    examples = buildExamples();

    $('modeDecode').addEventListener('click', () => { if (state.mode !== 'decode') { state.mode = 'decode'; applyMode(); } });
    $('modeEncode').addEventListener('click', () => { if (state.mode !== 'encode') { state.mode = 'encode'; applyMode(); } });

    $('input').addEventListener('input', () => {
        clearTimeout(debounce);
        debounce = setTimeout(run, 160);
    });
    $('input').addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
            event.preventDefault();
            clearTimeout(debounce);
            run();
        }
    });

    $('clearInput').addEventListener('click', () => {
        $('input').value = '';
        $('input').focus();
        run();
    });

    $('detectReadings').addEventListener('change', run);

    for (const button of document.querySelectorAll('button.copy')) {
        button.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(outputs[button.dataset.copy] ?? '');
                const original = button.textContent;
                button.textContent = 'Copied ✓';
                setTimeout(() => { button.textContent = original; }, 1200);
            } catch {
                /* clipboard unavailable (e.g. http without permission) — ignore */
            }
        });
    }

    $('mcborVersion').textContent = `v${__MCBOR_VERSION__}`;
    $('coseVersion').textContent  = `v${__COSE_VERSION__}`;

    applyMode();
}

init();
