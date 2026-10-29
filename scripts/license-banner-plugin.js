'use strict';

// Puts the licence obligations of everything bundled into validator.js at the
// top of validator.js itself.
//
// The deployed page is three files and nothing else, so the notices have to
// travel inside the bundle: the MIT licence of the @noble packages requires
// its copyright and permission notice in every copy, and the Apache licence
// of the Vanaheimr packages requires their NOTICE attribution. The source
// banners of the libraries do not cover this — @noble/hashes has none, and
// tree shaking drops the file @noble/ciphers keeps its banner in.
//
// The list is taken from the modules webpack actually bundled, and the
// copyright lines from each package's own LICENSE and NOTICE files, so a new
// dependency or a new copyright holder cannot be forgotten here.

const fs   = require('fs');
const path = require('path');
const { Compilation, sources } = require('webpack');

const PLUGIN = 'LicenseBannerPlugin';

/** The package a module file belongs to, or undefined for the app's own code. */
function packageRootOf(resource) {
    const normalized = resource.split(path.sep).join('/');
    const match = normalized.match(/^(.*\/node_modules\/(?:@[^/]+\/)?[^/]+)\//);
    return match ? match[1] : undefined;
}

function readIfPresent(directory, names) {
    for (const name of names) {
        const file = path.join(directory, name);
        if (fs.existsSync(file))
            return fs.readFileSync(file, 'utf8').replace(/\r/g, '');
    }
    return '';
}

/** Copyright lines of a package, NOTICE first; template placeholders skipped. */
function copyrightLines(directory) {
    const text = readIfPresent(directory, ['NOTICE']) + '\n'
               + readIfPresent(directory, ['LICENSE', 'LICENSE.md', 'LICENSE.txt']);
    const lines = text.split('\n')
        .map((line) => line.trim())
        .filter((line) => /^Copyright\b/.test(line) && !line.includes('['));
    return [...new Set(lines)];
}

/** The MIT permission text, from a package's LICENSE, without its title and copyright lines. */
function mitPermissionText(directory) {
    return readIfPresent(directory, ['LICENSE', 'LICENSE.md', 'LICENSE.txt'])
        .split('\n')
        .filter((line) => !/^\s*Copyright\b/.test(line) && !/^\s*The MIT License/.test(line))
        .join('\n')
        .trim();
}

class LicenseBannerPlugin {

    constructor({ title, copyright, license, url }) {
        this.header = [title, `${copyright} — ${license}`, url];
    }

    apply(compiler) {
        compiler.hooks.thisCompilation.tap(PLUGIN, (compilation) => {
            compilation.hooks.processAssets.tap(
                // Before minification, so that terser sees the banner and
                // keeps it as the /*! comment it is.
                { name: PLUGIN, stage: Compilation.PROCESS_ASSETS_STAGE_ADDITIONS },
                () => {
                    const banner = this.banner(compilation);
                    for (const chunk of compilation.chunks)
                        for (const file of chunk.files)
                            if (file.endsWith('.js'))
                                compilation.updateAsset(file, (old) =>
                                    new sources.ConcatSource(banner, '\n', old));
                });
        });
    }

    banner(compilation) {

        const roots = new Set();
        for (const module of compilation.modules)
            for (const inner of module.modules ?? [module])
                if (inner.resource) {
                    const root = packageRootOf(inner.resource);
                    if (root)
                        roots.add(root);
                }

        const packages = [...roots]
            .map((root) => ({ root, manifest: JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) }))
            .sort((a, b) => a.manifest.name.localeCompare(b.manifest.name));

        const lines = [...this.header, '', 'This file bundles the following software:', ''];
        let mitSource;
        let apache = false;

        for (const { root, manifest } of packages) {
            lines.push(`${manifest.name} ${manifest.version} — ${manifest.license}`);
            for (const copyright of copyrightLines(root))
                lines.push(`    ${copyright}`);
            if (manifest.license === 'MIT')
                mitSource ??= root;
            if (manifest.license === 'Apache-2.0')
                apache = true;
        }

        if (apache)
            lines.push('', 'Apache License 2.0: https://www.apache.org/licenses/LICENSE-2.0',
                       'This product includes software developed by GraphDefined GmbH',
                       '(https://www.graphdefined.com).');

        if (mitSource)
            lines.push('', 'The MIT License, under which the MIT-licensed packages above are distributed:',
                       '', mitPermissionText(mitSource));

        const body = lines.join('\n').replaceAll('*/', '* /');
        return `/*!\n${body.split('\n').map((line) => ` * ${line}`.trimEnd()).join('\n')}\n */`;
    }

}

module.exports = LicenseBannerPlugin;
