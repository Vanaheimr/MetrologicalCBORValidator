// Serves dist/ over HTTP, the way a web server would after the three files
// were copied onto it. No dependencies, so the browser tests and the local
// preview need nothing beyond Node itself.

import { createServer } from 'node:http';
import { readFile }     from 'node:fs/promises';
import { extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('../dist', import.meta.url)));
const port = Number(process.env.PORT ?? process.argv[2] ?? 8137);

const contentTypes = {
    '.html': 'text/html; charset=utf-8',
    '.css':  'text/css; charset=utf-8',
    '.js':   'text/javascript; charset=utf-8',
};

createServer(async (request, response) => {

    const path = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    const file = resolve(join(root, path.endsWith('/') ? `${path}index.html` : path));

    if (file !== root && !file.startsWith(root + sep)) {
        response.writeHead(403).end();
        return;
    }

    try {
        const body = await readFile(file);
        response.writeHead(200, {
            'Content-Type':  contentTypes[extname(file)] ?? 'application/octet-stream',
            'Cache-Control': 'no-cache',
        });
        response.end(body);
    } catch {
        response.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not found');
    }

}).listen(port, () => console.log(`Serving ${root} at http://localhost:${port}/`));
