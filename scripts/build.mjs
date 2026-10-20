// Bundles the backend into one ES module with no runtime dependencies (the server uses only Node built-ins).
// Output: dist/cli.mjs. The migrations are shipped as files next to dist/ (see Dockerfile).
import * as esbuild from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
fs.rmSync(path.join(root, 'dist'), { recursive: true, force: true });
await esbuild.build({
  entryPoints: [path.join(root, 'src', 'cli.ts')],
  outfile: path.join(root, 'dist', 'cli.mjs'),
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'esm',
  packages: 'bundle',
  sourcemap: true,
  logLevel: 'warning',
});
console.log('built server/dist/cli.mjs');
