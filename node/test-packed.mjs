import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

assert(process.platform === 'linux' && ['x64', 'arm64'].includes(process.arch),
  'packed integration tests require Linux x64 or ARM64');
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'node/fstrace/package.json')));
const { version } = manifest;
const archives = path.join(root, 'dist/npm');
const wrapper = path.join(archives, `fstrace-fstrace-${version}.tgz`);
const packages = new Map(['x64', 'arm64'].map(arch => {
  const metadata = JSON.parse(fs.readFileSync(path.join(root, `node/linux-${arch}/package.json`)));
  const tarball = fs.readFileSync(path.join(archives, `fstrace-linux-${arch}-${version}.tgz`));
  return [metadata.name, { metadata, tarball }];
}));

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', data => { stdout += data; });
    child.stderr.on('data', data => { stderr += data; });
    child.on('error', reject);
    child.on('close', (status, signal) => resolve({ status, signal, stdout, stderr }));
  });
}

// Serve the real platform tarballs locally so npm must select the optional
// dependency itself, without requiring registry publication or credentials.
const server = http.createServer((request, response) => {
  const name = decodeURIComponent(request.url.split('?')[0]).slice(1);
  const entry = packages.get(name.replace(/\/archive\.tgz$/, ''));
  if (!entry) {
    response.writeHead(404);
    response.end(JSON.stringify({ error: `unknown package ${name}` }));
    return;
  }
  if (name.endsWith('/archive.tgz')) {
    response.end(entry.tarball);
    return;
  }
  response.setHeader('content-type', 'application/json');
  response.end(JSON.stringify({
    name,
    'dist-tags': { latest: version },
    versions: {
      [version]: {
        ...entry.metadata,
        dist: {
          tarball: `http://127.0.0.1:${server.address().port}/${name}/archive.tgz`,
          integrity: `sha512-${createHash('sha512').update(entry.tarball).digest('base64')}`
        }
      }
    }
  }));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const registry = `http://127.0.0.1:${server.address().port}`;
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'fstrace-packed-test-'));

try {
  for (const global of [false, true]) {
    const prefix = path.join(temporary, global ? 'global' : 'local');
    const install = await run('npm', [
      'install', ...(global ? ['--global'] : []),
      '--prefix', prefix, '--registry', registry, '--cache', path.join(temporary, 'cache'),
      '--ignore-scripts', '--no-audit', '--no-fund', wrapper
    ]);
    assert.equal(install.status, 0, install.stderr);
    const modules = path.join(prefix, global ? 'lib/node_modules' : 'node_modules');
    const packageRoot = path.join(modules, '@fstrace');
    const require = createRequire(path.join(packageRoot, 'fstrace/resolve.cjs'));
    const installedPlatform = path.dirname(require.resolve(
      `@fstrace/linux-${process.arch}/package.json`
    ));
    assert(fs.existsSync(path.join(installedPlatform, 'bin/fstrace')));
    assert.throws(() => require.resolve(
      `@fstrace/linux-${process.arch === 'x64' ? 'arm64' : 'x64'}/package.json`
    ), { code: 'MODULE_NOT_FOUND' }, 'npm must omit the incompatible optional package');
    for (const name of ['fstrace', 'fstrace-daemon']) {
      const executable = path.join(global ? path.join(prefix, 'bin') : path.join(modules, '.bin'), name);
      const result = await run(executable, ['--version']);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, new RegExp(`^${name} ${version.replaceAll('.', '\\.')}\\s*$`));
    }
    fs.rmSync(installedPlatform, { recursive: true });
    const missing = await run(path.join(
      global ? path.join(prefix, 'bin') : path.join(modules, '.bin'), 'fstrace'
    ), ['--version']);
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /optional dependencies enabled/);
  }
  console.log(`PASS packed local/global installs: Linux ${process.arch}, both CLIs, native optional selection, missing-package diagnostics`);
} finally {
  await new Promise(resolve => server.close(resolve));
  fs.rmSync(temporary, { recursive: true, force: true });
}
