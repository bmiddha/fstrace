import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
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
packages.set(manifest.name, { metadata: manifest, tarball: fs.readFileSync(wrapper) });
const packageSpec = `${manifest.name}@${version}`;

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', data => { stdout += data; });
    child.stderr.on('data', data => { stderr += data; });
    child.on('error', error => {
      reject(error);
    });
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

async function testTracing(bin) {
  if (process.env.FSTRACE_PACKED_TRACE_TEST !== '1') return;
  const socket = path.join(temporary, 'daemon.sock');
  fs.rmSync(socket, { force: true });
  const daemon = spawn(path.join(bin, 'fstrace-daemon'), ['--socket', socket], {
    stdio: ['ignore', 'ignore', 'pipe']
  });
  let daemonError = '';
  daemon.stderr.on('data', data => { daemonError += data; });
  const daemonExit = new Promise(resolve => daemon.once('close', (status, signal) => resolve({ status, signal })));
  try {
    const deadline = Date.now() + 60000;
    while (!fs.existsSync(socket)) {
      assert.equal(daemon.exitCode, null, daemonError);
      assert(Date.now() < deadline, `daemon startup timed out: ${daemonError}`);
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    await new Promise((resolve, reject) => {
      const peer = net.createConnection(socket, () => { peer.destroy(); resolve(); });
      peer.on('error', reject);
    });
    async function trace(args, input = '') {
      const child = spawn(path.join(bin, 'fstrace'), args, {
        cwd: temporary,
        env: { ...process.env, FSTRACE_SOCKET: socket, FSTRACE_FILTER_PREFIX: temporary, FSTRACE_TEST_VALUE: 'kept' },
        stdio: ['pipe', 'pipe', 'pipe', 'pipe', 'pipe']
      });
      const output = ['', '', '', ''];
      child.stdio.slice(1).forEach((stream, index) => stream.on('data', data => { output[index] += data; }));
      child.stdin.end(input);
      const status = await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          child.kill('SIGKILL');
          reject(new Error('packed trace did not finish within 45 seconds'));
        }, 45000);
        child.on('error', reject);
        child.on('close', (code, signal) => {
          clearTimeout(timeout);
          resolve({ code, signal });
        });
      });
      return { ...status, output };
    }
    const target = path.join(temporary, 'packed-report');
    const result = await trace(['/bin/sh', '-c',
      'IFS= read -r line; printf "%s\\n" "$line" "$@" "$FSTRACE_TEST_VALUE" "$PWD"; printf "stderr\\n" >&2; printf "fd4\\n" >&4; printf "file\\n" > "$1"; exit 37',
      'sh', target, 'a b', '', '$x;*'], 'input\n');
    assert.equal(result.code, 37, result.output[1]);
    assert.equal(result.output[0], `input\n${target}\na b\n\n$x;*\nkept\n${temporary}\n`);
    assert.equal(result.output[1], 'stderr\n');
    assert.equal(result.output[2], `WF ${target}\n`);
    assert.equal(result.output[3], 'fd4\n');
    for (const [signal, code] of [['TERM', 143], ['PIPE', 141]]) {
      const killed = await trace(['/bin/sh', '-c', `kill -${signal} $$; exit 77`]);
      assert.equal(killed.code, code, killed.output[1]);
    }
    console.log('PASS packed tracing: args, stdin, stdout/stderr, FD3/4, exit37, SIGTERM143, SIGPIPE141');
  } finally {
    daemon.kill('SIGTERM');
    assert.equal((await daemonExit).signal, 'SIGTERM', daemonError);
  }
}

try {
  for (const global of [false, true]) {
    const prefix = path.join(temporary, global ? 'global' : 'local');
    const install = await run('npm', [
      'install', ...(global ? ['--global'] : []),
      '--prefix', prefix, '--registry', registry, '--cache', path.join(temporary, 'cache'),
      '--ignore-scripts', '--engine-strict', '--no-audit', '--no-fund', packageSpec
    ]);
    assert.equal(install.status, 0, install.stderr);
    const modules = path.join(prefix, global ? 'lib/node_modules' : 'node_modules');
    const packageRoot = path.join(modules, '@fstrace');
    const require = createRequire(path.join(packageRoot, 'fstrace/resolve.cjs'));
    assert.equal(require('./package.json').engines.node, '>=22');
    assert.equal(require(`@fstrace/linux-${process.arch}/package.json`).engines.node, '>=22');
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
    await testTracing(global ? path.join(prefix, 'bin') : path.join(modules, '.bin'));
    fs.rmSync(installedPlatform, { recursive: true });
    const missing = await run(path.join(
      global ? path.join(prefix, 'bin') : path.join(modules, '.bin'), 'fstrace'
    ), ['--version']);
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /optional dependencies enabled/);
  }
  const pnpmPrefix = path.join(temporary, 'pnpm');
  fs.mkdirSync(pnpmPrefix);
  fs.writeFileSync(path.join(pnpmPrefix, 'package.json'), '{"private":true}');
  const pnpm = await run('pnpm', [
    'add', '--dir', pnpmPrefix, '--registry', registry,
    '--store-dir', path.join(temporary, 'pnpm-store'), '--ignore-scripts', packageSpec
  ], { env: { ...process.env, npm_config_manage_package_manager_versions: 'false' } });
  assert.equal(pnpm.status, 0, pnpm.stderr);
  const pnpmRequire = createRequire(fs.realpathSync(path.join(
    pnpmPrefix, 'node_modules/@fstrace/fstrace/resolve.cjs'
  )));
  assert.equal(pnpmRequire(`@fstrace/linux-${process.arch}/package.json`).version, version);
  assert.throws(() => pnpmRequire.resolve(
    `@fstrace/linux-${process.arch === 'x64' ? 'arm64' : 'x64'}/package.json`
  ), { code: 'MODULE_NOT_FOUND' }, 'pnpm must omit the incompatible optional package');
  for (const name of ['fstrace', 'fstrace-daemon']) {
    const executable = path.join(pnpmPrefix, 'node_modules/.bin', name);
    assert(!fs.lstatSync(executable).isSymbolicLink(), 'exercise actual pnpm shell shims');
    const result = await run(executable, ['--version']);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, new RegExp(`^${name} ${version.replaceAll('.', '\\.')}\\s*$`));
  }
  console.log(`PASS packed local/global installs: Linux ${process.arch}, both CLIs, native optional selection, missing-package diagnostics`);
  console.log('PASS packed pnpm install: both real shell shims');
  await testTracing(path.join(pnpmPrefix, 'node_modules/.bin'));
} finally {
  await new Promise(resolve => server.close(resolve));
  fs.rmSync(temporary, { recursive: true, force: true });
}
