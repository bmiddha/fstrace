import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

assert(Number(process.versions.node.split('.')[0]) >= 22, 'packing requires Node.js 22 or newer');

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const skipBuild = process.argv.slice(2).includes('--skip-build');
assert(process.argv.slice(2).every(arg => arg === '--skip-build'), 'usage: node node/pack.mjs [--skip-build]');
const cargo = fs.readFileSync(path.join(root, 'Cargo.toml'), 'utf8');
const version = cargo.match(/\[workspace\.package\]\s+version = "([^"]+)"/)?.[1];
assert(version, 'workspace.package.version not found in Cargo.toml');

const platforms = [
  { arch: 'x64', target: 'x86_64-unknown-linux-musl', machine: 62 },
  { arch: 'arm64', target: 'aarch64-unknown-linux-musl', machine: 183 }
];
const wrapper = JSON.parse(fs.readFileSync(path.join(root, 'node/fstrace/package.json')));
assert.equal(wrapper.version, version, 'bump Rust and all npm package versions together');
assert.equal(wrapper.name, '@fstrace/fstrace');
assert.equal(wrapper.engines.node, '>=22', 'the wrapper requires Node.js 22 or newer');
for (const { arch } of platforms) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, `node/linux-${arch}/package.json`)));
  assert.equal(manifest.version, version, 'bump Rust and all npm package versions together');
  assert.equal(manifest.name, `@fstrace/linux-${arch}`);
  assert.equal(manifest.engines.node, wrapper.engines.node, 'all npm packages must share the Node.js minimum');
  assert.deepEqual(manifest.os, ['linux']);
  assert.deepEqual(manifest.cpu, [arch]);
  assert(!manifest.libc, 'static binaries support both glibc and musl hosts');
  assert.equal(wrapper.optionalDependencies[manifest.name], version);
}

if (!skipBuild) {
  execFileSync(process.env.CARGO || 'cargo', [
    'xtask', 'dist', ...platforms.flatMap(({ target }) => ['--target', target])
  ], { cwd: root, stdio: 'inherit' });
}

function checkBinary(binaryPath, machine) {
  const binary = fs.readFileSync(binaryPath);
  assert.equal(binary.subarray(0, 4).toString('hex'), '7f454c46', `${binaryPath}: expected ELF`);
  assert.equal(binary[4], 2, `${binaryPath}: expected 64-bit ELF`);
  assert.equal(binary[5], 1, `${binaryPath}: expected little-endian ELF`);
  assert.equal(binary.readUInt16LE(18), machine, `${binaryPath}: wrong architecture`);
  const start = Number(binary.readBigUInt64LE(32));
  const size = binary.readUInt16LE(54);
  const count = binary.readUInt16LE(56);
  assert(size >= 56 && start + size * count <= binary.length, 'invalid ELF program headers');
  for (let index = 0; index < count; index++) {
    assert.notEqual(binary.readUInt32LE(start + index * size), 3, `${binaryPath}: expected static binary without PT_INTERP`);
  }
}

const out = path.join(root, 'dist/npm');
fs.mkdirSync(out, { recursive: true });
const stage = fs.mkdtempSync(path.join(out, '.stage-'));
const artifacts = [];
try {
  for (const { arch, target, machine } of platforms) {
    const directory = path.join(stage, `linux-${arch}`);
    fs.mkdirSync(path.join(directory, 'bin'), { recursive: true });
    const archiveRoot = `fstrace-${version}-${target}`;
    execFileSync('tar', [
      '-xzf', path.join(root, 'dist', `${archiveRoot}.tar.gz`),
      '-C', directory, '--strip-components=1',
      `${archiveRoot}/fstrace`, `${archiveRoot}/fstrace-daemon`
    ]);
    for (const name of ['fstrace', 'fstrace-daemon']) {
      checkBinary(path.join(directory, name), machine);
      fs.renameSync(path.join(directory, name), path.join(directory, 'bin', name));
      fs.chmodSync(path.join(directory, 'bin', name), 0o755);
    }
    fs.copyFileSync(path.join(root, `node/linux-${arch}/package.json`), path.join(directory, 'package.json'));
    fs.copyFileSync(path.join(root, 'README.md'), path.join(directory, 'README.md'));
    artifacts.push(directory);
  }
  const directory = path.join(stage, 'fstrace');
  fs.mkdirSync(path.join(directory, 'bin'), { recursive: true });
  for (const name of ['package.json', 'resolve.cjs', 'bin/launch']) {
    fs.copyFileSync(path.join(root, 'node/fstrace', name), path.join(directory, name));
  }
  fs.chmodSync(path.join(directory, 'bin/launch'), 0o755);
  fs.copyFileSync(path.join(root, 'README.md'), path.join(directory, 'README.md'));
  for (const name of ['fstrace.1', 'fstrace-daemon.1']) {
    fs.copyFileSync(path.join(root, 'packaging/man', name), path.join(directory, name));
  }
  artifacts.push(directory);
  for (const directory of artifacts) {
    execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', out], {
      cwd: directory, stdio: 'inherit'
    });
  }
} finally {
  fs.rmSync(stage, { recursive: true, force: true });
}
console.log(`Packed @fstrace packages at version ${version} in ${out}`);
