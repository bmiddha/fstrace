'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const { resolveBinary } = require('../fstrace/resolve.cjs');

test('unsupported platforms and executable names fail explicitly', () => {
  for (const [platform, arch] of [['darwin', 'arm64'], ['win32', 'x64'], ['linux', 'ia32']]) {
    assert.throws(() => resolveBinary('fstrace', platform, arch), /unsupported platform/);
  }
  assert.throws(() => resolveBinary('unexpected', 'linux', 'x64'), /unknown executable/);
});

test('both launchers preserve argv, environment, cwd, I/O, FD 3 and exit/signal status', {
  skip: process.platform !== 'linux' || !['x64', 'arm64'].includes(process.arch)
}, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fstrace-launch-test-'));
  try {
    const wrapper = path.join(directory, 'node_modules/@fstrace/fstrace');
    const platform = path.join(directory, `node_modules/@fstrace/linux-${process.arch}`);
    fs.mkdirSync(path.join(platform, 'bin'), { recursive: true });
    fs.cpSync(path.join(__dirname, '../fstrace'), wrapper, { recursive: true });
    const { version } = require('../fstrace/package.json');
    const manifest = path.join(platform, 'package.json');
    fs.writeFileSync(manifest, JSON.stringify({ version }));
    const script = `#!/bin/sh
if [ "$1" = signal ]; then kill -TERM $$; fi
IFS= read -r line
printf 'stdin:%s\\n' "$line"
printf '%s\\n' "$@" "$FSTRACE_TEST_VALUE" "$PWD"
printf 'stderr\\n' >&2
printf 'report\\n' >&3
printf 'extra-fd\\n' >&4
exit 37
`;
    const bin = path.join(directory, 'node_modules/.bin');
    fs.mkdirSync(bin);
    for (const name of ['fstrace', 'fstrace-daemon']) {
      fs.chmodSync(path.join(wrapper, 'bin', name), 0o755);
      fs.writeFileSync(path.join(platform, 'bin', name), script, { mode: 0o755 });
      fs.symlinkSync(`../@fstrace/fstrace/bin/${name}`, path.join(bin, name));
      const result = spawnSync(path.join(bin, name), ['argument with spaces', '', '--flag=$value;*'], {
        cwd: directory,
        env: { ...process.env, FSTRACE_TEST_VALUE: 'environment preserved' },
        input: 'input preserved\n',
        stdio: ['pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
        encoding: 'utf8'
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 37);
      assert.equal(result.stdout, `stdin:input preserved\nargument with spaces\n\n--flag=$value;*\nenvironment preserved\n${directory}\n`);
      assert.equal(result.stderr, 'stderr\n');
      assert.equal(result.output[3], 'report\n');
      assert.equal(result.output[4], 'extra-fd\n');
      const signaled = spawnSync(path.join(bin, name), ['signal']);
      assert.equal(signaled.signal, 'SIGTERM');
      assert.equal(signaled.status, null);
    }

    for (const name of ['fstrace', 'fstrace-daemon']) {
      const result = spawnSync('/bin/sh', [path.join(wrapper, 'bin', name), 'argument with spaces', ''], {
        cwd: directory,
        env: { ...process.env, FSTRACE_TEST_VALUE: 'environment preserved' },
        input: 'input preserved\n',
        stdio: ['pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
        encoding: 'utf8'
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 37, result.stderr);
      assert.equal(result.output[3], 'report\n');
      assert.equal(result.output[4], 'extra-fd\n');
      assert.match(result.stdout, /argument with spaces\n\n/);
    }

    fs.writeFileSync(manifest, JSON.stringify({ version: '0.0.0' }));
    const mismatch = spawnSync(path.join(bin, 'fstrace'), [], { encoding: 'utf8' });
    assert.equal(mismatch.status, 1);
    assert.match(mismatch.stderr, /does not match/);

    fs.rmSync(path.join(platform, 'bin/fstrace'));
    fs.writeFileSync(manifest, JSON.stringify({ version }));
    const missingBinary = spawnSync(path.join(bin, 'fstrace'), [], { encoding: 'utf8' });
    assert.equal(missingBinary.status, 1);
    assert.match(missingBinary.stderr, /cannot execute/);

    fs.rmSync(platform, { recursive: true });
    const missingPackage = spawnSync(path.join(bin, 'fstrace'), [], { encoding: 'utf8' });
    assert.equal(missingPackage.status, 1);
    assert.match(missingPackage.stderr, /optional dependencies enabled/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
