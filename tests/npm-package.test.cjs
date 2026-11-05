const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { chmodSync, copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { test } = require('node:test');

const packageDir = resolve(__dirname, '../node/fstrace');

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'fstrace-package-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function executable(path, source) {
  writeFileSync(path, source, { mode: 0o755 });
}

for (const [machine, arch] of [['x86_64', 'x64'], ['aarch64', 'arm64'], ['arm64', 'arm64']]) {
  for (const binary of ['fstrace', 'fstrace-debug']) {
    test(`launcher selects ${binary} on ${machine} and preserves arguments, environment, fd3 and exit status`, (t) => {
      const dir = fixture(t);
      mkdirSync(join(dir, 'bin', arch), { recursive: true });
      mkdirSync(join(dir, 'commands'));
      copyFileSync(join(packageDir, binary), join(dir, binary));
      chmodSync(join(dir, binary), 0o755);
      executable(join(dir, 'commands/uname'), `#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo ${machine};; esac\n`);
      executable(join(dir, 'bin', arch, binary),
        `#!/bin/sh\nprintf '%s\\n' '${arch}/${binary}' "$@" "$FSTRACE_TEST"\nprintf report >&3\nexit 37\n`);
      symlinkSync(join(dir, binary), join(dir, 'commands', binary));
      symlinkSync(join(dir, binary), join(dir, 'commands', 'alias'));
      for (const command of [join(dir, binary), join(dir, 'commands', binary), join(dir, 'commands', 'alias')]) {
        const result = spawnSync(command, ['argument with spaces', '*'], {
          encoding: 'utf8',
          env: { ...process.env, PATH: `${join(dir, 'commands')}:${process.env.PATH}`, FSTRACE_TEST: 'environment' },
          stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
        });
        assert.equal(result.status, 37, result.stderr);
        assert.equal(result.stdout, `${arch}/${binary}\nargument with spaces\n*\nenvironment\n`);
        assert.equal(result.output[3], 'report');
      }
    });
  }
}

test('launcher rejects unsupported platforms', (t) => {
  const dir = fixture(t);
  executable(join(dir, 'uname'), '#!/bin/sh\necho Darwin\n');
  const result = spawnSync('sh', [join(packageDir, 'fstrace')], {
    encoding: 'utf8',
    env: { ...process.env, PATH: `${dir}:${process.env.PATH}` },
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /requires Linux on x64 or ARM64/);
});

test('prepack requires executable ELF binaries for both architectures and configurations', (t) => {
  const dir = fixture(t);
  copyFileSync(join(packageDir, 'verify-package.cjs'), join(dir, 'verify-package.cjs'));
  const run = () => spawnSync(process.execPath, [join(dir, 'verify-package.cjs')], { encoding: 'utf8' });
  assert.notEqual(run().status, 0);

  for (const [arch, machine] of [['x64', 62], ['arm64', 183]]) {
    mkdirSync(join(dir, 'bin', arch), { recursive: true });
    for (const binary of ['fstrace', 'fstrace-debug']) {
      const data = Buffer.alloc(64);
      data.writeUInt32BE(0x7f454c46);
      data[4] = 2;
      data[5] = 1;
      data.writeUInt16LE(machine, 18);
      writeFileSync(join(dir, 'bin', arch, binary), data, { mode: 0o755 });
    }
  }
  assert.equal(run().status, 0);

  const armDebug = join(dir, 'bin/arm64/fstrace-debug');
  chmodSync(armDebug, 0o644);
  assert.match(run().stderr, /must be executable/);
  chmodSync(armDebug, 0o755);
  copyFileSync(join(dir, 'bin/x64/fstrace'), armDebug);
  assert.match(run().stderr, /must be a 64-bit Linux arm64 ELF binary/);
});
