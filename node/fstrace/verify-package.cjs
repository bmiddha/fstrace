const { readFileSync, statSync } = require('node:fs');
const { join } = require('node:path');

for (const [arch, machine] of [['x64', 62], ['arm64', 183]]) {
  for (const binary of ['fstrace', 'fstrace-debug']) {
    const path = join(__dirname, 'bin', arch, binary);
    const data = readFileSync(path);
    if (data.length < 20 ||
        data.subarray(0, 4).toString('hex') !== '7f454c46' ||
        data[4] !== 2 || data[5] !== 1 || data.readUInt16LE(18) !== machine) {
      throw new Error(`${path} must be a 64-bit Linux ${arch} ELF binary`);
    }
    if ((statSync(path).mode & 0o111) === 0) {
      throw new Error(`${path} must be executable`);
    }
  }
}
