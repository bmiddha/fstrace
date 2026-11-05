'use strict';

const fs = require('node:fs');
const path = require('node:path');
const manifest = require('./package.json');

function resolveBinary(name, platform = process.platform, arch = process.arch) {
  if (!['fstrace', 'fstrace-daemon'].includes(name)) {
    throw new Error(`unknown executable ${JSON.stringify(name)}`);
  }
  if (platform !== 'linux' || !['x64', 'arm64'].includes(arch)) {
    throw new Error(`unsupported platform ${platform}/${arch}; expected Linux x64 or ARM64`);
  }
  const packageName = `@fstrace/linux-${arch}`;
  let packagePath;
  try {
    packagePath = require.resolve(`${packageName}/package.json`);
  } catch (error) {
    if (error.code !== 'MODULE_NOT_FOUND') throw error;
    throw new Error(
      `${packageName}@${manifest.version} is missing. Reinstall @fstrace/fstrace ` +
      'with optional dependencies enabled (do not use --omit=optional).'
    );
  }
  const installed = require(packagePath);
  if (installed.version !== manifest.version) {
    throw new Error(
      `${packageName} version ${installed.version} does not match @fstrace/fstrace ` +
      `${manifest.version}; reinstall the matching packages.`
    );
  }
  const binary = path.join(path.dirname(packagePath), 'bin', name);
  try {
    fs.accessSync(binary, fs.constants.X_OK);
  } catch (error) {
    throw new Error(`cannot execute ${binary}: ${error.message}`);
  }
  return binary;
}

if (require.main === module) {
  try {
    process.stdout.write(resolveBinary(process.argv[2]) + '\n');
  } catch (error) {
    console.error(`fstrace: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { resolveBinary };
