#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const AVAILABLE_COMBINATIONS = new Map([
  ['darwin:arm64', { triple: 'darwin-arm64', filename: 'leash' }],
  ['darwin:x64', { triple: 'darwin-amd64', filename: 'leash' }],
  ['linux:arm64', { triple: 'linux-arm64', filename: 'leash' }],
  ['linux:x64', { triple: 'linux-amd64', filename: 'leash' }]
]);

const WINDOWS_COMBINATIONS = new Map([
  ['win32:arm64', { triple: 'windows-arm64', filename: 'leash.exe' }],
  ['win32:x64', { triple: 'windows-amd64', filename: 'leash.exe' }]
]);

function main() {
  const platform = process.env.LEASH_NPM_FORCE_PLATFORM || process.platform;
  const arch = process.env.LEASH_NPM_FORCE_ARCH || process.arch;
  const key = `${platform}:${arch}`;
  const tripleConfig = AVAILABLE_COMBINATIONS.get(key);

  if (!tripleConfig) {
    if (WINDOWS_COMBINATIONS.has(key)) {
      const windowsTriple = WINDOWS_COMBINATIONS.get(key);
      console.error(
        `Windows support (${windowsTriple.triple}) is not yet available in the npm package. ` +
          'Please download the latest Windows binary from https://github.com/strongdm/leash/releases.'
      );
      process.exitCode = 1;
      return;
    }

    const supported = Array.from(AVAILABLE_COMBINATIONS.keys())
      .map((entry) => entry.replace(':', '/'));
    const message = [
      `Unsupported platform/architecture: ${platform}/${arch}.`,
      `Supported combinations: ${supported.join(', ')}`,
      `If you require leash on this platform, download the binary release from https://github.com/strongdm/leash/releases or build from source.`
    ].join(' ');
    console.error(message);
    process.exitCode = 1;
    return;
  }

  const overrideRoot = process.env.LEASH_NPM_PACKAGE_ROOT;
  const packageRoot = overrideRoot
    ? path.resolve(overrideRoot)
    : path.resolve(__dirname, '..');
  const vendorPath = path.join(packageRoot, 'vendor', tripleConfig.triple, tripleConfig.filename);

  try {
    fs.accessSync(vendorPath, fs.constants.X_OK);
  } catch (err) {
    console.error(
      `Unable to locate executable for ${platform}/${arch} at ${vendorPath}. ` +
        'Ensure the package was built with the expected vendor assets.'
    );
    process.exitCode = 1;
    return;
  }

  const child = spawn(vendorPath, process.argv.slice(2), {
    stdio: 'inherit',
    env: process.env
  });

  const shutdown = (signal) => {
    if (!child.killed) {
      child.kill(signal);
    }
  };

  ['SIGINT', 'SIGTERM', 'SIGQUIT'].forEach((signal) => {
    process.on(signal, () => shutdown(signal));
  });

  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code);
  });

  child.on('error', (err) => {
    console.error(`Failed to launch leash binary: ${err.message}`);
    process.exitCode = 1;
  });
}

main();
