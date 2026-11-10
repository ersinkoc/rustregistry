import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const read = (file) => readFileSync(resolve(root, file), 'utf8');
const expected = JSON.parse(read('package.json')).version;
if (!/^0\.\d+\.\d+$/.test(expected)) throw new Error('Expected a 0.x.y release version.');
const tag = process.argv[2];
if (tag && tag !== 'v' + expected) throw new Error('Release tag does not match package.json.');
const npmLock = JSON.parse(read('package-lock.json'));
const versions = {
  tauri: JSON.parse(read('src-tauri/tauri.conf.json')).version,
  cargo: read('Cargo.toml').match(/\[workspace\.package\][\s\S]*?version\s*=\s*"([^"]+)"/)?.[1],
  npmLock: npmLock.version,
  npmLockRootPackage: npmLock.packages[''].version,
};
for (const name of ['registry-core', 'registry-desktop', 'rustregistry']) {
  versions[`cargoLock:${name}`] = read('Cargo.lock').match(
    new RegExp(`\\[\\[package\\]\\]\\s+name = "${name}"\\s+version = "([^"]+)"`),
  )?.[1];
}
for (const [source, actual] of Object.entries(versions)) {
  if (actual !== expected) throw new Error(`${source}: expected ${expected}, got ${actual}`);
}
if (!read('CHANGELOG.md').includes(`## ${expected} —`)) {
  throw new Error(`Missing changelog entry for ${expected}.`);
}
console.log(`Version ${expected} is consistent across app manifests and lockfiles.`);
