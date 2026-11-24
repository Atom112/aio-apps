#!/usr/bin/env node
// Micro-app bundle gate: structural checks plus the style contract.
//
// Runs in the AIO repo over the bundled examples (`npm run check:apps`) and is the same
// script the catalog CI will run over submitted bundles. It fails the build on:
//   - manifest problems (id/version/entry/icon/screenshots, unknown capabilities),
//   - disallowed files, executables, oversize bundles or too many files,
//   - style drift: colour literals outside the `--aio-*` tokens and custom font stacks.
//
// Usage: node scripts/check-app-bundle.mjs [dir ...]   (default: examples/apps)
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const ALLOWED_EXTENSIONS = new Set([
  'html',
  'htm',
  'css',
  'js',
  'mjs',
  'json',
  'txt',
  'md',
  'svg',
  'png',
  'jpg',
  'jpeg',
  'webp',
  'gif',
  'woff',
  'woff2',
  'ttf',
  'otf',
]);
const IMAGE_EXTENSIONS = new Set(['png', 'svg', 'webp', 'jpg', 'jpeg']);
const KNOWN_CAPABILITIES = new Set([
  'ai.chat',
  'ai.embed',
  'ai.image',
  'storage.kv',
  'storage.file',
  'vector.self',
  'net.fetch',
  'import.file',
  'export.file',
  'ui.notify',
  'ui.openLink',
  'ui.theme',
]);
const MAX_BUNDLE_BYTES = 20 * 1024 * 1024;
const MAX_BUNDLE_FILES = 400;
const MAX_MANIFEST_BYTES = 64 * 1024;
/** Font stacks an app may declare; anything else is a style-contract violation. */
const ALLOWED_FONT_TOKENS = [
  'ui-sans-serif',
  'system-ui',
  'ui-monospace',
  'ui-serif',
  'sans-serif',
  'serif',
  'monospace',
  '-apple-system',
  'blinkmacsystemfont',
  'segoe ui',
  'sf mono',
  'jetbrains mono',
  'fira code',
  'noto sans sc',
  'noto sans',
  'helvetica',
  'arial',
  'pingfang sc',
  'microsoft yahei',
  'inherit',
];

const roots = process.argv.slice(2).length > 0 ? process.argv.slice(2) : ['examples/apps'];
const problems = [];
const seen = new Map();

function fail(file, message) {
  problems.push(`${relative(process.cwd(), file) || file}: ${message}`);
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isSymbolicLink()) {
      fail(path, 'symlink in a bundle');
      continue;
    }
    if (entry.isDirectory()) walk(path, out);
    else out.push(path);
  }
  return out;
}

function checkManifest(bundleDir, manifest) {
  const id = manifest.id;
  if (typeof id !== 'string' || !/^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$/.test(id)) {
    fail(bundleDir, `invalid app id: ${String(id)}`);
    return;
  }
  if (seen.has(id)) fail(bundleDir, `duplicate app id ${id} (also ${seen.get(id)})`);
  else seen.set(id, bundleDir);
  if (typeof manifest.version !== 'string' || !/^\d+\.\d+\.\d+([-+].*)?$/.test(manifest.version)) {
    fail(bundleDir, `invalid version: ${String(manifest.version)}`);
  }
  if (!manifest.entry || !/\.html$/.test(manifest.entry)) {
    fail(bundleDir, `entry must be a relative .html path: ${String(manifest.entry)}`);
  }
  if (!manifest.name || Object.keys(manifest.name).length === 0) {
    fail(bundleDir, 'name needs at least one locale key');
  }
  if (!manifest.ui || !['panel', 'canvas', 'inline'].includes(manifest.ui.mode)) {
    fail(bundleDir, 'ui.mode must be panel | canvas | inline');
  }
  const caps = manifest.capabilities ?? [];
  if (!Array.isArray(caps)) fail(bundleDir, 'capabilities must be an array');
  else {
    for (const capability of caps) {
      if (!KNOWN_CAPABILITIES.has(capability)) fail(bundleDir, `unknown capability: ${capability}`);
    }
    if (new Set(caps).size !== caps.length) fail(bundleDir, 'duplicate capabilities');
  }
  if (Array.isArray(manifest.network?.allow) && manifest.network.allow.length > 0) {
    fail(bundleDir, 'v1 does not accept network declarations (net.fetch is not implemented)');
  }
  if (manifest.description && Object.keys(manifest.description).length > 6) {
    fail(bundleDir, 'too many description locales (max 6)');
  }
  for (const shot of manifest.screenshots ?? []) {
    const ext = String(shot).split('.').pop()?.toLowerCase();
    if (!IMAGE_EXTENSIONS.has(ext ?? '')) fail(bundleDir, `screenshot must be an image: ${shot}`);
  }
  if (manifest.homepage) {
    try {
      const parsed = new URL(manifest.homepage);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        fail(bundleDir, `homepage must be http(s): ${manifest.homepage}`);
      }
    } catch {
      fail(bundleDir, `homepage is not a URL: ${manifest.homepage}`);
    }
  }
}

/** Colour literals are only allowed when they are `rgba(var(--aio-…))` token reads. */
function checkStyle(file, text) {
  const stripped = text
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/rgba?\(\s*var\(--aio-[^)]*\)[^)]*\)/gi, ' ')
    .replace(/var\(--aio-[^)]*\)/gi, ' ');
  const hex = stripped.match(/#[0-9a-f]{3,8}\b/gi) ?? [];
  const rgb = stripped.match(/\brgba?\(\s*\d/gi) ?? [];
  const hsl = stripped.match(/\bhsla?\(/gi) ?? [];
  for (const match of [...hex, ...rgb, ...hsl]) {
    fail(file, `colour literal "${match}" — use the --aio-* tokens`);
  }
  const fonts = text.match(/font-family\s*:\s*([^;}]+)/gi) ?? [];
  for (const declaration of fonts) {
    const value = declaration.split(':').slice(1).join(':').toLowerCase();
    const tokens = value
      .split(',')
      .map((part) => part.trim().replace(/^["']|["']$/g, ''))
      .filter(Boolean);
    const offending = tokens.filter((token) => !ALLOWED_FONT_TOKENS.includes(token));
    if (offending.length > 0) {
      fail(file, `custom font stack (${offending.join(', ')}) — use the host stack`);
    }
  }
}

/**
 * Collects bundle directories under `dir`: a directory with `aio.app.json` is a bundle,
 * otherwise its subdirectories are searched (catalog layout is `apps/<publisher>/<app>/`).
 * Depth is capped so a pathological tree cannot stall CI.
 */
function collectBundles(dir, out = [], depth = 0) {
  if (existsSync(join(dir, 'aio.app.json'))) {
    out.push(dir);
    return out;
  }
  if (depth >= 4) return out;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    collectBundles(join(dir, entry.name), out, depth + 1);
  }
  return out;
}

let appCount = 0;
for (const root of roots) {
  const rootDir = resolve(root);
  let bundleDirs;
  try {
    bundleDirs = collectBundles(rootDir);
    if (bundleDirs.length === 0) fail(rootDir, 'no bundle (aio.app.json) found below this path');
  } catch {
    fail(rootDir, 'directory not found');
    continue;
  }
  for (const bundleDir of bundleDirs) {
    const manifestPath = join(bundleDir, 'aio.app.json');
    let manifest;
    try {
      const raw = readFileSync(manifestPath);
      if (raw.byteLength > MAX_MANIFEST_BYTES) fail(manifestPath, 'manifest is too large');
      manifest = JSON.parse(raw.toString('utf8'));
    } catch {
      fail(manifestPath, 'missing or unparseable aio.app.json');
      continue;
    }
    checkManifest(bundleDir, manifest);

    const files = walk(bundleDir);
    if (files.length > MAX_BUNDLE_FILES) fail(bundleDir, `too many files (${files.length})`);
    let total = 0;
    for (const file of files) {
      const ext = file.split('.').pop()?.toLowerCase() ?? '';
      if (!ALLOWED_EXTENSIONS.has(ext)) fail(file, `disallowed file type .${ext}`);
      total += statSync(file).size;
      if (['html', 'htm', 'css', 'js', 'mjs'].includes(ext)) {
        checkStyle(file, readFileSync(file, 'utf8'));
      }
    }
    if (total > MAX_BUNDLE_BYTES) fail(bundleDir, `bundle too large (${total} bytes)`);
    if (
      manifest.entry &&
      !files.some((file) => relative(bundleDir, file).replace(/\\/g, '/') === manifest.entry)
    ) {
      fail(bundleDir, `entry file is missing: ${manifest.entry}`);
    }
    if (
      manifest.icon &&
      !files.some((file) => relative(bundleDir, file).replace(/\\/g, '/') === manifest.icon)
    ) {
      fail(bundleDir, `icon file is missing: ${manifest.icon}`);
    }
    for (const shot of manifest.screenshots ?? []) {
      if (!files.some((file) => relative(bundleDir, file).replace(/\\/g, '/') === shot)) {
        fail(bundleDir, `screenshot is missing: ${shot}`);
      }
    }
    appCount += 1;
  }
}

if (problems.length > 0) {
  process.stderr.write(`micro-app bundle gate failed (${problems.length}):\n`);
  for (const problem of problems) process.stderr.write(`  ${problem}\n`);
  process.exit(1);
}
process.stdout.write(`micro-app bundle gate passed (${appCount} app(s), ${roots.join(', ')})\n`);
