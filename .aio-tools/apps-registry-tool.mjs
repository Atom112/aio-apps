#!/usr/bin/env node
// Micro-app registry tool: build, sign, verify, revoke and pack bundles.
//
// The registry format is deliberately dumb (see `docs/en/development/micro-apps.md`):
// `{ schema, payload, signature }` where `payload` is base64 of the canonical JSON
// `{ updatedAt, apps[], revoked[] }` and `signature` is ed25519 over the decoded payload
// bytes. Signing the bytes avoids JSON canonicalization entirely, so the Rust verifier and
// this tool only have to agree on ordering (construction order is stable on both sides).
//
// Commands:
//   keygen  --out-dir DIR                        generate publisher.key + publisher.pub
//   pack    --app DIR --out FILE                  zip one bundle (store/deflate)
//   build   --apps DIR [--artifacts DIR] [--key FILE] [--out FILE] [--revocations FILE]
//                                                 validate, pack and index every bundle
//   sign    --in FILE --key FILE [--out FILE]     sign an unsigned registry
//   verify  --in FILE --pubkey B64               verify signature + payload shape
//   revoke  --revocations FILE --id ID (--version V | --digest D) [--reason TEXT]
//           (no FILE: append to ./revocations.json; legacy --in patches an envelope in place)
//
// `--apps DIR` expects `<DIR>/<publisher>/<app>/aio.app.json`, the catalog layout.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateRawSync } from 'node:zlib';

/** SPKI prefix for a raw 32-byte ed25519 public key. */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith('--')) args[token.slice(2)] = argv[i + 1] ?? true;
    else args._.push(token);
  }
  return args;
}

function die(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

/** Raw 32-byte public key from a base64 string, as the host expects it. */
function publicKeyFromBase64(encoded) {
  const raw = Buffer.from(encoded.trim(), 'base64');
  if (raw.length !== 32) die('public key must be 32 bytes of base64');
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

/** Reads a base64 PKCS#8 private key file. */
function privateKeyFromFile(file) {
  return createPrivateKey({
    key: Buffer.from(readFileSync(file, 'utf8').trim(), 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
}

function payloadBytes(payload) {
  return Buffer.from(JSON.stringify(payload), 'utf8');
}

function encodeEnvelope(payload, signature) {
  return `${JSON.stringify({ schema: 1, payload: payload.toString('base64'), signature }, null, 2)}\n`;
}

function decodeEnvelope(envelope) {
  if (envelope.schema !== 1) die(`unsupported schema: ${envelope.schema}`);
  const payload = Buffer.from(String(envelope.payload), 'base64');
  return { payload, signature: envelope.signature ? String(envelope.signature) : null };
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/** Minimal ZIP writer (deflate) — a catalog artifact must not need a zip dependency. */
function writeZip(files, outFile) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const file of files) {
    const name = Buffer.from(file.name.replace(/\\/g, '/'), 'utf8');
    const raw = file.data;
    const compressed = deflateRawSync(raw, { level: 9 });
    const crc = crc32(raw);
    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(0, 10);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    name.copy(local, 30);
    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(0, 12);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    name.copy(central, 46);
    locals.push(local, compressed);
    centrals.push(central);
    offset += local.length + compressed.length;
  }
  const centralSize = centrals.reduce((sum, entry) => sum + entry.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(centrals.length, 8);
  end.writeUInt16LE(centrals.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  writeFileSync(outFile, Buffer.concat([...locals, ...centrals, end]));
}

function collectBundleFiles(bundleDir) {
  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isSymbolicLink()) die(`symlink in bundle: ${path}`);
      if (entry.isDirectory()) walk(path);
      else
        files.push({
          name: relative(bundleDir, path).replace(/\\/g, '/'),
          data: readFileSync(path),
        });
    }
  };
  walk(bundleDir);
  return files.sort((left, right) => left.name.localeCompare(right.name));
}

function commandKeygen(args) {
  const outDir = resolve(args['out-dir'] ?? 'publisher');
  mkdirSync(outDir, { recursive: true });
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const rawPublic = spki.subarray(spki.length - 32).toString('base64');
  writeFileSync(join(outDir, 'publisher.key'), `${pkcs8}\n`);
  writeFileSync(join(outDir, 'publisher.pub'), `${rawPublic}\n`);
  process.stdout.write(
    `wrote ${join(outDir, 'publisher.key')} (secret) and ${join(outDir, 'publisher.pub')}\n` +
      `public key (paste into AIO → Store → Online catalog): ${rawPublic}\n`,
  );
}

function commandPack(args) {
  const appDir = resolve(args.app ?? die('--app is required'));
  const out = resolve(args.out ?? `${appDir.split(/[\\/]/).pop()}.zip`);
  if (!existsSync(join(appDir, 'aio.app.json'))) die(`${appDir} has no aio.app.json`);
  writeZip(collectBundleFiles(appDir), out);
  process.stdout.write(`${out}\n`);
}

function commandBuild(args) {
  const appsRoot = resolve(args.apps ?? die('--apps is required'));
  const artifacts = resolve(args['artifacts'] ?? join(dirname(appsRoot), 'artifacts'));
  const out = resolve(args.out ?? join(dirname(appsRoot), 'registry.json'));
  const gate = join(dirname(fileURLToPath(import.meta.url)), 'check-app-bundle.mjs');
  const bundles = [];
  for (const publisher of readdirSync(appsRoot, { withFileTypes: true }).filter((e) =>
    e.isDirectory(),
  )) {
    for (const app of readdirSync(join(appsRoot, publisher.name), { withFileTypes: true }).filter(
      (e) => e.isDirectory(),
    )) {
      bundles.push(join(appsRoot, publisher.name, app.name));
    }
  }
  if (bundles.length === 0) die(`no bundles under ${appsRoot}`);
  mkdirSync(artifacts, { recursive: true });

  // Same style/structure gate the host uses; a submission that fails here never gets signed.
  const gateRun = spawnSync(process.execPath, [gate, ...bundles], { stdio: 'inherit' });
  if (gateRun.status !== 0) die('bundle gate failed; nothing was built');

  // Revocations must survive rebuilds, so they live in a reviewed list file instead of
  // being regenerated from nothing. `--revocations` wins; otherwise `revocations.json` next
  // to the apps root is used when present.
  const revocationsFile = args.revocations
    ? resolve(String(args.revocations))
    : join(dirname(appsRoot), 'revocations.json');
  let revoked = [];
  if (existsSync(revocationsFile)) {
    const parsed = JSON.parse(readFileSync(revocationsFile, 'utf8'));
    if (!Array.isArray(parsed)) die(`${revocationsFile} must contain a JSON array`);
    revoked = parsed;
  }

  const apps = [];
  for (const bundle of bundles) {
    const manifest = JSON.parse(readFileSync(join(bundle, 'aio.app.json'), 'utf8'));
    const zipName = `${manifest.id}-${manifest.version}.zip`;
    const zipPath = join(artifacts, zipName);
    writeZip(collectBundleFiles(bundle), zipPath);
    const bytes = readFileSync(zipPath);
    const name = `artifacts/${zipName}`;
    apps.push({
      id: manifest.id,
      version: manifest.version,
      manifest,
      artifact: {
        url: name,
        sha256: createHash('sha256').update(bytes).digest('hex'),
        size: bytes.length,
      },
    });
  }
  const payload = { updatedAt: new Date().toISOString(), apps, revoked };
  const bytes = payloadBytes(payload);
  if (args.key) {
    const signature = sign(null, bytes, privateKeyFromFile(resolve(args.key))).toString('base64');
    writeFileSync(out, encodeEnvelope(bytes, signature));
    process.stdout.write(`${out} (${apps.length} app(s), signed)\n`);
  } else {
    writeFileSync(out, encodeEnvelope(bytes, null));
    process.stdout.write(`${out} (${apps.length} app(s), UNSIGNED — local use only)\n`);
  }
}

function commandSign(args) {
  const input = resolve(args.in ?? die('--in is required'));
  const keyFile = resolve(args.key ?? die('--key is required'));
  const envelope = JSON.parse(readFileSync(input, 'utf8'));
  const { payload } = decodeEnvelope(envelope);
  const signature = sign(null, payload, privateKeyFromFile(keyFile)).toString('base64');
  const out = resolve(args.out ?? input);
  writeFileSync(out, encodeEnvelope(payload, signature));
  process.stdout.write(`${out} (signed)\n`);
}

function commandVerify(args) {
  const input = resolve(args.in ?? die('--in is required'));
  const envelope = JSON.parse(readFileSync(input, 'utf8'));
  const { payload, signature } = decodeEnvelope(envelope);
  if (args.pubkey) {
    if (!signature) die('registry has no signature');
    const ok = verify(
      null,
      payload,
      publicKeyFromBase64(String(args.pubkey)),
      Buffer.from(signature, 'base64'),
    );
    if (!ok) die('signature does not match the public key');
  }
  const parsed = JSON.parse(payload.toString('utf8'));
  if (!Array.isArray(parsed.apps) || !Array.isArray(parsed.revoked))
    die('payload shape is invalid');
  for (const entry of parsed.apps) {
    if (!/^[0-9a-f]{64}$/.test(entry.artifact?.sha256 ?? ''))
      die(`bad artifact hash for ${entry.id}`);
  }
  process.stdout.write(
    `ok: ${parsed.apps.length} app(s), ${parsed.revoked.length} revoked, ${signature ? 'signed' : 'unsigned'}\n`,
  );
}

function commandRevoke(args) {
  const entry = { id: String(args.id ?? die('--id is required')) };
  if (args.version) entry.version = String(args.version);
  if (args.digest) entry.digest = String(args.digest);
  if (!entry.version && !entry.digest) die('revocation needs --version or --digest');
  if (args.reason) entry.reason = String(args.reason);

  // Preferred form: append to the reviewed list file that `build` seeds from.
  const listFile = args.revocations
    ? resolve(String(args.revocations))
    : args.in
      ? null
      : resolve('revocations.json');
  if (listFile) {
    const list = existsSync(listFile) ? JSON.parse(readFileSync(listFile, 'utf8')) : [];
    if (!Array.isArray(list)) die(`${listFile} must contain a JSON array`);
    list.push(entry);
    writeFileSync(listFile, `${JSON.stringify(list, null, 2)}\n`);
    process.stdout.write(
      `${listFile} (revoked ${entry.id}${entry.version ? `@${entry.version}` : ''}; ` +
        'commit it and CI re-signs the registry)\n',
    );
    return;
  }

  // Legacy form: patch an existing registry envelope in place (ad-hoc/local testing).
  const input = resolve(args.in);
  const envelope = JSON.parse(readFileSync(input, 'utf8'));
  const { payload } = decodeEnvelope(envelope);
  const parsed = JSON.parse(payload.toString('utf8'));
  parsed.revoked.push(entry);
  const bytes = payloadBytes(parsed);
  const out = resolve(args.out ?? input);
  const signature = args.key
    ? sign(null, bytes, privateKeyFromFile(resolve(args.key))).toString('base64')
    : null;
  writeFileSync(out, encodeEnvelope(bytes, signature));
  process.stdout.write(`${out} (revoked ${entry.id}${entry.version ? `@${entry.version}` : ''})\n`);
}

const args = parseArgs(process.argv.slice(2));
const command = args._[0];
switch (command) {
  case 'keygen':
    commandKeygen(args);
    break;
  case 'pack':
    commandPack(args);
    break;
  case 'build':
    commandBuild(args);
    break;
  case 'sign':
    commandSign(args);
    break;
  case 'verify':
    commandVerify(args);
    break;
  case 'revoke':
    commandRevoke(args);
    break;
  default:
    die(
      'usage: apps-registry-tool.mjs <keygen|pack|build|sign|verify|revoke> [options]\n' +
        'see docs/en/development/micro-apps.md#publishing',
    );
}
