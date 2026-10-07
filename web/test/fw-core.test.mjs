// Tests for the firmware core in utr_ble_client.html.
//
//   node --test web/test/
//
// The core is the block between FW-CORE-BEGIN and FW-CORE-END; it has no DOM,
// so it runs here as it does in the page. The stock-side scripts are run for
// real, under busybox sh (stock's shell) and dash, against a fake router: a
// directory standing in for /proc, /dev and /tmp, and stub fw_printenv,
// fw_setenv, mtd, ubiformat, curl, syswrapper.sh and reboot that act on it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, existsSync, symlinkSync, chmodSync, rmSync } from 'node:fs';
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
function loadCore() {
  const src = process.env.FW_CORE
    ? readFileSync(process.env.FW_CORE, 'utf8')
    : readFileSync(join(here, '..', 'utr_ble_client.html'), 'utf8');
  const m = /\/\/ FW-CORE-BEGIN\n([\s\S]*?)\/\/ FW-CORE-END/.exec(src);
  assert.ok(m, 'FW-CORE markers not found');
  return new Function(`${m[1]}\nreturn FW;`)();
}
const FW = loadCore();

const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const md5 = (b) => createHash('md5').update(b).digest('hex');

// ---------------------------------------------------------------------------
// Fake router

const PEB = 128 * 1024;
const SLOT = 16 * PEB;

function ubiSlot(kind) {
  const img = Buffer.alloc(SLOT, 0xff);
  if (kind === 'erased') return img;
  for (let i = 0; i < SLOT / PEB; i++) img.write('UBI#', i * PEB, 'latin1');
  if (kind === 'formatted') return img;
  // Stock's data was found well into the slot on a real UTR-LR, nothing
  // in its first 40 blocks; 'openwrt-deep' puts OpenWrt's table there too.
  const at = kind === 'openwrt' ? 0 : 12;
  img.write('UBI!', at * PEB + 2048, 'latin1');
  img.write('UBI!', (at + 1) * PEB + 2048, 'latin1');
  img.write(kind.startsWith('openwrt') ? 'vol\0rootfs\0rootfs_data' : 'vol\0', at * PEB + 4096 + 16, 'latin1');
  return img;
}

const SHELLS = [];
if (existsSync('/usr/bin/busybox')) SHELLS.push('busybox');
if (existsSync('/usr/bin/dash')) SHELLS.push('dash');

const STUBS = {
  fw_printenv: `#!/bin/sh
[ "$1" = -n ] && shift
[ -f "$ROOT/env/$1" ] || { echo "## Error: \\"$1\\" not defined" >&2; exit 1; }
cat "$ROOT/env/$1"; echo`,
  fw_setenv: `#!/bin/sh
echo "fw_setenv $*" >> "$ROOT/calls"
[ -f "$ROOT/fail/fw_setenv" ] && exit 1
if [ "$1" = -s ]; then
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    name=\${line%% *}; value=\${line#* }
    printf '%s' "$value" > "$ROOT/env/$name"
  done
elif [ $# = 1 ]; then rm -f "$ROOT/env/$1"
else name=$1; shift; printf '%s' "$*" > "$ROOT/env/$name"; fi`,
  mtd: `#!/bin/sh
echo "mtd $*" >> "$ROOT/calls"
[ -f "$ROOT/fail/mtd" ] && exit 1
[ "$1 $2 $3 $5" = "-e bs write bs" ] || { echo "unexpected mtd $*" >&2; exit 2; }
dd if="$4" of="$ROOT/dev/mtd9" conv=notrunc 2>/dev/null`,
  ubidetach: `#!/bin/sh
echo "ubidetach $*" >> "$ROOT/calls"`,
  ubiformat: `#!/bin/sh
echo "ubiformat $*" >> "$ROOT/calls"
[ -f "$ROOT/fail/ubiformat" ] && exit 1
dev=$1
if [ "$3" = -f ]; then
  dd if=/dev/zero bs=131072 count=16 2>/dev/null | tr '\\000' '\\377' > "$dev"
  dd if="$4" of="$dev" conv=notrunc 2>/dev/null
else
  cp "$ROOT/formatted" "$dev"
fi`,
  curl: `#!/bin/sh
echo "curl $*" >> "$ROOT/calls"
[ -f "$ROOT/fail/curl" ] && exit 7
out=; url=
while [ $# -gt 0 ]; do case $1 in -o) out=$2; shift;; -*) ;; *) url=$1;; esac; shift; done
# No file:// here: a local image must go through cp, never curl.
case $url in
  file://*) echo "curl: (1) Protocol \"file\" not supported or disabled in libcurl" >&2; exit 1 ;;
esac
[ -f "$ROOT/www/\${url##*/}" ] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
cp "$ROOT/www/\${url##*/}" "$out"`,
  'syswrapper.sh': `#!/bin/sh
echo "syswrapper.sh $*" >> "$ROOT/calls"
[ -f "$ROOT/fail/syswrapper" ] && exit 3
exit 0`,
  reboot: `#!/bin/sh
echo reboot >> "$ROOT/calls"`,
  sleep: `#!/bin/sh
exit 0`,
  // Not on stock: a script that reaches for it must fail here too.
  od: `#!/bin/sh
echo "sh: od: not found" >&2
exit 127`,
};

const BB_APPLETS = ['sh', 'dd', 'hexdump', 'tr', 'cut', 'grep', 'printf', 'echo', 'cat', 'rm', 'cp', 'base64',
  'sha256sum', 'md5sum', 'wc', 'df', 'awk', 'tail', 'head', 'setsid', 'mkdir', 'test', '['];

// A stock router in a directory. `opts` picks what is installed where.
function fakeStock(shellName, opts = {}) {
  const o = { running: 0, k0: 'stock', k1: 'openwrt', bs: '000000002be84da3', chooser: true, sysid: 'ea08', ...opts };
  const root = mkdtempSync(join(tmpdir(), 'fwcore-'));
  for (const d of ['proc/ubnthal', 'dev', 'tmp', 'usr/lib', 'env', 'fail', 'www', 'stubs', 'bb']) mkdirSync(join(root, d), { recursive: true });
  writeFileSync(join(root, 'proc/cmdline'), `ubootver=lcm-utr.204 ubntbootid=${o.running} ubi.mtd=kernel${o.running}\n`);
  writeFileSync(join(root, 'proc/mtd'), 'dev:    size   erasesize  name\nmtd9: 00010000 00010000 "bs"\n' +
    `mtd12: ${SLOT.toString(16).padStart(8, '0')} 00020000 "kernel0"\nmtd13: ${SLOT.toString(16).padStart(8, '0')} 00020000 "kernel1"\n`);
  writeFileSync(join(root, 'proc/ubnthal/system.info'), `cpu=IPQ40xx\nsystemid=${o.sysid}\nsubsystemid=0000\n`);
  writeFileSync(join(root, 'usr/lib/version'), 'BZ.ipq40xx.v6.6.117.15538.260823.2116\n');
  const bs = Buffer.alloc(0x10000, 0xff);
  Buffer.from(o.bs, 'hex').copy(bs);
  writeFileSync(join(root, 'dev/mtd9'), bs);
  writeFileSync(join(root, 'dev/mtd12'), ubiSlot(o.k0));
  writeFileSync(join(root, 'dev/mtd13'), ubiSlot(o.k1));
  writeFileSync(join(root, 'formatted'), ubiSlot('formatted'));
  if (o.chooser) {
    writeFileSync(join(root, 'env/bootcmd_real'), FW.BOOTCMD_REAL);
    writeFileSync(join(root, 'env/bootopenwrt'), FW.BOOTOPENWRT);
  } else {
    writeFileSync(join(root, 'env/bootcmd_real'), 'bootubnt');
  }
  writeFileSync(join(root, 'calls'), '');
  for (const [name, body] of Object.entries(STUBS)) {
    writeFileSync(join(root, 'stubs', name), body + '\n');
    chmodSync(join(root, 'stubs', name), 0o755);
  }
  let PATH;
  if (shellName === 'busybox') {
    for (const a of BB_APPLETS) if (!existsSync(join(root, 'stubs', a))) symlinkSync('/usr/bin/busybox', join(root, 'bb', a));
    PATH = `${join(root, 'stubs')}:${join(root, 'bb')}`;
  } else {
    PATH = `${join(root, 'stubs')}:/usr/bin:/bin`;
  }
  // One pass, so a path already moved into the root (which itself lives
  // under /tmp) is not moved again.
  const rewrite = (text) => text.replace(
    /\/proc\/|\/dev\/(?!null|zero)|\/tmp\/|\/tmp(?=[ |;)]|$)|\/usr\/lib\/version/gm,
    (p) => root + p);
  const runSh = (cmd) => {
    const argv = shellName === 'busybox' ? ['sh', '-c', cmd] : ['-c', cmd];
    const r = spawnSync(shellName === 'busybox' ? '/usr/bin/busybox' : '/usr/bin/dash', argv,
      { env: { PATH, ROOT: root }, encoding: 'latin1', timeout: 30000 });
    return (r.stdout || '') + (r.stderr || '');
  };
  // The session's shell: paths rewritten into the fake root, and a script
  // started in the background run to completion instead, so a test can look
  // at what it did.
  const shell = async (cmd) => {
    let c = cmd;
    const run = /sh (\/tmp\/\S+\.sh) /.exec(c);
    if (run) {
      const p = rewrite(run[1]);
      writeFileSync(p, rewrite(readFileSync(p, 'utf8')));
      c = c.replace(' &)', ')');
    }
    shellLog.push(cmd);
    return runSh(rewrite(c));
  };
  const shellLog = [];
  const read = (p) => readFileSync(join(root, p));
  const calls = () => readFileSync(join(root, 'calls'), 'utf8').split('\n').filter(Boolean);
  const fail = (what) => writeFileSync(join(root, 'fail', what), '');
  const serve = (name, data) => writeFileSync(join(root, 'www', name), data);
  const env = (name) => existsSync(join(root, 'env', name)) ? readFileSync(join(root, 'env', name), 'utf8') : null;
  const cleanup = () => rmSync(root, { recursive: true, force: true });
  return { root, shell, shellLog, read, calls, fail, serve, env, cleanup, selector: () => read('dev/mtd9').subarray(0, 8).toString('hex') };
}

async function runScript(r, st, name, text) {
  const path = `/tmp/utr-${name}.sh`;
  const log = `/tmp/utr-${name}.log`;
  await FW.stageScript(r.shell, path, text);
  await FW.startScript(r.shell, st, path, log);
  return FW.pollScript(r.shell, log, '/tmp/none');
}

// ---------------------------------------------------------------------------
// Pure pieces

test('command lines fit a Web Bluetooth write', () => {
  for (const cmd of [FW.STOCK_INFO_CMD, FW.STOCK_INFO_CMD2]) {
    assert.ok(cmd.length <= FW.MAX_CMD, `${cmd.length} chars: ${cmd}`);
  }
  const chunk = 'A'.repeat(FW.CHUNK);
  assert.ok(`printf %s '${chunk}' >> /tmp/utr-install-openwrt.sh.b64`.length <= FW.MAX_CMD);
  assert.ok(`utr-fw restore-put 4194303 ${chunk}`.length <= FW.MAX_CMD);
  const url = 'https://github.com/divinehawk/openwrt/releases/download/build-123/openwrt-ipq40xx-generic-ubnt_utr-lr-squashfs-sysupgrade.bin';
  assert.ok(`utr-fw fetch ${url} ${'0'.repeat(64)}`.length <= FW.MAX_CMD);
});

test('URLs that would need quoting are refused', () => {
  assert.ok(FW.isSafeUrl('https://fw-download.ubnt.com/data/unifi-firmware/16e2-UTREA08-6.6.117-66294cc9.bin'));
  assert.ok(FW.isSafeUrl('https://objects.example/a?b=1&c=%20'));
  for (const bad of ["https://x/a'b", 'https://x/a b', 'https://x/$(id)', 'https://x/`id`', 'https://x/a|b', 'https://x/a>b', 'ftp://x/a', 'https://x/a;reboot', '']) {
    assert.equal(FW.isSafeUrl(bad), false, bad);
  }
});

test('local images are /tmp files with plain names only', () => {
  assert.ok(FW.isLocalImage('file:///tmp/openwrt-ipq40xx-generic-ubnt_utr-lr-squashfs-factory.ubi'));
  for (const bad of ['file:///etc/passwd', 'file:///tmp/../etc/x', 'file:///tmp/a/b', "file:///tmp/a'b", 'file:///tmp/.hidden',
    'file:///tmp/a b', 'file://tmp/x', 'file:///tmp/', '']) {
    assert.equal(FW.isLocalImage(bad), false, bad);
  }
  assert.doesNotThrow(() => FW.installOpenWrtScript({ url: 'file:///tmp/f.ubi', sha256: 'a'.repeat(64) }));
  assert.throws(() => FW.installOpenWrtScript({ url: 'file:///etc/shadow', sha256: 'a'.repeat(64) }));
  assert.doesNotThrow(() => FW.upgradeStockScript({ url: 'file:///tmp/f.bin', sha256: 'a'.repeat(64) }));
  assert.throws(() => FW.upgradeStockScript({ url: 'file:///etc/f.bin', sha256: 'a'.repeat(64) }));
});

test('selectors are classified by their first byte and the vendor tail', () => {
  assert.equal(FW.classifySelector('ffffffff2be84da3'), 'openwrt');
  assert.equal(FW.classifySelector('000000002be84da3'), 'stock');
  assert.equal(FW.classifySelector('ffffffff01020304'), 'unknown');
  // Stock's own record, as read on a UTR-LR running stock from kernel1.
  assert.equal(FW.classifySelector('010050e32be84da3'), 'stock');
  assert.equal(FW.classifySelector(''), 'unknown');
});

const openwrtInfo = (over = {}) => FW.normalizeOpenWrt({
  ok: true, api: 1, os: 'openwrt', board: 'ubnt,utr-lr', profile: 'ubnt_utr-lr', sysid: 'ea08', stock_platform: 'UTREA08',
  running_slot: 1, selector: 'openwrt', chooser: true, job: { state: 'idle' },
  slots: { kernel0: { mtd: 'mtd12', ubi: true, volumes: ['kernel'] }, kernel1: { mtd: 'mtd13', ubi: true, volumes: ['rootfs', 'rootfs_data', 'vol'] } },
  ...over,
});

test('OpenWrt actions', () => {
  let a = FW.actions(openwrtInfo());
  assert.equal(a.switchToStock.enabled, true);
  assert.equal(a.upgradeOpenWrt.enabled, true);
  a = FW.actions(openwrtInfo({ slots: { kernel0: { ubi: true, volumes: [] }, kernel1: { ubi: true, volumes: ['rootfs_data'] } } }));
  assert.equal(a.switchToStock.enabled, false, 'an erased kernel0 is no stock firmware');
  a = FW.actions(openwrtInfo({ chooser: false }));
  assert.match(a.switchToStock.reason, /chooser/);
  a = FW.actions(openwrtInfo({ running_slot: 0 }));
  assert.equal(a.switchToStock.enabled, false);
  a = FW.actions(openwrtInfo({ job: { state: 'installing' } }));
  assert.equal(a.upgradeOpenWrt.enabled, false);
  assert.equal(a.switchToStock.enabled, false);
  assert.equal(a.restore.enabled, false);
  a = FW.actions({ os: 'openwrt', legacy: true });
  assert.ok(Object.values(a).every(x => !x.enabled));
});

test('round trip steps follow the router and what the browser saw', () => {
  const stock = (running, chooser = false) => ({ os: 'stock', running_slot: running, chooser });
  assert.equal(FW.roundTripStep(openwrtInfo()), 'backup');
  assert.equal(FW.roundTripStep(openwrtInfo(), { haveBackup: true }), 'toStock');
  assert.equal(FW.roundTripStep(stock(0, true)), 'remove');
  assert.equal(FW.roundTripStep(stock(0)), 'stock1');
  assert.equal(FW.roundTripStep(stock(1)), 'stock2');
  assert.equal(FW.roundTripStep(stock(0), { seenK1: true }), 'install');
  assert.equal(FW.roundTripStep(openwrtInfo(), { started: true, haveBackup: true }), 'restore');
});

// ---------------------------------------------------------------------------
// Catalogues

test('stock versions are sorted newest first and bad entries dropped', async () => {
  const fw = (v, extra = {}) => {
    const [maj, min, pat, build] = v.split(/[.+]/).map(Number);
    return { version: `v${v}`, channel: 'release', md5: 'a'.repeat(32), sha256_checksum: 'b'.repeat(64), file_size: 1,
      version_major: maj, version_minor: min, version_patch: pat, version_build: build,
      _links: { data: { href: `https://fw-download.ubnt.com/data/unifi-firmware/${v}.bin` } }, ...extra };
  };
  let asked = '';
  const list = await FW.stockVersions(async (url) => {
    asked = url;
    return { _embedded: { firmware: [fw('6.6.115+15476'), fw('6.6.117+15538'), fw('6.5.250+15313'), fw('6.6.118+1', { md5: 'nope' })] } };
  }, 'UTREA08');
  assert.match(asked, /platform~~UTREA08/);
  assert.deepEqual(list.map(f => f.version), ['6.6.117+15538', '6.6.115+15476', '6.5.250+15313']);
});

test('release images match the profile exactly', async () => {
  const asset = (name, digest = 'sha256:' + 'c'.repeat(64)) => ({ name, size: 10, digest, browser_download_url: `https://github.com/o/r/releases/download/b1/${name}` });
  const rels = [{ tag_name: 'build-2', published_at: '2026-10-05T00:00:00Z', assets: [
    asset('openwrt-ipq40xx-generic-ubnt_utr-lr-squashfs-sysupgrade.bin'),
    asset('openwrt-ipq40xx-generic-ubnt_utr-squashfs-sysupgrade.bin', 'sha256:' + 'd'.repeat(64)),
    asset('openwrt-ipq40xx-generic-ubnt_utr-squashfs-factory.ubi'),
  ] }, { tag_name: 'build-1', assets: [asset('openwrt-ipq40xx-generic-ubnt_utr-squashfs-sysupgrade.bin', '')] }];
  const utr = await FW.githubImages(async () => rels, 'divinehawk/openwrt', 'ubnt_utr', 'sysupgrade');
  assert.equal(utr.length, 1, 'no digest, no offer');
  assert.equal(utr[0].sha256, 'd'.repeat(64));
  const lr = await FW.githubImages(async () => rels, 'divinehawk/openwrt', 'ubnt_utr-lr', 'factory');
  assert.equal(lr.length, 0);
  await assert.rejects(FW.githubImages(async () => rels, 'not a repo', 'ubnt_utr', 'factory'));
});

test('snapshot images come from profiles.json', async () => {
  const data = { version_code: 'r1-abc', profiles: { ubnt_utr: { images: [
    { type: 'sysupgrade', name: 'openwrt-ipq40xx-generic-ubnt_utr-squashfs-sysupgrade.bin', sha256: 'e'.repeat(64) },
    { type: 'factory', name: 'openwrt-ipq40xx-generic-ubnt_utr-squashfs-factory.ubi', sha256: 'f'.repeat(64) },
  ] } } };
  const imgs = await FW.snapshotImages(async () => data, 'ubnt_utr', 'factory');
  assert.equal(imgs[0].url, FW.SNAPSHOT_BASE + 'openwrt-ipq40xx-generic-ubnt_utr-squashfs-factory.ubi');
  assert.equal((await FW.snapshotImages(async () => data, 'ubnt_utr-lr', 'factory')).length, 0);
});

// ---------------------------------------------------------------------------
// OpenWrt side, against a fake utrd

function fakeUtrd({ failPutAt = -1 } = {}) {
  const state = { uploaded: Buffer.alloc(0), meta: null, committed: null, puts: 0 };
  const shell = async (cmd) => {
    const f = cmd.split(' ');
    assert.equal(f[0], 'utr-fw');
    assert.ok(cmd.length <= FW.MAX_CMD, `${cmd.length}-char command`);
    switch (f[1]) {
      case 'info': return JSON.stringify(openwrtInfo());
      case 'restore-begin': state.meta = { size: Number(f[2]), sha: f[3] }; state.uploaded = Buffer.alloc(0); return '{"ok":true}';
      case 'restore-put': {
        state.puts++;
        if (state.puts === failPutAt) throw new Error('BLE receive timeout');
        const off = Number(f[2]); const chunk = Buffer.from(f[3], 'base64');
        if (off === state.uploaded.length) state.uploaded = Buffer.concat([state.uploaded, chunk]);
        else if (off + chunk.length > state.uploaded.length) return JSON.stringify({ ok: false, error: `expected the chunk at offset ${state.uploaded.length}` });
        return JSON.stringify({ ok: true, received: state.uploaded.length });
      }
      case 'restore-commit': state.committed = { args: f.slice(2), ok: sha256(state.uploaded) === state.meta.sha }; return '{"ok":true}';
      case 'backup': {
        const data = Buffer.from('backup-archive-bytes');
        return JSON.stringify({ ok: true, size: data.length, sha256: sha256(data), data: data.toString('base64') });
      }
    }
    return JSON.stringify({ ok: false, error: 'unknown' });
  };
  return { shell, state };
}

test('detect recognises utrd and an older utrd', async () => {
  const st = await FW.detect(fakeUtrd().shell);
  assert.equal(st.os, 'openwrt');
  assert.equal(st.slots.kernel0.firmware, true);
  assert.equal(st.slots.kernel1.openwrt, true);
  const legacy = await FW.detect(async () => '[utrd] received: utr-fw info\n');
  assert.deepEqual(legacy, { os: 'openwrt', legacy: true });
});

test('restore uploads in chunks and resends one whose reply was lost', async () => {
  const u = fakeUtrd({ failPutAt: 3 });
  const data = Uint8Array.from({ length: 2000 }, (_, i) => (i * 7) & 0xff);
  const progress = [];
  await FW.restore(u.shell, data, { reboot: false, onProgress: (n, t) => progress.push([n, t]) });
  assert.deepEqual(Buffer.from(u.state.uploaded), Buffer.from(data));
  assert.equal(u.state.committed.ok, true);
  assert.deepEqual(u.state.committed.args, ['--no-reboot']);
  assert.deepEqual(progress.at(-1), [2000, 2000]);
});

test('a damaged backup is refused', async () => {
  const good = await FW.backup(fakeUtrd().shell);
  assert.equal(Buffer.from(good.data).toString(), 'backup-archive-bytes');
  const bad = async () => JSON.stringify({ ok: true, size: 3, sha256: '0'.repeat(64), data: 'YWJj' });
  await assert.rejects(FW.backup(bad), /damaged/);
});

test('utr-fw errors surface as exceptions', async () => {
  await assert.rejects(FW.utrfw(async () => '{"ok":false,"error":"kernel0 holds no UBI volumes"}', 'boot stock'), /no UBI volumes/);
  await assert.rejects(FW.utrfw(async () => 'sh: utr-fw: not found', 'info'), /unexpected answer/);
  assert.throws(() => FW.openwrtFetch(async () => '', "https://x/a'b", 'a'.repeat(64)), /not allowed/);
});

// ---------------------------------------------------------------------------
// Stock side: real scripts, real shells, fake router

for (const sh of SHELLS) {
  test(`[${sh}] detect reads a stock unit with OpenWrt installed`, async (t) => {
    const r = fakeStock(sh);
    t.after(r.cleanup);
    const st = await FW.detect(r.shell);
    assert.equal(st.os, 'stock');
    assert.equal(st.running_slot, 0);
    assert.equal(st.sysid, 'ea08');
    assert.equal(st.stock_platform, 'UTREA08');
    assert.equal(st.profile, 'ubnt_utr-lr');
    assert.equal(st.selector, 'stock');
    assert.equal(st.selector_hex, '000000002be84da3');
    assert.equal(st.chooser, true);
    assert.equal(st.slots, undefined, 'stock detection reads no firmware slot');
    assert.ok(st.tmp_free > 0);
    for (const tool of ['curl', 'sha256sum', 'ubiformat', 'mtd', 'fw_setenv', 'base64', 'hexdump']) assert.ok(st.tools.includes(tool), tool);
    assert.ok(!st.tools.includes('od'));
    assert.ok(!r.shellLog.some(c => /mtd1[23]|kernel[01]/.test(c)), 'no slot read during detection');
    const a = FW.actions(st);
    assert.equal(a.switchToOpenWrt.enabled, true);
    assert.equal(a.upgradeStock.enabled, false);
    assert.equal(a.installOpenWrt.enabled, true);
    assert.equal(a.removeOpenWrt.enabled, true);
    assert.equal(FW.roundTripStep(st), 'remove');
  });

  test(`[${sh}] without the chooser OpenWrt is not installed`, async (t) => {
    const r = fakeStock(sh, { k1: 'stock', chooser: false });
    t.after(r.cleanup);
    const st = await FW.detect(r.shell);
    const a = FW.actions(st);
    assert.equal(a.switchToOpenWrt.enabled, false);
    assert.equal(a.removeOpenWrt.enabled, false);
    assert.equal(a.upgradeStock.enabled, true);
    assert.equal(FW.roundTripStep(st), 'stock1');
  });

  test(`[${sh}] stock running from kernel1 with its own selector record`, async (t) => {
    const r = fakeStock(sh, { running: 1, k0: 'stock', k1: 'stock', chooser: false, bs: '010050e32be84da3' });
    t.after(r.cleanup);
    const st = await FW.detect(r.shell);
    assert.equal(st.selector, 'stock');
    assert.equal(st.selector_hex, '010050e32be84da3');
    assert.equal(FW.roundTripStep(st), 'stock2');
    const a = FW.actions(st);
    assert.equal(a.upgradeStock.enabled, true);
    assert.equal(a.installOpenWrt.enabled, false);
  });

  test(`[${sh}] switch to OpenWrt writes the selector and reboots`, async (t) => {
    const r = fakeStock(sh);
    t.after(r.cleanup);
    const st = await FW.detect(r.shell);
    const res = await runScript(r, st, 'switch', FW.switchToOpenWrtScript());
    assert.equal(res.failed, '', res.lines.join('\n'));
    assert.equal(res.done, true);
    assert.equal(r.selector(), 'ffffffff2be84da3');
    assert.ok(r.calls().includes('reboot'));
    // The rest of the bs block is left as it was.
    assert.ok(r.read('dev/mtd9').subarray(8).every(b => b === 0xff));
  });

  test(`[${sh}] switch to OpenWrt finds OpenWrt's table deep in kernel1`, async (t) => {
    const r = fakeStock(sh, { k1: 'openwrt-deep', bs: '010050e32be84da3' });
    t.after(r.cleanup);
    const res = await runScript(r, { tools: ['setsid'] }, 'switch', FW.switchToOpenWrtScript());
    assert.equal(res.failed, '', res.lines.join('\n'));
    assert.equal(r.selector(), 'ffffffff2be84da3', 'first four bytes replaced, tail kept');
  });

  test(`[${sh}] switch to OpenWrt refuses unsafe states`, async (t) => {
    for (const [opts, why] of [
      [{ chooser: false }, /chooser/],
      [{ running: 1 }, /not running from kernel0/],
      [{ k1: 'stock' }, /does not hold OpenWrt/],
      [{ k1: 'formatted' }, /does not hold OpenWrt/],
      [{ k1: 'erased' }, /does not hold OpenWrt/],
      [{ bs: '0000000001020304' }, /which this does not write/],
    ]) {
      const r = fakeStock(sh, opts);
      t.after(r.cleanup);
      const before = r.selector();
      const res = await runScript(r, { tools: ['setsid'] }, 'switch', FW.switchToOpenWrtScript());
      assert.match(res.failed, why, JSON.stringify(opts));
      assert.equal(r.selector(), before);
      assert.ok(!r.calls().includes('reboot'));
    }
  });

  const factory = ubiSlot('openwrt').subarray(0, 3 * PEB);

  test(`[${sh}] install OpenWrt flashes kernel1, sets the chooser, then the selector`, async (t) => {
    const r = fakeStock(sh, { k1: 'stock', chooser: false });
    t.after(r.cleanup);
    r.serve('factory.ubi', factory);
    const st = await FW.detect(r.shell);
    assert.equal(FW.actions(st).installOpenWrt.enabled, true);
    const res = await runScript(r, st, 'install', FW.installOpenWrtScript({ url: 'https://example.invalid/factory.ubi', sha256: sha256(factory) }));
    assert.equal(res.failed, '', res.lines.join('\n'));
    assert.equal(res.done, true);
    assert.deepEqual(r.read('dev/mtd13').subarray(0, factory.length), factory);
    assert.equal(r.env('bootcmd_real'), FW.BOOTCMD_REAL);
    assert.equal(r.env('bootopenwrt'), FW.BOOTOPENWRT);
    assert.ok(r.env('bootopenwrt').includes('${fdtcontroladdr}'), 'u-boot variable passed through literally');
    assert.equal(r.selector(), 'ffffffff2be84da3');
    const calls = r.calls();
    assert.ok(calls.findIndex(c => c.startsWith('ubiformat')) < calls.findIndex(c => c.startsWith('mtd')), 'slot written before the selector');
    assert.ok(calls.includes('reboot'));
    const after = await FW.detect(r.shell);
    assert.equal(after.chooser, true);
    assert.equal(FW.actions(after).switchToOpenWrt.enabled, true);
  });

  test(`[${sh}] a missing copied image is reported, not downloaded`, async (t) => {
    const r = fakeStock(sh, { k1: 'stock', chooser: false });
    t.after(r.cleanup);
    const res = await runScript(r, { tools: ['setsid'] }, 'install', FW.installOpenWrtScript({ url: 'file:///tmp/missing.ubi', sha256: 'a'.repeat(64) }));
    assert.match(res.failed, /cannot copy \S*\/tmp\/missing\.ubi/);
    assert.ok(!r.calls().some(c => c.startsWith('curl')), 'a local image never goes through curl');
  });

  test(`[${sh}] install OpenWrt from an image copied onto the router`, async (t) => {
    const r = fakeStock(sh, { k1: 'stock', chooser: false });
    t.after(r.cleanup);
    writeFileSync(join(r.root, 'tmp', 'openwrt-factory.ubi'), factory);
    const st = await FW.detect(r.shell);
    const res = await runScript(r, st, 'install', FW.installOpenWrtScript({ url: 'file:///tmp/openwrt-factory.ubi', sha256: sha256(factory) }));
    assert.equal(res.failed, '', res.lines.join('\n'));
    assert.equal(res.done, true);
    assert.deepEqual(r.read('dev/mtd13').subarray(0, factory.length), factory);
    assert.equal(r.selector(), 'ffffffff2be84da3');
  });

  test(`[${sh}] a failed install leaves stock booting`, async (t) => {
    for (const [setup, sum, why] of [
      [() => {}, '0'.repeat(64), /SHA-256 does not match/],
      [(r) => r.fail('curl'), null, /download failed/],
      [(r) => { rmSync(join(r.root, 'www', 'factory.ubi')); }, null, /download failed: curl: \(22\)/],
      [(r) => r.fail('ubiformat'), null, /could not write kernel1/],
      [(r) => r.fail('fw_setenv'), null, /fw_setenv failed/],
      [(r) => r.fail('mtd'), null, /mtd could not write/],
    ]) {
      const r = fakeStock(sh, { k1: 'stock', chooser: false });
      t.after(r.cleanup);
      r.serve('factory.ubi', factory);
      setup(r);
      const res = await runScript(r, { tools: ['setsid'] }, 'install', FW.installOpenWrtScript({ url: 'https://example.invalid/factory.ubi', sha256: sum || sha256(factory) }));
      assert.match(res.failed, why);
      assert.equal(r.selector(), '000000002be84da3', 'selector untouched');
      assert.ok(!r.calls().includes('reboot'));
    }
    const notUBI = fakeStock(sh, { k1: 'stock', chooser: false });
    t.after(notUBI.cleanup);
    const junk = Buffer.from('this is a sysupgrade.bin, not a factory image');
    notUBI.serve('x.bin', junk);
    const res = await runScript(notUBI, { tools: [] }, 'install', FW.installOpenWrtScript({ url: 'https://example.invalid/x.bin', sha256: sha256(junk) }));
    assert.match(res.failed, /not a UBI image/);
    assert.ok(!notUBI.calls().some(c => c.startsWith('ubiformat')));
    const inK1 = fakeStock(sh, { running: 1, k1: 'stock', chooser: false });
    t.after(inK1.cleanup);
    const res2 = await runScript(inK1, { tools: [] }, 'install', FW.installOpenWrtScript({ url: 'https://example.invalid/factory.ubi', sha256: sha256(factory) }));
    assert.match(res2.failed, /not running from kernel0/);
    assert.ok(!inK1.calls().some(c => c.startsWith('curl')));
  });

  test(`[${sh}] remove OpenWrt erases kernel1 and the chooser`, async (t) => {
    const r = fakeStock(sh);
    t.after(r.cleanup);
    const res = await runScript(r, { tools: ['setsid'] }, 'remove', FW.removeOpenWrtScript());
    assert.equal(res.failed, '', res.lines.join('\n'));
    assert.equal(res.done, true);
    assert.equal(r.env('bootcmd_real'), 'bootubnt');
    assert.equal(r.env('bootopenwrt'), null);
    assert.equal(r.selector(), '000000002be84da3');
    const st = await FW.detect(r.shell);
    assert.equal(st.chooser, false);
    assert.equal(FW.roundTripStep(st), 'stock1');
    assert.equal(FW.actions(st).upgradeStock.enabled, true);
    assert.equal(FW.actions(st).switchToOpenWrt.enabled, false);
  });

  const stockImg = Buffer.from('UBNTBZ.ipq40xx_6.6.118 pretend stock image');

  test(`[${sh}] upgrade stock checks the download and hands it to fwupdate`, async (t) => {
    const r = fakeStock(sh, { k1: 'formatted', chooser: false });
    t.after(r.cleanup);
    r.serve('stock.bin', stockImg);
    const res = await runScript(r, { tools: ['setsid'] }, 'stock', FW.upgradeStockScript({ url: 'https://fw-download.ubnt.com/data/unifi-firmware/stock.bin', sha256: sha256(stockImg) }));
    assert.equal(res.failed, '', res.lines.join('\n'));
    assert.equal(res.done, true);
    const sw = r.calls().find(c => c.startsWith('syswrapper.sh'));
    assert.equal(sw, `syswrapper.sh fwupdate ${r.root}/tmp/utr-stock.bin --md5sum=${md5(stockImg)}`, 'the MD5 is taken on the router');
  });

  test(`[${sh}] upgrade stock from an image copied onto the router`, async (t) => {
    const r = fakeStock(sh, { running: 1, k1: 'stock', chooser: false, bs: '010050e32be84da3' });
    t.after(r.cleanup);
    writeFileSync(join(r.root, 'tmp', 'BZ.ipq40xx_6.6.118.bin'), stockImg);
    const res = await runScript(r, { tools: ['setsid'] }, 'stock', FW.upgradeStockScript({ url: 'file:///tmp/BZ.ipq40xx_6.6.118.bin', sha256: sha256(stockImg) }));
    assert.equal(res.failed, '', res.lines.join('\n'));
    assert.ok(r.calls().some(c => c.startsWith('syswrapper.sh fwupdate')));
  });

  test(`[${sh}] upgrade stock from just a URL, as the app does`, async (t) => {
    const r = fakeStock(sh, { k1: 'formatted', chooser: false });
    t.after(r.cleanup);
    r.serve('stock.bin', stockImg);
    const script = FW.upgradeStockScript({ url: 'https://x/stock.bin' });
    assert.ok(!script.includes('sha256sum'), 'no checksum to compare without one');
    const res = await runScript(r, { tools: ['setsid'] }, 'stock', script);
    assert.equal(res.failed, '', res.lines.join('\n'));
    assert.equal(r.calls().find(c => c.startsWith('syswrapper.sh')), `syswrapper.sh fwupdate ${r.root}/tmp/utr-stock.bin --md5sum=${md5(stockImg)}`);
    assert.throws(() => FW.upgradeStockScript({ url: 'https://x/stock.bin', sha256: 'abc' }), /64 hex digits/);
  });

  test(`[${sh}] upgrade stock refuses something that is not a stock image`, async (t) => {
    const r = fakeStock(sh, { k1: 'formatted', chooser: false });
    t.after(r.cleanup);
    const factoryUbi = ubiSlot('openwrt').subarray(0, PEB);
    r.serve('openwrt.ubi', factoryUbi);
    const res = await runScript(r, { tools: [] }, 'stock', FW.upgradeStockScript({ url: 'https://x/openwrt.ubi', sha256: sha256(factoryUbi) }));
    assert.match(res.failed, /not a stock firmware image/);
    assert.ok(!r.calls().some(c => c.startsWith('syswrapper')));
  });

  test(`[${sh}] upgrade stock refuses while OpenWrt is in kernel1, and on a bad download`, async (t) => {
    const r = fakeStock(sh);
    t.after(r.cleanup);
    r.serve('stock.bin', stockImg);
    let res = await runScript(r, { tools: [] }, 'stock', FW.upgradeStockScript({ url: 'https://x/stock.bin', sha256: sha256(stockImg) }));
    assert.match(res.failed, /OpenWrt is installed in kernel1; remove it first/);
    assert.ok(!r.calls().some(c => c.startsWith('curl')));

    const r2 = fakeStock(sh, { k1: 'formatted', chooser: false });
    t.after(r2.cleanup);
    r2.serve('stock.bin', stockImg);
    res = await runScript(r2, { tools: [] }, 'stock', FW.upgradeStockScript({ url: 'https://x/stock.bin', sha256: '0'.repeat(64) }));
    assert.match(res.failed, /SHA-256 does not match/);
    assert.ok(!r2.calls().some(c => c.startsWith('syswrapper')));

    const r3 = fakeStock(sh, { k1: 'formatted', chooser: false });
    t.after(r3.cleanup);
    r3.serve('stock.bin', stockImg);
    r3.fail('syswrapper');
    res = await runScript(r3, { tools: [] }, 'stock', FW.upgradeStockScript({ url: 'https://x/stock.bin', sha256: sha256(stockImg) }));
    assert.match(res.failed, /fwupdate exited 3/);
    assert.equal(res.done, false);
  });

  test(`[${sh}] a staged script that arrives damaged is not run`, async (t) => {
    const r = fakeStock(sh);
    t.after(r.cleanup);
    const shell = async (cmd) => (cmd.startsWith('printf') ? r.shell(cmd.replace(/'(.)/, "'X")) : r.shell(cmd));
    await assert.rejects(FW.stageScript(shell, '/tmp/utr-x.sh', FW.switchToOpenWrtScript()), /did not arrive intact/);
  });
}

test('at least one real shell ran the stock scripts', () => {
  assert.ok(SHELLS.length > 0, 'neither busybox nor dash is installed');
});
