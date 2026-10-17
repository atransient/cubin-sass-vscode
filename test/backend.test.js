'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { BackendRunner } = require('../backend.js');

function token() {
  const listeners = new Set();
  return { isCancellationRequested: false,
    onCancellationRequested(f) { listeners.add(f); return { dispose: () => listeners.delete(f) }; },
    cancel() { this.isCancellationRequested = true; for (const f of listeners) f(); },
  };
}

async function until(predicate) {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    assert.ok(Date.now() < deadline, 'backend did not reach the expected state');
    await delay(10);
  }
}

function fixture(t, options) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cubin-backend-test-'));
  const runner = new BackendRunner(options);
  t.after(async () => { await runner.dispose(); fs.rmSync(dir, { recursive: true, force: true }); });
  const run = (code, options) => runner.run(process.execPath, ['-e', code], { timeoutMs: 5000, ...options });
  const marker = (name) => path.join(dir, name);
  const hang = (name) => `require('fs').writeFileSync(${JSON.stringify(marker(name))}, String(process.pid)); setInterval(() => {}, 1000);`;
  return { runner, run, marker, hang };
}

test('backend accepts stdin JSON replies and reports process/protocol errors', async (t) => {
  const h = fixture(t);
  const reply = await h.run("let text=''; process.stdin.on('data', b => text+=b); process.stdin.on('end', () => console.log(JSON.stringify({ok:true,text})));", { input: Buffer.from('binary input') });
  assert.deepEqual(reply, { ok: true, text: 'binary input' });
  const rejected = await h.run("console.log(JSON.stringify({ok:false,error:'bad instruction'})); process.exitCode=1;", { hint: 'backend command' });
  assert.equal(rejected.error, 'bad instruction');
  assert.equal(rejected.hint, 'backend command');
  assert.equal(rejected.infrastructureError, undefined);
  for (const output of ['not JSON', 'null', '[]']) {
    const bad = await h.run(`console.log(${JSON.stringify(output)})`);
    assert.equal(bad.ok, false);
    assert.equal(bad.infrastructureError, true);
  }
  const missing = await h.runner.run(h.marker('missing-program'), [], { input: Buffer.alloc(1024 * 1024) });
  assert.equal(missing.ok, false);
  assert.equal(missing.infrastructureError, true);
  const earlyExit = await h.run("console.log('{\"ok\":false,\"error\":\"rejected early\"}'); process.exit(1);", { input: Buffer.alloc(4 * 1024 * 1024) });
  assert.equal(earlyExit.error, 'rejected early', 'early stdin closure must not crash the host');
});

test('backend enforces concurrency and queue limits, and releases cancelled slots', async (t) => {
  const h = fixture(t, { concurrency: 1, maxQueued: 1 });
  const cancellation = token();
  const first = h.run(h.hang('first'), { token: cancellation });
  await until(() => fs.existsSync(h.marker('first')));
  const second = h.run(`require('fs').writeFileSync(${JSON.stringify(h.marker('second'))}, 'started'); console.log('{"ok":true}');`);
  assert.equal(fs.existsSync(h.marker('second')), false);
  const full = await h.run("console.log('{\"ok\":true}')");
  assert.equal(full.ok, false);
  assert.match(full.error, /队列已满/);
  cancellation.cancel();
  assert.equal((await first).cancelled, true);
  assert.equal((await second).ok, true);
  assert.equal(fs.existsSync(h.marker('second')), true);
});

test('a new generation cancels both queued and running jobs with its key', async (t) => {
  const h = fixture(t, { concurrency: 1 });
  const blocker = h.run(h.hang('blocker'), { key: 'blocker' });
  await until(() => fs.existsSync(h.marker('blocker')));
  const old = h.run(h.hang('old'), { key: 'preview' });
  const latest = h.run(h.hang('latest'), { key: 'preview' });
  assert.equal((await old).cancelled, true);
  assert.equal(fs.existsSync(h.marker('old')), false);
  h.runner.cancelKey('blocker');
  await blocker;
  await until(() => fs.existsSync(h.marker('latest')));
  const final = h.run("console.log('{\"ok\":true,\"generation\":3}')", { key: 'preview' });
  assert.equal((await latest).cancelled, true);
  assert.deepEqual(await final, { ok: true, generation: 3 });
});

test('queued timeout and cancellation do not spawn their commands', async (t) => {
  const h = fixture(t, { concurrency: 1 });
  const blocker = h.run(h.hang('blocker'));
  await until(() => fs.existsSync(h.marker('blocker')));
  const cancellation = token();
  const cancelled = h.run(h.hang('cancelled'), { token: cancellation });
  cancellation.cancel();
  assert.equal((await cancelled).cancelled, true);
  const expired = await h.run(h.hang('expired'), { timeoutMs: 30 });
  assert.equal(expired.timedOut, true);
  assert.equal(fs.existsSync(h.marker('expired')), false);
  assert.equal(fs.existsSync(h.marker('cancelled')), false);
  h.runner.cancelAll();
  assert.equal((await blocker).cancelled, true);
});

test('cancelling one owner preserves other jobs and disposal drains every job', async (t) => {
  const h = fixture(t, { concurrency: 2 });
  const a = h.run(h.hang('a'), { owner: 'a' });
  const b = h.run(h.hang('b'), { owner: 'b' });
  await until(() => fs.existsSync(h.marker('a')) && fs.existsSync(h.marker('b')));
  const waiting = h.run(h.hang('waiting'), { owner: 'a' });
  h.runner.cancelOwner('a');
  assert.equal((await a).cancelled, true);
  assert.equal((await waiting).cancelled, true);
  assert.equal(fs.existsSync(h.marker('waiting')), false);
  await h.runner.dispose();
  assert.equal((await b).cancelled, true);
  assert.equal((await h.run(h.hang('after-disposal'))).cancelled, true);
  assert.equal(fs.existsSync(h.marker('after-disposal')), false);
});

test('timeout kills the process group including descendants that ignore TERM', { skip: process.platform !== 'linux' }, async (t) => {
  const h = fixture(t, { killGraceMs: 50 });
  const childCode = `process.on('SIGTERM', () => {}); ${h.hang('descendant')}`;
  const code = `require('child_process').spawn(process.execPath, ['-e', ${JSON.stringify(childCode)}], {stdio:'ignore'}); process.on('SIGTERM', () => {}); ${h.hang('parent')}`;
  const result = h.run(code, { timeoutMs: 1500 });
  await until(() => fs.existsSync(h.marker('descendant')));
  const pids = ['parent', 'descendant'].map((name) => Number(fs.readFileSync(h.marker(name), 'utf8')));
  assert.equal((await result).timedOut, true);
  const running = (pid) => {
    try { return !/\) [ZX] /.test(fs.readFileSync(`/proc/${pid}/stat`, 'utf8')); }
    catch (e) { if (e.code === 'ENOENT') return false; throw e; }
  };
  await until(() => pids.every((pid) => !running(pid)));
  assert.equal((await h.run("console.log('{\"ok\":true}')")).ok, true, 'a timed-out task must release its slot');
});
