'use strict';
// Real process cancellation through the extension's save/preview/source paths.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { loadExtension } = require('./helpers/extension.js');

async function until(predicate) {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    assert.ok(Date.now() < deadline, 'backend did not reach the expected state');
    await delay(10);
  }
}

function fixture(t) {
  const h = loadExtension();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cubin-backend-extension-'));
  const script = path.join(dir, 'backend.js');
  const log = path.join(dir, 'started.jsonl');
  fs.writeFileSync(script, `require('fs').appendFileSync(${JSON.stringify(log)}, JSON.stringify({pid:process.pid,args:process.argv.slice(2)})+'\\n'); process.stdin.resume(); setInterval(() => {}, 1000);`);
  const settings = { scriptPath: script, pythonPath: process.execPath, backendTimeout: 10, backendConcurrency: 1 };
  h.vscode.workspace.getConfiguration = () => ({ get: (key) => settings[key] });
  h.extension.activate(h.context);
  const provider = h.providers.get('cubinSass.preview');
  const uri = h.vscode.Uri.file(path.join(dir, 'base.cubin'));
  fs.writeFileSync(uri.fsPath, 'original');
  const doc = new h.CubinDocument(uri, Buffer.from('original'));
  t.after(async () => { await h.backend.dispose(); fs.rmSync(dir, { recursive: true, force: true }); });
  const starts = () => fs.existsSync(log)
    ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
  return { ...h, provider, uri, doc, settings, starts };
}

test('cancelled or timed-out binary validation keeps edits and never offers experimental save', async (t) => {
  const h = fixture(t);
  h.doc.applyWhole(Buffer.from('edited'), 'edit');
  const emitter = new h.vscode.EventEmitter();
  const token = { isCancellationRequested: false, onCancellationRequested: emitter.event };
  const saving = h.provider.saveCustomDocument(h.doc, token);
  const rejected = assert.rejects(saving, /取消/);
  await until(() => h.starts().length === 1);
  assert.ok(h.starts()[0].args.includes('--check-save'));
  token.isCancellationRequested = true;
  emitter.fire();
  await rejected;
  h.settings.backendTimeout = 1;
  await assert.rejects(h.provider.saveCustomDocument(h.doc), /超时/);
  assert.equal(h.doc.data.toString(), 'edited');
  assert.equal(h.doc.savedData.toString(), 'original');
  assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'original');
  assert.equal(h.warnings.length, 0);
});

test('preview edits supersede older processes, closing and explicit cancellation stop remaining work', async (t) => {
  const h = fixture(t);
  const panel = h.panel();
  await h.provider.resolveCustomEditor(h.doc, panel);
  await panel.receive({ type: 'ready' });
  await until(() => h.starts().length === 1);
  h.doc.applyEdit(0, Buffer.from('O'), 'edit');
  await until(() => h.starts().length === 2);
  assert.equal(h.backend.tasks.size, 1, 'the old process must exit before the replacement starts');
  panel.dispose();
  await until(() => h.backend.tasks.size === 0);
  assert.equal(panel.messages.some((m) => m.type === 'data'), false);
  const reopened = h.panel();
  await h.provider.resolveCustomEditor(h.doc, reopened);
  await reopened.receive({ type: 'ready' });
  await until(() => h.starts().length === 3);
  await h.commands.get('cubinSass.cancelTasks')();
  await until(() => h.backend.tasks.size === 0);
  await until(() => reopened.messages.some((m) => m.type === 'backendCancelled'));
});

test('editing or closing a source cancels assembly without committing its result', async (t) => {
  for (const action of ['edit', 'close']) {
    const h = fixture(t);
    h.provider.live.set(h.uri.toString(), { doc: h.doc });
    const uri = h.nvsassFS.set(h.uri, '.text.f', 'previous source');
    const source = h.sourceDoc(uri, 'source being assembled', true);
    const saving = source.save();
    await until(() => h.starts().length === 1);
    assert.ok(h.starts()[0].args.includes('--assemble-source'));
    if (action === 'edit') source.setText('newer source');
    else source.close();
    assert.equal(await saving, false);
    assert.equal(source.isDirty, true);
    assert.equal(h.doc.data.toString(), 'original');
    assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'original');
    assert.equal((await h.nvsassFS.readFile(uri)).toString(), 'previous source');
    assert.equal(h.backend.tasks.size, 0);
  }
});
