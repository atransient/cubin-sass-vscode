'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadExtension } = require('./helpers/extension.js');
const { baseHash } = require('../basehash.js');

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}
const tick = () => new Promise(setImmediate);

function fixture(t) {
  const host = loadExtension();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cubin-sass-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const uri = host.vscode.Uri.file(path.join(dir, 'base.cubin'));
  fs.writeFileSync(uri.fsPath, 'original');
  const doc = new host.CubinDocument(uri, Buffer.from('original'));
  const provider = new host.Provider(host.context);
  host.setProvider(provider);
  return { ...host, dir, uri, doc, provider };
}

test('backup restoration reads unsaved bytes and retains the disk save baseline', async (t) => {
  const h = fixture(t);
  const backupUri = h.vscode.Uri.file(path.join(h.dir, 'backup'));
  h.doc.applyWhole(Buffer.from('unsaved'), 'edit');
  const backup = await h.doc.backup(backupUri);
  const restored = await h.provider.openCustomDocument(h.uri, { backupId: backup.id });
  assert.equal(restored.data.toString(), 'unsaved');
  assert.equal(restored.savedData.toString(), 'original');
  assert.notEqual(restored.data.toString(), restored.savedData.toString());
});

test('backup restoration survives a missing original and validates before recreating it', async (t) => {
  const h = fixture(t);
  h.doc.applyWhole(Buffer.from('unsaved backup'), 'edit');
  const backup = await h.doc.backup(h.vscode.Uri.file(path.join(h.dir, 'backup')));
  fs.unlinkSync(h.uri.fsPath);
  const restored = await h.provider.openCustomDocument(h.uri, { backupId: backup.id });
  assert.equal(restored.data.toString(), 'unsaved backup');
  assert.equal(restored.diskMissing, true);
  assert.equal(fs.existsSync(h.uri.fsPath), false);
  let checks = 0;
  h.setRunner(async (_uri, args, data) => {
    checks++;
    assert.ok(args.includes('--check-save'));
    assert.equal(args.includes('--diff'), false, 'no trustworthy disk baseline exists');
    assert.equal(data.toString(), 'unsaved backup');
    return { ok: true };
  });
  await h.provider.saveCustomDocument(restored);
  assert.equal(checks, 1);
  assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'unsaved backup');
  assert.equal(restored.diskMissing, false);
  assert.equal(restored.savedData.toString(), 'unsaved backup');
});

test('recovered backups preserve their bytes on validation failure or external recreation', async (t) => {
  for (const conflict of ['validation', 'recreated']) {
    const h = fixture(t);
    const backup = await h.doc.backup(h.vscode.Uri.file(path.join(h.dir, 'backup')));
    fs.unlinkSync(h.uri.fsPath);
    const restored = await h.provider.openCustomDocument(h.uri, { backupId: backup.id });
    h.setRunner(async () => {
      if (conflict === 'recreated') fs.writeFileSync(h.uri.fsPath, 'external file');
      return { ok: conflict !== 'validation', error: 'invalid encoding' };
    });
    await assert.rejects(h.provider.saveCustomDocument(restored), /安全闸|磁盘文件/);
    assert.equal(restored.data.toString(), 'original');
    assert.equal(restored.diskMissing, true);
    assert.equal(fs.readFileSync(path.join(h.dir, 'backup'), 'utf8'), 'original');
    assert.equal(fs.existsSync(h.uri.fsPath), conflict === 'recreated');
    if (conflict === 'recreated') assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'external file');
  }
});

test('opening a missing original without a backup still reports file not found', async (t) => {
  const h = fixture(t);
  fs.unlinkSync(h.uri.fsPath);
  await assert.rejects(h.provider.openCustomDocument(h.uri), { code: 'ENOENT' });
});

test('save rejects edits made while validation is running, for save and save as', async (t) => {
  for (const saveAs of [false, true]) {
    const h = fixture(t);
    const answer = deferred();
    const dest = h.vscode.Uri.file(path.join(h.dir, 'other.cubin'));
    h.doc.applyWhole(Buffer.from('version A'), 'A');
    h.setRunner(async (_u, _args, data) => {
      assert.equal(data.toString(), 'version A');
      return answer.promise;
    });
    const saving = saveAs ? h.provider.saveCustomDocumentAs(h.doc, dest)
      : h.provider.saveCustomDocument(h.doc);
    const rejected = assert.rejects(saving, /已改变/);
    await tick();
    h.doc.applyWhole(Buffer.from('version B'), 'B');
    answer.resolve({ ok: true });
    await rejected;
    assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'original');
    assert.equal(fs.existsSync(dest.fsPath), false);
    assert.equal(h.doc.savedData.toString(), 'original');
  }
});

test('edits during staging abort the save and preserve the disk baseline', async (t) => {
  const h = fixture(t);
  const write = deferred();
  const writing = deferred();
  h.doc.applyWhole(Buffer.from('version A'), 'A');
  h.setRunner(async () => ({ ok: true }));
  h.vscode.workspace.fs.writeFile = async (u, bytes) => {
    writing.resolve();
    await write.promise;
    fs.writeFileSync(u.fsPath, bytes);
  };
  const saving = h.provider.saveCustomDocument(h.doc);
  const rejected = assert.rejects(saving, /已改变/);
  await writing.promise;
  h.doc.applyWhole(Buffer.from('version B'), 'B');
  write.resolve();
  await rejected;
  assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'original');
  assert.equal(h.doc.savedData.toString(), 'original');
  assert.equal(h.doc.data.toString(), 'version B');
  assert.deepEqual(fs.readdirSync(h.dir), ['base.cubin']);
});

test('saves preserve destination changes made while staging the temporary file', async (t) => {
  for (const destination of ['original', 'existing', 'missing']) {
    for (const change of ['replace', 'delete']) {
      if (destination === 'missing' && change === 'delete') continue;
      const h = fixture(t);
      const target = destination === 'original' ? h.uri
        : h.vscode.Uri.file(path.join(h.dir, 'other.cubin'));
      if (destination === 'existing') fs.writeFileSync(target.fsPath, 'previous destination');
      h.doc.applyWhole(Buffer.from('editor edit'), 'edit');
      h.setRunner(async () => ({ ok: true }));
      const writeFile = h.vscode.workspace.fs.writeFile;
      h.vscode.workspace.fs.writeFile = async (uri, bytes) => {
        await writeFile(uri, bytes);
        if (change === 'delete') fs.unlinkSync(target.fsPath);
        else fs.writeFileSync(target.fsPath, 'external edit');
      };
      await assert.rejects(h.provider.saveCustomDocumentAs(h.doc, target), /磁盘文件.*外部/);
      assert.equal(fs.existsSync(target.fsPath), change !== 'delete');
      if (change !== 'delete') assert.equal(fs.readFileSync(target.fsPath, 'utf8'), 'external edit');
      assert.equal(h.doc.data.toString(), 'editor edit');
      assert.equal(h.doc.savedData.toString(), 'original');
      assert.equal(fs.readdirSync(h.dir).some((name) => name.includes('.cubin-sass-')), false);
    }
  }
});

test('cancellation during staging leaves the original and save-as destination untouched', async (t) => {
  for (const saveAs of [false, true]) {
    const h = fixture(t);
    const target = saveAs ? h.vscode.Uri.file(path.join(h.dir, 'other.cubin')) : h.uri;
    const cancel = { isCancellationRequested: false };
    h.doc.applyWhole(Buffer.from('editor edit'), 'edit');
    h.setRunner(async () => ({ ok: true }));
    const writeFile = h.vscode.workspace.fs.writeFile;
    h.vscode.workspace.fs.writeFile = async (uri, bytes) => {
      await writeFile(uri, bytes);
      cancel.isCancellationRequested = true;
    };
    await assert.rejects(h.provider.saveCustomDocumentAs(h.doc, target, cancel), /取消/);
    assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'original');
    if (saveAs) assert.equal(fs.existsSync(target.fsPath), false);
    assert.equal(h.doc.savedData.toString(), 'original');
    assert.equal(h.doc.data.toString(), 'editor edit');
    assert.deepEqual(fs.readdirSync(h.dir), ['base.cubin']);
  }
});

test('closing a virtual source evicts its cache and reopening exports the current base', async (t) => {
  const h = fixture(t);
  h.extension.activate(h.context);
  const uri = h.nvsassFS.set(h.uri, '.text.f', 'old source', 1);
  const other = h.nvsassFS.set(h.uri, '.text.f', 'other image source', 0);
  const source = h.sourceDoc(uri, 'old source');
  source.close();
  assert.equal(h.nvsassFS.entries.has(uri.toString()), false);
  assert.equal(h.nvsassFS.entries.has(other.toString()), true);
  fs.writeFileSync(h.uri.fsPath, 'new base');
  h.setRunner(async (_uri, args, data) => {
    assert.equal(args[args.indexOf('--image') + 1], '1');
    assert.equal(data.toString(), 'new base');
    return { ok: true, source: 'new source' };
  });
  const reopened = await h.vscode.workspace.openTextDocument(uri);
  assert.notEqual(reopened, source);
  assert.equal(reopened.getText(), 'new source');
});

test('permission fallback checks conflicts and cancellation before writing the original', async (t) => {
  for (const change of ['external', 'cancel', 'none']) {
    const h = fixture(t);
    const cancel = { isCancellationRequested: false };
    h.doc.applyWhole(Buffer.from('editor edit'), 'edit');
    h.setRunner(async () => ({ ok: true }));
    const writeFile = h.vscode.workspace.fs.writeFile;
    h.vscode.workspace.fs.writeFile = async (uri, bytes) => {
      if (uri.fsPath === h.uri.fsPath) return writeFile(uri, bytes);
      if (change === 'external') fs.writeFileSync(h.uri.fsPath, 'external edit');
      if (change === 'cancel') cancel.isCancellationRequested = true;
      const error = new Error('read-only directory');
      error.code = 'EACCES';
      throw error;
    };
    const saving = h.provider.saveCustomDocument(h.doc, cancel);
    if (change === 'none') await saving;
    else await assert.rejects(saving, change === 'external' ? /磁盘文件.*外部/ : /取消/);
    const expected = change === 'external' ? 'external edit'
      : change === 'cancel' ? 'original' : 'editor edit';
    assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), expected);
    assert.equal(h.doc.savedData.toString(), change === 'none' ? 'editor edit' : 'original');
    assert.deepEqual(fs.readdirSync(h.dir), ['base.cubin']);
  }
});

test('binary saves preserve external changes or deletion during validation', async (t) => {
  for (const external of ['replace', 'delete']) {
    const h = fixture(t);
    h.doc.applyWhole(Buffer.from('editor edit'), 'edit');
    h.setRunner(async () => {
      if (external === 'delete') fs.unlinkSync(h.uri.fsPath);
      else fs.writeFileSync(h.uri.fsPath, 'external edit');
      return { ok: true };
    });
    await assert.rejects(h.provider.saveCustomDocument(h.doc), /磁盘文件.*外部/);
    assert.equal(h.doc.data.toString(), 'editor edit');
    assert.equal(h.doc.savedData.toString(), 'original');
    assert.equal(fs.existsSync(h.uri.fsPath), external !== 'delete');
    if (external !== 'delete') assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'external edit');
  }
});

test('save as rejects a changed or newly created destination during validation', async (t) => {
  for (const existed of [false, true]) {
    const h = fixture(t);
    const dest = h.vscode.Uri.file(path.join(h.dir, 'other.cubin'));
    if (existed) fs.writeFileSync(dest.fsPath, 'previous destination');
    h.doc.applyWhole(Buffer.from('editor edit'), 'edit');
    h.setRunner(async () => {
      fs.writeFileSync(dest.fsPath, 'external destination');
      return { ok: true };
    });
    await assert.rejects(h.provider.saveCustomDocumentAs(h.doc, dest), /磁盘文件.*外部/);
    assert.equal(fs.readFileSync(dest.fsPath, 'utf8'), 'external destination');
    assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'original');
    assert.equal(h.doc.data.toString(), 'editor edit');
    assert.equal(h.doc.savedData.toString(), 'original');
  }
});

test('concurrent saves of different documents use independent temporary baselines', async (t) => {
  const h = fixture(t);
  const other = new h.CubinDocument(h.vscode.Uri.file(path.join(h.dir, 'other.cubin')), Buffer.from('other base'));
  fs.writeFileSync(other.uri.fsPath, 'other base');
  h.doc.applyWhole(Buffer.from('first edit'), 'edit');
  other.applyWhole(Buffer.from('second edit'), 'edit');
  const requests = [];
  h.setRunner(async (_u, args) => {
    const answer = deferred();
    const file = args[args.indexOf('--diff') + 1];
    requests.push({ file, answer });
    return answer.promise;
  });
  const saves = [h.provider.saveCustomDocument(h.doc), h.provider.saveCustomDocument(other)];
  await tick();
  assert.equal(requests.length, 2);
  assert.notEqual(requests[0].file, requests[1].file);
  assert.equal(fs.readFileSync(requests[0].file, 'utf8'), 'original');
  assert.equal(fs.readFileSync(requests[1].file, 'utf8'), 'other base');
  requests[0].answer.resolve({ ok: true });
  await saves[0];
  assert.equal(fs.existsSync(requests[0].file), false);
  assert.equal(fs.readFileSync(requests[1].file, 'utf8'), 'other base');
  requests[1].answer.resolve({ ok: true });
  await saves[1];
  assert.equal(fs.existsSync(requests[1].file), false);
});

test('source assembly rejects newer binary or source edits without overwriting them', async (t) => {
  for (const editSource of [false, true]) {
    const h = fixture(t);
    const source = h.sourceDoc(h.vscode.Uri.file(path.join(h.dir, 'base.text.f.nvsass')), 'source A');
    const answer = deferred();
    let temp;
    h.setRunner(async (_u, args) => { temp = args[0]; return answer.promise; });
    const work = h.assembleIntoBuffer(source, h.uri, h.doc);
    const rejected = assert.rejects(work, /已改变/);
    if (editSource) source.setText('source B');
    else h.doc.applyWhole(Buffer.from('newer binary'), 'edit');
    answer.resolve({ ok: true, data: Buffer.from('stale output').toString('hex') });
    await rejected;
    assert.equal(h.doc.data.toString(), editSource ? 'original' : 'newer binary');
    assert.equal(fs.existsSync(temp), false);
  }
});

test('failed virtual source saves remain dirty and retain the last successful source', async (t) => {
  const h = fixture(t);
  h.extension.activate(h.context);
  const provider = h.providers.get('cubinSass.preview');
  provider.live.set(h.uri.toString(), { doc: h.doc });
  const sourceUri = h.nvsassFS.set(h.uri, '.text.f', 'old source');
  const source = h.sourceDoc(sourceUri, 'invalid source', true);
  h.setRunner(async () => ({ ok: false, error: 'invalid instruction' }));
  assert.equal(await source.save(), false);
  assert.equal(source.isDirty, true);
  assert.equal(source.getText(), 'invalid source');
  assert.equal((await h.nvsassFS.readFile(sourceUri)).toString(), 'old source');
  assert.equal(h.doc.data.toString(), 'original');
  assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'original');
});

test('assemble command on dirty virtual source assembles once and rebinds it', async (t) => {
  const h = fixture(t);
  h.extension.activate(h.context);
  const provider = h.providers.get('cubinSass.preview');
  provider.live.set(h.uri.toString(), { doc: h.doc });
  const text = `.base ${baseHash(h.doc.data)}\nsource A`;
  const sourceUri = h.nvsassFS.set(h.uri, '.text.f', text);
  const source = h.sourceDoc(sourceUri, text, true);
  h.vscode.window.activeTextEditor = { document: source };
  let calls = 0;
  h.setRunner(async () => {
    calls++;
    return { ok: true, data: Buffer.from('assembled').toString('hex'), source: 'rebound source', count: 1 };
  });
  await h.commands.get('cubinSass.assembleSource')();
  assert.equal(calls, 1);
  assert.equal(source.isDirty, false);
  assert.equal(source.getText(), 'rebound source');
  assert.equal(h.doc.data.toString(), 'assembled');
  assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'original');
});

test('disk assembly stages validation and rejects source or external base changes', async (t) => {
  for (const conflict of ['source', 'base', 'failure']) {
    const h = fixture(t);
    const source = h.sourceDoc(h.vscode.Uri.file(path.join(h.dir, 'base.text.f.nvsass')), 'source A');
    fs.writeFileSync(source.uri.fsPath, source.getText());
    const answer = deferred();
    h.setRunner(async (_u, args) => {
      assert.notEqual(args[0], h.uri.fsPath);
      fs.writeFileSync(args[0], 'assembled');
      return answer.promise;
    });
    const work = h.assembleOntoDisk(source, h.uri);
    const checked = conflict === 'failure' ? work : assert.rejects(work, /改变|修改/);
    if (conflict === 'source') source.setText('newer source');
    if (conflict === 'base') fs.writeFileSync(h.uri.fsPath, 'external edit');
    answer.resolve(conflict === 'failure' ? { ok: false, error: 'invalid' } : { ok: true });
    await checked;
    assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), conflict === 'base' ? 'external edit' : 'original');
  }
});

test('successful disk assembly commits atomically and preserves file mode', async (t) => {
  const h = fixture(t);
  const source = h.sourceDoc(h.vscode.Uri.file(path.join(h.dir, 'base.text.f.nvsass')), 'source A');
  fs.writeFileSync(source.uri.fsPath, source.getText());
  fs.chmodSync(h.uri.fsPath, 0o755);
  h.setRunner(async (_u, args) => {
    fs.writeFileSync(args[0], 'assembled');
    return { ok: true, source: 'rebound' };
  });
  const res = await h.assembleOntoDisk(source, h.uri);
  assert.equal(res.written, h.uri.fsPath);
  assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'assembled');
  assert.equal(fs.statSync(h.uri.fsPath).mode & 0o777, 0o755);
});

test('older preview responses cannot replace the latest revision', async (t) => {
  const h = fixture(t);
  const jobs = [];
  h.setRunner(async () => { const job = deferred(); jobs.push(job); return job.promise; });
  const panel = h.panel();
  await h.provider.resolveCustomEditor(h.doc, panel);
  await panel.receive({ type: 'ready' });
  h.doc.applyEdit(0, Buffer.from('O'), 'edit');
  assert.equal(jobs.length, 2);
  jobs[1].resolve({ ok: true, marker: 'new' });
  await tick();
  jobs[0].resolve({ ok: true, marker: 'old' });
  await tick();
  const data = panel.messages.filter((m) => m.type === 'data');
  assert.equal(data.length, 1);
  assert.equal(data[0].data.marker, 'new');
  assert.equal(data[0].data.revision, h.doc.revision);
});

test('single instruction assembly and reflow cannot overwrite newer binary edits', async (t) => {
  for (const type of ['assemble', 'reflow']) {
    const h = fixture(t);
    const answer = deferred();
    h.setRunner(async (_u, args) => args.includes('--assemble') || args.includes('--delete')
      ? answer.promise : { ok: true });
    const panel = h.panel();
    await h.provider.resolveCustomEditor(h.doc, panel);
    const work = panel.receive({ type, op: 'delete', fileOff: 0, text: 'NOP;', revision: h.doc.revision });
    h.doc.applyWhole(Buffer.from('newer edit'), 'edit');
    answer.resolve({ ok: true, bytes: '00'.repeat(16), data: '00'.repeat(16) });
    await work;
    assert.equal(h.doc.data.toString(), 'newer edit');
    assert.ok(h.errors.some((e) => e.includes('已改变')));
    const result = panel.messages.find((m) => m.type === (type === 'assemble' ? 'assembled' : 'reflowed'));
    assert.equal(result.res.ok, false);
  }
});

test('byte edits from an outdated preview are rejected', async (t) => {
  const h = fixture(t);
  h.setRunner(async () => ({ ok: true }));
  const panel = h.panel();
  await h.provider.resolveCustomEditor(h.doc, panel);
  await panel.receive({ type: 'edit', fileOff: 0, bytes: '00', revision: h.doc.revision - 1 });
  assert.equal(h.doc.data.toString(), 'original');
  assert.ok(h.errors.some((e) => e.includes('过期')));
});

test('patch results cannot overwrite edits made during patch validation', async (t) => {
  const h = fixture(t);
  h.extension.activate(h.context);
  const provider = h.providers.get('cubinSass.preview');
  provider.live.set(h.uri.toString(), { doc: h.doc, panel: { active: true } });
  h.vscode.window.showOpenDialog = async () => [h.vscode.Uri.file(path.join(h.dir, 'patch.json'))];
  const answer = deferred();
  h.setRunner(async () => answer.promise);
  const work = h.commands.get('cubinSass.applyPatch')();
  await tick();
  h.doc.applyWhole(Buffer.from('newer edit'), 'edit');
  answer.resolve({ ok: true, applied: 1, results: [{ ok: true, file_off: 0, bytes: '00', sass: 'NOP' }] });
  await work;
  assert.equal(h.doc.data.toString(), 'newer edit');
  assert.ok(h.errors.some((e) => e.includes('已改变')));
});

test('saves of the same document wait for the preceding save', async (t) => {
  const h = fixture(t);
  h.doc.applyWhole(Buffer.from('edited'), 'edit');
  const answer = deferred();
  let calls = 0;
  h.setRunner(async () => { calls++; return answer.promise; });
  const first = h.provider.saveCustomDocument(h.doc);
  const second = h.provider.saveCustomDocument(h.doc);
  await tick();
  assert.equal(calls, 1);
  answer.resolve({ ok: true });
  await Promise.all([first, second]);
  assert.equal(calls, 1, 'the second save sees the already validated, saved bytes');
  assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'edited');
});

test('undo/redo recorded before a disk reload do not splice old bytes into the new file', async (t) => {
  for (const reload of ['external', 'revert']) {
    const h = fixture(t);
    const edits = [];
    h.doc.onDidChangeCustomDocument((e) => edits.push(e));
    h.doc.applyEdit(0, Buffer.from('O'), 'byte edit');
    h.doc.applyWhole(Buffer.from('whole edit'), 'whole edit');
    fs.writeFileSync(h.uri.fsPath, 'reloaded from disk');
    if (reload === 'external') h.doc.reloadFromDisk(fs.readFileSync(h.uri.fsPath));
    else await h.doc.revert();
    for (const e of [...edits].reverse()) e.undo();
    for (const e of edits) e.redo();
    assert.equal(h.doc.data.toString(), 'reloaded from disk', reload);
    assert.equal(h.doc.savedData.toString(), 'reloaded from disk', reload);
    assert.equal(h.warnings.filter((w) => w.includes('重新载入之前')).length, 4, reload);
  }
});

test('edits made after a reload still undo and redo normally', async (t) => {
  const h = fixture(t);
  const edits = [];
  h.doc.onDidChangeCustomDocument((e) => edits.push(e));
  h.doc.reloadFromDisk(Buffer.from('disk'));
  h.doc.applyEdit(0, Buffer.from('D'), 'byte edit');
  edits[0].undo();
  assert.equal(h.doc.data.toString(), 'disk');
  edits[0].redo();
  assert.equal(h.doc.data.toString(), 'Disk');
  assert.deepEqual(h.warnings, []);
});

test('binary save replaces the file atomically, keeping mode and symlinks', async (t) => {
  const h = fixture(t);
  const real = path.join(h.dir, 'real.cubin');
  fs.renameSync(h.uri.fsPath, real);
  fs.symlinkSync(real, h.uri.fsPath);
  fs.chmodSync(real, 0o751);
  h.setRunner(async () => ({ ok: true }));
  h.doc.applyWhole(Buffer.from('saved bytes'), 'edit');
  await h.provider.saveCustomDocument(h.doc);
  assert.ok(fs.lstatSync(h.uri.fsPath).isSymbolicLink());
  assert.equal(fs.readFileSync(real, 'utf8'), 'saved bytes');
  assert.equal(fs.statSync(real).mode & 0o777, 0o751);
  assert.deepEqual(fs.readdirSync(h.dir).sort(), ['base.cubin', 'real.cubin']);
});

test('a failed rename leaves the original file and no temporary file behind', async (t) => {
  const h = fixture(t);
  h.vscode.workspace.fs.rename = async () => { throw new Error('rename failed'); };
  await assert.rejects(h.writeBinaryAtomic(h.uri, Buffer.from('new')), /rename failed/);
  assert.equal(fs.readFileSync(h.uri.fsPath, 'utf8'), 'original');
  assert.deepEqual(fs.readdirSync(h.dir), ['base.cubin']);
});

test('payload-only results are patched into the host bytes that were sent', () => {
  const h = loadExtension();
  const base = Buffer.from('HOST[cubin]TAIL');
  const res = { data: Buffer.from('CUBIN').toString('hex'), data_scope: 'payload',
    container: { embedded: true, payload_offset: 5, payload_size: 5 } };
  assert.equal(h.resultBytes(res, base).toString(), 'HOST[CUBIN]TAIL');
  assert.equal(base.toString(), 'HOST[cubin]TAIL');            // input untouched
  assert.equal(h.resultBytes({ data: '6869' }, base).toString(), 'hi');
  for (const container of [{ embedded: true, payload_offset: 5, payload_size: 4 },
                           { embedded: true, payload_offset: 12, payload_size: 5 },
                           { embedded: false, payload_offset: 5, payload_size: 5 }]) {
    assert.throws(() => h.resultBytes({ ...res, container }, base), /布局不符/);
  }
});

test('reflow asks for the payload only and applies it to the host buffer', async (t) => {
  const h = fixture(t);
  h.doc.applyWhole(Buffer.from('HOST[cubin]TAIL'), 'host');
  let seen = null;
  h.setRunner(async (_u, args) => {
    if (!args.includes('--delete')) return { ok: true };
    seen = args;
    return { ok: true, moved: 0, relocated: [], data: Buffer.from('CUBIN').toString('hex'),
      data_scope: 'payload', container: { embedded: true, payload_offset: 5, payload_size: 5 } };
  });
  const panel = h.panel();
  await h.provider.resolveCustomEditor(h.doc, panel);
  await panel.receive({ type: 'reflow', op: 'delete', fileOff: 5, revision: h.doc.revision });
  assert.ok(seen.includes('--payload-only'));
  assert.equal(h.doc.data.toString(), 'HOST[CUBIN]TAIL');
});

test('a file open in one SASS preview cannot be opened in the other view type', async (t) => {
  const h = fixture(t);
  h.setRunner(async () => ({ ok: true }));
  const first = h.panel();
  await h.provider.resolveCustomEditor(h.doc, first);
  const twin = new h.CubinDocument(h.uri, Buffer.from('original'));
  await assert.rejects(h.provider.resolveCustomEditor(twin, h.panel()), /另一个 SASS 预览/);
  assert.equal(h.provider.live.get(h.uri.toString()).doc, h.doc);
  first.dispose();
  assert.equal(h.provider.live.has(h.uri.toString()), false);
  await h.provider.resolveCustomEditor(twin, h.panel());    // 关掉之后可以换一种方式打开
  assert.equal(h.provider.live.get(h.uri.toString()).doc, twin);
});

test('webview nonces come from a CSPRNG', async (t) => {
  const h = fixture(t);
  h.setRunner(async () => ({ ok: true }));
  const seen = new Set();
  for (let i = 0; i < 2; i++) {
    h.provider.live.clear();
    const panel = h.panel();
    await h.provider.resolveCustomEditor(new h.CubinDocument(h.uri, Buffer.from('x')), panel);
    seen.add(/nonce-([^']+)'/.exec(panel.webview.html)[1]);
  }
  assert.equal(seen.size, 2);
  for (const n of seen) assert.match(n, /^[A-Za-z0-9+/]{22}==$/);   // 16 random bytes
});
