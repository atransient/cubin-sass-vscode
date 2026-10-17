'use strict';
// Exercise the source-save orchestration with the bundled Python backend and
// nvdisasm. The VS Code API is stubbed; IO, assembly and validation are real.
const test = require('node:test');
const assert = require('node:assert/strict');
const cp = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadExtension } = require('./helpers/extension.js');
const { baseHash, declaredBase } = require('../basehash.js');
const { hostWithCubins } = require('./helpers/fatbin.js');

const root = path.resolve(__dirname, '..');
const backend = path.join(root, 'scripts/cubin_sass.py');
const fixture = path.join(root, 'corpus/cubins/fma.sm_90.cubin');
const haveTools = cp.spawnSync('python3', ['--version']).status === 0
  && cp.spawnSync('nvdisasm', ['--version']).status === 0;
if (process.env.CUBIN_SASS_REQUIRE_CUDA === '1' && !haveTools) {
  throw new Error('CUDA CI requires python3 and nvdisasm; backend integration tests must not be skipped.');
}

test('real backend validates and recreates a recovered backup after original deletion', { skip: !haveTools }, async (t) => {
  const h = loadExtension();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cubin-sass-recovery-'));
  t.after(async () => { await h.backend.dispose(); fs.rmSync(dir, { recursive: true, force: true }); });
  const base = h.vscode.Uri.file(path.join(dir, 'base.cubin'));
  const original = fs.readFileSync(fixture);
  fs.writeFileSync(base.fsPath, original);
  const doc = new h.CubinDocument(base, original);
  const backup = await doc.backup(h.vscode.Uri.file(path.join(dir, 'backup')));
  fs.unlinkSync(base.fsPath);
  const provider = new h.Provider(h.context);
  const restored = await provider.openCustomDocument(base, { backupId: backup.id });
  assert.equal(restored.diskMissing, true);
  await provider.saveCustomDocument(restored);
  assert.equal(fs.readFileSync(base.fsPath).equals(original), true);
  assert.equal(restored.diskMissing, false);
  assert.equal(restored.savedData.equals(original), true);
});

test('virtual source save, validation, binary save and backup restore roundtrip', { skip: !haveTools }, async (t) => {
  const h = loadExtension();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cubin-sass-integration-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const base = h.vscode.Uri.file(path.join(dir, 'base.cubin'));
  const original = fs.readFileSync(fixture);
  fs.writeFileSync(base.fsPath, original);
  const doc = new h.CubinDocument(base, original);
  h.extension.activate(h.context);
  const provider = h.providers.get('cubinSass.preview');
  provider.live.set(base.toString(), { doc });
  const exported = JSON.parse(cp.execFileSync('python3', [backend, fixture, '--emit-source', '--all-sections']));
  const sourceUri = h.nvsassFS.set(base, exported.section, exported.source);
  const edited = exported.source.replace(/\.regcount \d+/, '.regcount 32');
  const source = h.sourceDoc(sourceUri, edited, true);
  assert.equal(await source.save(), true, h.errors.join('\n'));
  assert.equal(source.isDirty, false);
  assert.notEqual(doc.data.toString('hex'), original.toString('hex'));
  assert.equal(declaredBase(source.getText()), baseHash(doc.data));
  assert.equal(fs.readFileSync(base.fsPath).equals(original), true);
  // A second save uses the rebound base instead of reporting a conflict.
  source.setText(source.getText().replace('.regcount 32', '.regcount 40'));
  assert.equal(await source.save(), true, h.errors.join('\n'));
  assert.equal(declaredBase(source.getText()), baseHash(doc.data));
  await provider.saveCustomDocument(doc);
  assert.equal(fs.readFileSync(base.fsPath).equals(doc.data), true);
  const lastSaved = Buffer.from(doc.data);
  source.setText(source.getText().replace('.regcount 40', '.regcount 48'));
  assert.equal(await source.save(), true, h.errors.join('\n'));
  const backup = await doc.backup(h.vscode.Uri.file(path.join(dir, 'backup')));
  const restored = await provider.openCustomDocument(base, { backupId: backup.id });
  assert.equal(restored.data.equals(doc.data), true);
  assert.equal(restored.savedData.equals(lastSaved), true);
  const beforeFailure = Buffer.from(doc.data);
  source.setText(source.getText() + '[B------:R-:W-:-:S01] INVALID_OPCODE;\n');
  assert.equal(await source.save(), false);
  assert.equal(source.isDirty, true);
  assert.equal(doc.data.equals(beforeFailure), true);
  assert.equal(fs.readFileSync(base.fsPath).equals(lastSaved), true);
});

test('source-only saves stage full backend validation before committing to disk', { skip: !haveTools }, async (t) => {
  const h = loadExtension();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cubin-sass-integration-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const base = h.vscode.Uri.file(path.join(dir, 'base.cubin'));
  const original = fs.readFileSync(fixture);
  fs.writeFileSync(base.fsPath, original);
  fs.chmodSync(base.fsPath, 0o644);
  h.extension.activate(h.context);
  const exported = JSON.parse(cp.execFileSync('python3', [backend, fixture, '--emit-source', '--all-sections']));
  const sourceUri = h.nvsassFS.set(base, exported.section, exported.source);
  const source = h.sourceDoc(sourceUri, exported.source.replace(/\.regcount \d+/, '.regcount 32'), true);
  assert.equal(await source.save(), true, h.errors.join('\n'));
  const saved = fs.readFileSync(base.fsPath);
  assert.equal(saved.equals(original), false);
  assert.equal(declaredBase(source.getText()), baseHash(saved));
  assert.equal(fs.statSync(base.fsPath).mode & 0o777, 0o644);
  source.setText(source.getText() + '[B------:R-:W-:-:S01] INVALID_OPCODE;\n');
  assert.equal(await source.save(), false);
  assert.equal(source.isDirty, true);
  assert.equal(fs.readFileSync(base.fsPath).equals(saved), true);
  assert.deepEqual(fs.readdirSync(dir), ['base.cubin']);
});

test('multi-image sources retain identity across edits, undo, preview closure and reload', { skip: !haveTools }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cubin-sass-images-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const filename = path.join(dir, 'host');
  const original = hostWithCubins(fs.readFileSync(fixture), fs.readFileSync(fixture));
  fs.writeFileSync(filename, original);
  const inspect = (data, image) => JSON.parse(cp.execFileSync('python3', [
    backend, filename, '--stdin', '--image', String(image), '--emit-source', '--all-sections',
  ], { input: data }));
  const regcount = (data, image) => Number(/\.regcount (\d+)/.exec(inspect(data, image).source)[1]);
  const editRegcount = (source, count) => source.setText(source.getText().replace(/\.regcount \d+/, `.regcount ${count}`));
  const h = loadExtension();
  h.extension.activate(h.context);
  const base = h.vscode.Uri.file(filename);
  const doc = new h.CubinDocument(base, original);
  doc.image = 1;
  const provider = h.providers.get('cubinSass.preview');
  provider.live.set(base.toString(), { doc, panel: { active: true } });
  await h.commands.get('cubinSass.openSource')();
  const one = h.vscode.window.activeTextEditor.document;
  const firstVersion = one.getText();
  const savedUri = one.uri.toString();
  assert.equal(h.nvsassFS.imageOf(one.uri), 1);
  doc.image = 0;
  await h.commands.get('cubinSass.openSource')();
  const zero = h.vscode.window.activeTextEditor.document;
  assert.notEqual(zero.uri.toString(), savedUri);
  assert.equal(h.nvsassFS.imageOf(zero.uri), 0);
  editRegcount(zero, 40);
  assert.equal(await zero.save(), true, h.errors.join('\n'));
  // Editing image 0 must not re-export a dirty source bound to unchanged image 1.
  one.setText(one.getText() + '\n// pending image 1 draft\n');
  const draft = one.getText();
  const warnings = h.warnings.length;
  await h.rebaseSourcesFor(base, doc.data);
  assert.equal(one.getText(), draft);
  assert.equal(h.warnings.length, warnings);
  editRegcount(one, 32);
  assert.equal(await one.save(), true, h.errors.join('\n'));
  assert.equal(doc.image, 0, 'editing another image must retain the preview selection');
  assert.equal(regcount(doc.data, 0), 40);
  assert.equal(regcount(doc.data, 1), 32);
  // Undo source 1 to its original base, preserving newer bytes in image 0.
  one.setText(firstVersion);
  assert.equal(await one.save(), true, h.errors.join('\n'));
  assert.equal(regcount(doc.data, 0), 40);
  assert.equal(declaredBase(one.getText()), inspect(original, 1).base);
  await provider.saveCustomDocument(doc);
  provider.live.delete(base.toString());
  doc.dispose();
  editRegcount(one, 48);
  assert.equal(await one.save(), true, h.errors.join('\n'));
  assert.equal(regcount(fs.readFileSync(filename), 0), 40);
  assert.equal(regcount(fs.readFileSync(filename), 1), 48);
  // A new extension instance has no in-memory binding or image selection.
  const next = loadExtension();
  next.extension.activate(next.context);
  const restoredUri = next.vscode.Uri.parse(savedUri);
  const restoredText = (await next.nvsassFS.readFile(restoredUri)).toString('utf8');
  const restored = next.sourceDoc(restoredUri, restoredText);
  editRegcount(restored, 56);
  assert.equal(await restored.save(), true, next.errors.join('\n'));
  assert.equal(regcount(fs.readFileSync(filename), 0), 40);
  assert.equal(regcount(fs.readFileSync(filename), 1), 56);
  // Reopening the host on image 0 must still allow source 1 to target image 1.
  const nextBase = next.vscode.Uri.file(filename);
  const reopened = new next.CubinDocument(nextBase, fs.readFileSync(filename));
  reopened.image = 0;
  next.providers.get('cubinSass.preview').live.set(nextBase.toString(), { doc: reopened });
  editRegcount(restored, 64);
  assert.equal(await restored.save(), true, next.errors.join('\n'));
  assert.equal(reopened.image, 0);
  assert.equal(regcount(reopened.data, 0), 40);
  assert.equal(regcount(reopened.data, 1), 64);
  assert.equal(regcount(fs.readFileSync(filename), 1), 56);
});
