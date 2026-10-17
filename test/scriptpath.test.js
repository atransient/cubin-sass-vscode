'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { resolveScriptPath } = require('../scriptpath.js');

test('默认脚本跟随扩展软连接的真实目标，与当前工作区无关', () => {
  const wanted = '/checkout/cubin-sass-vscode/scripts/cubin_sass.py';
  const got = resolveScriptPath({
    configured: 'scripts/cubin_sass.py',
    resourcePath: '/some/other/project/kernel.cubin',
    workspaceRoot: '/some/other/project',
    extensionDir: '/extensions/atransient.cubin-sass-0.1.0',
    realpath: () => '/checkout/cubin-sass-vscode',
    exists: (p) => p === wanted,
  });
  assert.equal(got, wanted);
});

test('显式绝对配置优先于开发软连接', () => {
  const got = resolveScriptPath({
    configured: '/opt/cubin/backend.py',
    resourcePath: '/work/kernel.cubin',
    workspaceRoot: '/work',
    extensionDir: '/extension',
    realpath: () => { throw new Error('不该查询软连接'); },
  });
  assert.equal(got, '/opt/cubin/backend.py');
});

test('自定义相对配置保持按工作区解析', () => {
  const got = resolveScriptPath({
    configured: 'dev/backend.py',
    resourcePath: '/work/out/kernel.cubin',
    workspaceRoot: '/work',
    extensionDir: '/extension',
    realpath: () => '/checkout/cubin-sass-vscode',
    exists: (p) => p === '/work/dev/backend.py',
  });
  assert.equal(got, '/work/dev/backend.py');
});

test('不从 cubin 所在目录向上找脚本：打开的文件不能决定执行哪段代码', () => {
  const planted = (p) => p.startsWith('/downloads/');
  // 自定义相对路径：只按工作区解析；没有工作区就按扩展目录
  assert.equal(resolveScriptPath({
    configured: 'tools/backend.py',
    resourcePath: '/downloads/repo/out/kernel.cubin',
    extensionDir: '/installed/cubin-sass',
    realpath: (p) => p,
    exists: planted,
  }), '/installed/cubin-sass/tools/backend.py');
  // 默认路径：扩展自带的后端缺失时也不退回工作区里的同名脚本
  assert.equal(resolveScriptPath({
    configured: 'scripts/cubin_sass.py',
    resourcePath: '/downloads/repo/kernel.cubin',
    workspaceRoot: '/downloads/repo',
    extensionDir: '/installed/cubin-sass',
    realpath: (p) => p,
    exists: planted,
  }), '/installed/cubin-sass/scripts/cubin_sass.py');
});

test('安装目录直接包含后端，不依赖工作区或原仓库', () => {
  const path = require('node:path');
  const extensionDir = path.resolve(__dirname, '..');
  assert.equal(resolveScriptPath({
    resourcePath: '/unrelated/kernel.cubin',
    workspaceRoot: '/unrelated',
    extensionDir,
  }), path.join(extensionDir, 'scripts', 'cubin_sass.py'));
});
