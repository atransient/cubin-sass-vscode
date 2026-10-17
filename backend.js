'use strict';

const cp = require('node:child_process');

/** Bounded JSON backend jobs. A slot stays occupied until its child is reaped. */
class BackendRunner {
  constructor({ concurrency = 2, maxQueued = 32, killGraceMs = 250 } = {}) {
    this.concurrency = concurrency;
    this.maxQueued = maxQueued;
    this.killGraceMs = killGraceMs;
    this.queue = [];
    this.running = new Set();
    this.tasks = new Set();
    this.byKey = new Map();
    this.disposed = false;
  }

  setConcurrency(value) {
    this.concurrency = Number.isInteger(value) ? Math.max(1, Math.min(8, value)) : 2;
    this._pump();
  }

  run(command, args, { cwd, input, timeoutMs = 120000, token, key, owner, hint = '' } = {}) {
    if (this.disposed || token?.isCancellationRequested) {
      return Promise.resolve({ ok: false, cancelled: true, error: '后台任务已取消。' });
    }
    if (key) this.cancelKey(key);
    if (this.running.size >= this.concurrency && this.queue.length >= this.maxQueued) {
      return Promise.resolve({ ok: false, infrastructureError: true,
        error: '后台任务队列已满，请稍后重试。', hint });
    }
    const job = { command, args, cwd, input, key, owner, hint, state: 'queued' };
    job.promise = new Promise((resolve) => { job.resolve = resolve; });
    this.tasks.add(job);
    if (key) this.byKey.set(key, job);
    this.queue.push(job);
    job.timer = setTimeout(() => this._cancel(job, {
      ok: false, timedOut: true, error: `后台任务超时（${timeoutMs / 1000} 秒），已取消，请重试或调整超时设置。`, hint,
    }), timeoutMs);
    job.subscription = token?.onCancellationRequested(() => this._cancel(job));
    // Also handle tokens cancelled between the initial check and subscription.
    if (token?.isCancellationRequested) this._cancel(job);
    this._pump();
    return job.promise;
  }

  cancelKey(key) {
    const job = this.byKey.get(key);
    if (job) this._cancel(job);
  }

  cancelOwner(owner) {
    for (const job of [...this.tasks]) if (job.owner === owner) this._cancel(job);
  }

  cancelAll() {
    const jobs = [...this.tasks];
    for (const job of jobs) this._cancel(job);
    return jobs.length;
  }

  dispose() {
    this.disposed = true;
    const pending = [...this.tasks].map((job) => job.promise);
    this.cancelAll();
    return Promise.all(pending);
  }

  _cancel(job, result = { ok: false, cancelled: true, error: '后台任务已取消。' }) {
    if (job.state === 'done' || job.stopped) return;
    job.stopped = result;
    clearTimeout(job.timer);
    if (job.state === 'queued') {
      this.queue.splice(this.queue.indexOf(job), 1);
      this._finish(job, result);
    } else {
      this._kill(job, 'SIGTERM');
      // Escalate if the process group ignores TERM.
      job.killTimer = setTimeout(() => this._kill(job, 'SIGKILL'), this.killGraceMs);
    }
  }

  _kill(job, signal) {
    if (!job.child?.pid) return;
    if (process.platform === 'win32') {
      if (!job.treeKillStarted) {
        job.treeKillStarted = true;
        cp.execFile('taskkill', ['/pid', String(job.child.pid), '/T', '/F'], () => {});
      }
    } else {
      try { process.kill(-job.child.pid, signal); } catch (e) {
        if (e.code !== 'ESRCH') job.child.kill(signal);
      }
    }
  }

  _pump() {
    while (!this.disposed && this.running.size < this.concurrency && this.queue.length) {
      const job = this.queue.shift();
      job.state = 'running';
      this.running.add(job);
      try {
        job.child = cp.spawn(job.command, job.args, {
          cwd: job.cwd,
          detached: process.platform !== 'win32', windowsHide: true,
        });
        const stdoutChunks = [], stderrChunks = [];
        let outputBytes = 0;
        const collect = (chunks) => (chunk) => {
          outputBytes += chunk.length;
          if (outputBytes > 64 * 1024 * 1024) {
            this._cancel(job, { ok: false, infrastructureError: true,
              error: '后台输出超过 64 MiB，任务已终止。', hint: job.hint });
          } else chunks.push(chunk);
        };
        job.child.stdout.on('data', collect(stdoutChunks));
        job.child.stderr.on('data', collect(stderrChunks));
        job.child.on('error', (err) => { job.spawnError = err; });
        job.child.on('close', (code, signal) => {
          if (job.state === 'done') return;
          if (job.stopped) return this._finish(job, job.stopped);
          const stdout = Buffer.concat(stdoutChunks).toString('utf8');
          const stderr = Buffer.concat(stderrChunks).toString('utf8');
          const err = job.spawnError || (code !== 0
            ? new Error(`后台进程退出：${signal || code}`) : null);
          if (err) this._kill(job, 'SIGKILL');
          let result;
          try {
            result = JSON.parse(stdout);
            if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('invalid JSON response');
            if (err && result.ok !== false) throw err;
          } catch {
            result = { ok: false, infrastructureError: true,
              error: err
                ? (stderr || err.message || '').trim().split('\n').slice(-3).join('\n')
                : `脚本输出不是有效的 JSON 对象: ${String(stdout).slice(0, 300)}` };
          }
          if (result.ok === false && !result.hint) result.hint = job.hint;
          this._finish(job, result);
        });
        // A backend may reject input or fail to spawn before stdin is consumed.
        job.child.stdin.on('error', () => {});
        job.child.stdin.end(job.input);
        job.input = null;
      } catch (e) {
        this._kill(job, 'SIGKILL');
        this._finish(job, { ok: false, infrastructureError: true, error: e.message, hint: job.hint });
      }
    }
  }

  _finish(job, result) {
    if (job.state === 'done') return;
    job.state = 'done';
    clearTimeout(job.timer);
    clearTimeout(job.killTimer);
    // Python can exit before a descendant which does not inherit its stdio.
    if (job.stopped) this._kill(job, 'SIGKILL');
    job.subscription?.dispose();
    job.input = null;
    this.running.delete(job);
    this.tasks.delete(job);
    if (job.key && this.byKey.get(job.key) === job) this.byKey.delete(job.key);
    job.resolve(result);
    this._pump();
  }
}

module.exports = { BackendRunner };
