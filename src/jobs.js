// In-memory anchor jobs. A job exposes the four rholo evidence rungs so the UI
// can show what is submitted, executed, included and observed — separately.

import { randomBase64Url } from './crypto.js';

export const ANCHOR_STEPS = [
  { key: 'validated', label: 'Signature and sequence checked' },
  { key: 'submitted', label: 'Deploy accepted by rholo' },
  { key: 'executed', label: 'Executed without error' },
  { key: 'included', label: 'Included in a block' },
  { key: 'observed', label: 'Observed at the DID anchor name' },
];

export class JobStore {
  constructor({ ttlMs = 10 * 60 * 1000 } = {}) {
    this.ttlMs = ttlMs;
    this.jobs = new Map();
    this.timer = setInterval(() => this.sweep(), 60 * 1000);
    this.timer.unref?.();
  }

  create({ kind, did = null, event = null, steps = ANCHOR_STEPS }) {
    const now = new Date().toISOString();
    const job = {
      id: randomBase64Url(12),
      kind,
      did,
      eventId: event?.id || null,
      eventSeq: event?.seq || null,
      eventType: event?.type || null,
      status: 'queued',
      steps: steps.map((step) => ({ ...step, status: 'pending', detail: '' })),
      createdAt: now,
      updatedAt: now,
      error: null,
      receipt: null,
      resolution: null,
    };
    this.jobs.set(job.id, job);
    return job;
  }

  get(id) {
    return this.jobs.get(id) || null;
  }

  update(id, patch) {
    const job = this.get(id);
    if (!job) return null;
    Object.assign(job, patch, { updatedAt: new Date().toISOString() });
    return job;
  }

  setStep(id, key, status, detail = '') {
    const job = this.get(id);
    if (!job) return null;
    const step = job.steps.find((candidate) => candidate.key === key);
    if (step) {
      step.status = status;
      if (detail) step.detail = detail;
    }
    job.updatedAt = new Date().toISOString();
    return job;
  }

  fail(id, error) {
    const job = this.get(id);
    if (!job) return null;
    const active = job.steps.find((step) => step.status === 'active');
    if (active) active.status = 'failed';
    job.status = 'error';
    job.error = {
      code: error.code || 'anchor-failed',
      message: error.message || String(error),
      ...(error.resolution ? { resolution: error.resolution } : {}),
    };
    job.updatedAt = new Date().toISOString();
    return job;
  }

  run(id, fn) {
    this.update(id, { status: 'running' });
    Promise.resolve()
      .then(fn)
      .then((result) => {
        const job = this.get(id);
        if (!job) return;
        job.status = 'done';
        job.receipt = result?.receipt || null;
        job.resolution = result?.resolution || null;
        job.updatedAt = new Date().toISOString();
        for (const step of job.steps) step.status = 'done';
      })
      .catch((error) => this.fail(id, error));
    return this.get(id);
  }

  sweep() {
    const cutoff = Date.now() - this.ttlMs;
    for (const [id, job] of this.jobs) {
      if (Date.parse(job.updatedAt) < cutoff) this.jobs.delete(id);
    }
  }
}
