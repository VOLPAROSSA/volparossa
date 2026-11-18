// SPDX-License-Identifier: GPL-3.0-only
// Explicit disposable-fixture instrumentation; never retries or consumes a body.
import { closeSync, constants, fstatSync, openSync, writeFileSync } from 'node:fs';

export const MAX_RETRY_SECONDS = 7 * 24 * 60 * 60;
export const MAX_RECEIPT_BYTES = 1024;
const PRODUCTS = Object.freeze({
  weather: { origin: 'https://data.ecmwf.int', sidecar: 'weather-origin-http.json' },
  air_quality: { origin: 'https://noaa-gefs-pds.s3.amazonaws.com', sidecar: 'air-quality-origin-http.json' },
});
const STATES = new Set(['valid-seconds', 'valid-date', 'missing', 'malformed', 'out-of-range']);
const KEYS = ['schema', 'kind', 'product', 'status', 'observed_at_ms', 'retry_after_state', 'retry_not_before_ms'].sort();
const epoch = value => Number.isSafeInteger(value) && Math.abs(value) <= 8640000000000000;
const observedEpoch = value => epoch(value) && value >= 0;
const productInfo = product => typeof product === 'string' && Object.hasOwn(PRODUCTS, product) ? PRODUCTS[product] : null;

export function parseRetryAfter(value, observedAt) {
  if (!observedEpoch(observedAt)) throw new TypeError('invalid observation clock');
  const result = (state, until = null) => ({ retry_after_state: state, retry_not_before_ms: until });
  if (value === null) return result('missing');
  if (typeof value !== 'string' || value.length > 128 || !/^[\x20-\x7e]+$/.test(value)) {
    return result('malformed');
  }
  if (/^\d+$/.test(value)) {
    // BigInt avoids rounding large/overflowed advice into an earlier usable time.
    const seconds = BigInt(value);
    if (seconds > BigInt(MAX_RETRY_SECONDS)) return result('out-of-range');
    const until = observedAt + Number(seconds) * 1000;
    return epoch(until) ? result('valid-seconds', until) : result('out-of-range');
  }
  // Only canonical IMF-fixdate. Roundtrip rejects weekday and calendar rollover.
  if (!/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value)) {
    return result('malformed');
  }
  const until = Date.parse(value);
  if (!epoch(until) || new Date(until).toUTCString() !== value) return result('malformed');
  if (until - observedAt > MAX_RETRY_SECONDS * 1000) return result('out-of-range');
  // Past absolute guidance is preserved, not converted into permission to retry.
  return result('valid-date', until);
}

function encodeReceipt(receipt) {
  if (!receipt || Object.keys(receipt).sort().join(',') !== KEYS.join(',')
    || receipt.schema !== 1 || receipt.kind !== 'weather-source-rate-limit'
    || !productInfo(receipt.product) || receipt.status !== 429 || !observedEpoch(receipt.observed_at_ms)
    || !STATES.has(receipt.retry_after_state)) throw new TypeError('invalid source diagnostic');
  const until = receipt.retry_not_before_ms;
  if (receipt.retry_after_state.startsWith('valid-')) {
    if (!epoch(until) || until - receipt.observed_at_ms > MAX_RETRY_SECONDS * 1000
      || (receipt.retry_after_state === 'valid-seconds'
        ? until < receipt.observed_at_ms || (until - receipt.observed_at_ms) % 1000 !== 0
        : until % 1000 !== 0)) throw new TypeError('invalid retry guidance');
  } else if (until !== null) throw new TypeError('unknown retry guidance must remain unknown');
  const raw = Buffer.from(`${JSON.stringify(receipt)}\n`);
  if (raw.length > MAX_RECEIPT_BYTES) throw new TypeError('oversized source diagnostic');
  return raw;
}

export function writeReceipt(receipt, directory = process.cwd()) {
  const raw = encodeReceipt(receipt);
  // Anchor creation to one already-open private directory, never follow a sidecar
  // symlink or overwrite prior evidence. The parent owns the fixed publisher cwd.
  const folder = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  let file;
  try {
    const info = fstatSync(folder);
    if (info.uid !== process.getuid() || (info.mode & 0o777) !== 0o700) {
      throw new TypeError('private source diagnostic directory required');
    }
    file = openSync(`/proc/self/fd/${folder}/${productInfo(receipt.product).sidecar}`,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const created = fstatSync(file);
    if (created.uid !== process.getuid() || created.nlink !== 1 || (created.mode & 0o777) !== 0o600) {
      throw new TypeError('private source diagnostic file required');
    }
    writeFileSync(file, raw);
  } finally {
    if (file !== undefined) closeSync(file);
    closeSync(folder);
  }
}

export function observeFetch(fetcher, { product, now = Date.now, emit = writeReceipt } = {}) {
  const info = productInfo(product);
  if (!info || typeof fetcher !== 'function') throw new TypeError('invalid source observer');
  let attempted = false;
  return async function (...args) {
    let started;
    try { started = now(); } catch { /* Diagnostics must not replace fetch errors. */ }
    const response = await Reflect.apply(fetcher, this, args);
    try {
      if (attempted || typeof args[0] !== 'string') return response;
      const input = new URL(args[0]);
      if (input.origin !== info.origin || input.username || input.password
        || response.url !== args[0] || response.redirected !== false || response.status !== 429) return response;
      attempted = true;
      const observedAt = now();
      if (!observedEpoch(started) || !observedEpoch(observedAt) || observedAt < started) return response;
      emit({ schema: 1, kind: 'weather-source-rate-limit', product, status: 429,
        observed_at_ms: observedAt, ...parseRetryAfter(response.headers.get('retry-after'), observedAt) });
    } catch { /* Missing/invalid metadata is not a new source failure. */ }
    return response;
  };
}

// No query means a side-effect-free library import. The core supplies only this
// fixed product selector via explicit --import, not environment or CLI rewriting.
const self = new URL(import.meta.url);
if (self.search || self.hash) {
  const product = self.searchParams.get('product');
  if (self.hash || !productInfo(product) || self.search !== `?product=${product}`) {
    throw new TypeError('invalid source observer bootstrap');
  }
  globalThis.fetch = observeFetch(globalThis.fetch, { product });
}
