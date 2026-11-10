// functions/build-attest.js
// The one implementation of "is this build what we shipped?".
//
// ── Why this replaces the old anchor scheme ────────────────────────────────────
// The previous design stamped ANCHOR = sha256(build-hashes.json) into the guards,
// and build-hashes.json held the hash of every other file. All three artifacts ship
// together, so an attacker could edit a file, update its hash in build-hashes.json,
// recompute the anchor, and patch that in — the chain was self-referential and had no
// root of trust.
//
// Now build-hashes.json is ES256-signed with a key that exists only on the release
// machine. Editing the manifest invalidates the signature, and producing a valid one
// requires the private key. That is a value the attacker cannot compute.
//
// ── Honest limits ─────────────────────────────────────────────────────────────
// This code ships inside the bundle it checks, so a determined attacker can still
// patch THIS FILE to return ok:true. That is irreducible for any client-side check.
// It is why the digest returned here is also sent to the Worker and checked against a
// server-side allowlist: skipping the check locally does not make the server accept
// the build. See server/src/process.js.
//
// ── Tri-state integrity ───────────────────────────────────────────────────────
//   'ok'      — full sweep passed, build is intact.
//   'unknown' — not yet verified, or a transient I/O failure (SW cold start).
//               Callers MUST NOT block features in this state.
//   'failed'  — confirmed tamper (bad signature, hash mismatch). TOTAL LOCKDOWN.
//
// The design rule: 'unknown' is NOT evidence of tampering. A cold-SW fetch blip
// is not a security event. Only 'failed' triggers lockdown.
'use strict';

const BUILD_PUBLIC_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'ZFgFWayMmv3R8LjroZYbUHSOUv_FQTQtBcEtTuodwQw',
  y: 'uzQXpG7YIHBF6M5EVDk-9PsX7q5-dySAU9C68anCOj8',
};

const MANIFEST_PATH = 'build-hashes.json';
const SIG_PATH = 'build-hashes.sig';
const RETRY_AFTER_PERMANENT_FAILURE_MS = 60_000;
const RETRY_AFTER_TRANSIENT_FAILURE_MS = 10_000;

const enc = new TextEncoder();
const dec = new TextDecoder();

let _result = null;              // { ok, digest, reason } — set ONLY on success or permanent fail
let _lastPermanentFailureAt = 0;
let _lastTransientFailureAt = 0;
let _lastTransientReason = null;
let _inFlight = null;
let _verifiedAt = 0;              // timestamp of last successful verification

// How long an ok result is trusted before the NEXT attest() call re-verifies.
// The hot message-router path no longer awaits a sweep (it reads the latched
// tri-state synchronously via integrityState()), so this TTL now only governs
// the occasional re-sweep triggered by a fresh ASHEO_INTEGRITY_CHECK (per-frame
// boot) or a premium buildDigest() call. Keeping it at 60s meant a full ~15MB
// fetch+hash sweep of every packaged file roughly once a minute of active
// browsing, on the service worker — a real, ongoing perf tax. 10 min keeps a
// periodic tamper-while-alive self-check (a full reload always re-verifies from
// cold, and the server-side digest allowlist is the authoritative gate) while
// cutting that sweep churn ~10x.
const CACHE_OK_TTL_MS = 600_000; // 10 minutes

function fromB64url(str) {
  let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Hex(buf) {
  const d = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function verifyJws(jws, jwk) {
  const parts = String(jws || '').trim().split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  try {
    const key = await crypto.subtle.importKey(
      'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
    );
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, key, fromB64url(s), enc.encode(`${h}.${p}`)
    );
    if (!ok) return null;
    return JSON.parse(dec.decode(fromB64url(p)));
  } catch {
    return null;
  }
}

// Retry a fetch for extension resources. SW cold starts can trigger transient
// fetch failures (Chrome's SW I/O layer isn't ready for the first few seconds).
// Retrying with backoff absorbs the blip without masking a real missing file.
async function _fetchWithRetry(rel, tries) {
  tries = Math.max(1, Number(tries) || 3);
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try {
      if (i > 0) await new Promise(function (r) { setTimeout(r, Math.pow(2, i) * 1000); }); // 1s, 2s, 4s
      const res = await fetch(chrome.runtime.getURL(rel));
      if (!res.ok) throw new Error(rel + ': HTTP ' + res.status);
      return res;
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error(rel + ': fetch failed after ' + tries + ' attempts');
}

async function fetchPacked(rel) { return _fetchWithRetry(rel, 3); }

// ── Transient vs permanent failure ─────────────────────────────────────────────
// Transient: fetch I/O errors — the build may be fine, Chrome just isn't ready.
//   NEVER sets _result. integrityState() stays 'unknown'. Self-heals.
// Permanent: content validation errors — the build IS tampered.
//   Sets _result. integrityState() becomes 'failed'. TOTAL LOCKDOWN.
const TRANSIENT_REASONS = new Set(['manifest-missing', 'signature-missing', 'file-missing']);

function _isTransient(reason) { return TRANSIENT_REASONS.has(reason); }

async function _run(_opts) {
  const opts = _opts || {};
  const files = opts.files;

  const transientFail = function (reason, detail) {
    _lastTransientFailureAt = Date.now();
    _lastTransientReason = reason;
    try { console.warn('[asheo attest] TRANSIENT:', reason, detail || ''); } catch (_) {}
    // DO NOT set _result — caller gets {ok:false} but integrityState() stays 'unknown'.
    return { ok: false, digest: null, reason: reason };
  };

  const permanentFail = function (reason, detail) {
    _lastPermanentFailureAt = Date.now();
    _result = { ok: false, digest: null, reason: reason };
    try { console.error('[asheo attest] FAILED:', reason, detail || ''); } catch (_) {}
    return _result;
  };

  try {
    if (!(globalThis.chrome && chrome.runtime && chrome.runtime.getURL) || !crypto || !crypto.subtle) {
      return permanentFail('environment', 'chrome.runtime or crypto.subtle unavailable');
    }

    // 1. The manifest, and the digest that identifies this build.
    var manifestText;
    try { manifestText = await (await fetchPacked(MANIFEST_PATH)).text(); }
    catch (e) { return transientFail('manifest-missing', e && e.message ? e.message : e); }
    var digest = await sha256Hex(enc.encode(manifestText));

    // 2. The signature. Unsigned build = failed build.
    var sig;
    try { sig = (await (await fetchPacked(SIG_PATH)).text()).trim(); }
    catch (e) { return transientFail('signature-missing', e && e.message ? e.message : e); }

    var claim = await verifyJws(sig, BUILD_PUBLIC_JWK);
    if (!claim) return permanentFail('signature-invalid', 'JWS did not verify against the build key');
    if (claim.manifestHash !== digest) {
      return permanentFail('manifest-tampered',
        'signed ' + String(claim.manifestHash).slice(0, 16) + '… != actual ' + digest.slice(0, 16) + '…');
    }

    // 3. Parse and sanity-check the manifest.
    var manifest;
    try { manifest = JSON.parse(manifestText); }
    catch (e) { return permanentFail('manifest-parse', e && e.message ? e.message : e); }
    var entries = Array.isArray(manifest.files) ? manifest.files : null;
    if (!entries) return permanentFail('manifest-shape', 'files[] missing');
    if (Number(claim.fileCount) !== entries.length) {
      return permanentFail('file-count', 'signed ' + claim.fileCount + ', got ' + entries.length);
    }

    // 4. Sweep. Full check of every file in the manifest — no shortcuts, no sampling.
    // A partial check is a partial answer, and this system exists to leave no gap.
    var wanted = (files && files.length)
      ? entries.filter(function (e) { return files.indexOf(e.path) >= 0; })
      : entries;

    if (files && files.length && wanted.length !== files.length) {
      var present = new Set(wanted.map(function (e) { return e.path; }));
      var missing = files.filter(function (f) { return !present.has(f); });
      return permanentFail('critical-file-absent', missing.join(', '));
    }

    for (var i = 0; i < wanted.length; i++) {
      var entry = wanted[i];
      var p = String(entry && entry.path ? entry.path : '');
      var want = String(entry && entry.sha256 ? entry.sha256 : '');
      if (!p || !want) return permanentFail('bad-entry', p || '(empty path)');
      var buf;
      try { buf = await (await fetchPacked(p)).arrayBuffer(); }
      catch (e) { return transientFail('file-missing', p + ': ' + (e && e.message ? e.message : e)); }
      var got = await sha256Hex(buf);
      if (got !== want) return permanentFail('file-modified', p);
    }

    // Success.
    _result = { ok: true, digest: digest, reason: null };
    _verifiedAt = Date.now();
    _lastTransientFailureAt = 0;
    _lastTransientReason = null;
    return _result;
  } catch (e) {
    return permanentFail('exception', e && e.message ? e.message : e);
  }
}

// ── Public API ─────────────────────────────────────────────────────────────────

// Fast digest path: the full sweep fetches every packaged file (~15MB) to
// detect local tampering, but the DIGEST the server checks needs only the
// manifest + signature — the ES256 JWS proves the manifest is genuine and
// sha256(manifest) IS the digest. On a cold service worker the sweep can lose
// the race against the first bootstrap (MV3 I/O not ready) and returned
// digest:null, which the server saw as an empty x-asheo-build and403'd the
// enc pack as build-not-recognized. JWS-verified — cannot be forged without
// the build key; a tampered manifest fails the manifestHash check, same as
// in the full sweep.
var _fastDigest = null; // { digest, at } — cached for the OK TTL

async function _fastVerifiedDigest() {
 try {
 if (_fastDigest && (Date.now() - _fastDigest.at) < CACHE_OK_TTL_MS) return _fastDigest.digest;
 if (!(globalThis.chrome && chrome.runtime && chrome.runtime.getURL) || !crypto || !crypto.subtle) return;
 var manifestText = await (await fetchPacked(MANIFEST_PATH)).text();
 var sig = (await (await fetchPacked(SIG_PATH)).text()).trim();
 var digest = await sha256Hex(enc.encode(manifestText));
 var claim = await verifyJws(sig, BUILD_PUBLIC_JWK);
 if (!claim || claim.manifestHash !== digest) return; // tampered or unverifiable — no fast path
 _fastDigest = { digest: digest, at: Date.now() };
 return digest;
 } catch (_) { return; }
}

export async function attest(opts) {
  // Success is cached with a short TTL. After CACHE_OK_TTL_MS, force a fresh
  // sweep. This catches tampering that occurs while the SW is alive.
  if (_result && _result.ok) {
    if (_verifiedAt > 0 && (Date.now() - _verifiedAt) < CACHE_OK_TTL_MS) {
      return _result;
    }
    resetVerification();
  }

  // Permanent failure cooldown.
  if (_result && !_result.ok && (Date.now() - _lastPermanentFailureAt) < RETRY_AFTER_PERMANENT_FAILURE_MS) {
    return _result;
  }

  // Transient failure backoff — don't hammer fetch(), but don't latch either.
  if (_lastTransientFailureAt > 0 && (Date.now() - _lastTransientFailureAt) < RETRY_AFTER_TRANSIENT_FAILURE_MS) {
    return { ok: false, digest: null, reason: _lastTransientReason || 'transient' };
  }

  // Dedup in-flight verification.
  if (_inFlight) return _inFlight;
  _inFlight = _run(opts).finally(function () { _inFlight = null; });
  return _inFlight;
}

export async function buildDigest(opts) {
 // v2 ordering: the fast path FIRST. It is two small fetches (manifest+sig)
 // versus the sweep's ~86 — and the digest the server needs is exactly
 // sha256(JWS-verified manifest). Trying attest() first meant the transient
 // backoff window (10s) or a cold-sweep loss produced digest:null even though
 // the fast path would have answered in milliseconds. Sweep still runs for
 // tamper state; only its result is authoritative when it CAN complete.
 var fast = await _fastVerifiedDigest();
 if (fast) return fast;
 var r = await attest(opts);
 if (r.ok) return r.digest;
 // Permanent failure (confirmed tamper — _result latched) → null, by design.
 if (r.ok === false && _result && !_result.ok) return null;
 // Transient: fall through (fast path already failed above — nothing more).
 return null;
}

export function lastResult() { return _result; }

/**
 * Tri-state: 'unknown' | 'ok' | 'failed'.
 *   'unknown' — not yet verified, or transient failure. NEVER block features.
 *   'ok'      — verified and intact.
 *   'failed'  — confirmed tamper. TOTAL LOCKDOWN.
 */
export function integrityState() {
  var r = lastResult();
  if (!r) {
    // Kick off verification on first access (fire-and-forget).
    attest().catch(function () {});
    return 'unknown';
  }
  return r.ok ? 'ok' : 'failed';
}

export function failureReason() {
  var r = lastResult();
  return (r && !r.ok) ? r.reason : null;
}

// Reset the in-memory cache so the next attest() call does a fresh full sweep.
// Called by the periodic integrity re-check alarm to detect tampering that
// occurred while the SW was alive (the _result cache is per-SW-lifetime).
export function resetVerification() {
  _result = null;
  _lastPermanentFailureAt = 0;
  _lastTransientFailureAt = 0;
  _lastTransientReason = null;
}
