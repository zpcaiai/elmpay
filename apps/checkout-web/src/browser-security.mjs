import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';

const sriPattern = /^sha384-[A-Za-z0-9+/]{64}$/;
const digestPattern = /^[0-9a-f]{64}$/;
const safeSourcePattern = /^\/[A-Za-z0-9._/-]+\.mjs$/;
const integrityReasons = new Set([
  'POLICY_UNAVAILABLE', 'UNAUTHORIZED_SCRIPT_ELEMENT', 'DUPLICATE_SCRIPT_ELEMENT',
  'SCRIPT_SRI_MISMATCH', 'ALLOWLISTED_SCRIPT_MISSING',
]);

function exactKeys(value, expected) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}

function sha384(bytes) {
  return `sha384-${createHash('sha384').update(bytes).digest('base64')}`;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function safeAsset(root, source) {
  if (!safeSourcePattern.test(source) || source.includes('..')) throw new Error('unsafe script source');
  const path = resolve(root, source.slice(1));
  const canonicalRoot = resolve(root);
  if (path !== canonicalRoot && !path.startsWith(`${canonicalRoot}${sep}`)) throw new Error('script leaves public root');
  return path;
}

function cleanUrl(value) {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const url = new URL(value);
    if (!['https:', 'http:'].includes(url.protocol)) return null;
    return `${url.origin}${url.pathname}`.slice(0, 512);
  } catch { return null; }
}

export class BrowserSecurityRuntime {
  constructor({ publicRoot, manifestPath, now = new Date() }) {
    this.publicRoot = resolve(publicRoot);
    this.manifestPath = manifestPath;
    let manifest;
    try { manifest = JSON.parse(readFileSync(manifestPath, 'utf8')); } catch { throw new Error('browser script manifest unavailable'); }
    if (!exactKeys(manifest, ['schemaVersion', 'manifestVersion', 'reviewExpiresAt', 'pageTemplateSha256',
      'trustedTypesPolicy', 'scripts', 'externalAssessmentStatus']) || manifest.schemaVersion !== 1
      || !/^[A-Za-z0-9._:-]{1,128}$/.test(manifest.manifestVersion)
      || manifest.trustedTypesPolicy !== 'elmpay-checkout'
      || !digestPattern.test(manifest.pageTemplateSha256)
      || !['BLOCKED', 'VERIFIED'].includes(manifest.externalAssessmentStatus)
      || !Array.isArray(manifest.scripts) || manifest.scripts.length === 0
      || !Number.isFinite(Date.parse(manifest.reviewExpiresAt)) || Date.parse(manifest.reviewExpiresAt) <= now.getTime()) {
      throw new Error('browser script manifest is invalid or expired');
    }
    this.manifestVersion = manifest.manifestVersion;
    this.templateDigest = manifest.pageTemplateSha256;
    this.scripts = new Map();
    for (const item of manifest.scripts) {
      if (!exactKeys(item, ['id', 'source', 'sri', 'owner', 'purpose', 'reviewExpiresAt', 'thirdParty',
        'executionContext', 'privileges']) || typeof item.id !== 'string' || item.id.length === 0
        || typeof item.owner !== 'string' || item.owner.length === 0
        || typeof item.purpose !== 'string' || item.purpose.length === 0
        || !sriPattern.test(item.sri) || typeof item.thirdParty !== 'boolean'
        || !Array.isArray(item.privileges) || item.privileges.length === 0
        || !Number.isFinite(Date.parse(item.reviewExpiresAt)) || Date.parse(item.reviewExpiresAt) <= now.getTime()
        || (item.thirdParty ? item.executionContext !== 'isolated-frame' : item.executionContext !== 'main')
        || this.scripts.has(item.source)) throw new Error('browser script allowlist entry is invalid');
      const path = safeAsset(this.publicRoot, item.source);
      if (sha384(readFileSync(path)) !== item.sri) throw new Error(`browser script digest mismatch: ${item.id}`);
      this.scripts.set(item.source, Object.freeze({ id: item.id, source: item.source, sri: item.sri }));
    }
    if (!this.scripts.has('/integrity.mjs') || !this.scripts.has('/checkout.mjs')) {
      throw new Error('mandatory checkout scripts are not allowlisted');
    }
    this.verifyTemplate();
  }

  nonce() { return randomBytes(18).toString('base64url'); }

  verifyTemplate() {
    const bytes = readFileSync(resolve(this.publicRoot, 'index.html'));
    if (sha256(bytes) !== this.templateDigest) throw new Error('checkout page template digest mismatch');
    return bytes.toString('utf8');
  }

  verifyScript(pathname) {
    const entry = this.scripts.get(pathname);
    if (!entry) throw new Error('script is not allowlisted');
    const bytes = readFileSync(safeAsset(this.publicRoot, pathname));
    if (sha384(bytes) !== entry.sri) throw new Error('script integrity changed after startup');
    return bytes;
  }

  renderIndex(nonce) {
    if (!/^[A-Za-z0-9_-]{24}$/.test(nonce)) throw new Error('CSP nonce is invalid');
    let html = this.verifyTemplate().replaceAll('__CSP_NONCE__', nonce);
    for (const entry of this.scripts.values()) {
      const token = `__SRI_${entry.source.slice(1).replaceAll('.', '_').toUpperCase()}__`;
      html = html.replaceAll(token, entry.sri);
    }
    if (html.includes('__CSP_NONCE__') || /__SRI_[A-Z0-9_]+__/.test(html)) {
      throw new Error('checkout template contains unresolved integrity tokens');
    }
    return Buffer.from(html, 'utf8');
  }

  csp(nonce) {
    return [
      "default-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'",
      "connect-src 'self'", "img-src 'self' data:", "style-src 'self'",
      `script-src 'nonce-${nonce}' 'strict-dynamic'`, "require-trusted-types-for 'script'",
      "trusted-types elmpay-checkout", 'report-uri /security/csp-report', 'report-to elmpay-csp',
    ].join('; ');
  }

  publicPolicy() {
    return {
      manifestVersion: this.manifestVersion,
      trustedTypesPolicy: 'elmpay-checkout',
      scripts: [...this.scripts.values()].map(({ source, sri }) => ({ source, sri })),
    };
  }

  sanitizeReport(value, now = new Date()) {
    if (Array.isArray(value)) {
      if (value.length !== 1 || !value[0] || value[0].type !== 'csp-violation'
          || !value[0].body || Object.getPrototypeOf(value[0].body) !== Object.prototype) {
        throw new Error('Reporting API payload is invalid');
      }
      const entry = value[0]; const body = entry.body;
      const directive = body.effectiveDirective ?? body.violatedDirective;
      if (typeof directive !== 'string' || !/^[a-z-]{3,64}$/.test(directive)) {
        throw new Error('CSP directive is invalid');
      }
      return {
        reportId: randomUUID(), occurredAt: now.toISOString(), category: 'CSP',
        policyVersion: this.manifestVersion, directive,
        disposition: body.disposition === 'report' ? 'report' : 'enforce',
        document: cleanUrl(body.documentURL ?? entry.url), blocked: cleanUrl(body.blockedURL),
      };
    }
    if (!value || Object.getPrototypeOf(value) !== Object.prototype) throw new Error('security report is invalid');
    if (exactKeys(value, ['type', 'policyVersion', 'reasons']) || exactKeys(value, ['type', 'reasons'])) {
      if (!['PAGE_INTEGRITY', 'PAGE_MUTATION', 'POLICY_UNAVAILABLE'].includes(value.type)
          || (value.policyVersion !== undefined && value.policyVersion !== this.manifestVersion)
          || !Array.isArray(value.reasons) || value.reasons.length < 1 || value.reasons.length > 16
          || value.reasons.some(reason => !integrityReasons.has(reason))) throw new Error('integrity report is invalid');
      return {
        reportId: randomUUID(), occurredAt: now.toISOString(), category: 'BROWSER_INTEGRITY',
        type: value.type, policyVersion: value.policyVersion ?? this.manifestVersion,
        reasons: [...new Set(value.reasons)].sort(),
      };
    }
    const csp = value['csp-report'];
    if (!csp || Object.getPrototypeOf(csp) !== Object.prototype) throw new Error('CSP report is invalid');
    const directive = csp['effective-directive'] ?? csp['violated-directive'];
    if (typeof directive !== 'string' || !/^[a-z-]{3,64}$/.test(directive)) throw new Error('CSP directive is invalid');
    return {
      reportId: randomUUID(), occurredAt: now.toISOString(), category: 'CSP',
      policyVersion: this.manifestVersion, directive,
      disposition: csp.disposition === 'report' ? 'report' : 'enforce',
      document: cleanUrl(csp['document-uri']), blocked: cleanUrl(csp['blocked-uri']),
    };
  }
}
