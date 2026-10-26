import { closeSync, constants, fstatSync, openSync, readSync, realpathSync } from 'node:fs';
import { request as httpsRequest, Agent } from 'node:https';
import { createSecureContext } from 'node:tls';
import { dirname, sep } from 'node:path';

const maximumCredentialBytes = 128 * 1024;
const maximumResponseBytes = 1024 * 1024;

export function readMountedCredential(path, name) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.includes('\0')) {
    throw new Error(`${name} path must be absolute`);
  }
  const directory = realpathSync(dirname(path));
  const resolved = realpathSync(path);
  if (!(resolved === directory || resolved.startsWith(`${directory}${sep}`))) {
    throw new Error(`${name} must remain inside its read-only mount`);
  }
  const fd = openSync(resolved, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const metadata = fstatSync(fd);
    if (!metadata.isFile() || (metadata.mode & 0o222) !== 0 || metadata.size < 1
        || metadata.size > maximumCredentialBytes) {
      throw new Error(`${name} must be a bounded read-only regular file`);
    }
    const bytes = Buffer.alloc(metadata.size + 1);
    let size = 0;
    while (size < bytes.length) {
      const count = readSync(fd, bytes, size, bytes.length - size, null);
      if (count === 0) break;
      size += count;
    }
    const after = fstatSync(fd);
    if (size !== metadata.size || after.size !== metadata.size || after.mode !== metadata.mode
        || after.mtimeMs !== metadata.mtimeMs || after.ctimeMs !== metadata.ctimeMs) {
      bytes.fill(0);
      throw new Error(`${name} changed during its bounded read`);
    }
    return bytes.subarray(0, size);
  } finally { closeSync(fd); }
}

function boundedBody(body) {
  if (body === undefined || body === null) return undefined;
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(body);
  if (bytes.byteLength > 32_768) throw new Error('edge request body is too large');
  return bytes;
}

/** Creates one origin-pinned TLS 1.3 client. Node never follows redirects for https.request. */
export function createEdgeTransport({ apiBaseUrl, certificateFile, privateKeyFile,
  trustBundleFile, serverName }) {
  const base = new URL(apiBaseUrl);
  if (base.protocol !== 'https:' || base.username || base.password || base.hash || base.search
      || base.pathname !== '/'
      || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(base.hostname)
      || serverName !== base.hostname) {
    throw new Error('edge API origin or TLS server name is invalid');
  }
  const secureContext = createSecureContext({
    cert: readMountedCredential(certificateFile, 'edge client certificate'),
    key: readMountedCredential(privateKeyFile, 'edge client private key'),
    ca: readMountedCredential(trustBundleFile, 'edge trust bundle'),
    minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
  });
  const agent = new Agent({
    secureContext,
    minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', rejectUnauthorized: true,
    servername: serverName, keepAlive: true, maxSockets: 32, maxFreeSockets: 8,
  });
  const allowedOrigin = base.origin;
  return async function edgeTransport(target, options = {}) {
    const url = target instanceof URL ? target : new URL(target);
    if (url.origin !== allowedOrigin || url.protocol !== 'https:' || url.username || url.password
        || url.hash || options.redirect !== 'manual') {
      throw new Error('edge transport target is outside the pinned origin');
    }
    const body = boundedBody(options.body);
    return new Promise((resolve, reject) => {
      const request = httpsRequest(url, {
        agent, method: options.method ?? 'GET', headers: options.headers ?? {},
        signal: options.signal, servername: serverName,
        minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', rejectUnauthorized: true,
      }, response => {
        const chunks = []; let length = 0;
        response.on('data', chunk => {
          length += chunk.length;
          if (length > maximumResponseBytes) response.destroy(new Error('edge response is too large'));
          else chunks.push(Buffer.from(chunk));
        });
        response.on('error', reject);
        response.on('end', () => {
          const headers = new Headers();
          for (const [name, value] of Object.entries(response.headers)) {
            if (Array.isArray(value)) value.forEach(item => headers.append(name, item));
            else if (value !== undefined) headers.set(name, String(value));
          }
          resolve(new Response(Buffer.concat(chunks), {
            status: response.statusCode ?? 502, headers,
          }));
        });
      });
      request.once('error', reject);
      if (body !== undefined) request.write(body);
      request.end();
    });
  };
}
