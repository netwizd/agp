// Process, PKI and transport helpers for disposable S0 acceptance only.
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { request as httpsRequest } from 'node:https';
import { createServer } from 'node:net';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

export const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
export const token = () => randomBytes(24).toString('base64url');
export const required = name => { assert.ok(process.env[name], `${name} is required`); return process.env[name]; };
export async function privateFile(path, value) { await writeFile(path, value, { mode: 0o600 }); await chmod(path, 0o600); return path; }
export async function freePort() {
  const listener = createServer();
  await new Promise((resolve, reject) => { listener.once('error', reject); listener.listen(0, '127.0.0.1', resolve); });
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  return port;
}
export class Processes {
  commands = new Set();
  start(binary, args = [], env = process.env, input = '', options = {}) {
    const child = spawn(binary, args, { env, stdio: ['pipe', 'pipe', 'pipe'], detached: !!options.processGroup });
    const output = [];
    for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => output.push(bytes.toString()));
    const command = { child, output, processGroup: !!options.processGroup, finished: false };
    command.closed = new Promise((resolve, reject) => {
      child.once('error', error => { command.error = error; output.push(error.message); this.commands.delete(command); resolve(127); });
      child.once('close', code => { command.finished = true; this.commands.delete(command); resolve(code); });
    });
    child.stdin.on('error', () => {});
    child.stdin.end(input);
    this.commands.add(command);
    return command;
  }
  async run(binary, args, env, input) {
    const command = this.start(binary, args, env, input);
    assert.equal(await command.closed, 0, `${binary} failed: ${command.output.join('').slice(-8000)}`);
    return command.output.join('');
  }
  async stop(command) {
    if (!command) return;
    if (command.processGroup && !command.finished) {
      // PRoot does not reliably forward a signal to its traced agent. Signal
      // only the dedicated group created for this owned test command.
      const signal = value => { try { process.kill(-command.child.pid, value); } catch (error) { if(error.code!=='ESRCH')throw error; } };
      signal('SIGTERM');
      const force = setTimeout(() => { if(!command.finished)signal('SIGKILL'); }, 5000);force.unref();
      try { await command.closed; } finally { clearTimeout(force); }
      return;
    }
    if (command.child.exitCode === null) command.child.kill('SIGTERM');
    await command.closed;
  }
  async close() { await Promise.allSettled([...this.commands].map(command => this.stop(command))); }
}
export async function waitReady(url, command, probe = async url => (await fetch(url)).ok) {
  for (let attempt = 0; attempt < 150; attempt++) {
    if (command.error || command.child.exitCode !== null) throw new Error(`Process exited: ${command.output.join('').slice(-8000)}`);
    try { if (await probe(url)) return; } catch {}
    await pause(80);
  }
  throw new Error(`Process not ready: ${command.output.join('').slice(-8000)}`);
}
export async function raw(url, options = {}, context) {
  const parsed = new URL(url);
  assert.ok(['127.0.0.1', 'management.agp.test', 'login.agp.test', 'app1.agp.test', 'app2.agp.test', 'unknown.agp.test'].includes(parsed.hostname), 'probe must stay inside the disposable lab');
  const headers = { Host: parsed.host, ...(options.headers || {}) };
  if (context && headers.Cookie === undefined) {
    const cookies = await context.cookies(url);
    if (cookies.length) headers.Cookie = cookies.map(cookie => `${cookie.name}=${cookie.value}`).join('; ');
  }
  let body = options.body;
  if (body !== undefined && typeof body !== 'string') { body = JSON.stringify(body); headers['Content-Type'] ||= 'application/json'; }
  if (body !== undefined) headers['Content-Length'] = Buffer.byteLength(body);
  const response = await new Promise((resolve, reject) => {
    const request = httpsRequest({ hostname: '127.0.0.1', port: parsed.port || 443, servername: parsed.hostname === '127.0.0.1' ? undefined : parsed.hostname,
      path: parsed.pathname + parsed.search, method: options.method || 'GET', headers, agent: false, timeout: 6000,
      ...(options.tls || { rejectUnauthorized: false }),
    }, response => {
      const bytes = [];
      response.on('data', data => bytes.push(data));
      response.once('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(bytes).toString() }));
    });
    request.once('error', reject);
    request.once('timeout', () => request.destroy(new Error('Disposable HTTPS probe timed out')));
    request.end(body);
  });
  if (context && options.acceptCookies) {
    for (const value of response.headers['set-cookie'] || []) {
      const parts = value.split(';').map(part => part.trim());
      const separator = parts[0].indexOf('=');
      const name = parts[0].slice(0, separator), cookieValue = parts[0].slice(separator + 1);
      if (parts.some(part => /^max-age=0$/i.test(part))) { await context.clearCookies({ name, domain: parsed.hostname }); continue; }
      await context.addCookies([{ name, value: cookieValue, url: parsed.origin,
        secure: parts.some(part => /^secure$/i.test(part)), httpOnly: parts.some(part => /^httponly$/i.test(part)), sameSite: 'Lax' }]);
    }
  }
  return response;
}
export async function jsonPost(origin, path, body, context, overrides = {}) {
  const cookies = await context.cookies(origin);
  const csrf = cookies.find(cookie => cookie.name === '__Host-agp_flow_csrf')?.value || '';
  return raw(origin + path, { method: 'POST', headers: { Origin: origin, 'X-CSRF-Token': csrf, ...overrides }, body, acceptCookies: true }, context);
}
export async function pki(processes, dir, label) {
  const root = resolve(dir, label);
  await mkdir(root, { mode: 0o700 });
  const ca = resolve(root, 'ca.pem'), caKey = resolve(root, 'ca.key');
  await processes.run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1', '-subj', `/CN=S0 ${label} CA`,
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', caKey, '-out', ca]);
  await chmod(caKey, 0o600);
  const issue = async (name, san, eku) => {
    const key = resolve(root, name + '.key'), csr = resolve(root, name + '.csr'), cert = resolve(root, name + '.pem'), ext = resolve(root, name + '.ext');
    await processes.run('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', `/CN=${name}`, '-keyout', key, '-out', csr]);
    await privateFile(ext, `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=${eku}\nsubjectAltName=${san}\n`);
    await processes.run('openssl', ['x509', '-req', '-in', csr, '-CA', ca, '-CAkey', caKey, '-CAcreateserial', '-days', '1', '-sha256', '-extfile', ext, '-out', cert]);
    await chmod(key, 0o600);
    return { key, cert, ca, tls: { key: await readFile(key), cert: await readFile(cert), ca: await readFile(ca), rejectUnauthorized: true, minVersion: 'TLSv1.3' } };
  };
  return { ca, issue };
}
export async function signingKey(path) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  await privateFile(path, privateKey.export({ format: 'pem', type: 'pkcs8' }));
  return publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
}
const acceptedSteps = new Map();
export async function totp(seed, principal = seed) {
  const current = Math.floor(Date.now() / 30_000);
  if ((acceptedSteps.get(principal) ?? -1) >= current) await pause((current + 1) * 30_000 - Date.now() + 150);
  const step = Math.floor(Date.now() / 30_000);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of seed) { assert.ok(alphabet.includes(char)); bits += alphabet.indexOf(char).toString(2).padStart(5, '0'); }
  const key = Buffer.from((bits.match(/.{8}/g) || []).map(value => parseInt(value, 2)));
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac('sha1', key).update(counter).digest();
  const value = (mac.readUInt32BE(mac[19] & 15) & 0x7fffffff) % 1_000_000;
  acceptedSteps.set(principal, step);
  return String(value).padStart(6, '0');
}
