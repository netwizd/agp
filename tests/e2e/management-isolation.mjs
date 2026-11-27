// Disposable HTTPS/browser acceptance for the single-node management boundary.
// Requires built agp/agpctl, a verified Nginx, OpenSSL and an existing Playwright installation.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { request as requestHTTPS } from 'node:https';
import { createServer as createTCPServer } from 'node:net';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const required = name => {
  assert.ok(process.env[name], `${name} is required`);
  return resolve(process.env[name]);
};
const agp = required('AGP_TEST_AGP_BIN');
const ctl = required('AGP_TEST_CTL_BIN');
const nginx = required('AGP_TEST_NGINX_BIN');
const playwrightModule = process.env.AGP_TEST_PLAYWRIGHT_MODULE || 'playwright';
const { chromium } = await import(playwrightModule.startsWith('/') ? pathToFileURL(playwrightModule).href : playwrightModule);
const workdir = await mkdtemp(resolve(tmpdir(), 'agp-management-e2e-'));
const children = new Set();
const username = 'browser-admin';
const password = randomBytes(24).toString('base64url');
const mgmtCookieName = '__Host-agp_management';
const csrfCookieName = '__Host-agp_management_csrf';
let browser, app;
const timeout = setTimeout(() => {
  console.error('Management browser acceptance timed out');
  for (const process of children) process.kill('SIGTERM');
  if (browser) void browser.close();
}, 90_000);
timeout.unref();

function child(binary, args, env = process.env, input = '') {
  const process = spawn(binary, args, { env, stdio: ['pipe', 'pipe', 'pipe'] });
  const output = [];
  process.stdout.on('data', data => output.push(data.toString()));
  process.stderr.on('data', data => output.push(data.toString()));
  const closed = new Promise((resolve, reject) => {
    process.once('error', reject);
    process.once('close', code => { children.delete(process); resolve(code); });
  });
  process.stdin.end(input);
  children.add(process);
  return { process, closed, output };
}
async function run(binary, args, env, input) {
  const command = child(binary, args, env, input);
  assert.equal(await command.closed, 0, `${binary} failed: ${command.output.join('').slice(-8000)}`);
  return command.output.join('');
}
async function stop(command) {
  if (command.process.exitCode === null) command.process.kill('SIGTERM');
  await command.closed;
}
async function freePort() {
  const server = createTCPServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
async function ready(url, command) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (command.process.exitCode !== null) throw new Error(command.output.join('').slice(-8000));
    try { if ((await fetch(url)).ok) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`Server did not become ready: ${command.output.join('').slice(-8000)}`);
}
async function rawRequest(url, options = {}, cookieContext) {
  const parsed = new URL(url);
  const cookies = cookieContext ? await cookieContext.cookies(url) : [];
  const headers = { Host: parsed.host, ...options.headers };
  if (headers.Cookie === undefined && cookies.length) headers.Cookie = cookies.map(cookie => `${cookie.name}=${cookie.value}`).join('; ');
  return new Promise((resolve, reject) => {
    // Node's client does not use Chromium's per-test DNS mapping. Connect only
    // to the disposable listener, preserving HTTP authority and TLS SNI.
    const request = requestHTTPS({ hostname: '127.0.0.1', port: parsed.port, path: parsed.pathname + parsed.search,
      servername: parsed.hostname, rejectUnauthorized: false, agent: false,
      method: options.method || 'GET', headers, timeout: 5000,
    }, response => {
      response.resume();
      response.once('end', () => resolve(response.statusCode));
    });
    request.once('error', reject);
    request.once('timeout', () => request.destroy(new Error('Local HTTPS probe timed out')));
    request.end(options.body);
  });
}
async function login(page, origin, mode) {
  await page.goto(origin, { waitUntil: 'networkidle' });
  await page.locator(`body[data-runtime-mode="${mode}"]`).waitFor();
  await page.locator('#loginForm [name=username]').fill(username);
  await page.locator('#loginForm [name=password]').fill(password);
  await page.locator('#loginForm button[type=submit]').click();
  await page.locator(mode === 'management' ? '#adminView' : '#portalView').waitFor({ state: 'visible' });
}
try {
  const pin = await readFile(new URL('../../scripts/nginx-toolchain.env', import.meta.url), 'utf8');
  const version = pin.match(/^AGP_NGINX_QUALIFIED_VERSION=([\d.]+)$/m)?.[1];
  assert.ok(version, 'missing reviewed Nginx pin');
  assert.ok((await run(nginx, ['-v'])).includes(`nginx/${version}`));
  const backendPort = await freePort();
  const tlsPort = await freePort();
  const portalHost = `portal.agp.test:${tlsPort}`;
  const management = `https://management.agp.test:${tlsPort}`;
  const portal = `https://${portalHost}`;
  const env = { ...process.env, AGP_HTTP_ADDR: `127.0.0.1:${backendPort}`,
    AGP_DATABASE_DRIVER: 'sqlite', AGP_DATABASE_PATH: resolve(workdir, 'test.db'),
    AGP_DOWNLOADS_DIR: resolve(workdir, 'downloads'), AGP_PORTAL_HOST: portalHost,
    AGP_MANAGEMENT_ORIGIN: management, AGP_COOKIE_SECURE: 'true',
    AGP_SESSION_COOKIE_NAME: 'agp_session', AGP_CSRF_COOKIE_NAME: 'agp_csrf',
    AGP_TRUST_PROXY_HEADERS: 'true', AGP_TRUSTED_PROXY_CIDRS: '127.0.0.1/32',
  };
  await run(ctl, ['create-admin', '-username', username], env, password + '\n');
  await run(ctl, ['session-profile', '--preview'], env);
  await run(ctl, ['session-profile', '--apply', '--revoke-sessions'], env);
  let backend = child(agp, [], env);
  await ready(`http://127.0.0.1:${backendPort}/readyz`, backend);
  const upstreamCookies = [];
  app = createServer((req, res) => {
    upstreamCookies.push(req.headers.cookie || '');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html lang="en"><title>Untrusted application</title><body>Untrusted application</body></html>');
  });
  await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));
  const appURL = `http://127.0.0.1:${app.address().port}`;
  const cert = resolve(workdir, 'cert.pem'), key = resolve(workdir, 'key.pem');
  await run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
    '-subj', '/CN=agp.test', '-addext', 'subjectAltName=DNS:*.agp.test', '-keyout', key, '-out', cert]);
  const proxyHeaders = `proxy_set_header Host $http_host; proxy_set_header X-Forwarded-Host $http_host; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Real-IP $remote_addr;`;
  const listener = `listen 127.0.0.1:${tlsPort} ssl; http2 on; ssl_certificate ${cert}; ssl_certificate_key ${key};`;
  const configuration = `pid nginx.pid; error_log stderr; events {} http {
    access_log off; client_body_temp_path body; proxy_temp_path proxy; fastcgi_temp_path fastcgi; uwsgi_temp_path uwsgi; scgi_temp_path scgi;
    server { ${listener} server_name management.agp.test;
      location / { proxy_pass http://127.0.0.1:${backendPort}; ${proxyHeaders} }
    }
    server { ${listener} server_name portal.agp.test;
      location = /_agp_auth { internal; proxy_pass http://127.0.0.1:${backendPort}/auth/request;
        proxy_pass_request_body off; proxy_set_header Content-Length ""; ${proxyHeaders}
        proxy_set_header X-Original-URI $request_uri; proxy_set_header Cookie $http_cookie; }
      location ^~ /untrusted { auth_request /_agp_auth; proxy_pass ${appURL}; ${proxyHeaders} }
      location / { proxy_pass http://127.0.0.1:${backendPort}; ${proxyHeaders} }
    }
  }`;
  await mkdir(resolve(workdir, 'logs'));
  await writeFile(resolve(workdir, 'nginx.conf'), configuration);
  const native = child(nginx, ['-p', workdir + '/', '-c', resolve(workdir, 'nginx.conf'), '-g', 'daemon off;']);
  browser = await chromium.launch({ headless: true,
    ...(process.env.AGP_TEST_CHROMIUM_EXECUTABLE ? { executablePath: process.env.AGP_TEST_CHROMIUM_EXECUTABLE } : {}),
    args: ['--host-resolver-rules=MAP *.agp.test 127.0.0.1', '--no-proxy-server'],
  });
  // Only the disposable, self-signed lab certificate is accepted by this context.
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 } });
  const managementPage = await context.newPage();
  const pageErrors = [];
  context.on('page', page => page.on('pageerror', error => pageErrors.push(error.message)));
  managementPage.on('pageerror', error => pageErrors.push(error.message));
  const protocols = [];
  const cdp = await context.newCDPSession(managementPage);
  await cdp.send('Network.enable');
  cdp.on('Network.responseReceived', ({ response }) => { if (response.url.startsWith(management)) protocols.push(response.protocol); });
  // Give the new native listener a bounded opportunity to bind.
  await new Promise(resolve => setTimeout(resolve, 100));
  assert.equal(native.process.exitCode, null, native.output.join(''));
  await login(managementPage, management, 'management');
  let cookies = await context.cookies(management);
  const managementCookie = cookies.find(cookie => cookie.name === mgmtCookieName);
  const csrfCookie = cookies.find(cookie => cookie.name === csrfCookieName);
  assert.ok(managementCookie?.secure && managementCookie.httpOnly && managementCookie.path === '/');
  assert.equal(managementCookie.domain, 'management.agp.test');
  assert.ok(csrfCookie?.secure && !csrfCookie.httpOnly);
  assert.ok(protocols.includes('h2'), 'browser did not negotiate HTTP/2 with the tested Nginx');
  console.log('PASS HTTPS/HTTP2 management login with host-only management cookies');
  await managementPage.reload({ waitUntil: 'networkidle' });
  const createStatus = await managementPage.evaluate(async ({ portalHost, appURL }) => {
    const csrf = decodeURIComponent(document.cookie.split('; ').find(value => value.startsWith('__Host-agp_management_csrf='))?.split('=').slice(1).join('=') || '');
    const groups = (await (await fetch('/api/v1/admin/groups')).json()).groups;
    return (await fetch('/api/v1/admin/resources', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({ name: 'Untrusted browser fixture', internal_url: appURL, public_host: portalHost, public_path: '/untrusted', enabled: true, group_ids: [groups[0].ID] }) })).status;
  }, { portalHost, appURL });
  assert.equal(createStatus, 201, 'management mutation after reload must use its CSRF cookie');
  assert.equal(await rawRequest(management + '/api/v1/admin/users', {}, context), 200, 'management user list must complete without locking the SQLite connection');
  const portalPage = await context.newPage();
  await login(portalPage, portal, 'portal');
  assert.ok(await portalPage.locator('.nav-link[data-view=admin]').isHidden());
  assert.equal(await portalPage.locator('#managementLink').getAttribute('href'), management + '/admin');
  const portalCookie = (await context.cookies(portal)).find(cookie => cookie.name === 'agp_session');
  assert.ok(portalCookie);
  await portalPage.goto(portal + '/untrusted', { waitUntil: 'networkidle' });
  assert.equal(await portalPage.title(), 'Untrusted application');
  assert.ok(upstreamCookies.length > 0);
  assert.ok(upstreamCookies.every(value => !value.includes(mgmtCookieName) && !value.includes(csrfCookieName)));
  console.log('PASS portal login, protected legacy application and no management cookie upstream');
  const attack = await portalPage.evaluate(async ({ management, username, password }) => {
    document.cookie = '__Host-agp_management=attacker; Domain=agp.test; Secure; Path=/';
    let read = false, login = false;
    try { await fetch(management + '/api/v1/me', { credentials: 'include' }); read = true; } catch {}
    try { await fetch(management + '/api/v1/auth/login', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'text/plain' }, body: JSON.stringify({ username, password }) }); login = true; } catch {}
    return { read, login };
  }, { management, username, password });
  assert.deepEqual(attack, { read: false, login: false });
  // A blocked CORS response is deliberately invisible to page script and may
  // omit Playwright's page response event. Check the HTTP rejection separately.
  const csrfStatus = await rawRequest(management + '/api/v1/auth/login', {
    method: 'POST',
    headers: { Origin: portal, 'Content-Type': 'text/plain' },
    body: JSON.stringify({ username, password }),
  }, context);
  assert.equal(csrfStatus, 403, 'simple login-CSRF did not receive a server-side rejection');
  assert.equal((await context.cookies(management)).find(cookie => cookie.name === mgmtCookieName)?.value, managementCookie.value);
  console.log('PASS browser CORS/read isolation, login-CSRF rejection and __Host cookie tossing');
  for (const [url, name, value] of [
    [management + '/api/v1/me', mgmtCookieName, portalCookie.value],
    [portal + '/api/v1/me', 'agp_session', managementCookie.value],
    [portal + '/auth/request', 'agp_session', managementCookie.value],
  ]) {
    assert.equal(await rawRequest(url, { headers: { Cookie: `${name}=${value}` } }), 401, 'session audience substitution accepted');
  }
  for (const path of ['/api/v1/public/downloads', '/downloads/missing', '/api/v1/resources']) {
    assert.ok([403, 404].includes(await rawRequest(management + path, {}, context)));
  }
  assert.ok([403, 404].includes(await rawRequest(portal + '/api/v1/admin/users', { headers: { 'X-Forwarded-Host': new URL(management).host } }, context)));
  console.log('PASS server-side audience checks, content separation and forged forwarding-host rejection');
  await run(ctl, ['session-profile', '--apply', '--revoke-sessions'], env);
  assert.equal(await rawRequest(management + '/api/v1/me', {}, context), 200, 'same-profile apply reset a valid session');
  await stop(backend);
  backend = child(agp, [], env);
  await ready(`http://127.0.0.1:${backendPort}/readyz`, backend);
  await managementPage.reload({ waitUntil: 'networkidle' });
  await managementPage.locator('#adminView').waitFor({ state: 'visible' });
  console.log('PASS repeated activation and restart preserve management sessions');
  if (process.env.AGP_TEST_SCREENSHOT_DIR) {
    await mkdir(process.env.AGP_TEST_SCREENSHOT_DIR, { recursive: true });
    await managementPage.screenshot({ path: resolve(process.env.AGP_TEST_SCREENSHOT_DIR, 'management.png'), fullPage: true });
  }
  await managementPage.locator('#logoutButton').click();
  await managementPage.locator('#loginView').waitFor({ state: 'visible' });
  assert.equal(await rawRequest(management + '/api/v1/me', { headers: { Cookie: `${mgmtCookieName}=${managementCookie.value}` } }), 401);
  assert.equal(await rawRequest(portal + '/api/v1/me', {}, context), 200, 'management logout destroyed the independent portal session');
  assert.deepEqual(pageErrors, []);
  console.log('PASS management logout revokes its session while portal remains available; no browser JS errors');
} finally {
  clearTimeout(timeout);
  if (browser) await browser.close();
  for (const process of children) process.kill('SIGTERM');
  await Promise.all([...children].map(process => new Promise(resolve => process.once('close', resolve))));
  if (app) await new Promise(resolve => app.close(resolve));
  await rm(workdir, { recursive: true, force: true });
}
