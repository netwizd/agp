// Unified S0: real CP, independent journal DB/service, mTLS EdgeAuth, Nginx HTTPS/h2,
// and the embedded production Angular authentication UI. No request mocking.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Processes, freePort, jsonPost, pki, privateFile, raw, required, signingKey, token, totp, waitReady } from './s0-support.mjs';

process.umask(0o077);
assert.equal(required('AGP_TEST_S0_DISPOSABLE'), '1', 'only the disposable two-cluster harness may run this suite');
const cpMaintenance = required('AGP_TEST_S0_CP_DSN');
const journalMaintenance = required('AGP_TEST_JOURNAL_DSN');
for (const dsn of [cpMaintenance, journalMaintenance]) assert.match(dsn, /^host=\/tmp\/agp-s0-full\.[^ ]+\/socket /, 'non-disposable DSN rejected');
assert.notEqual(cpMaintenance.split(' ')[0], journalMaintenance.split(' ')[0], 'CP and journal must use independent clusters');
assert.match(cpMaintenance, /(?:^| )dbname=agp_cp(?: |$)/, 'expected disposable CP maintenance database');
assert.match(journalMaintenance, /(?:^| )dbname=agp_journal(?: |$)/, 'expected disposable journal maintenance database');
const bin = Object.fromEntries(['AGP', 'CTL', 'JOURNAL', 'EDGE', 'NGINX'].map(role => [role.toLowerCase(), resolve(required(`AGP_TEST_${role}_BIN`))]));
const pg = resolve(required('AGP_TEST_PG_BINDIR'));
const playwrightModule = required('AGP_TEST_PLAYWRIGHT_MODULE');
const { chromium } = await import(playwrightModule.startsWith('/') ? pathToFileURL(playwrightModule).href : playwrightModule);
const work = await mkdtemp(resolve(process.env.AGP_TEST_BROWSER_TMPDIR || tmpdir(), 'agp-s0-browser.'));
const processes = new Processes();
const dbSuffix = token().replace(/[^a-zA-Z0-9]/g, '').slice(0, 14).toLowerCase();
const cpName = `browser_cp_${dbSuffix}`, journalName = `browser_journal_${dbSuffix}`;
const cpDSN = cpMaintenance.replace(/dbname=[^ ]+/, `dbname=${cpName}`);
const journalDSN = journalMaintenance.replace(/dbname=[^ ]+/, `dbname=${journalName}`);
const accounts = { admin: { username: 'browser-admin', password: token() }, user: { username: 'browser-user', password: token() } };
if(process.env.AGP_TEST_WAF==='1')accounts.approver={username:'browser-approver',password:token()};
const observedUpstreams = [];
const apps = [];
const ownedDBs = [];
let browser, cp, journal, fleet, nodeStage;
let failure;
const deadline = setTimeout(() => { failure = new Error('Full S0 browser acceptance exceeded 8 minutes'); void processes.close(); void browser?.close(); }, 480_000);
deadline.unref();
const pageErrors = [];
const callbacks = [];
const contextOptions = { ignoreHTTPSErrors: true, viewport: { width: 1440, height: 1000 } };

function ok(response, status, why) { assert.equal(response.status, status, `${why}: ${response.body.slice(0, 300)}`); return response; }
async function cookie(context, origin, name) { return (await context.cookies(origin)).find(value => value.name === name); }
async function primary(page, account) {
  await page.locator('#authUsername').fill(account.username);
  await page.locator('#authPassword').fill(account.password);
  await page.locator('#authPrimaryForm button[type=submit]').click();
  await page.locator('#authPrimaryForm').waitFor({ state: 'hidden' });
  assert.equal(await page.locator('#authError').count(), 0, 'primary authentication failed');
}
async function enrollment(page, principal) {
  await page.locator('#authStartEnrollment').click();
  const input = page.locator('#authManualSeed');
  await input.waitFor();
  const seed = await input.inputValue();
  assert.match(seed, /^[A-Z2-7]{16,128}$/);
  await page.locator('#authEnrollmentCode').fill(await totp(seed, principal));
  const confirmation = page.waitForResponse(response => new URL(response.url()).pathname.endsWith('/confirmations') && response.request().method() === 'POST');
  await page.locator('#authEnrollmentForm button[type=submit]').click();
  const response = await confirmation;
  assert.equal(response.status(), 201, `enrollment confirmation rejected: ${response.status() >= 400 ? await response.text() : ''}`);
  const payload = await response.json();
  assert.equal(payload.flow?.nextStep, 'complete', `enrollment did not become ready: ${JSON.stringify(payload.flow)}`);
  await page.locator('#authRecoveryCodes').waitFor();
  const codes = await page.locator('#authRecoveryCodes code').allTextContents();
  assert.ok(codes.length >= 1 && codes.every(value => value.length >= 16), 'one-time recovery codes must be displayed');
  // The application may keep a flow ID but must never persist enrollment secrets.
  const storage = await page.evaluate(() => [JSON.stringify(localStorage), JSON.stringify(sessionStorage)].join('\n'));
  assert.ok(!storage.includes(seed) && codes.every(value => !storage.includes(value)), 'secrets persisted in browser storage');
  await page.locator('#authCodesSaved').check();
  return { seed, codes };
}
async function proveTOTP(page, seed, principal) {
  await page.locator('#authTotp').fill(await totp(seed, principal));
  await page.locator('#authTotpForm button[type=submit]').click();
  await page.locator('#authComplete').waitFor();
}
async function complete(page) {
  await page.locator('#authComplete').click();
  await page.locator('.auth-success').waitFor();
}
async function flowOf(page) { return page.evaluate(() => JSON.parse(sessionStorage.getItem('agp_auth_flow') || 'null')); }
async function capture(page) {
  page.on('pageerror', error => pageErrors.push(error.message));
  page.on('response', response => {
    if (new URL(response.url()).pathname === '/_agp/callback') callbacks.push({ url: response.url(), status: response.status(), headers: response.headers() });
  });
}

try {
  const pin = await readFile(new URL('../../scripts/nginx-toolchain.env', import.meta.url), 'utf8');
  const version = pin.match(/^AGP_NGINX_QUALIFIED_VERSION=([\d.]+)$/m)?.[1];
  assert.ok(version && (await processes.run(bin.nginx, ['-V'])).includes(`nginx/${version}`), 'qualified Nginx pin mismatch');
  await processes.run(resolve(pg, 'createdb'), [`--maintenance-db=${cpMaintenance}`, cpName]); ownedDBs.push([cpMaintenance, cpName]);
  await processes.run(resolve(pg, 'createdb'), [`--maintenance-db=${journalMaintenance}`, journalName]); ownedDBs.push([journalMaintenance, journalName]);
  const [httpPort, authPort, journalPort, tlsPort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
  const management = `https://management.agp.test:${tlsPort}`, login = `https://login.agp.test:${tlsPort}`;
  const origins = [`https://app1.agp.test:${tlsPort}`, `https://app2.agp.test:${tlsPort}`];
  const central = `https://127.0.0.1:${authPort}`, journalURL = `https://127.0.0.1:${journalPort}`;
  const browserPKI = await pki(processes, work, 'browser');
  const browserCert = await browserPKI.issue('browser-listener', 'DNS:*.agp.test', 'serverAuth');
  const journalPKI = await pki(processes, work, 'journal');
  const journalCert = await journalPKI.issue('journal-listener', 'IP:127.0.0.1', 'serverAuth');
  const cpJournalCert = await journalPKI.issue('cp-journal-client', 'URI:spiffe://agp/control-plane/browser', 'clientAuth');
  const issuerJournalCert = process.env.AGP_TEST_NODE_IDENTITY==='1' ? await journalPKI.issue('issuer-journal-client', 'URI:spiffe://agp/node-issuer/journal-reader', 'clientAuth') : null;
  const validatorJournalCert = process.env.AGP_TEST_NODE_IDENTITY==='1' ? await journalPKI.issue('validator-journal-client', 'URI:spiffe://agp/agent/local-validation-reader', 'clientAuth') : null;
  const centralPKI = await pki(processes, work, 'central');
  const centralCert = await centralPKI.issue('central-listener', 'IP:127.0.0.1', 'serverAuth');
  const edgeCertificates = [];
  for (const index of [1, 2]) edgeCertificates.push(await centralPKI.issue(`edge-${index}`, `URI:spiffe://agp/edge/node_browser_${index}/gateway_browser_${index}`, 'clientAuth'));
  const wrongRoleCert = await centralPKI.issue('management-agent', 'URI:spiffe://agp/agent/node_browser_1', 'clientAuth');
  const journalKey = resolve(work, 'journal-signing.pem');
  const publicKey = await signingKey(journalKey);
  const mfaKey = await privateFile(resolve(work, 'mfa-keyring.json'), JSON.stringify({ active: 'browser_mfa', keys: { browser_mfa: randomBytes(32).toString('base64url') } }));
  const journalConfig = await privateFile(resolve(work, 'journal.json'), JSON.stringify({ authorityId: 'browser_authority', keyId: 'browser_signer', signingKeyFile: journalKey,
    listenAddress: `127.0.0.1:${journalPort}`, tlsCertificateFile: journalCert.cert, tlsKeyFile: journalCert.key, clientCAFile: journalPKI.ca,
    readClientURIs: ['spiffe://agp/control-plane/browser',...(issuerJournalCert?['spiffe://agp/node-issuer/journal-reader','spiffe://agp/agent/local-validation-reader']:[])], appendClientURIs: ['spiffe://agp/control-plane/browser'], approvalKeys: {} }));
  const journalEnv = { ...process.env, AGP_JOURNAL_DATABASE_DSN: journalDSN };
  await processes.run(bin.journal, ['migrate', '-config', journalConfig], journalEnv);
  journal = processes.start(bin.journal, ['serve', '-config', journalConfig], journalEnv);
  await waitReady(journalURL, journal, async () => (await raw(journalURL + '/healthz', { tls: cpJournalCert.tls })).status !== 503);
  const cpEnv = { ...process.env, AGP_DATABASE_DRIVER: 'postgres', AGP_DATABASE_DSN: cpDSN, AGP_HTTP_ADDR: `127.0.0.1:${httpPort}`,
    AGP_DOWNLOADS_DIR: resolve(work, 'downloads'), AGP_PORTAL_HOST: new URL(origins[0]).host, AGP_MANAGEMENT_ORIGIN: management, AGP_LOGIN_ORIGIN: login,
    AGP_SECURE_PROFILE: 'true', AGP_CONFIGURATION_ENABLED: process.env.AGP_TEST_S1 === '1' ? 'true' : 'false', AGP_COOKIE_SECURE: 'true', AGP_MFA_KEYRING_FILE: mfaKey, AGP_MFA_KEY_FILE: mfaKey,
    AGP_AUTH_MTLS_ADDR: `127.0.0.1:${authPort}`, AGP_AUTH_MTLS_CERT_FILE: centralCert.cert, AGP_AUTH_MTLS_KEY_FILE: centralCert.key,
    AGP_AUTH_MTLS_CLIENT_CA_FILE: centralPKI.ca, AGP_JOURNAL_URL: journalURL, AGP_JOURNAL_AUTHORITY_ID: 'browser_authority',
    AGP_JOURNAL_KEY_ID: 'browser_signer', AGP_JOURNAL_PUBLIC_KEY: publicKey, AGP_JOURNAL_CLIENT_CERT: cpJournalCert.cert,
    AGP_JOURNAL_CLIENT_KEY: cpJournalCert.key, AGP_JOURNAL_CA: journalPKI.ca, AGP_TRUST_PROXY_HEADERS: 'true', AGP_TRUSTED_PROXY_CIDRS: '127.0.0.1/32',
  };
  if(process.env.AGP_TEST_WAF==='1'){
    const nativeInput=resolve(work,'native-test-repository');
    const descriptor=JSON.parse(await processes.run(required('AGP_TEST_WAF_FIXTURE_BIN'),['--bundle',required('AGP_TEST_WAF_BUNDLE'),'--evidence',required('AGP_TEST_WAF_EVIDENCE'),'--renderer',required('AGP_TEST_WAF_RENDERER'),'--output',nativeInput]));
    const repositoryDir=resolve(work,'independent-waf-store');await mkdir(repositoryDir,{mode:0o700});
    cpEnv.AGP_WAF_TRUST_CONFIG=descriptor.anchor;cpEnv.AGP_WAF_REPOSITORY_DIR=repositoryDir;cpEnv.AGP_WAF_TEMP_DIR=work;
    await processes.run(bin.ctl,['waf-repository','--trust-config',descriptor.anchor,'--store',repositoryDir,'--import-bundle',descriptor.bundle],cpEnv);
  }
  for (const account of Object.values(accounts)) await processes.run(bin.ctl, ['create-admin', '-username', account.username], { ...cpEnv, AGP_SECURE_PROFILE: 'false', AGP_CONFIGURATION_ENABLED: 'false' }, account.password + '\n');
  if (process.env.AGP_TEST_S1 === '1') {
    await processes.run(resolve(pg,'psql'),['-X','-v','ON_ERROR_STOP=1',`--dbname=${cpDSN}`,'-c',"UPDATE users SET is_admin=false WHERE username='browser-user'; DELETE FROM group_permissions WHERE group_id IN (SELECT group_id FROM user_groups WHERE user_id=(SELECT id FROM users WHERE username='browser-user'));"]);
    const scopedID=(await processes.run(resolve(pg,'psql'),['-X','-At',`--dbname=${cpDSN}`,'-c',"SELECT id FROM users WHERE username='browser-user'"])).trim();
    const grants=[{principalId:scopedID,permission:'config.edit',scopeType:'site',scopeId:'site_msk'}];
    if(process.env.AGP_TEST_WAF==='1'){
      await processes.run(resolve(pg,'psql'),['-X','-v','ON_ERROR_STOP=1',`--dbname=${cpDSN}`,'-c',"UPDATE users SET is_admin=false WHERE username='browser-approver';"]);
      const approverID=(await processes.run(resolve(pg,'psql'),['-X','-At',`--dbname=${cpDSN}`,'-c',"SELECT id FROM users WHERE username='browser-approver'"])).trim();
      const adminID=(await processes.run(resolve(pg,'psql'),['-X','-At',`--dbname=${cpDSN}`,'-c',"SELECT id FROM users WHERE username='browser-admin'"])).trim();
      grants.push({principalId:approverID,permission:'config.read',scopeType:'site',scopeId:'site_msk'},{principalId:approverID,permission:'config.approve',scopeType:'site',scopeId:'site_msk'},{principalId:adminID,permission:'config.approve',scopeType:'global',scopeId:''});
    }
    const manifest=await privateFile(resolve(work,'configuration-bootstrap.json'),JSON.stringify({grants,ownership:[{gatewayId:'gw_portal',siteId:'site_msk'}]}));
    await processes.run(bin.ctl,['configuration-access','--bootstrap-manifest',manifest],{...cpEnv,AGP_SECURE_PROFILE:'false',AGP_CONFIGURATION_ENABLED:'false'});
  }
  await processes.run(bin.ctl, ['identity-profile', '--activate', '--revoke-sessions'], cpEnv);
  if(process.env.AGP_TEST_FLEET==='1'){
    const {prepareFleet}=await import('./fleet-support.mjs');
    fleet=await prepareFleet({processes,work,cpEnv,repositoryDir:cpEnv.AGP_WAF_REPOSITORY_DIR});
  }
  cp = processes.start(bin.agp, [], cpEnv);
  await waitReady(`http://127.0.0.1:${httpPort}/readyz`, cp);
  if(fleet){
    const receipt=await fleet.report();assert.equal(receipt.nodeId,'node_msk01');assert.ok(receipt.capabilityDigest);fleet.start();
  }

  for (let index = 0; index < 2; index++) {
    const app = createServer((request, response) => {
      observedUpstreams.push({ app: index + 1, path: request.url, cookie: request.headers.cookie || '', headers: request.headers });
      response.writeHead(200, { 'Content-Type': 'text/html', 'X-AGP-User-ID': 'upstream-forged', 'Set-Cookie': [
        `app_session=accepted_${index + 1}; Path=/; Secure; HttpOnly; SameSite=Lax`,
        '__Host-agp_gateway=upstream-forged; Path=/; Secure; HttpOnly',
        '__Host-agp_management=upstream-forged; Path=/; Secure; HttpOnly',
        'tracking=not-approved; Path=/; Secure', 'app_session=domain-injection; Domain=agp.test; Path=/; Secure',
      ] });
      response.end(`<!doctype html><html lang="en"><title>Protected application ${index + 1}</title><body><h1>Protected application ${index + 1}</h1></body></html>`);
    });
    await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));
    apps.push(app);
  }
  await mkdir(resolve(work, 'logs'));
  const socketPaths = [resolve(work, 'edge1.sock'), resolve(work, 'edge2.sock')];
  const listen = `listen 127.0.0.1:${tlsPort} ssl; http2 on; ssl_certificate ${browserCert.cert}; ssl_certificate_key ${browserCert.key};`;
  const forward = 'proxy_set_header Host $http_host; proxy_set_header X-Forwarded-Host $http_host; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Real-IP $remote_addr;';
  const edgeServers = origins.map((origin, index) => `upstream edge_${index} { server unix:${socketPaths[index]}; }
    server { ${listen} server_name ${new URL(origin).hostname};
      location = /_agp/authorize { return 404; }
      location / { proxy_pass http://edge_${index}; proxy_http_version 1.1; proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https; proxy_set_header X-AGP-Client-IP $remote_addr;
        proxy_set_header X-AGP-Start ""; proxy_set_header X-AGP-Original-URI ""; proxy_set_header X-AGP-Original-Method ""; }
    }`).join('\n');
  const nginxConfig = `pid nginx.pid; error_log stderr; events {} http { access_log off;
    client_body_temp_path body; proxy_temp_path proxy; fastcgi_temp_path fastcgi; uwsgi_temp_path uwsgi; scgi_temp_path scgi;
    server { ${listen} server_name _; return 421; }
    server { ${listen} server_name management.agp.test login.agp.test;
      location / { proxy_pass http://127.0.0.1:${httpPort}; ${forward} }
    }
    ${edgeServers}
  }`;
  const nginxPath = await privateFile(resolve(work, 'nginx.conf'), nginxConfig);
  await processes.run(bin.nginx, ['-p', work + '/', '-c', nginxPath, '-t']);
  const native = processes.start(bin.nginx, ['-p', work + '/', '-c', nginxPath, '-g', 'daemon off;']);
  await waitReady(management, native, async () => (await raw(management + '/auth/v2/bootstrap')).status === 200);
  browser = await chromium.launch({ headless: true,
    ...(process.env.AGP_TEST_CHROMIUM_EXECUTABLE ? { executablePath: process.env.AGP_TEST_CHROMIUM_EXECUTABLE } : {}),
    args: ['--host-resolver-rules=MAP *.agp.test 127.0.0.1', '--no-proxy-server'] });
  const context = await browser.newContext(contextOptions);
  const managementPage = await context.newPage(); await capture(managementPage);
  const protocols = [];
  const cdp = await context.newCDPSession(managementPage); await cdp.send('Network.enable');
  cdp.on('Network.responseReceived', ({ response }) => { if (response.url.startsWith(management)) protocols.push(response.protocol); });
  await managementPage.goto(management + '/auth-ui/login', { waitUntil: 'networkidle' });
  await primary(managementPage, accounts.admin);
  const pending = await flowOf(managementPage); assert.ok(pending?.id);
  assert.ok(!await cookie(context, management, '__Host-agp_management'), 'password alone created management session');
  ok(await raw(management + '/api/v1/admin/users', {}, context), 401, 'first-factor-only management access');
  assert.ok((await jsonPost(management, `/auth/v2/flows/${pending.id}/completions`, {}, context)).status >= 400, 'first-factor-only completion accepted');
  const adminFactor = await enrollment(managementPage, accounts.admin.username);
  await complete(managementPage);
  let adminCookie = await cookie(context, management, '__Host-agp_management');
  assert.ok(adminCookie?.secure && adminCookie.httpOnly && adminCookie.path === '/' && adminCookie.domain === 'management.agp.test');
  assert.ok(protocols.includes('h2'), 'browser did not negotiate actual HTTP/2');
  ok(await raw(management + '/api/v1/admin/users', {}, context), 200, 'MFA management session');
  console.log('PASS real Angular password/TOTP enrollment and management HTTPS/h2; password-only stays closed');

  const groupResponse = ok(await raw(management + '/api/v1/admin/groups', {}, context), 200, 'bootstrap groups');
  const groupID = JSON.parse(groupResponse.body).groups[0].ID;
  const resourceIDs = [];
  for (let index = 0; index < 2; index++) {
    const csrf = (await cookie(context, management, '__Host-agp_management_csrf')).value;
    const response = ok(await raw(management + '/api/v1/admin/resources', { method: 'POST', headers: { Origin: management, 'X-CSRF-Token': csrf },
      body: { name: `Browser application ${index + 1}`, internal_url: `http://127.0.0.1:${apps[index].address().port}`, public_host: new URL(origins[index]).host,
        enabled: true, group_ids: [groupID] } }, context), 201, 'create protected application fixture');
    const resource = JSON.parse(response.body).resource; resourceIDs.push(resource.ID || resource.id);
    assert.ok(resourceIDs[index]);
  }
  // Gateway registry CLI shares the CP writer lease; stop the disposable CP explicitly.
  await processes.stop(cp);
  for (let index = 0; index < 2; index++) {
    await processes.run(bin.ctl, ['gateway-register', '--id', `gateway_browser_${index + 1}`, '--node', `node_browser_${index + 1}`,
      '--origin', origins[index], '--callback', origins[index] + '/_agp/callback', '--resource', resourceIDs[index], '--generation', '1'], cpEnv);
    const cfg = await privateFile(resolve(work, `edge${index + 1}.json`), JSON.stringify({ nodeId: `node_browser_${index + 1}`, gatewayId: `gateway_browser_${index + 1}`,
      origin: origins[index], loginOrigin: login, centralOrigin: central, deploymentGeneration: '1', socketPath: socketPaths[index], statePath: resolve(work, `edge${index + 1}.db`),
      clientCertificateFile: edgeCertificates[index].cert, clientKeyFile: edgeCertificates[index].key, serverCaFile: centralPKI.ca,
      routes: [{ id: resourceIDs[index], pathPrefix: '/', upstream: `http://127.0.0.1:${apps[index].address().port}`, applicationCookies: ['app_session'] }] }));
    const edge = processes.start(bin.edge, ['-config', cfg]);
    await waitReady(origins[index], edge, async () => { await stat(socketPaths[index]); return true; });
  }
  cp = processes.start(bin.agp, [], cpEnv);
  await waitReady(`http://127.0.0.1:${httpPort}/readyz`, cp);
  console.log('PASS real CP/journal and two node-bound EdgeAuth processes provisioned over independent mTLS PKI');

  const loginPage = await context.newPage(); await capture(loginPage);
  await loginPage.goto(origins[0] + '/protected', { waitUntil: 'networkidle' });
  assert.equal(new URL(loginPage.url()).origin, login);
  await primary(loginPage, accounts.user);
  const loginPending = await flowOf(loginPage); assert.ok(loginPending?.id);
  assert.ok(!await cookie(context, login, '__Host-agp_login'));
  assert.ok(!await cookie(context, origins[0], '__Host-agp_gateway'));
  const incompleteAuthorize = new URL(loginPage.url()).searchParams.get('return');
  assert.ok(incompleteAuthorize?.startsWith('/auth/v2/authorize?'));
  const deniedAuthorize = await raw(login + incompleteAuthorize, {}, context);
  assert.ok(deniedAuthorize.status !== 200 && !String(deniedAuthorize.headers.location || '').includes('code='), 'password-only handoff issued');
  const userFactor = await enrollment(loginPage, accounts.user.username);
  await complete(loginPage); await loginPage.locator('#authContinue').click();
  await loginPage.waitForURL(origins[0] + '/protected');
  assert.equal(await loginPage.title(), 'Protected application 1');
  const gateway1 = await cookie(context, origins[0], '__Host-agp_gateway');
  assert.ok(gateway1?.secure && gateway1.httpOnly && gateway1.domain === 'app1.agp.test' && gateway1.path === '/');
  assert.ok(!await cookie(context, origins[1], '__Host-agp_gateway'), 'gateway cookie escaped its host');
  await loginPage.goto(origins[1] + '/protected', { waitUntil: 'networkidle' });
  assert.equal(await loginPage.title(), 'Protected application 2');
  const gateway2 = await cookie(context, origins[1], '__Host-agp_gateway');
  assert.ok(gateway2 && gateway2.value !== gateway1.value, 'different gateways reused a session token');
  assert.ok(callbacks.length >= 2 && callbacks.every(value => value.status === 303 && value.headers['cache-control']?.includes('no-store')));
  assert.ok(!loginPage.url().includes('code='), 'handoff code survived the callback');
  for (const origin of origins) {
    const response = ok(await raw(origin + '/cookie-check', { headers: { 'X-AGP-User-ID': 'spoofed', 'X-Forwarded-Host': new URL(management).host } }, context), 200, 'protected upstream');
    assert.equal(response.headers['x-agp-user-id'], undefined, 'untrusted identity response header escaped');
    const issued = response.headers['set-cookie'] || [];
    assert.equal(issued.length, 1); assert.match(issued[0], /^app_session=accepted_/);
  }
  assert.ok(observedUpstreams.some(value => value.cookie.includes('app_session=accepted_')));
  assert.ok(observedUpstreams.every(value => !/agp/i.test(value.cookie)), 'AGP credential reached an application');
  assert.ok(observedUpstreams.every(value => value.headers['x-agp-user-id'] && value.headers['x-agp-user-id'] !== 'spoofed'));
  assert.ok(observedUpstreams.every(value => !String(value.headers.referer || '').includes('code=')), 'handoff code leaked through Referer');
  const browserIsolation = await loginPage.evaluate(async ({ management }) => {
    document.cookie = '__Host-agp_management=attacker; Domain=agp.test; Secure; Path=/';
    try { await fetch(management + '/api/v1/admin/users', { credentials: 'include' }); return false; } catch { return true; }
  }, { management });
  assert.equal(browserIsolation, true, 'application JavaScript read the management origin');
  assert.equal((await cookie(context, management, '__Host-agp_management')).value, adminCookie.value, '__Host cookie tossing replaced management session');
  for (const candidate of [gateway1.value, adminCookie.value]) {
    const count = observedUpstreams.length;
    const substituted = await raw(origins[1] + '/wrong-audience', { headers: { Cookie: `__Host-agp_gateway=${candidate}` } });
    assert.notEqual(substituted.status, 200, 'cross-gateway/management token substitution accepted');
    assert.equal(observedUpstreams.length, count, 'substituted credential reached upstream');
  }
  assert.ok((await context.cookies(origins[0])).every(value => value.name !== 'tracking' && value.value !== 'upstream-forged' && value.value !== 'domain-injection'));
  console.log('PASS actual login→PKCE/mTLS handoff→two HTTPS applications; isolated gateway cookies, request/Set-Cookie filtering');

  const firstCallback = callbacks[0].url;
  ok(await raw(firstCallback, {}, context), 400, 'callback state replay');
  const stranger = await browser.newContext(contextOptions);
  ok(await raw(firstCallback, {}, stranger), 400, 'callback without browser binding');
  ok(await raw(firstCallback.replace(origins[0], origins[1]), {}, context), 400, 'callback to wrong gateway');
  const start = ok(await raw(origins[0] + '/_agp/start?return=%2Fprobe', { acceptCookies: true }, context), 303, 'new pending handoff');
  const authorize = ok(await raw(start.headers.location, {}, context), 303, 'fresh authorize');
  const code = new URL(authorize.headers.location).searchParams.get('code'); assert.ok(code);
  const redeemBody = { code, codeVerifier: token() + token(), gatewayId: 'gateway_browser_1', redirectUri: origins[0] + '/_agp/callback' };
  assert.ok((await raw(central + '/auth/v2/handoffs/redeem', { method: 'POST', body: redeemBody, tls: edgeCertificates[0].tls })).status >= 400, 'PKCE mismatch accepted');
  assert.ok((await raw(central + '/auth/v2/handoffs/redeem', { method: 'POST', body: redeemBody, tls: edgeCertificates[1].tls })).status >= 400, 'another node/gateway certificate accepted');
  assert.ok((await raw(central + '/auth/v2/handoffs/redeem', { method: 'POST', body: redeemBody, tls: wrongRoleCert.tls })).status >= 400, 'management-agent role accepted as EdgeAuth');
  await assert.rejects(raw(central + '/auth/v2/decisions', { method: 'POST', body: {}, tls: { ca: await readFile(centralPKI.ca), rejectUnauthorized: true, minVersion: 'TLSv1.3' } }), 'unauthenticated client reached the mTLS handler');
  const wrongRedirect = new URL(start.headers.location); wrongRedirect.searchParams.set('redirectUri', origins[1] + '/_agp/callback');
  assert.ok((await raw(wrongRedirect.href, {}, context)).status >= 400, 'unregistered callback accepted');
  for (const headers of [{ Origin: origins[0] }, { Origin: management, 'X-CSRF-Token': '' }, { Origin: '' }]) {
    const response = await jsonPost(management, '/auth/v2/flows', { purpose: 'login', audience: 'management' }, context, headers);
    assert.ok(response.status >= 400, 'origin/CSRF negative accepted');
  }
  ok(await raw(`https://unknown.agp.test:${tlsPort}/api/v1/admin/users`, {}, context), 421, 'unknown Host');
  const appAdminPath = ok(await raw(origins[0] + '/api/v1/admin/users', {}, context), 200, 'application path must stay inside application');
  assert.ok(appAdminPath.body.includes('<title>Protected application 1</title>'), 'app origin exposed management instead of its fixed upstream');
  await stranger.close();
  console.log('PASS handoff replay/binding/redirect/PKCE/node/role negatives, no-client-cert mTLS, origin/CSRF and unknown-Host rejection');

  // A stale timestamp is an explicit fixture in this suite's private CP database.
  await processes.run(resolve(pg, 'psql'), ['-X', '-v', 'ON_ERROR_STOP=1', `--dbname=${cpDSN}`, '-c',
    "UPDATE sessions SET mfa_at=clock_timestamp()-interval '10 minutes' WHERE audience='management' AND revoked_at IS NULL"]);
  const stepUpResource = { name: 'Fresh step-up fixture', internal_url: `http://127.0.0.1:${apps[0].address().port}`, public_host: 'stepup.agp.test', enabled: true, group_ids: [groupID] };
  ok(await raw(management + '/api/v1/admin/resources', { method: 'POST', headers: { Origin: management, 'X-CSRF-Token': (await cookie(context, management, '__Host-agp_management_csrf')).value }, body: stepUpResource }, context), 403, 'stale MFA management mutation');
  await managementPage.goto(management + '/auth-ui/step-up', { waitUntil: 'networkidle' });
  await primary(managementPage, accounts.admin); await proveTOTP(managementPage, adminFactor.seed, accounts.admin.username); await complete(managementPage);
  const refreshedCookie = await cookie(context, management, '__Host-agp_management');
  assert.ok(refreshedCookie && refreshedCookie.value !== adminCookie.value, 'fresh step-up did not rotate session');
  ok(await raw(management + '/api/v1/admin/users', { headers: { Cookie: `__Host-agp_management=${adminCookie.value}` } }), 401, 'old management token after step-up');
  adminCookie = refreshedCookie;
  ok(await raw(management + '/api/v1/admin/resources', { method: 'POST', headers: { Origin: management, 'X-CSRF-Token': (await cookie(context, management, '__Host-agp_management_csrf')).value }, body: stepUpResource }, context), 201, 'fresh MFA management mutation');
  console.log('PASS stale MFA blocks mutation; real browser fresh password+TOTP step-up rotates session and revokes the prior token');

  const recoveryContext = await browser.newContext(contextOptions);
  const recoveryPage = await recoveryContext.newPage(); await capture(recoveryPage);
  await recoveryPage.goto(login + '/auth-ui/recover', { waitUntil: 'networkidle' });
  await primary(recoveryPage, accounts.user);
  await recoveryPage.locator('#authRecovery').fill(userFactor.codes[0]);
  await recoveryPage.locator('#authRecoveryForm button[type=submit]').click();
  await recoveryPage.locator('#authStartEnrollment').waitFor();
  assert.ok(!await cookie(recoveryContext, login, '__Host-agp_login'), 'recovery proof created a login session');
  await processes.stop(cp); cp = processes.start(bin.agp, [], cpEnv);
  await waitReady(`http://127.0.0.1:${httpPort}/readyz`, cp);
  await recoveryPage.reload({ waitUntil: 'networkidle' });
  await recoveryPage.locator('#authStartEnrollment').waitFor();
  const recoveredFactor = await enrollment(recoveryPage, accounts.user.username);
  await complete(recoveryPage);
  assert.ok(!await cookie(recoveryContext, login, '__Host-agp_login'));
  assert.ok(!await cookie(recoveryContext, management, '__Host-agp_management'));
  assert.ok(!await cookie(recoveryContext, origins[0], '__Host-agp_gateway'));
  ok(await raw(login + '/api/v1/me', {}, recoveryContext), 401, 'recovery completion must not create session');
  const reused = await jsonPost(login, '/auth/v2/flows', { purpose: 'recover', audience: 'setup' }, recoveryContext);
  const reusedFlow = JSON.parse(ok(reused, 201, 'recovery replay flow').body);
  ok(await jsonPost(login, `/auth/v2/flows/${reusedFlow.id}/primary-proofs`, { method: 'local_password', username: accounts.user.username, password: accounts.user.password }, recoveryContext), 200, 'recovery replay primary');
  assert.ok((await jsonPost(login, `/auth/v2/flows/${reusedFlow.id}/recovery-proofs`, { method: 'recovery_code', code: userFactor.codes[0] }, recoveryContext)).status >= 400, 'consumed recovery code replay accepted');
  await recoveryPage.goto(login + '/auth-ui/login', { waitUntil: 'networkidle' });
  await primary(recoveryPage, accounts.user); await proveTOTP(recoveryPage, recoveredFactor.seed, accounts.user.username); await complete(recoveryPage);
  assert.ok(await cookie(recoveryContext, login, '__Host-agp_login'));
  await recoveryPage.goto(origins[0] + '/after-recovery', { waitUntil: 'networkidle' });
  assert.equal(await recoveryPage.title(), 'Protected application 1');
  console.log('PASS sessionless recovery survives CP restart; replaces factor, rejects code replay and requires fresh MFA login');

  const beforeOutage = observedUpstreams.length;
  await processes.stop(journal);
  ok(await raw(origins[0] + '/journal-outage', {}, recoveryContext), 503, 'journal outage gateway fail-closed');
  assert.ok((await raw(management + '/api/v1/admin/users', {}, context)).status >= 500, 'journal outage management remained available');
  assert.equal(observedUpstreams.length, beforeOutage, 'journal outage still invoked application');
  journal = processes.start(bin.journal, ['serve', '-config', journalConfig], journalEnv);
  await waitReady(journalURL, journal, async () => (await raw(journalURL + '/healthz', { tls: cpJournalCert.tls })).status !== 503);
  ok(await raw(origins[0] + '/journal-recovered', {}, recoveryContext), 200, 'journal service recovery');
  console.log('PASS independent journal outage closes gateway and management; service recovery restores verified access');
  if (process.env.AGP_TEST_S1 === '1') {
    const { s1Acceptance } = await import('./s1-browser.mjs');
    const authored=await s1Acceptance({ page: managementPage, context, management, raw, assert });
    const scopedPage=await recoveryContext.newPage();await capture(scopedPage);
    await scopedPage.goto(management+'/auth-ui/login',{waitUntil:'networkidle'});
    await primary(scopedPage,accounts.user);await proveTOTP(scopedPage,recoveredFactor.seed,accounts.user.username);await complete(scopedPage);
    const {s1bAcceptance}=await import('./s1b-browser.mjs');
    await s1bAcceptance({page:scopedPage,context:recoveryContext,reviewerPage:managementPage,reviewerContext:context,management,raw,revisionId:authored.revisionId,assert});
    if(process.env.AGP_TEST_WAF==='1'){
      const approverContext=await browser.newContext(contextOptions);const approverPage=await approverContext.newPage();await capture(approverPage);
      await approverPage.goto(management+'/auth-ui/login',{waitUntil:'networkidle'});await primary(approverPage,accounts.approver);await enrollment(approverPage,accounts.approver.username);await complete(approverPage);
      const {wafPolicyAcceptance}=await import('./waf-policy-browser.mjs');
      const publishedPolicy=await wafPolicyAcceptance({page:managementPage,context,approverPage,approverContext,management,raw,assert,repositoryDir:cpEnv.AGP_WAF_REPOSITORY_DIR});
      if(fleet){
        const {fleetAcceptance}=await import('./fleet-browser.mjs');
        await fleetAcceptance({page:managementPage,context,approverPage,approverContext,scopedPage,scopedContext:recoveryContext,management,raw,assert,fleet,policy:publishedPolicy.policy});
        if(process.env.AGP_TEST_NODE_IDENTITY==='1') {
          const {prepareNodeIdentity,nodeIdentityAcceptance}=await import('./node-identity-browser.mjs');
          nodeStage=await prepareNodeIdentity({processes,work,cpEnv,issuerJournalCert,validatorJournalCert,fleet});
          await fleet.stop();
          await processes.stop(cp);
          Object.assign(cpEnv,nodeStage.cpConfig);
          cp=processes.start(bin.agp,[],cpEnv);
          await waitReady(`http://127.0.0.1:${httpPort}/readyz`,cp);
          await nodeIdentityAcceptance({page:managementPage,context,scopedContext:recoveryContext,management,raw,assert,stage:nodeStage,processes,policy:publishedPolicy.policy,qualification:publishedPolicy.report.qualification});
        }
      }
    }
    ok(await raw(login + '/api/v2/config/revisions', {}, recoveryContext), 403, 'login origin cannot read canonical configuration');
    const requestHeaders = { Origin: management, 'X-CSRF-Token': (await cookie(context, management, '__Host-agp_management_csrf')).value };
    ok(await raw(management + '/api/v2/config/documents', { method: 'POST', headers: { ...requestHeaders, 'Content-Type': 'application/json' }, body: '{"format":"json","format":"yaml","document":"{}"}' }, context), 400, 'duplicate envelope keys rejected');
    ok(await raw(management + '/api/v2/config/documents', { method: 'POST', headers: requestHeaders, body: { Format: 'json', document: '{}' } }, context), 400, 'case-variant envelope keys rejected');
    await processes.stop(cp);
    await processes.run(bin.ctl, ['configuration-profile', '--activate'], cpEnv);
    const downgraded = processes.start(bin.agp, [], { ...cpEnv, AGP_CONFIGURATION_ENABLED: 'false' });
    assert.notEqual(await downgraded.closed, 0, 'activated configuration profile accepted environment downgrade');
    assert.match(downgraded.output.join(''), /configuration profile/);
    cp = processes.start(bin.agp, [], cpEnv);
    await waitReady(`http://127.0.0.1:${httpPort}/readyz`, cp);
    ok(await raw(management + '/api/v1/admin/resources', { method: 'POST', headers: requestHeaders, body: { ...stepUpResource, public_host: 'legacy-bypass.agp.test' } }, context), 409, 'canonical profile fences legacy live writer');
    assert.equal(JSON.parse(ok(await raw(management + '/api/v2/config/profile', {}, context), 200, 'persisted canonical profile').body).enabled, true);
    ok(await raw(origins[0] + '/after-canonical-cutover', {}, recoveryContext), 200, 'authoring cutover preserves existing application access');
    console.log('PASS S1 offline canonical-profile activation, persisted downgrade fence and legacy-write rejection; existing live access preserved');
  }
  assert.deepEqual(pageErrors, [], 'production Angular emitted JavaScript errors');
  if (process.env.AGP_TEST_SCREENSHOT_DIR) {
    await mkdir(process.env.AGP_TEST_SCREENSHOT_DIR, { recursive: true });
    await managementPage.screenshot({ path: resolve(process.env.AGP_TEST_SCREENSHOT_DIR, 's0-step-up.png'), fullPage: true });
    await recoveryPage.screenshot({ path: resolve(process.env.AGP_TEST_SCREENSHOT_DIR, 's0-protected-app.png'), fullPage: true });
  }
  if (failure) throw failure;
  console.log('Full S0 HTTPS/browser acceptance passed.');
} catch (error) {
  failure = error;
  throw error;
} finally {
  clearTimeout(deadline);
  await browser?.close();
  await processes.close();
  await fleet?.cleanup();
  await nodeStage?.cleanup();
  for (const app of apps) { app.closeAllConnections(); await new Promise(resolve => app.close(resolve)); }
  for (const [dsn, name] of ownedDBs.reverse()) await processes.run(resolve(pg, 'dropdb'), [`--maintenance-db=${dsn}`, name]);
  await rm(work, { recursive: true, force: true });
}
