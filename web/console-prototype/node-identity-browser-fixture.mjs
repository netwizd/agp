// Browser transport fixtures only: no real issuer, TLS identity or native qualification.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const moduleName = process.env.AGP_TEST_PLAYWRIGHT_MODULE || 'playwright';
const { chromium } = await import(moduleName.startsWith('/') ? pathToFileURL(moduleName).href : moduleName);
const browser = await chromium.launch({ headless: true, ...(process.env.AGP_TEST_CHROMIUM_BIN ? { executablePath: process.env.AGP_TEST_CHROMIUM_BIN } : {}) });
const origin = 'https://management.example.test', assetRoot = new URL('../../internal/frontend/static/config/', import.meta.url);
const csrf = 'C'.repeat(43), cookie = '__Host-node_fixture_csrf', digest = 'sha256:' + 'a'.repeat(64), requestDigest = 'sha256:' + 'b'.repeat(64);
const future = '2030-01-01T00:00:00Z', failures = [];
const managedNode = (id = 'node_fixture') => ({ id, siteId: 'site_fixture', name: '<img src=x onerror=alert(1)>', labels: { role: 'edge' }, connectivity: 'unknown', maintenance: false, identityState: 'pending', revision: '1' });

async function scenario(options = {}) {
    const context = await browser.newContext({ viewport: { width: options.width || 1440, height: 1000 } });
    const page = await context.newPage(), calls = [], receipts = new Map(), nodes = options.empty ? [] : [managedNode()];
    const flags = { loseToken: false, stepUp: false, malformedPending: false, malformedOperation: false, shortTTL: false, duplicatePage: false }, enrollments = new Map();
    let serial = 0;
    await context.addCookies([{ name: cookie, value: csrf, url: origin, secure: true, sameSite: 'Strict' }]);
    page.on('pageerror', error => failures.push(error.message));
    page.on('console', message => { if (message.type() === 'error' && /Content Security Policy|Refused to|NG0/.test(message.text())) failures.push(message.text()); });
    await page.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method();
        if (url.origin !== origin) { failures.push('Unexpected external request'); return route.abort(); }
        const reply = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
        if (path === '/api/v1/public/runtime') return reply({ mode: 'management', secure_profile: true, csrf_cookie_name: cookie, management_url: origin, auth_ui_url: '/auth-ui/login' });
        if (path === '/api/v1/me') return reply({ user: { id: 'user_fixture', username: 'fixture', is_admin: options.admin !== false } });
        if (path === '/api/v2/config/access') return reply({ principalId: 'user_fixture', globalRead: options.admin !== false, globalEdit: options.admin !== false, globalApprove: false, sites: [{ siteId: 'site_fixture', read: true, edit: false, approve: false }], authorityEpoch: '1' });
        if (path === '/api/v2/config/profile') return reply({ enabled: true });
        if (['/api/v2/config/revisions', '/api/v2/config/catalog-snapshots', '/api/v2/waf/authoring-zones', '/api/v2/agent-inventory'].includes(path)) return reply({ items: [] });
        if (path.startsWith('/api/v2/')) {
            const headers = request.headers(), body = method === 'GET' ? null : request.postDataJSON();
            calls.push({ path, query: url.search, method, body, headers });
            if (path === '/api/v2/node-identity-profile') return options.missingProfile ? reply({ code: 'not_found' }, 404) : reply({ enabled: options.enabled !== false, supportedRoles: ['agent'] });
            if (method !== 'GET') {
                assert.equal(headers['x-csrf-token'], csrf); assert.equal(headers['origin'], origin);
                assert.match(headers['idempotency-key'], /^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/);
                if (flags.stepUp) return reply({ code: 'step_up_required' }, 403);
                const old = receipts.get(headers['idempotency-key']);
                if (old) { assert.equal(old.fingerprint, JSON.stringify([path, body])); return reply(old.body, old.status); }
            }
            const remember = (response, status = 200, replay = response) => { receipts.set(headers['idempotency-key'], { fingerprint: JSON.stringify([path, body]), body: replay, status }); return reply(response, status); };
            if (path === '/api/v2/nodes' && method === 'GET') {
                assert.equal(url.searchParams.get('limit'), '50');
                if (options.oversizePage) return reply({ items: Array.from({ length: 51 }, (_, index) => managedNode('node_' + index)) });
                if (url.searchParams.has('cursor')) return reply({ items: [managedNode(flags.duplicatePage ? 'node_fixture' : 'node_second')] });
                return reply({ items: nodes, ...(options.pagination ? { nextCursor: 'bm9kZV9maXh0dXJl' } : {}) });
            }
            if (path === '/api/v2/nodes' && method === 'POST') {
                assert.deepEqual(Object.keys(body).sort(), ['id', 'labels', 'name', 'siteId']);
                const node = { ...managedNode(body.id), ...body }; nodes.push(node); return remember(node, 201);
            }
            const nodeId = path.split('/')[4], enrollmentId = path.split('/')[6];
            if (/^\/api\/v2\/nodes\/[^/]+\/enrollments$/.test(path) && method === 'POST') {
                assert.deepEqual(body, { role: 'agent', ttlSeconds: 600 });
                const id = 'enroll_fixture_' + ++serial, expiresAt = flags.shortTTL ? new Date(Date.now() + 1000).toISOString() : future;
                enrollments.set(id, { id, enrollmentId: id, nodeId, state: 'issued', publicKeyDigest: '', requestDigest: '', expiresAt });
                const replay = { enrollmentId: id, tokenAvailable: false, expiresAt }, response = { ...replay, tokenAvailable: true, token: String(serial).repeat(43) };
                if (flags.loseToken) { flags.loseToken = false; receipts.set(headers['idempotency-key'], { fingerprint: JSON.stringify([path, body]), body: replay, status: 201 }); return route.abort(); }
                return remember(response, 201, replay);
            }
            if (enrollmentId && enrollments.has(enrollmentId)) {
                const pending = enrollments.get(enrollmentId);
                if (method === 'GET') return reply(flags.malformedPending ? { ...pending, nodeId: 'node_someone_else' } : pending);
                if (path.endsWith('/approvals')) { assert.deepEqual(body, { expectedPublicKeyDigest: digest, requestDigest }); assert.equal(pending.state, 'csr_pending'); pending.state = 'approved'; return remember(pending); }
                if (path.endsWith('/revocations')) { assert.deepEqual(body, {}); pending.state = 'revoked'; return remember(pending); }
            }
            if (/^\/api\/v2\/nodes\/[^/]+\/revocations$/.test(path)) {
                assert.ok(body.reason.trim()); nodes.find(node => node.id === nodeId).identityState = 'revoked';
                return remember({ operationId: 'nrev_fixture', resourceId: nodeId, statusUrl: flags.malformedOperation ? 'https://attacker.invalid/token' : '/api/v2/node-identity-operations/nrev_fixture', submittedAt: new Date().toISOString() }, 202);
            }
            if (path === '/api/v2/node-identity-operations/nrev_fixture') return reply({ id: 'nrev_fixture', nodeId: 'node_fixture', kind: 'revoke_node', state: 'completed' });
            failures.push('Unexpected API path ' + path); return reply({ code: 'not_found' }, 404);
        }
        const file = path.startsWith('/config-ui/') && /\.[A-Za-z0-9]+$/.test(path) ? path.slice('/config-ui/'.length) : 'index.html';
        assert.ok(!file.includes('..') && !file.includes('/'));
        const contentType = file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.png') ? 'image/png' : 'text/html';
        return route.fulfill({ status: 200, headers: { 'Content-Type': contentType, 'Content-Security-Policy': "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'" }, body: await readFile(new URL(file, assetRoot)) });
    });
    await page.goto(origin + '/config-ui/', { waitUntil: 'networkidle' }); await page.locator('#zonesTitle').waitFor();
    return { context, page, calls, flags, nodes, enrollments };
}
async function open(s) { await s.page.locator('#inventoryTab').click(); await s.page.locator('#nodeIdentityTitle').waitFor(); await s.page.waitForFunction(() => !document.querySelector('#inventoryPanel agp-node-identity-panel')?.textContent.includes('Запрашиваем состояние')); }
async function select(s) { await open(s); await s.page.locator('#nodeSelect').selectOption('node_fixture'); }
async function issue(s) { await s.page.locator('#nodeIssueToken').click(); await s.page.waitForFunction(() => document.querySelector('#nodeEnrollmentId')?.value); return s.page.locator('#nodeEnrollmentId').inputValue(); }
async function csr(s, id) { Object.assign(s.enrollments.get(id), { state: 'csr_pending', publicKeyDigest: digest, requestDigest }); await s.page.locator('#nodePendingLoad').click(); await s.page.waitForFunction(() => document.querySelector('#nodeEnrollmentState')?.textContent === 'csr_pending'); }
try {
    for (const options of [{ enabled: false }, { missingProfile: true }]) {
        const s = await scenario(options);
        assert.equal(s.calls.some(call => call.path.includes('node-identity') || call.path === '/api/v2/nodes'), false);
        await open(s); await s.page.locator('#nodeIdentityDisabled').waitFor();
        assert.equal(await s.page.locator('#nodeCreateForm').count(), 0); assert.equal(s.calls.some(call => call.path === '/api/v2/nodes'), false);
        await s.context.close();
    }
    { const s = await scenario({ admin: false }); assert.equal(await s.page.locator('#inventoryTab').count(), 0); assert.equal(s.calls.some(call => call.path.includes('node-identity')), false); await s.context.close(); }
    console.log('PASS: lazy admin-only identity profile, disabled/external/404 hide mutations and non-admin never fetches');
    {
        const s = await scenario({ empty: true, width: 390 }); await open(s);
        await s.page.locator('#nodeId').fill('node_new'); await s.page.locator('#nodeSite').fill('site_fixture'); await s.page.locator('#nodeName').fill('<img src=x onerror=alert(1)>'); await s.page.locator('#nodeLabels').fill('{"role":"edge"}');
        await s.page.locator('#nodeCreate').focus(); await s.page.keyboard.press('Enter'); await s.page.waitForFunction(() => document.querySelector('#nodeSelect')?.value === 'node_new');
        assert.equal(await s.page.locator('agp-node-identity-panel img').count(), 0);
        await issue(s); assert.equal(await s.page.locator('#nodeEnrollmentToken').inputValue(), '1'.repeat(43));
        assert.equal(await s.page.locator('#nodeIssueToken').isDisabled(), true);
        assert.deepEqual(await s.page.evaluate(() => [Object.keys(localStorage), Object.keys(sessionStorage)]), [[], []]);
        assert.equal(s.calls.some(call => JSON.stringify(call).includes('1'.repeat(43))), false); assert.equal(s.page.url().includes('1'.repeat(43)), false);
        assert.ok(await s.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        await s.page.locator('#nodeForgetToken').click(); await s.page.locator('#nodeEnrollmentToken').waitFor({ state: 'detached' });
        await s.page.locator('#nodeRevokeEnrollment').click(); await s.page.waitForFunction(() => document.querySelector('#nodeEnrollmentState')?.textContent === 'revoked');
        await issue(s); assert.equal(await s.page.locator('#nodeEnrollmentToken').inputValue(), '2'.repeat(43));
        await s.page.locator('#zonesTab').click(); await s.page.locator('#inventoryTab').click(); await s.page.locator('#nodeCreateForm').waitFor();
        assert.equal(await s.page.locator('#nodeEnrollmentToken').count(), 0);
        await s.context.close(); console.log('PASS: typed node creation, operator labels, TTL600, secret memory-only/forget/destroy, explicit revoke/reissue, escaped DOM and mobile');
    }
    {
        const s = await scenario(); await select(s); const id = await issue(s); await csr(s, id);
        assert.equal(await s.page.locator('#nodeFingerprint').inputValue(), ''); assert.equal(await s.page.locator('#nodeApprove').isDisabled(), true);
        await s.page.locator('#nodeFingerprint').fill('sha256:' + 'c'.repeat(64)); await s.page.locator('#nodeFingerprintConfirmed').check(); assert.equal(await s.page.locator('#nodeApprove').isDisabled(), true);
        await s.page.locator('#nodeFingerprint').fill(digest); await s.page.locator('#nodeFingerprintConfirmed').uncheck(); await s.page.waitForFunction(() => document.querySelector('#nodeApprove')?.disabled);
        await s.page.locator('#nodeFingerprintConfirmed').focus(); await s.page.keyboard.press('Space'); await s.page.locator('#nodeApprove').click(); await s.page.waitForFunction(() => document.querySelector('#nodeEnrollmentState')?.textContent === 'approved');
        assert.equal(await s.page.locator('#nodeEnrollmentToken').count(), 0); assert.match(await s.page.locator('#nodeIdentityNotice').textContent(), /enroll/);
        s.enrollments.get(id).state = 'issued_certificate'; await s.page.locator('#nodePendingLoad').click(); await s.page.waitForFunction(() => document.querySelector('#nodeEnrollmentState')?.textContent === 'issued_certificate');
        assert.match(await s.page.locator('#nodeEnrollmentReport').textContent(), /проверяются отдельно/); assert.equal(await s.page.locator('#nodeApprove').isDisabled(), true);
        await s.context.close(); console.log('PASS: CSR key exact manual comparison plus explicit owner confirmation, request digest binding and no inferred health');
    }
    {
        const s = await scenario(); await select(s); s.flags.loseToken = true; await s.page.locator('#nodeIssueToken').click(); await s.page.locator('#nodeIdentityRetry').waitFor();
        assert.equal(await s.page.locator('#nodeSelect').isDisabled(), true); assert.equal(await s.page.locator('#nodeId').isDisabled(), true);
        await s.page.locator('#nodeIdentityRetry').click(); await s.page.locator('#nodeTokenUnavailable').waitFor();
        const writes = s.calls.filter(call => call.path.endsWith('/enrollments') && call.method === 'POST');
        assert.equal(writes[0].headers['idempotency-key'], writes[1].headers['idempotency-key']); assert.deepEqual(writes[0].body, writes[1].body);
        assert.equal(await s.page.locator('#nodeEnrollmentToken').count(), 0); assert.equal(await s.page.locator('#nodeIssueToken').isDisabled(), true);
        await s.page.locator('#nodeRevokeEnrollment').click(); await s.page.waitForFunction(() => document.querySelector('#nodeEnrollmentState')?.textContent === 'revoked'); await issue(s);
        assert.equal(await s.page.locator('#nodeEnrollmentToken').inputValue(), '2'.repeat(43));
        await s.context.close(); console.log('PASS: unknown response freezes inputs, exact retry returns no secret, lost token requires revoke and new authorization');
    }
    {
        const s = await scenario({ empty: true }); await open(s); s.flags.stepUp = true;
        await s.page.locator('#nodeId').fill('node_new'); await s.page.locator('#nodeSite').fill('site_fixture'); await s.page.locator('#nodeName').fill('Сохранить введённое имя'); await s.page.locator('#nodeCreate').click();
        await s.page.locator('#nodeIdentityError').waitFor(); assert.equal(await s.page.locator('#nodeName').inputValue(), 'Сохранить введённое имя');
        assert.equal(await s.page.locator('#nodeIdentityRetry').count(), 0); assert.equal(await s.page.getByRole('link', { name: 'Подтвердить MFA', exact: true }).getAttribute('href'), '/auth-ui/step-up?return=%2Fconfig-ui%2F');
        await s.context.close(); console.log('PASS: server fresh-step-up denial preserves form, safe return link, no automatic new mutation');
    }
    {
        const s = await scenario({ pagination: true }); await select(s); await s.page.locator('#nodeMore').click(); await s.page.waitForFunction(() => document.querySelector('#nodeSelect')?.options.length === 3);
        assert.equal(await s.page.locator('#nodeSelect').inputValue(), 'node_fixture'); assert.equal(await s.page.locator('#nodeMore').count(), 0);
        await s.page.locator('#nodeRevokeReason').fill('Узел выведен из эксплуатации'); await s.page.locator('#nodeRevoke').click(); await s.page.locator('#nodeRevocationReport').waitFor();
        assert.equal(await s.page.locator('#nodeIdentityState').textContent(), 'revoked'); assert.equal(await s.page.locator('#nodeIssueToken').isDisabled(), true);
        assert.ok(s.calls.some(call => call.path === '/api/v2/node-identity-operations/nrev_fixture'));
        await s.context.close(); console.log('PASS: bounded cursor pages preserve target and 202 node revocation follows exact same-origin operation');
    }
    for (const mode of ['wrong-node', 'oversize-page', 'duplicate-page', 'unsafe-operation']) {
        const s = await scenario({ oversizePage: mode === 'oversize-page', pagination: mode === 'duplicate-page' }); await open(s);
        if (mode !== 'oversize-page') await s.page.locator('#nodeSelect').selectOption('node_fixture');
        if (mode === 'wrong-node') { const id = await issue(s); await csr(s, id); s.flags.malformedPending = true; await s.page.locator('#nodePendingLoad').click(); }
        if (mode === 'duplicate-page') { s.flags.duplicatePage = true; await s.page.locator('#nodeMore').click(); }
        if (mode === 'unsafe-operation') { s.flags.malformedOperation = true; await s.page.locator('#nodeRevokeReason').fill('Отзыв'); await s.page.locator('#nodeRevoke').click(); }
        await s.page.locator('#nodeIdentityError').waitFor();
        assert.match(await s.page.locator('#nodeIdentityError').textContent(), /invalid_/); assert.equal(await s.page.locator('#nodeApprove').isEnabled().catch(() => false), false);
        await s.context.close();
    }
    console.log('PASS: malformed cross-node CSR, oversize/duplicate pages and unsafe operation URL fail closed');
    {
        const s = await scenario(); await select(s); s.flags.shortTTL = true; await issue(s); await s.page.locator('#nodeEnrollmentToken').waitFor();
        await s.page.waitForFunction(() => !document.querySelector('#nodeEnrollmentToken')); assert.match(await s.page.locator('#nodeEnrollmentExpiry').textContent(), /Истёк/);
        await s.context.close(); console.log('PASS: token expiry clears secret and closes approval window without page reload');
    }
    assert.deepEqual(failures, []); console.log('PASS: strict CSP, escaped values, no external requests or browser runtime errors');
} finally { await browser.close(); }
