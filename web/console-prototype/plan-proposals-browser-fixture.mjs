// Browser transport fixtures: preliminary review only, no execution or native qualification.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const moduleName = process.env.AGP_TEST_PLAYWRIGHT_MODULE || 'playwright';
const { chromium } = await import(moduleName.startsWith('/') ? pathToFileURL(moduleName).href : moduleName);
const browser = await chromium.launch({ headless: true, ...(process.env.AGP_TEST_CHROMIUM_BIN ? { executablePath: process.env.AGP_TEST_CHROMIUM_BIN } : {}) });
const origin = 'https://management.example.test', assetRoot = new URL('../../internal/frontend/static/config/', import.meta.url);
const cookie = '__Host-planning_fixture_csrf', csrf = 'P'.repeat(43), digest = 'sha256:' + 'a'.repeat(64), failures = [];
const createdAt = '2026-11-24T10:00:00Z', expiresAt = '2030-01-01T00:00:00Z';
const proposal = (id = 'proposal_seed', authorId = 'user_author') => ({
    apiVersion: 'agp.plan-proposal/v1alpha1', purpose: 'planning_review', deployable: false, noExecution: true,
    id, siteId: 'site_fixture', revisionId: 'cfg_fixture', configDigest: digest, compilerDigest: digest, compilerVersion: 'fixture_compiler', inventoryDigest: digest,
    catalogSnapshotId: 'catalog_fixture', catalogDigest: digest, dependencyDigest: digest, previewDigest: digest, proposalDigest: digest, authorId, authorityEpoch: '1',
    createdAt, expiresAt, reason: '<img src=x onerror=alert(1)>', rolloutPolicy: { canaryNodeIds: ['node_a'], maxParallel: 1, maxUnavailable: 0, observationSeconds: 60, failureAction: 'pause' },
    targets: [{ nodeId: 'node_a', capabilityDigest: digest, previewBundleDigest: digest, gatewayIds: ['gateway_selected', 'gateway_other_site'], secretVersionIds: ['secret_v1'] }, { nodeId: 'node_b', capabilityDigest: digest, previewBundleDigest: digest, gatewayIds: ['gateway_selected'], secretVersionIds: [] }],
    resolvedInputs: [{ kind: 'component', id: 'component_fixture', digest }], blockers: ['capture_baseline_required', 'owned_tree_verification_required', 'node_bundle_qualification_required', 'execution_authorizer_required'],
});
const seedReview = (proposal) => ({ id: 'review_seed', proposalId: proposal.id, proposalDigest: proposal.proposalDigest, authorId: proposal.authorId, reviewerId: 'user_reviewer', purpose: 'planning_review', current: true, createdAt, expiresAt, reason: 'Независимая проверка полного дерева' });

async function scenario(options = {}) {
    const context = await browser.newContext({ viewport: { width: options.width || 1440, height: 1000 }, acceptDownloads: true });
    const page = await context.newPage(), calls = [], receipts = new Map(), proposals = new Map([['proposal_seed', proposal()]]), reviews = new Map();
    const flags = { loseCreate: false, loseReview: false, stale: !!options.stale, rejectStale: false, stepUp: false, signerUnavailable: false, malformed: '', shortTTL: false, duplicatePage: false };
    if (options.review) reviews.set('proposal_seed', [seedReview(proposals.get('proposal_seed'))]);
    let serial = 0; const expiries = new Map();
    await context.addCookies([{ name: cookie, value: csrf, url: origin, secure: true, sameSite: 'Strict' }]);
    page.on('pageerror', error => failures.push(error.message));
    page.on('console', message => { if (message.type() === 'error' && /Content Security Policy|Refused to|NG0/.test(message.text())) failures.push(message.text()); });
    await page.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method();
        if (url.origin !== origin) { failures.push('Unexpected external request'); return route.abort(); }
        const reply = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
        if (path === '/api/v1/public/runtime') return reply({ mode: 'management', secure_profile: true, csrf_cookie_name: cookie, management_url: origin, auth_ui_url: '/auth-ui/login' });
        if (path === '/api/v1/me') return reply({ user: { id: 'user_reviewer', username: 'fixture', is_admin: options.admin !== false } });
        if (path === '/api/v2/config/access') return reply({ principalId: 'user_reviewer', globalRead: options.read !== false, globalEdit: options.edit !== false, globalApprove: options.approve !== false, sites: [{ siteId: 'site_fixture', read: true, edit: false, approve: false }], authorityEpoch: '1' });
        if (path === '/api/v2/config/profile') return reply({ enabled: true });
        if (path === '/api/v2/config/revisions') return reply({ items: [{ id: 'cfg_fixture', contentDigest: digest, revision: '1', viewScope: 'full', state: 'ready' }] });
        if (['/api/v2/config/catalog-snapshots', '/api/v2/waf/authoring-zones'].includes(path)) return reply({ items: [] });
        if (path.startsWith('/api/v2/')) {
            const headers = request.headers(), body = method === 'GET' ? null : request.postDataJSON();
            calls.push({ path, query: url.search, method, headers, body });
            if (method !== 'GET') {
                assert.equal(headers['origin'], origin); assert.equal(headers['x-csrf-token'], csrf); assert.match(headers['idempotency-key'], /^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/);
                if (flags.stepUp) return reply({ code: 'step_up_required' }, 403);
                if (flags.rejectStale) return reply({ code: 'proposal_stale' }, 409);
                const old = receipts.get(headers['idempotency-key']);
                if (old) { assert.equal(old.fingerprint, JSON.stringify([path, body])); return reply(old.body, old.status); }
            }
            const remember = async (response, status = 200, lose = false) => {
                receipts.set(headers['idempotency-key'], { fingerprint: JSON.stringify([path, body]), body: response, status });
                return lose ? route.abort() : reply(response, status);
            };
            if (path === '/api/v2/config/plan-proposals') {
                if (method === 'GET') {
                    assert.equal(url.searchParams.get('limit'), '20');
                    const second = url.searchParams.has('cursor');
                    return reply({ items: options.empty ? [] : [{ proposal: proposal(second && !flags.duplicatePage ? 'proposal_second' : 'proposal_seed'), current: !flags.stale }], ...(!second && options.pagination ? { nextCursor: 'cGxhbl9wYWdl' } : {}) });
                }
                assert.deepEqual(Object.keys(body).sort(), ['reason', 'revisionId', 'rolloutPolicy', 'siteId', 'targetNodeIds']);
                assert.equal(body.revisionId, 'cfg_fixture'); assert.equal(body.siteId, 'site_fixture'); assert.deepEqual(body.targetNodeIds, ['node_a', 'node_b']);
                assert.deepEqual(body.rolloutPolicy, { canaryNodeIds: ['node_a'], maxParallel: 1, maxUnavailable: 0, observationSeconds: 60, failureAction: 'pause' });
                const result = { ...proposal('proposal_created_' + ++serial, 'user_reviewer'), reason: body.reason, rolloutPolicy: body.rolloutPolicy };
                proposals.set(result.id, result); const lose = flags.loseCreate; flags.loseCreate = false; return remember(result, 201, lose);
            }
            const parts = path.split('/'), id = parts[5], p = proposals.get(id);
            if (p && parts.length === 6 && method === 'GET') {
                const value = structuredClone(p);
                if (flags.shortTTL) { value.expiresAt = new Date(Date.now() + 1000).toISOString(); expiries.set(id, value.expiresAt); }
                if (flags.malformed === 'executable') value.deployable = true;
                if (flags.malformed === 'wrong-node') value.targets[1].nodeId = 'node_a';
                if (flags.malformed === 'wrong-id') value.id = 'proposal_elsewhere';
                return reply({ proposal: value, current: !flags.stale });
            }
            if (p && parts[6] === 'reviews' && parts.length === 7) {
                if (method === 'GET') return reply((reviews.get(id) || []).map(review => ({ ...review, ...(flags.shortTTL ? { expiresAt: expiries.get(id) } : {}) })));
                assert.deepEqual(Object.keys(body).sort(), ['proposalDigest', 'reason']); assert.equal(body.proposalDigest, digest);
                const review = { ...seedReview(p), id: 'review_' + ++serial, reason: body.reason };
                reviews.set(id, [...(reviews.get(id) || []), review]); const lose = flags.loseReview; flags.loseReview = false; return remember(review, 201, lose);
            }
            if (p && parts[6] === 'reviews' && parts[8] === 'signatures') {
                assert.deepEqual(body, {});
                if (flags.signerUnavailable) return reply({ code: 'security_state_unavailable' }, 503);
                const review = reviews.get(id).find(item => item.id === parts[7]);
                return remember({ apiVersion: 'agp.signed-plan-review/v1alpha1', purpose: 'planning_review', deployable: false, noExecution: true, keyId: 'planning_key_fixture', proposal: p, review, signatureAlgorithm: 'Ed25519', signatureBase64: Buffer.alloc(64).toString('base64') });
            }
            failures.push('Unexpected API path ' + path); return reply({ code: 'not_found' }, 404);
        }
        const file = path.startsWith('/config-ui/') && /\.[A-Za-z0-9]+$/.test(path) ? path.slice('/config-ui/'.length) : 'index.html';
        assert.ok(!file.includes('..') && !file.includes('/'));
        const contentType = file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.png') ? 'image/png' : 'text/html';
        return route.fulfill({ status: 200, headers: { 'Content-Type': contentType, 'Content-Security-Policy': "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'" }, body: await readFile(new URL(file, assetRoot)) });
    });
    await page.goto(origin + '/config-ui/', { waitUntil: 'networkidle' }); await page.locator('#zonesTitle').waitFor();
    return { context, page, calls, flags, proposals, reviews };
}
async function open(s) { await s.page.locator('#planProposalsTab').click(); await s.page.locator('#planProposalsTitle').waitFor(); await s.page.waitForFunction(() => document.querySelector('#planRefreshList')?.disabled === false); }
async function load(s, id = 'proposal_seed') { await s.page.locator('#planLookup').fill(id); await s.page.locator('#planLoad').click(); await s.page.locator('#planReport').waitFor(); }
async function fill(s) { await s.page.locator('#planRevision').selectOption('cfg_fixture'); await s.page.locator('#planSite').fill('site_fixture'); await s.page.locator('#planTargets').fill('node_a\nnode_b'); await s.page.locator('#planReason').fill('Подготовка конфигурации по точному снимку'); }
try {
    {
        const s = await scenario({ read: false }); assert.equal(await s.page.locator('#planProposalsTab').count(), 0); assert.equal(s.calls.some(call => call.path.includes('plan-proposals')), false); await s.context.close();
        console.log('PASS: scoped-only read has no global planning tab or planning requests');
    }
    {
        const s = await scenario({ empty: true, width: 390 }); assert.equal(s.calls.some(call => call.path.includes('plan-proposals')), false);
        await s.page.locator('#zonesTab').focus(); await s.page.keyboard.press('End'); await s.page.waitForFunction(() => document.querySelector('#scopedGatewayTab')?.getAttribute('aria-selected') === 'true');
        await open(s); await s.page.locator('#planEmpty').waitFor(); await fill(s);
        await s.page.locator('#planTargets').fill('node_a,node_a'); assert.equal(await s.page.locator('#planCreate').isDisabled(), true);
        await s.page.locator('#planTargets').fill('node_a,node_b'); await s.page.locator('#planCanaries').fill('node_outside'); assert.equal(await s.page.locator('#planCreate').isDisabled(), true);
        await s.page.locator('#planCanaries').fill(''); await s.page.waitForFunction(() => document.querySelector('#planCreate')?.disabled === false); await s.page.locator('#planCreate').focus(); await s.page.keyboard.press('Enter'); await s.page.locator('#planReport').waitFor();
        await s.page.locator('#planLoad').click(); await s.page.locator('#planSelfReview').waitFor(); assert.equal(await s.page.locator('#planReview').count(), 0);
        await s.page.locator('.plan-target').first().locator('summary').click(); assert.match(await s.page.locator('#planReport').textContent(), /gateway_other_site/);
        assert.ok(await s.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        assert.deepEqual(await s.page.evaluate(() => [Object.keys(localStorage), Object.keys(sessionStorage)]), [[], []]);
        assert.equal(s.calls.some(call => /tasks|apply|deployments|executions/.test(call.path)), false);
        await s.context.close(); console.log('PASS: lazy mobile/keyboard planning, exact typed target/canary validation, frozen full-node tree and self-review prevention');
    }
    {
        const s = await scenario(); await open(s); await fill(s); s.flags.loseCreate = true; await s.page.locator('#planCreate').click(); await s.page.locator('#planRetry').waitFor();
        assert.equal(await s.page.locator('#planSite').isDisabled(), true); assert.equal(await s.page.locator('#planLookup').isEditable(), false);
        await s.page.locator('#zonesTab').click(); await s.page.locator('#planProposalsTab').click(); await s.page.locator('#planRetry').waitFor();
        await s.page.locator('#planRetry').click(); await s.page.locator('#planPending').waitFor({ state: 'detached' }); await s.page.locator('#planReport').waitFor();
        const writes = s.calls.filter(call => call.path.endsWith('/plan-proposals') && call.method === 'POST'); assert.equal(writes.length, 2); assert.equal(writes[0].headers['idempotency-key'], writes[1].headers['idempotency-key']); assert.deepEqual(writes[0].body, writes[1].body);
        await s.context.close(); console.log('PASS: lost creation response preserves exact body/key and pending state across tabs');
    }
    {
        const s = await scenario({ edit: false, admin: false }); await open(s); assert.equal(await s.page.locator('#planCreate').isDisabled(), true); await load(s);
        assert.equal(await s.page.locator('agp-plan-proposals-panel img').count(), 0); assert.match(await s.page.locator('#planReport').textContent(), /<img src=x/);
        await s.page.locator('#planReviewReason').fill('Независимое согласование полного дерева'); s.flags.loseReview = true; await s.page.locator('#planReview').click(); await s.page.locator('#planRetry').waitFor(); await s.page.locator('#planRetry').click(); await s.page.locator('#planPending').waitFor({ state: 'detached' });
        const writes = s.calls.filter(call => call.path.endsWith('/reviews') && call.method === 'POST'); assert.equal(writes.length, 2); assert.equal(writes[0].headers['idempotency-key'], writes[1].headers['idempotency-key']); assert.deepEqual(writes[0].body, writes[1].body);
        s.flags.signerUnavailable = true; await s.page.getByRole('button', { name: 'Получить подписанное согласование' }).click(); await s.page.waitForFunction(() => document.querySelector('#planStatus')?.textContent.includes('недоступен'));
        assert.equal(await s.page.locator('#planPending').count(), 1); assert.equal(await s.page.locator('.plan-reviews li').count(), 1);
        s.flags.signerUnavailable = false; await s.page.locator('#planRetry').click(); await s.page.locator('#planSignedArtifact').waitFor();
        assert.match(await s.page.locator('#planSignedArtifact').textContent(), /Подлинность подписи в браузере не проверялась/);
        const downloaded = s.page.waitForEvent('download'); await s.page.locator('#planDownloadSigned').click(); const file = await downloaded; assert.match(file.suggestedFilename(), /^planning-review-review_\d+\.json$/);
        await s.context.close(); console.log('PASS: independent global approver without edit/admin, escaped DOM, review idempotency, optional signer503 and read-only signed artifact download');
    }
    {
        const s = await scenario({ approve: false, admin: true }); await open(s); await load(s); await s.page.locator('#planNoApprove').waitFor(); assert.equal(await s.page.locator('#planReview').count(), 0); await s.context.close();
        console.log('PASS: administrator has no implicit approve bypass');
    }
    {
        const s = await scenario({ stale: true, review: true }); await open(s); await load(s); await s.page.locator('#planStale').waitFor(); assert.equal(await s.page.locator('#planReview').count(), 0); assert.equal(await s.page.getByRole('button', { name: 'Получить подписанное согласование' }).count(), 0);
        s.flags.stale = false; await load(s); await s.page.locator('#planReviewReason').fill('Причина при конкурентном устаревании'); s.flags.rejectStale = true; await s.page.locator('#planReview').click(); await s.page.locator('#planStale').waitFor(); assert.equal(await s.page.locator('#planPending').count(), 0);
        s.flags.rejectStale = false; s.flags.shortTTL = true; await load(s); await s.page.locator('#planReviewReason').waitFor(); await s.page.locator('#planStale').waitFor();
        await s.context.close(); console.log('PASS: stale current pins, concurrent409 and live expiry close review and signature actions');
    }
    {
        const s = await scenario({ empty: true }); await open(s); await fill(s); s.flags.stepUp = true; await s.page.locator('#planCreate').click(); await s.page.locator('#planError').waitFor();
        assert.equal(await s.page.locator('#planReason').inputValue(), 'Подготовка конфигурации по точному снимку'); assert.equal(await s.page.locator('#planPending').count(), 0); assert.equal(await s.page.getByRole('link', { name: 'Подтвердить MFA', exact: true }).getAttribute('href'), '/auth-ui/step-up?return=%2Fconfig-ui%2F');
        await s.context.close(); console.log('PASS: current MFA denial preserves input and offers safe same-origin return');
    }
    {
        const s = await scenario({ pagination: true }); await open(s); await s.page.locator('#planMore').click(); await s.page.waitForFunction(() => document.querySelectorAll('.plan-list li').length === 2); assert.equal(await s.page.locator('#planMore').count(), 0); await s.context.close();
        const d = await scenario({ pagination: true }); await open(d); d.flags.duplicatePage = true; await d.page.locator('#planMore').click(); await d.page.locator('#planError').waitFor(); assert.equal(await d.page.locator('.plan-list li').count(), 1); await d.context.close();
        console.log('PASS: bounded cursor pagination and duplicate-page fail-closed');
    }
    for (const malformed of ['executable', 'wrong-node', 'wrong-id']) {
        const s = await scenario(); await open(s); s.flags.malformed = malformed; await s.page.locator('#planLookup').fill('proposal_seed'); await s.page.locator('#planLoad').click(); await s.page.locator('#planError').waitFor();
        assert.equal(await s.page.locator('#planReport').count(), 0); assert.equal(await s.page.locator('#planReview').count(), 0); await s.context.close();
    }
    console.log('PASS: executable claims, duplicate targets and cross-proposal responses are rejected');
    assert.deepEqual(failures, []); console.log('PASS: strict CSP, custom CSRF cookie, no external requests or browser runtime errors');
} finally { await browser.close(); }
