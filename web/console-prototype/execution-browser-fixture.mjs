// Controlled browser transport tests. These do not qualify a native Nginx host.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
const moduleName = process.env.AGP_TEST_PLAYWRIGHT_MODULE || 'playwright';
const { chromium } = await import(moduleName.startsWith('/') ? pathToFileURL(moduleName).href : moduleName);
const browser = await chromium.launch({ headless: true, ...(process.env.AGP_TEST_CHROMIUM_BIN ? { executablePath: process.env.AGP_TEST_CHROMIUM_BIN } : {}) });
const origin = 'https://management.example.test', assetRoot = new URL('../../internal/frontend/static/config/', import.meta.url);
const cookie = '__Host-execution_fixture_csrf', csrf = 'E'.repeat(43), digest = 'sha256:' + 'a'.repeat(64), baseDigest = 'sha256:' + 'b'.repeat(64), failures = [];
const selectedCases = new Set((process.env.AGP_TEST_EXECUTION_CASES || '').split(',').filter(Boolean));
const run = name => !selectedCases.size || selectedCases.has(name);
const policy = { canaryNodeIds: ['node_a'], maxParallel: 1, maxUnavailable: 1, observationSeconds: 60, failureAction: 'pause' };
function plan(id = 'plan_seed') {
    return { apiVersion: 'agp.plan/v1alpha1', id, kind: 'apply_config', siteId: 'site_fixture', revisionId: 'cfg_new', createdBy: 'user_author', createdAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 20 * 60000).toISOString(), targets: [{ nodeId: 'node_a', baseRevisionId: 'cfg_base', expectedNodeDeploymentSequence: '7', capabilityDigest: digest, bundleDigest: digest, baseBundleDigest: baseDigest, secretVersionIds: [] }], rolloutPolicy: policy, compilerVersion: 'fixture_compiler', minimumDenySequence: '1', planDigest: digest, authorityEpoch: '1', reason: '<img src=x onerror=alert(1)>', resolvedInputs: [{ kind: 'assignment_resolution', id: 'execution_sources', digest }] };
}
function approval(p) { return { id: 'approval_' + p.id, planId: p.id, planDigest: p.planDigest, approvedBy: 'user_reviewer', approvalDigest: digest, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 4 * 60000).toISOString(), mfaAt: new Date().toISOString() }; }
function receipt(p, task) { return { apiVersion: 'agp.helper-execution-receipt/v1alpha1', purpose: 'local_execution_outcome', receiptId: 'receipt_' + task.id, receiptSequence: '1', nodeId: task.nodeId, taskId: task.id, requestDigest: digest, nodeDeploymentSequence: task.nodeDeploymentSequence, state: 'succeeded', recoveryRequired: false, recordedAt: new Date().toISOString(), keyId: 'root_receipt_fixture', signature: 'A'.repeat(86), active: { generationId: 'generation_new', treeDigest: digest, baseline: { revisionId: p.revisionId, bundleDigest: p.targets[0].bundleDigest, nodeDeploymentSequence: task.nodeDeploymentSequence } } }; }
async function scenario(options = {}) {
    const context = await browser.newContext({ viewport: { width: options.width || 1440, height: 1000 } }), page = await context.newPage(), calls = [], saved = new Map(), plans = new Map();
    const flags = { lose: '', malformed: '', disabled: false, unavailable: false, stepUp: false, complete: false, approver: options.user || 'user_reviewer' };
    const initial = { plan: plan(), state: options.approved ? 'approved' : 'validated', current: true, tasks: [] };
    if (options.approved) initial.approval = approval(initial.plan);
    plans.set('plan_seed', initial);
    await context.addCookies([{ name: cookie, value: csrf, url: origin, secure: true, sameSite: 'Strict' }]);
    page.on('pageerror', error => failures.push(error.message));
    page.on('console', message => { if (message.type() === 'error' && /Content Security Policy|Refused to|NG0/.test(message.text())) failures.push(message.text()); });
    let serial = 0;
    const view = item => {
        const v = structuredClone(item);
        if (flags.complete && v.tasks.length) { v.tasks = v.tasks.map(t => ({ ...t, state: 'succeeded', receipt: receipt(v.plan, t) })); v.state = 'succeeded'; }
        const terminal = ['succeeded', 'failed', 'cancelled', 'recovery_required'].includes(v.state);
        v.current = !terminal;
        v.access = { read: true, approve: !options.denied && v.state === 'validated' && v.plan.createdBy !== flags.approver, dispatch: !options.denied && ['approved', 'running'].includes(v.state), cancel: !options.denied && !terminal, rollback: !options.denied };
        if (flags.malformed === 'receipt' && v.tasks[0]?.receipt) v.tasks[0].receipt.taskId = 'task_wrong';
        if (flags.malformed === 'get') v.plan.targets[0].nodeId = 'node_wrong';
        return v;
    };
    await page.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method();
        if (url.origin !== origin) { failures.push('Unexpected external request'); return route.abort(); }
        const reply = (body, status = 200) => route.fulfill({ status, ...(status === 204 ? {} : { contentType: 'application/json', body: JSON.stringify(body) }) });
        if (path === '/api/v1/public/runtime') return reply({ mode: 'management', secure_profile: true, csrf_cookie_name: cookie, management_url: origin });
        if (path === '/api/v1/me') return reply({ user: { id: flags.approver, username: 'fixture', is_admin: options.admin !== false } });
        if (path === '/api/v2/config/access') return reply({ principalId: flags.approver, globalRead: options.scoped !== true, globalEdit: options.scoped !== true, globalApprove: options.scoped !== true, sites: [{ siteId: 'site_fixture', read: true, edit: true, approve: false }], authorityEpoch: '1' });
        if (path === '/api/v2/config/profile') return reply({ enabled: true });
        if (path === '/api/v2/config/revisions') return reply({ items: [] });
        if (['/api/v2/config/catalog-snapshots', '/api/v2/waf/authoring-zones'].includes(path)) return reply({ items: [] });
        if (path.startsWith('/api/v2/config/execution-plans')) {
            const headers = request.headers(), raw = request.postData(), body = method === 'GET' ? null : request.postDataJSON(), parts = path.split('/'), id = parts[5], action = parts[6] || 'create';
            calls.push({ path, method, headers, body, raw });
            if (flags.disabled) return reply({ code: 'execution_disabled' }, 404);
            if (flags.unavailable) return reply({ code: 'execution_source_unavailable' }, 503);
            if (method !== 'GET') {
                assert.equal(headers['origin'], origin); assert.equal(headers['x-csrf-token'], csrf); assert.match(headers['idempotency-key'], /^ui_[a-f0-9]{32}$/);
                if (flags.stepUp) return reply({ code: 'step_up_required' }, 403);
                const old = saved.get(headers['idempotency-key']);
                if (old) { assert.equal(old.path, path); assert.equal(old.raw, raw); return reply(old.body, old.status); }
            }
            const remember = (response, status) => {
                saved.set(headers['idempotency-key'], { path, raw, body: response, status });
                if (flags.lose === action) { flags.lose = ''; return route.abort(); }
                if (flags.malformed === 'empty-ack' && action === 'dispatch') { flags.malformed = ''; return reply({ items: [] }, status); }
                if (flags.malformed === 'write') { flags.malformed = ''; return reply({ accepted: true }, status); }
                return reply(response, status);
            };
            if (method === 'POST' && (!id || action === 'rollback-plans')) {
                assert.deepEqual(Object.keys(body).sort(), ['expiresAt', 'nodeIds', 'reason', 'revisionId', 'rolloutPolicy', 'siteId']); assert.deepEqual(body.rolloutPolicy, policy);
                const p = { ...plan('plan_created_' + ++serial), siteId: body.siteId, revisionId: body.revisionId, createdBy: flags.approver, expiresAt: body.expiresAt, reason: body.reason, rolloutPolicy: body.rolloutPolicy };
                if (action === 'rollback-plans') { p.kind = 'rollback_config'; p.targets[0].baseRevisionId = 'cfg_new'; p.targets[0].baseBundleDigest = digest; p.targets[0].bundleDigest = baseDigest; }
                const item = { plan: p, state: 'validated', current: true, tasks: [], ...(id ? { parentPlanId: id } : {}) };
                plans.set(p.id, item); return remember(item, 201);
            }
            const item = plans.get(id);
            if (!item) return reply({ code: 'not_found' }, 404);
            if (method === 'GET') return reply(view(item));
            if (action === 'approvals') { assert.deepEqual(body, { planDigest: digest }); item.approval = approval(item.plan); item.approval.approvedBy = flags.approver; item.state = 'approved'; return remember(item.approval, 201); }
            if (action === 'dispatch') {
                assert.deepEqual(body, { planDigest: digest });
                const task = { id: 'task_' + id, nodeId: 'node_a', nodeDeploymentSequence: '8', state: 'dispatched' }; item.tasks = [task]; item.state = 'running';
                const { state, ...ack } = task; return remember({ items: [ack] }, 201);
            }
            if (action === 'cancel') { assert.deepEqual(body, {}); item.state = 'cancelled'; return remember(undefined, 204); }
            failures.push('Unexpected execution API ' + path); return reply({ code: 'not_found' }, 404);
        }
        if (path.startsWith('/api/')) { failures.push('Unexpected API ' + path); return reply({ code: 'not_found' }, 404); }
        const file = path.startsWith('/config-ui/') && /\.[A-Za-z0-9]+$/.test(path) ? path.slice('/config-ui/'.length) : 'index.html';
        assert.ok(!file.includes('..') && !file.includes('/'));
        const contentType = file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.png') ? 'image/png' : 'text/html';
        return route.fulfill({ status: 200, headers: { 'Content-Type': contentType, 'Content-Security-Policy': "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'" }, body: await readFile(new URL(file, assetRoot)) });
    });
    await page.goto(origin + '/config-ui/', { waitUntil: 'networkidle' }); await page.locator('#zonesTitle').waitFor();
    assert.equal(calls.length, 0);
    await page.locator('#executionTab').click(); await page.locator('#executionTitle').waitFor();
    return { page, context, calls, flags, plans };
}
async function idle(s) { await s.page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))); await s.page.waitForFunction(() => document.querySelector('#executionLoad')?.disabled === false); }
async function load(s, id = 'plan_seed') { await s.page.locator('#executionLookup').fill(id); await s.page.locator('#executionLoad').click(); await idle(s); }
async function fill(s, revision = 'cfg_new') { await s.page.locator('#executionSite').fill('site_fixture'); await s.page.locator('#executionRevision').fill(revision); await s.page.locator('#executionNodes').fill('node_a'); await s.page.locator('#executionReason').fill('Проверенное изменение конфигурации'); }
async function approve(s) { await s.page.locator('#executionConfirmDigest').check(); await s.page.locator('#executionApprove').click(); await idle(s); }
async function dispatch(s) { await s.page.locator('#executionConfirmDispatch').check(); await s.page.locator('#executionDispatch').click(); await idle(s); }
try {
    if (run('workflow')) {
        const s = await scenario(); await load(s); assert.equal(await s.page.locator('#executionReport img').count(), 0); await approve(s);
        assert.equal(s.calls.filter(c => c.path.endsWith('/dispatch')).length, 0); await dispatch(s); assert.match(await s.page.locator('.execution-task').textContent(), /результат ожидается/);
        assert.doesNotMatch(await s.page.locator('#executionState').textContent(), /проверки пройдены/);
        s.flags.complete = true; await load(s); assert.match(await s.page.locator('#executionState').textContent(), /Применено, проверки пройдены/); assert.match(await s.page.locator('.execution-task').textContent(), /root_receipt_fixture/);
        await s.page.locator('#executionRollback').click(); await fill(s, 'cfg_base'); await s.page.locator('#executionCreate').click(); await idle(s);
        const id = await s.page.locator('#executionLookup').inputValue(); assert.notEqual(id, 'plan_seed'); assert.match(await s.page.locator('#executionState').textContent(), /Ждёт согласования/); assert.equal(await s.page.locator('#executionDispatch').count(), 0);
        s.flags.approver = 'user_other'; s.flags.complete = false; await load(s, id); await approve(s); assert.equal(s.calls.filter(c => c.path.endsWith('/dispatch')).length, 1);
        await s.context.close(); console.log('PASS: independent approval, explicit dispatch, authoritative signed outcome and rollback requiring new approval');
    }
    if (run('cancel')) {
        const s = await scenario({ approved: true }); await load(s); await s.page.locator('#executionCancel').click(); await idle(s); assert.match(await s.page.locator('#executionState').textContent(), /отменена/); assert.equal(await s.page.locator('#executionRetry').count(), 0); await s.context.close(); console.log('PASS: 204 cancellation resolves once without JSON parsing or invented rollback');
    }
    if (run('rights')) {
        const s = await scenario({ denied: true, approved: true }); await load(s); assert.equal(await s.page.locator('#executionApprove,#executionDispatch,#executionCancel,#executionRollback').count(), 0); assert.equal(s.calls.filter(c => c.method === 'POST').length, 0); await s.context.close(); console.log('PASS: admin/config permissions never imply exact execution rights');
    }
    if (run('scoped')) {
        const s = await scenario({ scoped: true, admin: false, width: 390 }); await fill(s); assert.equal(await s.page.locator('#executionCreate').isEnabled(), true); await s.page.locator('#executionNodes').fill('node_a,node_a'); assert.equal(await s.page.locator('#executionCreate').isDisabled(), true); await s.page.locator('#executionNodes').fill('node_a'); await s.page.locator('#executionCreate').focus(); await s.page.keyboard.press('Enter'); await idle(s); assert.equal(await s.page.locator('#executionReport').count(), 1); assert.equal(await s.page.locator('#executionApprove').count(), 0); assert.ok(await s.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)); assert.deepEqual(await s.page.evaluate(() => [Object.keys(localStorage), Object.keys(sessionStorage)]), [[], []]); await s.context.close(); console.log('PASS: scoped authoring, duplicate validation, keyboard/mobile layout and no browser token persistence');
    }
    if (run('sources')) {
        const s = await scenario(); s.flags.disabled = true; await load(s); assert.match(await s.page.locator('#executionError').textContent(), /ещё не подключено/); assert.equal(await s.page.locator('#executionReport').count(), 0); s.flags.disabled = false; s.flags.unavailable = true; await load(s); assert.match(await s.page.locator('#executionError').textContent(), /исходное состояние или готовность выбранных узлов/); await s.context.close(); console.log('PASS: disabled execution and unavailable verified sources remain visibly unavailable');
    }
    if (run('lost-create')) {
        const s = await scenario(); await fill(s); s.flags.lose = 'create'; await s.page.locator('#executionCreate').click(); await s.page.locator('#executionRetry').waitFor(); assert.equal(await s.page.locator('#executionRevision').isDisabled(), true); await s.page.locator('#zonesTab').click(); await s.page.locator('#executionTab').click(); await s.page.locator('#executionRetry').click(); await idle(s); const writes = s.calls.filter(c => c.method === 'POST'); assert.equal(writes.length, 2); assert.equal(writes[0].headers['idempotency-key'], writes[1].headers['idempotency-key']); assert.equal(writes[0].raw, writes[1].raw); assert.equal(s.plans.size, 2); await s.context.close(); console.log('PASS: lost create response freezes fields and preserves exact request/key across tab changes');
    }
    if (run('lost-dispatch')) {
        const s = await scenario({ approved: true }); await load(s); s.flags.lose = 'dispatch'; await s.page.locator('#executionConfirmDispatch').check(); await s.page.locator('#executionDispatch').click(); await s.page.locator('#executionRetry').waitFor(); assert.equal(await s.page.locator('#executionDispatch').count(), 0); await s.page.locator('#executionRetry').click(); await idle(s); const writes = s.calls.filter(c => c.path.endsWith('/dispatch')); assert.equal(writes.length, 2); assert.equal(writes[0].raw, writes[1].raw); assert.equal(writes[0].headers['idempotency-key'], writes[1].headers['idempotency-key']); assert.match(await s.page.locator('.execution-task').textContent(), /результат ожидается/); await s.context.close(); console.log('PASS: lost dispatch response retries exactly without inventing successful application');
    }
    if (run('bad-receipt')) {
        const s = await scenario({ approved: true }); await load(s); await dispatch(s); s.flags.complete = true; s.flags.malformed = 'receipt'; await load(s); assert.equal(await s.page.locator('#executionReport').count(), 0); assert.match(await s.page.locator('#executionError').textContent(), /неподтверждённый ответ/); await s.context.close(); console.log('PASS: mismatched signed receipt cannot become displayed success or execution authority');
    }
    if (run('bad-write')) {
        const s = await scenario(); await fill(s); s.flags.malformed = 'write'; await s.page.locator('#executionCreate').click(); await s.page.locator('#executionRetry').waitFor(); assert.equal(await s.page.locator('#executionReport').count(), 0); await s.page.locator('#executionRetry').click(); await idle(s); assert.equal(s.plans.size, 2); await s.context.close(); console.log('PASS: malformed committed write response retains exact safe retry');
    }
    if (run('mfa')) {
        const s = await scenario(); await load(s); s.flags.stepUp = true; await approve(s); assert.match(await s.page.locator('#executionError').textContent(), /свежую MFA/); assert.equal(await s.page.locator('#executionDispatch').count(), 0); assert.equal(await s.page.locator('#executionRetry').count(), 0); await s.context.close(); console.log('PASS: fresh MFA rejection invalidates authority and requires refresh');
    }
    if (run('empty-dispatch')) {
        const s = await scenario({ approved: true }); await load(s); s.flags.malformed = 'empty-ack';
        await s.page.locator('#executionConfirmDispatch').check(); await s.page.locator('#executionDispatch').click(); await s.page.locator('#executionRetry').waitFor();
        assert.match(await s.page.locator('#executionError').textContent(), /неподтверждённый ответ/);
        assert.doesNotMatch(await s.page.locator('#executionStatus').textContent(), /Выдача задания подтверждена/);
        assert.equal(await s.page.locator('.execution-task').count(), 0); assert.equal(await s.page.locator('#executionDispatch').count(), 0);
        await s.page.locator('#executionRetry').click(); await idle(s);
        const writes = s.calls.filter(c => c.path.endsWith('/dispatch')); assert.equal(writes.length, 2);
        assert.equal(writes[0].headers['idempotency-key'], writes[1].headers['idempotency-key']); assert.equal(writes[0].raw, writes[1].raw);
        assert.match(await s.page.locator('.execution-task').textContent(), /результат ожидается/);
        await s.context.close(); console.log('PASS: empty sequential dispatch acknowledgement retains exact retry and never confirms delivery');
    }
    assert.deepEqual(failures, []);
} finally { await browser.close(); }
