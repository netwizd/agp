// Browser-only transport fixtures. These assertions do not qualify native WAF,
// authenticate real agents, or replace the full PostgreSQL/native acceptance.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const moduleName = process.env.AGP_TEST_PLAYWRIGHT_MODULE || 'playwright';
const { chromium } = await import(moduleName.startsWith('/') ? pathToFileURL(moduleName).href : moduleName);
const browser = await chromium.launch({ headless: true, ...(process.env.AGP_TEST_CHROMIUM_BIN ? { executablePath: process.env.AGP_TEST_CHROMIUM_BIN } : {}) });
const origin = 'https://management.example.test';
const assetRoot = new URL('../../internal/frontend/static/config/', import.meta.url);
const digest = 'sha256:' + 'a'.repeat(64), token = 'C'.repeat(43), cookie = '__Host-fleet_fixture_csrf';
const future = '2030-01-01T00:00:00Z', created = '2026-11-19T12:00:00Z';
const failures = [];
const proof = { id: 'qualification_fixture', contentDigest: digest, rulesetVersionId: 'crs_fixture', rulesetDigest: digest, profileId: 'profile_fixture', profileDigest: digest, tupleDigest: digest, evidenceDigest: digest, manifestDigest: digest, releaseSequence: '42', compilerDigest: digest, expiresAt: future };

async function scenario(options = {}) {
    const context = await browser.newContext({ viewport: { width: options.width || 1440, height: 1000 } });
    const page = await context.newPage();
    await context.addCookies([{ name: cookie, value: token, url: origin, secure: true, sameSite: 'Strict' }]);
    const calls = [], receipts = new Map(), operations = new Map(), flags = { lost: false, stale: false, self: false, expired: false, conflicts: false, inventoryFailure: false };
    let resolutionCount = 0, change = null;
    const zone = { id: 'zone_revision_fixture', content: { apiVersion: 'agp.waf-zone/v1alpha1', kind: 'WafZone', metadata: { id: 'zone_fixture', name: 'Fixture zone', siteId: 'site_fixture', ownerId: 'user_other' }, spec: { policyRevisionId: 'policy_fixture', mode: 'blocking', membership: { gatewayIds: ['gw_fixture'] }, reason: 'Fixture browser lifecycle' } }, contentDigest: digest, state: options.state || 'draft', revision: '1' };
    let resolution;
    const validation = () => ({ id: 'zone_validation_fixture', zoneRevisionId: zone.id, contentDigest: digest, policyRevisionId: 'policy_fixture', policyPublicationId: 'publication_fixture', qualification: proof, dependencyDigest: digest, valid: true, current: !flags.stale, deployable: false, issues: [], createdAt: created, expiresAt: future });
    function accepted(resourceId) {
        const operationId = 'operation_' + resourceId;
        operations.set(operationId, { id: operationId, resourceId, state: 'succeeded', createdAt: created, updatedAt: created });
        return { operationId, resourceId, statusUrl: '/api/v2/operations/' + operationId, submittedAt: created };
    }
    page.on('pageerror', error => failures.push(error.message));
    page.on('console', message => { if (message.type() === 'error' && /Content Security Policy|Refused to|NG0/.test(message.text())) failures.push(message.text()); });
    await page.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method();
        if (url.origin !== origin) { failures.push('Unexpected external request ' + url.origin); return route.abort(); }
        const reply = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
        if (path === '/api/v1/public/runtime') return reply({ mode: 'management', secure_profile: true, csrf_cookie_name: cookie, management_url: origin, auth_ui_url: '/auth-ui/login' });
        if (path === '/api/v1/me') return reply({ user: { id: 'user_fixture', username: 'fixture', display_name: 'Browser fixture', is_admin: !!options.admin } });
        if (path === '/api/v2/config/access') return reply({ principalId: 'user_fixture', globalRead: !!options.admin, globalEdit: !!options.admin, globalApprove: false, sites: [{ siteId: 'site_fixture', read: true, edit: options.edit !== false, approve: !!options.approve }], authorityEpoch: '1' });
        if (path === '/api/v2/config/profile') return reply({ enabled: true });
        if (path === '/api/v2/config/revisions' || path === '/api/v2/config/catalog-snapshots') return reply({ items: [] });
        if (path.startsWith('/api/v2/operations/')) return reply(operations.get(path.split('/').at(-1)));
        if (path.startsWith('/api/v2/')) {
            const headers = request.headers(), body = method === 'GET' ? null : request.postDataJSON();
            calls.push({ path, method, body, headers });
            if (method !== 'GET') {
                assert.equal(headers['x-csrf-token'], token);
                assert.equal(headers['origin'], origin);
                assert.match(headers['idempotency-key'], /^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/);
                const old = receipts.get(headers['idempotency-key']);
                if (old) { assert.equal(old.fingerprint, JSON.stringify([path, body])); return reply(old.body, old.status); }
            }
            const remember = (response, status = 200) => { receipts.set(headers['idempotency-key'], { fingerprint: JSON.stringify([path, body]), body: response, status }); return reply(response, status); };
            if (path === '/api/v2/node-identity-profile') return reply({ enabled: false, supportedRoles: ['agent'] });
            if (path === '/api/v2/agent-inventory') {
                if (flags.inventoryFailure) return reply({ code: 'journal_unavailable' }, 503);
                return reply({ items: [{ id: 'node_fixture', siteId: 'site_fixture', name: '<img src=x onerror=alert(1)>', labels: { role: 'edge' }, groupIds: ['group_fixture'], connectivity: 'online', identityState: 'active', capabilityDigest: digest, lastSeenAt: created }] });
            }
            if (path === '/api/v2/waf/authoring-zones') return reply({ items: [{ id: zone.id, zoneId: zone.content.metadata.id, siteId: 'site_fixture', ownerId: 'user_other', contentDigest: digest, state: zone.state, revision: '1' }] });
            if (path === '/api/v2/waf/zone-revisions/' + zone.id) return reply(zone);
            if (path === '/api/v2/waf/zone-revisions/' + zone.id + '/validations') { zone.state = 'validated'; return remember(accepted('zone_validation_fixture'), 202); }
            if (path === '/api/v2/waf/zone-validations/zone_validation_fixture') return reply(validation());
            if (path === '/api/v2/waf/zone-revisions/' + zone.id + '/approvals') {
                assert.equal(body.contentDigest, digest);
                if (flags.self) return reply({ code: 'distinct_approver_required' }, 403);
                if (flags.stale) return reply({ code: 'native_qualification_required' }, 409);
                zone.state = 'approved'; return remember({ approvalId: 'approval_fixture', contentDigest: digest }, 201);
            }
            if (path === '/api/v2/waf/zone-revisions/' + zone.id + '/publications') { assert.equal(zone.state, 'approved'); assert.equal(body.contentDigest, digest); zone.state = 'published'; return remember(zone); }
            if (path === '/api/v2/waf/zone-revisions/' + zone.id + '/resolutions') {
                assert.equal('catalogSnapshotId' in body, false);
                assert.equal(body.baseRevisionId, 'config_fixture');
                resolutionCount++;
                resolution = { apiVersion: 'agp.waf-zone-resolution/v1alpha1', kind: 'WafZoneResolution', id: 'resolution_' + resolutionCount, siteId: 'site_fixture', zoneRevisionId: zone.id, baseConfigRevisionId: 'config_fixture', action: body.action, inventoryDigest: digest, capacityProfile: body.capacityProfile, createdAt: created, expiresAt: flags.expired ? '2020-01-01T00:00:00Z' : future, resolutionDigest: digest, members: [{ gatewayId: 'gw_fixture', routeIds: ['route_fixture'], nodeIds: ['node_fixture'], sourcePolicyRevisionId: 'policy_old', targetPolicyRevisionId: 'policy_fixture', targetZoneRevisionId: zone.id, baseBindingDigest: digest, targetBindingDigest: digest, disposition: 'derived' }], conflicts: flags.conflicts ? [{ gatewayId: 'gw_fixture', code: 'waf_zone_ambiguous', path: '/', message: 'Fixture ambiguity' }] : [] };
                return remember(accepted(resolution.id), 202);
            }
            if (path.startsWith('/api/v2/waf/zone-resolutions/')) return reply(resolution);
            if (path === '/api/v2/waf/zone-changes') {
                assert.deepEqual(body, { apiVersion: 'agp.waf-zone-change/v1alpha1', kind: 'WafZoneChange', baseRevisionId: 'config_fixture', zoneRevisionId: zone.id, resolutionId: resolution.id, resolutionDigest: digest, reason: body.reason });
                if (flags.stale) return reply({ code: 'inventory_stale' }, 409);
                change = { id: 'change_fixture', request: body, requestDigest: digest, state: 'materialized', resultRevisionId: 'config_materialized_fixture', revision: '0' };
                const response = accepted(change.id);
                if (flags.lost) { flags.lost = false; receipts.set(headers['idempotency-key'], { fingerprint: JSON.stringify([path, body]), body: response, status: 202 }); return route.abort(); }
                return remember(response, 202);
            }
            if (path === '/api/v2/waf/zone-changes/change_fixture') return reply(change);
            failures.push('Unexpected API path ' + path); return reply({ code: 'not_found' }, 404);
        }
        const file = path.startsWith('/config-ui/') && /\.[A-Za-z0-9]+$/.test(path) ? path.slice('/config-ui/'.length) : 'index.html';
        assert.ok(!file.includes('..') && !file.includes('/'));
        const contentType = file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.png') ? 'image/png' : 'text/html';
        return route.fulfill({ status: 200, headers: { 'Content-Type': contentType, 'Content-Security-Policy': "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'" }, body: await readFile(new URL(file, assetRoot)) });
    });
    await page.goto(origin + '/config-ui/', { waitUntil: 'networkidle' });
    await page.locator('#zonesTitle').waitFor();
    return { context, page, calls, flags, zone };
}
async function loadZone(s) { await s.page.locator('#zoneRevisionLookup').fill(s.zone.id); await s.page.getByRole('button', { name: 'Открыть версию', exact: true }).click(); await s.page.locator('#zoneLifecycleTitle').waitFor(); }
async function loadValidation(s) { await s.page.locator('#zoneValidationLookup').fill('zone_validation_fixture'); await s.page.locator('#zoneLoadValidation').click(); await s.page.locator('#zoneValidationReport').waitFor(); }
async function resolve(s) { await s.page.locator('#zoneTrustedBase').fill('config_fixture'); await s.page.locator('#zoneResolve').click(); await s.page.locator('#zoneResolutionReport').waitFor(); }
async function materializeFields(s) { await s.page.locator('#zoneMaterializeDigest').fill(digest); await s.page.locator('#zoneMaterializeReason').fill('Создать полную desired-ревизию по точному resolution'); }
try {
    {
        const s = await scenario({ admin: true, width: 390 });
        assert.equal(s.calls.some(call => call.path === '/api/v2/agent-inventory'), false, 'hidden inventory must not fetch');
        await s.page.locator('#zonesTab').focus(); await s.page.keyboard.press('ArrowRight'); await s.page.keyboard.press('ArrowRight');
        await s.page.waitForFunction(() => document.querySelector('#inventoryTab')?.getAttribute('aria-selected') === 'true');
        assert.equal(await s.page.locator('#inventoryTab').getAttribute('aria-selected'), 'true');
        assert.equal(await s.page.locator('#inventoryTab').evaluate(element => element === document.activeElement), true);
        await s.page.locator('.inventory-node').waitFor();
        assert.match(await s.page.locator('.inventory-node').textContent(), /online.*active/s);
        assert.match(await s.page.locator('.inventory-node').textContent(), /Применённая ревизияНеизвестна/);
        assert.equal(await s.page.locator('.inventory-node img').count(), 0, 'untrusted name stays text');
        assert.ok(await s.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'mobile page must not overflow');
        s.flags.inventoryFailure = true; await s.page.locator('#inventoryRefresh').click(); await s.page.locator('#inventoryError').waitFor();
        assert.match(await s.page.locator('#inventoryError').textContent(), /актуальность не подтверждена/);
        await s.context.close(); console.log('PASS: admin inventory lazy load, explicit unknown health/applied, DOM escaping, stale read error and mobile layout');
    }
    {
        const s = await scenario({ edit: false, approve: true, state: 'validated' });
        assert.equal(await s.page.locator('#inventoryTab').count(), 0);
        assert.equal(s.calls.some(call => call.path === '/api/v2/agent-inventory'), false);
        await loadZone(s); await loadValidation(s);
        assert.equal(await s.page.locator('#zoneValidate').isDisabled(), true);
        await s.page.locator('#zoneApprovalDigest').fill(digest); await s.page.locator('#zoneApprovalReason').fill('Независимое подтверждение точного digest зоны');
        await s.page.locator('#zoneApprove').click(); await s.page.waitForFunction(() => document.querySelector('#zoneLifecycleState')?.textContent === 'approved');
        await s.page.locator('#zonePublish').click(); await s.page.waitForFunction(() => document.querySelector('#zoneLifecycleState')?.textContent === 'published');
        assert.equal(s.calls.some(call => call.path.endsWith('/resolutions') && call.method === 'POST'), false);
        await s.context.close(); console.log('PASS: read+approve actor publishes exact zone without edit, inventory disclosure or materialization');
    }
    {
        const s = await scenario({ admin: true }); await loadZone(s); await s.page.locator('#zoneValidate').click(); await s.page.locator('#zoneValidationReport').waitFor();
        assert.equal(await s.page.locator('#zoneApprove').isDisabled(), true, 'admin must not implicitly gain config.approve');
        assert.match(await s.page.locator('#zoneValidationReport').textContent(), /publication_fixture/);
        await s.context.close(); console.log('PASS: 202 native validation follows operation and admin has no implicit approval');
    }
    {
        const s = await scenario({ approve: true, state: 'validated' }); await loadZone(s); await loadValidation(s);
        await s.page.locator('#zoneApprovalDigest').fill(digest); await s.page.locator('#zoneApprovalReason').fill('Причина сохраняется при отказе собственного approval');
        s.flags.self = true; await s.page.locator('#zoneApprove').click(); await s.page.locator('#zoneLifecycleError').waitFor();
        assert.match(await s.page.locator('#zoneLifecycleError').textContent(), /HTTP 403/);
        assert.match(await s.page.locator('#zoneApprovalReason').inputValue(), /Причина сохраняется/);
        s.flags.self = false; s.flags.stale = true; await s.page.locator('#zoneApprove').click(); await s.page.waitForFunction(() => document.querySelector('#zoneLifecycleError')?.textContent.includes('409'));
        assert.equal(await s.page.locator('#zoneApprove').isDisabled(), true);
        await s.context.close(); console.log('PASS: server distinct approver and stale qualification failures preserve reason and require fresh check');
    }
    {
        const s = await scenario({ state: 'published' }); await loadZone(s); await resolve(s); await materializeFields(s);
        s.flags.lost = true; await s.page.locator('#zoneMaterialize').click(); await s.page.locator('#zoneLifecycleRetry').waitFor();
        const first = s.calls.find(call => call.path === '/api/v2/waf/zone-changes');
        assert.equal(await s.page.locator('#zoneName').isDisabled(), true, 'unknown result freezes revision selection');
        await s.page.locator('#zoneLifecycleRetry').click(); await s.page.locator('#zoneChangeReport').waitFor();
        const writes = s.calls.filter(call => call.path === '/api/v2/waf/zone-changes');
        assert.equal(writes[1].headers['idempotency-key'], first.headers['idempotency-key']); assert.deepEqual(writes[1].body, first.body);
        assert.equal(await s.page.locator('#zoneResultRevision').textContent(), 'config_materialized_fixture');
        assert.match(await s.page.locator('#zoneChangeReport').textContent(), /применения на узлах: неизвестно/);
        await s.context.close(); console.log('PASS: trusted resolution and full desired materialization, exact lost-response retry and no inferred node application');
    }
    {
        const s = await scenario({ state: 'published' }); await loadZone(s); await resolve(s); await materializeFields(s);
        s.flags.stale = true; await s.page.locator('#zoneMaterialize').click(); await s.page.locator('#zoneLifecycleError').waitFor();
        assert.equal(await s.page.locator('#zoneMaterialize').isDisabled(), true);
        assert.match(await s.page.locator('#zoneMaterializeReason').inputValue(), /Создать полную/);
        await s.page.locator('#zoneLoadResolution').click(); await materializeFields(s);
        assert.equal(await s.page.locator('#zoneMaterialize').isDisabled(), true, 'loading old frozen report cannot clear stale failure');
        s.flags.stale = false; await s.page.locator('#zoneResolve').click(); await s.page.waitForFunction(() => document.querySelector('#zoneResolutionLookup')?.value === 'resolution_2'); await materializeFields(s);
        assert.equal(await s.page.locator('#zoneMaterialize').isDisabled(), false);
        await s.context.close(); console.log('PASS: concurrent inventory409 retains reason and only a new resolution re-enables materialization');
    }
    for (const mode of ['expired', 'conflicts']) {
        const s = await scenario({ state: 'published' }); await loadZone(s); s.flags[mode] = true; await resolve(s); await materializeFields(s);
        assert.equal(await s.page.locator('#zoneMaterialize').isDisabled(), true);
        await s.context.close(); console.log('PASS: ' + mode + ' frozen resolution blocks desired materialization');
    }
    assert.deepEqual(failures, []); console.log('PASS: strict CSP, typed transport and no external requests or browser runtime errors');
} finally { await browser.close(); }
