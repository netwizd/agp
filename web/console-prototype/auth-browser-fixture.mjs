// UI contract tests only. API responses are fixtures; security enforcement needs the real HTTPS/backend suite.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
const moduleName = process.env.AGP_TEST_PLAYWRIGHT_MODULE || 'playwright';
const { chromium } = await import(moduleName.startsWith('/') ? pathToFileURL(moduleName).href : moduleName);
const browser = await chromium.launch({ headless: true, ...(process.env.AGP_TEST_CHROMIUM_BIN ? { executablePath: process.env.AGP_TEST_CHROMIUM_BIN } : {}) });
const assetRoot = new URL('../../internal/frontend/static/auth/', import.meta.url);
const failures = [];
const csrfInitial = 'C'.repeat(43), csrfRotated = 'R'.repeat(43);
const csp = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'";
const waitFor = async (page, selector) => page.locator(selector).waitFor({ state: 'visible' });
async function visible(page, selector) { return page.locator(selector).isVisible(); }
async function scenario(options = {}) {
  const audience = options.audience || 'management', purpose = options.purpose || 'login';
  const origin = audience === 'management' ? 'https://management.example.test' : 'https://login.example.test';
  const context = await browser.newContext({ viewport: { width: options.width || 1440, height: 1000 } });
  const page = await context.newPage();
  const calls = [], flags = { bootstrapFailure: false, corruptedAudience: false, weakMFA: false, lostCompletion: false }, stats = { sessions: 0 };
  let flow = null, csrfCurrent = csrfInitial;
  page.on('pageerror', error => failures.push(error.message));
  page.on('console', message => { if (message.type() === 'error' && /Content Security Policy|Refused to|NG0/.test(message.text())) failures.push(message.text()); });
  await page.addInitScript(() => localStorage.setItem('agp_csrf_token', 'stale-storage-token'));
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url()), pathname = url.pathname;
    if (url.origin !== origin) { failures.push('Unexpected external request: ' + url.origin); return route.abort(); }
    const reply = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (pathname === '/api/v1/public/settings') return reply({ settings: { brand_name: 'NLGate', logo_text: 'A' } });
    if (pathname === '/auth/v2/oidc/providers') return reply({ items: [] });
    if (pathname.startsWith('/auth/v2/')) {
      calls.push({ path: pathname, method: request.method(), headers: request.headers() });
      if (pathname === '/auth/v2/bootstrap') {
        if (flags.bootstrapFailure) return reply({ error: 'security_state_unavailable' }, 503);
        csrfCurrent = csrfInitial;
        await context.addCookies([{ name: '__Host-agp_flow_csrf', value: csrfInitial, url: origin, secure: true, sameSite: 'Strict' }]);
        return reply({ csrfToken: csrfInitial, csrfCookieName: '__Host-agp_flow_csrf', audience, loginUrl: 'https://login.example.test', managementUrl: 'https://management.example.test' });
      }
      if (request.method() === 'POST') {
        assert.equal(request.headers()['origin'], origin, 'browser must supply its own Origin');
        assert.equal(request.headers()['x-csrf-token'], csrfCurrent, 'CSRF must follow current cookie');
      }
      if (pathname === '/auth/v2/flows') {
        const body = request.postDataJSON();
        assert.equal(body.purpose, purpose); assert.equal(body.audience, purpose === 'recover' ? 'setup' : audience);
        await context.addCookies([{ name: '__Host-agp_pending', value: 'browser-binding', url: origin, secure: true, httpOnly: true, sameSite: 'Strict' }]);
        flow = { id: 'flow_initial', purpose, audience: purpose === 'recover' ? 'setup' : audience, state: 'pending_primary', nextStep: 'primary', expiresAt: '2030-01-01T12:00:00Z', mfaSatisfied: false };
        return reply(flow, 201);
      }
      if (!flow || !request.headers()['cookie']?.includes('__Host-agp_pending=browser-binding')) return reply({ error: 'binding_required' }, 401);
      if (pathname === `/auth/v2/flows/${flow.id}`) return reply({ ...flow, ...(flags.corruptedAudience ? { audience: audience === 'management' ? 'login' : 'management' } : {}) });
      if (pathname.endsWith('/primary-proofs')) {
        const body = request.postDataJSON();
        assert.equal(body.method, 'local_password');
        if (body.password !== 'test-password') return reply({ error: 'invalid_proof' }, 401);
        csrfCurrent = csrfRotated;
        await context.addCookies([{ name: '__Host-agp_flow_csrf', value: csrfRotated, url: origin, secure: true, sameSite: 'Strict' }]);
        flow = { ...flow, id: 'flow_rotated', state: options.passwordOnly ? 'ready' : 'pending_mfa', nextStep: options.passwordOnly ? 'complete' : purpose === 'recover' ? 'recovery' : options.enrollment ? 'totp_enrollment' : 'totp' };
        return reply(flow);
      }
      if (pathname.endsWith('/totp-proofs')) {
        if (request.postDataJSON().code !== '123456') return reply({ error: 'invalid_proof' }, 401);
        flow = { ...flow, state: 'ready', nextStep: 'complete', mfaSatisfied: !flags.weakMFA }; return reply(flow);
      }
      if (pathname.endsWith('/recovery-proofs')) {
        assert.equal(request.postDataJSON().method,'recovery_code');
        if (request.postDataJSON().code !== 'recovery-example-0001') return reply({ error: 'invalid_proof' }, 401);
        flow = { ...flow, nextStep: 'totp_enrollment' }; return reply(flow);
      }
      if (pathname.endsWith('/totp-enrollments')) return reply({ enrollmentId: 'enrollment_1', provisioningUri: 'otpauth://totp/AGP:user?secret=JBSWY3DPEHPK3PXP&issuer=AGP&digits=6&period=30', expiresAt: flow.expiresAt }, 201);
      if (pathname.endsWith('/confirmations')) {
        if (request.postDataJSON().code !== '123456') return reply({ error: 'invalid_proof' }, 401);
        flow = { ...flow, state: 'ready', nextStep: 'complete', mfaSatisfied: purpose !== 'recover' };
        return reply({ flow, issuedAt: '2026-11-18T12:00:00Z', recoveryCodes: ['recovery-example-0001', 'recovery-example-0002'] }, 201);
      }
      if (pathname.endsWith('/completions')) {
        assert.equal(flow.state, 'ready'); flow = { ...flow, state: 'completed', nextStep: 'none' }; if (purpose !== 'recover') stats.sessions++;
        if (flags.lostCompletion) { flags.lostCompletion = false; return route.abort(); }
        return reply(flow);
      }
      if (pathname.endsWith('/cancellations')) { flow = { ...flow, state: 'cancelled', nextStep: 'none', mfaSatisfied: false }; return reply(flow); }
      return reply({ error: 'unexpected_fixture_endpoint' }, 404);
    }
    const file = pathname.startsWith('/auth-ui/') && /\.[A-Za-z0-9]+$/.test(pathname) ? pathname.slice('/auth-ui/'.length) : 'index.html';
    assert.ok(!file.includes('..') && !file.includes('/'), 'asset must stay in fixture bundle root');
    const contentType = file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.png') ? 'image/png' : 'text/html';
    return route.fulfill({ status: 200, headers: { 'Content-Type': contentType, 'Content-Security-Policy': csp }, body: await readFile(new URL(file, assetRoot)) });
  });
  const path = purpose === 'step_up' ? 'step-up' : purpose === 'recover' ? 'recover' : 'login';
  await page.goto(origin + '/auth-ui/' + path + (options.returnPath ? '?return=' + encodeURIComponent(options.returnPath) : ''), { waitUntil: 'networkidle' });
  await waitFor(page, '#authPrimaryForm');
  const primary = async (password = 'test-password') => {
    await page.locator('#authUsername').fill('user'); await page.locator('#authPassword').fill(password); await page.locator('#authPrimaryForm button[type=submit]').click();
  };
  const totp = async (code = '123456') => { await page.locator('#authTotp').fill(code); await page.locator('#authTotpForm button[type=submit]').click(); };
  const enroll = async () => {
    await page.locator('#authStartEnrollment').click(); await waitFor(page, '#authManualSeed');
    await page.locator('#authEnrollmentCode').fill('123456'); await page.locator('#authEnrollmentForm button[type=submit]').click(); await waitFor(page, '#authRecoveryCodes');
  };
  return { page, context, calls, flags, stats, primary, totp, enroll, origin };
}
try {
  {
    const test = await scenario(); const { page, stats, calls } = test;
    assert.equal(await page.evaluate(() => localStorage.getItem('agp_csrf_token')), null);
    await page.locator('#authPrimaryForm button[type=submit]').click(); assert.equal(calls.filter(call => call.path.endsWith('/primary-proofs')).length, 0);
    await test.primary('wrong-password'); await waitFor(page, '#authError'); assert.equal(await page.locator('#authPassword').inputValue(), '');
    await test.primary(); await waitFor(page, '#authTotpForm'); assert.equal(stats.sessions, 0);
    assert.equal(await page.evaluate(() => JSON.parse(sessionStorage.getItem('agp_auth_flow')).id), 'flow_rotated');
    assert.ok(!(await page.evaluate(() => sessionStorage.getItem('agp_auth_flow'))).includes('test-password'));
    await test.totp('000000'); await waitFor(page, '#authError'); assert.equal(stats.sessions, 0); assert.equal(await page.locator('#authTotp').inputValue(), '');
    await test.totp(); await waitFor(page, '#authComplete'); assert.equal(stats.sessions, 0);
    await page.locator('#authComplete').click(); await waitFor(page, '#authContinue'); assert.equal(stats.sessions, 1);
    assert.equal(await page.locator('#authContinue').getAttribute('href'), '/admin');
    console.log('PASS local login: primary/TOTP failures, binding+CSRF rotation, no session before explicit completion, strict CSP'); await test.context.close();
  }
  {
    const test = await scenario({ enrollment: true }); const { page } = test;
    await test.primary(); await waitFor(page, '#authStartEnrollment'); await page.locator('#authStartEnrollment').click(); await waitFor(page, '#authManualSeed');
    assert.equal(await page.locator('#authManualSeed').inputValue(), 'JBSWY3DPEHPK3PXP');
    const storage = await page.evaluate(() => JSON.stringify({ ...sessionStorage, ...localStorage })); assert.ok(!storage.includes('JBSWY3DPEHPK3PXP'));
    await page.reload({ waitUntil: 'networkidle' }); await waitFor(page, '#authStartEnrollment'); assert.equal(await visible(page, '#authManualSeed'), false);
    await test.enroll(); assert.equal(await page.locator('#authComplete').isDisabled(), true);
    assert.ok(!(await page.evaluate(() => sessionStorage.getItem('agp_auth_flow'))).includes('recovery-example'));
    await page.reload({ waitUntil: 'networkidle' }); await waitFor(page, '#authComplete'); assert.equal(await page.locator('#authComplete').isDisabled(), true); assert.equal(await visible(page, '#authRecoveryCodes'), false);
    await page.locator('#authCodesSaved').check(); await page.locator('#authComplete').click(); await waitFor(page, '#authContinue');
    console.log('PASS enrollment: manual seed only in memory, bound reload/new seed, one-time recovery codes acknowledgement'); await test.context.close();
  }
  {
    const test = await scenario({ purpose: 'recover' }); const { page, stats } = test;
    await test.primary(); await waitFor(page, '#authRecoveryForm');
    await page.locator('#authRecovery').fill('recovery-example-0001'); await page.locator('#authRecoveryForm button[type=submit]').click();
    await waitFor(page, '#authStartEnrollment'); await test.enroll(); await page.locator('#authCodesSaved').check(); await page.locator('#authComplete').click();
    await waitFor(page, '#authFreshLogin'); assert.equal(stats.sessions, 0); assert.equal(await visible(page, '#authContinue'), false);
    console.log('PASS recovery: proof then replacement factor, never login/step-up session'); await test.context.close();
  }
  {
    const test = await scenario({ purpose: 'step_up', returnPath: '/auth-ui/contacts' }); await test.primary(); await waitFor(test.page, '#authTotpForm'); await test.totp(); await waitFor(test.page, '#authComplete');
    await test.page.locator('#authComplete').click(); await waitFor(test.page, '#authContinue'); assert.equal(test.stats.sessions, 1);
    assert.equal(await test.page.locator('#authContinue').getAttribute('href'),'/auth-ui/contacts');console.log('PASS step-up uses complete primary+TOTP flow and exact contacts return'); await test.context.close();
  }
  {
    const test = await scenario({ returnPath: '//attacker.example/steal' }); await test.primary(); await waitFor(test.page, '#authTotpForm'); await test.totp(); await waitFor(test.page, '#authComplete');
    test.flags.lostCompletion = true; await test.page.locator('#authComplete').click(); await waitFor(test.page, '#authRefresh');
    assert.equal(test.calls.filter(call => call.path.endsWith('/completions')).length, 1); assert.equal(await visible(test.page, '#authComplete'), false);
    await test.page.locator('#authRefresh').click(); await waitFor(test.page, '#authContinue'); assert.equal(await test.page.locator('#authContinue').getAttribute('href'), '/admin');
    console.log('PASS lost completion response reconciles state without replay; external return rejected'); await test.context.close();
  }
  {
    const test = await scenario(); await test.primary(); await waitFor(test.page, '#authTotpForm'); test.flags.corruptedAudience = true;
    await test.page.reload({ waitUntil: 'networkidle' }); await waitFor(test.page, '#authError'); assert.equal(await visible(test.page, '#authTotpForm'), false); assert.equal(test.stats.sessions, 0);
    console.log('PASS cross-audience server response fails closed'); await test.context.close();
  }
  {
    const test = await scenario(); await test.primary(); await waitFor(test.page, '#authTotpForm'); await test.context.clearCookies({ name: '__Host-agp_pending' });
    await test.page.reload({ waitUntil: 'networkidle' }); await waitFor(test.page, '#authError'); assert.equal(await visible(test.page, '#authTotpForm'), false);
    console.log('PASS missing browser binding fails closed on restored flow'); await test.context.close();
  }
  {
    const test = await scenario({ width: 390, audience: 'login', returnPath: '/auth/v2/authorize?state=local-state' });
    assert.ok(await test.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await test.primary(); await waitFor(test.page, '#authTotpForm'); await test.totp(); await waitFor(test.page, '#authComplete'); await test.page.locator('#authComplete').click(); await waitFor(test.page, '#authContinue');
    assert.equal(await test.page.locator('#authContinue').getAttribute('href'), '/auth/v2/authorize?state=local-state');
    console.log('PASS login origin, mobile layout and local authorize return preserved'); await test.context.close();
  }
  {
    const test = await scenario(); test.flags.bootstrapFailure = true;
    await test.page.reload({ waitUntil: 'networkidle' }); await waitFor(test.page, '#authBootstrapRetry'); assert.equal(await visible(test.page, '#authPrimaryForm'), false);
    test.flags.bootstrapFailure = false; await test.page.locator('#authBootstrapRetry').click(); await waitFor(test.page, '#authPrimaryForm');
    console.log('PASS unavailable security bootstrap fails closed and explicit retry recovers'); await test.context.close();
  }
  {
    const test = await scenario(); test.flags.weakMFA = true; await test.primary(); await waitFor(test.page, '#authTotpForm'); await test.totp(); await waitFor(test.page, '#authError');
    assert.equal(await visible(test.page, '#authComplete'), false); assert.equal(test.stats.sessions, 0);
    console.log('PASS ready response without required MFA fails closed'); await test.context.close();
  }
  {
    const test = await scenario({ audience: 'login', passwordOnly: true }); await test.primary(); await waitFor(test.page, '#authComplete');
    assert.equal(await visible(test.page, '#authTotpForm'), false); await test.page.locator('#authComplete').click(); await waitFor(test.page, '#authContinue'); assert.equal(test.stats.sessions, 1);
    console.log('PASS ordinary login accepts server-authorized policy without required MFA'); await test.context.close();
  }
  assert.deepEqual(failures, []); console.log('PASS no browser JS/CSP errors or external requests');
} finally { await browser.close(); }
