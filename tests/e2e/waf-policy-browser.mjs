import {randomUUID} from 'node:crypto';
import {chmod,readFile,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';

export async function wafPolicyAcceptance({page,context,approverPage,approverContext,management,raw,assert,repositoryDir}){
  const parsed=(r,status=200)=>{assert.equal(r.status,status,r.body.slice(0,800));return JSON.parse(r.body);};
  const wait=(target,method,path)=>target.waitForResponse(r=>r.request().method()===method&&new URL(r.url()).pathname===path);
  const headers=async(ctx,key)=>({Origin:management,'X-CSRF-Token':(await ctx.cookies(management)).find(c=>c.name==='__Host-agp_management_csrf').value,'Idempotency-Key':key});
  const key=()=>`native_waf_${randomUUID().replaceAll('-','')}`;
  const head=parsed(await raw(management+'/api/v2/config/profile',{},context)).headRevisionId;
  await page.goto(management+'/config-ui/',{waitUntil:'networkidle'});await page.locator('#wafPoliciesTab').click();
  await page.locator('#wafPolicyId').fill('policy_real_native');await page.locator('#wafPolicyName').fill('Real qualified native policy');await page.locator('#wafPolicySite').fill('site_msk');await page.locator('#wafPolicyRuleset').fill('crs_4_30_0');
  const created=wait(page,'POST','/api/v2/waf/policy-revisions');await page.locator('#wafPolicyCreate').click();const cr=await created;assert.equal(cr.status(),201,await cr.text());const policy=await cr.json();assert.equal(policy.state,'draft');assert.deepEqual(Object.keys(policy).sort(),['content','contentDigest','id','revision','state']);
  const validated=wait(page,'POST',`/api/v2/waf/policy-revisions/${policy.id}/validations`);await page.locator('#wafPolicyValidate').click();const vr=await validated;assert.equal(vr.status(),202,await vr.text());const accepted=await vr.json();
  await page.locator('#wafPolicyValidationReport').waitFor();
  const report=parsed(await raw(management+`/api/v2/waf/validations/${accepted.resourceId}`,{},context));assert.equal(report.valid,true);assert.equal(report.current,true);assert.equal(report.deployable,false);assert.equal(report.contentDigest,policy.contentDigest);assert.equal(report.qualification.rulesetVersionId,'crs_4_30_0');assert.ok(report.qualification.manifestDigest&&report.qualification.evidenceDigest&&report.qualification.compilerDigest);assert.equal(report.qualification.releaseSequence,'1');
  const self=await raw(management+`/api/v2/waf/policy-revisions/${policy.id}/approvals`,{method:'POST',headers:await headers(context,key()),body:{contentDigest:policy.contentDigest,reason:'Self approval must be refused even with explicit grant'}},context);assert.equal(self.status,403);
  console.log('PASS WAF real immutable policy and verified native validation bind exact TUF/manifest/profile/CRS/compiler; self-approval rejected');
  await approverPage.goto(management+'/config-ui/',{waitUntil:'networkidle'});await approverPage.locator('#wafPoliciesTab').click();
  const access=parsed(await raw(management+'/api/v2/config/access',{},approverContext));assert.equal(access.globalEdit,false);assert.deepEqual(access.sites,[{siteId:'site_msk',read:true,edit:false,approve:true}]);
  assert.equal((await raw(management+'/api/v2/waf/policy-revisions',{method:'POST',headers:await headers(approverContext,key()),body:{content:policy.content}},approverContext)).status,403,'read/approve principal gained edit');
  await approverPage.locator('#wafPolicyLookup').fill(policy.id);await approverPage.locator('#wafPolicyLoad').click();await approverPage.locator('#wafPolicyDigest').waitFor();
  assert.equal(await approverPage.locator('#wafPolicyName').isDisabled(),true);
  await approverPage.locator('#wafPolicyValidationLookup').fill(report.id);await approverPage.locator('#wafPolicyLoadValidation').click();await approverPage.locator('#wafPolicyValidationReport').waitFor();
  await approverPage.locator('#wafPolicyApprovalDigest').fill(policy.contentDigest);await approverPage.locator('#wafPolicyApprovalReason').fill('Independent review of exact real native policy evidence');
  const approved=wait(approverPage,'POST',`/api/v2/waf/policy-revisions/${policy.id}/approvals`);await approverPage.locator('#wafPolicyApprove').click();const ar=await approved;assert.equal(ar.status(),201,await ar.text());assert.equal((await ar.json()).contentDigest,policy.contentDigest);
  await approverPage.waitForFunction(()=>document.querySelector('#wafPolicyPublish')?.disabled===false);
  const published=wait(approverPage,'POST',`/api/v2/waf/policy-revisions/${policy.id}/publications`);await approverPage.locator('#wafPolicyPublish').click();const pr=await published;assert.equal(pr.status(),200,await pr.text());const result=await pr.json();assert.equal(result.state,'published');assert.equal(result.id,policy.id);
  const publishHeaders=await pr.request().allHeaders();const publicationKey=publishHeaders['idempotency-key'];
  assert.equal(parsed(await raw(management+`/api/v2/waf/policy-revisions/${policy.id}/publications`,{method:'POST',headers:await headers(approverContext,publicationKey),body:{contentDigest:policy.contentDigest}},approverContext)).state,'published');
  assert.equal(parsed(await raw(management+'/api/v2/config/profile',{},context)).headRevisionId,head,'publication changed Configuration head');
  console.log('PASS WAF real independent read/approve-only human publishes exact native policy; no edit or Configuration/live change');
  // The trusted store is outside CP storage. Tampering must invalidate both an
  // old report and an exact publication retry, rather than using cached proof.
  const record=JSON.parse(await readFile(resolve(repositoryDir,'state.json'),'utf8'));
  const artifact=record.manifest.signed.artifacts.find(a=>a.mediaType==='application/vnd.agp.component-profile+json');assert.ok(artifact);
  const file=resolve(repositoryDir,artifact.path);const original=await readFile(file);const changed=Buffer.from(original);changed[0]^=1;
  try{
    await chmod(file,0o600);await writeFile(file,changed);
    const stale=parsed(await raw(management+`/api/v2/waf/validations/${report.id}`,{},approverContext));assert.equal(stale.current,false);assert.equal(stale.valid,true);
    const rejected=await raw(management+`/api/v2/waf/policy-revisions/${policy.id}/publications`,{method:'POST',headers:await headers(approverContext,publicationKey),body:{contentDigest:policy.contentDigest}},approverContext);assert.equal(rejected.status,409);
  }finally{await writeFile(file,original);await chmod(file,0o400);}
  assert.equal(parsed(await raw(management+`/api/v2/waf/validations/${report.id}`,{},approverContext)).current,true);
  console.log('PASS WAF real independent CAS tamper invalidates persisted proof and publication replay; restoring exact bytes restores verified evidence');
  return {policy:result,report};
}
