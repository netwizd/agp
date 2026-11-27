import {randomUUID} from 'node:crypto';
import {chmod,readFile,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';

export async function fleetAcceptance({page,context,approverPage,approverContext,scopedPage,scopedContext,management,raw,assert,fleet,policy}){
  const parsed=(r,status=200)=>{assert.equal(r.status,status,r.body.slice(0,1200));return JSON.parse(r.body);};
  const wait=(target,method,path)=>target.waitForResponse(r=>r.request().method()===method&&new URL(r.url()).pathname===path);
  const key=()=>`fleet_${randomUUID().replaceAll('-','')}`;
  const headers=async(ctx,k=key())=>({Origin:management,'X-CSRF-Token':(await ctx.cookies(management)).find(c=>c.name==='__Host-agp_management_csrf').value,'Idempotency-Key':k});
  const post=async(path,body,ctx=context,k=key())=>raw(management+path,{method:'POST',headers:await headers(ctx,k),body},ctx);
  const currentHead=async()=>parsed(await raw(management+'/api/v2/config/profile',{},context)).headRevisionId;

  await page.goto(management+'/config-ui/',{waitUntil:'networkidle'});
  await page.locator('#inventoryTab').click();await page.locator('.inventory-node').waitFor();
  const inventory=parsed(await raw(management+'/api/v2/agent-inventory',{},context));
  assert.equal(inventory.items.length,1);assert.equal(inventory.items[0].id,'node_msk01');assert.equal(inventory.items[0].connectivity,'online');
  assert.match(await page.locator('.inventory-node').textContent(),/Неизвестн/);
  assert.equal((await raw(management+'/api/v2/agent-inventory',{},scopedContext)).status,403);
  await scopedPage.goto(management+'/config-ui/',{waitUntil:'networkidle'});assert.equal(await scopedPage.locator('#inventoryTab').count(),0);
  assert.equal((await raw(fleet.origin+'/agent/v1/inventory-challenges',{method:'POST',tls:fleet.edgeRole.tls,body:{}})).status,403);
  assert.equal((await raw(management+'/agent/v1/inventory-challenges',{method:'POST',headers:{Origin:management},body:{}})).status,403);
  console.log('PASS Fleet real Ubuntu24 read-only agent over role-bound TLS1.3; admin inventory and listener isolation; applied/health unknown');

  const head=await currentHead();const before=parsed(await raw(management+`/api/v2/config/revisions/${head}`,{},context));
  const content=structuredClone(before.content);
  for(const gateway of content.gateways.filter(g=>g.metadata.siteId==='site_msk')){
    gateway.spec.componentProfileRef=fleet.profileRef;
    gateway.spec.waf={engine:'modsecurity',mode:'detection',policyRevisionId:policy.id};
    gateway.spec.nodeSelector={nodeIds:['node_msk01']};
  }
  const base=parsed(await post('/api/v2/config/revisions',{baseRevisionId:head,content}),201);
  const access=parsed(await raw(management+'/api/v2/config/access',{},context));
  await page.locator('#zonesTab').click();await page.locator('#zoneNew').click();
  await page.locator('#zoneId').fill('zone_real_trusted');await page.locator('#zoneName').fill('Native qualified trusted zone');await page.locator('#zoneSite').fill('site_msk');await page.locator('#zoneOwner').fill(access.principalId);await page.locator('#zonePolicy').fill(policy.id);await page.locator('#zoneMode').selectOption('blocking');await page.locator('#zoneGatewayIds').fill('gw_portal');await page.locator('#zoneReason').fill('Apply the published qualified baseline to an existing owned Gateway');
  const created=wait(page,'POST','/api/v2/waf/zone-revisions');await page.locator('#zoneCreateRevision').click();const createdResponse=await created;assert.equal(createdResponse.status(),201,await createdResponse.text());const zone=await createdResponse.json();
  const validated=wait(page,'POST',`/api/v2/waf/zone-revisions/${zone.id}/validations`);await page.locator('#zoneValidate').click();const validatedResponse=await validated;assert.equal(validatedResponse.status(),202,await validatedResponse.text());const accepted=await validatedResponse.json();await page.locator('#zoneValidationReport').waitFor();
  const report=parsed(await raw(management+`/api/v2/waf/zone-validations/${accepted.resourceId}`,{},context));assert.equal(report.current,true);assert.equal(report.valid,true);assert.equal(report.deployable,false);assert.equal(report.qualification.profileDigest,fleet.profileRef.digest);assert.equal(report.policyRevisionId,policy.id);
  assert.equal((await post(`/api/v2/waf/zone-revisions/${zone.id}/approvals`,{contentDigest:zone.contentDigest,reason:'Self approval must be rejected'})).status,403);
  console.log('PASS Fleet real zone validation binds exact published policy/native closure; independent approval is mandatory');

  await approverPage.goto(management+'/config-ui/',{waitUntil:'networkidle'});
  await approverPage.locator('#zoneRevisionLookup').fill(zone.id);await approverPage.getByRole('button',{name:'Открыть версию',exact:true}).click();await approverPage.locator('#zoneValidate').waitFor();
  assert.equal(await approverPage.locator('#zoneName').isDisabled(),true);
  await approverPage.locator('#zoneValidationLookup').fill(report.id);await approverPage.locator('#zoneLoadValidation').click();await approverPage.locator('#zoneValidationReport').waitFor();
  await approverPage.locator('#zoneApprovalDigest').fill(zone.contentDigest);await approverPage.locator('#zoneApprovalReason').fill('Independent review of the exact published native baseline and zone');
  const approved=wait(approverPage,'POST',`/api/v2/waf/zone-revisions/${zone.id}/approvals`);await approverPage.locator('#zoneApprove').click();const approvedResponse=await approved;assert.equal(approvedResponse.status(),201,await approvedResponse.text());
  await approverPage.waitForFunction(()=>document.querySelector('#zonePublish')?.disabled===false);
  const published=wait(approverPage,'POST',`/api/v2/waf/zone-revisions/${zone.id}/publications`);await approverPage.locator('#zonePublish').click();const publishedResponse=await published;assert.equal(publishedResponse.status(),200,await publishedResponse.text());assert.equal((await publishedResponse.json()).state,'published');
  assert.equal(await currentHead(),base.id,'publication changed desired head');
  console.log('PASS Fleet independent read/approve-only human publishes the zone without configuration or live-node changes');

  await page.goto(management+'/config-ui/',{waitUntil:'networkidle'});await page.locator('#zoneRevisionLookup').fill(zone.id);await page.getByRole('button',{name:'Открыть версию',exact:true}).click();await page.locator('#zoneTrustedBase').waitFor();await page.locator('#zoneTrustedBase').fill(base.id);
  const resolveZone=async()=>{
    const pending=wait(page,'POST',`/api/v2/waf/zone-revisions/${zone.id}/resolutions`);await page.locator('#zoneResolve').click();const response=await pending;assert.equal(response.status(),202,await response.text());const op=await response.json();await page.waitForFunction(id=>document.querySelector('#zoneResolutionReport')?.textContent.includes(id),op.resourceId);return parsed(await raw(management+`/api/v2/waf/zone-resolutions/${op.resourceId}`,{},context));
  };
  let frozen=await resolveZone();assert.equal(frozen.members.length,1);assert.deepEqual(frozen.members[0].nodeIds,['node_msk01']);assert.equal(frozen.conflicts.length,0);assert.equal(Date.parse(frozen.expiresAt)-Date.parse(frozen.createdAt),1800000);
  const receipt=await fleet.report();assert.equal(receipt.capabilityDigest,inventory.items[0].capabilityDigest);
  assert.equal(parsed(await raw(management+`/api/v2/waf/zone-resolutions/${frozen.id}`,{},context)).inventoryDigest,frozen.inventoryDigest);
  const requestFor=r=>({apiVersion:'agp.waf-zone-change/v1alpha1',kind:'WafZoneChange',baseRevisionId:r.baseConfigRevisionId,zoneRevisionId:zone.id,resolutionId:r.id,resolutionDigest:r.resolutionDigest,reason:'Materialize only the frozen authenticated full Site change'});
  const originalRegistry=await readFile(fleet.registryPath);
  try{
    const changed=structuredClone(fleet.registry);changed.nodes[0].labels.environment='changed';await writeFile(fleet.registryPath,JSON.stringify(changed));
    assert.equal((await post('/api/v2/waf/zone-changes',requestFor(frozen))).status,409);assert.equal(await currentHead(),base.id);
  }finally{await writeFile(fleet.registryPath,originalRegistry);}
  const runtimeFile=resolve(fleet.runtimeRoot,'share/modsecurity/unicode.mapping'),originalRuntime=await readFile(runtimeFile);
  try{
    await chmod(runtimeFile,0o600);await writeFile(runtimeFile,Buffer.concat([originalRuntime,Buffer.from('\n# actual observed drift\n')]));await fleet.report();
    const rejected=await post('/api/v2/waf/zone-changes',requestFor(frozen));assert.equal(rejected.status,409,rejected.body);assert.equal(await currentHead(),base.id);
  }finally{await writeFile(runtimeFile,originalRuntime);await chmod(runtimeFile,0o400);await fleet.report();}
  console.log('PASS Fleet unchanged heartbeat preserves frozen digest; server registry drift and actual runtime-byte drift reject all writes atomically');

  frozen=await resolveZone();
  // A different receipt with identical authenticated capability facts must
  // leave this exact frozen permit usable at the actual mutation boundary.
  await fleet.report();
  await page.locator('#zoneMaterializeDigest').fill(frozen.resolutionDigest);await page.locator('#zoneMaterializeReason').fill('Create the exact full desired revision after independent zone publication');
  const materialized=wait(page,'POST','/api/v2/waf/zone-changes');await page.locator('#zoneMaterialize').click();const changeResponse=await materialized;assert.equal(changeResponse.status(),202,await changeResponse.text());const changeOperation=await changeResponse.json();await page.locator('#zoneResultRevision').waitFor();
  const change=parsed(await raw(management+`/api/v2/waf/zone-changes/${changeOperation.resourceId}`,{},context));assert.equal(change.state,'materialized');assert.ok(change.resultRevisionId);assert.equal(await currentHead(),change.resultRevisionId);
  const revision=parsed(await raw(management+`/api/v2/config/revisions/${change.resultRevisionId}`,{},context));assert.equal(revision.baseRevisionId,base.id);assert.equal(revision.viewScope,'global');assert.deepEqual(revision.content.gateways[0].spec.routes,base.content.gateways[0].spec.routes);assert.equal(revision.content.gateways[0].spec.waf.mode,'blocking');
  const immutableBase=parsed(await raw(management+`/api/v2/config/revisions/${base.id}`,{},context));assert.equal(immutableBase.content.gateways[0].spec.waf.mode,'detection');
  const originalHeaders=await changeResponse.request().allHeaders();const replay=parsed(await post('/api/v2/waf/zone-changes',change.request,context,originalHeaders['idempotency-key']),202);assert.equal(replay.resourceId,change.id);assert.equal(await currentHead(),revision.id);
  const bypass=structuredClone(revision.content);bypass.gateways[0].spec.waf.mode='detection';const denied=await post('/api/v2/config/revisions',{baseRevisionId:revision.id,content:bypass});assert.equal(denied.status,422,denied.body);assert.equal(await currentHead(),revision.id);
  console.log('PASS Fleet real Angular materializes one immutable full ConfigRevision under CAS; exact retry reuses result and manual binding bypass fails');
}
