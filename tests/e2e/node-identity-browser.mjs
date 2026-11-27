// Disposable real owner-approved enrollment, separate issuer and local probe.
import {createHash,randomUUID,X509Certificate} from 'node:crypto';
import {chmod,copyFile,mkdir,mkdtemp,readFile,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {relative,resolve} from 'node:path';
import {freePort,pki,privateFile,required,waitReady,raw as labRaw} from './s0-support.mjs';

const digest=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
export async function prepareNodeIdentity({processes,work,cpEnv,issuerJournalCert,validatorJournalCert,fleet}) {
  const dir=await mkdtemp(resolve(process.env.AGP_TEST_LOCAL_SYNTAX_TMPDIR||tmpdir(),'agp-node-stage.'));
  let issuer;
  try {
  const copy=async(name,path)=>{const dst=resolve(dir,name);await copyFile(path,dst);await chmod(dst,0o600);return dst;};
  const transport=await pki(processes,dir,'transport');
  const server=await transport.issue('issuer','IP:127.0.0.1,URI:spiffe://agp/node-issuer/agent','serverAuth');
  const writer=await transport.issue('cp-writer','URI:spiffe://agp/control-plane/node-issuer','clientAuth');
  const reader=await transport.issue('cp-reader','URI:spiffe://agp/control-plane/agent-registry','clientAuth');
  const agentServer=await transport.issue('agent-listener','IP:127.0.0.1','serverAuth');
  const enrollmentServer=await transport.issue('enrollment-listener','IP:127.0.0.1','serverAuth');
  const identities=await pki(processes,dir,'identity-root');
  const edge=await identities.issue('wrong-edge','URI:spiffe://agp/edge/node_enrolled/gw_enrolled','clientAuth');
  edge.tls.ca=await readFile(transport.ca);
  const issuingKey=resolve(dir,'issuing.key'),csr=resolve(dir,'issuing.csr'),issuingCert=resolve(dir,'issuing.pem');
  await processes.run('openssl',['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=Disposable AGP Agent Issuer','-keyout',issuingKey,'-out',csr]);
  await chmod(issuingKey,0o600);
  const extensions=await privateFile(resolve(dir,'issuing.ext'),'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n');
  await processes.run('openssl',['x509','-req','-in',csr,'-CA',identities.ca,'-CAkey',resolve(dir,'identity-root/ca.key'),'-CAcreateserial','-days','1','-sha256','-extfile',extensions,'-out',issuingCert]);
  const chain=await privateFile(resolve(dir,'issuing-chain.pem'),await readFile(issuingCert,'utf8')+await readFile(identities.ca,'utf8'));
  // Only this test's root key is removed after the intermediate is prepared.
  // Neither CP nor the running issuer has an offline-root key configuration.
  await rm(resolve(dir,'identity-root/ca.key'));
  const journalCert=await copy('issuer-journal.pem',issuerJournalCert.cert),journalKey=await copy('issuer-journal.key',issuerJournalCert.key),journalCA=await copy('journal-ca.pem',cpEnv.AGP_JOURNAL_CA);
  const validatorCert=await copy('validator-journal.pem',validatorJournalCert.cert),validatorKey=await copy('validator-journal.key',validatorJournalCert.key);
  const [issuerPort,agentPort,enrollmentPort]=await Promise.all([freePort(),freePort(),freePort()]);
  const issuerURL=`https://127.0.0.1:${issuerPort}`,origin=`https://127.0.0.1:${agentPort}`,enrollmentOrigin=`https://127.0.0.1:${enrollmentPort}`;
  const ca=new X509Certificate(await readFile(transport.ca)),identityCA=new X509Certificate(await readFile(identities.ca));
  const issuerConfig=await privateFile(resolve(dir,'issuer.json'),JSON.stringify({issuer:{ledgerFile:resolve(dir,'issuer.db'),issuingCertificateFile:chain,issuingKeyFile:issuingKey,certificateLifetimeSeconds:3600,renewalOverlapSeconds:300},listenAddress:`127.0.0.1:${issuerPort}`,tlsCertificateFile:server.cert,tlsKeyFile:server.key,clientCAFile:transport.ca,journal:{url:cpEnv.AGP_JOURNAL_URL,authorityId:cpEnv.AGP_JOURNAL_AUTHORITY_ID,keyId:cpEnv.AGP_JOURNAL_KEY_ID,publicKey:cpEnv.AGP_JOURNAL_PUBLIC_KEY,certificateFile:journalCert,keyFile:journalKey,caFile:journalCA,serverName:'127.0.0.1'}}));
  issuer=processes.start(required('AGP_TEST_ISSUER_BIN'),['-config',issuerConfig]);
  await waitReady(issuerURL,issuer,async()=>{await labRaw(issuerURL+'/issuer/v1/registry',{method:'POST',tls:reader.tls,body:{authorityId:cpEnv.AGP_JOURNAL_AUTHORITY_ID,epoch:'1'}});return true;});
  const client=await privateFile(resolve(dir,'client.json'),JSON.stringify({url:issuerURL,serverName:'127.0.0.1',certificateFile:writer.cert,keyFile:writer.key,registryCertificateFile:reader.cert,registryKeyFile:reader.key,caFile:transport.ca,caFingerprint:digest(ca.raw),timeoutSeconds:10}));
  const cpConfig={AGP_AGENT_REGISTRY_FILE:'',AGP_NODE_IDENTITY_CONFIG:client,AGP_AGENT_MTLS_ADDR:`127.0.0.1:${agentPort}`,AGP_AGENT_MTLS_CERT_FILE:agentServer.cert,AGP_AGENT_MTLS_KEY_FILE:agentServer.key,AGP_AGENT_MTLS_CLIENT_CA_FILE:identities.ca,AGP_ENROLLMENT_TLS_ADDR:`127.0.0.1:${enrollmentPort}`,AGP_ENROLLMENT_TLS_CERT_FILE:enrollmentServer.cert,AGP_ENROLLMENT_TLS_KEY_FILE:enrollmentServer.key};
  const initial=resolve(dir,'identity-v1'),renewed=resolve(dir,'identity-v2');
  for(const path of [initial,renewed,resolve(dir,'receipts'),resolve(dir,'syntax-scratch')])await mkdir(path,{mode:0o700});
  const common=directory=>['--directory',directory,'--url',enrollmentOrigin,'--ca',transport.ca,'--ca-fingerprint',digest(ca.raw),'--identity-ca',identities.ca,'--identity-ca-fingerprint',digest(identityCA.raw),'--node','node_enrolled'];
  const identityCLI=async(mode,directory,input='',extra=[])=>JSON.parse(await processes.run(required('AGP_TEST_NODE_IDENTITY_BIN'),[mode,...(mode==='keygen'?['--directory',directory]:common(directory)),...extra],process.env,input));
  const userspace=JSON.parse(await readFile(required('AGP_TEST_AGENT_USERSPACE'),'utf8'));
  const env={PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',PROOT_NO_SECCOMP:'1',LD_LIBRARY_PATH:userspace.hostLibraryPath};
  const prootArgs=['-r',userspace.rootfs,'-b','/proc','-b','/dev/null','-b','/dev/urandom','-b',`${work}:/lab`,'-b',`${dir}:/identity`,'-b',`${fleet.runtimeRoot}:/runtime`,'-w','/'];
  const localPath=path=>'/identity/'+relative(dir,path);
  const report=async(directory)=>JSON.parse(await processes.run(userspace.proot,[...prootArgs,'-b',`${required('AGP_TEST_AGENT_BIN')}:/agp-agent`,'/agp-agent','--url',origin,'--ca',localPath(transport.ca),'--ca-fingerprint',digest(ca.raw),'--certificate',localPath(resolve(directory,'certificate.pem')),'--key',localPath(resolve(directory,'key.pem')),'--component-profile','/lab/agent-profile.json','--runtime-root','/runtime','--once'],env));
  const tls=async(directory)=>({ca:await readFile(transport.ca),cert:await readFile(resolve(directory,'certificate.pem')),key:await readFile(resolve(directory,'key.pem')),rejectUnauthorized:true,minVersion:'TLSv1.3'});
  const validateLocal=async(request)=>{
    const path=path=>'/lab/'+relative(work,path);
    const args=[...prootArgs,'-b',`${required('AGP_TEST_AGENT_VALIDATE_BIN')}:/agp-agent-validate`,'/agp-agent-validate','--repository',path(cpEnv.AGP_WAF_REPOSITORY_DIR),'--anchor',path(cpEnv.AGP_WAF_TRUST_CONFIG),'--receipts','/identity/receipts','--scratch','/identity/syntax-scratch','--component-profile','/lab/agent-profile.json','--runtime-root','/runtime','--journal-url',cpEnv.AGP_JOURNAL_URL,'--journal-authority',cpEnv.AGP_JOURNAL_AUTHORITY_ID,'--journal-key-id',cpEnv.AGP_JOURNAL_KEY_ID,'--journal-public-key',cpEnv.AGP_JOURNAL_PUBLIC_KEY,'--journal-certificate',localPath(validatorCert),'--journal-key',localPath(validatorKey),'--journal-ca',localPath(journalCA)];
    return JSON.parse(await processes.run(userspace.proot,args,env,JSON.stringify(request)));
  };
  return {dir,origin,enrollmentOrigin,cpConfig,initial,renewed,identityCLI,report,tls,edge,transport,validateLocal,
    restartIssuer:async()=>{await processes.stop(issuer);issuer=processes.start(required('AGP_TEST_ISSUER_BIN'),['-config',issuerConfig]);await waitReady(issuerURL,issuer,async()=>{await labRaw(issuerURL+'/issuer/v1/registry',{method:'POST',tls:reader.tls,body:{authorityId:cpEnv.AGP_JOURNAL_AUTHORITY_ID,epoch:'1'}});return true;});},
    cleanup:()=>rm(dir,{recursive:true,force:true})};
  } catch(error) {
    if(issuer)await processes.stop(issuer);
    await rm(dir,{recursive:true,force:true});
    throw error;
  }
}

export async function nodeIdentityAcceptance({page,context,scopedContext,management,raw,assert,stage,processes,policy,qualification}) {
  const parsed=(r,status=200)=>{assert.equal(r.status,status,r.body.slice(0,1500));return JSON.parse(r.body);};
  const key=()=>`node_${randomUUID().replaceAll('-','')}`;
  const headers=async(k=key())=>({Origin:management,'X-CSRF-Token':(await context.cookies(management)).find(c=>c.name==='__Host-agp_management_csrf').value,'Idempotency-Key':k});
  const post=async(path,body,k=key())=>raw(management+path,{method:'POST',headers:await headers(k),body},context);
  const wait=(method,path)=>page.waitForResponse(r=>r.request().method()===method&&new URL(r.url()).pathname===path);
  await page.goto(management+'/config-ui/',{waitUntil:'networkidle'});await page.locator('#inventoryTab').click();
  await page.locator('#nodeCreateForm').waitFor();
  await page.locator('#nodeId').fill('node_enrolled');await page.locator('#nodeSite').fill('site_msk');await page.locator('#nodeName').fill('Owner-approved Ubuntu24 agent');
  const created=wait('POST','/api/v2/nodes');await page.locator('#nodeCreate').click();assert.equal((await created).status(),201);
  await page.locator('#nodeSelect').selectOption('node_enrolled');
  const issued=wait('POST','/api/v2/nodes/node_enrolled/enrollments');await page.locator('#nodeIssueToken').click();const issuedResponse=await issued;assert.equal(issuedResponse.status(),201,await issuedResponse.text());const issuance=await issuedResponse.json();assert.equal(issuance.tokenAvailable,true);assert.ok(issuance.token);
  await page.locator('#nodeEnrollmentToken').waitFor();
  const issuedHeaders=await issuedResponse.request().allHeaders();
  const metadata=parsed(await post('/api/v2/nodes/node_enrolled/enrollments',{role:'agent',ttlSeconds:600},issuedHeaders['idempotency-key']),201);assert.equal(metadata.tokenAvailable,false);assert.equal(metadata.token,undefined);
  assert.equal((await raw(management+'/api/v2/nodes',{},scopedContext)).status,403);
  const storage=await page.evaluate(()=>JSON.stringify([Object.entries(localStorage),Object.entries(sessionStorage)]));assert.ok(!storage.includes(issuance.token));
  console.log('PASS Node real Angular reserves an immutable node and issues a hash-only first-only token; retry returns metadata and scoped editor is denied');

  const localKey=await stage.identityCLI('keygen',stage.initial);
  const tokenFile=await privateFile(resolve(stage.dir,'enrollment-token'),issuance.token+'\n');
  const pending=await stage.identityCLI('request',stage.initial,'',['--token-file',tokenFile]);assert.equal(pending.publicKeyDigest,localKey.publicKeyDigest);assert.equal(pending.state,'csr_pending');
  const csr=await readFile(resolve(stage.initial,'request.pem'),'utf8');
  const premature=await raw(stage.enrollmentOrigin+'/agent/v1/enroll',{method:'POST',body:{nodeId:'node_enrolled',enrollmentToken:issuance.token,csrPem:csr}});assert.equal(premature.status,403,premature.body);
  const exact=await stage.identityCLI('request',stage.initial,issuance.token+'\n');assert.deepEqual(exact,pending);
  await page.locator('#nodeEnrollmentId').fill(issuance.enrollmentId);await page.locator('#nodePendingLoad').click();await page.waitForFunction(()=>document.body.textContent.includes('csr_pending'));
  assert.equal((await post(`/api/v2/nodes/node_enrolled/enrollments/${issuance.enrollmentId}/approvals`,{expectedPublicKeyDigest:'sha256:'+'0'.repeat(64),requestDigest:pending.requestDigest})).status,403);
  await page.locator('#nodeFingerprint').fill(localKey.publicKeyDigest);await page.locator('#nodeFingerprintConfirmed').check();
  const approved=wait('POST',`/api/v2/nodes/node_enrolled/enrollments/${issuance.enrollmentId}/approvals`);await page.locator('#nodeApprove').click();const approvedResponse=await approved;assert.equal(approvedResponse.status(),200,await approvedResponse.text());
  const cert=await stage.identityCLI('enroll',stage.initial,'',['--token-file',tokenFile]);assert.equal(cert.nodeId,'node_enrolled');await assert.rejects(stat(tokenFile));
  const exactCert=await stage.identityCLI('enroll',stage.initial,issuance.token+'\n');assert.equal(exactCert.serial,cert.serial);
  assert.equal(await page.locator('#nodeEnrollmentToken').count(),0,'approval should forget the token from the browser');
  console.log('PASS Node local key/CSR requires owner fingerprint approval before external issuance; exact retries keep the serial and successful CLI consumes its token file');

  const receipt=await stage.report(stage.initial);assert.equal(receipt.nodeId,'node_enrolled');
  const inventory=parsed(await raw(management+'/api/v2/agent-inventory',{},context));assert.equal(inventory.items[0].id,'node_enrolled');assert.equal(inventory.items[0].connectivity,'online');
  assert.equal((await raw(stage.origin+'/agent/v1/inventory-challenges',{method:'POST',tls:stage.edge.tls,body:{}})).status,403);
  assert.equal((await raw(stage.origin+'/agent/v1/enroll',{method:'POST',tls:await stage.tls(stage.initial),body:{}})).status,404);
  console.log('PASS Node issued agent performs real Ubuntu24 inventory over role-bound TLS; EdgeAuth and enrollment paths cannot cross listeners');

  const localRequest={apiVersion:'agp.agent-local-syntax/v1alpha1',requestId:key(),authorityEpoch:'1',nodeDeploymentSequence:'0',capabilityDigest:receipt.capabilityDigest,pins:{manifestDigest:qualification.manifestDigest,profileDigest:qualification.profileDigest,tupleDigest:qualification.tupleDigest,evidenceDigest:qualification.evidenceDigest,rendererDigest:digest(await readFile(required('AGP_TEST_WAF_RENDERER')))},policy:policy.content,mode:'detection'};
  const local=await stage.validateLocal(localRequest);assert.equal(local.state,'validated');assert.equal(local.executionLocation,'local_process');assert.equal(local.nativeSyntaxOnly,true);assert.equal(local.nodeDeploymentSequence,'0');assert.equal(local.nodeId,undefined);
  const blocking=await stage.validateLocal({...localRequest,requestId:key(),mode:'blocking'});assert.equal(blocking.state,'validated');assert.equal(blocking.nativeSyntaxOnly,true);assert.equal(blocking.nodeDeploymentSequence,'0');
  assert.deepEqual(await stage.validateLocal(localRequest),local);
  console.log('PASS Node standalone Ubuntu24 local CLI validates exact signed detection/blocking native syntax with durable replay and sequence zero; no remote task/apply or healthy claim');

  await stage.identityCLI('keygen',stage.renewed);
  const renewedArgs=['renew','--directory',stage.renewed,'--current-directory',stage.initial,'--url',stage.origin,'--ca',stage.transport.ca,'--ca-fingerprint',digest(new X509Certificate(await readFile(stage.transport.ca)).raw),'--identity-ca',resolve(stage.dir,'identity-root/ca.pem'),'--identity-ca-fingerprint',digest(new X509Certificate(await readFile(resolve(stage.dir,'identity-root/ca.pem'))).raw),'--node','node_enrolled'];
  const renewed=JSON.parse(await processes.run(required('AGP_TEST_NODE_IDENTITY_BIN'),renewedArgs));assert.notEqual(renewed.serial,cert.serial);assert.equal((await stage.report(stage.renewed)).nodeId,'node_enrolled');
  await stage.restartIssuer();assert.equal((await stage.report(stage.renewed)).nodeId,'node_enrolled');
  await page.locator('#nodeRevokeReason').fill('Acceptance confirms current role identity revocation after renewal');
  const revoked=wait('POST','/api/v2/nodes/node_enrolled/revocations');await page.locator('#nodeRevoke').click();const revokedResponse=await revoked;assert.equal(revokedResponse.status(),202,await revokedResponse.text());
  for(const directory of [stage.initial,stage.renewed])assert.equal((await raw(stage.origin+'/agent/v1/inventory-challenges',{method:'POST',tls:await stage.tls(directory),body:{}})).status,403);
  await stage.restartIssuer();assert.equal((await raw(stage.origin+'/agent/v1/inventory-challenges',{method:'POST',tls:await stage.tls(stage.renewed),body:{}})).status,403);
  assert.equal(parsed(await raw(management+'/api/v2/nodes/node_enrolled',{},context)).identityState,'revoked');
  const refreshed=wait('GET','/api/v2/agent-inventory');await page.locator('#inventoryRefresh').click();assert.equal((await refreshed).status(),200);await page.waitForFunction(()=>document.querySelector('.inventory-node')?.textContent.includes('revoked'));
  console.log('PASS Node real new-key renewal and issuer restart preserve identity; journal revocation rejects both generations before and after restart');
}
