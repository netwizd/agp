// Test-only real agent/PKI setup. No enrollment issuer or production identity.
import assert from 'node:assert/strict';
import {createHash,X509Certificate} from 'node:crypto';
import {chmod,cp,mkdtemp,readFile,readdir,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {relative,resolve} from 'node:path';
import {freePort,pki,privateFile,required} from './s0-support.mjs';

const digest=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');

export async function prepareFleet({processes,work,cpEnv,repositoryDir}){
  const userspace=JSON.parse(await readFile(required('AGP_TEST_AGENT_USERSPACE'),'utf8'));
  assert.equal(userspace.isolation,'unprivileged-proot-userspace-shared-host-kernel');
  assert.equal(userspace.imageSHA256,'e77b6f10c2590cef872b33ee9f635a0e3fd1f57fb074c0e52b5c7f56147a0c86');
  const rootID=(await processes.run(userspace.proot,['-0','-r',userspace.rootfs,'-w','/','/bin/cat','/etc/os-release'],{PATH:'/usr/bin:/bin',LANG:'C',PROOT_NO_SECCOMP:'1',LD_LIBRARY_PATH:userspace.hostLibraryPath}));
  assert.match(rootID,/VERSION_ID="24.04"/);
  const state=JSON.parse(await readFile(resolve(repositoryDir,'state.json'),'utf8'));
  const profileRef=state.manifest.signed.compatibilityProfile;
  const artifact=state.manifest.signed.artifacts.find(a=>a.mediaType==='application/vnd.agp.component-profile+json');
  assert.ok(artifact);
  const profilePath=await privateFile(resolve(work,'agent-profile.json'),await readFile(resolve(repositoryDir,artifact.path)));
  assert.equal(digest(await readFile(profilePath)),profileRef.digest);
  const runtimeRoot=resolve(work,'agent-runtime');
  await cp(required('AGP_TEST_WAF_BUNDLE'),runtimeRoot,{recursive:true});
  // Build output modes can reflect the builder's umask. This isolated node's
  // runtime is installed read-only; byte hashes remain the qualified hashes.
  const protectRuntime=async dir=>{
    await chmod(dir,0o700);
    for(const entry of await readdir(dir,{withFileTypes:true})){
      const path=resolve(dir,entry.name);
      if(entry.isDirectory())await protectRuntime(path);
      else if(entry.isFile())await chmod(path,(await stat(path)).mode&0o111?0o500:0o400);
      else assert.fail('unexpected nonregular runtime entry');
    }
  };
  await protectRuntime(runtimeRoot);
  const authority=await pki(processes,work,'agent-inventory');
  const server=await authority.issue('agent-listener','IP:127.0.0.1','serverAuth');
  const agent=await authority.issue('read-only-node','URI:spiffe://agp/agent/node_msk01','clientAuth');
  const edgeRole=await authority.issue('wrong-edge-role','URI:spiffe://agp/edge/node_msk01/gw_portal','clientAuth');
  const cert=new X509Certificate(await readFile(agent.cert)),ca=new X509Certificate(await readFile(authority.ca));
  const registry={apiVersion:'agp.agent-registry/v1alpha1',authorityId:'browser_authority',nodes:[{
    nodeId:'node_msk01',siteId:'site_msk',name:'Real Ubuntu24 read-only agent',labels:{environment:'pilot'},groupIds:[],
    certificatePem:await readFile(agent.cert,'utf8'),certificateDigest:digest(cert.raw),publicKeyDigest:digest(cert.publicKey.export({type:'spki',format:'der'})),
    issuerDigest:digest(ca.raw),serial:BigInt('0x'+cert.serialNumber).toString(16),issuanceEpoch:'1',
  }]};
  // Trust registry must have a protected ancestor chain. The workspace may be
  // group writable; root-owned sticky /tmp plus a private directory is safe.
  const registryDir=await mkdtemp(resolve(tmpdir(),'agp-agent-registry.'));
  const registryPath=await privateFile(resolve(registryDir,'registry.json'),JSON.stringify(registry));
  const port=await freePort(),origin=`https://127.0.0.1:${port}`;
  Object.assign(cpEnv,{AGP_AGENT_MTLS_ADDR:`127.0.0.1:${port}`,AGP_AGENT_MTLS_CERT_FILE:server.cert,AGP_AGENT_MTLS_KEY_FILE:server.key,AGP_AGENT_MTLS_CLIENT_CA_FILE:authority.ca,AGP_AGENT_REGISTRY_FILE:registryPath});
  const env={PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',PROOT_NO_SECCOMP:'1',LD_LIBRARY_PATH:userspace.hostLibraryPath};
  const labPath=name=>'/lab/'+relative(work,name);
  const args=['-0','-r',userspace.rootfs,'-b','/proc','-b','/dev/null','-b','/dev/urandom','-b',`${work}:/lab`,'-b',`${runtimeRoot}:/runtime`,'-b',`${required('AGP_TEST_AGENT_BIN')}:/agp-agent`,'-w','/','/agp-agent',
    '--url',origin,'--ca',labPath(authority.ca),'--ca-fingerprint',digest(ca.raw),'--certificate',labPath(agent.cert),'--key',labPath(agent.key),
    '--component-profile',labPath(profilePath),'--runtime-root','/runtime','--disk-path','/','--interval','10s'];
  let command;
  return {origin,profileRef,runtimeRoot,registryPath,registry,edgeRole,agent,cleanup:()=>rm(registryDir,{recursive:true,force:true}),
    report:async()=>JSON.parse(await processes.run(userspace.proot,[...args,'--once'],env)),
    start:()=>command=processes.start(userspace.proot,args,env,'',{processGroup:true}),
    stop:()=>processes.stop(command),
  };
}
