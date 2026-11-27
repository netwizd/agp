import { DirectoryDocument, Provider, SecurityOperation, Version } from './contracts';
import { Mutation } from './directory-api';
export interface ProviderBinding { id:string; forestGuid:string; guardId:string; }
interface PendingBase { id:string; principalId:string; }
export type PendingWrite = PendingBase & (
  {kind:'activation';request:Mutation;provider:ProviderBinding;revision:string;version:Version;enabled:boolean;reason:string}
  | {kind:'approval'|'execution';request:Mutation;provider:ProviderBinding;operation:SecurityOperation}
  | {kind:'create';name:string;forestGuid:string}
  | {kind:'version';provider:ProviderBinding;revision:string;document:DirectoryDocument}
  | {kind:'test';provider:ProviderBinding;version:Version}
  | {kind:'provision';provider:ProviderBinding;objectGuid:string}
);
export interface RecoveryProof { pendingId:string;checkedAt:number;summary:string;resourceId:string; }
export const providerBinding=(p:Provider):ProviderBinding=>({id:p.id,forestGuid:p.forestGuid,guardId:p.securityGuardId});
export const sameProvider=(p:Provider,b:ProviderBinding)=>p.id===b.id&&p.forestGuid===b.forestGuid&&p.securityGuardId===b.guardId;
// JSON values only. Freeze nested snapshots too: editing a form cannot alter a retained request.
export function immutable<T>(value:T):T { const copy=structuredClone(value);function freeze(v:unknown):void{if(v&&typeof v==='object'){for(const child of Object.values(v))freeze(child);Object.freeze(v);}}freeze(copy);return copy; }
function canonical(v:unknown):unknown {if(Array.isArray(v))return v.map(canonical);if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([key,value])=>[key,canonical(value)]));return v;}
export const equalJSON=(a:unknown,b:unknown)=>JSON.stringify(canonical(a))===JSON.stringify(canonical(b));
// The directory boundary normalizes DN sets / group mappings, while endpoint order is failover policy.
export function sameDocument(a:DirectoryDocument,b:DirectoryDocument):boolean {const normalize=(d:DirectoryDocument)=>({...d,spec:{...d.spec,userBaseDns:[...d.spec.userBaseDns].sort(),groupBaseDns:[...d.spec.groupBaseDns].sort(),groupMappings:[...d.spec.groupMappings].sort((x,y)=>x.groupObjectGuid<y.groupObjectGuid?-1:x.groupObjectGuid>y.groupObjectGuid?1:0)}});return equalJSON(normalize(a),normalize(b));}
export function sameOperation(a:SecurityOperation,b:SecurityOperation):boolean {return a.id===b.id&&a.family===b.family&&a.requestDigest===b.requestDigest&&a.subjectId===b.subjectId&&a.createdBy===b.createdBy&&a.createdAt===b.createdAt&&equalJSON(a.providerChange,b.providerChange);}
export function matchesActivation(op:SecurityOperation,p:Extract<PendingWrite,{kind:'activation'}>):boolean {const c=op.providerChange,d=p.version.configuration;return op.createdBy===p.principalId&&op.subjectId===p.provider.id&&c.providerId===p.provider.id&&c.versionId===d.metadata.versionId&&c.contentDigest===p.version.contentDigest&&c.guardId===p.provider.guardId&&c.expectedRowVersion===p.revision&&c.nextGuardVersion===d.metadata.securityGuardVersion&&c.enabled===p.enabled&&c.reason===p.reason;}
export const retryable=(p:PendingWrite):p is Extract<PendingWrite,{request:Mutation}>=>'request' in p;
