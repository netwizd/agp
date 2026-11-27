import { Injectable, inject } from '@angular/core';
import { DirectoryApi } from '../directory-api';
import { DirectoryError, decodeAccepted, decodeApproval, id, obj } from '../contracts';
import { access } from '../lifecycle/lifecycle-contracts';
import { LifecycleApi } from '../lifecycle/lifecycle-api';
import * as C from './roles-contracts';
export interface Request {readonly path:string;readonly method:'POST'|'DELETE';readonly body:string;readonly key:string;readonly revision?:string;readonly status:201|202;}
const identifier=(v:string)=>{if(!id(v))throw new DirectoryError('invalid_input');return encodeURIComponent(v);};
const operationPath=(v:string)=>{if(!v.startsWith('roleop_'))throw new DirectoryError('invalid_input');return '/api/v2/security/operations/'+identifier(v);};
const mutation=(path:string,body:unknown,method:'POST'|'DELETE'='POST',revision?:string,status:201|202=202):Request=>Object.freeze({path,method,body:JSON.stringify(body),key:'role_'+crypto.randomUUID().replaceAll('-',''),...(revision!==undefined?{revision}:{}),status});
@Injectable({providedIn:'root'})
export class RolesApi {
 readonly small=inject(DirectoryApi);readonly identity=inject(LifecycleApi);private cookieName='';
 async bootstrap(){const runtime=await this.small.request('/api/v1/public/runtime');if(!obj(runtime)||runtime['mode']!=='management'||runtime['secure_profile']!==true||typeof runtime['csrf_cookie_name']!=='string'||!/^[-A-Za-z0-9_]{1,128}$/.test(runtime['csrf_cookie_name']))throw new DirectoryError('management_required',403);this.cookieName=runtime['csrf_cookie_name'];const me=await this.small.request('/api/v1/me'),a=await this.access();if(!obj(me)||!obj(me['user'])||a.principalId!==me['user']['id'])throw new DirectoryError('invalid_response');return a;}
 async access(){return access(await this.small.request('/api/v2/identity-access'));}
 async catalog(){return C.catalog(await this.small.request('/api/v2/roles'));}
 async permissions(){return C.permissions(await this.small.request('/api/v2/permissions'));}
 async bindings(cursor=''){return C.bindings(await this.small.request('/api/v2/role-bindings?limit=50'+(cursor?'&cursor='+identifier(cursor):'')));}
 async operation(id:string){const o=await C.operation(await this.request(operationPath(id),undefined,true));if(o.id!==id)throw new DirectoryError('invalid_response');return o;}
 create(input:C.Input){return mutation('/api/v2/role-bindings',input);}
 revoke(b:C.Binding,reason:string){return mutation('/api/v2/role-bindings/'+identifier(b.id),{reason},'DELETE',b.revision);}
 decision(o:C.Operation,kind:'approvals'|'executions',reason:string){return mutation(operationPath(o.id)+'/'+kind,{requestDigest:o.requestDigest,reason},'POST',undefined,kind==='approvals'?201:202);}
 async accepted(m:Request){const a=decodeAccepted(await this.request(m.path,m));if(!a.operationId.startsWith('roleop_'))throw new DirectoryError('invalid_response');return a;}
 async approve(m:Request,o:C.Operation,actor:string){const a=decodeApproval(await this.request(m.path,m));if(a.operationId!==o.id||a.requestDigest!==o.requestDigest||a.approvedBy!==actor)throw new DirectoryError('invalid_response');}
 private csrf():string{if(!this.cookieName)throw new DirectoryError('bootstrap_required');const items=document.cookie.split(';').map(x=>x.trim()).filter(x=>x.startsWith(this.cookieName+'='));if(items.length!==1)throw new DirectoryError('csrf_required',403);let value:string;try{value=decodeURIComponent(items[0].slice(this.cookieName.length+1));}catch{throw new DirectoryError('csrf_required',403);}if(!/^[A-Za-z0-9_-]{32,256}$/.test(value))throw new DirectoryError('csrf_required',403);return value;}
 // Only exact roleop_ GET uses the agreed 65 MiB budget. Generic and list readers remain 2 MiB.
 private async request(path:string,m?:Request,large=false):Promise<unknown>{const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);try{const headers:Record<string,string>={Accept:'application/json'};if(m){headers['Content-Type']='application/json';headers['X-CSRF-Token']=this.csrf();headers['Idempotency-Key']=m.key;if(m.revision!==undefined)headers['If-Match']='"'+m.revision+'"';}const r=await fetch(path,{method:m?.method??'GET',headers,credentials:'same-origin',redirect:'error',cache:'no-store',signal:controller.signal,...(m?{body:m.body}:{})});const limit=large&&r.ok?65*1024*1024:2*1024*1024;if(r.ok&&(m?r.status!==m.status:r.status!==200)||!r.body||Number(r.headers.get('content-length'))>limit)throw new DirectoryError('invalid_response',r.status);const reader=r.body.getReader(),parts:Uint8Array[]=[];let size=0;try{for(;;){const c=await reader.read();if(c.done)break;size+=c.value.length;if(size>limit){await reader.cancel();throw new DirectoryError('invalid_response',r.status);}parts.push(c.value);}}finally{reader.releaseLock();}const bytes=new Uint8Array(size);let n=0;for(const part of parts){bytes.set(part,n);n+=part.length;}let value:unknown;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new DirectoryError('invalid_response',r.status);}if(!r.ok)throw new DirectoryError(obj(value)&&typeof value['code']==='string'?value['code']:'request_failed',r.status);return value;}catch(e){if(e instanceof DirectoryError)throw e;throw new DirectoryError(controller.signal.aborted?'request_timeout':'network_error');}finally{clearTimeout(timer);controller.abort();}}
}
