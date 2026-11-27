import { Injectable } from '@angular/core';
import { Access, Accepted, DirectoryIdentity, IdentityPage, decodeIdentity, decodeIdentities, DirectoryDocument, DirectoryError, Provider, ProviderPage, SecurityOperation, TestResult, Version, decodeAccess, decodeAccepted, decodeApproval, decodeOperation, decodePage, decodeProvider, decodeTest, decodeVersion, id, obj, validDocument } from './contracts';
export interface Mutation { readonly path:string;readonly method:'POST'|'PUT';readonly body:string;readonly revision?:string;readonly key?:string;readonly expectedStatus?:201|202; }
export const requestKey=()=>`directory_${crypto.randomUUID().replaceAll('-','')}`;
@Injectable({providedIn:'root'})
export class DirectoryApi {
  private cookieName='';
  async initializeSession():Promise<string>{
    const runtime=await this.request('/api/v1/public/runtime');
    if(!obj(runtime)||runtime['mode']!=='management'||runtime['secure_profile']!==true||typeof runtime['csrf_cookie_name']!=='string'||!/^[-A-Za-z0-9_]{1,128}$/.test(runtime['csrf_cookie_name']))throw new DirectoryError('management_required',403);
    this.cookieName=runtime['csrf_cookie_name'];
    const me=await this.request('/api/v1/me');if(!obj(me)||!obj(me['user'])||!id(me['user']['id']))throw new DirectoryError('invalid_response');
    return me['user']['id'];
  }
  async bootstrap():Promise<Access>{
    const principal=await this.initializeSession();const access=await this.access();if(access.principalId!==principal)throw new DirectoryError('invalid_response');return access;
  }
  async access():Promise<Access>{return decodeAccess(await this.request('/api/v2/directory-access'));}
  async providers(cursor=''):Promise<ProviderPage>{return decodePage(await this.request('/api/v2/directory-providers?limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):'')));}
  async provider(provider:string):Promise<Provider>{return decodeProvider(await this.request(this.path(provider)));}
  async version(provider:string,version:string):Promise<Version>{return decodeVersion(await this.request(this.path(provider)+'/versions/'+this.identifier(version)));}
  async test(provider:string,test:string):Promise<TestResult>{return decodeTest(await this.request(this.path(provider)+'/tests/'+this.identifier(test)));}
  async operation(operation:string):Promise<SecurityOperation>{return decodeOperation(await this.request('/api/v2/security/operations/'+this.identifier(operation)));}
  async create(name:string,forestGuid:string):Promise<Provider>{return decodeProvider(await this.request('/api/v2/directory-providers',{path:'/api/v2/directory-providers',method:'POST',body:JSON.stringify({name,forestGuid})}));}
  async propose(provider:string,revision:string,document:DirectoryDocument):Promise<DirectoryDocument>{const path=this.path(provider);const value=await this.request(path,{path,method:'PUT',revision,body:JSON.stringify(document)});if(!validDocument(value))throw new DirectoryError('invalid_response');return value;}
  async startTest(provider:string,versionId:string):Promise<TestResult>{const path=this.path(provider)+'/tests';return decodeTest(await this.request(path,{path,method:'POST',body:JSON.stringify({versionId})}));}
  activation(provider:string,revision:string,versionId:string,enabled:boolean,reason:string):Mutation{return Object.freeze({path:this.path(provider)+'/activations',method:'POST',revision,key:requestKey(),body:JSON.stringify({versionId,enabled,reason})});}
  decision(operation:SecurityOperation,kind:'approvals'|'executions',reason:string):Mutation{return Object.freeze({path:'/api/v2/security/operations/'+this.identifier(operation.id)+'/'+kind,method:'POST',key:requestKey(),body:JSON.stringify({requestDigest:operation.requestDigest,reason})});}
  async plan(m:Mutation):Promise<SecurityOperation>{return decodeOperation(await this.request(m.path,m));}
  async approve(m:Mutation,operation:SecurityOperation,principalId:string):Promise<void>{const value=decodeApproval(await this.request(m.path,m));if(value.requestDigest!==operation.requestDigest||value.operationId!==operation.id||value.approvedBy!==principalId)throw new DirectoryError('invalid_response');}
  async execute(m:Mutation):Promise<Accepted>{return decodeAccepted(await this.request(m.path,m));}
  async identities(provider:string,cursor=''):Promise<IdentityPage>{return decodeIdentities(await this.request(this.path(provider)+'/identities?limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):'')));}
  async provision(provider:string,objectGuid:string):Promise<DirectoryIdentity>{const path=this.path(provider)+'/identities';return decodeIdentity(await this.request(path,{path,method:'POST',body:JSON.stringify({objectGuid})}));}
  private identifier(v:string):string{if(!id(v))throw new DirectoryError('invalid_input');return encodeURIComponent(v);}
  private path(provider:string):string{return '/api/v2/directory-providers/'+this.identifier(provider);}
  private csrf():string{const name=this.cookieName;if(!name)throw new DirectoryError('bootstrap_required');const cookies=document.cookie.split(';').map(c=>c.trim()).filter(c=>c.startsWith(name+'='));if(cookies.length!==1)throw new DirectoryError('csrf_required',403);let value='';try{value=decodeURIComponent(cookies[0].slice(name.length+1));}catch{throw new DirectoryError('csrf_required',403);}if(!/^[A-Za-z0-9_-]{32,256}$/.test(value))throw new DirectoryError('csrf_required',403);return value;}
  async request(path:string,m?:Mutation):Promise<unknown>{
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
    try{
      const headers:Record<string,string>={Accept:'application/json'};if(m){headers['Content-Type']='application/json';headers['X-CSRF-Token']=this.csrf();if(m.key)headers['Idempotency-Key']=m.key;if(m.revision!==undefined)headers['If-Match']='"'+m.revision+'"';}
      const response=await fetch(path,{method:m?.method??'GET',credentials:'same-origin',cache:'no-store',redirect:'error',headers,signal:controller.signal,...(m?{body:m.body}:{})});
      if(response.ok&&m?.expectedStatus!==undefined&&response.status!==m.expectedStatus)throw new DirectoryError('invalid_response',response.status);
      const declared=response.headers.get('content-length');if(declared&&Number(declared)>2*1024*1024)throw new DirectoryError('invalid_response',response.status);
      // Stream with a hard limit, including chunked responses. Never trust Content-Length alone.
      if(!response.body)throw new DirectoryError('invalid_response',response.status);const reader=response.body.getReader(),chunks:Uint8Array[]=[];let total=0;
      try{for(;;){const result=await reader.read();if(result.done)break;total+=result.value.byteLength;if(total>2*1024*1024){await reader.cancel();throw new DirectoryError('invalid_response',response.status);}chunks.push(result.value);}}finally{reader.releaseLock();}
      const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}let value:unknown;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new DirectoryError('invalid_response',response.status);}
      if(!response.ok)throw new DirectoryError(obj(value)&&typeof value['code']==='string'?value['code']:obj(value)&&typeof value['error']==='string'?value['error']:'request_failed',response.status);return value;
    }catch(e:unknown){if(e instanceof DirectoryError)throw e;throw new DirectoryError(controller.signal.aborted?'request_timeout':'network_error');}finally{clearTimeout(timer);controller.abort();}
  }
}
