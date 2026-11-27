import { Injectable, inject } from '@angular/core';
import { DirectoryApi, Mutation } from '../directory-api';
import { decodeAccepted, decodeApproval, DirectoryError, id } from '../contracts';
import { decodeLink, decodeOperation, decodePage, decodeProvider, decodeTest, decodeVersion, Document, Operation, validDocument } from './oidc-contracts';
export const key=()=>`oidc_${crypto.randomUUID().replaceAll('-','')}`;
const identifier=(v:string)=>{if(!id(v))throw new DirectoryError('invalid_input');return encodeURIComponent(v);};
const base='/api/v2/identity-providers';
export const path=(provider:string)=>base+'/'+identifier(provider);
@Injectable({providedIn:'root'})
export class OidcApi {
 readonly directory=inject(DirectoryApi);
 async providers(cursor=''){return decodePage(await this.directory.request(base+'?limit=50'+(cursor?'&cursor='+identifier(cursor):'')),decodeProvider);}
 async provider(provider:string){return decodeProvider(await this.directory.request(path(provider)));}
 async version(provider:string,version:string){return decodeVersion(await this.directory.request(path(provider)+'/versions/'+identifier(version)));}
 async test(provider:string,test:string){return decodeTest(await this.directory.request(path(provider)+'/tests/'+identifier(test)));}
 async links(provider:string,cursor=''){const page=decodePage(await this.directory.request(path(provider)+'/links?limit=50'+(cursor?'&cursor='+identifier(cursor):'')),decodeLink);if(page.items.some(l=>l.providerId!==provider))throw new DirectoryError('invalid_response');return page;}
 async link(provider:string,link:string){const item=decodeLink(await this.directory.request(path(provider)+'/links/'+identifier(link)));if(item.providerId!==provider||item.id!==link)throw new DirectoryError('invalid_response');return item;}
 async operation(operation:string){if(!operation.startsWith('oidcop_'))throw new DirectoryError('invalid_input');return decodeOperation(await this.directory.request('/api/v2/security/operations/'+identifier(operation)));}
 create(name:string,issuer:string):Mutation{return Object.freeze({path:base,method:'POST',body:JSON.stringify({name,issuer})});}
 propose(provider:string,revision:string,document:Document):Mutation{return Object.freeze({path:path(provider),method:'PUT',revision,body:JSON.stringify(document)});}
 testRequest(provider:string,versionId:string):Mutation{return Object.freeze({path:path(provider)+'/tests',method:'POST',body:JSON.stringify({versionId})});}
 activation(provider:string,revision:string,versionId:string,enabled:boolean,reason:string):Mutation{return Object.freeze({path:path(provider)+'/activations',method:'POST',revision,key:key(),body:JSON.stringify({versionId,enabled,reason})});}
 linkRequest(provider:string,subject:string,directoryIdentityId:string,expiresAt:string,reason:string):Mutation{return Object.freeze({path:path(provider)+'/links',method:'POST',key:key(),body:JSON.stringify({subject,directoryIdentityId,expiresAt,reason})});}
 linkChange(provider:string,link:string,revision:string,directoryIdentityId:string,enabled:boolean,expiresAt:string,reason:string):Mutation{return Object.freeze({path:path(provider)+'/links/'+identifier(link)+'/changes',method:'POST',revision,key:key(),body:JSON.stringify({directoryIdentityId,enabled,expiresAt,reason})});}
 decision(operation:Operation,kind:'approvals'|'executions',reason:string):Mutation{return Object.freeze({path:'/api/v2/security/operations/'+identifier(operation.id)+'/'+kind,method:'POST',key:key(),body:JSON.stringify({requestDigest:operation.requestDigest,reason})});}
 async sendCreate(m:Mutation){return decodeProvider(await this.directory.request(m.path,m));}
 async sendVersion(m:Mutation){const d=await this.directory.request(m.path,m);if(!validDocument(d))throw new DirectoryError('invalid_response');return d;}
 async sendTest(m:Mutation){return decodeTest(await this.directory.request(m.path,m));}
 async sendPlan(m:Mutation){return decodeOperation(await this.directory.request(m.path,m));}
 async sendApproval(m:Mutation,op:Operation,actor:string){const a=decodeApproval(await this.directory.request(m.path,m));if(a.operationId!==op.id||a.requestDigest!==op.requestDigest||a.approvedBy!==actor)throw new DirectoryError('invalid_response');}
 async sendExecution(m:Mutation,op:Operation){const a=decodeAccepted(await this.directory.request(m.path,m));if(a.operationId!==op.id||a.resourceId!==op.subjectId)throw new DirectoryError('invalid_response');}
}
