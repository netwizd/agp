import { Injectable, inject } from '@angular/core';
import { DirectoryApi, Mutation } from '../directory-api';
import { DirectoryError, decodeAccepted, decodeApproval, id } from '../contracts';
import * as C from './lifecycle-contracts';
const identifier=(v:string)=>{if(!id(v))throw new DirectoryError('invalid_input');return encodeURIComponent(v);};
const users='/api/v2/users',opPath=(id:string)=>'/api/v2/security/operations/'+identifier(id);
const key=()=>`lifecycle_${crypto.randomUUID().replaceAll('-','')}`;
const mutation=(path:string,body:unknown,revision?:string,expectedStatus:201|202=201):Mutation=>Object.freeze({path,method:'POST',key:key(),body:JSON.stringify(body),expectedStatus,...(revision!==undefined?{revision}:{})});
@Injectable({providedIn:'root'})
export class LifecycleApi {
 readonly http=inject(DirectoryApi);
 async bootstrap(){const principal=await this.http.initializeSession(),a=await this.access();if(a.principalId!==principal)throw new DirectoryError('invalid_response');return a;}
 async access(){return C.access(await this.http.request('/api/v2/identity-access'));}
 async users(cursor=''){return C.page(await this.http.request(users+'?limit=50'+(cursor?'&cursor='+identifier(cursor):'')));}
 async user(id:string){const u=C.user(await this.http.request(users+'/'+identifier(id)));if(u.id!==id)throw new DirectoryError('invalid_response');return u;}
 create(input:C.Create){return mutation(users,input);}
 async sendCreate(m:Mutation){return C.user(await this.http.request(m.path,m));}
 async invite(u:C.User,email:string,ttlSeconds:number){const m=mutation(users+'/'+identifier(u.id)+'/invites',{email,ttlSeconds},u.revision);return C.invite(await this.http.request(m.path,m));}
 async delivery(invite:C.Invite){const v=C.delivery(await this.http.request('/api/v2/identity-deliveries/'+identifier(invite.deliveryOperationId)));if(v.id!==invite.deliveryOperationId||v.inviteId!==invite.inviteId||Date.parse(v.expiresAt)>Date.parse(invite.expiresAt))throw new DirectoryError('invalid_response');return v;}
 plan(input:C.Plan){const route={replace_mfa:'mfa-recovery-plans',reset_password:'password-reset-plans',restart_activation:'activation-recovery-plans'}[input.allowedAction];return mutation(users+'/'+identifier(input.targetPrincipalId)+'/'+route,input,undefined,202);}
 async sendPlan(m:Mutation){return C.verifiedOperation(await this.http.request(m.path,m));}
 async operation(id:string){if(!id.startsWith('recoveryop_'))throw new DirectoryError('invalid_input');const o=await C.verifiedOperation(await this.http.request(opPath(id)));if(o.id!==id)throw new DirectoryError('invalid_response');return o;}
 decision(o:C.Operation,kind:'approvals'|'executions',reason:string){return mutation(opPath(o.id)+'/'+kind,{requestDigest:o.requestDigest,reason},undefined,kind==='approvals'?201:202);}
 async approve(m:Mutation,o:C.Operation,actor:string){const a=decodeApproval(await this.http.request(m.path,m));if(a.operationId!==o.id||a.requestDigest!==o.requestDigest||a.approvedBy!==actor)throw new DirectoryError('invalid_response');}
 async execute(m:Mutation,o:C.Operation){const a=decodeAccepted(await this.http.request(m.path,m));if(a.operationId!==o.id||a.resourceId!==o.subjectId)throw new DirectoryError('invalid_response');}
 async ticket(o:C.Operation){const path=opPath(o.id)+'/recovery-tickets',t=C.ticket(await this.http.request(path,{path,method:'POST',body:'{}',expectedStatus:201}));if(Date.parse(t.expiresAt)>Date.parse(o.recoveryRequest.expiresAt)||Date.parse(t.expiresAt)<=Date.now())throw new DirectoryError('invalid_response');return t;}
}
