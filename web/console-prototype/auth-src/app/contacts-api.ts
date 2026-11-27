import { Injectable, inject } from '@angular/core';
import { AuthApi, AuthBootstrap } from './auth-api';
import { AuthError, authJSON, csrfCookie, object } from './auth-http';
export interface Contact {id:string;maskedAddress:string;verified:boolean;authenticatorVersion:string;revision:string;}
export const contactID=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(v);
const uint=(v:unknown):v is string=>typeof v==='string'&&/^[1-9][0-9]{0,18}$/.test(v)&&BigInt(v)<=9223372036854775807n;
export function decodeContact(v:unknown):Contact{if(!object(v)||Object.keys(v).length!==5||!['id','maskedAddress','verified','authenticatorVersion','revision'].every(k=>Object.hasOwn(v,k))||!contactID(v['id'])||typeof v['maskedAddress']!=='string'||!/^[\x21-\x7e]\*{3}@[a-z0-9.-]{1,253}$/.test(v['maskedAddress'])||typeof v['verified']!=='boolean'||!uint(v['authenticatorVersion'])||!uint(v['revision']))throw new AuthError('invalid_response');return v as unknown as Contact;}
@Injectable({providedIn:'root'})
export class ContactsApi {
  private readonly auth=inject(AuthApi);private cookieName='';
  async initialize():Promise<{runtime:AuthBootstrap;principalId:string}>{const runtime=await this.auth.bootstrap(),config=await authJSON('/api/v1/public/runtime');if(!object(config)||config['secure_profile']!==true||config['mode']!==(runtime.audience==='management'?'management':'login')||typeof config['csrf_cookie_name']!=='string'||!/^[-A-Za-z0-9_]{1,128}$/.test(config['csrf_cookie_name']))throw new AuthError('origin_mismatch',403);this.cookieName=config['csrf_cookie_name'];return {runtime,principalId:await this.principal()};}
  async principal():Promise<string>{const value=await authJSON('/api/v1/me');if(!object(value)||!object(value['user'])||!contactID(value['user']['id']))throw new AuthError('invalid_response');return value['user']['id'];}
  async list():Promise<Contact[]>{const v=await authJSON('/api/v2/me/contacts');if(!object(v)||Object.keys(v).length!==1||!Array.isArray(v['items'])||v['items'].length>20)throw new AuthError('invalid_response');const items=v['items'].map(decodeContact);if(new Set(items.map(c=>c.id)).size!==items.length)throw new AuthError('invalid_response');return items;}
  async create(email:string):Promise<Contact>{return decodeContact(await authJSON('/api/v2/me/contacts',{method:'POST',body:{email},csrf:this.csrf()}));}
  async replace(contact:Contact,email:string):Promise<Contact>{if(!contactID(contact.id))throw new AuthError('invalid_response');return decodeContact(await authJSON('/api/v2/me/contacts/'+encodeURIComponent(contact.id),{method:'PUT',body:{email},revision:contact.revision,csrf:this.csrf()}));}
  private csrf():string{if(!this.cookieName)throw new AuthError('bootstrap_required');return csrfCookie(this.cookieName);}
}
