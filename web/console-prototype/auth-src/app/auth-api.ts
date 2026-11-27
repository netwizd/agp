import { Injectable } from '@angular/core';
import { AuthError, authJSON } from './auth-http';
export { AuthError } from './auth-http';
import { FlowView, PrimaryProof, StartFlow, TotpProof, ChallengeView } from './flow-contracts.generated';

export type Purpose = 'login' | 'recover' | 'step_up';
export type Audience = 'login' | 'management';
export interface AuthBootstrap { csrfToken: string; csrfCookieName: string; audience: Audience; loginUrl: string; managementUrl: string; }
export interface Enrollment { enrollmentId: string; provisioningUri: string; expiresAt: string; }
export interface EnrollmentResult { flow: FlowView; issuedAt: string; recoveryCodes?: string[]; }
export interface Branding { brandName: string; logoText: string; }
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const id = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const utcTime = (value: unknown): value is string => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value) && Number.isFinite(Date.parse(value));
const included = (value: unknown, values: readonly string[]): value is string => typeof value === 'string' && values.includes(value);

export function decodeFlow(value: unknown): FlowView {
  if (!object(value) || !['id','purpose','audience','state','nextStep','expiresAt','mfaSatisfied'].every(k=>Object.hasOwn(value,k)) || Object.keys(value).some(k=>!['id','purpose','audience','state','nextStep','expiresAt','mfaSatisfied','contactId'].includes(k)) || value['contactId']!==undefined&&!id(value['contactId']) || !id(value['id']) || !included(value['purpose'], ['login', 'step_up', 'verify_email', 'activate', 'recover'])
    || !included(value['audience'], ['login', 'management', 'setup']) || !included(value['state'], ['pending_primary', 'pending_mfa', 'ready', 'completed', 'expired', 'cancelled'])
    || !included(value['nextStep'], ['primary', 'redirect', 'totp', 'email_code', 'complete', 'none', 'totp_enrollment', 'recovery', 'password_setup'])
    || !utcTime(value['expiresAt']) || typeof value['mfaSatisfied'] !== 'boolean') throw new AuthError('invalid_response');
  const flow = value as unknown as FlowView;
  if (['pending_primary', 'pending_mfa', 'expired', 'cancelled'].includes(flow.state) && flow.mfaSatisfied) throw new AuthError('invalid_response');
  if (['recover', 'activate', 'verify_email'].includes(flow.purpose) && flow.mfaSatisfied) throw new AuthError('invalid_response');
  const allowed: Record<FlowView['state'], FlowView['nextStep'][]> = {
    pending_primary: ['primary'], pending_mfa: ['totp', 'totp_enrollment', 'recovery', 'email_code', 'password_setup'], ready: ['complete'],
    completed: ['none'], expired: ['none'], cancelled: ['none'],
  };
  if (flow.purpose === 'verify_email' && (flow.mfaSatisfied || flow.state === 'pending_primary' || flow.state === 'pending_mfa' && flow.nextStep !== 'email_code') || flow.nextStep === 'email_code' && !['verify_email','activate'].includes(flow.purpose) || flow.nextStep==='password_setup'&&!['activate','recover'].includes(flow.purpose) || flow.purpose==='activate'&&flow.audience!=='setup') throw new AuthError('invalid_response');
  if (!allowed[flow.state].includes(flow.nextStep)) throw new AuthError('unsupported_flow');
  return flow;
}
export function decodeChallenge(value:unknown,flowId:string,purpose:ChallengeView['purpose']='verify_email'):ChallengeView {
  if(!object(value)||Object.keys(value).length!==7||!['id','flowId','purpose','generation','expiresAt','resendAfter','deliveryState'].every(k=>Object.hasOwn(value,k))||!id(value['id'])||value['flowId']!==flowId||value['purpose']!==purpose||typeof value['generation']!=='string'||!/^[1-9][0-9]{0,18}$/.test(value['generation'])||BigInt(value['generation'])>9223372036854775807n||!utcTime(value['expiresAt'])||!utcTime(value['resendAfter'])||!included(value['deliveryState'],['queued','accepted','failed','expired','unknown']))throw new AuthError('invalid_response');
  // Unknown SMTP outcome never becomes a successful delivery claim.
  return {...value,deliveryState:value['deliveryState']==='unknown'?'failed':value['deliveryState']} as unknown as ChallengeView;
}
function originURL(value: unknown): string {
  if (typeof value !== 'string') throw new AuthError('invalid_response');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) throw new AuthError('invalid_response');
  return url.origin;
}
function decodeBootstrap(value: unknown): AuthBootstrap {
  if (!object(value) || !included(value['audience'], ['management', 'login']) || value['csrfCookieName'] !== '__Host-agp_flow_csrf'
    || typeof value['csrfToken'] !== 'string' || !/^[A-Za-z0-9_-]{32,128}$/.test(value['csrfToken'])) throw new AuthError('invalid_response');
  return { audience: value['audience'] as Audience, csrfToken: value['csrfToken'], csrfCookieName: value['csrfCookieName'],
    loginUrl: originURL(value['loginUrl']), managementUrl: originURL(value['managementUrl']) };
}
function decodeEnrollment(value: unknown): Enrollment {
  if (!object(value) || !id(value['enrollmentId']) || !utcTime(value['expiresAt']) || typeof value['provisioningUri'] !== 'string'
    || value['provisioningUri'].length > 2048) throw new AuthError('invalid_response');
  const uri = new URL(value['provisioningUri']);
  if (uri.protocol !== 'otpauth:' || uri.hostname !== 'totp' || !/^[A-Z2-7]{16,128}$/.test(uri.searchParams.get('secret') || '')
    || (uri.searchParams.has('digits') && uri.searchParams.get('digits') !== '6') || (uri.searchParams.has('period') && uri.searchParams.get('period') !== '30')) throw new AuthError('invalid_response');
  return value as unknown as Enrollment;
}

@Injectable({ providedIn: 'root' })
export class AuthApi {
  private bootstrapValue: AuthBootstrap | null = null;

  async bootstrap(): Promise<AuthBootstrap> {
    this.bootstrapValue = null;
    try { localStorage.removeItem('agp_csrf_token'); } catch { /* Legacy cleanup only; no web-storage token fallback. */ }
    const result = decodeBootstrap(await this.request('/auth/v2/bootstrap'));
    const expectedOrigin = result.audience === 'management' ? result.managementUrl : result.loginUrl;
    if (expectedOrigin !== location.origin) throw new AuthError('origin_mismatch');
    this.bootstrapValue = result;
    return result;
  }
  async branding(): Promise<Branding> {
    try {
      const value = await this.request('/api/v1/public/settings');
      if (!object(value) || !object(value['settings'])) return { brandName: 'AGP', logoText: 'A' };
      return { brandName: typeof value['settings']['brand_name'] === 'string' ? value['settings']['brand_name'].slice(0, 128) : 'AGP',
        logoText: typeof value['settings']['logo_text'] === 'string' ? value['settings']['logo_text'].slice(0, 8) : 'A' };
    } catch { return { brandName: 'AGP', logoText: 'A' }; }
  }
  async start(body: StartFlow): Promise<FlowView> { return decodeFlow(await this.request('/auth/v2/flows', body)); }
  async flow(flowId: string): Promise<FlowView> { return decodeFlow(await this.request(this.path(flowId))); }
  async primary(flowId: string, body: PrimaryProof): Promise<FlowView> { return decodeFlow(await this.request(this.path(flowId, 'primary-proofs'), body)); }
  async oidcAuthorization(flowId:string,providerId:string):Promise<unknown>{if(!id(providerId))throw new AuthError('invalid_response');return this.request(this.path(flowId,'oidc-authorizations'),{providerId});}
  async totp(flowId: string, body: TotpProof): Promise<FlowView> { return decodeFlow(await this.request(this.path(flowId, 'totp-proofs'), body)); }
  async recovery(flowId: string, code: string): Promise<FlowView> { return decodeFlow(await this.request(this.path(flowId, 'recovery-proofs'), { method: 'recovery_code', code })); }
  async enrollment(flowId: string): Promise<Enrollment> { return decodeEnrollment(await this.request(this.path(flowId, 'totp-enrollments'), {})); }
  async confirm(flowId: string, enrollmentId: string, code: string): Promise<EnrollmentResult> {
    if (!id(enrollmentId)) throw new AuthError('invalid_response');
    const value = await this.request(this.path(flowId, `totp-enrollments/${encodeURIComponent(enrollmentId)}/confirmations`), { code });
    if (!object(value) || !utcTime(value['issuedAt'])) throw new AuthError('invalid_response');
    const codes = value['recoveryCodes'];
    if (codes !== undefined && (!Array.isArray(codes) || codes.length < 1 || codes.length > 20 || codes.some(code => typeof code !== 'string' || code.length < 16 || code.length > 64 || /[\u0000-\u001f\u007f]/.test(code)))) throw new AuthError('invalid_response');
    return { flow: decodeFlow(value['flow']), issuedAt: value['issuedAt'], ...(codes === undefined ? {} : { recoveryCodes: codes as string[] }) };
  }
  async emailIssue(flowId:string,contactId:string,purpose:ChallengeView['purpose']='verify_email'):Promise<ChallengeView>{if(!id(contactId))throw new AuthError('invalid_response');return decodeChallenge(await this.request(this.path(flowId,'email-challenges'),{purpose,contactId}),flowId,purpose);}
  async emailStatus(flowId:string,challengeId:string,purpose:ChallengeView['purpose']='verify_email'):Promise<ChallengeView>{if(!id(challengeId))throw new AuthError('invalid_response');return decodeChallenge(await this.request(this.path(flowId,'email-challenges/'+encodeURIComponent(challengeId))),flowId,purpose);}
  async emailProof(flowId:string,challengeId:string,code:string):Promise<FlowView>{if(!id(challengeId)||!/^\d{8}$/.test(code))throw new AuthError('invalid_proof');return decodeFlow(await this.request(this.path(flowId,'email-challenges/'+encodeURIComponent(challengeId)+'/proofs'),{code}));}
  async complete(flowId: string): Promise<FlowView> { return decodeFlow(await this.request(this.path(flowId, 'completions'), {})); }
  async cancel(flowId: string): Promise<FlowView> { return decodeFlow(await this.request(this.path(flowId, 'cancellations'), {})); }

  async passwordSetup(flowId:string,newPassword:string):Promise<FlowView>{return decodeFlow(await this.request(this.path(flowId,'password-setups'),{newPassword}));}
  async supervised(flowId:string,ticket:string):Promise<FlowView>{return decodeFlow(await this.request(this.path(flowId,'recovery-proofs'),{method:'supervised_ticket',ticket}));}
  async passwordResetRequest(username:string,email:string):Promise<void>{await authJSON('/auth/v2/password-reset-requests',{method:'POST',body:{username,email},csrf:this.csrf(),expectedStatus:202,emptyStatus:202});}
  private path(flowId: string, suffix = ''): string {
    if (!id(flowId)) throw new AuthError('invalid_response');
    return `/auth/v2/flows/${encodeURIComponent(flowId)}${suffix ? `/${suffix}` : ''}`;
  }
  private csrf(): string {
    const bootstrap = this.bootstrapValue;
    if (!bootstrap) throw new AuthError('bootstrap_required');
    const cookie = document.cookie.split(';').map(value => value.trim()).find(value => value.startsWith(`${bootstrap.csrfCookieName}=`));
    let token = '';
    try { token = cookie ? decodeURIComponent(cookie.slice(bootstrap.csrfCookieName.length + 1)) : bootstrap.csrfToken; }
    catch { throw new AuthError('binding_required'); }
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(token)) throw new AuthError('binding_required');
    return token;
  }
  private async request(path:string,body?:unknown):Promise<unknown>{return authJSON(path,body===undefined?{}:{method:'POST',body,csrf:this.csrf()});}
}
