import { Injectable, computed, inject, signal } from '@angular/core';
import { AuthApi, AuthBootstrap, AuthError, Branding, Enrollment, Purpose } from './auth-api';
import { FlowView, PrimaryProof } from './flow-contracts.generated';

const FLOW_STORAGE_KEY = 'agp_auth_flow';
const MESSAGES: Record<string, string> = {
  invalid_proof: 'Не удалось подтвердить данные. Проверьте ввод и повторите попытку.',
  flow_expired: 'Время входа истекло. Начните вход заново.',
  flow_cancelled: 'Вход отменён. Начните заново.',
  rate_limited: 'Слишком много попыток. Подождите и повторите действие.',
  security_state_unavailable: 'Проверка безопасности временно недоступна. Доступ остаётся закрытым.',
  step_up_required: 'Для этого действия необходимо повторно подтвердить пароль и второй фактор.',
  binding_required: 'Запрос не связан с этим браузером. Начните вход заново и разрешите cookies.',
  flow_not_found: 'Запрос входа недоступен в этом браузере. Начните заново.',
  origin_mismatch: 'Адрес страницы не соответствует разрешённому адресу входа.',
  csrf_invalid: 'Не удалось проверить защиту запроса. Начните вход заново.',
  csrf_required: 'Не удалось проверить защиту запроса. Начните вход заново.',
  origin_required: 'Откройте разрешённый адрес входа и начните заново.',
  unsupported_flow: 'Этот способ входа не поддерживается текущим интерфейсом. Обратитесь к администратору.',
  invalid_response: 'Сервер вернул некорректное состояние входа. Доступ остаётся закрытым.',
  network_error: 'Ответ сервера не получен. Проверьте состояние запроса перед продолжением.',
  request_timeout: 'Сервер не ответил вовремя. Проверьте состояние запроса перед продолжением.',
};
interface SavedFlow { id: string; purpose: Purpose; audience: 'management' | 'login' | 'setup'; codesIssued?: boolean; }

@Injectable({ providedIn: 'root' })
export class AuthFlowStore {
  private readonly api = inject(AuthApi);
  private generation = 0;
  readonly purpose = signal<Purpose>('login');
  readonly runtime = signal<AuthBootstrap | null>(null);
  readonly branding = signal<Branding>({ brandName: 'AGP', logoText: 'A' });
  readonly flow = signal<FlowView | null>(null);
  readonly enrollment = signal<Enrollment | null>(null);
  readonly recoveryCodes = signal<string[]>([]);
  readonly codesIssued = signal(false);
  readonly codesSaved = signal(false);
  readonly busy = signal(false);
  readonly error = signal('');
  readonly blocked = signal(false);
  readonly uncertain = signal(false);
  readonly restored = signal(false);
  readonly stage = computed(() => this.flow()?.nextStep || 'primary');
  readonly seed = computed(() => { const enrollment = this.enrollment(); return enrollment ? new URL(enrollment.provisioningUri).searchParams.get('secret') || '' : ''; });
  readonly mustSaveCodes = computed(() => this.codesIssued() && !this.codesSaved());
  readonly canLeave = computed(() => !this.busy() && !this.mustSaveCodes());

  async initialize(purpose: Purpose, callbackId?: string): Promise<void> {
    const generation = ++this.generation;
    this.purpose.set(purpose);
    this.runtime.set(null);
    this.flow.set(null);
    this.clearSecrets();
    this.error.set('');
    this.blocked.set(false);
    this.uncertain.set(false);
    this.restored.set(false);
    this.busy.set(true);
    try {
      const [runtime, branding] = await Promise.all([this.api.bootstrap(), this.api.branding()]);
      if (generation !== this.generation) return;
      this.runtime.set(runtime);
      this.branding.set(branding);
      if(callbackId!==undefined){
        if(!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(callbackId))throw new AuthError('binding_required');
        const resumed=await this.api.flow(callbackId);if(generation!==this.generation)return;
        if(!['login','step_up'].includes(resumed.purpose)||resumed.audience!==runtime.audience||resumed.state==='pending_primary'||resumed.state==='pending_mfa'&&(!['totp','totp_enrollment'].includes(resumed.nextStep)||resumed.mfaSatisfied)||['ready','completed'].includes(resumed.state)&&!resumed.mfaSatisfied)throw new AuthError('invalid_response');
        this.purpose.set(resumed.purpose as Purpose);this.accept(resumed);this.restored.set(true);return;
      }
      const saved = this.readSaved();
      if (saved && saved.purpose === purpose && saved.audience === (purpose==='recover'?'setup':runtime.audience)) {
        this.codesIssued.set(saved.codesIssued === true);
        const restored=await this.api.flow(saved.id);if(generation!==this.generation)return;this.accept(restored);
        this.restored.set(true);
      }
    } catch (error: unknown) {
      if (generation !== this.generation) return;
      this.handleError(error);
    } finally { if (generation === this.generation) this.busy.set(false); }
  }

  async externalPrimary(authorize:(flow:FlowView)=>Promise<void>):Promise<void>{await this.perform(async()=>{if(this.purpose()==='recover')throw new AuthError('unsupported_flow');let flow=this.flow();if(!flow){flow=await this.api.start({purpose:this.purpose(),audience:this.requireRuntime().audience});this.accept(flow);}if(flow.state!=='pending_primary'||flow.nextStep!=='primary')throw new AuthError('invalid_response');await authorize(flow);});}

  async primary(proof: Extract<PrimaryProof, { method: 'local_password' | 'directory_password' }>): Promise<void> {
    await this.perform(async () => {
      const runtime = this.requireRuntime();
      let flow = this.flow();
      if (!flow) {
        flow = await this.api.start({ purpose: this.purpose(), audience: this.purpose()==='recover'?'setup':runtime.audience });
        this.accept(flow);
      }
      if (flow.nextStep !== 'primary') throw new AuthError('invalid_response');
      this.accept(await this.api.primary(flow.id, proof));
    });
  }
  async totp(code: string): Promise<void> { await this.perform(async () => this.accept(await this.api.totp(this.requireFlow().id, { code }))); }
  async recovery(code: string): Promise<void> { await this.perform(async () => this.accept(await this.api.recovery(this.requireFlow().id, code))); }
  async startEnrollment(): Promise<void> {
    await this.perform(async () => {
      const flow = this.requireFlow();
      if (flow.nextStep !== 'totp_enrollment') throw new AuthError('invalid_response');
      this.enrollment.set(null);
      this.enrollment.set(await this.api.enrollment(flow.id));
    });
  }
  async confirmEnrollment(code: string): Promise<void> {
    await this.perform(async () => {
      const enrollment = this.enrollment();
      if (!enrollment) throw new AuthError('invalid_response');
      const result = await this.api.confirm(this.requireFlow().id, enrollment.enrollmentId, code);
      this.enrollment.set(null);
      this.recoveryCodes.set(result.recoveryCodes || []);
      this.codesIssued.set(true);
      this.codesSaved.set(false);
      this.accept(result.flow);
    });
  }
  async complete(): Promise<void> {
    if (this.mustSaveCodes()) return;
    await this.perform(async () => {
      if (this.requireFlow().nextStep !== 'complete') throw new AuthError('invalid_response');
      const result = await this.api.complete(this.requireFlow().id);
      if (result.state !== 'completed') throw new AuthError('invalid_response');
      this.accept(result);
      this.clearSecrets();
    });
  }
  async refresh(): Promise<void> {
    await this.perform(async () => {
      const flow = this.requireFlow();
      this.accept(await this.api.flow(flow.id));
      this.uncertain.set(false);
      this.blocked.set(false);
    }, true);
  }
  async restart(): Promise<void> {
    if (this.busy()) return;
    const flow = this.flow();
    if (flow && !['completed', 'expired', 'cancelled'].includes(flow.state)) {
      await this.perform(async () => { await this.api.cancel(flow.id); }, true);
    }
    this.forget();
    await this.initialize(this.purpose());
  }
  async cancel(): Promise<void> {
    await this.perform(async () => {
      const result = await this.api.cancel(this.requireFlow().id);
      if (result.state !== 'cancelled') throw new AuthError('invalid_response');
      this.accept(result);
      this.clearSecrets();
    }, true);
  }
  acknowledgeCodes(value: boolean): void {
    this.codesSaved.set(value);

  }

  private requireRuntime(): AuthBootstrap { const value = this.runtime(); if (!value) throw new AuthError('bootstrap_required'); return value; }
  private requireFlow(): FlowView { const value = this.flow(); if (!value) throw new AuthError('flow_not_found'); return value; }
  private async perform(operation: () => Promise<void>, allowBlocked = false): Promise<void> {
    if (this.busy() || (!allowBlocked && (this.blocked() || this.uncertain()))) return;
    this.busy.set(true);
    this.error.set('');
    try { await operation(); }
    catch (error: unknown) { this.handleError(error); }
    finally { this.busy.set(false); }
  }
  private accept(flow: FlowView): void {
    const runtime = this.requireRuntime();
    if (flow.purpose !== this.purpose() || flow.audience !== (this.purpose()==='recover'?'setup':runtime.audience)) throw new AuthError('invalid_response');
    if ((flow.purpose === 'step_up' || (flow.purpose === 'login' && flow.audience === 'management')) && ['ready', 'completed'].includes(flow.state) && !flow.mfaSatisfied) throw new AuthError('invalid_response');
    this.flow.set(flow);
    if (['completed', 'expired', 'cancelled'].includes(flow.state)) {
      this.forget();
      this.clearSecrets();
      return;
    }
    try { sessionStorage.setItem(FLOW_STORAGE_KEY, JSON.stringify({ id: flow.id, purpose: flow.purpose, audience: flow.audience, ...(this.codesIssued() ? { codesIssued: true } : {}) })); }
    catch { /* A denied storage permission does not grant access or persist secrets. */ }
  }
  private readSaved(): SavedFlow | null {
    try {
      const value: unknown = JSON.parse(sessionStorage.getItem(FLOW_STORAGE_KEY) || 'null');
      if (!value || typeof value !== 'object') return null;
      const saved = value as Partial<SavedFlow>;
      if (typeof saved.id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(saved.id) || !['login', 'recover', 'step_up'].includes(saved.purpose || '') || !['management', 'login', 'setup'].includes(saved.audience || '')) return null;
      return saved as SavedFlow;
    } catch { return null; }
  }
  private forget(): void { try { sessionStorage.removeItem(FLOW_STORAGE_KEY); } catch { /* No secret storage fallback. */ } }
  private clearSecrets(): void { this.enrollment.set(null); this.recoveryCodes.set([]); this.codesIssued.set(false); this.codesSaved.set(false); }
  private handleError(error: unknown): void {
    const problem = error instanceof AuthError ? error : new AuthError('request_failed');
    this.error.set(MESSAGES[problem.code] || 'Не удалось выполнить действие. Доступ остаётся закрытым. Повторите проверку или начните заново.');
    if (['network_error', 'request_timeout'].includes(problem.code)) this.uncertain.set(true);
    if (problem.code !== 'invalid_proof' && problem.code !== 'rate_limited') {
      this.blocked.set(true);
      this.enrollment.set(null);
      this.recoveryCodes.set([]);
    }
    if (['flow_expired', 'flow_cancelled', 'flow_not_found', 'binding_required', 'csrf_invalid', 'csrf_required'].includes(problem.code)) this.forget();
  }
}
