import { Component, OnInit, inject } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { AuthFlowStore } from './auth-flow.store';
import { Purpose } from './auth-api';
import { safeReturnPath } from './safe-return';
import { clearHandoff, takeHandoff } from './oidc-handoff';
import { OidcMethods } from './oidc-methods';
export { safeReturnPath } from './safe-return';

@Component({ selector: 'agp-auth-page', standalone: true, imports: [ReactiveFormsModule, RouterLink, DatePipe, OidcMethods], templateUrl: './auth-page.html' })
export class AuthPage implements OnInit {
  readonly store = inject(AuthFlowStore);
  private readonly route = inject(ActivatedRoute);
  returnPath = safeReturnPath(this.route.snapshot.queryParamMap.get('return'));
  get returnQuery(){return this.returnPath ? { return: this.returnPath } : {};}
  readonly primaryForm = new FormGroup({
    method: new FormControl<'local_password' | 'directory_password'>('local_password', { nonNullable: true }),
    providerId: new FormControl('', { nonNullable: true, validators: [Validators.pattern(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/)] }),
    username: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.maxLength(128)] }),
    password: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.maxLength(1024)] }),
  });
  readonly totpForm = new FormGroup({ code: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.pattern(/^[0-9]{6}$/)] }) });
  readonly recoveryForm = new FormGroup({ code: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.minLength(16), Validators.maxLength(64)] }) });
  copyNotice = '';

  async ngOnInit(): Promise<void> {
    const purpose = this.route.snapshot.data['purpose'] as Purpose;
    const query=this.route.snapshot.queryParamMap,callback=query.has('flow');const handoff=callback?takeHandoff():null;if(!callback)clearHandoff();
    if(callback){const ids=query.getAll('flow'),valid=ids.length===1&&query.keys.length===1&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(ids[0]);history.replaceState(null,'','/auth-ui/');await this.store.initialize(purpose,valid?ids[0]:'');if(handoff&&handoff.sourceFlowId!==ids[0]&&handoff.purpose===this.store.purpose()&&handoff.audience===this.store.runtime()?.audience&&!this.store.blocked())this.returnPath=safeReturnPath(handoff.returnPath);else this.returnPath='';if(!this.store.blocked())history.replaceState(null,'','/auth-ui/'+(this.store.purpose()==='step_up'?'step-up':'login')+(this.returnPath?'?return='+encodeURIComponent(this.returnPath):''));}
    else await this.store.initialize(purpose);
  }
  get title(): string {
    if (this.store.flow()?.state === 'completed') return this.store.purpose() === 'recover' ? 'Фактор восстановлен' : this.store.purpose() === 'step_up' ? 'Проверка завершена' : 'Вход выполнен';
    if (this.store.purpose() === 'recover') return 'Восстановление второго фактора';
    if (this.store.purpose() === 'step_up') return 'Подтвердите текущую сессию';
    return this.store.runtime()?.audience === 'management' ? 'Вход в управление' : 'Вход в AGP';
  }
  get cannotSubmit(): boolean { return this.store.busy() || this.store.blocked() || this.store.uncertain(); }
  get terminal(): boolean { return ['completed', 'expired', 'cancelled'].includes(this.store.flow()?.state || ''); }
  get continuation(): string { return this.returnPath || (this.store.runtime()?.audience === 'management' ? '/admin' : this.store.purpose()==='step_up'?'/resources':'/'); }
  invalid(form: typeof this.totpForm, name: 'code'): boolean { const control = form.controls[name]; return control.touched && control.invalid; }
  primaryInvalid(name: 'username' | 'password' | 'providerId'): boolean { const control = this.primaryForm.controls[name]; return control.touched && control.invalid; }
  private valid(form: FormGroup): boolean {
    form.markAllAsTouched();
    if (form.valid) return true;
    requestAnimationFrame(() => document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
    return false;
  }
  private focusResult(): void {
    requestAnimationFrame(() => {
      if (this.store.error()) document.getElementById('authError')?.focus();
      else document.getElementById('authStageTitle')?.focus();
    });
  }
  async primary(): Promise<void> {
    const provider = this.primaryForm.controls.providerId;
    if (this.primaryForm.controls.method.value === 'directory_password') provider.setValidators([Validators.required, Validators.pattern(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/)]);
    else provider.clearValidators();
    provider.updateValueAndValidity();
    if (!this.valid(this.primaryForm) || this.cannotSubmit) return;
    const { method, providerId, username, password } = this.primaryForm.getRawValue();
    try { await this.store.primary(method === 'directory_password' ? { method, providerId, username, password } : { method, username, password }); }
    finally { this.primaryForm.controls.password.reset(); this.focusResult(); }
  }
  async totp(): Promise<void> {
    if (!this.valid(this.totpForm) || this.cannotSubmit) return;
    const code = this.totpForm.controls.code.value;
    try {
      if (this.store.stage() === 'totp_enrollment') await this.store.confirmEnrollment(code);
      else await this.store.totp(code);
    } finally { this.totpForm.reset(); this.focusResult(); }
  }
  async recovery(): Promise<void> {
    if (!this.valid(this.recoveryForm) || this.cannotSubmit) return;
    try { await this.store.recovery(this.recoveryForm.controls.code.value); }
    finally { this.recoveryForm.reset(); this.focusResult(); }
  }
  async startEnrollment(): Promise<void> { this.copyNotice = ''; await this.store.startEnrollment(); this.focusResult(); }
  async complete(): Promise<void> { await this.store.complete(); this.focusResult(); }
  async refresh(): Promise<void> { await this.store.refresh(); this.focusResult(); }
  clearInputs():void{this.primaryForm.controls.password.reset();this.totpForm.reset();this.recoveryForm.reset();}
  async restart(): Promise<void> { clearHandoff();this.primaryForm.reset(); this.totpForm.reset(); this.recoveryForm.reset(); this.copyNotice = ''; await this.store.restart(); this.focusResult(); }
  async cancel(): Promise<void> { clearHandoff();await this.store.cancel(); this.focusResult(); }
  codesSaved(event: Event): void { this.store.acknowledgeCodes((event.target as HTMLInputElement).checked); }
  async copy(value: string): Promise<void> {
    try { await navigator.clipboard.writeText(value); this.copyNotice = 'Скопировано. Сохраните в защищённом месте.'; }
    catch { this.copyNotice = 'Копирование недоступно. Выделите и сохраните значение вручную.'; }
  }
}
