import { Component, HostListener, OnDestroy, inject } from '@angular/core';
import { DatePipe } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { LifecycleAuthStore, SetupKind, secretToken, validPassword } from './lifecycle-auth.store';
import { takeSetupFragment } from './setup-fragment';
@Component({selector:'agp-lifecycle-auth',standalone:true,imports:[DatePipe,RouterLink,ReactiveFormsModule],providers:[LifecycleAuthStore],templateUrl:'./lifecycle-auth-page.html'})
export class LifecycleAuthPage implements OnDestroy {
 readonly state=inject(LifecycleAuthStore);private readonly route=inject(ActivatedRoute);readonly kind=this.route.snapshot.data['setupKind'] as SetupKind;
 readonly tokenForm=new FormGroup({token:new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.pattern(/^[A-Za-z0-9_-]{43}$/)]})});
 readonly passwordForm=new FormGroup({password:new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.maxLength(1024)]}),confirmation:new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.maxLength(1024)]})});
 readonly codeForm=new FormGroup({code:new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.pattern(/^[0-9]{6}$/)]})});readonly emailForm=new FormGroup({code:new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.pattern(/^[0-9]{8}$/)]})});
 readonly requestForm=new FormGroup({username:new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.maxLength(128)]}),email:new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.email,Validators.maxLength(254)]})});
 constructor(){const input=takeSetupFragment(this.kind);this.tokenForm.controls.token.setValue(input.token);void this.state.initialize(this.kind).then(()=>{if(input.invalid)this.state.error.set('Ссылка не прошла проверку. Одноразовый секрет можно ввести вручную; он не должен находиться в query.');});}
 get title():string{return this.kind==='activate'?'Активация учётной записи':this.kind==='reset_password'?'Восстановление пароля':'Согласованное восстановление';}
 invalid(form:FormGroup,key:string):boolean{const c=form.controls[key];return c.touched&&c.invalid;}
 private valid(form:FormGroup):boolean{form.markAllAsTouched();if(form.valid)return true;requestAnimationFrame(()=>document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());return false;}
 focus():void{requestAnimationFrame(()=>document.getElementById(this.state.error()?'setupError':'setupNotice')?.focus());}
 async token():Promise<void>{if(!this.valid(this.tokenForm)||!secretToken(this.tokenForm.controls.token.value))return;try{await this.state.bind(this.tokenForm.controls.token.value);}finally{this.tokenForm.reset();this.focus();}}
 async password():Promise<void>{if(!this.valid(this.passwordForm))return;const v=this.passwordForm.getRawValue();if(!validPassword(v.password)||v.password!==v.confirmation){this.state.error.set('Введите одинаковый новый пароль длиной 12–1024 байта UTF-8. Пароль не обрезается и не нормализуется.');this.passwordForm.reset();this.focus();return;}try{await this.state.password(v.password);}finally{this.passwordForm.reset();this.focus();}}
 async code():Promise<void>{if(!this.valid(this.codeForm))return;try{if(this.state.stage()==='totp_enrollment')await this.state.confirm(this.codeForm.controls.code.value);else await this.state.totp(this.codeForm.controls.code.value);}finally{this.codeForm.reset();this.focus();}}
 async email():Promise<void>{if(!this.valid(this.emailForm))return;try{await this.state.email(this.emailForm.controls.code.value);}finally{this.emailForm.reset();this.focus();}}
 async request():Promise<void>{if(!this.valid(this.requestForm))return;const v=this.requestForm.getRawValue();try{await this.state.requestReset(v.username,v.email);}finally{this.requestForm.reset();this.focus();}}
 async reconcile():Promise<void>{await this.state.reconcile();this.focus();}
 async cancel():Promise<void>{if(!confirm('Отменить ограниченный процесс на сервере? Подготовленные пароль и фактор будут отозваны; может потребоваться новое приглашение или ticket.'))return;await this.state.cancel();this.tokenForm.reset();this.passwordForm.reset();this.codeForm.reset();this.emailForm.reset();this.focus();}
 async complete():Promise<void>{await this.state.complete();this.focus();}
 saved(event:Event):void{this.state.codesSaved.set((event.target as HTMLInputElement).checked);}
 abandon():void{if(!confirm('Начать новый процесс вручную? Исходный запрос не повторится. Одноразовый секрет мог быть зарезервирован; тогда потребуется новая ссылка или согласованная операция.'))return;this.tokenForm.reset();this.passwordForm.reset();this.codeForm.reset();this.emailForm.reset();this.state.abandon();}
 canLeave():boolean{if(this.state.busy())return false;return !(this.state.active()||this.state.uncertain()||this.tokenForm.controls.token.value||this.passwordForm.controls.password.value||this.passwordForm.controls.confirmation.value||this.codeForm.controls.code.value||this.emailForm.controls.code.value||this.state.codesIssued()&&!this.state.codesSaved())||confirm('Покинуть ограниченный процесс? Пароли, коды и ключ настройки не сохранятся. Использованная ссылка или ticket могут потребовать нового разрешённого восстановления.');}
 @HostListener('window:beforeunload',['$event'])beforeUnload(event:BeforeUnloadEvent):void{if(this.state.active()||this.state.uncertain()||this.state.busy()||this.tokenForm.controls.token.value||this.passwordForm.controls.password.value||this.state.codesIssued()&&!this.state.codesSaved()){event.preventDefault();event.returnValue='';}}
 ngOnDestroy():void{this.tokenForm.reset();this.passwordForm.reset();this.codeForm.reset();this.emailForm.reset();this.requestForm.reset();}
}
