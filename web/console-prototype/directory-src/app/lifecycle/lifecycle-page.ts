import { Component, HostListener, OnDestroy, inject, signal } from '@angular/core';
import { DatePipe, JsonPipe } from '@angular/common';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { LifecycleStore } from './lifecycle.store';
import { Action, id } from './lifecycle-contracts';
const required=(max:number)=>new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.maxLength(max)]});
const expiry=()=>new Date(Date.now()+10*60000).toISOString().slice(0,16);
@Component({selector:'agp-directory-shell',standalone:true,imports:[DatePipe,JsonPipe,ReactiveFormsModule],providers:[LifecycleStore],templateUrl:'./lifecycle-page.html'})
export class LifecyclePage implements OnDestroy {
 readonly state=inject(LifecycleStore);readonly showTicket=signal(false);
 readonly createForm=new FormGroup({id:new FormControl('usr_'+crypto.randomUUID().replaceAll('-',''),{nonNullable:true,validators:[Validators.required,Validators.pattern(/^usr_[A-Za-z0-9_-]{1,123}$/)]}),username:required(128),displayName:new FormControl('',{nonNullable:true,validators:Validators.maxLength(256)}),groups:new FormControl('',{nonNullable:true,validators:Validators.maxLength(12800)})});
 readonly inviteForm=new FormGroup({email:new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.email,Validators.maxLength(254)]}),ttl:new FormControl(3600,{nonNullable:true,validators:[Validators.required,Validators.min(300),Validators.max(86400)]})});
 readonly planForm=new FormGroup({action:new FormControl<Action>('replace_mfa',{nonNullable:true,validators:Validators.required}),expiry:new FormControl(expiry(),{nonNullable:true,validators:Validators.required}),reason:required(2048)});
 readonly operationForm=new FormGroup({id:new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.pattern(/^recoveryop_[A-Za-z0-9_-]+$/),Validators.maxLength(128)]})});
 readonly decisionForm=new FormGroup({reason:required(2048),reviewed:new FormControl(false,{nonNullable:true})});
 readonly recoveryForm=new FormGroup({id:new FormControl('',{nonNullable:true,validators:[Validators.maxLength(128)]}),confirmed:new FormControl(false,{nonNullable:true})});
 constructor(){void this.state.start();}
 invalid(f:FormGroup,k:string):boolean{return f.controls[k].touched&&f.controls[k].invalid;}
 private valid(f:FormGroup):boolean{f.markAllAsTouched();if(f.valid)return true;requestAnimationFrame(()=>document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());return false;}
 private focus():void{requestAnimationFrame(()=>document.getElementById(this.state.error()?'identityError':'identityNotice')?.focus());}
 private dirty():boolean{return this.createForm.dirty||this.inviteForm.dirty||this.planForm.dirty||this.decisionForm.dirty;}
 private reset():void{this.inviteForm.reset({email:'',ttl:3600});this.planForm.reset({action:this.state.selected()?.lifecycleState==='invited'?'restart_activation':'replace_mfa',expiry:expiry(),reason:''});this.decisionForm.reset({reason:'',reviewed:false});}
 async choose(id:string):Promise<void>{if(this.dirty()&&!confirm('Сменить учётную запись? Несохранённые поля будут очищены.'))return;await this.state.choose(id);this.reset();this.focus();}
 async create():Promise<void>{if(!this.valid(this.createForm))return;const v=this.createForm.getRawValue(),groups=v.groups.split(/[\s,]+/).filter(Boolean);if(groups.length>100||new Set(groups).size!==groups.length||!groups.every(id)){this.state.error.set('Укажите до 100 уникальных ID существующих групп, разделённых пробелом или запятой.');this.focus();return;}await this.state.create({id:v.id,username:v.username,displayName:v.displayName,groupIds:groups});if(!this.state.error()){this.createForm.reset({id:'usr_'+crypto.randomUUID().replaceAll('-',''),username:'',displayName:'',groups:''});this.reset();}this.focus();}
 async invite():Promise<void>{if(!this.valid(this.inviteForm))return;const v=this.inviteForm.getRawValue();if(!Number.isInteger(v.ttl))return;try{await this.state.invite(v.email,v.ttl);}finally{this.inviteForm.reset({email:'',ttl:3600});this.focus();}}
 async plan():Promise<void>{if(!this.valid(this.planForm))return;const v=this.planForm.getRawValue(),end=Date.parse(v.expiry+'Z');if(!Number.isFinite(end)||end<=Date.now()||end>Date.now()+15*60000||!['replace_mfa','reset_password','restart_activation'].includes(v.action)){this.state.error.set('Укажите UTC-срок в пределах следующих 15 минут и точное действие.');this.focus();return;}await this.state.plan(v.action,new Date(end).toISOString(),v.reason);if(!this.state.error())this.planForm.markAsPristine();this.decisionForm.reset({reason:'',reviewed:false});this.focus();}
 async loadOperation():Promise<void>{if(!this.valid(this.operationForm)||this.dirty()&&!confirm('Открыть операцию и очистить несохранённые поля?'))return;await this.state.loadOperation(this.operationForm.controls.id.value);this.reset();this.focus();}
 async decision(kind:'approve'|'execute'):Promise<void>{if(!this.valid(this.decisionForm)||!this.decisionForm.controls.reviewed.value)return;await this.state[kind](this.decisionForm.controls.reason.value);this.decisionForm.reset({reason:'',reviewed:false});this.focus();}
 async refresh():Promise<void>{await this.state.refresh();this.decisionForm.controls.reviewed.setValue(false);this.focus();}
 async ticket():Promise<void>{if(!confirm('Получить ticket единственный раз? Подготовьте доверенный канал передачи проверенному владельцу. При потере ответа ticket не выдаётся повторно.'))return;await this.state.issueTicket();this.showTicket.set(false);this.focus();}
 clearTicket():void{if(!confirm('Удалить ticket из памяти? Повторно получить его этой операцией нельзя.'))return;this.state.clearTicket();this.showTicket.set(false);}
 async reconcile():Promise<void>{if(this.recoveryForm.controls.id.invalid)return;this.recoveryForm.controls.confirmed.setValue(false);await this.state.reconcile(this.recoveryForm.controls.id.value);this.focus();}
 async retry():Promise<void>{if(!confirm('Явно повторить только сохранённые неизменяемые тело, ключ и CAS? Сервер повторно проверит текущие разрешения. Новые поля формы не используются.'))return;await this.state.retryExact();this.focus();}
 async acknowledge():Promise<void>{if(!this.recoveryForm.controls.confirmed.value)return;await this.state.acknowledge();this.focus();}
 navigate(e:MouseEvent):void{if(this.state.busy()||this.state.pending()||this.state.ticket()||this.dirty()){if(this.state.busy()||!confirm('Покинуть страницу? Несохранённые поля, ticket и сведения для проверки потерянного ответа не сохранятся.'))e.preventDefault();}}
 @HostListener('window:beforeunload',['$event'])beforeUnload(e:BeforeUnloadEvent):void{if(this.state.busy()||this.state.pending()||this.state.ticket()||this.dirty()){e.preventDefault();e.returnValue='';}}
 ngOnDestroy():void{this.inviteForm.reset();this.state.clearTicket();}
}
