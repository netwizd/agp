import { Component, HostListener, inject, signal } from '@angular/core';
import { DatePipe, JsonPipe } from '@angular/common';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { DirectoryStore } from './directory.store';
import { DirectoryError, Provider } from './contracts';
import { VersionFields, buildDocument, versionFields } from './directory-form';
const idValidators=[Validators.required,Validators.pattern(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/)];
const uuidValidators=[Validators.required,Validators.pattern(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)];
const field=(max:number)=>new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.maxLength(max)]});
@Component({selector:'agp-directory-shell',standalone:true,imports:[ReactiveFormsModule,DatePipe,JsonPipe],templateUrl:'./directory-shell.html'})
export class DirectoryShell {
  readonly state=inject(DirectoryStore);readonly editorOpen=signal(false);
  readonly createForm=new FormGroup({name:field(128),forestGuid:new FormControl('',{nonNullable:true,validators:uuidValidators})});
  readonly versionForm=new FormGroup({
    versionId:new FormControl('',{nonNullable:true,validators:idValidators}),domainDns:field(253),transport:new FormControl<'ldaps'|'starttls'>('ldaps',{nonNullable:true}),
    endpoints:field(2200),userBaseDns:field(33000),groupBaseDns:field(33000),bindDn:field(2048),bindSecretVersionId:new FormControl('',{nonNullable:true,validators:idValidators}),caSecretVersionId:new FormControl('',{nonNullable:true,validators:idValidators}),
    loginAttribute:new FormControl<'userPrincipalName'|'sAMAccountName'>('userPrincipalName',{nonNullable:true}),provisioning:new FormControl<'preprovisioned'|'jit_unprivileged'>('preprovisioned',{nonNullable:true}),
    operationTimeoutSeconds:new FormControl(3,{nonNullable:true,validators:[Validators.required,Validators.min(1),Validators.max(10)]}),maximumGroups:new FormControl(2048,{nonNullable:true,validators:[Validators.required,Validators.min(1),Validators.max(10000)]}),groupMappings:new FormControl('',{nonNullable:true,validators:[Validators.maxLength(340000)]})
  });
  readonly versionLookup=new FormGroup({versionId:new FormControl('',{nonNullable:true,validators:idValidators})});
  readonly recoveryForm=new FormGroup({resourceId:new FormControl('',{nonNullable:true,validators:[Validators.pattern(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/)]}),confirmed:new FormControl(false,{nonNullable:true})});
  readonly provisionForm=new FormGroup({objectGuid:new FormControl('',{nonNullable:true,validators:uuidValidators})});
  readonly operationLookup=new FormGroup({operationId:new FormControl('',{nonNullable:true,validators:idValidators})});
  readonly activationForm=new FormGroup({enabled:new FormControl(true,{nonNullable:true}),reason:field(2048)});
  readonly decisionForm=new FormGroup({reason:field(2048),reviewed:new FormControl(false,{nonNullable:true,validators:[Validators.requiredTrue]})});
  readonly checkLabels:Record<string,string>={tls:'TLS и доверие сертификату',service_bind:'Сервисная учётная запись',account_lookup:'Поиск учётной записи',group_resolution:'Группы безопасности',domain_policy:'Политика домена'};
  constructor(){
    this.versionForm.valueChanges.pipe(takeUntilDestroyed()).subscribe(()=>{if(this.editorOpen())this.state.dirty.set(true);});
    this.createForm.valueChanges.pipe(takeUntilDestroyed()).subscribe(()=>this.state.dirty.set(true));
    void this.state.start();
  }
  get disabled():boolean{return this.state.busy()||!this.state.canManage();}
  get canPlanEnable():boolean{return this.state.test()?.state==='passed';}
  get canApprove():boolean{return !this.disabled&&this.state.canApprove()&&!this.state.selfOperation()&&this.state.operationCurrent()&&this.state.operation()?.approvalStatus==='pending';}
  get canExecute():boolean{return !this.disabled&&this.state.operationCurrent()&&this.state.operation()?.approvalStatus==='approved';}
  invalid(form:FormGroup,name:string):boolean{const c=form.controls[name];return c.touched&&c.invalid;}
  private valid(form:FormGroup):boolean{form.markAllAsTouched();if(form.valid)return true;requestAnimationFrame(()=>document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());return false;}
  private leave():boolean{return !this.state.dirty()||confirm('Отбросить несохранённые поля формы?');}
  focus():void{requestAnimationFrame(()=>document.getElementById(this.state.error()?'directoryError':'directoryNotice')?.focus());}
  async create():Promise<void>{if(this.disabled||!this.valid(this.createForm))return;const v=this.createForm.getRawValue();if(await this.state.create(v.name,v.forestGuid)){this.createForm.reset();this.state.dirty.set(false);this.editorOpen.set(false);}this.focus();}
  async choose(p:Provider):Promise<void>{if(!this.leave())return;await this.state.choose(p);this.createForm.reset();this.versionForm.reset();this.editorOpen.set(false);this.state.dirty.set(false);this.decisionForm.reset();this.focus();}
  openEditor():void{const p=this.state.selected();if(!p||!this.leave())return;this.createForm.reset();this.versionForm.reset(versionFields(p));this.editorOpen.set(true);this.state.dirty.set(false);requestAnimationFrame(()=>document.getElementById('directoryVersionId')?.focus());}
  closeEditor():void{if(!this.leave())return;this.editorOpen.set(false);this.versionForm.reset();this.state.dirty.set(false);}
  async propose():Promise<void>{const p=this.state.selected();if(!p||this.disabled||!this.valid(this.versionForm))return;try{const d=buildDocument(p,this.versionForm.getRawValue() as VersionFields);if(await this.state.propose(d)){this.editorOpen.set(false);this.versionForm.reset();}}catch(e){this.state.error.set(e instanceof DirectoryError?'Проверьте домен, адреса host:port, списки DN и соответствия GUID группе доступа. Ввод не отправлен.':'Не удалось подготовить версию.');}this.focus();}
  async loadVersion():Promise<void>{if(!this.valid(this.versionLookup)||!this.leave())return;if(await this.state.loadVersion(this.versionLookup.controls.versionId.value)){this.editorOpen.set(false);this.createForm.reset();this.versionForm.reset();this.state.dirty.set(false);this.decisionForm.reset();}this.focus();}
  async loadOperation():Promise<void>{if(!this.valid(this.operationLookup)||!this.leave())return;if(await this.state.loadOperation(this.operationLookup.controls.operationId.value)){this.editorOpen.set(false);this.createForm.reset();this.versionForm.reset();this.state.dirty.set(false);this.decisionForm.reset();}this.focus();}
  async provision():Promise<void>{if(this.disabled||!this.valid(this.provisionForm))return;if(await this.state.provision(this.provisionForm.controls.objectGuid.value))this.provisionForm.reset();this.focus();}
  async plan():Promise<void>{if(this.disabled||!this.valid(this.activationForm))return;const v=this.activationForm.getRawValue();if(v.enabled&&!this.canPlanEnable)return;await this.state.plan(v.enabled,v.reason);this.decisionForm.reset();this.focus();}
  async approve():Promise<void>{if(!this.canApprove||!this.valid(this.decisionForm))return;await this.state.approve(this.decisionForm.controls.reason.value);this.decisionForm.reset();this.focus();}
  async execute():Promise<void>{if(!this.canExecute||!this.valid(this.decisionForm))return;await this.state.execute(this.decisionForm.controls.reason.value);this.decisionForm.reset();this.focus();}
  async reconcile():Promise<void>{if(!this.valid(this.recoveryForm))return;this.recoveryForm.controls.confirmed.reset();await this.state.reconcile(this.recoveryForm.controls.resourceId.value);this.focus();}
  async retryExact():Promise<void>{if(!confirm('Повторить только исходный сохранённый запрос с тем же ключом, телом и условием ревизии? Поля формы не используются.'))return;this.recoveryForm.controls.confirmed.reset();await this.state.retryExact();this.focus();}
  async confirmRecovery():Promise<void>{if(!this.recoveryForm.controls.confirmed.value)return;await this.state.confirmRecovery();this.recoveryForm.reset();this.focus();}
  async refresh():Promise<void>{await this.state.refresh();this.focus();}
  async test():Promise<void>{await this.state.startTest();this.focus();}
  async refreshTest():Promise<void>{await this.state.refreshTest();this.focus();}
  @HostListener('window:beforeunload',['$event'])beforeUnload(event:BeforeUnloadEvent):void{if(this.state.dirty()||this.state.busy()||this.state.uncertain()){event.preventDefault();event.returnValue='';}}
  navigate(event:Event):void{if(!this.leave())event.preventDefault();}
}
