import { Component, HostListener, computed, inject, signal } from '@angular/core';
import { DatePipe, JsonPipe } from '@angular/common';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { RolesStore } from './roles.store';
import { Binding, Input, ScopeType, id, intent, scopeTypes } from './roles-contracts';
const required=(max:number)=>new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.maxLength(max)]});
@Component({selector:'agp-directory-shell',standalone:true,imports:[DatePipe,JsonPipe,ReactiveFormsModule],providers:[RolesStore],templateUrl:'./roles-page.html'})
export class RolesPage {
 readonly state=inject(RolesStore);readonly scopeTypes=scopeTypes;readonly closurePage=signal(0);readonly sourcePage=signal(0);readonly pageSize=100;
 readonly createForm=new FormGroup({principalId:required(128),roleId:required(128),scopeType:new FormControl<ScopeType|''>('',{nonNullable:true,validators:Validators.required}),scopeId:new FormControl('',{nonNullable:true,validators:Validators.maxLength(128)})});
 readonly lookupForm=new FormGroup({id:new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.pattern(/^roleop_[A-Za-z0-9_-]+$/),Validators.maxLength(128)]})});
 readonly revokeForm=new FormGroup({reason:required(2048)});readonly decisionForm=new FormGroup({reason:required(2048),reviewed:new FormControl(false,{nonNullable:true})});
 readonly closure=computed(()=>{const o=this.state.operation();return o?.family==='grant_role_binding'?o.roleGrantRequest.scopeClosure:[];});
 readonly sources=computed(()=>{const o=this.state.operation();return o?.family==='grant_role_binding'?o.roleGrantRequest.scopeSourceVersions:[];});
 readonly visibleClosure=computed(()=>this.closure().slice(this.closurePage()*this.pageSize,(this.closurePage()+1)*this.pageSize));readonly visibleSources=computed(()=>this.sources().slice(this.sourcePage()*this.pageSize,(this.sourcePage()+1)*this.pageSize));
 readonly metadata=computed(()=>{const o=this.state.operation();if(!o)return null;if(o.family==='restriction')return o.roleBindingRevokeRequest;const {scopeClosure,scopeSourceVersions,...rest}=o.roleGrantRequest;return {...rest,scopeClosureCount:scopeClosure.length,scopeSourceVersionsCount:scopeSourceVersions.length};});
 constructor(){void this.state.start();}
 role(){return this.state.roles().find(r=>r.id===this.createForm.controls.roleId.value);}
 scopeName(type:string):string{return ({global:'Вся система',site:'Площадка',node_group:'Группа узлов',node:'Узел',resource:'Ресурс'} as Record<string,string>)[type]??type;}
 roleName(id:string):string{return this.state.roles().find(r=>r.id===id)?.name??id;}
 description(code:string):string{return this.state.permissions().find(x=>x.id===code)?.description??code;}
 invalid(form:FormGroup,key:string):boolean{return form.controls[key].touched&&form.controls[key].invalid;}
 private valid(form:FormGroup):boolean{form.markAllAsTouched();if(form.valid)return true;requestAnimationFrame(()=>document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());return false;}
 private focus():void{requestAnimationFrame(()=>document.getElementById(this.state.error()?'rolesError':'rolesNotice')?.focus());}
 private resetReview():void{this.decisionForm.reset({reason:'',reviewed:false});this.closurePage.set(0);this.sourcePage.set(0);}
 roleChanged():void{this.createForm.controls.scopeType.reset('');this.createForm.controls.scopeId.reset('');}
 scopeChanged():void{this.createForm.controls.scopeId.reset('');}
 async create():Promise<void>{if(!this.valid(this.createForm))return;const v=this.createForm.getRawValue();if(!id(v.principalId)||!id(v.roleId)||!scopeTypes.includes(v.scopeType as ScopeType)||!this.role()?.allowedScopes.includes(v.scopeType as ScopeType)||v.scopeType!=='global'&&!id(v.scopeId)){this.state.error.set('Выберите точную разрешённую область и её ID. Пустой ID не расширяет область до всей системы.');this.focus();return;}const input:Input=v.scopeType==='global'?{principalId:v.principalId,roleId:v.roleId,scopeType:'global'}:{principalId:v.principalId,roleId:v.roleId,scopeType:v.scopeType as Exclude<ScopeType,'global'>,scopeId:v.scopeId};await this.state.create(input);if(!this.state.error())this.createForm.reset({principalId:'',roleId:'',scopeType:'',scopeId:''});this.resetReview();this.focus();}
 choose(b:Binding):void{if(this.revokeForm.dirty&&!confirm('Выбрать другое назначение и очистить несохранённое основание отзыва?'))return;this.state.choose(b);this.revokeForm.reset();}
 async revoke():Promise<void>{if(!this.valid(this.revokeForm)||!confirm('Отозвать именно это назначение с показанной ревизией? Это ограничительное действие, а не новое назначение роли.'))return;await this.state.revoke(this.revokeForm.controls.reason.value);if(!this.state.error())this.revokeForm.reset();this.resetReview();this.focus();}
 async load():Promise<void>{if(!this.valid(this.lookupForm))return;await this.state.loadOperation(this.lookupForm.controls.id.value);this.resetReview();this.focus();}
 async refresh():Promise<void>{await this.state.refresh();this.decisionForm.controls.reviewed.setValue(false);this.focus();}
 async decide(kind:'approve'|'execute'):Promise<void>{if(!this.valid(this.decisionForm)||!this.decisionForm.controls.reviewed.value)return;await this.state[kind](this.decisionForm.controls.reason.value);this.decisionForm.reset({reason:'',reviewed:false});this.focus();}
 async retry():Promise<void>{if(!confirm('Явно повторить только сохранённые исходные тело, ключ и CAS? Изменённые поля формы не используются. Сервер снова проверит права и участников.'))return;await this.state.retry();this.focus();}
 async reconcile():Promise<void>{await this.state.reconcile();this.focus();}
 private dirty():boolean{return this.createForm.dirty||this.revokeForm.dirty||this.decisionForm.dirty;}
 navigate(e:Event):void{if(this.state.busy()||(this.state.pending()||this.dirty())&&!confirm('Покинуть страницу? Несохранённые формы и сведения для проверки неизвестного ответа находятся только в памяти и будут потеряны.'))e.preventDefault();}
 @HostListener('window:beforeunload',['$event'])beforeUnload(e:BeforeUnloadEvent):void{if(this.state.busy()||this.state.pending()||this.dirty()){e.preventDefault();e.returnValue='';}}
}
