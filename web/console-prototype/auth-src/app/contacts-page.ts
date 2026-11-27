import { Component, HostListener, OnDestroy, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Contact } from './contacts-api';
import { ContactsStore } from './contacts.store';
@Component({selector:'agp-contacts-page',standalone:true,providers:[ContactsStore],imports:[ReactiveFormsModule,RouterLink,DatePipe],templateUrl:'./contacts-page.html'})
export class ContactsPage implements OnDestroy {
  readonly state=inject(ContactsStore);readonly editing=signal<Contact|null>(null);
  readonly addressForm=new FormGroup({email:new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.email,Validators.maxLength(254),Validators.pattern(/^[\x21-\x7e]+$/)]}),replaceConsent:new FormControl(false,{nonNullable:true})});
  readonly codeForm=new FormGroup({code:new FormControl('',{nonNullable:true,validators:[Validators.required,Validators.pattern(/^[0-9]{8}$/)]})});
  readonly recoveryForm=new FormGroup({acknowledged:new FormControl(false,{nonNullable:true})});
  readonly stepUpQuery={return:'/auth-ui/contacts'};
  constructor(){void this.state.initialize().then(()=>requestAnimationFrame(()=>document.getElementById(this.state.error()?'contactError':'contactsTitle')?.focus()));}
  invalid(form:FormGroup,name:string):boolean{const c=form.controls[name];return c.touched&&c.invalid;}
  private valid(form:FormGroup):boolean{form.markAllAsTouched();if(form.valid)return true;requestAnimationFrame(()=>document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());return false;}
  focus():void{requestAnimationFrame(()=>document.getElementById(this.state.error()?'contactError':'contactNotice')?.focus());}
  replace(contact:Contact):void{if(!this.state.canWrite())return;if(this.addressForm.controls.email.value&&!confirm('Очистить несохранённый адрес и выбрать этот контакт для замены?'))return;this.addressForm.reset();this.editing.set({...contact});requestAnimationFrame(()=>document.getElementById('contactEmail')?.focus());}
  cancelEdit():void{this.addressForm.reset();this.editing.set(null);}
  async save():Promise<void>{if(!this.state.canWrite()||!this.valid(this.addressForm))return;const target=this.editing();if(target&&!this.addressForm.controls.replaceConsent.value){this.addressForm.controls.replaceConsent.markAsTouched();requestAnimationFrame(()=>document.getElementById('contactReplaceConsent')?.focus());return;}const email=this.addressForm.controls.email.value;try{if(target)await this.state.replace(target,email);else await this.state.create(email);}finally{this.addressForm.reset();if(this.state.reloginRequired())this.editing.set(null);this.focus();}}
  async start(contact:Contact):Promise<void>{if(this.addressForm.controls.email.value&&!confirm('Очистить несохранённый адрес и перейти к подтверждению выбранного контакта?'))return;this.addressForm.reset();this.editing.set(null);this.codeForm.reset();await this.state.start(contact);this.focus();}
  async issue():Promise<void>{this.codeForm.reset();await this.state.issue();this.focus();}
  async status():Promise<void>{await this.state.status();this.focus();}
  async proof():Promise<void>{if(!this.valid(this.codeForm)||!this.state.canProof())return;const code=this.codeForm.controls.code.value;try{await this.state.proof(code);}finally{this.codeForm.reset();this.focus();}}
  async complete():Promise<void>{await this.state.complete();this.focus();}
  async cancel():Promise<void>{this.codeForm.reset();await this.state.cancel();this.focus();}
  async reconcile():Promise<void>{this.codeForm.reset();this.recoveryForm.reset();await this.state.reconcile();this.focus();}
  async acknowledge():Promise<void>{if(!this.recoveryForm.controls.acknowledged.value)return;await this.state.acknowledgeRecovery();this.recoveryForm.reset();this.focus();}
  async refresh():Promise<void>{await this.state.refreshContacts();this.focus();}
  canLeave():boolean{if(this.state.busy())return false;if(this.state.reloginRequired())return true;return !this.addressForm.controls.email.value&&!this.codeForm.controls.code.value&&!this.state.active()&&!this.state.uncertain()||confirm('Покинуть страницу адресов? Ввод и состояние подтверждения не сохраняются. Неизвестные отправки автоматически не повторяются.');}
  @HostListener('window:beforeunload',['$event'])beforeUnload(event:BeforeUnloadEvent):void{if(this.state.busy()||this.addressForm.controls.email.value||this.codeForm.controls.code.value||this.state.active()||this.state.uncertain()){event.preventDefault();event.returnValue='';}}
  ngOnDestroy():void{this.addressForm.reset();this.codeForm.reset();this.recoveryForm.reset();}
}
