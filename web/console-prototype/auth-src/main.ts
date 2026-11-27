import { APP_BASE_HREF } from '@angular/common';
import { inject, provideZonelessChangeDetection } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { CanDeactivateFn, provideRouter } from '@angular/router';
import { AuthShell } from './app/auth-shell';
import type { AuthPage } from './app/auth-page';
import { captureSetupFragment } from './app/setup-fragment';
import type { LifecycleAuthPage } from './app/lifecycle-auth-page';
import type { ContactsPage } from './app/contacts-page';
import { AuthFlowStore } from './app/auth-flow.store';
captureSetupFragment();
const canLeaveAuth: CanDeactivateFn<AuthPage> = () => inject(AuthFlowStore).canLeave();
bootstrapApplication(AuthShell, { providers: [provideZonelessChangeDetection(), { provide: APP_BASE_HREF, useValue: '/auth-ui/' }, provideRouter([
  ...([{path:'activate',kind:'activate'},{path:'reset-password',kind:'reset_password'},{path:'recovery-ticket',kind:'supervised'}] as const).map(r=>({path:r.path,loadComponent:()=>import('./app/lifecycle-auth-page').then(m=>m.LifecycleAuthPage),data:{setupKind:r.kind},canDeactivate:[(page:LifecycleAuthPage)=>page.canLeave()]})),
  { path: 'contacts', loadComponent: () => import('./app/contacts-page').then(m => m.ContactsPage), canDeactivate: [(page: ContactsPage) => page.canLeave()] },
  { path: 'login', loadComponent: () => import('./app/auth-page').then(m => m.AuthPage), data: { purpose: 'login' }, canDeactivate: [canLeaveAuth] },
  { path: 'recover', loadComponent: () => import('./app/auth-page').then(m => m.AuthPage), data: { purpose: 'recover' }, canDeactivate: [canLeaveAuth] },
  { path: 'step-up', loadComponent: () => import('./app/auth-page').then(m => m.AuthPage), data: { purpose: 'step_up' }, canDeactivate: [canLeaveAuth] },
  { path: '', pathMatch: 'full', loadComponent: () => import('./app/auth-page').then(m => m.AuthPage), data: { purpose: 'login', callback: true }, canDeactivate: [canLeaveAuth] },
  { path: '**', redirectTo: 'login' },
])] }).catch(() => {
  const root = document.querySelector('agp-auth-shell');
  if (root) { const message = document.createElement('p'); message.className = 'bootstrap-notice'; message.setAttribute('role', 'alert'); message.textContent = 'Не удалось загрузить защищённый вход. Обновите страницу или обратитесь к администратору.'; root.replaceChildren(message); }
});
