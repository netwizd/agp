import { Component, inject } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';
import { AuthFlowStore } from './auth-flow.store';
@Component({ selector: 'agp-auth-shell', standalone: true, imports: [RouterOutlet, RouterLink], template: `
  <main class="auth-shell">
    <header class="auth-brand" aria-label="Бренд организации">
      @if (store.branding().logoText === 'A') { <span class="auth-logo"><img src="/auth-ui/nlgate-logo.png" alt="НЛГЕЙТ" width="150" height="47" /></span> }
      @else { <span class="auth-custom-logo">{{ store.branding().logoText }}</span> }
      <div><strong>{{ store.branding().brandName }}</strong><span>Auth Gateway Portal</span></div>
    </header>
    <router-outlet />
    <footer class="auth-footer"><a routerLink="/contacts" id="ownContactsLink">Мои адреса</a><p>Защищённый доступ к корпоративным ресурсам</p></footer>
  </main>` })
export class AuthShell { readonly store = inject(AuthFlowStore); }
