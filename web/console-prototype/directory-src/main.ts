import { bootstrapApplication } from '@angular/platform-browser';
const view=new URL(location.href).searchParams.get('view');
const page=view==='roles'?import('./app/roles/roles-page').then(m=>m.RolesPage):view==='identity'?import('./app/lifecycle/lifecycle-page').then(m=>m.LifecyclePage):view==='oidc'?import('./app/oidc/oidc-page').then(m=>m.OidcPage):import('./app/directory-shell').then(m=>m.DirectoryShell);
page.then(component=>bootstrapApplication(component)).catch(() => { const root = document.querySelector('agp-directory-shell'); if (root) root.textContent = 'Не удалось открыть управление идентификацией. Обновите страницу.'; });
