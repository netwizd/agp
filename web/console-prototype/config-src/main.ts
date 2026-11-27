import { bootstrapApplication } from '@angular/platform-browser';
import { ConfigShell } from './app/config-shell';
bootstrapApplication(ConfigShell).catch(() => { const root = document.querySelector('agp-config-shell'); if (root)
    root.textContent = 'Не удалось открыть редактор. Обновите страницу.'; });
