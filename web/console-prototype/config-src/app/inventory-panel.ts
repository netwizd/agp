import { Component, inject, signal } from '@angular/core';
import { JsonPipe } from '@angular/common';
import { ConfigError } from './config-api';
import { AgentInventoryItem, InventoryApi } from './inventory-api';
import { NodeIdentityPanel } from './node-identity-panel';

@Component({ selector: 'agp-inventory-panel', standalone: true, imports: [JsonPipe, NodeIdentityPanel], templateUrl: './inventory-panel.html' })
export class InventoryPanel {
    private readonly api = inject(InventoryApi);
    readonly busy = signal(false);
    readonly error = signal('');
    readonly loaded = signal(false);
    readonly items = signal<AgentInventoryItem[]>([]);
    ngOnInit(): void { void this.refresh(); }
    async refresh(): Promise<void> {
        if (this.busy()) return;
        this.busy.set(true);
        this.error.set('');
        try { this.items.set(await this.api.list()); this.loaded.set(true); }
        catch (error) { this.error.set(error instanceof ConfigError ? error.code : 'request_failed'); }
        finally { this.busy.set(false); }
    }
}
