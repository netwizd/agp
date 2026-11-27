import { Component, HostListener, effect, inject, signal } from '@angular/core';
import { JsonPipe } from '@angular/common';
import { FormControl, ReactiveFormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ConfigStore } from './config.store';
import { ResourceForm } from './resource-form';
import { ConfigHelp, Topic, topics } from './help-tip';
import { DocumentFormat } from './contracts';
import { ZonesPanel } from './zones-panel';
import { ScopedGateway } from './scoped-gateway';
import { ScopedResource } from './scoped-resource';
import { WafPolicyPanel } from './waf-policy-panel';
import { InventoryPanel } from './inventory-panel';
import { PlanProposalsPanel } from './plan-proposals-panel';
import { ExecutionPanel } from './execution-panel';
@Component({ selector: 'agp-config-shell', standalone: true, imports: [JsonPipe, ResourceForm, ConfigHelp, ReactiveFormsModule, ZonesPanel, ScopedGateway, ScopedResource, WafPolicyPanel, InventoryPanel, PlanProposalsPanel, ExecutionPanel], templateUrl: './config-shell.html' })
export class ConfigShell {
    readonly state = inject(ConfigStore);
    readonly tab = signal<'zones'|'configuration'|'gateway'|'resource'|'policies'|'inventory'|'plans'|'execution'>(new URL(location.href).searchParams.has('draft') ? 'configuration' : 'zones');
    readonly topics = topics;
    readonly topicIds = Object.keys(topics) as Topic[];
    formInvalid = signal(false);
    readonly openSections = signal<ReadonlySet<string>>(new Set());
    catalogText = signal('');
    catalogFormat = signal<DocumentFormat>('json');
    readonly catalogControl = new FormControl('', { nonNullable: true });
    readonly revisionControl = new FormControl('', { nonNullable: true });
    constructor() {
        // SelectControlValueAccessor reapplies selection when asynchronous
        // @for options register, including an imported catalog in this turn.
        effect(() => this.catalogControl.setValue(this.state.catalogId(), { emitEvent: false }));
        effect(() => {
            const access = this.state.access();
            if (access && !access.globalRead && !access.sites.some(site => site.read)) {
                if (access.gatewayRead || access.gatewayEdit) this.tab.set('gateway');
                else if (access.resourceRead) this.tab.set('resource');
            }
        });
        effect(() => {
            this.revisionControl.setValue(this.state.selectedRevision()?.id ?? '', { emitEvent: false });
            const disabled = this.state.dirty() || !!this.state.pending() || this.state.busy() || this.formInvalid();
            if (disabled) this.revisionControl.disable({ emitEvent: false });
            else this.revisionControl.enable({ emitEvent: false });
        });
        this.revisionControl.valueChanges.pipe(takeUntilDestroyed()).subscribe(value => {
            if (value) void this.state.loadRevision(value);
        });
        this.catalogControl.valueChanges.pipe(takeUntilDestroyed()).subscribe(value => {
            this.state.catalogId.set(value);
            this.state.report.set(null);
        });
        void this.state.start();
    }
    value(event: Event): string { return (event.target as HTMLInputElement).value; }
    tabsKeydown(event: KeyboardEvent): void {
        if (event.altKey || event.ctrlKey || event.metaKey || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        const list = event.currentTarget as HTMLElement;
        const tabs = Array.from(list.querySelectorAll<HTMLButtonElement>('button[role="tab"]:not(:disabled)'));
        const current = tabs.indexOf(event.target as HTMLButtonElement);
        if (current < 0 || !tabs.length) return;
        const index = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
        event.preventDefault(); tabs[index].focus(); tabs[index].click();
    }
    showManual(topic: Topic): void { const target = document.getElementById('manual-' + topic); target?.focus(); target?.scrollIntoView({ block: 'center', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' }); }
    toggle(event: Event, key: string): void { const next = new Set(this.openSections()); if ((event.target as HTMLDetailsElement).open)
        next.add(key);
    else
        next.delete(key); this.openSections.set(next); }
    isOpen(key: string): boolean { return this.openSections().has(key); }
    stepUpURL(): string { return '/auth-ui/step-up?return=' + encodeURIComponent(location.pathname + location.search); }
    loginURL(): string { return '/auth-ui/login?return=' + encodeURIComponent(location.pathname + location.search); }
    @HostListener('window:beforeunload', ['$event'])
    beforeUnload(event: BeforeUnloadEvent): void { if (this.state.dirty() || this.state.pending() || this.formInvalid()) {
        event.preventDefault();
        event.returnValue = '';
    } }
}
