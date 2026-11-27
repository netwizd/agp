import { Component, EventEmitter, HostListener, Input, OnInit, Output, inject, signal } from '@angular/core';
import { FormControl, ReactiveFormsModule, Validators } from '@angular/forms';
import { ConfigApi, ConfigError, Mutation, mutation } from './config-api';
import { ConfigAccess, Configuration, Gateway, Issue } from './contracts';
import { ResourceForm } from './resource-form';
import { Topic } from './help-tip';
interface GatewayRevision {
    id: string;
    baseRevisionId?: string;
    contentDigest: string;
    viewScope: 'gateway';
    gatewayView: Gateway;
    gatewayAccess?: { read: boolean; edit: boolean };
    state: string;
    revision: string;
}
interface PendingGateway {
    operation: Mutation;
    sequence: number;
}
interface GatewaySummary { id: string; siteId: string; name: string; deploymentState: 'unknown'; access: { read: boolean; edit: boolean }; }
interface GatewayPage { revisionId?: string; items: GatewaySummary[]; nextCursor?: string; }
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const id = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const permissions = (value: unknown): boolean => object(value) && typeof value['read'] === 'boolean' && typeof value['edit'] === 'boolean';
@Component({ selector: 'agp-scoped-gateway', standalone: true, imports: [ReactiveFormsModule, ResourceForm], templateUrl: './scoped-gateway.html' })
export class ScopedGateway implements OnInit {
    private api = inject(ConfigApi);
    private sequence = 0;
    @Input({ required: true })
    access!: ConfigAccess;
    @Output()
    manual = new EventEmitter<Topic>();
    readonly baseId = new FormControl('', { nonNullable: true, validators: [Validators.required] });
    readonly gatewayId = new FormControl('', { nonNullable: true, validators: [Validators.required] });
    readonly listRevision = new FormControl('', { nonNullable: true });
    readonly gateways = signal<GatewaySummary[]>([]);
    readonly listRevisionId = signal('');
    readonly nextCursor = signal('');
    readonly listBusy = signal(false);
    readonly listLoaded = signal(false);
    readonly listError = signal('');
    readonly loaded = signal<GatewayRevision | null>(null);
    readonly model = signal<Configuration | null>(null);
    readonly busy = signal(false);
    readonly dirty = signal(false);
    readonly invalid = signal(false);
    readonly pending = signal<PendingGateway | null>(null);
    readonly conflict = signal(false);
    readonly error = signal('');
    readonly issues = signal<Issue[]>([]);
    readonly notice = signal('');
    ngOnInit(): void { void this.refreshGateways(); }
    async refreshGateways(): Promise<void> { await this.loadGateways(false); }
    async moreGateways(): Promise<void> { if (this.nextCursor()) await this.loadGateways(true); }
    private async loadGateways(more: boolean): Promise<void> {
        if (this.listBusy()) return;
        this.listBusy.set(true);
        this.listError.set('');
        try {
            const revision = more ? this.listRevisionId() : this.listRevision.value;
            if (revision && !id(revision)) throw new ConfigError('invalid_id');
            const query = ['limit=50', ...(revision ? ['revisionId=' + encodeURIComponent(revision)] : []), ...(more ? ['cursor=' + encodeURIComponent(this.nextCursor())] : [])];
            const value = await this.api.get('/api/v2/gateways?' + query.join('&'));
            if (!object(value) || !Array.isArray(value['items']) || (value['revisionId'] !== undefined && !id(value['revisionId'])) || (value['nextCursor'] !== undefined && !id(value['nextCursor']))) throw new ConfigError('invalid_response');
            for (const item of value['items']) if (!object(item) || !id(item['id']) || !id(item['siteId']) || typeof item['name'] !== 'string' || item['deploymentState'] !== 'unknown' || !permissions(item['access']) || !(item['access'] as { read: boolean }).read) throw new ConfigError('invalid_response');
            const page = value as unknown as GatewayPage;
            if (((page.items.length || page.nextCursor) && !page.revisionId) || (more && page.revisionId !== this.listRevisionId())) throw new ConfigError('invalid_response');
            if (new Set(page.items.map(item => item.id)).size !== page.items.length || more && page.items.some(item => this.gateways().some(prior => prior.id === item.id))) throw new ConfigError('invalid_response');
            this.gateways.set(more ? [...this.gateways(), ...page.items] : page.items);
            this.listRevisionId.set(page.revisionId ?? '');
            this.nextCursor.set(page.nextCursor ?? '');
            this.listLoaded.set(true);
        } catch (error) { this.listError.set(error instanceof ConfigError ? error.code : 'request_failed'); }
        finally { this.listBusy.set(false); }
    }
    async openGateway(item: GatewaySummary): Promise<void> {
        if (this.busy() || this.dirty() || this.invalid() || this.pending() || !this.listRevisionId()) return;
        this.baseId.setValue(this.listRevisionId());
        this.gatewayId.setValue(item.id);
        await this.load();
    }
    private decode(value: unknown): GatewayRevision { if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new ConfigError('invalid_response'); const record = value as Record<string, unknown>; if (record['viewScope'] !== 'gateway' || 'content' in record || typeof record['id'] !== 'string' || typeof record['contentDigest'] !== 'string' || !record['gatewayView'] || typeof record['gatewayView'] !== 'object')
        throw new ConfigError('invalid_response'); if (record['gatewayAccess'] !== undefined && !permissions(record['gatewayAccess'])) throw new ConfigError('invalid_response'); return value as GatewayRevision; }
    private path(): string { if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(this.gatewayId.value))
        throw new ConfigError('invalid_gateway_id'); return this.api.path('revisions', this.baseId.value) + '?gatewayId=' + encodeURIComponent(this.gatewayId.value); }
    async load(): Promise<void> { if (this.busy() || this.dirty() || this.invalid() || this.pending())
        return; this.busy.set(true); try {
        this.install(this.decode(await this.api.get(this.path())));
        this.clearError();
        this.notice.set('Загружен только разрешённый шлюз; соседние конфигурации не передаются.');
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    changed(value: Configuration): void { this.model.set(value); this.dirty.set(true); this.sequence++; }
    canEdit(): boolean { const loaded = this.loaded(); if (!loaded) return false; if (loaded.gatewayAccess) return loaded.gatewayAccess.read && loaded.gatewayAccess.edit; if (this.access.gatewayRead !== undefined || this.access.gatewayEdit !== undefined) return false; const site = loaded.gatewayView.metadata.siteId; return this.access.globalEdit || this.access.sites.some(item => item.siteId === site && item.edit); }
    async save(): Promise<void> { const gateway = this.model()?.gateways[0], loaded = this.loaded(); if (!gateway || !loaded || !this.canEdit() || this.busy() || this.pending() || this.invalid() || this.conflict())
        return; await this.execute({ operation: mutation('/api/v2/config/revisions', { baseRevisionId: loaded.id, gatewayChange: { gatewayId: gateway.metadata.id, content: gateway } }), sequence: this.sequence }); }
    async retry(): Promise<void> { const pending = this.pending(); if (pending && !this.busy())
        await this.execute(pending); }
    async useBase(): Promise<void> { if (this.pending() || this.busy())
        return; this.busy.set(true); try {
        const base = this.decode(await this.api.get(this.path()));
        const current = this.model()?.gateways[0];
        if (!current || base.gatewayView.metadata.id !== current.metadata.id || base.gatewayView.metadata.siteId !== current.metadata.siteId)
            throw new ConfigError('gateway_base_mismatch');
        this.loaded.set(base);
        this.conflict.set(false);
        this.clearError();
        this.notice.set('Base заменён явно; локальный шлюз сохранён. Проверьте отличия перед созданием ревизии.');
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    discard(): void { if (this.pending() || this.busy())
        return; this.model.set(null); this.loaded.set(null); this.dirty.set(false); this.invalid.set(false); this.conflict.set(false); this.clearError(); }
    private async execute(pending: PendingGateway): Promise<void> { this.busy.set(true); this.pending.set(pending); this.clearError(); try {
        const result = this.decode(await this.api.write(pending.operation));
        this.pending.set(null);
        if (pending.sequence === this.sequence)
            this.install(result);
        else
            this.loaded.set(result);
        this.notice.set('Создана неизменяемая ревизия ' + result.id + '. Сервер сохранил соседние шлюзы; публикация не выполнялась.');
    }
    catch (error) {
        this.fail(error);
        if (error instanceof ConfigError && error.status >= 400 && error.status < 500) {
            this.pending.set(null);
            if (error.status === 412)
                this.conflict.set(true);
        }
    }
    finally {
        this.busy.set(false);
    } }
    private install(value: GatewayRevision): void { this.loaded.set(value); this.baseId.setValue(value.id); this.gatewayId.setValue(value.gatewayView.metadata.id); this.model.set({ apiVersion: 'agp.config/v1alpha1', kind: 'Configuration', metadata: { id: 'local_gateway_wrapper', name: 'Локальное представление одного шлюза' }, gateways: [structuredClone(value.gatewayView)], profileAssignments: [] }); this.dirty.set(false); this.invalid.set(false); this.conflict.set(false); }
    download(): void { const gateway = this.model()?.gateways[0]; if (!gateway)
        return; const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([JSON.stringify(gateway, null, 2)], { type: 'application/json' })); link.download = 'agp-gateway-local.json'; link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000); }
    @HostListener('window:beforeunload', ['$event'])
    beforeUnload(event: BeforeUnloadEvent): void { if (this.dirty() || this.pending() || this.invalid()) {
        event.preventDefault();
        event.returnValue = '';
    } }
    private clearError(): void { this.error.set(''); this.issues.set([]); }
    private fail(error: unknown): void { this.error.set(error instanceof ConfigError ? error.code : 'request_failed'); this.issues.set(error instanceof ConfigError ? error.issues : []); }
}
