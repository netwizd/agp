import { Component, HostListener, OnInit, inject, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ConfigApi, ConfigError, Mutation, mutation } from './config-api';
import { Issue, Route } from './contracts';

interface Placement { resourceId: string; gatewayId: string; routeId: string; }
interface ResourceSummary extends Placement {
    resourceName: string;
    routeName: string;
    hostname: string;
    path: string;
    access: { read: boolean; edit: boolean };
}
interface ResourcePage { revisionId?: string; items: ResourceSummary[]; nextCursor?: string; }
interface ResourceRevision {
    id: string;
    baseRevisionId?: string;
    contentDigest: string;
    viewScope: 'resource';
    resourceView: { resourceId: string; resourceName: string; gatewayId: string; route: Route };
    resourceAccess: { read: boolean; edit: boolean };
    state: string;
    revision: string;
}
interface PendingResource { operation: Mutation; sequence: number; placement: Placement; }
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const id = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const cursor = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_-]{1,4096}$/.test(value);
const permissions = (value: unknown): value is { read: boolean; edit: boolean } => object(value) && typeof value['read'] === 'boolean' && typeof value['edit'] === 'boolean';
const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every(item => typeof item === 'string');
const tuple = (value: Placement): string => JSON.stringify([value.resourceId, value.gatewayId, value.routeId]);
const text = (value = '', required = false) => new FormControl(value, { nonNullable: true, validators: required ? [Validators.required] : [] });
const seconds = (value: number, maximum: number) => new FormControl(value, { nonNullable: true, validators: [Validators.required, Validators.min(1), Validators.max(maximum), Validators.pattern(/^\d+$/)] });
const list = (value: string): string[] => value.split(/[\s,]+/).map(item => item.trim()).filter(Boolean);

@Component({ selector: 'agp-scoped-resource', standalone: true, imports: [ReactiveFormsModule], templateUrl: './scoped-resource.html' })
export class ScopedResource implements OnInit {
    private readonly api = inject(ConfigApi);
    private sequence = 0;
    readonly listRevision = text();
    readonly baseId = text();
    readonly resources = signal<ResourceSummary[]>([]);
    readonly listRevisionId = signal('');
    readonly nextCursor = signal('');
    readonly listBusy = signal(false);
    readonly listLoaded = signal(false);
    readonly listError = signal('');
    readonly loaded = signal<ResourceRevision | null>(null);
    readonly busy = signal(false);
    readonly dirty = signal(false);
    readonly pending = signal<PendingResource | null>(null);
    readonly conflict = signal(false);
    readonly error = signal('');
    readonly issues = signal<Issue[]>([]);
    readonly notice = signal('');
    readonly form = new FormGroup({
        name: text('', true), hostname: text('', true), path: text('', true),
        url: text('', true), connect: seconds(5, 60), read: seconds(60, 3600),
        serverName: text(), ca: text(), groups: text(), cidrs: text(), exceptions: text()
    });

    constructor() { this.form.valueChanges.subscribe(() => { if (this.loaded()) { this.sequence++; this.dirty.set(true); } }); }
    ngOnInit(): void { void this.refreshResources(); }
    placementKey(value: Placement): string { return tuple(value); }
    hasLocalChanges(): boolean { return this.dirty() || (!!this.loaded() && this.form.invalid); }
    canEdit(): boolean { const access = this.loaded()?.resourceAccess; return !!access?.read && access.edit; }
    async refreshResources(): Promise<void> { await this.loadResources(false); }
    async moreResources(): Promise<void> { if (this.nextCursor()) await this.loadResources(true); }

    private async loadResources(more: boolean): Promise<void> {
        if (this.listBusy()) return;
        this.listBusy.set(true);
        this.listError.set('');
        try {
            const revision = more ? this.listRevisionId() : this.listRevision.value;
            if (revision && !id(revision)) throw new ConfigError('invalid_id');
            const query = ['limit=50', ...(revision ? ['revisionId=' + encodeURIComponent(revision)] : []), ...(more ? ['cursor=' + encodeURIComponent(this.nextCursor())] : [])];
            const value = await this.api.get('/api/v2/config/resources?' + query.join('&'));
            if (!object(value) || !Array.isArray(value['items']) || (value['revisionId'] !== undefined && !id(value['revisionId'])) || (value['nextCursor'] !== undefined && !cursor(value['nextCursor']))) throw new ConfigError('invalid_response');
            for (const item of value['items']) {
                if (!object(item) || !id(item['resourceId']) || !id(item['gatewayId']) || !id(item['routeId']) || !['resourceName', 'routeName', 'hostname', 'path'].every(key => typeof item[key] === 'string') || !permissions(item['access']) || !item['access'].read) throw new ConfigError('invalid_response');
            }
            const page = value as unknown as ResourcePage;
            if (((page.items.length || page.nextCursor) && !page.revisionId) || (more && page.revisionId !== this.listRevisionId()) || (revision && page.revisionId && revision !== page.revisionId)) throw new ConfigError('invalid_response');
            if (new Set(page.items.map(tuple)).size !== page.items.length || (more && page.items.some(item => this.resources().some(prior => tuple(prior) === tuple(item))))) throw new ConfigError('invalid_response');
            this.resources.set(more ? [...this.resources(), ...page.items] : page.items);
            this.listRevisionId.set(page.revisionId ?? '');
            this.nextCursor.set(page.nextCursor ?? '');
            this.listLoaded.set(true);
        } catch (error) { this.listError.set(error instanceof ConfigError ? error.code : 'request_failed'); }
        finally { this.listBusy.set(false); }
    }

    async openResource(placement: Placement): Promise<void> {
        if (this.busy() || this.hasLocalChanges() || this.pending() || !this.listRevisionId()) return;
        this.busy.set(true);
        try {
            const value = await this.fetchResource(placement, this.listRevisionId());
            this.install(value);
            this.clearError();
            this.notice.set('Загружен только выбранный маршрут ресурса.');
        } catch (error) { this.fail(error); }
        finally { this.busy.set(false); }
    }

    async save(): Promise<void> {
        const loaded = this.loaded();
        if (!loaded || !this.canEdit() || this.busy() || this.pending() || !this.dirty() || this.form.invalid || this.conflict()) return;
        const placement = this.currentPlacement(loaded);
        const content = this.route(placement.routeId);
        await this.execute({ operation: mutation('/api/v2/config/revisions', { baseRevisionId: loaded.id, resourceChange: { ...placement, content } }), sequence: this.sequence, placement });
    }
    async retry(): Promise<void> { const pending = this.pending(); if (pending && !this.busy()) await this.execute(pending); }
    async useBase(): Promise<void> {
        const loaded = this.loaded();
        if (!loaded || this.pending() || this.busy()) return;
        this.busy.set(true);
        try {
            const base = await this.fetchResource(this.currentPlacement(loaded), this.baseId.value);
            this.loaded.set(base);
            this.conflict.set(false);
            this.clearError();
            this.notice.set('Base заменён явно. Локальные поля маршрута и его размещение сохранены; проверьте изменения перед записью.');
        } catch (error) { this.fail(error); }
        finally { this.busy.set(false); }
    }
    discard(): void {
        if (this.pending() || this.busy()) return;
        this.loaded.set(null);
        this.dirty.set(false);
        this.conflict.set(false);
        this.form.reset(undefined, { emitEvent: false });
        this.clearError();
        this.notice.set('Локальная форма сброшена явно.');
    }

    private async execute(pending: PendingResource): Promise<void> {
        this.busy.set(true);
        this.pending.set(pending);
        this.clearError();
        try {
            const value = this.decodeRevision(await this.api.write(pending.operation), pending.placement);
            this.pending.set(null);
            if (pending.sequence === this.sequence) this.install(value);
            else { this.loaded.set(value); this.baseId.setValue(value.id); }
            this.notice.set('Создана неизменяемая ревизия ' + value.id + '. Применение конфигурации не выполнялось.');
        } catch (error) {
            this.fail(error);
            if (error instanceof ConfigError && error.status >= 400 && error.status < 500) {
                this.pending.set(null);
                if (error.status === 412) this.conflict.set(true);
            }
        } finally { this.busy.set(false); }
    }

    private currentPlacement(value: ResourceRevision): Placement { return { resourceId: value.resourceView.resourceId, gatewayId: value.resourceView.gatewayId, routeId: value.resourceView.route.id }; }
    private async fetchResource(placement: Placement, revision: string): Promise<ResourceRevision> {
        if (![placement.resourceId, placement.gatewayId, placement.routeId, revision].every(id)) throw new ConfigError('invalid_id');
        const path = '/api/v2/config/resources/' + encodeURIComponent(placement.resourceId) + '/routes/' + encodeURIComponent(placement.gatewayId) + '/' + encodeURIComponent(placement.routeId) + '?revisionId=' + encodeURIComponent(revision);
        const value = this.decodeRevision(await this.api.get(path), placement);
        if (value.id !== revision) throw new ConfigError('resource_base_mismatch');
        return value;
    }
    private decodeRevision(value: unknown, placement: Placement): ResourceRevision {
        if (!object(value) || !id(value['id']) || typeof value['contentDigest'] !== 'string' || value['viewScope'] !== 'resource' || 'content' in value || 'gatewayView' in value || typeof value['state'] !== 'string' || typeof value['revision'] !== 'string' || !/^\d+$/.test(value['revision']) || !permissions(value['resourceAccess']) || !value['resourceAccess'].read || !object(value['resourceView'])) throw new ConfigError('invalid_response');
        const view = value['resourceView'];
        if (view['resourceId'] !== placement.resourceId || view['gatewayId'] !== placement.gatewayId || typeof view['resourceName'] !== 'string' || !object(view['route']) || view['route']['id'] !== placement.routeId) throw new ConfigError('resource_base_mismatch');
        const route = view['route'];
        if (!['name', 'hostname', 'path'].every(key => typeof route[key] === 'string') || !object(route['upstream']) || typeof route['upstream']['url'] !== 'string' || !Number.isInteger(route['upstream']['connectTimeoutSeconds']) || !Number.isInteger(route['upstream']['readTimeoutSeconds']) || !object(route['upstream']['tls']) || route['upstream']['tls']['verify'] !== true || !object(route['access']) || !strings(route['access']['groupIds']) || !strings(route['access']['allowCidrs']) || !strings(route['wafExceptionIds'])) throw new ConfigError('invalid_response');
        for (const key of ['serverName', 'caSecretVersionId']) if (route['upstream']['tls'][key] !== undefined && typeof route['upstream']['tls'][key] !== 'string') throw new ConfigError('invalid_response');
        return value as unknown as ResourceRevision;
    }
    private install(value: ResourceRevision): void {
        const route = value.resourceView.route;
        this.loaded.set(value);
        this.baseId.setValue(value.id);
        this.form.setValue({ name: route.name, hostname: route.hostname, path: route.path, url: route.upstream.url, connect: route.upstream.connectTimeoutSeconds, read: route.upstream.readTimeoutSeconds, serverName: route.upstream.tls.serverName ?? '', ca: route.upstream.tls.caSecretVersionId ?? '', groups: route.access.groupIds.join('\n'), cidrs: route.access.allowCidrs.join('\n'), exceptions: route.wafExceptionIds.join('\n') }, { emitEvent: false });
        this.dirty.set(false);
        this.conflict.set(false);
    }
    private route(routeId: string): Route {
        const value = this.form.getRawValue();
        return { id: routeId, name: value.name, hostname: value.hostname, path: value.path, upstream: { url: value.url, connectTimeoutSeconds: value.connect, readTimeoutSeconds: value.read, tls: { verify: true, ...(value.serverName ? { serverName: value.serverName } : {}), ...(value.ca ? { caSecretVersionId: value.ca } : {}) } }, access: { groupIds: list(value.groups), allowCidrs: list(value.cidrs) }, wafExceptionIds: list(value.exceptions) };
    }
    download(): void {
        const loaded = this.loaded();
        if (!loaded) return;
        const value = this.form.invalid ? { ...this.currentPlacement(loaded), localFields: this.form.getRawValue() } : this.route(loaded.resourceView.route.id);
        const link = document.createElement('a');
        link.href = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }));
        link.download = 'agp-resource-route-local.json';
        link.click();
        setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    }
    @HostListener('window:beforeunload', ['$event'])
    beforeUnload(event: BeforeUnloadEvent): void { if (this.loaded() && (this.dirty() || this.pending() || this.form.invalid)) { event.preventDefault(); event.returnValue = ''; } }
    private clearError(): void { this.error.set(''); this.issues.set([]); }
    private fail(error: unknown): void { this.error.set(error instanceof ConfigError ? error.code : 'request_failed'); this.issues.set(error instanceof ConfigError ? error.issues : []); }
}
