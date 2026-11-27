import { Injectable } from '@angular/core';
import { AcceptedOperation, CatalogSnapshot, Configuration, DocumentFormat, Draft, Me, ParsedDocument, Profile, Report, Revision, RevisionPage, Runtime, Issue, ConfigAccess } from './contracts';
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const id = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
export class ConfigError extends Error {
    constructor(readonly code: string, readonly status = 0, readonly issues: Issue[] = []) { super(code); }
}
export interface Mutation {
    path: string;
    method: 'POST' | 'PUT';
    body: string;
    key: string;
    version?: string;
}
export const mutation = (path: string, body: unknown, version?: string, method: 'POST' | 'PUT' = 'POST'): Mutation => ({ path, body: JSON.stringify(body), key: `ui_${crypto.randomUUID().replaceAll('-', '')}`, method, ...(version === undefined ? {} : { version }) });
@Injectable({ providedIn: 'root' })
export class ConfigApi {
    private runtimeValue: Runtime | null = null;
    async bootstrap(): Promise<{
        runtime: Runtime;
        me: Me;
        access: ConfigAccess;
    }> {
        const value = await this.request('/api/v1/public/runtime');
        if (!object(value) || value['mode'] !== 'management' || value['secure_profile'] !== true || typeof value['csrf_cookie_name'] !== 'string' || !/^[-A-Za-z0-9_]{1,128}$/.test(value['csrf_cookie_name']))
            throw new ConfigError('management_required');
        this.runtimeValue = value as unknown as Runtime;
        const me = await this.request('/api/v1/me');
        if (!object(me) || !object(me['user']) || typeof me['user']['is_admin'] !== 'boolean' || typeof me['user']['username'] !== 'string')
            throw new ConfigError('invalid_response');
        const access = await this.access();
        if (!access.globalRead && !access.gatewayRead && !access.gatewayEdit && !access.resourceRead && !access.resourceEdit && !access.sites.some(site => site.read)) throw new ConfigError('permission_required', 403);
        return { runtime: this.runtimeValue, me: me as unknown as Me, access };
    }
    async access(): Promise<ConfigAccess> {
        const value = await this.request('/api/v2/config/access');
        if (!object(value) || !id(value['principalId']) || typeof value['globalRead'] !== 'boolean' || typeof value['globalEdit'] !== 'boolean' || (value['globalApprove'] !== undefined && typeof value['globalApprove'] !== 'boolean') || (value['gatewayRead'] !== undefined && typeof value['gatewayRead'] !== 'boolean') || (value['gatewayEdit'] !== undefined && typeof value['gatewayEdit'] !== 'boolean') || (value['resourceRead'] !== undefined && typeof value['resourceRead'] !== 'boolean') || (value['resourceEdit'] !== undefined && typeof value['resourceEdit'] !== 'boolean') || typeof value['authorityEpoch'] !== 'string' || !Array.isArray(value['sites'])) throw new ConfigError('invalid_response');
        for (const site of value['sites']) if (!object(site) || !id(site['siteId']) || typeof site['read'] !== 'boolean' || typeof site['edit'] !== 'boolean' || (site['approve'] !== undefined && typeof site['approve'] !== 'boolean')) throw new ConfigError('invalid_response');
        return value as unknown as ConfigAccess;
    }
    async get(path: string): Promise<unknown> {
        if (!/^\/api\/v2\/[A-Za-z0-9/_-]+(?:\?[A-Za-z0-9_%=&-]*)?$/.test(path)) throw new ConfigError('invalid_path');
        return this.request(path);
    }
    async profile(): Promise<Profile> { const value = await this.request('/api/v2/config/profile'); if (!object(value) || typeof value['enabled'] !== 'boolean')
        throw new ConfigError('invalid_response'); return value as unknown as Profile; }
    async revisions(cursor = ''): Promise<RevisionPage> { const value = await this.request('/api/v2/config/revisions' + (cursor ? '?cursor=' + encodeURIComponent(cursor) : '')); if (!object(value) || !Array.isArray(value['items']))
        throw new ConfigError('invalid_response'); return value as unknown as RevisionPage; }
    async revision(value: string): Promise<Revision> { return this.decodeSnapshot(await this.request(this.path('revisions', value))) as Revision; }
    async draft(value: string): Promise<Draft> { return this.decodeSnapshot(await this.request(this.path('drafts', value))) as Draft; }
    async catalogs(): Promise<CatalogSnapshot[]> { const value = await this.request('/api/v2/config/catalog-snapshots'); if (!object(value) || !Array.isArray(value['items']))
        throw new ConfigError('invalid_response'); return value['items'] as CatalogSnapshot[]; }
    async parse(document: string, format: DocumentFormat): Promise<ParsedDocument> { return this.write(mutation('/api/v2/config/documents', { format, document })) as Promise<ParsedDocument>; }
    async preview(draftId: string, catalogSnapshotId: string): Promise<Report> { return this.decodeReport(await this.write(mutation(this.path('drafts', draftId) + '/previews', catalogSnapshotId ? { catalogSnapshotId } : {}))); }
    async validate(revisionId: string): Promise<Report> {
        const accepted = await this.write(mutation(this.path('revisions', revisionId) + '/validations', {})) as AcceptedOperation;
        if (!object(accepted) || typeof accepted.statusUrl !== 'string' || !/^\/api\/v2\/config\/[A-Za-z0-9/_-]+$/.test(accepted.statusUrl))
            throw new ConfigError('invalid_response');
        return this.decodeReport(await this.request(accepted.statusUrl));
    }
    async importCatalog(document: string, format: DocumentFormat): Promise<CatalogSnapshot> { return this.write(mutation('/api/v2/config/catalog-snapshots', { format, document })) as Promise<CatalogSnapshot>; }
    async write(operation: Mutation): Promise<unknown> { return this.request(operation.path, operation); }
    private decodeReport(value: unknown): Report {
        if (!object(value) || !id(value['id']) || !['draft', 'revision'].includes(String(value['targetKind'])) || !id(value['targetId']) || typeof value['targetRevision'] !== 'string' || typeof value['configDigest'] !== 'string' || typeof value['compilerDigest'] !== 'string' || typeof value['authoringValid'] !== 'boolean' || value['deployable'] !== false || !Array.isArray(value['issues']) || !Array.isArray(value['diff']))
            throw new ConfigError('invalid_response');
        const preview = value['preview'];
        if (preview !== undefined) {
            if (!object(preview) || !Array.isArray(preview['bundles']) || !Array.isArray(preview['resolvedInputs']) || typeof preview['previewDigest'] !== 'string')
                throw new ConfigError('invalid_response');
            for (const bundle of preview['bundles'])
                if (!object(bundle) || !id(bundle['nodeId']) || !Array.isArray(bundle['routes']) || !Array.isArray(bundle['gatewayIds']) || !Array.isArray(bundle['secretVersionIds']) || !Array.isArray(bundle['resolvedInputs']) || !Array.isArray(bundle['artifacts']))
                    throw new ConfigError('invalid_response');
        }
        return value as unknown as Report;
    }
    decodeSnapshot(value: unknown): Draft | Revision {
        if (!object(value) || !id(value['id']) || typeof value['revision'] !== 'string' || !/^\d+$/.test(value['revision']) || typeof value['contentDigest'] !== 'string' || !object(value['content']) || !Array.isArray(value['content']['gateways']) || !object(value['content']['metadata']))
            throw new ConfigError('invalid_response');
        return value as unknown as Draft | Revision;
    }
    path(kind: 'drafts' | 'revisions', value: string): string { if (!id(value))
        throw new ConfigError('invalid_id'); return `/api/v2/config/${kind}/${encodeURIComponent(value)}`; }
    private csrf(): string {
        if (!this.runtimeValue)
            throw new ConfigError('bootstrap_required');
        const name = this.runtimeValue.csrf_cookie_name;
        const values = document.cookie.split(';').map(part => part.trim()).filter(part => part.startsWith(name + '='));
        if (values.length !== 1)
            throw new ConfigError('csrf_required', 401);
        let token = '';
        try {
            token = decodeURIComponent(values[0].slice(name.length + 1));
        }
        catch {
            throw new ConfigError('csrf_required', 401);
        }
        if (!/^[A-Za-z0-9_-]{32,256}$/.test(token))
            throw new ConfigError('csrf_required', 401);
        return token;
    }
    private async request(path: string, operation?: Mutation): Promise<unknown> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 15000);
        try {
            const headers: Record<string, string> = { Accept: 'application/json' };
            if (operation) {
                headers['Content-Type'] = 'application/json';
                headers['X-CSRF-Token'] = this.csrf();
                headers['Idempotency-Key'] = operation.key;
                if (operation.version !== undefined)
                    headers['If-Match'] = `"${operation.version}"`;
            }
            const response = await fetch(path, { method: operation?.method ?? 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers, signal: controller.signal, ...(operation ? { body: operation.body } : {}) });
            if (response.status === 204) return undefined;
            let value: unknown;
            try {
                value = await response.json();
            }
            catch {
                throw new ConfigError('invalid_response', response.status);
            }
            if (!response.ok)
                throw new ConfigError(object(value) && typeof value['code'] === 'string' ? value['code'] : object(value) && typeof value['error'] === 'string' ? value['error'] : 'request_failed', response.status, object(value) && Array.isArray(value['issues']) ? value['issues'] as Issue[] : []);
            return value;
        }
        catch (error: unknown) {
            if (error instanceof ConfigError)
                throw error;
            throw new ConfigError(controller.signal.aborted ? 'request_timeout' : 'network_error');
        }
        finally {
            clearTimeout(timer);
        }
    }
}
