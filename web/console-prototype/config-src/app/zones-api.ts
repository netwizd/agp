import { Injectable, inject } from '@angular/core';
import { ConfigApi, ConfigError, Mutation } from './config-api';
import { Issue } from './contracts';
export interface WafZone {
    apiVersion: 'agp.waf-zone/v1alpha1';
    kind: 'WafZone';
    metadata: {
        id: string;
        name: string;
        siteId: string;
        ownerId: string;
    };
    spec: {
        policyRevisionId: string;
        mode: 'detection' | 'blocking';
        membership: {
            gatewayIds: string[];
        } | {
            matchLabels: Record<string, string>;
        } | {
            siteDefault: true;
        };
        reason: string;
    };
}
export interface ZoneRevision {
    id: string;
    baseRevisionId?: string;
    zoneId: string;
    siteId: string;
    ownerId: string;
    contentDigest: string;
    content?: WafZone;
    state: 'draft' | 'validated' | 'approved' | 'published' | 'superseded';
    revision: string;
}
export interface ZonePage {
    items: ZoneRevision[];
    nextCursor?: string;
}
export interface ZoneMember {
    gatewayId: string;
    routeIds: string[];
    nodeIds: string[];
    sourceZoneRevisionId?: string;
    targetZoneRevisionId?: string;
    sourcePolicyRevisionId: string;
    targetPolicyRevisionId?: string;
    baseBindingDigest: string;
    targetBindingDigest?: string;
    disposition: 'inherited' | 'derived' | 'conflict';
}
export interface ZoneConflict {
    gatewayId: string;
    code: string;
    path: string;
    message: string;
    candidateZoneRevisionIds?: string[];
}
export interface ZonePreview {
    id: string;
    purpose: 'authoring_preview';
    authorId: string;
    zoneRevisionId: string;
    siteId: string;
    baseRevisionId: string;
    configDigest: string;
    catalogSnapshotId: string;
    catalogDigest: string;
    resolverDigest: string;
    inventoryDigest: string;
    capacityProfile: 'pilot-500' | 'fleet-10k';
    action: 'reconcile' | 'retire';
    assignmentSource: 'hypothetical_authoring_membership';
    previewDigest: string;
    createdAt: string;
    expiresAt: string;
    authoringValid: boolean;
    deployable: false;
    members: ZoneMember[];
    conflicts: ZoneConflict[];
    issues: Issue[];
    pins: {
        zoneRevisionId: string;
        zoneId: string;
        contentDigest: string;
    }[];
}
export interface AuthoringReview {
    id: string;
    purpose: 'draft_review';
    previewId: string;
    previewDigest: string;
    authorId: string;
    reviewerId: string;
    createdAt: string;
    expiresAt: string;
    status?: 'current' | 'stale';
}
export interface ZonePreviewRequest {
    baseRevisionId: string;
    catalogSnapshotId: string;
    capacityProfile: 'pilot-500' | 'fleet-10k';
    action: 'reconcile' | 'retire';
    replacementAssignments?: {
        gatewayId: string;
        targetZoneRevisionId: string;
    }[];
}
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const id = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
@Injectable({ providedIn: 'root' })
export class ZonesApi {
    private api = inject(ConfigApi);
    async list(siteId: string, cursor = ''): Promise<ZonePage> {
        const parameters = new URLSearchParams({ limit: '25' });
        if (siteId)
            parameters.set('siteId', siteId);
        if (cursor)
            parameters.set('cursor', cursor);
        const value = await this.api.get('/api/v2/waf/authoring-zones?' + parameters.toString());
        if (!object(value) || !Array.isArray(value['items']))
            throw new ConfigError('invalid_response');
        return value as unknown as ZonePage;
    }
    async revision(value: string): Promise<ZoneRevision> { return this.decodeRevision(await this.api.get(this.path('zone-revisions', value))); }
    async preview(value: string): Promise<ZonePreview> { return this.decodePreview(await this.api.get(this.path('zone-previews', value))); }
    async reviews(value: string): Promise<AuthoringReview[]> { const result = await this.api.get(this.path('zone-previews', value) + '/authoring-reviews'); if (!object(result) || !Array.isArray(result['items']))
        throw new ConfigError('invalid_response'); return result['items'] as AuthoringReview[]; }
    decodeReview(value: unknown): AuthoringReview { if (!object(value) || !id(value['id']) || value['purpose'] !== 'draft_review' || !id(value['reviewerId']) || !id(value['authorId']) || value['reviewerId'] === value['authorId'])
        throw new ConfigError('invalid_response'); return value as unknown as AuthoringReview; }
    async write(operation: Mutation): Promise<unknown> { return this.api.write(operation); }
    path(kind: 'zone-revisions' | 'zone-previews', value: string): string { if (!id(value))
        throw new ConfigError('invalid_id'); return `/api/v2/waf/${kind}/${encodeURIComponent(value)}`; }
    decodeRevision(value: unknown): ZoneRevision {
        if (!object(value) || !id(value['id']) || typeof value['contentDigest'] !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(value['contentDigest']) || !['draft','validated','approved','published','superseded'].includes(String(value['state'])) || typeof value['revision'] !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value['revision']) || !object(value['content']) || !object(value['content']['metadata']))
            throw new ConfigError('invalid_response');
        const metadata = value['content']['metadata'];
        if (!id(metadata['id']) || !id(metadata['siteId']) || !id(metadata['ownerId'])) throw new ConfigError('invalid_response');
        // The closed transport is WafZoneRevision's five fields. Metadata below
        // is a client view derived from the canonical body, never extra wire fields.
        return {id:value['id'],content:value['content'] as unknown as WafZone,contentDigest:value['contentDigest'],state:value['state'] as ZoneRevision['state'],revision:value['revision'],zoneId:metadata['id'],siteId:metadata['siteId'],ownerId:metadata['ownerId']};
    }
    decodePreview(value: unknown): ZonePreview {
        if (!object(value) || !id(value['id']) || value['purpose'] !== 'authoring_preview' || value['deployable'] !== false || typeof value['authoringValid'] !== 'boolean' || !Array.isArray(value['members']) || !Array.isArray(value['conflicts']) || !Array.isArray(value['issues']) || typeof value['previewDigest'] !== 'string' || typeof value['expiresAt'] !== 'string' || !id(value['authorId']) || !id(value['siteId']) || !Array.isArray(value['pins']) || value['assignmentSource'] !== 'hypothetical_authoring_membership')
            throw new ConfigError('invalid_response');
        return value as unknown as ZonePreview;
    }
}
