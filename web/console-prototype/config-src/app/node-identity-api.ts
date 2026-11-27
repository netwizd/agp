import { Injectable, inject } from '@angular/core';
import { ConfigApi, ConfigError, Mutation } from './config-api';

export interface ManagedNode {
    id: string;
    siteId: string;
    name: string;
    labels: Record<string, string>;
    connectivity: 'unknown' | 'online' | 'offline';
    maintenance: boolean;
    identityState: 'pending' | 'active' | 'expired' | 'revoked';
    revision: string;
}
export interface EnrollmentToken {
    enrollmentId: string;
    tokenAvailable: boolean;
    token?: string;
    expiresAt: string;
}
export interface PendingEnrollment {
    id: string;
    enrollmentId: string;
    nodeId: string;
    state: 'issued' | 'csr_pending' | 'approved' | 'issued_certificate' | 'revoked';
    publicKeyDigest: string;
    requestDigest: string;
    expiresAt: string;
}
export interface NodeIdentityOperation { id: string; nodeId: string; kind: 'revoke_node'; state: 'completed'; }
export const nodeIdentifier = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const utc = (value: unknown): value is string => typeof value === 'string' && value.length <= 40 && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value) && Number.isFinite(Date.parse(value));
const digest = (value: unknown): value is string => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const boundedText = (value: unknown, max: number, required = false): value is string => typeof value === 'string' && (!required || value.length > 0) && new TextEncoder().encode(value).length <= max && !/[\u0000\r\n]/.test(value);
export function nodeLabels(value: unknown): value is Record<string, string> {
    return object(value) && Object.keys(value).length <= 32 && Object.entries(value).every(([key, item]) => /^[a-z][a-z0-9_.-]{0,62}$/.test(key) && boundedText(item, 128));
}
@Injectable({ providedIn: 'root' })
export class NodeIdentityApi {
    private readonly api = inject(ConfigApi);
    async enabled(): Promise<boolean> {
        let value: unknown;
        try { value = await this.api.get('/api/v2/node-identity-profile'); }
        catch (error) { if (error instanceof ConfigError && error.status === 404) return false; throw error; }
        if (!object(value) || typeof value['enabled'] !== 'boolean' || !Array.isArray(value['supportedRoles']) || value['supportedRoles'].length !== 1 || value['supportedRoles'][0] !== 'agent') throw new ConfigError('invalid_response');
        return value['enabled'];
    }
    async nodes(cursor = ''): Promise<{ items: ManagedNode[]; nextCursor: string }> {
        if (cursor && !/^[A-Za-z0-9_-]{1,171}$/.test(cursor)) throw new ConfigError('invalid_cursor');
        const value = await this.api.get('/api/v2/nodes?limit=50' + (cursor ? '&cursor=' + encodeURIComponent(cursor) : ''));
        if (!object(value) || !Array.isArray(value['items']) || value['items'].length > 50 || (value['nextCursor'] !== undefined && (typeof value['nextCursor'] !== 'string' || !/^[A-Za-z0-9_-]{1,171}$/.test(value['nextCursor']) || value['nextCursor'] === cursor))) throw new ConfigError('invalid_response');
        const items = value['items'].map(item => this.decodeNode(item));
        if (new Set(items.map(item => item.id)).size !== items.length) throw new ConfigError('invalid_response');
        return { items, nextCursor: value['nextCursor'] as string || '' };
    }
    nodePath(nodeId: string): string {
        if (!nodeIdentifier(nodeId)) throw new ConfigError('invalid_node_id');
        return '/api/v2/nodes/' + encodeURIComponent(nodeId);
    }
    enrollmentPath(nodeId: string, enrollmentId: string): string {
        if (!nodeIdentifier(enrollmentId)) throw new ConfigError('invalid_enrollment_id');
        return this.nodePath(nodeId) + '/enrollments/' + encodeURIComponent(enrollmentId);
    }
    write(operation: Mutation): Promise<unknown> { return this.api.write(operation); }
    decodeNode(value: unknown): ManagedNode {
        if (!object(value) || !nodeIdentifier(value['id']) || !nodeIdentifier(value['siteId']) || !boundedText(value['name'], 128, true) || !nodeLabels(value['labels']) || !['unknown', 'online', 'offline'].includes(String(value['connectivity'])) || typeof value['maintenance'] !== 'boolean' || !['pending', 'active', 'expired', 'revoked'].includes(String(value['identityState'])) || typeof value['revision'] !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value['revision']) || BigInt(value['revision']) > 9223372036854775807n) throw new ConfigError('invalid_response');
        return value as unknown as ManagedNode;
    }
    decodeToken(value: unknown): EnrollmentToken {
        if (!object(value) || !nodeIdentifier(value['enrollmentId']) || typeof value['tokenAvailable'] !== 'boolean' || !utc(value['expiresAt']) || (value['tokenAvailable'] ? typeof value['token'] !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value['token']) : value['token'] !== undefined)) throw new ConfigError('invalid_response');
        return value as unknown as EnrollmentToken;
    }
    decodePending(value: unknown, nodeId: string, enrollmentId: string): PendingEnrollment {
        if (!object(value) || value['id'] !== enrollmentId || value['enrollmentId'] !== enrollmentId || value['nodeId'] !== nodeId || !['issued', 'csr_pending', 'approved', 'issued_certificate', 'revoked'].includes(String(value['state'])) || !utc(value['expiresAt'])) throw new ConfigError('invalid_response');
        const hasRequest = ['csr_pending', 'approved', 'issued_certificate'].includes(String(value['state']));
        if (hasRequest ? !digest(value['publicKeyDigest']) || !digest(value['requestDigest']) : !(value['publicKeyDigest'] === '' || digest(value['publicKeyDigest'])) || !(value['requestDigest'] === '' || digest(value['requestDigest']))) throw new ConfigError('invalid_response');
        return value as unknown as PendingEnrollment;
    }
    async pending(nodeId: string, enrollmentId: string): Promise<PendingEnrollment> {
        return this.decodePending(await this.api.get(this.enrollmentPath(nodeId, enrollmentId)), nodeId, enrollmentId);
    }
    async followRevocation(value: unknown, nodeId: string): Promise<NodeIdentityOperation> {
        if (!object(value) || !nodeIdentifier(value['operationId']) || value['resourceId'] !== nodeId || value['statusUrl'] !== '/api/v2/node-identity-operations/' + value['operationId'] || !utc(value['submittedAt'])) throw new ConfigError('invalid_response');
        const operation = await this.api.get('/api/v2/node-identity-operations/' + value['operationId']);
        if (!object(operation) || operation['id'] !== value['operationId'] || operation['nodeId'] !== nodeId || operation['kind'] !== 'revoke_node' || operation['state'] !== 'completed') throw new ConfigError('invalid_response');
        return operation as unknown as NodeIdentityOperation;
    }
}
