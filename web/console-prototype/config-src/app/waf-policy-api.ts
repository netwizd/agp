import { Injectable, inject } from '@angular/core';
import { ConfigApi, ConfigError, Mutation } from './config-api';
import { AcceptedOperation, Issue } from './contracts';
export interface WafPolicy {
    apiVersion: 'agp.waf/v1alpha1';
    kind: 'WafPolicy';
    metadata: {
        id: string;
        name: string;
        siteId: string;
    };
    spec: {
        engine: 'modsecurity';
        rulesetVersionId: string;
        paranoiaLevel: number;
        inboundAnomalyThreshold: number;
        outboundAnomalyThreshold: number;
        exceptions: [
        ];
    };
}
export interface WafPolicyRevision {
    id: string;
    content: WafPolicy;
    contentDigest: string;
    state: 'draft' | 'validated' | 'approved' | 'published' | 'superseded';
    revision: string;
}
export interface WafQualification {
    id: string;
    contentDigest: string;
    rulesetVersionId: string;
    rulesetDigest: string;
    profileId: string;
    profileDigest: string;
    tupleDigest: string;
    evidenceDigest: string;
    manifestDigest: string;
    releaseSequence: string;
    compilerDigest: string;
    expiresAt: string;
}
export interface WafPolicyValidation {
    id: string;
    policyRevisionId: string;
    contentDigest: string;
    qualification: WafQualification | null;
    qualificationDigest: string;
    valid: boolean;
    current: boolean;
    deployable: false;
    issues: Issue[];
    createdAt: string;
    expiresAt: string;
}
export interface WafPolicyApproval {
    approvalId: string;
    contentDigest: string;
}
export interface WafPolicyOperation {
    id: string;
    resourceId: string;
    state: string;
    createdAt: string;
    updatedAt: string;
}
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const id = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const digest = (value: unknown): value is string => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const utc = (value: unknown): value is string => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value) && Number.isFinite(Date.parse(value));
@Injectable({ providedIn: 'root' })
export class WafPolicyApi {
    private api = inject(ConfigApi);
    path(value: string, suffix = ''): string { if (!id(value))
        throw new ConfigError('invalid_id'); return `/api/v2/waf/policy-revisions/${encodeURIComponent(value)}${suffix ? '/' + suffix : ''}`; }
    async revision(value: string): Promise<WafPolicyRevision> { return this.decodeRevision(await this.api.get(this.path(value))); }
    async validation(value: string): Promise<WafPolicyValidation> { if (!id(value))
        throw new ConfigError('invalid_id'); return this.decodeValidation(await this.api.get('/api/v2/waf/validations/' + encodeURIComponent(value))); }
    async write(operation: Mutation): Promise<unknown> { return this.api.write(operation); }
    decodeRevision(value: unknown): WafPolicyRevision {
        if (!object(value) || !id(value['id']) || !digest(value['contentDigest']) || typeof value['revision'] !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value['revision']) || !['draft', 'validated', 'approved', 'published', 'superseded'].includes(String(value['state'])) || !object(value['content']))
            throw new ConfigError('invalid_response');
        const body = value['content'];
        if (body['apiVersion'] !== 'agp.waf/v1alpha1' || body['kind'] !== 'WafPolicy' || !object(body['metadata']) || !id(body['metadata']['id']) || !id(body['metadata']['siteId']) || typeof body['metadata']['name'] !== 'string' || !object(body['spec']) || body['spec']['engine'] !== 'modsecurity' || !id(body['spec']['rulesetVersionId']) || !Array.isArray(body['spec']['exceptions']))
            throw new ConfigError('invalid_response');
        for (const key of ['paranoiaLevel', 'inboundAnomalyThreshold', 'outboundAnomalyThreshold'])
            if (typeof body['spec'][key] !== 'number' || !Number.isInteger(body['spec'][key]))
                throw new ConfigError('invalid_response');
        if (body['spec']['exceptions'].length)
            throw new ConfigError('unsupported_exceptions');
        return value as unknown as WafPolicyRevision;
    }
    decodeApproval(value: unknown): WafPolicyApproval { if (!object(value) || !id(value['approvalId']) || !digest(value['contentDigest']))
        throw new ConfigError('invalid_response'); return value as unknown as WafPolicyApproval; }
    decodeValidation(value: unknown): WafPolicyValidation {
        if (!object(value) || !id(value['id']) || !id(value['policyRevisionId']) || !digest(value['contentDigest']) || typeof value['valid'] !== 'boolean' || typeof value['current'] !== 'boolean' || value['deployable'] !== false || !Array.isArray(value['issues']) || !utc(value['createdAt']) || !utc(value['expiresAt']))
            throw new ConfigError('invalid_response');
        const qualification = value['qualification'];
        if (value['valid'] && !object(qualification)) throw new ConfigError('invalid_response');
        if (qualification !== null) {
            if (!object(qualification) || !id(qualification['id']) || !id(qualification['rulesetVersionId']) || !id(qualification['profileId']) || !utc(qualification['expiresAt']))
                throw new ConfigError('invalid_response');
            for (const key of ['contentDigest', 'rulesetDigest', 'profileDigest', 'tupleDigest', 'evidenceDigest', 'manifestDigest', 'compilerDigest'])
                if (!digest(qualification[key]))
                    throw new ConfigError('invalid_response');
            if (typeof qualification['releaseSequence'] !== 'string' || !/^([1-9][0-9]{0,18})$/.test(qualification['releaseSequence']) || BigInt(qualification['releaseSequence']) > 9223372036854775807n || qualification['contentDigest'] !== value['contentDigest'] || !digest(value['qualificationDigest']))
                throw new ConfigError('invalid_response');
        }
        return value as unknown as WafPolicyValidation;
    }
    async follow(value: unknown, onOperation: (id: string) => void): Promise<WafPolicyValidation> {
        if (!object(value) || !id(value['operationId']) || !id(value['resourceId']) || typeof value['statusUrl'] !== 'string' || value['statusUrl'] !== `/api/v2/operations/${value['operationId']}`)
            throw new ConfigError('invalid_response');
        const accepted = value as unknown as AcceptedOperation;
        onOperation(accepted.operationId);
        for (let attempt = 0; attempt < 120; attempt++) {
            const operation = await this.api.get(accepted.statusUrl);
            if (!object(operation) || operation['id'] !== accepted.operationId || !id(operation['resourceId']) || typeof operation['state'] !== 'string')
                throw new ConfigError('invalid_response');
            if (operation['state'] === 'succeeded') {
                if (operation['resourceId'] !== accepted.resourceId)
                    throw new ConfigError('invalid_response');
                return this.validation(operation['resourceId']);
            }
            if (!['queued', 'pending', 'running'].includes(operation['state']))
                throw new ConfigError('validation_failed');
            await new Promise(resolve => setTimeout(resolve, 500));
        }
        throw new ConfigError('operation_timeout');
    }
}
