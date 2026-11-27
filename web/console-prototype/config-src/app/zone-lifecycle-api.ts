import { Injectable, inject } from '@angular/core';
import { ConfigApi, ConfigError, Mutation } from './config-api';
import { Issue } from './contracts';
import { WafQualification } from './waf-policy-api';
import { ZoneConflict, ZoneMember } from './zones-api';

export interface ZoneValidation {
    id: string;
    zoneRevisionId: string;
    contentDigest: string;
    policyRevisionId: string;
    policyPublicationId: string;
    qualification: WafQualification | null;
    dependencyDigest: string;
    valid: boolean;
    current: boolean;
    deployable: false;
    issues: Issue[];
    createdAt: string;
    expiresAt: string;
}
export interface ZoneResolution {
    apiVersion: 'agp.waf-zone-resolution/v1alpha1';
    kind: 'WafZoneResolution';
    id: string;
    siteId: string;
    zoneRevisionId: string;
    baseConfigRevisionId: string;
    action: 'reconcile' | 'retire';
    inventoryDigest: string;
    capacityProfile: 'pilot-500' | 'fleet-10k';
    createdAt: string;
    expiresAt: string;
    resolutionDigest: string;
    members: ZoneMember[];
    conflicts: ZoneConflict[];
}
export interface ZoneChangeRequest {
    apiVersion: 'agp.waf-zone-change/v1alpha1';
    kind: 'WafZoneChange';
    baseRevisionId: string;
    zoneRevisionId: string;
    resolutionId: string;
    resolutionDigest: string;
    reason: string;
}
export interface ZoneChange {
    id: string;
    request: ZoneChangeRequest;
    requestDigest: string;
    state: 'pending' | 'materialized' | 'failed';
    resultRevisionId: string | null;
    revision: string;
}
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const id = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const digest = (value: unknown): value is string => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const utc = (value: unknown): value is string => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value) && Number.isFinite(Date.parse(value));
@Injectable({ providedIn: 'root' })
export class ZoneLifecycleApi {
    private readonly api = inject(ConfigApi);
    path(kind: 'zone-revisions' | 'zone-validations' | 'zone-resolutions' | 'zone-changes', value: string, suffix = ''): string {
        if (!id(value) || (suffix && !['validations', 'approvals', 'publications', 'resolutions'].includes(suffix))) throw new ConfigError('invalid_id');
        return `/api/v2/waf/${kind}/${encodeURIComponent(value)}${suffix ? '/' + suffix : ''}`;
    }
    write(operation: Mutation): Promise<unknown> { return this.api.write(operation); }
    async validation(value: string): Promise<ZoneValidation> { return this.decodeValidation(await this.api.get(this.path('zone-validations', value))); }
    async resolution(value: string): Promise<ZoneResolution> { return this.decodeResolution(await this.api.get(this.path('zone-resolutions', value))); }
    async change(value: string): Promise<ZoneChange> { return this.decodeChange(await this.api.get(this.path('zone-changes', value))); }
    decodeValidation(value: unknown): ZoneValidation {
        if (!object(value) || !id(value['id']) || !id(value['zoneRevisionId']) || !digest(value['contentDigest']) || !id(value['policyRevisionId']) || typeof value['policyPublicationId'] !== 'string' || typeof value['valid'] !== 'boolean' || typeof value['current'] !== 'boolean' || value['deployable'] !== false || !Array.isArray(value['issues']) || !utc(value['createdAt']) || !utc(value['expiresAt'])) throw new ConfigError('invalid_response');
        const proof = value['qualification'];
        if (value['valid'] && (!object(proof) || !digest(value['dependencyDigest']) || !id(value['policyPublicationId']))) throw new ConfigError('invalid_response');
        if (proof !== null) {
            if (!object(proof) || !id(proof['id']) || !id(proof['rulesetVersionId']) || !id(proof['profileId']) || !utc(proof['expiresAt']) || typeof proof['releaseSequence'] !== 'string' || !/^[1-9][0-9]{0,18}$/.test(proof['releaseSequence']) || BigInt(proof['releaseSequence']) > 9223372036854775807n) throw new ConfigError('invalid_response');
            for (const key of ['contentDigest', 'rulesetDigest', 'profileDigest', 'tupleDigest', 'evidenceDigest', 'manifestDigest', 'compilerDigest']) if (!digest(proof[key])) throw new ConfigError('invalid_response');
        }
        return value as unknown as ZoneValidation;
    }
    decodeResolution(value: unknown): ZoneResolution {
        if (!object(value) || value['apiVersion'] !== 'agp.waf-zone-resolution/v1alpha1' || value['kind'] !== 'WafZoneResolution' || !id(value['id']) || !id(value['siteId']) || !id(value['zoneRevisionId']) || !id(value['baseConfigRevisionId']) || !digest(value['inventoryDigest']) || !digest(value['resolutionDigest']) || !utc(value['createdAt']) || !utc(value['expiresAt']) || !['reconcile', 'retire'].includes(String(value['action'])) || !['pilot-500', 'fleet-10k'].includes(String(value['capacityProfile'])) || !Array.isArray(value['members']) || !Array.isArray(value['conflicts'])) throw new ConfigError('invalid_response');
        for (const member of value['members']) {
            if (!object(member) || !id(member['gatewayId']) || !Array.isArray(member['nodeIds']) || !member['nodeIds'].every(id) || !Array.isArray(member['routeIds']) || !member['routeIds'].every(id) || !id(member['sourcePolicyRevisionId']) || !digest(member['baseBindingDigest']) || !['inherited', 'derived', 'conflict'].includes(String(member['disposition']))) throw new ConfigError('invalid_response');
            if (member['disposition'] !== 'conflict' && (!member['nodeIds'].length || !id(member['targetZoneRevisionId']) || !id(member['targetPolicyRevisionId']) || !digest(member['targetBindingDigest']))) throw new ConfigError('invalid_response');
        }
        for (const conflict of value['conflicts']) if (!object(conflict) || !id(conflict['gatewayId']) || typeof conflict['code'] !== 'string' || typeof conflict['path'] !== 'string' || typeof conflict['message'] !== 'string') throw new ConfigError('invalid_response');
        return value as unknown as ZoneResolution;
    }
    decodeApproval(value: unknown): { approvalId: string; contentDigest: string } {
        if (!object(value) || !id(value['approvalId']) || !digest(value['contentDigest'])) throw new ConfigError('invalid_response');
        return value as { approvalId: string; contentDigest: string };
    }
    decodeChange(value: unknown): ZoneChange {
        if (!object(value) || !id(value['id']) || !object(value['request']) || !digest(value['requestDigest']) || !['pending', 'materialized', 'failed'].includes(String(value['state'])) || !(value['resultRevisionId'] === null || id(value['resultRevisionId'])) || typeof value['revision'] !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value['revision'])) throw new ConfigError('invalid_response');
        const request = value['request'];
        if (request['apiVersion'] !== 'agp.waf-zone-change/v1alpha1' || request['kind'] !== 'WafZoneChange' || !id(request['baseRevisionId']) || !id(request['zoneRevisionId']) || !id(request['resolutionId']) || !digest(request['resolutionDigest']) || typeof request['reason'] !== 'string' || (value['state'] === 'materialized' && !id(value['resultRevisionId']))) throw new ConfigError('invalid_response');
        return value as unknown as ZoneChange;
    }
    async follow(value: unknown, onOperation: (id: string) => void): Promise<string> {
        if (!object(value) || !id(value['operationId']) || !id(value['resourceId']) || value['statusUrl'] !== `/api/v2/operations/${value['operationId']}` || !utc(value['submittedAt'])) throw new ConfigError('invalid_response');
        const operationId = value['operationId'], resourceId = value['resourceId'], statusUrl = value['statusUrl'];
        onOperation(operationId);
        for (let attempt = 0; attempt < 120; attempt++) {
            const operation = await this.api.get(statusUrl);
            if (!object(operation) || operation['id'] !== operationId || operation['resourceId'] !== resourceId || typeof operation['state'] !== 'string') throw new ConfigError('invalid_response');
            if (operation['state'] === 'succeeded') return resourceId;
            if (!['queued', 'pending', 'running'].includes(operation['state'])) throw new ConfigError('operation_failed');
            await new Promise(resolve => setTimeout(resolve, 500));
        }
        throw new ConfigError('operation_timeout');
    }
}
