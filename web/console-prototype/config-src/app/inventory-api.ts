import { Injectable, inject } from '@angular/core';
import { ConfigApi, ConfigError } from './config-api';

export interface AgentInventoryItem {
    id: string;
    siteId: string;
    name: string;
    labels: Record<string, string>;
    groupIds: string[];
    connectivity: string;
    identityState: string;
    capabilityDigest?: string;
    lastSeenAt?: string;
}
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const id = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
@Injectable({ providedIn: 'root' })
export class InventoryApi {
    private readonly api = inject(ConfigApi);
    async list(): Promise<AgentInventoryItem[]> {
        const result = await this.api.get('/api/v2/agent-inventory');
        if (!object(result) || !Array.isArray(result['items'])) throw new ConfigError('invalid_response');
        for (const item of result['items']) {
            if (!object(item) || !id(item['id']) || !id(item['siteId']) || typeof item['name'] !== 'string' || !object(item['labels']) || Object.values(item['labels']).some(value => typeof value !== 'string') || !Array.isArray(item['groupIds']) || !item['groupIds'].every(id) || typeof item['connectivity'] !== 'string' || typeof item['identityState'] !== 'string') throw new ConfigError('invalid_response');
            if (item['capabilityDigest'] !== undefined && (typeof item['capabilityDigest'] !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(item['capabilityDigest']))) throw new ConfigError('invalid_response');
            if (item['lastSeenAt'] !== undefined && (typeof item['lastSeenAt'] !== 'string' || !Number.isFinite(Date.parse(item['lastSeenAt'])))) throw new ConfigError('invalid_response');
        }
        return result['items'] as AgentInventoryItem[];
    }
}
