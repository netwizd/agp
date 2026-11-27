export type WafMode = 'detection' | 'blocking';
export type WafMatchField = 'query_arg' | 'header' | 'cookie' | 'body_field';

export interface WafResource {
  id: string;
  name: string;
  domain: string;
  nodes: string[];
  waf: WafMode;
  revision: string;
}

export interface WafException {
  id: string;
  routeId: string;
  ruleIds: string[];
  match: { field: WafMatchField; name: string };
  ownerId: string;
  reason: string;
  reviewAt: string;
  expiresAt: string;
}

// WAF mode belongs to the Gateway binding, never to WafPolicy.spec.
export interface WafPolicyDto {
  apiVersion: 'agp.waf/v1alpha1';
  kind: 'WafPolicy';
  metadata: { id: string; name: string; siteId: string };
  spec: {
    engine: 'modsecurity';
    rulesetVersionId: string;
    paranoiaLevel: number;
    inboundAnomalyThreshold: number;
    outboundAnomalyThreshold: number;
    exceptions: WafException[];
  };
}

export interface EditableWaf {
  mode: WafMode;
  paranoiaLevel: number;
  inboundAnomalyThreshold: number;
  outboundAnomalyThreshold: number;
  exceptions: WafException[];
}

export interface WafDraft {
  id: string;
  resourceId: string;
  resourceName: string;
  domain: string;
  nodes: string[];
  baseRevision: string;
  basePolicyId: string;
  // This is a resource-scoped policy copy plus its exact Gateway binding.
  gatewayBinding: { resourceId: string; mode: WafMode; policyRef: string };
  policy: WafPolicyDto;
  values: EditableWaf;
  savedAt: string;
}

export interface WafEvent {
  id: string;
  occurredAt: string;
  resourceId: string;
  routeId: string;
  method: 'GET' | 'POST';
  path: string;
  ruleId: string;
  category: string;
  requestScore: number;
  match: { field: WafMatchField; name: string };
  mode: WafMode;
  outcome: 'recorded' | 'blocked';
  revision: string;
  inboundThreshold: number;
}

export const MATCH_FIELDS: { value: WafMatchField; label: string }[] = [
  { value: 'query_arg', label: 'Параметр URL · query_arg' },
  { value: 'header', label: 'HTTP-заголовок · header' },
  { value: 'cookie', label: 'Cookie · cookie' },
  { value: 'body_field', label: 'Поле тела запроса · body_field' },
];

export function routeIdFor(resourceId: string): string {
  return `route_${resourceId.replace(/^gw-/, '').replace(/[^A-Za-z0-9_-]/g, '_')}`;
}

export function baselineFor(resource: WafResource, now: number): EditableWaf {
  return {
    mode: resource.waf,
    paranoiaLevel: 1,
    inboundAnomalyThreshold: 5,
    outboundAnomalyThreshold: 4,
    exceptions: resource.id === 'gw-zabbix' ? [{
      id: 'exception_zabbix_filter', routeId: routeIdFor(resource.id), ruleIds: ['942100'],
      match: { field: 'query_arg', name: 'filter' }, ownerId: 'usr_security',
      reason: 'Подтверждённое ложное срабатывание фильтра в тестовом сценарии',
      reviewAt: new Date(now + 2 * 86_400_000).toISOString(),
      expiresAt: new Date(now + 3 * 86_400_000).toISOString(),
    }] : [],
  };
}

export function sampleEvents(resource: WafResource, now: number): WafEvent[] {
  const inboundThreshold = 5;
  return [
    { ruleId: '942100', category: 'SQL injection', match: { field: 'query_arg' as const, name: 'q' }, requestScore: 5, path: '/search', method: 'GET' as const },
    { ruleId: '941100', category: 'Cross-site scripting', match: { field: 'body_field' as const, name: 'message' }, requestScore: 8, path: '/api/messages', method: 'POST' as const },
    { ruleId: '930100', category: 'Path traversal', match: { field: 'query_arg' as const, name: 'file' }, requestScore: 5, path: '/download', method: 'GET' as const },
    { ruleId: '921110', category: 'HTTP protocol', match: { field: 'header' as const, name: 'Content-Type' }, requestScore: 3, path: '/api/status', method: 'GET' as const },
  ].map((event, index) => ({
    ...event, id: `wafevt_${resource.id}_${index + 1}`, resourceId: resource.id,
    routeId: routeIdFor(resource.id), occurredAt: new Date(now - (index + 1) * 240_000).toISOString(),
    mode: resource.waf, revision: resource.revision, inboundThreshold,
    outcome: resource.waf === 'blocking' && event.requestScore >= inboundThreshold ? 'blocked' as const : 'recorded' as const,
  }));
}
