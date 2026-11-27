export type DocumentFormat = 'json' | 'yaml';
export interface Configuration {
    apiVersion: 'agp.config/v1alpha1' | 'agp.config/v1alpha2';
    kind: 'Configuration';
    metadata: {
        id: string;
        name: string;
    };
    gateways: Gateway[];
    profileAssignments: ProfileAssignment[];
    capacityProfile?: 'fleet-10k';
}
export interface ProfileAssignment {
    id: string;
    profileRevisionId: string;
    scopeType: 'global' | 'site' | 'node_group' | 'node' | 'route';
    scopeId?: string;
}
export interface Gateway {
    apiVersion: 'agp.config/v1alpha1';
    kind: 'Gateway';
    metadata: {
        id: string;
        name: string;
        siteId: string;
        labels: Record<string, string>;
    };
    spec: {
        ownership: 'managed' | 'adopted';
        nodeSelector: {
            nodeIds?: string[];
            matchLabels?: Record<string, string>;
        };
        componentProfileRef: {
            id: string;
            digest: string;
        };
        tls: {
            certificateVersionId: string;
        };
        authorization: {
            mode: 'central';
            failureMode: 'closed';
        };
        waf: {
            engine: 'modsecurity';
            policyRevisionId: string;
            mode: 'off' | 'detection' | 'blocking';
        };
        routes: Route[];
        monitoring: {
            metrics: boolean;
            logs: boolean;
        };
    };
}
export interface Route {
    id: string;
    name: string;
    hostname: string;
    path: string;
    upstream: {
        url: string;
        connectTimeoutSeconds: number;
        readTimeoutSeconds: number;
        tls: {
            verify: true;
            serverName?: string;
            caSecretVersionId?: string;
        };
    };
    access: {
        groupIds: string[];
        allowCidrs: string[];
    };
    wafExceptionIds: string[];
}
export interface Draft {
    id: string;
    baseRevisionId?: string;
    revision: string;
    contentDigest: string;
    content: Configuration;
}
export interface Revision extends Omit<Draft, 'content'> {
    content?: Configuration;
    viewScope: string;
    state: string;
}
export interface RevisionPage {
    items: Revision[];
    nextCursor?: string;
}
export interface CatalogSnapshot {
    id: string;
    contentDigest: string;
    sourceKind: string;
    sourceRef: string;
    recordedAt: string;
}
export interface ParsedDocument {
    content: Configuration;
    contentDigest: string;
    canonicalJSON: string;
    yaml: string;
}
export interface Issue {
    path: string;
    code: string;
    message: string;
    severity: string;
}
export interface Change {
    path: string;
    kind: string;
    before?: unknown;
    after?: unknown;
    dangerous: boolean;
}
export interface Report {
    id: string;
    targetKind: 'draft' | 'revision';
    targetId: string;
    targetRevision: string;
    createdAt: string;
    configDigest: string;
    catalogSnapshotId?: string;
    catalogDigest?: string;
    compilerDigest: string;
    authoringValid: boolean;
    deployable: false;
    issues: Issue[];
    diff: Change[];
    preview?: CompilerResult;
}
export interface AcceptedOperation {
    operationId: string;
    resourceId: string;
    statusUrl: string;
    submittedAt: string;
}
export interface Profile {
    enabled: boolean;
    headRevisionId?: string;
}
export interface Runtime {
    mode: string;
    secure_profile: boolean;
    csrf_cookie_name: string;
    management_url: string;
    auth_ui_url: string;
}
export interface Me {
    user: {
        id: string;
        username: string;
        display_name: string;
        is_admin: boolean;
    };
}
export const emptyConfiguration = (): Configuration => ({ apiVersion: 'agp.config/v1alpha1', kind: 'Configuration', metadata: { id: 'config_main', name: 'Основная конфигурация' }, gateways: [], profileAssignments: [] });
export const newGateway = (id: string): Gateway => ({ apiVersion: 'agp.config/v1alpha1', kind: 'Gateway', metadata: { id, name: 'Новый шлюз', siteId: '', labels: {} }, spec: { ownership: 'managed', nodeSelector: { nodeIds: [] }, componentProfileRef: { id: '', digest: '' }, tls: { certificateVersionId: '' }, authorization: { mode: 'central', failureMode: 'closed' }, waf: { engine: 'modsecurity', policyRevisionId: '', mode: 'detection' }, routes: [newRoute(`${id}_route`)], monitoring: { metrics: true, logs: true } } });
export const newRoute = (id: string): Route => ({ id, name: 'Новый маршрут', hostname: '', path: '/', upstream: { url: '', connectTimeoutSeconds: 5, readTimeoutSeconds: 60, tls: { verify: true } }, access: { groupIds: [], allowCidrs: [] }, wafExceptionIds: [] });
export interface CompilerResult {
    configDigest: string;
    catalogDigest: string;
    compilerDigest: string;
    compilerVersion: string;
    capacityProfile: string;
    previewDigest: string;
    deployable: false;
    bundles: NodeBundle[];
    resolvedInputs: ResolvedInput[];
    issues: Issue[];
}
export interface ResolvedInput {
    kind: string;
    id: string;
    digest: string;
}
export interface NodeBundle {
    nodeId: string;
    capabilityDigest?: string;
    baseBundleDigest?: string;
    gatewayIds: string[];
    routes: EffectiveRoute[];
    resolvedInputs: ResolvedInput[];
    secretVersionIds: string[];
    artifacts: {
        name: string;
        content: string;
        digest: string;
    }[];
    bundleDigest: string;
    deployable: false;
}
export interface EffectiveRoute {
    gatewayId: string;
    routeId: string;
    route: Route;
    waf: Gateway['spec']['waf'];
    requireMfa: boolean;
    provenance: unknown;
}
export interface ConfigAccess { principalId:string;globalRead:boolean;globalEdit:boolean;globalApprove?:boolean;gatewayRead?:boolean;gatewayEdit?:boolean;resourceRead?:boolean;resourceEdit?:boolean;sites:{siteId:string;read:boolean;edit:boolean;approve?:boolean}[];authorityEpoch:string; }
