import { Injectable, inject } from '@angular/core';
import { ConfigApi, ConfigError, Mutation } from './config-api';

export const executionID = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(v);
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const digest = (v: unknown): v is string => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v);
const utc = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v));
const sequence = (v: unknown): v is string => typeof v === 'string' && /^(0|[1-9]\d{0,18})$/.test(v) && BigInt(v) <= 9223372036854775807n;
const ids = (v: unknown): v is string[] => Array.isArray(v) && v.length <= 10000 && v.every(executionID) && new Set(v).size === v.length;
export interface ExecutionPolicy { canaryNodeIds: string[]; maxParallel: 1; maxUnavailable: 1; observationSeconds: number; failureAction: 'pause'; }
export interface ExecutionInput { siteId: string; revisionId: string; nodeIds: string[]; rolloutPolicy: ExecutionPolicy; reason: string; expiresAt: string; }
export interface ExecutionTarget { nodeId: string; baseRevisionId: string; expectedNodeDeploymentSequence: string; capabilityDigest: string; bundleDigest: string; baseBundleDigest: string; secretVersionIds: string[]; }
export interface ExecutionPlan { apiVersion: 'agp.plan/v1alpha1'; id: string; kind: 'apply_config' | 'rollback_config'; siteId: string; revisionId: string; createdBy: string; createdAt: string; expiresAt: string; targets: ExecutionTarget[]; rolloutPolicy: ExecutionPolicy; compilerVersion: string; minimumDenySequence: string; planDigest: string; authorityEpoch: string; reason: string; resolvedInputs: { kind: string; id: string; digest: string }[]; }
export interface ExecutionApproval { id: string; planId: string; planDigest: string; approvedBy: string; approvalDigest: string; createdAt: string; expiresAt: string; mfaAt: string; }
export interface ExecutionReceipt { apiVersion: string; purpose: string; receiptId: string; receiptSequence: string; nodeId: string; taskId: string; requestDigest: string; nodeDeploymentSequence: string; state: string; recoveryRequired: boolean; recordedAt: string; keyId: string; signature: string; active: { generationId: string; treeDigest: string; baseline: { revisionId: string; bundleDigest: string; nodeDeploymentSequence: string } }; }
export interface ExecutionTask { id: string; nodeId: string; nodeDeploymentSequence: string; state: string; receipt?: ExecutionReceipt; }
export interface ExecutionView { plan: ExecutionPlan; state: string; current: boolean; parentPlanId?: string; approval?: ExecutionApproval; tasks: ExecutionTask[]; access?: { read: boolean; approve: boolean; dispatch: boolean; cancel: boolean; rollback: boolean }; }
const planStates = ['validated', 'approved', 'running', 'succeeded', 'failed', 'cancelled', 'recovery_required'];
const taskStates = ['dispatched', 'succeeded', 'failed', 'recovered', 'recovery_required'];

@Injectable({ providedIn: 'root' })
export class ExecutionApi {
    private readonly api = inject(ConfigApi);
    path(id?: string): string {
        if (id !== undefined && !executionID(id)) throw new ConfigError('invalid_execution_id');
        return '/api/v2/config/execution-plans' + (id ? '/' + encodeURIComponent(id) : '');
    }
    write(operation: Mutation): Promise<unknown> { return this.api.write(operation); }
    async load(id: string): Promise<ExecutionView> {
        const view = this.decodeView(await this.api.get(this.path(id)));
        if (view.plan.id !== id || !view.access?.read) throw new ConfigError('invalid_execution_response');
        return view;
    }
    decodeView(value: unknown): ExecutionView {
        if (!object(value) || !object(value['plan']) || typeof value['current'] !== 'boolean' || !planStates.includes(String(value['state'])) || (value['parentPlanId'] !== undefined && !executionID(value['parentPlanId']))) throw new ConfigError('invalid_execution_response');
        const p = value['plan'], targets = p['targets'], policy = p['rolloutPolicy'];
        if (p['apiVersion'] !== 'agp.plan/v1alpha1' || !['apply_config', 'rollback_config'].includes(String(p['kind'])) || !['id', 'siteId', 'revisionId', 'createdBy'].every(k => executionID(p[k])) || !digest(p['planDigest']) || !sequence(p['authorityEpoch']) || p['authorityEpoch'] === '0' || !sequence(p['minimumDenySequence']) || !utc(p['createdAt']) || !utc(p['expiresAt']) || Date.parse(p['expiresAt']) <= Date.parse(p['createdAt']) || typeof p['reason'] !== 'string' || p['reason'].length > 4096 || typeof p['compilerVersion'] !== 'string' || p['compilerVersion'].length > 128) throw new ConfigError('invalid_execution_response');
        if (!Array.isArray(targets) || !targets.length || targets.length > 500 || targets.some(t => !object(t) || !executionID(t['nodeId']) || !executionID(t['baseRevisionId']) || !sequence(t['expectedNodeDeploymentSequence']) || !['bundleDigest', 'baseBundleDigest', 'capabilityDigest'].every(k => digest(t[k])) || !ids(t['secretVersionIds'])) || new Set(targets.map(t => t['nodeId'])).size !== targets.length) throw new ConfigError('invalid_execution_response');
        if (!object(policy) || !ids(policy['canaryNodeIds']) || !policy['canaryNodeIds'].length || policy['canaryNodeIds'].some(id => !targets.some(t => t['nodeId'] === id)) || policy['maxParallel'] !== 1 || policy['maxUnavailable'] !== 1 || policy['failureAction'] !== 'pause' || !Number.isInteger(policy['observationSeconds']) || Number(policy['observationSeconds']) < 30 || Number(policy['observationSeconds']) > 86400) throw new ConfigError('invalid_execution_response');
        const inputs = p['resolvedInputs'];
        if (!Array.isArray(inputs) || inputs.length > 50000 || inputs.some(i => !object(i) || typeof i['kind'] !== 'string' || !executionID(i['id']) || !digest(i['digest']))) throw new ConfigError('invalid_execution_response');
        const access = value['access'];
        if (access !== undefined && (!object(access) || ['read', 'approve', 'dispatch', 'cancel', 'rollback'].some(k => typeof access[k] !== 'boolean'))) throw new ConfigError('invalid_execution_response');
        const plan = p as unknown as ExecutionPlan;
        if (value['approval'] !== undefined) this.decodeApproval(value['approval'], plan);
        const tasks = value['tasks'];
        if (!Array.isArray(tasks) || tasks.length > 500 || tasks.some(t => !object(t) || !executionID(t['id']) || !targets.some(x => x['nodeId'] === t['nodeId']) || !sequence(t['nodeDeploymentSequence']) || t['nodeDeploymentSequence'] === '0' || !taskStates.includes(String(t['state']))) || new Set(tasks.map(t => t['id'])).size !== tasks.length || new Set(tasks.map(t => t['nodeId'])).size !== tasks.length) throw new ConfigError('invalid_execution_response');
        for (const t of tasks) {
            if (t['receipt'] !== undefined) this.decodeReceipt(t['receipt'], t as unknown as ExecutionTask, plan);
            else if (t['state'] !== 'dispatched') throw new ConfigError('invalid_execution_response');
        }
        if (value['state'] === 'succeeded' && (tasks.length !== targets.length || tasks.some(t => t['state'] !== 'succeeded'))) throw new ConfigError('invalid_execution_response');
        return value as unknown as ExecutionView;
    }
    decodeApproval(value: unknown, plan: ExecutionPlan): ExecutionApproval {
        if (!object(value) || !executionID(value['id']) || value['planId'] !== plan.id || value['planDigest'] !== plan.planDigest || !executionID(value['approvedBy']) || value['approvedBy'] === plan.createdBy || !digest(value['approvalDigest']) || !utc(value['createdAt']) || !utc(value['expiresAt']) || !utc(value['mfaAt']) || Date.parse(value['expiresAt']) <= Date.parse(value['createdAt']) || Date.parse(value['expiresAt']) > Date.parse(plan.expiresAt)) throw new ConfigError('invalid_execution_response');
        return value as unknown as ExecutionApproval;
    }
    decodeDispatch(value: unknown, plan: ExecutionPlan): void {
        if (!object(value) || !Array.isArray(value['items']) || value['items'].length !== 1 || value['items'].some(t => !object(t) || !executionID(t['id']) || !plan.targets.some(x => x.nodeId === t['nodeId']) || !sequence(t['nodeDeploymentSequence']) || t['nodeDeploymentSequence'] === '0') || new Set(value['items'].map(t => t['id'])).size !== value['items'].length) throw new ConfigError('invalid_execution_response');
    }
    private decodeReceipt(value: unknown, task: ExecutionTask, plan: ExecutionPlan): void {
        if (!object(value) || value['apiVersion'] !== 'agp.helper-execution-receipt/v1alpha1' || value['purpose'] !== 'local_execution_outcome' || !executionID(value['receiptId']) || !sequence(value['receiptSequence']) || value['receiptSequence'] === '0' || value['nodeId'] !== task.nodeId || value['taskId'] !== task.id || value['nodeDeploymentSequence'] !== task.nodeDeploymentSequence || value['state'] !== task.state || !digest(value['requestDigest']) || typeof value['recoveryRequired'] !== 'boolean' || value['recoveryRequired'] !== (task.state === 'recovery_required') || !utc(value['recordedAt']) || !executionID(value['keyId']) || typeof value['signature'] !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(value['signature'])) throw new ConfigError('invalid_execution_response');
        const active = value['active'];
        if (!object(active) || !executionID(active['generationId']) || !digest(active['treeDigest']) || !object(active['baseline']) || !executionID(active['baseline']['revisionId']) || !digest(active['baseline']['bundleDigest']) || !sequence(active['baseline']['nodeDeploymentSequence'])) throw new ConfigError('invalid_execution_response');
        const target = plan.targets.find(t => t.nodeId === task.nodeId)!;
        if (task.state === 'succeeded' && (active['baseline']['revisionId'] !== plan.revisionId || active['baseline']['bundleDigest'] !== target.bundleDigest || active['baseline']['nodeDeploymentSequence'] !== task.nodeDeploymentSequence)) throw new ConfigError('invalid_execution_response');
        if (['failed', 'recovered', 'recovery_required'].includes(task.state) && (active['baseline']['revisionId'] !== target.baseRevisionId || active['baseline']['bundleDigest'] !== target.baseBundleDigest)) throw new ConfigError('invalid_execution_response');
    }
}
