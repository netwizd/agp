import { Injectable, inject } from '@angular/core';
import { ConfigApi, ConfigError, Mutation } from './config-api';

export interface ProposalRollout { canaryNodeIds: string[]; maxParallel: number; maxUnavailable: number; observationSeconds: number; failureAction: 'pause' | 'rollback_wave'; }
export interface ProposalTarget { nodeId: string; capabilityDigest: string; previewBundleDigest: string; gatewayIds: string[]; secretVersionIds: string[]; }
export interface PlanProposal {
    apiVersion: 'agp.plan-proposal/v1alpha1'; purpose: 'planning_review'; deployable: false; noExecution: true;
    id: string; siteId: string; revisionId: string; configDigest: string; compilerDigest: string; compilerVersion: string;
    inventoryDigest: string; catalogSnapshotId: string; catalogDigest: string; dependencyDigest: string; previewDigest: string;
    proposalDigest: string; authorId: string; authorityEpoch: string; createdAt: string; expiresAt: string; reason: string;
    rolloutPolicy: ProposalRollout; targets: ProposalTarget[]; resolvedInputs: { kind: string; id: string; digest: string }[]; blockers: string[];
}
export interface ProposalView { proposal: PlanProposal; current: boolean; }
export interface ProposalReview { id: string; proposalId: string; proposalDigest: string; authorId: string; reviewerId: string; purpose: 'planning_review'; current: boolean; createdAt: string; expiresAt: string; reason: string; }
export interface SignedPlanReview { apiVersion: 'agp.signed-plan-review/v1alpha1'; purpose: 'planning_review'; deployable: false; noExecution: true; keyId: string; proposal: PlanProposal; review: ProposalReview; signatureAlgorithm: 'Ed25519'; signatureBase64: string; }
export const proposalIdentifier = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const digest = (value: unknown): value is string => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const utc = (value: unknown): value is string => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value));
const text = (value: unknown, max: number): value is string => typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).length <= max && !/[\u0000-\u001f\u007f]/.test(value);
const reason = (value: unknown): value is string => typeof value === 'string' && Array.from(value.trim()).length >= 8 && Array.from(value).length <= 1024 && new TextEncoder().encode(value).length <= 4096;
const ids = (value: unknown, max: number, min = 0): value is string[] => Array.isArray(value) && value.length >= min && value.length <= max && value.every(proposalIdentifier) && new Set(value).size === value.length;
const integer = (value: unknown, min: number, max: number): value is number => typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;

@Injectable({ providedIn: 'root' })
export class PlanProposalsApi {
    private readonly api = inject(ConfigApi);
    path(id?: string): string {
        if (id !== undefined && !proposalIdentifier(id)) throw new ConfigError('invalid_proposal_id');
        return '/api/v2/config/plan-proposals' + (id ? '/' + encodeURIComponent(id) : '');
    }
    async list(cursor = ''): Promise<{ items: ProposalView[]; nextCursor: string }> {
        if (cursor && !/^[A-Za-z0-9_-]{1,256}$/.test(cursor)) throw new ConfigError('invalid_cursor');
        const value = await this.api.get(this.path() + '?limit=20' + (cursor ? '&cursor=' + encodeURIComponent(cursor) : ''));
        if (!object(value) || !Array.isArray(value['items']) || value['items'].length > 20 || (value['nextCursor'] !== undefined && (typeof value['nextCursor'] !== 'string' || !/^[A-Za-z0-9_-]{1,256}$/.test(value['nextCursor']) || value['nextCursor'] === cursor))) throw new ConfigError('invalid_proposal_page');
        const items = value['items'].map(item => this.decodeView(item));
        if (new Set(items.map(item => item.proposal.id)).size !== items.length) throw new ConfigError('invalid_proposal_page');
        return { items, nextCursor: value['nextCursor'] as string || '' };
    }
    async load(id: string): Promise<ProposalView> {
        const view = this.decodeView(await this.api.get(this.path(id)));
        if (view.proposal.id !== id) throw new ConfigError('proposal_response_mismatch');
        return view;
    }
    async reviews(proposal: PlanProposal): Promise<ProposalReview[]> {
        const value = await this.api.get(this.path(proposal.id) + '/reviews');
        if (!Array.isArray(value) || value.length > 500) throw new ConfigError('invalid_review_response');
        const reviews = value.map(item => this.decodeReview(item, proposal));
        if (new Set(reviews.map(item => item.id)).size !== reviews.length) throw new ConfigError('invalid_review_response');
        return reviews;
    }
    write(operation: Mutation): Promise<unknown> { return this.api.write(operation); }
    decodeView(value: unknown): ProposalView {
        if (!object(value) || typeof value['current'] !== 'boolean') throw new ConfigError('invalid_proposal_response');
        return { proposal: this.decodeProposal(value['proposal']), current: value['current'] };
    }
    decodeProposal(value: unknown): PlanProposal {
        if (!object(value) || value['apiVersion'] !== 'agp.plan-proposal/v1alpha1' || value['purpose'] !== 'planning_review' || value['deployable'] !== false || value['noExecution'] !== true || !['id', 'siteId', 'revisionId', 'catalogSnapshotId', 'authorId'].every(key => proposalIdentifier(value[key])) || !['configDigest', 'compilerDigest', 'inventoryDigest', 'catalogDigest', 'dependencyDigest', 'previewDigest', 'proposalDigest'].every(key => digest(value[key])) || !text(value['compilerVersion'], 128) || typeof value['authorityEpoch'] !== 'string' || !/^[1-9]\d{0,18}$/.test(value['authorityEpoch']) || !utc(value['createdAt']) || !utc(value['expiresAt']) || Date.parse(value['expiresAt']) <= Date.parse(value['createdAt']) || !reason(value['reason'])) throw new ConfigError('invalid_proposal_response');
        const targets = value['targets'], policy = value['rolloutPolicy'], inputs = value['resolvedInputs'], blockers = value['blockers'];
        if (!Array.isArray(targets) || targets.length < 1 || targets.length > 500 || targets.some(target => !object(target) || !proposalIdentifier(target['nodeId']) || !digest(target['capabilityDigest']) || !digest(target['previewBundleDigest']) || !ids(target['gatewayIds'], 10000) || !ids(target['secretVersionIds'], 10000)) || new Set(targets.map(target => target['nodeId'])).size !== targets.length) throw new ConfigError('invalid_proposal_response');
        if (!object(policy) || !ids(policy['canaryNodeIds'], 10, 1) || policy['canaryNodeIds'].some(id => !targets.some(target => target['nodeId'] === id)) || !integer(policy['maxParallel'], 1, 25) || !integer(policy['maxUnavailable'], 0, 25) || !integer(policy['observationSeconds'], 30, 86400) || !['pause', 'rollback_wave'].includes(String(policy['failureAction']))) throw new ConfigError('invalid_proposal_response');
        if (!Array.isArray(inputs) || inputs.length > 50000 || inputs.some(item => !object(item) || !text(item['kind'], 128) || !proposalIdentifier(item['id']) || !digest(item['digest'])) || !Array.isArray(blockers) || blockers.length > 64 || blockers.some(item => !text(item, 256))) throw new ConfigError('invalid_proposal_response');
        return value as unknown as PlanProposal;
    }
    decodeReview(value: unknown, proposal: PlanProposal): ProposalReview {
        if (!object(value) || !proposalIdentifier(value['id']) || value['proposalId'] !== proposal.id || value['proposalDigest'] !== proposal.proposalDigest || value['authorId'] !== proposal.authorId || !proposalIdentifier(value['reviewerId']) || value['reviewerId'] === value['authorId'] || value['purpose'] !== 'planning_review' || typeof value['current'] !== 'boolean' || !utc(value['createdAt']) || !utc(value['expiresAt']) || Date.parse(value['expiresAt']) <= Date.parse(value['createdAt']) || value['expiresAt'] !== proposal.expiresAt || Date.parse(value['createdAt']) < Date.parse(proposal.createdAt) || !reason(value['reason'])) throw new ConfigError('invalid_review_response');
        return value as unknown as ProposalReview;
    }
    decodeSignature(value: unknown, proposal: PlanProposal, reviewId: string): SignedPlanReview {
        if (!object(value) || value['apiVersion'] !== 'agp.signed-plan-review/v1alpha1' || value['purpose'] !== 'planning_review' || value['deployable'] !== false || value['noExecution'] !== true || !proposalIdentifier(value['keyId']) || value['signatureAlgorithm'] !== 'Ed25519' || typeof value['signatureBase64'] !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(value['signatureBase64'])) throw new ConfigError('invalid_signature_response');
        const signedProposal = this.decodeProposal(value['proposal']);
        const review = this.decodeReview(value['review'], proposal);
        if (signedProposal.id !== proposal.id || signedProposal.proposalDigest !== proposal.proposalDigest || review.id !== reviewId || !review.current) throw new ConfigError('signature_response_mismatch');
        return value as unknown as SignedPlanReview;
    }
}
