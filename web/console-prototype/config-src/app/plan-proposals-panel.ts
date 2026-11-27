import { Component, DestroyRef, HostListener, Input, inject, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ConfigAccess, Revision } from './contracts';
import { ConfigError, Mutation, mutation } from './config-api';
import { PlanProposal, PlanProposalsApi, ProposalReview, ProposalView, SignedPlanReview, proposalIdentifier } from './plan-proposals-api';

const idControl = () => new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.pattern(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/)] });
const reasonControl = () => new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.maxLength(1024), Validators.pattern(/^[^\u0000-\u001f\u007f]+$/)] });
interface PendingProposal { kind: 'create' | 'review' | 'sign'; operation: Mutation; proposal?: PlanProposal; reviewId?: string; }
const blockerLabels: Record<string, string> = {
    capture_baseline_required: 'Нужно зафиксировать исходное состояние узлов.',
    owned_tree_verification_required: 'Нужно проверить принадлежность управляемых файлов.',
    node_bundle_qualification_required: 'Нужно квалифицировать полный комплект конфигурации для каждого узла.',
    execution_authorizer_required: 'Нужно подключить проверку разрешения на применение.',
    functional_probes_required: 'Нужны функциональные проверки узлов.',
    rollback_qualification_required: 'Нужно проверить локальный откат.',
};

@Component({ selector: 'agp-plan-proposals-panel', standalone: true, imports: [ReactiveFormsModule], templateUrl: './plan-proposals-panel.html' })
export class PlanProposalsPanel {
    private readonly api = inject(PlanProposalsApi);
    private destroyed = false;
    private expiryTimer: ReturnType<typeof setTimeout> | undefined;
    private readonly clock = signal(Date.now());
    @Input({ required: true }) access!: ConfigAccess;
    @Input({ required: true }) revisions: Revision[] = [];
    readonly busy = signal(false);
    readonly loadedList = signal(false);
    readonly error = signal('');
    readonly status = signal(0);
    readonly notice = signal('');
    readonly items = signal<ProposalView[]>([]);
    readonly nextCursor = signal('');
    readonly loaded = signal<ProposalView | null>(null);
    readonly reviews = signal<ProposalReview[]>([]);
    readonly signed = signal<SignedPlanReview | null>(null);
    readonly inputLimit = signal(100);
    readonly pending = signal<PendingProposal | null>(null);
    readonly lookup = idControl();
    readonly reviewReason = reasonControl();
    readonly form = new FormGroup({ revisionId: idControl(), siteId: idControl(), targetNodeIds: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.maxLength(65000)] }), canaryNodeIds: new FormControl('', { nonNullable: true, validators: [Validators.maxLength(65000)] }), reason: reasonControl() });
    constructor() { inject(DestroyRef).onDestroy(() => { this.destroyed = true; clearTimeout(this.expiryTimer); }); }
    ngOnInit(): void { if (this.access.globalRead) void this.refresh(); }
    blocked(): boolean { return this.busy() || !!this.pending(); }
    revisionOptions(): Revision[] { return this.revisions.filter(item => proposalIdentifier(item.id)); }
    current(): boolean { this.clock(); const value = this.loaded(); return !!value && value.current && Date.parse(value.proposal.expiresAt) > Date.now() && value.proposal.authorityEpoch === this.access.authorityEpoch; }
    canReview(): boolean { return !this.blocked() && this.current() && this.access.globalApprove === true && this.loaded()?.proposal.authorId !== this.access.principalId && this.validReason(this.reviewReason.value); }
    canSign(review: ProposalReview): boolean { this.clock(); return !this.blocked() && this.current() && this.access.globalApprove === true && review.reviewerId === this.access.principalId && review.current && Date.parse(review.expiresAt) > Date.now(); }
    blocker(code: string): string { return blockerLabels[code] ?? 'Нужна дополнительная серверная проверка перед применением.'; }
    targetIDs(value: string): string[] {
        const values = value.trim().split(/[\s,]+/).filter(Boolean);
        if (!values.length || values.length > 500 || !values.every(proposalIdentifier) || new Set(values).size !== values.length) throw new ConfigError('invalid_target_nodes');
        return values;
    }
    validReason(value: string): boolean { return Array.from(value.trim()).length >= 8 && Array.from(value).length <= 1024 && new TextEncoder().encode(value).length <= 4096 && !/[\u0000-\u001f\u007f]/.test(value); }
    canCreate(): boolean {
        if (this.blocked() || !this.access.globalEdit || this.form.invalid || !this.validReason(this.form.controls.reason.value) || !this.revisionOptions().some(item => item.id === this.form.controls.revisionId.value)) return false;
        try { const targets = this.targetIDs(this.form.controls.targetNodeIds.value); const canaries = this.form.controls.canaryNodeIds.value.trim() ? this.targetIDs(this.form.controls.canaryNodeIds.value) : targets.slice(0, 1); return canaries.length <= 10 && canaries.every(id => targets.includes(id)); }
        catch { return false; }
    }
    async refresh(more = false): Promise<void> {
        if (this.blocked() || !this.access.globalRead || (more && !this.nextCursor())) return;
        this.busy.set(true); this.clearError();
        try {
            const page = await this.api.list(more ? this.nextCursor() : '');
            if (this.destroyed) return;
            const previous = more ? this.items() : [];
            if (previous.length + page.items.length > 10000 || page.items.some(item => previous.some(old => old.proposal.id === item.proposal.id))) throw new ConfigError('invalid_proposal_page');
            this.items.set([...previous, ...page.items]); this.nextCursor.set(page.nextCursor); this.loadedList.set(true);
        } catch (error) { this.fail(error); } finally { this.busy.set(false); }
    }
    async load(id = this.lookup.value): Promise<void> {
        if (this.blocked() || !this.access.globalRead || !proposalIdentifier(id)) return;
        this.busy.set(true); this.clearError(); this.loaded.set(null); this.reviews.set([]); this.signed.set(null);
        try {
            const view = await this.api.load(id);
            const reviews = await this.api.reviews(view.proposal);
            if (this.destroyed) return;
            this.install(view); this.reviews.set(reviews);
            this.notice.set('Открыто предварительное согласование точного снимка и набора узлов.');
        } catch (error) { this.fail(error); } finally { this.busy.set(false); }
    }
    async create(): Promise<void> {
        if (!this.canCreate()) return;
        const input = this.form.getRawValue(), targets = this.targetIDs(input.targetNodeIds), canaries = input.canaryNodeIds.trim() ? this.targetIDs(input.canaryNodeIds) : targets.slice(0, 1);
        await this.execute({ kind: 'create', operation: mutation(this.api.path(), { revisionId: input.revisionId, siteId: input.siteId, targetNodeIds: targets, rolloutPolicy: { canaryNodeIds: canaries, maxParallel: 1, maxUnavailable: 0, observationSeconds: 60, failureAction: 'pause' }, reason: input.reason }) });
    }
    async review(): Promise<void> {
        if (!this.canReview()) return;
        const proposal = this.loaded()!.proposal;
        await this.execute({ kind: 'review', proposal, operation: mutation(this.api.path(proposal.id) + '/reviews', { proposalDigest: proposal.proposalDigest, reason: this.reviewReason.value }) });
    }
    async sign(review: ProposalReview): Promise<void> {
        if (!this.canSign(review)) return;
        const proposal = this.loaded()!.proposal;
        await this.execute({ kind: 'sign', proposal, reviewId: review.id, operation: mutation(this.api.path(proposal.id) + '/reviews/' + review.id + '/signatures', {}) });
    }
    async retry(): Promise<void> { const pending = this.pending(); if (pending && !this.busy()) await this.execute(pending); }
    download(): void {
        const signed = this.signed(); if (!signed) return;
        const url = URL.createObjectURL(new Blob([JSON.stringify(signed, null, 2) + '\n'], { type: 'application/json' }));
        const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'planning-review-' + signed.review.id + '.json'; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    stepUpURL(): string { return '/auth-ui/step-up?return=' + encodeURIComponent(location.pathname + location.search); }
    loginURL(): string { return '/auth-ui/login?return=' + encodeURIComponent(location.pathname + location.search); }
    @HostListener('window:beforeunload', ['$event']) beforeUnload(event: BeforeUnloadEvent): void { if (this.pending()) { event.preventDefault(); event.returnValue = ''; } }
    private async execute(pending: PendingProposal): Promise<void> {
        this.pending.set(pending); this.busy.set(true); this.clearError();
        try {
            const value = await this.api.write(pending.operation);
            if (this.destroyed) return;
            if (pending.kind === 'create') {
                const proposal = this.api.decodeProposal(value);
                const input = JSON.parse(pending.operation.body) as { revisionId: string; siteId: string; targetNodeIds: string[] };
                if (proposal.revisionId !== input.revisionId || proposal.siteId !== input.siteId || proposal.authorId !== this.access.principalId || proposal.targets.length !== input.targetNodeIds.length || proposal.targets.some(target => !input.targetNodeIds.includes(target.nodeId))) throw new ConfigError('proposal_response_mismatch');
                // Creation alone cannot establish currentness: the authoritative GET checks all current pins.
                this.install({ proposal, current: false }); this.reviews.set([]);
                this.items.update(items => [{ proposal, current: false }, ...items.filter(item => item.proposal.id !== proposal.id)]);
                this.notice.set('Предложение сохранено. Обновите его состояние перед независимым согласованием.');
            } else if (pending.kind === 'review') {
                const review = this.api.decodeReview(value, pending.proposal!);
                if (review.reviewerId !== this.access.principalId) throw new ConfigError('review_response_mismatch');
                this.reviews.update(items => [...items.filter(item => item.id !== review.id), review]); this.signed.set(null);
                this.notice.set('Предварительное согласование сохранено. Разрешение на применение не выдано.');
            } else {
                this.signed.set(this.api.decodeSignature(value, pending.proposal!, pending.reviewId!));
                this.notice.set('Подписанный артефакт предварительного согласования получен. Он не разрешает применение.');
            }
            this.pending.set(null);
        } catch (error) {
            this.fail(error);
            if (error instanceof ConfigError && error.status >= 400 && error.status < 500) {
                this.pending.set(null);
                if ([401, 403, 409, 410, 412].includes(error.status)) this.invalidate();
            } else if (pending.kind === 'sign' && error instanceof ConfigError && error.status === 503) {
                this.notice.set('Подписанный артефакт сейчас недоступен. Согласование сохранено; применение остаётся недоступным. Повтор использует исходный ключ.');
            } else this.notice.set('Ответ не подтверждён. Повторите исходный запрос с тем же ключом и содержимым. Поля заблокированы до выяснения результата.');
        } finally { this.busy.set(false); }
    }
    private invalidate(): void { const view = this.loaded(); if (view) this.loaded.set({ ...view, current: false }); this.reviews.update(items => items.map(item => ({ ...item, current: false }))); this.signed.set(null); }
    private install(view: ProposalView): void { this.loaded.set(view); this.inputLimit.set(100); this.lookup.setValue(view.proposal.id); this.reviewReason.reset(''); this.signed.set(null); this.scheduleExpiry(); }
    private scheduleExpiry(): void {
        clearTimeout(this.expiryTimer); this.clock.set(Date.now());
        const expiresAt = this.loaded()?.proposal.expiresAt;
        if (!expiresAt) return;
        const remaining = Date.parse(expiresAt) - Date.now();
        if (remaining <= 0) { this.invalidate(); return; }
        this.expiryTimer = setTimeout(() => { this.clock.set(Date.now()); this.invalidate(); }, Math.min(remaining + 10, 2147483647));
    }
    private clearError(): void { this.error.set(''); this.status.set(0); }
    private fail(error: unknown): void { if (this.destroyed) return; const value = error instanceof ConfigError ? error : new ConfigError('request_failed'); this.error.set(/^[a-z][a-z0-9_]{0,80}$/.test(value.code) ? value.code : 'request_failed'); this.status.set(value.status); }
}
