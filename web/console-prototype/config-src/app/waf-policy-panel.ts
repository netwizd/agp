import { Component, EventEmitter, HostListener, Input, Output, inject, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ConfigAccess, Issue } from './contracts';
import { ConfigError, Mutation, mutation } from './config-api';
import { ConfigHelp, Topic } from './help-tip';
import { WafPolicy, WafPolicyApi, WafPolicyApproval, WafPolicyRevision, WafPolicyValidation } from './waf-policy-api';
const text = (required = false) => new FormControl('', { nonNullable: true, validators: required ? [Validators.required] : [] });
const numeric = (value: number, min: number, max: number) => new FormControl(value, { nonNullable: true, validators: [Validators.required, Validators.min(min), Validators.max(max)] });
interface PendingPolicy {
    kind: 'create' | 'validate' | 'approve' | 'publish';
    operation: Mutation;
    sequence: number;
    revisionId?: string;
}
@Component({ selector: 'agp-waf-policy-panel', standalone: true, imports: [ReactiveFormsModule, ConfigHelp], templateUrl: './waf-policy-panel.html' })
export class WafPolicyPanel {
    private readonly api = inject(WafPolicyApi);
    private sequence = 0;
    private installing = false;
    @Input({ required: true })
    access!: ConfigAccess;
    @Output()
    manual = new EventEmitter<Topic>();
    readonly busy = signal(false);
    readonly dirty = signal(false);
    readonly conflict = signal(false);
    readonly error = signal('');
    readonly issues = signal<Issue[]>([]);
    readonly notice = signal('');
    readonly status = signal(0);
    readonly pending = signal<PendingPolicy | null>(null);
    readonly loaded = signal<WafPolicyRevision | null>(null);
    readonly validation = signal<WafPolicyValidation | null>(null);
    readonly approval = signal<WafPolicyApproval | null>(null);
    readonly operationId = signal('');
    readonly requiresRefresh = signal(false);
    readonly revisionLookup = text(true);
    readonly validationLookup = text(true);
    readonly form = new FormGroup({ id: text(true), name: text(true), siteId: text(true), rulesetVersionId: text(true), paranoiaLevel: numeric(1, 1, 4), inboundAnomalyThreshold: numeric(5, 1, 100), outboundAnomalyThreshold: numeric(4, 1, 100) });
    readonly approvalDigest = new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.pattern(/^sha256:[a-f0-9]{64}$/)] });
    readonly approvalReason = new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.minLength(8), Validators.maxLength(1024)] });
    constructor() { this.form.valueChanges.pipe(takeUntilDestroyed()).subscribe(() => { if (!this.installing) {
        this.dirty.set(true);
        this.sequence++;
        this.approval.set(null);
    } }); }
    ngOnInit(): void { this.newPolicy(); }
    canEdit(siteId = this.form.controls.siteId.value): boolean { return this.access.globalEdit || this.access.sites.some(site => site.siteId === siteId && site.edit); }
    canApprove(): boolean { const site = this.loaded()?.content.metadata.siteId; return !!this.access.globalApprove || this.access.sites.some(item => item.siteId === site && item.approve === true); }
    unsupported(): boolean { return !!this.loaded()?.content.spec.exceptions.length; }
    qualified(): boolean { const validation = this.validation(), revision = this.loaded(); return !this.requiresRefresh() && !!validation && !!revision && validation.policyRevisionId === revision.id && validation.contentDigest === revision.contentDigest && validation.valid && validation.current && !!validation.qualification && validation.qualification.contentDigest === revision.contentDigest && validation.qualification.rulesetVersionId === revision.content.spec.rulesetVersionId && Date.parse(validation.qualification.expiresAt) > Date.now() && Date.parse(validation.expiresAt) > Date.now(); }
    digestMatches(): boolean { return !!this.loaded() && this.approvalDigest.value === this.loaded()!.contentDigest; }
    newPolicy(): void { if (this.pending() || this.busy())
        return; this.loaded.set(null); this.validation.set(null); this.approval.set(null); this.operationId.set(''); this.installing = true; this.form.setValue({ id: `waf_${crypto.randomUUID().replaceAll('-', '').slice(0, 12)}`, name: 'Новая базовая WAF-политика', siteId: this.access.sites.find(site => site.edit)?.siteId || '', rulesetVersionId: '', paranoiaLevel: 1, inboundAnomalyThreshold: 5, outboundAnomalyThreshold: 4 }, { emitEvent: false }); this.installing = false; this.dirty.set(false); this.conflict.set(false); this.approvalDigest.reset(''); this.approvalReason.reset(''); this.clearError(); this.notice.set('Базовая политика: exceptions=[]; derivation требует отдельного квалифицированного процесса.'); }
    async load(): Promise<void> { if (this.dirty() || this.pending() || this.busy())
        return; this.busy.set(true); try {
        this.install(await this.api.revision(this.revisionLookup.value));
        this.clearError();
        this.notice.set('Загружена точная неизменяемая ревизия.');
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    async loadValidation(): Promise<void> { if (this.busy())
        return; this.busy.set(true); try {
        const report = await this.api.validation(this.validationLookup.value);
        const revision = this.loaded();
        if (!revision || report.policyRevisionId !== revision.id || report.contentDigest !== revision.contentDigest)
            throw new ConfigError('validation_revision_mismatch');
        this.validation.set(report);
        this.requiresRefresh.set(false);
        this.clearError();
        this.notice.set(report.current ? 'Проверена текущая native qualification.' : 'Qualification устарела; повторите validate перед approval/publication.');
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    private body(): WafPolicy { if (this.form.invalid)
        throw new ConfigError('invalid_policy_form'); const value = this.form.getRawValue(); if (![value.paranoiaLevel, value.inboundAnomalyThreshold, value.outboundAnomalyThreshold].every(Number.isInteger))
        throw new ConfigError('integer_thresholds_required'); return { apiVersion: 'agp.waf/v1alpha1', kind: 'WafPolicy', metadata: { id: value.id, name: value.name, siteId: value.siteId }, spec: { engine: 'modsecurity', rulesetVersionId: value.rulesetVersionId, paranoiaLevel: value.paranoiaLevel, inboundAnomalyThreshold: value.inboundAnomalyThreshold, outboundAnomalyThreshold: value.outboundAnomalyThreshold, exceptions: [] } }; }
    async create(): Promise<void> { if (this.pending() || this.busy() || !this.canEdit())
        return; try {
        const base = this.loaded();
        await this.execute({ kind: 'create', operation: mutation('/api/v2/waf/policy-revisions', { ...(base ? { baseRevisionId: base.id } : {}), content: this.body() }), sequence: this.sequence });
    }
    catch (error) {
        this.fail(error);
    } }
    async validate(): Promise<void> { const revision = this.loaded(); if (!revision || this.dirty() || this.pending() || this.busy() || !this.canEdit(revision.content.metadata.siteId))
        return; await this.execute({ kind: 'validate', operation: mutation(this.api.path(revision.id, 'validations'), {}), sequence: this.sequence, revisionId: revision.id }); }
    async approve(): Promise<void> { const revision = this.loaded(); if (!revision || this.dirty() || this.pending() || this.busy() || !this.canApprove() || !this.qualified() || !this.digestMatches() || this.approvalReason.invalid)
        return; await this.execute({ kind: 'approve', operation: mutation(this.api.path(revision.id, 'approvals'), { contentDigest: revision.contentDigest, reason: this.approvalReason.value }), sequence: this.sequence, revisionId: revision.id }); }
    async publish(): Promise<void> { const revision = this.loaded(); if (!revision || this.dirty() || this.pending() || this.busy() || !this.canApprove() || !this.qualified() || !this.digestMatches() || revision.state !== 'approved')
        return; await this.execute({ kind: 'publish', operation: mutation(this.api.path(revision.id, 'publications'), { contentDigest: revision.contentDigest }), sequence: this.sequence, revisionId: revision.id }); }
    async retry(): Promise<void> { const pending = this.pending(); if (pending && !this.busy())
        await this.execute(pending); }
    async useBase(): Promise<void> { if (this.pending() || this.busy())
        return; this.busy.set(true); try {
        const base = await this.api.revision(this.revisionLookup.value);
        if (base.content.metadata.id !== this.form.controls.id.value || base.content.metadata.siteId !== this.form.controls.siteId.value)
            throw new ConfigError('policy_base_mismatch');
        this.loaded.set(base);
        this.validation.set(null);
        this.approval.set(null);
        this.conflict.set(false);
        this.approvalDigest.reset('');
        this.clearError();
        this.notice.set('Base заменён явно, локальные поля сохранены. Проверьте изменения и создайте ревизию.');
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    private async execute(pending: PendingPolicy): Promise<void> { this.busy.set(true); this.pending.set(pending); this.clearError(); try {
        const result = await this.api.write(pending.operation);
        if (pending.kind === 'create') {
            const revision = this.api.decodeRevision(result);
            if (pending.sequence === this.sequence)
                this.install(revision);
            else
                this.loaded.set(revision);
            this.notice.set('Создана неизменяемая ревизия ' + revision.id + '.');
        }
        else if (pending.kind === 'validate') {
            const report = await this.api.follow(result, id => this.operationId.set(id));
            if (report.policyRevisionId !== pending.revisionId)
                throw new ConfigError('validation_revision_mismatch');
            this.validation.set(report);
            this.requiresRefresh.set(false);
            this.validationLookup.setValue(report.id);
            this.loaded.set(await this.api.revision(pending.revisionId!));
            this.notice.set(report.current ? 'Native validation завершена; проверьте точные pins.' : 'Qualification устарела; approval/publication недоступны.');
        }
        else if (pending.kind === 'approve') {
            this.approval.set(this.api.decodeApproval(result));
            this.loaded.set(await this.api.revision(pending.revisionId!));
            this.notice.set('Exact digest подтверждён независимым approver. Политика ещё не опубликована.');
        }
        else {
            const revision = this.api.decodeRevision(result);
            this.loaded.set(revision);
            this.notice.set('Policy published. Конфигурация и live WAF на узлах не изменены.');
        }
        this.pending.set(null);
    }
    catch (error) {
        this.fail(error);
        if (error instanceof ConfigError && error.status >= 400 && error.status < 500) {
            this.pending.set(null);
            if (error.status === 409 || error.status === 412)
                this.requiresRefresh.set(true);
            if (error.status === 412) {
                this.conflict.set(true);
                this.notice.set('Head политики изменился. Локальные поля и причина сохранены.');
            }
        }
        else
            this.notice.set('Результат неизвестен; повтор сохранит исходные ключ, digest, base и payload.');
    }
    finally {
        this.busy.set(false);
    } }
    private install(revision: WafPolicyRevision): void { this.installing = true; const value = revision.content; this.form.setValue({ id: value.metadata.id, name: value.metadata.name, siteId: value.metadata.siteId, rulesetVersionId: value.spec.rulesetVersionId, paranoiaLevel: value.spec.paranoiaLevel, inboundAnomalyThreshold: value.spec.inboundAnomalyThreshold, outboundAnomalyThreshold: value.spec.outboundAnomalyThreshold }, { emitEvent: false }); this.installing = false; this.loaded.set(revision); this.revisionLookup.setValue(revision.id); this.dirty.set(false); this.conflict.set(false); this.validation.set(null); this.requiresRefresh.set(false); this.approval.set(null); this.approvalDigest.reset(''); }
    download(): void { let content: unknown; try {
        content = this.body();
    }
    catch {
        content = this.form.getRawValue();
    } const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([JSON.stringify(content, null, 2)], { type: 'application/json' })); link.download = 'agp-waf-policy-local.json'; link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000); }
    stepUpURL(): string { return '/auth-ui/step-up?return=' + encodeURIComponent(location.pathname + location.search); }
    @HostListener('window:beforeunload', ['$event'])
    beforeUnload(event: BeforeUnloadEvent): void { if (this.dirty() || this.pending()) {
        event.preventDefault();
        event.returnValue = '';
    } }
    private clearError(): void { this.error.set(''); this.issues.set([]); this.status.set(0); }
    private fail(error: unknown): void { this.error.set(error instanceof ConfigError ? error.code : 'request_failed'); this.issues.set(error instanceof ConfigError ? error.issues : []); this.status.set(error instanceof ConfigError ? error.status : 0); }
}
