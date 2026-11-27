import { Component, DestroyRef, EventEmitter, HostListener, Input, OnChanges, Output, SimpleChanges, inject, signal } from '@angular/core';
import { JsonPipe } from '@angular/common';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ConfigAccess, Issue, Revision } from './contracts';
import { ConfigError, Mutation, mutation } from './config-api';
import { ZoneRevision, ZonesApi } from './zones-api';
import { ZoneChange, ZoneChangeRequest, ZoneLifecycleApi, ZoneResolution, ZoneValidation } from './zone-lifecycle-api';

const text = (required = false) => new FormControl('', { nonNullable: true, validators: required ? [Validators.required] : [] });
const digestControl = () => new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.pattern(/^sha256:[a-f0-9]{64}$/)] });
const reasonControl = () => new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.minLength(8), Validators.maxLength(1024)] });
interface PendingLifecycle {
    kind: 'validate' | 'approve' | 'publish' | 'resolve' | 'materialize';
    revisionId: string;
    operation: Mutation;
}
@Component({ selector: 'agp-zone-lifecycle', standalone: true, imports: [ReactiveFormsModule, JsonPipe], templateUrl: './zone-lifecycle.html' })
export class ZoneLifecycle implements OnChanges {
    private readonly api = inject(ZoneLifecycleApi);
    private readonly zones = inject(ZonesApi);
    private readonly clock = signal(Date.now());
    private expiryTimer: ReturnType<typeof setTimeout> | undefined;
    @Input({ required: true }) access!: ConfigAccess;
    @Input({ required: true }) revision!: ZoneRevision;
    @Input() dirty = false;
    @Input() parentBusy = false;
    @Input() revisions: Revision[] = [];
    @Output() revisionChanged = new EventEmitter<ZoneRevision>();
    @Output() busyChanged = new EventEmitter<boolean>();
    @Output() materialized = new EventEmitter<string>();
    readonly busy = signal(false);
    readonly pending = signal<PendingLifecycle | null>(null);
    readonly error = signal('');
    readonly status = signal(0);
    readonly notice = signal('');
    readonly issues = signal<Issue[]>([]);
    readonly operationId = signal('');
    readonly validation = signal<ZoneValidation | null>(null);
    readonly resolution = signal<ZoneResolution | null>(null);
    readonly change = signal<ZoneChange | null>(null);
    readonly stale = signal(false);
    readonly requiresResolutionRefresh = signal(false);
    readonly openMembers = signal<ReadonlySet<string>>(new Set());
    readonly validationLookup = text(true);
    readonly resolutionLookup = text(true);
    readonly changeLookup = text(true);
    readonly approvalDigest = digestControl();
    readonly approvalReason = reasonControl();
    readonly materializeDigest = digestControl();
    readonly materializeReason = reasonControl();
    readonly resolveForm = new FormGroup({ baseRevisionId: text(true), capacityProfile: new FormControl<'pilot-500' | 'fleet-10k'>('pilot-500', { nonNullable: true }), action: new FormControl<'reconcile' | 'retire'>('reconcile', { nonNullable: true }), replacements: new FormControl('[]', { nonNullable: true }) });

    constructor() { inject(DestroyRef).onDestroy(() => clearTimeout(this.expiryTimer)); }

    ngOnChanges(changes: SimpleChanges): void {
        const previous = changes['revision']?.previousValue as ZoneRevision | undefined;
        if (previous && this.revision && (previous.id !== this.revision.id || previous.contentDigest !== this.revision.contentDigest)) {
            this.validation.set(null); this.resolution.set(null); this.change.set(null); this.stale.set(false); this.requiresResolutionRefresh.set(false);
            this.approvalDigest.reset(''); this.materializeDigest.reset(''); this.operationId.set(''); this.clearError(); this.notice.set('');
            this.scheduleExpiry();
        }
    }
    canEdit(): boolean { return this.access.globalEdit || this.access.sites.some(site => site.siteId === this.revision.siteId && site.edit); }
    canApprove(): boolean { return this.access.globalApprove === true || this.access.sites.some(site => site.siteId === this.revision.siteId && site.approve === true); }
    blocked(): boolean { return this.busy() || this.parentBusy || !!this.pending() || this.dirty; }
    qualified(): boolean {
        this.clock();
        const report = this.validation();
        return !this.stale() && !!report && report.zoneRevisionId === this.revision.id && report.contentDigest === this.revision.contentDigest && report.valid && report.current && !!report.qualification && Date.parse(report.qualification.expiresAt) > Date.now() && Date.parse(report.expiresAt) > Date.now();
    }
    resolutionMatches(): boolean { const resolution = this.resolution(); return !!resolution && resolution.zoneRevisionId === this.revision.id && resolution.siteId === this.revision.siteId; }
    resolutionExpired(): boolean { this.clock(); const resolution = this.resolution(); return !!resolution && Date.parse(resolution.expiresAt) <= Date.now(); }
    canMaterialize(): boolean {
        const resolution = this.resolution();
        return !this.blocked() && !this.stale() && !this.requiresResolutionRefresh() && this.canEdit() && this.revision.state === 'published' && this.resolutionMatches() && !this.resolutionExpired() && !!resolution && resolution.members.length > 0 && !resolution.conflicts.length && resolution.members.every(member => member.disposition !== 'conflict' && member.nodeIds.length > 0) && this.materializeDigest.value === resolution.resolutionDigest && this.materializeReason.valid && this.change()?.state !== 'materialized';
    }
    async validate(): Promise<void> {
        if (this.blocked() || !this.canEdit()) return;
        await this.execute({ kind: 'validate', revisionId: this.revision.id, operation: mutation(this.api.path('zone-revisions', this.revision.id, 'validations'), {}) });
    }
    async approve(): Promise<void> {
        if (this.blocked() || !this.canApprove() || !this.qualified() || this.approvalDigest.value !== this.revision.contentDigest || this.approvalReason.invalid) return;
        await this.execute({ kind: 'approve', revisionId: this.revision.id, operation: mutation(this.api.path('zone-revisions', this.revision.id, 'approvals'), { contentDigest: this.revision.contentDigest, reason: this.approvalReason.value }) });
    }
    async publish(): Promise<void> {
        if (this.blocked() || !this.canApprove() || !this.qualified() || this.revision.state !== 'approved' || this.approvalDigest.value !== this.revision.contentDigest) return;
        await this.execute({ kind: 'publish', revisionId: this.revision.id, operation: mutation(this.api.path('zone-revisions', this.revision.id, 'publications'), { contentDigest: this.revision.contentDigest }) });
    }
    async resolve(): Promise<void> {
        if (this.blocked() || !this.canEdit() || this.revision.state !== 'published' || this.resolveForm.invalid) return;
        try {
            const value = this.resolveForm.getRawValue();
            let replacements: unknown;
            try { replacements = JSON.parse(value.replacements); } catch { throw new ConfigError('invalid_replacement_assignments'); }
            const identifier = (value: unknown) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
            if (!Array.isArray(replacements) || replacements.length > 10000 || replacements.some(item => !item || typeof item !== 'object' || Array.isArray(item) || Object.keys(item).length !== 2 || !identifier(item.gatewayId) || !identifier(item.zoneRevisionId))) throw new ConfigError('invalid_replacement_assignments');
            await this.execute({ kind: 'resolve', revisionId: this.revision.id, operation: mutation(this.api.path('zone-revisions', this.revision.id, 'resolutions'), { baseRevisionId: value.baseRevisionId, capacityProfile: value.capacityProfile, action: value.action, ...(replacements.length ? { replacementAssignments: replacements } : {}) }) });
        } catch (error) { this.fail(error); }
    }
    async materialize(): Promise<void> {
        if (!this.canMaterialize()) return;
        const resolution = this.resolution()!;
        const body: ZoneChangeRequest = { apiVersion: 'agp.waf-zone-change/v1alpha1', kind: 'WafZoneChange', baseRevisionId: resolution.baseConfigRevisionId, zoneRevisionId: resolution.zoneRevisionId, resolutionId: resolution.id, resolutionDigest: resolution.resolutionDigest, reason: this.materializeReason.value };
        await this.execute({ kind: 'materialize', revisionId: this.revision.id, operation: mutation('/api/v2/waf/zone-changes', body) });
    }
    async loadValidation(): Promise<void> {
        if (this.busy() || this.parentBusy || this.pending()) return;
        this.setBusy(true);
        try { const report = await this.api.validation(this.validationLookup.value); this.acceptValidation(report); this.stale.set(false); this.clearError(); }
        catch (error) { this.fail(error); } finally { this.setBusy(false); }
    }
    async loadResolution(): Promise<void> {
        if (this.busy() || this.parentBusy || this.pending()) return;
        this.setBusy(true);
        try { this.acceptResolution(await this.api.resolution(this.resolutionLookup.value)); this.stale.set(false); this.clearError(); this.notice.set('Открыт сохранённый resolution. Перед записью сервер повторно проверит head, inventory и зависимости.'); }
        catch (error) { this.fail(error); } finally { this.setBusy(false); }
    }
    async loadChange(): Promise<void> {
        if (this.busy() || this.parentBusy || this.pending()) return;
        this.setBusy(true);
        try { this.acceptChange(await this.api.change(this.changeLookup.value)); this.clearError(); }
        catch (error) { this.fail(error); } finally { this.setBusy(false); }
    }
    async retry(): Promise<void> { const pending = this.pending(); if (pending && !this.busy() && !this.parentBusy) await this.execute(pending); }
    private async execute(pending: PendingLifecycle): Promise<void> {
        this.pending.set(pending); this.setBusy(true); this.clearError();
        try {
            const result = await this.api.write(pending.operation);
            if (pending.kind === 'validate') {
                const resourceId = await this.api.follow(result, value => this.operationId.set(value));
                this.acceptValidation(await this.api.validation(resourceId));
                this.validationLookup.setValue(resourceId); this.stale.set(false);
                this.revisionChanged.emit(await this.zones.revision(pending.revisionId));
                this.notice.set('Проверка зоны завершена. Изучите закреплённую опубликованную политику и qualification.');
            } else if (pending.kind === 'approve') {
                const approval = this.api.decodeApproval(result);
                if (approval.contentDigest !== this.revision.contentDigest) throw new ConfigError('approval_revision_mismatch');
                this.revisionChanged.emit(await this.zones.revision(pending.revisionId));
                this.notice.set('Сохранено независимое approval на точный digest.');
            } else if (pending.kind === 'publish') {
                const revision = this.zones.decodeRevision(result);
                if (revision.id !== pending.revisionId || revision.state !== 'published') throw new ConfigError('publication_revision_mismatch');
                this.revisionChanged.emit(revision); this.notice.set('Зона опубликована. Теперь доступен resolution по аутентифицированной инвентаризации.');
            } else if (pending.kind === 'resolve') {
                const resourceId = await this.api.follow(result, value => this.operationId.set(value));
                this.acceptResolution(await this.api.resolution(resourceId));
                this.resolutionLookup.setValue(resourceId); this.stale.set(false); this.requiresResolutionRefresh.set(false); this.change.set(null);
                this.notice.set('Получен замороженный resolution. Проверьте всех участников, конфликты и точный digest.');
            } else {
                const resourceId = await this.api.follow(result, value => this.operationId.set(value));
                this.acceptChange(await this.api.change(resourceId)); this.changeLookup.setValue(resourceId);
                this.notice.set('Создана полная desired-ревизия конфигурации. Применение на узлы не выполнялось.');
            }
            this.pending.set(null);
        } catch (error) {
            this.fail(error);
            if (error instanceof ConfigError && error.status >= 400 && error.status < 500) {
                this.pending.set(null);
                if ([409, 412].includes(error.status)) { this.stale.set(true); if (pending.kind === 'resolve' || pending.kind === 'materialize') this.requiresResolutionRefresh.set(true); this.notice.set('Входы изменились или устарели. Текст и причина сохранены. Создайте новую проверку или resolution на актуальном head.'); }
            } else this.notice.set('Результат запроса неизвестен. Повтор использует исходные body и Idempotency-Key.');
        } finally { this.setBusy(false); }
    }
    private acceptValidation(report: ZoneValidation): void {
        if (report.zoneRevisionId !== this.revision.id || report.contentDigest !== this.revision.contentDigest || report.policyRevisionId !== this.revision.content?.spec.policyRevisionId) throw new ConfigError('validation_revision_mismatch');
        this.validation.set(report);
        this.scheduleExpiry();
    }
    private acceptResolution(resolution: ZoneResolution): void {
        if (resolution.zoneRevisionId !== this.revision.id || resolution.siteId !== this.revision.siteId) throw new ConfigError('resolution_revision_mismatch');
        this.resolution.set(resolution); this.materializeDigest.reset('');
        this.scheduleExpiry();
    }
    private acceptChange(change: ZoneChange): void {
        if (change.request.zoneRevisionId !== this.revision.id) throw new ConfigError('change_revision_mismatch');
        const resolution = this.resolution();
        if (resolution && (change.request.resolutionId !== resolution.id || change.request.resolutionDigest !== resolution.resolutionDigest || change.request.baseRevisionId !== resolution.baseConfigRevisionId)) throw new ConfigError('change_resolution_mismatch');
        this.change.set(change);
        if (change.state === 'materialized' && change.resultRevisionId) this.materialized.emit(change.resultRevisionId);
    }
    memberToggle(event: Event, gatewayId: string): void { const next = new Set(this.openMembers()); if ((event.target as HTMLDetailsElement).open) next.add(gatewayId); else next.delete(gatewayId); this.openMembers.set(next); }
    stepUpURL(): string { return '/auth-ui/step-up?return=' + encodeURIComponent(location.pathname + location.search); }
    private scheduleExpiry(): void {
        clearTimeout(this.expiryTimer);
        const now = Date.now(); this.clock.set(now);
        const deadlines = [this.validation()?.expiresAt, this.validation()?.qualification?.expiresAt, this.resolution()?.expiresAt].filter((value): value is string => !!value).map(value => Date.parse(value)).filter(value => value > now);
        if (deadlines.length) this.expiryTimer = setTimeout(() => this.scheduleExpiry(), Math.min(Math.min(...deadlines) - now + 1, 2147483647));
    }
    private setBusy(value: boolean): void { this.busy.set(value); this.busyChanged.emit(value || !!this.pending()); }
    private clearError(): void { this.error.set(''); this.status.set(0); this.issues.set([]); }
    private fail(error: unknown): void { this.error.set(error instanceof ConfigError ? error.code : 'request_failed'); this.status.set(error instanceof ConfigError ? error.status : 0); this.issues.set(error instanceof ConfigError ? error.issues : []); }
    @HostListener('window:beforeunload', ['$event'])
    beforeUnload(event: BeforeUnloadEvent): void { if (this.pending()) { event.preventDefault(); event.returnValue = ''; } }
}
