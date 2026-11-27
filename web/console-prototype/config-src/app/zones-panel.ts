import { Component, EventEmitter, HostListener, Input, Output, effect, inject, signal } from '@angular/core';
import { JsonPipe } from '@angular/common';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ConfigAccess, CatalogSnapshot, Revision, Issue } from './contracts';
import { ConfigError, Mutation, mutation } from './config-api';
import { ZonesApi, WafZone, ZoneRevision, ZonePreview, ZonePreviewRequest, AuthoringReview } from './zones-api';
import { ConfigHelp, Topic } from './help-tip';
import { ZoneLifecycle } from './zone-lifecycle';
const text = (value = '', required = false) => new FormControl(value, { nonNullable: true, validators: required ? [Validators.required] : [] });
interface PendingZone {
    operation: Mutation;
    kind: 'revision' | 'preview' | 'review';
    sequence: number;
}
@Component({ selector: 'agp-zones-panel', standalone: true, imports: [ReactiveFormsModule, JsonPipe, ConfigHelp, ZoneLifecycle], templateUrl: './zones-panel.html' })
export class ZonesPanel {
    private readonly api = inject(ZonesApi);
    private sequence = 0;
    private loadingForm = false;
    private started = false;
    @Input({ required: true })
    access!: ConfigAccess;
    @Input()
    catalogs: CatalogSnapshot[] = [];
    @Input()
    revisions: Revision[] = [];
    @Output()
    manual = new EventEmitter<Topic>();
    readonly busy = signal(false);
    readonly lifecycleBusy = signal(false);
    readonly dirty = signal(false);
    readonly error = signal('');
    readonly issues = signal<Issue[]>([]);
    readonly notice = signal('');
    readonly conflict = signal(false);
    readonly pending = signal<PendingZone | null>(null);
    readonly openMembers = signal<ReadonlySet<string>>(new Set());
    readonly items = signal<ZoneRevision[]>([]);
    readonly cursor = signal('');
    readonly selected = signal<ZoneRevision | null>(null);
    readonly frozen = signal<ZonePreview | null>(null);
    readonly reviews = signal<AuthoringReview[]>([]);
    readonly reviewReason = new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.minLength(8), Validators.maxLength(1024)] });
    readonly filter = text();
    readonly selectedControl = text();
    readonly lookup = text();
    readonly previewLookup = text();
    readonly form = new FormGroup({ id: text('', true), name: text('', true), siteId: text('', true), ownerId: text('', true), policyRevisionId: text('', true), mode: new FormControl<'detection' | 'blocking'>('detection', { nonNullable: true }), membership: new FormControl<'ids' | 'labels' | 'default'>('ids', { nonNullable: true }), gatewayIds: text(), labels: text('{}'), reason: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.minLength(8), Validators.maxLength(1024)] }) });
    readonly previewForm = new FormGroup({ baseRevisionId: text('', true), catalogSnapshotId: text('', true), capacityProfile: new FormControl<'pilot-500' | 'fleet-10k'>('pilot-500', { nonNullable: true }), action: new FormControl<'reconcile' | 'retire'>('reconcile', { nonNullable: true }), replacementAssignments: text('[]') });
    constructor() {
        this.form.valueChanges.pipe(takeUntilDestroyed()).subscribe(() => { if (!this.loadingForm) {
            this.sequence++;
            this.dirty.set(true);
            this.frozen.set(null);
        } });
        this.selectedControl.valueChanges.pipe(takeUntilDestroyed()).subscribe(value => { if (value)
            void this.load(value); });
        effect(() => { this.selectedControl.setValue(this.selected()?.id ?? '', { emitEvent: false }); if (this.dirty() || this.pending() || this.busy() || this.lifecycleBusy())
            this.selectedControl.disable({ emitEvent: false });
        else
            this.selectedControl.enable({ emitEvent: false }); });
    }
    ngOnInit(): void { if (!this.started) {
        this.started = true;
        this.reset();
        const first = this.access.sites.find(site => site.read);
        if (!this.access.globalRead && first)
            this.filter.setValue(first.siteId);
        void this.list();
    } }
    canEdit(siteId = this.form.controls.siteId.value): boolean { return this.access.globalEdit || this.access.sites.some(site => site.siteId === siteId && site.edit); }
    async list(more = false): Promise<void> { this.busy.set(true); try {
        const page = await this.api.list(this.filter.value, more ? this.cursor() : '');
        this.items.set(more ? [...this.items(), ...page.items] : page.items);
        this.cursor.set(page.nextCursor ?? '');
        this.clearError();
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    async load(id: string): Promise<void> { if (this.dirty() || this.pending() || this.lifecycleBusy()) {
        this.notice.set('Сначала создайте версию или явно начните новый черновик. Локальный текст сохранён.');
        return;
    } this.busy.set(true); try {
        const revision = await this.api.revision(id);
        if (!revision.content)
            throw new ConfigError('invalid_response');
        this.install(revision);
        this.clearError();
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    reset(): void { if (this.pending() || this.lifecycleBusy())
        return; this.selected.set(null); this.frozen.set(null); this.conflict.set(false); this.loadingForm = true; this.form.reset({ id: `zone_${crypto.randomUUID().replaceAll('-', '').slice(0, 12)}`, name: 'Новая WAF-зона', siteId: this.filter.value || this.access.sites.find(site => site.edit)?.siteId || '', ownerId: this.access.principalId, policyRevisionId: '', mode: 'detection', membership: 'ids', gatewayIds: '', labels: '{}', reason: '' }, { emitEvent: false }); this.loadingForm = false; this.dirty.set(false); this.clearError(); this.notice.set('Новый локальный черновик. Версия появится только после явного сохранения.'); }
    private body(): WafZone {
        if (this.form.invalid)
            throw new ConfigError('invalid_zone_form');
        const value = this.form.getRawValue();
        let membership: WafZone['spec']['membership'];
        if (value.membership === 'ids') {
            const ids = value.gatewayIds.split(/[\s,]+/).filter(Boolean);
            if (!ids.length)
                throw new ConfigError('gateway_ids_required');
            membership = { gatewayIds: ids };
        }
        else if (value.membership === 'default')
            membership = { siteDefault: true };
        else {
            let labels: unknown;
            try {
                labels = JSON.parse(value.labels);
            }
            catch {
                throw new ConfigError('invalid_labels');
            }
            if (!labels || Array.isArray(labels) || typeof labels !== 'object' || Object.keys(labels).length === 0 || Object.values(labels).some(item => typeof item !== 'string'))
                throw new ConfigError('invalid_labels');
            membership = { matchLabels: labels as Record<string, string> };
        }
        return { apiVersion: 'agp.waf-zone/v1alpha1', kind: 'WafZone', metadata: { id: value.id, name: value.name, siteId: value.siteId, ownerId: value.ownerId }, spec: { policyRevisionId: value.policyRevisionId, mode: value.mode, membership, reason: value.reason } };
    }
    async save(): Promise<void> { if (this.pending() || this.busy() || this.lifecycleBusy() || !this.canEdit())
        return; try {
        const base = this.selected();
        const operation = mutation('/api/v2/waf/zone-revisions', { ...(base ? { baseRevisionId: base.id } : {}), content: this.body() });
        await this.execute({ operation, kind: 'revision', sequence: this.sequence });
    }
    catch (error) {
        this.fail(error);
    } }
    async preview(): Promise<void> { const revision = this.selected(); if (!revision || this.dirty() || this.pending() || this.previewForm.invalid)
        return; try {
        const value = this.previewForm.getRawValue();
        let replacements: unknown;
        try {
            replacements = JSON.parse(value.replacementAssignments);
        }
        catch {
            throw new ConfigError('invalid_replacement_assignments');
        }
        if (!Array.isArray(replacements))
            throw new ConfigError('invalid_replacement_assignments');
        const body: ZonePreviewRequest = { baseRevisionId: value.baseRevisionId, catalogSnapshotId: value.catalogSnapshotId, capacityProfile: value.capacityProfile, action: value.action, ...(replacements.length ? { replacementAssignments: replacements as {
                    gatewayId: string;
                    targetZoneRevisionId: string;
                }[] } : {}) };
        await this.execute({ operation: mutation(this.api.path('zone-revisions', revision.id) + '/previews', body), kind: 'preview', sequence: this.sequence });
    }
    catch (error) {
        this.fail(error);
    } }
    async loadPreview(): Promise<void> { this.busy.set(true); try {
        this.frozen.set(await this.api.preview(this.previewLookup.value));
        this.reviews.set(await this.api.reviews(this.previewLookup.value));
        this.clearError();
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    async useBase(): Promise<void> { if (this.pending() || this.busy() || this.lifecycleBusy())
        return; this.busy.set(true); try {
        const revision = await this.api.revision(this.lookup.value);
        if (revision.zoneId !== this.form.controls.id.value || revision.siteId !== this.form.controls.siteId.value)
            throw new ConfigError('zone_base_mismatch');
        this.selected.set(revision);
        this.conflict.set(false);
        this.clearError();
        this.notice.set('Base заменён явно. Все локальные поля сохранены; проверьте изменения и создайте версию.');
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    async review(): Promise<void> { const preview = this.frozen(); if (!preview || !this.canReview() || this.expired() || this.reviewReason.invalid || this.busy() || this.pending())
        return; await this.execute({ operation: mutation(this.api.path('zone-previews', preview.id) + '/authoring-reviews', { previewDigest: preview.previewDigest, reason: this.reviewReason.value }), kind: 'review', sequence: this.sequence }); }
    async refreshReviews(): Promise<void> { const preview = this.frozen(); if (!preview)
        return; this.busy.set(true); try {
        this.reviews.set(await this.api.reviews(preview.id));
        this.clearError();
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    async retry(): Promise<void> { const pending = this.pending(); if (pending && !this.busy())
        await this.execute(pending); }
    private async execute(pending: PendingZone): Promise<void> { this.busy.set(true); this.pending.set(pending); this.clearError(); try {
        const result = await this.api.write(pending.operation);
        if (pending.kind === 'revision') {
            const revision = this.api.decodeRevision(result);
            this.selected.set(revision);
            if (pending.sequence === this.sequence) {
                this.install(revision);
                this.notice.set('Создана неизменяемая authoring-версия ' + revision.id + '. Публикация не выполнена.');
            }
            else
                this.notice.set('Версия создана; более новые локальные изменения сохранены в форме.');
            await this.list();
        }
        else if (pending.kind === 'preview') {
            this.frozen.set(this.api.decodePreview(result));
            this.reviews.set([]);
            this.notice.set('Создан замороженный предпросмотр; публикация и применение не выполнялись.');
        }
        else {
            const review = this.api.decodeReview(result);
            this.reviews.set(await this.api.reviews(review.previewId));
            this.notice.set('Сохранён независимый draft_review. Публикация и применение не разрешены.');
        }
        this.pending.set(null);
    }
    catch (error) {
        this.fail(error);
        if (error instanceof ConfigError && error.status >= 400 && error.status < 500) {
            this.pending.set(null);
            if (error.status === 412) {
                this.conflict.set(true);
                this.notice.set('Head зоны изменился. Локальные поля сохранены; для продолжения выберите актуальную версию явно.');
            }
        }
        else
            this.notice.set('Результат запроса неизвестен. Повтор сохранит исходные body, base и Idempotency-Key.');
    }
    finally {
        this.busy.set(false);
    } }
    private install(revision: ZoneRevision): void { const zone = revision.content!; this.loadingForm = true; this.form.setValue({ id: zone.metadata.id, name: zone.metadata.name, siteId: zone.metadata.siteId, ownerId: zone.metadata.ownerId, policyRevisionId: zone.spec.policyRevisionId, mode: zone.spec.mode, membership: 'gatewayIds' in zone.spec.membership ? 'ids' : 'matchLabels' in zone.spec.membership ? 'labels' : 'default', gatewayIds: 'gatewayIds' in zone.spec.membership ? zone.spec.membership.gatewayIds.join('\n') : '', labels: JSON.stringify('matchLabels' in zone.spec.membership ? zone.spec.membership.matchLabels : {}, null, 2), reason: zone.spec.reason }, { emitEvent: false }); this.loadingForm = false; this.selected.set(revision); this.dirty.set(false); this.conflict.set(false); this.frozen.set(null); }
    download(): void { const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([JSON.stringify(this.form.getRawValue(), null, 2)], { type: 'application/json' })); link.download = 'agp-zone-local-fields.json'; link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000); }
    memberToggle(event: Event, key: string): void { const next = new Set(this.openMembers()); if ((event.target as HTMLDetailsElement).open)
        next.add(key);
    else
        next.delete(key); this.openMembers.set(next); }
    memberOpen(key: string): boolean { return this.openMembers().has(key); }
    canReview(): boolean { const preview = this.frozen(); return !!preview && this.canEdit(preview.siteId) && preview.authorId !== this.access.principalId; }
    stepUpURL(): string { return '/auth-ui/step-up?return=' + encodeURIComponent(location.pathname + location.search); }
    expired(): boolean { return !!this.frozen() && Date.parse(this.frozen()!.expiresAt) <= Date.now(); }
    @HostListener('window:beforeunload', ['$event'])
    beforeUnload(event: BeforeUnloadEvent): void { if (this.dirty() || this.pending()) {
        event.preventDefault();
        event.returnValue = '';
    } }
    private clearError(): void { this.error.set(''); this.issues.set([]); }
    private fail(error: unknown): void { this.error.set(error instanceof ConfigError ? error.code : 'request_failed'); this.issues.set(error instanceof ConfigError ? error.issues : []); }
}
