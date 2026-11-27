import { Component, DestroyRef, ElementRef, ViewChild, computed, effect, inject, input, output, signal, untracked } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { AbstractControl, FormControl, FormGroup, ReactiveFormsModule, ValidationErrors, Validators } from '@angular/forms';
import { HelpTip } from './help-tip';
import { HelpTopicId } from './help-topics';
import { Icon } from './icon';
import { EditableWaf, MATCH_FIELDS, WafDraft, WafEvent, WafException, WafMatchField, WafMode, WafResource, baselineFor, routeIdFor, sampleEvents } from './waf-data';

export type { WafResource } from './waf-data';
export interface WafChangeSummary { id: string; name: string; state: 'draft' | 'validated' | 'pending'; resourceId: string; summary: string }
type Stage = 'editing' | 'draft' | 'validated' | 'pending';
type Tab = 'policy' | 'events' | 'exceptions';
interface Difference { label: string; before: string; after: string }
interface StoredDraft { draft: WafDraft; stage: 'draft' | 'validated' | 'pending' }

const integer = (control: AbstractControl): ValidationErrors | null => Number.isInteger(control.value) ? null : { integer: true };
const nonblank = (control: AbstractControl): ValidationErrors | null => typeof control.value === 'string' && control.value.trim() ? null : { blank: true };
const reasonLength = (control: AbstractControl): ValidationErrors | null => {
  const length = String(control.value ?? '').trim().length;
  return length >= 8 && length <= 1024 ? null : { reasonLength: true };
};
const ruleIdsValidator = (control: AbstractControl): ValidationErrors | null => {
  const ids = String(control.value ?? '').split(',').map((part) => part.trim());
  return ids.length >= 1 && ids.length <= 50 && ids.every((id) => /^[0-9]{6,9}$/.test(id)) && new Set(ids).size === ids.length ? null : { ruleIds: true };
};
const parseUtc = (value: string): number => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value) ? Date.parse(`${value}:00Z`) : NaN;
function timeWindow(control: AbstractControl): ValidationErrors | null {
  const review = parseUtc(String(control.get('reviewAt')?.value ?? ''));
  const expires = parseUtc(String(control.get('expiresAt')?.value ?? ''));
  return Number.isFinite(review) && Number.isFinite(expires) && review > Date.now() && expires > review ? null : { timeWindow: true };
}
function clone<T>(value: T): T { return structuredClone(value); }
function freezeSnapshot<T extends object>(value: T): T {
  Object.freeze(value);
  for (const child of Object.values(value)) if (child && typeof child === 'object' && !Object.isFrozen(child)) freezeSnapshot(child);
  return value;
}

@Component({
  selector: 'agp-waf-panel', standalone: true,
  imports: [ReactiveFormsModule, HelpTip, Icon],
  templateUrl: './waf-panel.html', styleUrl: './waf-panel.css',
})
export class WafPanel {
  readonly resources = input<WafResource[]>([]);
  readonly initialResourceId = input<string>('gw-zabbix');
  readonly manual = output<HelpTopicId>();
  readonly change = output<WafChangeSummary>();
  @ViewChild('discardDialog') private discardDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('exceptionEditor') private exceptionEditor?: ElementRef<HTMLElement>;

  readonly matchFields = MATCH_FIELDS;
  readonly selectedId = signal('');
  readonly resource = computed(() => this.resources().find((item) => item.id === this.selectedId()) ?? null);
  readonly routeId = computed(() => routeIdFor(this.selectedId()));
  readonly tab = signal<Tab>('policy');
  readonly active = signal<EditableWaf | null>(null);
  readonly exceptions = signal<WafException[]>([]);
  readonly stage = signal<Stage>('editing');
  readonly saved = signal<WafDraft | null>(null);
  readonly notice = signal('');
  readonly error = signal('');
  readonly exceptionOpen = signal(false);
  readonly expandedEvent = signal<string | null>(null);
  readonly eventSearch = signal('');
  readonly events = signal<WafEvent[]>([]);
  readonly formVersion = signal(0);
  readonly exceptionVersion = signal(0);
  readonly hasPolicyChanges = computed(() => {
    this.formVersion();
    return this.active() !== null && JSON.stringify(this.currentValues()) !== JSON.stringify(this.active());
  });
  readonly differences = computed(() => {
    this.formVersion();
    return this.diff(this.active(), this.currentValues());
  });
  readonly savedIsCurrent = computed(() => {
    this.formVersion();
    return this.saved() !== null && JSON.stringify(this.saved()!.values) === JSON.stringify(this.currentValues());
  });
  readonly unsaved = computed(() => {
    this.formVersion(); this.exceptionVersion();
    const baseline = this.saved()?.values ?? this.active();
    return (baseline !== null && JSON.stringify(this.currentValues()) !== JSON.stringify(baseline)) || (this.exceptionOpen() && this.exceptionForm.dirty);
  });
  readonly filteredEvents = computed(() => {
    const needle = this.eventSearch().toLocaleLowerCase('ru').trim();
    return this.events().filter((event) => !needle || `${event.id} ${event.ruleId} ${event.category} ${event.path} ${event.match.field} ${event.match.name}`.toLocaleLowerCase('ru').includes(needle));
  });
  readonly removedExceptions = computed(() => (this.active()?.exceptions ?? []).filter((item) => !this.exceptions().some((candidate) => candidate.id === item.id)));
  readonly expiredActiveExceptions = computed(() => (this.active()?.exceptions ?? []).filter((item) => Date.parse(item.expiresAt) <= Date.now()));

  readonly form = new FormGroup({
    mode: new FormControl<WafMode>('detection', { nonNullable: true, validators: [Validators.required] }),
    paranoiaLevel: new FormControl(1, { nonNullable: true, validators: [Validators.required, integer, Validators.min(1), Validators.max(4)] }),
    inboundAnomalyThreshold: new FormControl(5, { nonNullable: true, validators: [Validators.required, integer, Validators.min(1), Validators.max(100)] }),
    outboundAnomalyThreshold: new FormControl(4, { nonNullable: true, validators: [Validators.required, integer, Validators.min(1), Validators.max(100)] }),
  });
  readonly exceptionForm = new FormGroup({
    ruleIds: new FormControl('942100', { nonNullable: true, validators: [Validators.required, ruleIdsValidator] }),
    field: new FormControl<WafMatchField>('query_arg', { nonNullable: true, validators: [Validators.required] }),
    name: new FormControl('q', { nonNullable: true, validators: [Validators.required, Validators.maxLength(128), Validators.pattern(/^[A-Za-z0-9_.-]+$/)] }),
    reason: new FormControl('', { nonNullable: true, validators: [Validators.required, nonblank, reasonLength] }),
    reviewAt: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    expiresAt: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  }, { validators: timeWindow });

  private readonly destroyRef = inject(DestroyRef);
  private readonly startedAt = Date.now();
  private readonly baselines = new Map<string, EditableWaf>();
  private readonly drafts = new Map<string, StoredDraft>();
  private readonly submitted = new Map<string, WafDraft>();
  private requestedInput = '';
  private pendingResourceId: string | null = null;
  private pendingDraftId: string | null = null;
  private discardAction: 'resource' | 'exception' | 'draft' = 'resource';
  private nextDraft = 1051;
  private nextException = 1;
  private discardedTrigger: HTMLElement | null = null;

  constructor() {
    this.form.valueChanges.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => this.editChanged());
    this.exceptionForm.valueChanges.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => this.exceptionVersion.update((value) => value + 1));
    effect(() => {
      const resources = this.resources();
      const requested = this.initialResourceId();
      if (!resources.length) return;
      untracked(() => {
        if (requested !== this.requestedInput || !this.resource()) {
          this.requestedInput = requested;
          this.requestResource(resources.some((item) => item.id === requested) ? requested : resources[0].id);
        }
      });
    });
  }

  value(event: Event): string { return (event.target as HTMLInputElement | HTMLSelectElement).value; }
  modeLabel(mode: WafMode): string { return mode === 'blocking' ? 'Блокировка' : 'Наблюдение'; }
  stageLabel(stage: Stage): string { return { editing: 'Редактирование', draft: 'Черновик', validated: 'Проверено локально', pending: 'На согласовании' }[stage]; }
  dateLabel(value: string): string { return new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'short', timeZone: 'UTC' }).format(new Date(value)) + ' UTC'; }
  fieldLabel(value: WafMatchField): string { return MATCH_FIELDS.find((field) => field.value === value)?.label ?? value; }
  invalid(field: 'paranoiaLevel' | 'inboundAnomalyThreshold' | 'outboundAnomalyThreshold'): boolean { return this.form.controls[field].invalid && this.form.controls[field].touched; }
  exceptionInvalid(field: keyof typeof this.exceptionForm.controls): boolean { return this.exceptionForm.controls[field].invalid && this.exceptionForm.controls[field].touched; }
  isActiveException(id: string): boolean { return !!this.active()?.exceptions.some((item) => item.id === id); }
  expired(exception: WafException): boolean { return Date.parse(exception.expiresAt) <= Date.now(); }
  eventOutcome(event: WafEvent): string { return event.outcome === 'blocked' ? 'Отклонено WAF · пример' : 'Записано WAF, не заблокировано WAF'; }
  reviewOverdue(exception: WafException): boolean { return !this.expired(exception) && Date.parse(exception.reviewAt) <= Date.now(); }
  tabKeydown(event: KeyboardEvent): void {
    const tabs: Tab[] = ['policy', 'events', 'exceptions'];
    const current = tabs.indexOf(this.tab());
    const index = event.key === 'ArrowRight' ? (current + 1) % tabs.length : event.key === 'ArrowLeft' ? (current + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : -1;
    if (index < 0) return;
    event.preventDefault(); this.tab.set(tabs[index]);
    (event.currentTarget as HTMLElement).querySelectorAll<HTMLButtonElement>('[role="tab"]')[index]?.focus();
  }

  openResource(id: string): void { this.requestResource(id); }

  chooseResource(event: Event): void {
    const select = event.target as HTMLSelectElement;
    const requested = select.value;
    select.value = this.selectedId();
    this.requestResource(requested);
  }
  private requestResource(id: string): void {
    if (id === this.selectedId()) return;
    if (this.unsaved() && this.discardDialog) {
      this.pendingResourceId = id;
      this.discardAction = 'resource';
      this.discardedTrigger = document.activeElement as HTMLElement;
      this.discardDialog.nativeElement.showModal();
      return;
    }
    this.loadResource(id);
  }
  private loadResource(id: string): void {
    const resource = this.resources().find((item) => item.id === id);
    if (!resource) return;
    this.selectedId.set(id);
    if (!this.baselines.has(id)) this.baselines.set(id, freezeSnapshot(baselineFor(resource, this.startedAt)));
    const baseline = clone(this.baselines.get(id)!);
    this.active.set(baseline);
    const stored = this.drafts.get(id);
    const values = stored?.draft.values ?? baseline;
    this.form.enable({ emitEvent: false });
    this.form.reset({ mode: values.mode, paranoiaLevel: values.paranoiaLevel, inboundAnomalyThreshold: values.inboundAnomalyThreshold, outboundAnomalyThreshold: values.outboundAnomalyThreshold }, { emitEvent: false });
    this.exceptions.set(clone(values.exceptions));
    this.saved.set(stored?.draft ?? null);
    this.stage.set(stored?.stage ?? 'editing');
    if (stored?.stage === 'pending') this.form.disable({ emitEvent: false });
    this.closeExceptionEditor();
    this.events.set(sampleEvents(resource, this.startedAt));
    this.expandedEvent.set(null); this.eventSearch.set('');
    this.error.set(''); this.notice.set('');
    this.formVersion.update((version) => version + 1);
  }
  cancelDiscard(): void { this.pendingResourceId = null; this.pendingDraftId = null; this.discardDialog?.nativeElement.close(); this.discardedTrigger?.focus(); }
  confirmDiscard(): void {
    this.discardDialog?.nativeElement.close();
    if (this.discardAction === 'exception') this.closeExceptionEditor();
    else if (this.discardAction === 'draft' && this.pendingDraftId) this.loadDraft(this.pendingDraftId);
    else if (this.pendingResourceId) this.loadResource(this.pendingResourceId);
    this.pendingResourceId = null;
    this.pendingDraftId = null;
    this.discardedTrigger?.focus();
  }

  private currentValues(): EditableWaf { return { ...this.form.getRawValue(), exceptions: clone(this.exceptions()) }; }
  openDraft(id: string): void {
    const exists = this.submitted.has(id) || [...this.drafts.values()].some((item) => item.draft.id === id);
    if (!exists || (this.saved()?.id === id && !this.unsaved())) return;
    if (this.unsaved() && this.discardDialog) {
      this.pendingDraftId = id; this.discardAction = 'draft'; this.discardedTrigger = document.activeElement as HTMLElement;
      this.discardDialog.nativeElement.showModal();
      return;
    }
    this.loadDraft(id);
  }
  private loadDraft(id: string): void {
    const submitted = this.submitted.get(id);
    const stored = [...this.drafts.values()].find((item) => item.draft.id === id);
    const draft = submitted ?? stored?.draft;
    if (!draft) return;
    this.loadResource(draft.resourceId);
    this.form.enable({ emitEvent: false });
    this.form.reset({ mode: draft.values.mode, paranoiaLevel: draft.values.paranoiaLevel, inboundAnomalyThreshold: draft.values.inboundAnomalyThreshold, outboundAnomalyThreshold: draft.values.outboundAnomalyThreshold }, { emitEvent: false });
    this.exceptions.set(clone(draft.values.exceptions)); this.saved.set(draft);
    this.stage.set(submitted ? 'pending' : stored!.stage);
    if (submitted) this.form.disable({ emitEvent: false });
    this.tab.set('policy'); this.formVersion.update((version) => version + 1);
  }
  private editChanged(): void {
    this.formVersion.update((version) => version + 1);
    this.error.set(''); this.notice.set('');
    if (this.stage() === 'validated' && !this.savedIsCurrent()) {
      this.stage.set('draft');
      const draft = this.saved();
      if (draft) { this.drafts.set(draft.resourceId, { draft, stage: 'draft' }); this.emitChange(draft, 'draft', 'Редакция изменена: сохраните и проверьте заново.'); }
    }
  }
  private diff(before: EditableWaf | null, after: EditableWaf): Difference[] {
    if (!before) return [];
    const differences: Difference[] = [];
    if (before.mode !== after.mode) differences.push({ label: 'Режим в назначении ресурса', before: this.modeLabel(before.mode), after: this.modeLabel(after.mode) });
    if (before.paranoiaLevel !== after.paranoiaLevel) differences.push({ label: 'Уровень paranoia', before: String(before.paranoiaLevel), after: String(after.paranoiaLevel) });
    if (before.inboundAnomalyThreshold !== after.inboundAnomalyThreshold) differences.push({ label: 'Порог входящих запросов', before: String(before.inboundAnomalyThreshold), after: String(after.inboundAnomalyThreshold) });
    if (before.outboundAnomalyThreshold !== after.outboundAnomalyThreshold) differences.push({ label: 'Порог ответов', before: String(before.outboundAnomalyThreshold), after: String(after.outboundAnomalyThreshold) });
    for (const item of after.exceptions.filter((exception) => !before.exceptions.some((old) => old.id === exception.id))) differences.push({ label: `Добавить исключение ${item.id}`, before: 'Нет исключения', after: `${item.ruleIds.join(', ')} · ${item.routeId} · ${item.match.field}.${item.match.name} · до ${this.dateLabel(item.expiresAt)}` });
    for (const item of before.exceptions.filter((exception) => !after.exceptions.some((current) => current.id === exception.id))) differences.push({ label: `Удалить исключение ${item.id}`, before: `${item.ruleIds.join(', ')} · ${item.match.field}.${item.match.name}`, after: 'После применения новой ревизии' });
    return differences;
  }

  saveDraft(): void {
    if (this.stage() === 'pending') return;
    this.form.markAllAsTouched();
    if (this.form.invalid) { this.error.set('Проверьте параметры политики: допускаются только целые числа в указанных диапазонах.'); return; }
    if (!this.hasPolicyChanges()) return;
    if (this.exceptionOpen() && this.exceptionForm.dirty) { this.error.set('Сначала добавьте подготовленное исключение в черновик или отмените его создание.'); return; }
    const resource = this.resource();
    if (!resource) return;
    const old = this.saved();
    const id = old?.id ?? `WAF-${this.nextDraft++}`;
    const policyId = `waf_${resource.id.replace(/-/g, '_')}_${id.toLowerCase().replace(/-/g, '_')}`;
    const values = this.currentValues();
    const draft = freezeSnapshot<WafDraft>({
      id, resourceId: resource.id, resourceName: resource.name, domain: resource.domain, nodes: [...resource.nodes],
      baseRevision: resource.revision, basePolicyId: `waf_${resource.id.replace(/^gw-/, '')}_v1`,
      gatewayBinding: { resourceId: resource.id, mode: values.mode, policyRef: policyId },
      policy: {
        apiVersion: 'agp.waf/v1alpha1', kind: 'WafPolicy',
        metadata: { id: policyId, name: `CRS · ${resource.name}`, siteId: resource.nodes.some((node) => node.includes('spb')) ? 'site_spb' : 'site_msk' },
        spec: { engine: 'modsecurity', rulesetVersionId: 'crs_qualified_001', paranoiaLevel: values.paranoiaLevel, inboundAnomalyThreshold: values.inboundAnomalyThreshold, outboundAnomalyThreshold: values.outboundAnomalyThreshold, exceptions: clone(values.exceptions) },
      },
      values: clone(values), savedAt: new Date().toISOString(),
    });
    this.saved.set(draft); this.stage.set('draft');
    this.drafts.set(resource.id, { draft, stage: 'draft' });
    this.form.markAsPristine();
    this.emitChange(draft, 'draft');
    this.error.set(''); this.notice.set('Демонстрационный черновик сохранён в памяти вкладки. Действующая политика не менялась.');
  }
  validateDraft(): void {
    const draft = this.saved();
    if (!draft || !this.savedIsCurrent() || this.stage() !== 'draft') return;
    this.exceptionForm.updateValueAndValidity({ emitEvent: false });
    const now = Date.now();
    const exceptionsValid = draft.values.exceptions.length <= 100 && draft.values.exceptions.every((item) => item.routeId === routeIdFor(draft.resourceId) && item.reason.trim().length >= 8 && item.reason.trim().length <= 1024 && Date.parse(item.expiresAt) > now && Date.parse(item.expiresAt) > Date.parse(item.reviewAt) && (this.isActiveException(item.id) || Date.parse(item.reviewAt) > now));
    if (this.form.invalid || !exceptionsValid) { this.error.set('Проверка не пройдена: проверьте диапазоны, маршрут и будущие сроки исключений. Просроченные исключения удалите новой редакцией.'); return; }
    this.stage.set('validated'); this.drafts.set(draft.resourceId, { draft, stage: 'validated' });
    this.emitChange(draft, 'validated');
    this.error.set(''); this.notice.set('Локально проверены форма, scope и сроки. Nginx, совместимость модулей, probes и реальное согласование в макете не выполняются.');
  }
  requestApproval(): void {
    const draft = this.saved();
    if (!draft || !this.savedIsCurrent() || this.stage() !== 'validated') return;
    if (draft.values.exceptions.some((item) => Date.parse(item.expiresAt) <= Date.now() || Date.parse(item.expiresAt) <= Date.parse(item.reviewAt) || (!this.isActiveException(item.id) && Date.parse(item.reviewAt) <= Date.now()))) {
      this.stage.set('draft'); this.drafts.set(draft.resourceId, { draft, stage: 'draft' }); this.emitChange(draft, 'draft');
      this.error.set('Срок исключения изменился с момента проверки. Подготовьте новую редакцию и проверьте её заново.');
      return;
    }
    const snapshot = freezeSnapshot(clone(draft));
    this.submitted.set(snapshot.id, snapshot);
    this.saved.set(snapshot); this.stage.set('pending');
    this.drafts.set(snapshot.resourceId, { draft: snapshot, stage: 'pending' });
    this.form.disable({ emitEvent: false }); this.closeExceptionEditor();
    this.emitChange(snapshot, 'pending');
    this.notice.set('Зафиксирована отдельная демонстрационная редакция для согласования вторым инженером. Отправка не включает блокировку и не меняет узлы.');
  }
  startSuccessor(): void {
    if (this.stage() !== 'pending') return;
    this.saved.set(null); this.stage.set('editing'); this.form.enable({ emitEvent: false });
    this.notice.set('Создаётся новая редакция. Ранее отправленный снимок остаётся неизменным.');
    this.formVersion.update((version) => version + 1);
  }
  private emitChange(draft: WafDraft, state: 'draft' | 'validated' | 'pending', summary?: string): void {
    this.change.emit({ id: draft.id, name: `WAF · ${draft.resourceName}`, state, resourceId: draft.resourceId, summary: summary ?? `${this.modeLabel(draft.gatewayBinding.mode)} · PL ${draft.policy.spec.paranoiaLevel} · ${draft.nodes.join(', ')} · база ${draft.baseRevision}` });
  }

  openException(event?: WafEvent): void {
    if (this.stage() === 'pending') return;
    if (this.exceptionOpen() && this.exceptionForm.dirty) { this.notice.set('Сначала завершите или отмените уже открытое исключение.'); this.tab.set('exceptions'); return; }
    this.tab.set('exceptions'); this.exceptionOpen.set(true);
    this.exceptionForm.reset({ ruleIds: event?.ruleId ?? '942100', field: event?.match.field ?? 'query_arg', name: event?.match.name ?? 'q', reason: '', reviewAt: new Date(Date.now() + 86_400_000).toISOString().slice(0, 16), expiresAt: new Date(Date.now() + 2 * 86_400_000).toISOString().slice(0, 16) });
    this.exceptionVersion.update((version) => version + 1);
    this.error.set(''); this.notice.set(event ? `Событие ${event.id}: скопированы только правило, маршрут и имя поля. Проверьте причину и сроки.` : 'Новое исключение затронет только выбранный маршрут и указанное поле.');
    setTimeout(() => { this.exceptionEditor?.nativeElement.scrollIntoView({ block: 'start', behavior: 'smooth' }); this.exceptionEditor?.nativeElement.focus(); }, 0);
  }
  cancelException(): void {
    if (this.exceptionForm.dirty && this.discardDialog) {
      this.discardAction = 'exception'; this.discardedTrigger = document.activeElement as HTMLElement;
      this.discardDialog.nativeElement.showModal();
    } else this.closeExceptionEditor();
  }
  private closeExceptionEditor(): void { this.exceptionOpen.set(false); this.exceptionForm.reset(); this.exceptionVersion.update((version) => version + 1); }
  addException(): void {
    if (this.stage() === 'pending') return;
    this.exceptionForm.updateValueAndValidity({ emitEvent: false });
    this.exceptionForm.markAllAsTouched();
    if (this.exceptionForm.invalid) { this.error.set('Исправьте поля исключения. Срок пересмотра должен быть в будущем и раньше окончания.'); return; }
    if (this.exceptions().length >= 100) { this.error.set('В одной политике допускается не более 100 исключений.'); return; }
    const values = this.exceptionForm.getRawValue();
    const ruleIds = values.ruleIds.split(',').map((id) => id.trim());
    if (this.exceptions().some((item) => item.routeId === this.routeId() && item.match.field === values.field && item.match.name === values.name && item.ruleIds.join(',') === ruleIds.join(','))) { this.error.set('Такое исключение уже есть в этой редакции.'); return; }
    const exception: WafException = {
      id: `exception_demo_${this.nextException++}`, routeId: this.routeId(), ruleIds,
      match: { field: values.field, name: values.name }, ownerId: 'usr_engineer_demo', reason: values.reason.trim(),
      reviewAt: new Date(parseUtc(values.reviewAt)).toISOString(), expiresAt: new Date(parseUtc(values.expiresAt)).toISOString(),
    };
    this.exceptions.update((items) => [...items, exception]);
    this.closeExceptionEditor(); this.editChanged();
    this.notice.set('Исключение добавлено в редактируемую политику. Сохраните черновик, проверьте diff и запросите согласование.');
  }
  removeException(id: string): void {
    if (this.stage() === 'pending') return;
    this.exceptions.update((items) => items.filter((item) => item.id !== id)); this.editChanged();
    this.notice.set('Удаление подготовлено в новой редакции. Действующее исключение сохраняется до согласования и применения.');
  }
  restoreException(item: WafException): void {
    if (this.stage() === 'pending' || this.exceptions().length >= 100) return;
    this.exceptions.update((items) => [...items, clone(item)]); this.editChanged();
  }
}
