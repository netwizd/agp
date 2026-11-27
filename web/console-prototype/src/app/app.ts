import { Component, ElementRef, HostListener, ViewChild, computed, signal } from '@angular/core';
import { AbstractControl, FormControl, FormGroup, ReactiveFormsModule, ValidationErrors, Validators } from '@angular/forms';
import { Icon, IconName } from './icon';
import { HelpTip } from './help-tip';
import { HELP_TOPICS, HelpTopic, HelpTopicId } from './help-topics';
import { WafPanel } from './waf-panel';

type Section = 'overview' | 'gateways' | 'waf' | 'identity' | 'changes' | 'events' | 'manual';
type GatewayState = 'healthy' | 'attention' | 'unknown';
type WafMode = 'detection' | 'blocking';
type ChangeState = 'draft' | 'validated' | 'pending' | 'applied';
interface GatewayValues { name: string; domain: string; upstream: string; site: string; accessGroup: string; directory: boolean; mfa: boolean; waf: WafMode; }
interface Gateway extends GatewayValues { id: string; nodes: string[]; state: GatewayState; revision: string; lastSeen: string; }
interface Change { id: string; name: string; status: ChangeState; resourceId: string | null; values: GatewayValues; base: GatewayValues | null; createdAt: string; }
interface AuditEvent { id: string; kind: 'info' | 'warning' | 'success'; title: string; detail: string; time: string; actor: string; }
interface Difference { label: string; before: string; after: string; }
interface WafChangeSummary { id: string; name: string; state: 'draft' | 'validated' | 'pending'; resourceId: string; summary: string; }

const EMPTY_GATEWAY: GatewayValues = { name: '', domain: '', upstream: '', site: 'Москва · DC-1', accessGroup: 'AGP-Employees', directory: true, mfa: true, waf: 'detection' };
const GATEWAYS: Gateway[] = [
  { id: 'gw-portal', name: 'Корпоративный портал', domain: 'portal.nlgate.ru', upstream: 'https://portal.internal:8443', site: 'Москва · DC-1', accessGroup: 'AGP-Employees', directory: true, mfa: true, waf: 'blocking', nodes: ['edge-msk-01', 'edge-msk-02'], state: 'healthy', revision: 'r-1042', lastSeen: '12 секунд назад' },
  { id: 'gw-gitlab', name: 'GitLab', domain: 'git.nlgate.ru', upstream: 'https://gitlab.internal:443', site: 'Москва · DC-1', accessGroup: 'AGP-Developers', directory: true, mfa: true, waf: 'blocking', nodes: ['edge-msk-01', 'edge-msk-02'], state: 'healthy', revision: 'r-1042', lastSeen: '15 секунд назад' },
  { id: 'gw-zabbix', name: 'Zabbix', domain: 'monitor.nlgate.ru', upstream: 'https://zabbix.internal:443', site: 'Москва · DC-1', accessGroup: 'AGP-Engineers', directory: true, mfa: true, waf: 'detection', nodes: ['edge-msk-02'], state: 'attention', revision: 'r-1041', lastSeen: '18 секунд назад' },
  { id: 'gw-helpdesk', name: 'Service Desk', domain: 'help.nlgate.ru', upstream: 'https://helpdesk.internal:443', site: 'Санкт-Петербург · DC-2', accessGroup: 'AGP-Employees', directory: true, mfa: true, waf: 'detection', nodes: ['edge-spb-01', 'edge-spb-02'], state: 'healthy', revision: 'r-1042', lastSeen: '9 секунд назад' },
  { id: 'gw-grafana', name: 'Grafana', domain: 'grafana.nlgate.ru', upstream: 'https://grafana.internal:3000', site: 'Санкт-Петербург · DC-2', accessGroup: 'AGP-Engineers', directory: true, mfa: true, waf: 'blocking', nodes: ['edge-spb-01', 'edge-spb-02'], state: 'healthy', revision: 'r-1042', lastSeen: '11 секунд назад' },
  { id: 'gw-wiki', name: 'База знаний', domain: 'wiki.nlgate.ru', upstream: 'https://wiki.internal:443', site: 'Москва · DC-1', accessGroup: 'AGP-Employees', directory: true, mfa: true, waf: 'detection', nodes: ['edge-msk-03'], state: 'unknown', revision: 'r-1040', lastSeen: '7 минут назад' },
];

function upstreamValidator(control: AbstractControl<string>): ValidationErrors | null {
  if (!control.value) return null;
  try {
    const url = new URL(control.value);
    return ['http:', 'https:'].includes(url.protocol) && url.hostname && !url.username && !url.password && !url.search && !url.hash ? null : { upstream: true };
  } catch { return { upstream: true }; }
}

@Component({
  selector: 'agp-app', standalone: true,
  imports: [ReactiveFormsModule, Icon, HelpTip, WafPanel],
  templateUrl: './app.html', styleUrl: './app.css',
})
export class App {
  @ViewChild('editorDialog') editorDialog!: ElementRef<HTMLDialogElement>;
  @ViewChild('manualDialog') manualDialog!: ElementRef<HTMLDialogElement>;
  @ViewChild('discardDialog') discardDialog!: ElementRef<HTMLDialogElement>;
  @ViewChild(WafPanel) wafPanel!: WafPanel;

  readonly nav: { id: Section; label: string; icon: IconName }[] = [
    { id: 'overview', label: 'Обзор', icon: 'grid' },
    { id: 'gateways', label: 'Шлюзы и ресурсы', icon: 'gateway' },
    { id: 'waf', label: 'WAF и защита', icon: 'shield' },
    { id: 'identity', label: 'Доступ и AD', icon: 'shield' },
    { id: 'changes', label: 'Изменения', icon: 'changes' },
    { id: 'events', label: 'События', icon: 'events' },
    { id: 'manual', label: 'Руководство', icon: 'book' },
  ];
  readonly sites = ['Москва · DC-1', 'Санкт-Петербург · DC-2'];
  readonly accessGroups = ['AGP-Employees', 'AGP-Developers', 'AGP-Engineers'];
  readonly topics = Object.values(HELP_TOPICS);
  section = signal<Section>('gateways');
  mobileNav = signal(false);
  search = signal('');
  stateFilter = signal('all');
  siteFilter = signal('all');
  manualSearch = signal('');
  gateways = signal<Gateway[]>(GATEWAYS);
  wafResourceId = signal('gw-zabbix');
  wafChanges = signal<WafChangeSummary[]>([]);
  filteredGateways = computed(() => this.gateways().filter((gateway) => {
    const needle = this.search().toLocaleLowerCase('ru').trim();
    return (!needle || `${gateway.name} ${gateway.domain} ${gateway.nodes.join(' ')}`.toLocaleLowerCase('ru').includes(needle))
      && (this.stateFilter() === 'all' || gateway.state === this.stateFilter())
      && (this.siteFilter() === 'all' || gateway.site === this.siteFilter());
  }));
  filteredTopics = computed(() => {
    const needle = this.manualSearch().toLocaleLowerCase('ru').trim();
    return this.topics.filter((topic) => `${topic.title} ${topic.short} ${topic.category}`.toLocaleLowerCase('ru').includes(needle));
  });
  currentGateway = signal<Gateway | null>(null);
  editorMode = signal<'details' | 'edit' | 'preview'>('details');
  currentChangeId = signal<string | null>(null);
  currentChange = computed(() => this.changes().find((change) => change.id === this.currentChangeId()) ?? null);
  activeManual = signal<HelpTopic>(HELP_TOPICS.central_auth);
  notice = signal('');
  adTesting = signal(false);
  adResult = signal(false);
  editorError = signal('');
  private editorTrigger: HTMLElement | null = null;
  private manualTrigger: HTMLElement | null = null;
  private hashBeforeManual = '#/gateways';
  private initialValues = EMPTY_GATEWAY;
  private nextChangeId = 1050;
  private pendingWafResourceId: string | null = null;

  form = new FormGroup({
    name: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.minLength(3), Validators.maxLength(80)] }),
    domain: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.pattern(/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/)] }),
    upstream: new FormControl('', { nonNullable: true, validators: [Validators.required, upstreamValidator] }),
    site: new FormControl(EMPTY_GATEWAY.site, { nonNullable: true, validators: [Validators.required] }),
    accessGroup: new FormControl(EMPTY_GATEWAY.accessGroup, { nonNullable: true, validators: [Validators.required] }),
    directory: new FormControl(true, { nonNullable: true }),
    mfa: new FormControl(true, { nonNullable: true }),
    waf: new FormControl<WafMode>('detection', { nonNullable: true }),
  });

  changes = signal<Change[]>([
    { id: 'CH-1049', name: 'Группа доступа к Zabbix', status: 'pending', resourceId: GATEWAYS[2].id, values: { ...GATEWAYS[2], accessGroup: 'AGP-Developers' }, base: GATEWAYS[2], createdAt: 'Сегодня, 14:32' },
    { id: 'CH-1048', name: 'Upstream корпоративного портала', status: 'validated', resourceId: GATEWAYS[0].id, values: { ...GATEWAYS[0], upstream: 'https://portal-v2.internal:8443' }, base: GATEWAYS[0], createdAt: 'Сегодня, 13:40' },
    { id: 'CH-1047', name: 'Группа доступа к Grafana', status: 'draft', resourceId: GATEWAYS[4].id, values: { ...GATEWAYS[4], accessGroup: 'AGP-Developers' }, base: GATEWAYS[4], createdAt: 'Сегодня, 12:18' },
    { id: 'CH-1042', name: 'Обновление политики портала', status: 'applied', resourceId: GATEWAYS[0].id, values: GATEWAYS[0], base: { ...GATEWAYS[0], waf: 'detection' }, createdAt: 'Вчера, 17:05' },
  ]);
  events = signal<AuditEvent[]>([
    { id: 'ev-1', kind: 'warning', title: 'Нет свежих данных от edge-msk-03', detail: 'База знаний · последнее подтверждение 7 минут назад', time: '14:38', actor: 'Контроль состояния' },
    { id: 'ev-2', kind: 'info', title: 'Изменение CH-1049 ожидает согласования', detail: 'Zabbix · группа доступа: AGP-Engineers → AGP-Developers', time: '14:32', actor: 'Алексей Иванов' },
    { id: 'ev-3', kind: 'warning', title: 'Ревизия Zabbix отличается от целевой', detail: 'edge-msk-02 · r-1041 → r-1042', time: '14:21', actor: 'Сверка конфигурации' },
    { id: 'ev-4', kind: 'success', title: 'Подтверждена доступность каталога AD', detail: 'Пример события · corp.nlgate.ru · LDAPS', time: '14:20', actor: 'Служба идентификации' },
    { id: 'ev-5', kind: 'success', title: 'Ревизия r-1042 применена', detail: 'Пример события · 4 узла · контрольные проверки завершены', time: 'Вчера', actor: 'Мария Петрова' },
  ]);

  constructor() {
    this.readHash();
    // The first hash can refer to a manual topic; wait until native dialogs exist.
    if (window.location.hash.startsWith('#/manual/')) setTimeout(() => this.readHash(), 0);
  }
  sectionLabel(): string { return this.nav.find((item) => item.id === this.section())?.label ?? 'Шлюзы и ресурсы'; }
  value(event: Event): string { return (event.target as HTMLInputElement | HTMLSelectElement).value; }
  statusLabel(state: GatewayState): string { return { healthy: 'В норме', attention: 'Требует внимания', unknown: 'Нет данных' }[state]; }
  changeLabel(state: ChangeState): string { return { draft: 'Черновик', validated: 'Проверено', pending: 'На согласовании', applied: 'Применено' }[state]; }
  wafLabel(mode: WafMode): string { return mode === 'blocking' ? 'Блокировка' : 'Наблюдение'; }
  countPending(): number { return this.changes().filter((change) => change.status === 'pending').length + this.wafChanges().filter((change) => change.state === 'pending').length; }
  initials(name: string): string { return name.split(' ').map((word) => word[0]).slice(0, 2).join(''); }
  invalid(field: keyof GatewayValues): boolean { const control = this.form.controls[field]; return control.invalid && control.touched; }

  navigate(section: Section): void {
    this.section.set(section); this.mobileNav.set(false); this.search.set('');
    window.location.hash = `/${section}`;
    window.scrollTo({ top: 0, behavior: 'instant' });
  }
  openWaf(resourceId: string, fromEditor = false): void {
    if (fromEditor && this.editorMode() === 'edit' && this.form.dirty) {
      this.pendingWafResourceId = resourceId;
      this.discardDialog.nativeElement.showModal(); return;
    }
    if (fromEditor) this.finishCloseEditor();
    this.navigate('waf'); this.wafPanel.openResource(resourceId);
  }
  receiveWafChange(change: WafChangeSummary): void {
    this.wafChanges.update((all) => [change, ...all.filter((item) => item.id !== change.id)]);
  }
  openWafChange(change: WafChangeSummary): void {
    this.navigate('waf');
    this.wafPanel.openDraft(change.id);
  }
  @HostListener('window:hashchange') readHash(): void {
    const parts = window.location.hash.replace(/^#\//, '').split('/');
    const section = parts[0] as Section;
    if (this.nav.some((item) => item.id === section)) this.section.set(section);
    if (section === 'waf' && parts[1] && this.gateways().some((gateway) => gateway.id === parts[1])) this.wafResourceId.set(parts[1]);
    if (section === 'manual' && parts[1] && parts[1] in HELP_TOPICS && this.manualDialog) {
      this.activeManual.set(HELP_TOPICS[parts[1] as HelpTopicId]);
      if (!this.manualDialog.nativeElement.open) this.manualDialog.nativeElement.showModal();
    } else if (this.manualDialog?.nativeElement.open && !parts[1]) {
      this.manualDialog.nativeElement.close();
    }
  }
  showGateway(gateway: Gateway): void {
    this.editorTrigger = document.activeElement as HTMLElement;
    this.currentGateway.set(gateway); this.currentChangeId.set(null); this.editorMode.set('details'); this.editorError.set('');
    this.resetForm(gateway); this.editorDialog.nativeElement.showModal();
  }
  createGateway(): void {
    this.editorTrigger = document.activeElement as HTMLElement;
    this.currentGateway.set(null); this.currentChangeId.set(null); this.editorMode.set('edit'); this.editorError.set('');
    this.resetForm(EMPTY_GATEWAY); this.editorDialog.nativeElement.showModal();
  }
  beginEdit(): void { this.editorMode.set('edit'); }
  resetForm(values: GatewayValues): void {
    const { name, domain, upstream, site, accessGroup, directory, mfa, waf } = values;
    this.initialValues = { name, domain, upstream, site, accessGroup, directory, mfa, waf };
    this.form.reset(this.initialValues); this.editorError.set('');
  }
  closeEditor(event?: Event): void {
    event?.preventDefault();
    if (this.editorMode() === 'edit' && this.form.dirty) { this.discardDialog.nativeElement.showModal(); return; }
    this.finishCloseEditor();
  }
  cancelDiscard(): void { this.pendingWafResourceId = null; this.discardDialog.nativeElement.close(); }
  discardChanges(): void {
    const wafResourceId = this.pendingWafResourceId; this.pendingWafResourceId = null;
    this.discardDialog.nativeElement.close(); this.finishCloseEditor();
    if (wafResourceId) this.openWaf(wafResourceId);
  }
  private finishCloseEditor(): void {
    this.editorDialog.nativeElement.close(); this.form.markAsPristine(); this.editorTrigger?.focus();
  }
  backdrop(event: MouseEvent, dialog: 'editor' | 'manual'): void {
    if (event.target !== event.currentTarget) return;
    const target = event.currentTarget as HTMLDialogElement; const rect = target.getBoundingClientRect();
    if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) {
      if (dialog === 'manual') this.closeManual(); else this.closeEditor();
    }
  }
  saveDraft(): void {
    this.form.markAllAsTouched(); this.editorError.set('');
    if (this.form.invalid) {
      this.editorError.set('Проверьте выделенные поля. Черновик ещё не сохранён.');
      queueMicrotask(() => this.editorDialog.nativeElement.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus()); return;
    }
    const values = this.form.getRawValue();
    const duplicate = this.gateways().some((gateway) => gateway.domain.toLocaleLowerCase() === values.domain.toLocaleLowerCase() && gateway.id !== this.currentGateway()?.id);
    if (duplicate) { this.editorError.set('Этот домен уже используется другим ресурсом. Укажите уникальный домен.'); return; }
    const existing = this.currentChange();
    const id = existing && ['draft', 'validated'].includes(existing.status) ? existing.id : `CH-${this.nextChangeId++}`;
    const change: Change = { id, name: `${this.currentGateway() ? 'Изменение' : 'Создание'}: ${values.name}`, status: 'draft', resourceId: this.currentGateway()?.id ?? null, values, base: this.currentGateway() ? this.initialValues : null, createdAt: 'Только что' };
    this.changes.update((all) => [change, ...all.filter((item) => item.id !== id)]);
    this.currentChangeId.set(id); this.editorMode.set('preview'); this.form.markAsPristine();
    this.notice.set(`Черновик ${id} сохранён в памяти демо. Действующая конфигурация не изменена.`);
  }
  openChange(change: Change): void {
    this.editorTrigger = document.activeElement as HTMLElement;
    this.currentGateway.set(this.gateways().find((gateway) => gateway.id === change.resourceId) ?? null);
    this.currentChangeId.set(change.id); this.resetForm(change.values); this.initialValues = change.base ?? EMPTY_GATEWAY;
    this.editorMode.set('preview'); this.editorDialog.nativeElement.showModal();
  }
  differences(): Difference[] {
    const change = this.currentChange(); if (!change) return [];
    const labels: Record<keyof GatewayValues, string> = { name: 'Название', domain: 'Публичный домен', upstream: 'Внутреннее приложение', site: 'Площадка', accessGroup: 'Группа доступа', directory: 'Корпоративный каталог AD', mfa: 'Обязательная 2FA', waf: 'Режим WAF' };
    return (Object.keys(labels) as (keyof GatewayValues)[]).filter((field) => !change.base || change.base[field] !== change.values[field]).map((field) => ({
      label: labels[field], before: change.base ? this.formatValue(field, change.base[field]) : 'Не задано', after: this.formatValue(field, change.values[field]),
    }));
  }
  private formatValue(field: keyof GatewayValues, value: string | boolean): string {
    if (typeof value === 'boolean') return value ? 'Обязательно' : 'Отключено';
    return field === 'waf' ? this.wafLabel(value as WafMode) : value;
  }
  validateDraft(): void {
    const id = this.currentChangeId(); if (this.currentChange()?.status !== 'draft') return;
    this.changes.update((all) => all.map((change) => change.id === id ? { ...change, status: 'validated' } : change));
    this.notice.set('Демо: формат полей проверен локально. Серверная проверка Nginx, сети и сертификатов не выполнялась.');
  }
  requestApproval(): void {
    const id = this.currentChangeId(); if (this.currentChange()?.status !== 'validated') return;
    this.changes.update((all) => all.map((change) => change.id === id ? { ...change, status: 'pending' } : change));
    this.events.update((all) => [{ id: `ev-${id}`, kind: 'info', title: `${id}: демо-запрос согласования`, detail: 'Изменение сохранено только в памяти браузера. Уведомление не отправлено.', time: 'Сейчас', actor: 'Вы · инженер' }, ...all]);
    this.notice.set(`${id}: показан этап согласования. Запрос в реальную систему не отправлен.`);
  }
  openManual(topicId: HelpTopicId, event?: Event): void {
    event?.preventDefault(); this.manualTrigger = document.activeElement as HTMLElement;
    this.hashBeforeManual = window.location.hash.startsWith('#/manual/') ? '#/manual' : window.location.hash || '#/gateways';
    this.activeManual.set(HELP_TOPICS[topicId]);
    window.history.replaceState(null, '', `#/manual/${topicId}`);
    if (!this.manualDialog.nativeElement.open) this.manualDialog.nativeElement.showModal();
    this.manualDialog.nativeElement.querySelector<HTMLElement>('.dialog-close')?.focus();
  }
  closeManual(event?: Event): void {
    event?.preventDefault(); this.manualDialog.nativeElement.close();
    window.history.replaceState(null, '', this.hashBeforeManual); this.manualTrigger?.focus();
  }
  demoAdTest(): void {
    if (this.adTesting()) return;
    this.adTesting.set(true); this.adResult.set(false);
    setTimeout(() => { this.adTesting.set(false); this.adResult.set(true); }, 650);
  }
  resetFilters(): void { this.search.set(''); this.stateFilter.set('all'); this.siteFilter.set('all'); }
}
