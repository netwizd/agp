import { Component, ElementRef, HostListener, inject, input, output } from '@angular/core';
export const topics = {
    'waf-policy': { title:'Базовая WAF-политика', text:'Stable ID объединяет неизменяемые ревизии одного Site. Точная версия ruleset, PL и thresholds входят в content digest. Здесь поддерживается exceptions=[]; derivation и локальные исключения требуют отдельного квалифицированного процесса.' },
    'waf-tuning': { title:'PL и anomaly thresholds', text:'Paranoia level 1–4 определяет строгость правил. Пороги inbound/outbound задаются целыми значениями 1–100. Изменение создаёт новую ревизию, которая проходит native validation и независимое approval.' },
    'waf-qualification': { title:'Native qualification', text:'Validation фиксирует точные ruleset/profile/tuple/evidence/compiler digests и срок. Актуальность проверяется сервером повторно. Stale или expired qualification не разрешает approval и publication.' },
    'waf-approval': { title:'Approval и publication', text:'Отдельное config.approve и свежая MFA требуются другому человеку для подтверждения exact digest. Publication создаёт версию политики; она не меняет configuration head, назначения зон или live WAF на узлах.' },

    zones: { title: 'WAF-зоны', text: 'Зона объединяет шлюзы одного Site: явные ID, AND по меткам или Site default. Каждое сохранение создаёт неизменяемую authoring-версию в состоянии draft; права каталога не заменяют права Site.' },
    'zone-preview': { title: 'Замороженный предпросмотр зоны', text: 'Укажите точные baseConfigRevisionId, catalogSnapshotId, capacity и action. Результат фиксирует участников, узлы, digests и срок действия. Membership является hypothetical_authoring_membership, публикация не выполнена.' },
    'draft-review': { title: 'Независимый draft_review', text: 'Автор и reviewer — разные люди с текущими правами редактирования по Site. Review связывается с точным preview digest и сроком. Отзыв прав или изменение входов делает его stale. Этот маркер не разрешает публикацию.' }, snapshot: { title: 'Полный снимок', text: 'Форма, JSON и YAML описывают одну конфигурацию. Все шлюзы и назначения входят в один снимок. Комментарии YAML не сохраняются в канонической модели.' }, draft: { title: 'Черновик и ревизия', text: 'Черновик сохраняется автоматически с проверкой версии. Кнопка «Создать ревизию» фиксирует неизменяемый снимок. Конфликт не перезаписывает локальный текст.' }, catalog: { title: 'Каталог и входные данные', text: 'Каталог объявлен оператором. Его наличие не подтверждает подключение узлов, квалификацию компонентов или работоспособность сертификатов.' }, preview: { title: 'Предварительная проверка', text: 'Проверка показывает ошибки, закреплённые digests, изменения и полные предложения для узлов. Этот этап не применяет конфигурацию и не перезагружает Nginx.' }, gateway: { title: 'Шлюз и маршруты', text: 'Укажите Site, выбор узлов, точные версии профиля компонентов, сертификата и WAF. Маршруты используют центральную авторизацию с закрытым отказом и проверкой TLS upstream.' } } as const;
export type Topic = keyof typeof topics;
@Component({ selector: 'agp-config-help', standalone: true, template: `<details class="help"><summary [attr.aria-label]="'Справка: '+topic().title">?</summary><section><strong>{{topic().title}}</strong><p>{{topic().text}}</p><a href="#manual" (click)="open($event)">Открыть руководство</a></section></details>` })
export class ConfigHelp {
    private element = inject<ElementRef<HTMLElement>>(ElementRef);
    @HostListener('document:keydown.escape', ['$event'])
    escape(event: Event): void { const details = this.element.nativeElement.querySelector('details'); if (details?.open) {
        details.open = false;
        this.element.nativeElement.querySelector('summary')?.focus();
        event.preventDefault();
    } }
    @HostListener('document:pointerdown', ['$event'])
    outside(event: PointerEvent): void { if (!this.element.nativeElement.contains(event.target as Node)) {
        const details = this.element.nativeElement.querySelector('details');
        if (details)
            details.open = false;
    } }
    topicId = input.required<Topic>();
    manual = output<Topic>();
    topic = () => topics[this.topicId()];
    open(event: Event): void { event.preventDefault(); const details = this.element.nativeElement.querySelector('details'); if (details)
        details.open = false; this.manual.emit(this.topicId()); }
}
