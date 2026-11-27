import { Component, ElementRef, HostListener, inject, input, output, signal } from '@angular/core';
import { HELP_TOPICS, HelpTopicId } from './help-topics';

let nextHelpId = 0;

@Component({
  selector: 'agp-help', standalone: true,
  template: `
    <button type="button" class="help-button" [attr.aria-label]="'Справка: ' + topic().title"
      [attr.aria-expanded]="opened()" [attr.aria-controls]="id" (click)="show()" (focus)="onFocus($event)"><span aria-hidden="true">?</span></button>
    @if (opened()) {
      <section class="help-popover" role="dialog" [id]="id" [attr.aria-label]="topic().title"
        [style.top.px]="top()" [style.left.px]="left()">
        <div class="help-heading"><strong>{{ topic().title }}</strong><button type="button" class="help-close" aria-label="Закрыть справку" (click)="close(true)">×</button></div>
        <p>{{ topic().short }}</p>
        <a [href]="'#/manual/' + topicId()" (click)="readManual($event)">Открыть в руководстве <span aria-hidden="true">→</span></a>
      </section>
    }
  `,
  styles: `
    :host { display:inline-flex; position:relative; vertical-align:middle; margin:-7px -5px -7px 0 }
    .help-button { display:grid; place-items:center; width:32px; height:32px; padding:0; border:0; border-radius:7px; color:#68788f; background:transparent; font:600 11px/1 inherit; cursor:pointer }
    .help-button span { display:grid; place-items:center; width:16px; height:16px; border:1px solid #9ba8ba; border-radius:50%; font-size:11px }
    .help-button:hover,.help-button[aria-expanded="true"] { color:#4058cc; background:#eef1ff }
    .help-button:hover span,.help-button[aria-expanded="true"] span { border-color:#4058cc }
    .help-popover { position:fixed; z-index:40; width:min(320px,calc(100vw - 32px)); padding:17px 18px; border:1px solid #dfe5ef; border-radius:12px; background:white; color:#26344d; box-shadow:0 12px 36px #15244b25; font-size:13px; font-weight:400; line-height:1.6; text-align:left }
    .help-heading { display:flex; gap:12px; align-items:flex-start; justify-content:space-between }
    .help-heading strong { font-size:13px; line-height:1.5 }
    .help-close { border:0; border-radius:4px; background:transparent; color:#708096; font-size:20px; line-height:1; cursor:pointer }
    p { margin:9px 0 13px }
    a { color:#4058cc; font-weight:600; text-decoration:none }
    a:hover { text-decoration:underline }
    @media(pointer:coarse) { .help-button { width:44px;height:44px } :host { margin:-13px -8px -13px 0 } }
  `,
})
export class HelpTip {
  topicId = input.required<HelpTopicId>();
  manual = output<HelpTopicId>();
  opened = signal(false);
  top = signal(0);
  left = signal(0);
  id = `agp-help-${++nextHelpId}`;
  private element = inject<ElementRef<HTMLElement>>(ElementRef);
  private suppressNextFocus = false;
  topic = () => HELP_TOPICS[this.topicId()];

  show(): void {
    const rect = this.element.nativeElement.getBoundingClientRect();
    this.left.set(Math.max(16, Math.min(rect.left - 8, window.innerWidth - 336)));
    this.top.set(rect.bottom + 9 < window.innerHeight - 230 ? rect.bottom + 9 : Math.max(16, rect.top - 218));
    this.opened.set(true);
  }
  onFocus(event: FocusEvent): void {
    if (this.suppressNextFocus) { this.suppressNextFocus = false; return; }
    if ((event.target as HTMLElement).matches(':focus-visible')) this.show();
  }
  close(returnFocus = false): void {
    this.opened.set(false);
    if (returnFocus) { this.suppressNextFocus = true; this.element.nativeElement.querySelector('button')?.focus(); }
  }
  readManual(event: Event): void {
    event.preventDefault();
    this.close(true);
    this.manual.emit(this.topicId());
    // Native dialog closing restores focus to this persistent trigger. Do not
    // immediately reopen the help popover when the manual returns that focus.
    this.suppressNextFocus = true;
  }
  @HostListener('document:pointerdown', ['$event']) outside(event: PointerEvent): void {
    if (!this.element.nativeElement.contains(event.target as Node)) this.close();
  }
  @HostListener('document:keydown.escape', ['$event']) escape(event: Event): void {
    if (this.opened()) { event.preventDefault(); event.stopPropagation(); this.close(true); }
  }
  @HostListener('window:resize') resize(): void { this.close(); }
}
