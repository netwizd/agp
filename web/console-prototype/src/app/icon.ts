import { Component, input } from '@angular/core';

export type IconName = 'grid' | 'gateway' | 'shield' | 'changes' | 'events' | 'book' | 'search' | 'chevron' | 'arrow' | 'plus' | 'close' | 'check' | 'external' | 'clock' | 'menu' | 'server' | 'users' | 'lock' | 'filter' | 'activity' | 'refresh';

const paths: Record<IconName, string> = {
  grid: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  gateway: 'M4 4h16v16H4z M4 9h16 M9 9v11 M7 6.5h.01 M10 6.5h.01 M13 6.5h.01',
  shield: 'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z M9 12l2 2 4-4',
  changes: 'M7 7h13l-4-4 M20 7l-4 4 M17 17H4l4 4 M4 17l4-4',
  events: 'M5 3h14v18H5z M8 7h8 M8 11h8 M8 15h5',
  book: 'M12 5c-3-2-6-2-10-1v15c4-1 7-1 10 1 3-2 6-2 10-1V4c-4-1-7-1-10 1z M12 5v15',
  search: 'M21 21l-5-5 M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0',
  chevron: 'm9 5 7 7-7 7',
  arrow: 'M4 12h16 M14 6l6 6-6 6',
  plus: 'M12 5v14 M5 12h14',
  close: 'm6 6 12 12 M18 6 6 18',
  check: 'm5 12 4 4 10-10',
  external: 'M14 3h7v7 M21 3 10 14 M10 3H3v18h18v-7',
  clock: 'M12 8v5l3 2 M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',
  menu: 'M4 6h16 M4 12h16 M4 18h16',
  server: 'M3 3h18v7H3z M3 14h18v7H3z M7 6.5h.01 M7 17.5h.01 M11 6.5h6 M11 17.5h6',
  users: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M16 3a4 4 0 0 1 0 8 M22 21v-2a4 4 0 0 0-3-3.87 M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0',
  lock: 'M5 10h14v11H5z M8 10V7a4 4 0 0 1 8 0v3 M12 14v3',
  filter: 'M4 5h16 M7 12h10 M10 19h4',
  activity: 'M2 12h4l3-8 5 16 3-8h5',
  refresh: 'M20 7a9 9 0 1 0 1 8 M20 3v5h-5',
};

@Component({
  selector: 'agp-icon',
  standalone: true,
  template: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path [attr.d]="path()" /></svg>',
  styles: ':host { display:inline-flex; width:20px; height:20px; flex-shrink:0; vertical-align:middle } svg { width:100%;height:100% }',
})
export class Icon {
  name = input<IconName>('gateway');
  path = () => paths[this.name()];
}
