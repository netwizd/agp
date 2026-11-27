import { Injectable, inject, signal } from '@angular/core';
import { ConfigApi, ConfigError, Mutation, mutation } from './config-api';
import { CatalogSnapshot, Configuration, DocumentFormat, Draft, Issue, Me, Report, Revision, emptyConfiguration, ConfigAccess } from './contracts';
export type EditorMode = 'form' | DocumentFormat;
interface Pending {
    operation: Mutation;
    kind: 'save' | 'seal';
    sequence: number;
}
@Injectable({ providedIn: 'root' })
export class ConfigStore {
    readonly api = inject(ConfigApi);
    readonly ready = signal(false);
    readonly busy = signal(false);
    readonly saving = signal(false);
    readonly parsing = signal(false);
    readonly me = signal<Me | null>(null);
    readonly access = signal<ConfigAccess | null>(null);
    readonly enabled = signal(false);
    readonly head = signal('');
    readonly revisions = signal<Revision[]>([]);
    readonly nextCursor = signal('');
    readonly catalogs = signal<CatalogSnapshot[]>([]);
    readonly catalogId = signal('');
    readonly content = signal<Configuration>(emptyConfiguration());
    readonly draft = signal<Draft | null>(null);
    readonly selectedRevision = signal<Revision | null>(null);
    readonly mode = signal<EditorMode>('form');
    readonly document = signal('');
    readonly dirty = signal(false);
    readonly error = signal('');
    readonly issues = signal<Issue[]>([]);
    readonly notice = signal('');
    readonly conflict = signal(false);
    readonly pending = signal<Pending | null>(null);
    readonly report = signal<Report | null>(null);
    private sequence = 0;
    private parseSequence = 0;
    private validatedDocument = "";
    private timer: ReturnType<typeof setTimeout> | undefined;
    async start(): Promise<void> {
        this.busy.set(true);
        try {
            const session = await this.api.bootstrap();
            this.me.set(session.me);
            this.access.set(session.access);
            if (!session.access.globalRead) { this.ready.set(true); return; }
            await this.refresh();
            const id = new URL(location.href).searchParams.get('draft');
            if (id) {
                const draft = await this.api.draft(id);
                this.installDraft(draft);
            }
            else if (this.head()) {
                await this.loadRevision(this.head());
            }
            else {
                this.document.set(this.json());
                this.notice.set('Создайте первый полный снимок конфигурации.');
            }
            this.ready.set(true);
        }
        catch (error) {
            this.fail(error);
            if (error instanceof ConfigError && error.status === 401)
                location.assign('/auth-ui/login?return=' + encodeURIComponent('/config-ui/'));
        }
        finally {
            this.busy.set(false);
        }
    }
    async refresh(): Promise<void> { const [profile, revisions, catalogs] = await Promise.all([this.api.profile(), this.api.revisions(), this.api.catalogs()]); this.enabled.set(profile.enabled); this.head.set(profile.headRevisionId ?? ''); this.revisions.set(revisions.items); this.nextCursor.set(revisions.nextCursor ?? ''); this.catalogs.set(catalogs); }
    async moreRevisions(): Promise<void> { this.busy.set(true); try {
        const page = await this.api.revisions(this.nextCursor());
        this.revisions.update(items => [...items, ...page.items]);
        this.nextCursor.set(page.nextCursor ?? '');
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    async loadRevision(id: string): Promise<void> { if (this.dirty() || this.pending())
        return; this.busy.set(true); try {
        const value = await this.api.revision(id);
        if (!value.content)
            throw new ConfigError('invalid_response');
        this.content.set(structuredClone(value.content));
        this.selectedRevision.set(value);
        this.draft.set(null);
        this.document.set(this.json());
        this.report.set(null);
        this.clearError();
        this.setDraftURL('');
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    changed(value: Configuration): void { if (!this.access()?.globalEdit) return; this.content.set(value); this.edit(); if (this.mode() !== 'yaml')
        this.document.set(this.json()); this.schedule(); }
    rawChanged(value: string): void { if (!this.access()?.globalEdit) return; this.document.set(value); this.edit(); clearTimeout(this.timer); const sequence = ++this.parseSequence; this.timer = setTimeout(() => void this.parseRaw(sequence, true), 600); }
    private edit(): void { this.sequence++; this.dirty.set(true); this.report.set(null); this.notice.set('Есть несохранённые изменения.'); if (!this.conflict() && !this.pending())
        this.clearError(); }
    private schedule(): void { clearTimeout(this.timer); this.timer = setTimeout(() => void this.save(), 700); }
    async switchMode(mode: EditorMode): Promise<void> {
        if (mode === this.mode())
            return;
        if (!this.access()?.globalEdit) { if (mode !== 'yaml') { this.mode.set(mode); this.document.set(this.json()); } return; }
        clearTimeout(this.timer);
        if (this.mode() !== 'form' && !await this.parseRaw(++this.parseSequence, false))
            return;
        if (mode === 'form') {
            this.mode.set(mode);
            if (this.dirty())
                this.schedule();
            return;
        }
        this.parsing.set(true);
        try {
            const parsed = await this.api.parse(this.json(), 'json');
            this.document.set(mode === 'json' ? JSON.stringify(parsed.content, null, 2) : parsed.yaml);
            this.content.set(parsed.content);
            this.mode.set(mode);
            if (this.dirty())
                this.schedule();
        }
        catch (error) {
            this.fail(error);
        }
        finally {
            this.parsing.set(false);
        }
    }
    private async parseRaw(sequence: number, autosave: boolean): Promise<boolean> {
        if (this.mode() === 'form')
            return true;
        const text = this.document(), format = this.mode() as DocumentFormat;
        this.parsing.set(true);
        try {
            const parsed = await this.api.parse(text, format);
            if (sequence !== this.parseSequence || text !== this.document())
                return false;
            this.content.set(parsed.content);
            this.validatedDocument = text;
            this.clearError();
            if (autosave)
                await this.save();
            return true;
        }
        catch (error) {
            if (sequence === this.parseSequence)
                this.fail(error);
            return false;
        }
        finally {
            if (sequence === this.parseSequence)
                this.parsing.set(false);
        }
    }
    async save(): Promise<boolean> {
        if (!this.access()?.globalEdit) return false;
        clearTimeout(this.timer);
        if (this.saving() || this.conflict() || this.pending())
            return false;
        if (!this.dirty())
            return true;
        if (this.mode() !== 'form' && this.validatedDocument !== this.document() && !await this.parseRaw(++this.parseSequence, false))
            return false;
        const current = this.draft();
        const body = current ? { content: this.content() } : { ...(this.head() ? { baseRevisionId: this.head() } : {}), content: this.content() };
        const operation = current ? mutation(this.api.path('drafts', current.id), body, current.revision, 'PUT') : mutation('/api/v2/config/drafts', body);
        return this.execute({ operation, kind: 'save', sequence: this.sequence });
    }
    async retry(): Promise<void> { const pending = this.pending(); if (pending && !this.saving())
        await this.execute(pending); }
    private async execute(pending: Pending): Promise<boolean> {
        this.saving.set(true);
        this.pending.set(pending);
        this.clearError();
        try {
            const result = this.api.decodeSnapshot(await this.api.write(pending.operation));
            this.pending.set(null);
            if (pending.kind === 'save') {
                const draft = result as Draft;
                this.draft.set(draft);
                this.selectedRevision.set(null);
                this.setDraftURL(draft.id);
                if (pending.sequence === this.sequence) {
                    this.dirty.set(false);
                    this.notice.set('Черновик сохранён. Версия ' + draft.revision + '.');
                }
                else {
                    this.notice.set('Сохранена предыдущая версия; новые изменения ожидают сохранения.');
                    this.schedule();
                }
            }
            else {
                this.selectedRevision.set(result as Revision);
                this.draft.set(null);
                this.setDraftURL('');
                if (pending.sequence === this.sequence) {
                    this.dirty.set(false);
                    this.content.set(structuredClone(result.content!));
                    this.document.set(this.json());
                    this.notice.set('Создана неизменяемая ревизия ' + result.id + '.');
                }
                else {
                    this.notice.set('Ревизия создана. Новые локальные изменения ожидают отдельного черновика.');
                }
                await this.refresh();
                if (this.dirty())
                    this.schedule();
            }
            return true;
        }
        catch (error) {
            this.fail(error);
            if (error instanceof ConfigError && error.status >= 400 && error.status < 500) {
                this.pending.set(null);
                if (error.status === 412) {
                    this.conflict.set(true);
                    this.notice.set('Конфликт версий. Локальный текст сохранён в редакторе.');
                }
            }
            else
                this.notice.set('Результат записи неизвестен. Повторите исходный запрос; ключ и содержимое сохранены.');
            return false;
        }
        finally {
            this.saving.set(false);
        }
    }
    async seal(): Promise<void> {
        if (!this.access()?.globalEdit) return; if (this.mode() !== 'form' && !await this.parseRaw(++this.parseSequence, false))
        return; if (this.dirty() && !await this.save())
        return; const draft = this.draft(); if (!draft)
        return; await this.execute({ operation: mutation(this.api.path('drafts', draft.id) + '/revisions', {}, draft.revision), kind: 'seal', sequence: this.sequence }); }
    async forkLocal(): Promise<void> {
        if (this.pending() || this.saving())
            return;
        this.busy.set(true);
        try {
            const profile = await this.api.profile();
            this.head.set(profile.headRevisionId ?? '');
            this.draft.set(null);
            this.selectedRevision.set(null);
            this.conflict.set(false);
            this.clearError();
            this.dirty.set(true);
            this.sequence++;
            this.setDraftURL('');
            await this.save();
        }
        catch (error) {
            this.fail(error);
        }
        finally {
            this.busy.set(false);
        }
    }
    async preview(): Promise<void> { if (this.mode() !== 'form' && !await this.parseRaw(++this.parseSequence, false))
        return; if (this.dirty() && !await this.save())
        return; const draft = this.draft(); if (!draft)
        return; this.busy.set(true); try {
        this.report.set(await this.api.preview(draft.id, this.catalogId()));
        this.clearError();
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    async validate(): Promise<void> { const revision = this.selectedRevision(); if (!revision || this.dirty())
        return; this.busy.set(true); try {
        this.report.set(await this.api.validate(revision.id));
        this.clearError();
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    async importCatalog(text: string, format: DocumentFormat): Promise<void> { this.busy.set(true); try {
        const catalog = await this.api.importCatalog(text, format);
        this.catalogs.set(await this.api.catalogs());
        this.catalogId.set(catalog.id);
        this.report.set(null);
        this.notice.set('Объявленный оператором каталог импортирован.');
        this.clearError();
    }
    catch (error) {
        this.fail(error);
    }
    finally {
        this.busy.set(false);
    } }
    download(): void { const text = this.mode() === 'form' ? this.json() : this.document(); const ext = this.mode() === 'yaml' ? 'yaml' : 'json'; const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' })); link.download = `agp-configuration.${ext}`; link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000); }
    private installDraft(value: Draft): void { this.draft.set(value); this.content.set(structuredClone(value.content)); this.document.set(this.json()); this.dirty.set(false); this.setDraftURL(value.id); }
    private setDraftURL(id: string): void { const url = new URL(location.href); if (id)
        url.searchParams.set('draft', id);
    else
        url.searchParams.delete('draft'); history.replaceState(null, '', url.pathname + url.search); }
    private json(): string { return JSON.stringify(this.content(), null, 2); }
    private clearError(): void { this.error.set(''); this.issues.set([]); }
    private fail(error: unknown): void { this.error.set(error instanceof ConfigError ? error.code : 'request_failed'); this.issues.set(error instanceof ConfigError ? error.issues : []); }
}
