import { Component, DestroyRef, HostListener, inject, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ConfigError, Mutation, mutation } from './config-api';
import { ExecutionApi, ExecutionInput, ExecutionPlan, ExecutionView, executionID } from './execution-api';

const identifier = () => new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.pattern(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/)] });
interface Pending { kind: 'create' | 'rollback' | 'approve' | 'dispatch' | 'cancel'; operation: Mutation; plan?: ExecutionPlan; }

@Component({ selector: 'agp-execution-panel', standalone: true, imports: [ReactiveFormsModule], templateUrl: './execution-panel.html' })
export class ExecutionPanel {
    private readonly api = inject(ExecutionApi);
    private destroyed = false;
    private timer: ReturnType<typeof setTimeout> | undefined;
    private readonly clock = signal(Date.now());
    readonly busy = signal(false);
    readonly error = signal('');
    readonly status = signal(0);
    readonly notice = signal('');
    readonly loaded = signal<ExecutionView | null>(null);
    readonly pending = signal<Pending | null>(null);
    readonly rollbackParent = signal<ExecutionPlan | null>(null);
    readonly lookup = identifier();
    readonly confirmedDigest = new FormControl(false, { nonNullable: true });
    readonly confirmedDispatch = new FormControl(false, { nonNullable: true });
    readonly form = new FormGroup({ siteId: identifier(), revisionId: identifier(), nodeIds: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.maxLength(65000)] }), reason: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.maxLength(1024)] }) });
    constructor() { inject(DestroyRef).onDestroy(() => { this.destroyed = true; clearTimeout(this.timer); }); }
    blocked(): boolean { return this.busy() || !!this.pending(); }
    current(): boolean { this.clock(); const v = this.loaded(); return !!v && v.current && Date.parse(v.plan.expiresAt) > Date.now(); }
    canApprove(): boolean { return !this.blocked() && this.current() && this.loaded()?.access?.approve === true && this.confirmedDigest.value; }
    canDispatch(): boolean { this.clock(); const v = this.loaded(); return !this.blocked() && this.current() && v?.access?.dispatch === true && !!v.approval && Date.parse(v.approval.expiresAt) > Date.now() && this.confirmedDispatch.value; }
    nodeIDs(value: string): string[] {
        const values = value.trim().split(/[\s,]+/).filter(Boolean);
        if (!values.length || values.length > 500 || !values.every(executionID) || new Set(values).size !== values.length) throw new ConfigError('invalid_target_nodes');
        return values.sort();
    }
    canCreate(): boolean {
        if (this.blocked() || this.form.invalid) return false;
        const reason = this.form.controls.reason.value;
        if (reason.trim().length < 8 || new TextEncoder().encode(reason).length > 4096 || /[\u0000-\u001f\u007f]/.test(reason)) return false;
        try { this.nodeIDs(this.form.controls.nodeIds.value); return true; } catch { return false; }
    }
    async load(): Promise<void> {
        if (this.blocked() || !executionID(this.lookup.value)) return;
        const id = this.lookup.value;
        this.busy.set(true); this.clearError(); this.invalidate();
        try { const view = await this.api.load(id); if (!this.destroyed) { this.install(view); this.notice.set('Состояние и доступ проверены сервером.'); } }
        catch (error) { this.loaded.set(null); this.fail(error); }
        finally { this.busy.set(false); }
    }
    async create(): Promise<void> {
        if (!this.canCreate()) return;
        const fields = this.form.getRawValue(), nodes = this.nodeIDs(fields.nodeIds), parent = this.rollbackParent();
        const input: ExecutionInput = { siteId: fields.siteId, revisionId: fields.revisionId, nodeIds: nodes, rolloutPolicy: { canaryNodeIds: nodes.slice(0, 1), maxParallel: 1, maxUnavailable: 1, observationSeconds: 60, failureAction: 'pause' }, reason: fields.reason, expiresAt: new Date(Date.now() + 20 * 60000).toISOString() };
        await this.execute({ kind: parent ? 'rollback' : 'create', ...(parent ? { plan: parent } : {}), operation: mutation(parent ? this.api.path(parent.id) + '/rollback-plans' : this.api.path(), input) });
    }
    async approve(): Promise<void> { if (this.canApprove()) { const plan = this.loaded()!.plan; await this.execute({ kind: 'approve', plan, operation: mutation(this.api.path(plan.id) + '/approvals', { planDigest: plan.planDigest }) }); } }
    async dispatch(): Promise<void> { if (this.canDispatch()) { const plan = this.loaded()!.plan; await this.execute({ kind: 'dispatch', plan, operation: mutation(this.api.path(plan.id) + '/dispatch', { planDigest: plan.planDigest }) }); } }
    async cancel(): Promise<void> { const view = this.loaded(); if (!this.blocked() && view?.access?.cancel === true) await this.execute({ kind: 'cancel', plan: view.plan, operation: mutation(this.api.path(view.plan.id) + '/cancel', {}) }); }
    prepareRollback(): void {
        const view = this.loaded(); if (this.blocked() || view?.access?.rollback !== true) return;
        // Preserve any unsaved authoring fields; the user explicitly supplies
        // the captured base revision and exact node set for the new plan.
        this.rollbackParent.set(view.plan);
        this.notice.set('Укажите исходную ревизию и те же узлы. Откат создаёт новый план и требует нового независимого согласования.');
        document.getElementById('executionRevision')?.focus();
    }
    reset(): void { if (this.blocked()) return; this.form.reset(); this.rollbackParent.set(null); this.notice.set('Поля нового плана очищены.'); }
    async retry(): Promise<void> { const p = this.pending(); if (p && !this.busy()) await this.execute(p); }
    stateLabel(state: string): string { return ({ validated: 'Ждёт согласования', approved: 'Согласован', running: 'Выполняется', dispatched: 'Задание выдано, результат ожидается', succeeded: 'Применено, проверки пройдены', failed: 'Ошибка; дальнейшее применение остановлено', recovered: 'Исходное состояние восстановлено', cancelled: 'Выдача новых заданий отменена', recovery_required: 'Нужно восстановление: состояние узла не подтверждено' } as Record<string, string>)[state] ?? 'Неизвестное состояние'; }
    errorText(): string {
        return ({ execution_disabled: 'Применение ещё не подключено на этом сервере.', execution_source_unavailable: 'Не удалось подтвердить исходное состояние или готовность выбранных узлов. Обновите состояние и повторите проверку.', execution_precondition_changed: 'Исходные данные или права изменились. Обновите состояние и подготовьте новый план.', execution_conflict: 'Действие конфликтует с текущим состоянием плана.', permission_required: 'Для этого действия не хватает прав.', permission_denied: 'Для этого действия не хватает прав.', step_up_required: 'Подтвердите свежую MFA и повторите действие.', csrf_required: 'Обновите сеанс входа перед повтором.', invalid_execution_response: 'Сервер вернул неподтверждённый ответ. Действия по этому ответу закрыты.', request_timeout: 'Ответ сервера не получен вовремя.', network_error: 'Ответ сервера не получен.' } as Record<string, string>)[this.error()] ?? 'Запрос не выполнен. Код: ' + this.error();
    }
    stepUpURL(): string { return '/auth-ui/step-up?return=' + encodeURIComponent(location.pathname + location.search); }
    @HostListener('window:beforeunload', ['$event']) beforeUnload(event: BeforeUnloadEvent): void { if (this.pending() || this.form.dirty) { event.preventDefault(); event.returnValue = ''; } }
    private async execute(p: Pending): Promise<void> {
        this.pending.set(p); this.busy.set(true); this.clearError(); this.invalidate();
        try {
            const value = await this.api.write(p.operation);
            if (this.destroyed) return;
            let id = p.plan?.id ?? '';
            if (p.kind === 'create' || p.kind === 'rollback') {
                const view = this.api.decodeView(value), input = JSON.parse(p.operation.body) as ExecutionInput;
                if (view.plan.kind !== (p.kind === 'rollback' ? 'rollback_config' : 'apply_config') || view.plan.revisionId !== input.revisionId || view.plan.siteId !== input.siteId || view.plan.targets.length !== input.nodeIds.length || view.plan.targets.some(t => !input.nodeIds.includes(t.nodeId)) || Date.parse(view.plan.expiresAt) !== Date.parse(input.expiresAt) || (p.kind === 'rollback' && view.parentPlanId !== p.plan?.id)) throw new ConfigError('invalid_execution_response');
                id = view.plan.id; this.install({ ...view, current: false, access: undefined }); this.rollbackParent.set(null); this.form.markAsPristine();
                this.notice.set(p.kind === 'rollback' ? 'Создан новый план отката. Нужно независимое согласование и явный запуск.' : 'План создан. Нужно независимое согласование и явный запуск.');
            } else if (p.kind === 'approve') {
                this.api.decodeApproval(value, p.plan!); this.notice.set('Согласование записано. Применение запускается отдельным действием.');
            } else if (p.kind === 'dispatch') {
                this.api.decodeDispatch(value, p.plan!); this.notice.set('Выдача задания подтверждена. Итог применения проверяется по результатам узла.');
            } else {
                if (value !== undefined) throw new ConfigError('invalid_execution_response');
                this.notice.set('Выдача новых заданий отменена. Уже начатое изменение завершается и сообщает результат отдельно.');
            }
            // A valid mutation reply resolves this exact request. A failed GET
            // must never turn it into another mutation with another key.
            this.pending.set(null);
            try { const view = await this.api.load(id); if (!this.destroyed) this.install(view); }
            catch (error) { this.invalidate(); this.fail(error); this.notice.update(n => n + ' Текущее состояние пока не подтверждено; обновите его.'); }
        } catch (error) {
            this.fail(error);
            if (error instanceof ConfigError && error.status >= 400 && error.status < 500) {
                this.pending.set(null); this.notice.set('Действие отклонено сервером. Обновите состояние перед следующей попыткой.');
            } else this.notice.set('Результат исходного запроса неизвестен. Повторите его с тем же ключом и содержимым. Поля заблокированы.');
        } finally { this.busy.set(false); }
    }
    private install(view: ExecutionView): void {
        if (this.destroyed) return;
        this.loaded.set(view); this.lookup.setValue(view.plan.id); this.confirmedDigest.reset(false); this.confirmedDispatch.reset(false); this.clock.set(Date.now()); clearTimeout(this.timer);
        const expiry = Math.min(Date.parse(view.plan.expiresAt), view.approval ? Date.parse(view.approval.expiresAt) : Infinity);
        this.timer = setTimeout(() => { this.clock.set(Date.now()); this.invalidate(); }, Math.max(0, Math.min(expiry - Date.now() + 20, 2147483647)));
    }
    private invalidate(): void { const v = this.loaded(); if (v) this.loaded.set({ ...v, current: false, access: undefined }); this.confirmedDigest.reset(false); this.confirmedDispatch.reset(false); }
    private clearError(): void { this.error.set(''); this.status.set(0); }
    private fail(error: unknown): void { if (this.destroyed) return; const e = error instanceof ConfigError ? error : new ConfigError('request_failed'); this.error.set(/^[a-z][a-z0-9_]{0,80}$/.test(e.code) ? e.code : 'request_failed'); this.status.set(e.status); }
}
