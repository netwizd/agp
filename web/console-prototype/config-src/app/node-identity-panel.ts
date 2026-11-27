import { Component, DestroyRef, HostListener, inject, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ConfigError, Mutation, mutation } from './config-api';
import { ManagedNode, NodeIdentityApi, NodeIdentityOperation, PendingEnrollment, nodeIdentifier, nodeLabels } from './node-identity-api';

const identifier = () => new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.pattern(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/)] });
interface PendingMutation {
    kind: 'create' | 'issue' | 'approve' | 'cancel' | 'revoke';
    nodeId: string;
    enrollmentId?: string;
    operation: Mutation;
}
interface IssuedEnrollment { enrollmentId: string; expiresAt: string; tokenLost: boolean; }

@Component({ selector: 'agp-node-identity-panel', standalone: true, imports: [ReactiveFormsModule], templateUrl: './node-identity-panel.html' })
export class NodeIdentityPanel {
    private readonly api = inject(NodeIdentityApi);
    private destroyed = false;
    private expiryTimer: ReturnType<typeof setTimeout> | undefined;
    private readonly clock = signal(Date.now());
    readonly profileLoaded = signal(false);
    readonly enabled = signal(false);
    readonly busy = signal(false);
    readonly error = signal('');
    readonly status = signal(0);
    readonly notice = signal('');
    readonly nodes = signal<ManagedNode[]>([]);
    readonly nextCursor = signal('');
    readonly pending = signal<PendingMutation | null>(null);
    readonly enrollment = signal<PendingEnrollment | null>(null);
    readonly issued = signal<IssuedEnrollment | null>(null);
    readonly enrollmentToken = signal('');
    readonly revocation = signal<NodeIdentityOperation | null>(null);
    readonly selectedNode = new FormControl('', { nonNullable: true });
    readonly enrollmentId = identifier();
    readonly fingerprint = new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.pattern(/^sha256:[a-f0-9]{64}$/)] });
    readonly fingerprintConfirmed = new FormControl(false, { nonNullable: true });
    readonly revokeReason = new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.maxLength(512), Validators.pattern(/^[^\u0000\r\n]+$/)] });
    readonly createForm = new FormGroup({ id: identifier(), siteId: identifier(), name: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.maxLength(128), Validators.pattern(/^[^\u0000\r\n]+$/)] }), labels: new FormControl('{}', { nonNullable: true, validators: [Validators.maxLength(8192)] }) });

    constructor() {
        const destroyRef = inject(DestroyRef);
        destroyRef.onDestroy(() => { this.destroyed = true; this.forgetToken(); clearTimeout(this.expiryTimer); });
        this.selectedNode.valueChanges.pipe(takeUntilDestroyed()).subscribe(() => this.resetSelection());
        this.enrollmentId.valueChanges.pipe(takeUntilDestroyed()).subscribe(() => { this.enrollment.set(null); this.clearVerification(); });
    }
    ngOnInit(): void { void this.initialize(); }
    blocked(): boolean { return this.busy() || !!this.pending(); }
    node(): ManagedNode | undefined { return this.nodes().find(item => item.id === this.selectedNode.value); }
    expired(): boolean { this.clock(); const expiry = this.enrollment()?.expiresAt || this.issued()?.expiresAt; return !!expiry && Date.parse(expiry) <= Date.now(); }
    canIssue(): boolean {
        const active = this.enrollment();
        return !this.blocked() && !!this.node() && this.node()?.identityState !== 'revoked' && (!(this.issued() || (active && ['issued', 'csr_pending', 'approved'].includes(active.state))) || active?.state === 'revoked' || this.expired());
    }
    canApprove(): boolean {
        const pending = this.enrollment();
        return !this.blocked() && this.node()?.identityState !== 'revoked' && !!pending && pending.state === 'csr_pending' && !this.expired() && this.fingerprint.value === pending.publicKeyDigest && this.fingerprintConfirmed.value;
    }
    canCancel(): boolean { const pending = this.enrollment(); return !this.blocked() && nodeIdentifier(this.selectedNode.value) && this.enrollmentId.valid && pending?.state !== 'revoked' && pending?.state !== 'issued_certificate'; }
    async initialize(): Promise<void> {
        if (this.blocked()) return;
        this.busy.set(true); this.clearError();
        try {
            const enabled = await this.api.enabled();
            if (this.destroyed) return;
            this.enabled.set(enabled); this.profileLoaded.set(true);
            if (enabled) this.acceptNodes(await this.api.nodes(), false);
        } catch (error) { this.fail(error); } finally { this.busy.set(false); }
    }
    async refreshNodes(more = false): Promise<void> {
        if (this.blocked() || !this.enabled() || (more && !this.nextCursor())) return;
        this.busy.set(true); this.clearError();
        try { this.acceptNodes(await this.api.nodes(more ? this.nextCursor() : ''), more); }
        catch (error) { this.fail(error); } finally { this.busy.set(false); }
    }
    async create(): Promise<void> {
        if (this.blocked() || !this.enabled() || this.createForm.invalid) return;
        try {
            const input = this.createForm.getRawValue();
            let labels: unknown;
            try { labels = JSON.parse(input.labels); } catch { throw new ConfigError('invalid_node_labels'); }
            if (!nodeLabels(labels) || new TextEncoder().encode(input.name).length > 128) throw new ConfigError('invalid_node_labels_or_name');
            await this.execute({ kind: 'create', nodeId: input.id, operation: mutation('/api/v2/nodes', { id: input.id, siteId: input.siteId, name: input.name, labels }) });
        } catch (error) { this.fail(error); }
    }
    async issueToken(): Promise<void> {
        if (!this.canIssue()) return;
        const nodeId = this.selectedNode.value;
        await this.execute({ kind: 'issue', nodeId, operation: mutation(this.api.nodePath(nodeId) + '/enrollments', { role: 'agent', ttlSeconds: 600 }) });
    }
    async loadPending(): Promise<void> {
        if (this.blocked() || !nodeIdentifier(this.selectedNode.value) || this.enrollmentId.invalid) return;
        this.busy.set(true); this.clearError(); this.clearVerification();
        try {
            this.acceptEnrollment(await this.api.pending(this.selectedNode.value, this.enrollmentId.value));
            this.notice.set('Открыто состояние запроса. Отпечаток сверяйте с выводом CLI непосредственно на выбранном узле.');
        } catch (error) { this.enrollment.set(null); this.fail(error); } finally { this.busy.set(false); }
    }
    async approve(): Promise<void> {
        if (!this.canApprove()) return;
        const pending = this.enrollment()!;
        await this.execute({ kind: 'approve', nodeId: pending.nodeId, enrollmentId: pending.enrollmentId, operation: mutation(this.api.enrollmentPath(pending.nodeId, pending.enrollmentId) + '/approvals', { expectedPublicKeyDigest: this.fingerprint.value, requestDigest: pending.requestDigest }) });
    }
    async cancelEnrollment(): Promise<void> {
        if (!this.canCancel()) return;
        const nodeId = this.selectedNode.value, enrollmentId = this.enrollmentId.value;
        await this.execute({ kind: 'cancel', nodeId, enrollmentId, operation: mutation(this.api.enrollmentPath(nodeId, enrollmentId) + '/revocations', {}) });
    }
    async revokeNode(): Promise<void> {
        const node = this.node();
        if (this.blocked() || !node || node.identityState === 'revoked' || this.revokeReason.invalid || !this.revokeReason.value.trim() || new TextEncoder().encode(this.revokeReason.value).length > 512) return;
        await this.execute({ kind: 'revoke', nodeId: node.id, operation: mutation(this.api.nodePath(node.id) + '/revocations', { reason: this.revokeReason.value }) });
    }
    async retry(): Promise<void> { const pending = this.pending(); if (pending && !this.busy()) await this.execute(pending); }
    @HostListener('window:pagehide')
    forgetToken(): void { this.enrollmentToken.set(''); }
    stepUpURL(): string { return '/auth-ui/step-up?return=' + encodeURIComponent(location.pathname); }
    loginURL(): string { return '/auth-ui/login?return=' + encodeURIComponent(location.pathname); }
    private async execute(pending: PendingMutation): Promise<void> {
        this.pending.set(pending); this.busy.set(true); this.clearError();
        let writeReceived = false;
        try {
            const result = await this.api.write(pending.operation);
            writeReceived = true;
            if (this.destroyed) return;
            if (pending.kind === 'create') {
                const node = this.api.decodeNode(result);
                if (node.id !== pending.nodeId) throw new ConfigError('node_response_mismatch');
                this.nodes.update(items => [...items.filter(item => item.id !== node.id), node].sort((a, b) => a.id.localeCompare(b.id)));
                this.selectedNode.setValue(node.id); this.createForm.reset({ id: '', siteId: '', name: '', labels: '{}' });
                this.notice.set('Узел создан. Метки и Site задаются оператором. Создайте одноразовое разрешение только для agent.');
            } else if (pending.kind === 'issue') {
                const issued = this.api.decodeToken(result);
                this.forgetToken(); this.enrollment.set(null); this.clearVerification();
                this.issued.set({ enrollmentId: issued.enrollmentId, expiresAt: issued.expiresAt, tokenLost: !issued.tokenAvailable });
                this.enrollmentId.setValue(issued.enrollmentId, { emitEvent: false });
                if (issued.tokenAvailable && Date.parse(issued.expiresAt) > Date.now()) this.enrollmentToken.set(issued.token!);
                this.scheduleExpiry();
                this.notice.set(issued.tokenAvailable ? 'Токен показан только в этом ответе и хранится в памяти страницы. Передайте его узловому CLI через stdin или защищённый файл; затем скройте.' : 'Первый ответ с токеном утрачен. Повтор не возвращает секрет: отзовите это разрешение и выпустите новое.');
            } else if (pending.kind === 'revoke') {
                const operation = await this.api.followRevocation(result, pending.nodeId);
                if (this.destroyed) return;
                this.revocation.set(operation); this.forgetToken(); this.clearVerification();
                this.nodes.update(items => items.map(node => node.id === pending.nodeId ? { ...node, identityState: 'revoked' } : node));
                this.notice.set('Отзыв идентичности узла подтверждён сервером. Это не изменение конфигурации или состояния WAF.');
            } else {
                const enrollment = this.api.decodePending(result, pending.nodeId, pending.enrollmentId!);
                if (enrollment.state !== (pending.kind === 'approve' ? 'approved' : 'revoked')) throw new ConfigError('enrollment_state_mismatch');
                this.acceptEnrollment(enrollment); this.forgetToken();
                this.notice.set(pending.kind === 'approve' ? 'Подтверждён точный публичный ключ. Завершите agp-agent-identity enroll на том же узле, затем запустите инвентаризацию агента.' : 'Разрешение отозвано. При необходимости выпустите новый одноразовый токен.');
            }
            this.pending.set(null);
        } catch (error) {
            this.fail(error);
            if (!writeReceived && error instanceof ConfigError && error.status >= 400 && error.status < 500) {
                this.pending.set(null); this.clearVerification();
            } else this.notice.set('Ответ не подтверждён. Повторите исходный запрос с тем же ключом и содержимым. Поля заблокированы до выяснения результата.');
        } finally { this.busy.set(false); }
    }
    private acceptNodes(page: { items: ManagedNode[]; nextCursor: string }, more: boolean): void {
        if (this.destroyed) return;
        const previous = more ? this.nodes() : [];
        if (previous.length + page.items.length > 10000 || (more && page.items.some(item => previous.some(old => old.id === item.id)))) throw new ConfigError('invalid_node_page');
        this.nodes.set([...previous, ...page.items]); this.nextCursor.set(page.nextCursor);
        // A selection may live on a later page: never silently move actions to a different node.
        if (this.selectedNode.value && !this.node()) this.selectedNode.setValue('');
    }
    private acceptEnrollment(enrollment: PendingEnrollment): void {
        if (this.destroyed) return;
        this.enrollment.set(enrollment); this.clearVerification(); this.scheduleExpiry();
        if (['revoked', 'issued_certificate'].includes(enrollment.state)) this.forgetToken();
    }
    private clearVerification(): void { this.fingerprint.reset(''); this.fingerprintConfirmed.reset(false); }
    private resetSelection(): void {
        this.forgetToken(); this.issued.set(null); this.enrollment.set(null); this.revocation.set(null); this.enrollmentId.reset('', { emitEvent: false }); this.revokeReason.reset(''); this.clearVerification(); this.clearError(); this.notice.set(''); this.scheduleExpiry();
    }
    private scheduleExpiry(): void {
        clearTimeout(this.expiryTimer); this.clock.set(Date.now());
        const expiry = this.enrollment()?.expiresAt || this.issued()?.expiresAt;
        if (!expiry) return;
        const remaining = Date.parse(expiry) - Date.now();
        if (remaining <= 0) { this.forgetToken(); return; }
        this.expiryTimer = setTimeout(() => { this.clock.set(Date.now()); this.forgetToken(); this.clearVerification(); }, Math.min(remaining + 10, 2147483647));
    }
    private clearError(): void { this.error.set(''); this.status.set(0); }
    private fail(error: unknown): void {
        if (this.destroyed) return;
        const value = error instanceof ConfigError ? error : new ConfigError('request_failed');
        // Server diagnostics may contain arbitrary data. Never render token-bearing bodies.
        this.error.set(/^[a-z][a-z0-9_]{0,80}$/.test(value.code) ? value.code : 'request_failed'); this.status.set(value.status);
    }
}
