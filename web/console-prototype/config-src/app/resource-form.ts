import { Component, EventEmitter, Input, Output, signal } from '@angular/core';
import { FormArray, FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { Configuration, Gateway, Route, newGateway, newRoute, ProfileAssignment } from './contracts';
import { ConfigHelp, Topic } from './help-tip';
const text = (value = '') => new FormControl(value, { nonNullable: true });
const number = (value: number, min: number, max: number) => new FormControl(value, { nonNullable: true, validators: [Validators.min(min), Validators.max(max), Validators.required] });
const flag = (value: boolean) => new FormControl(value, { nonNullable: true });
const list = (value: string) => value.split(/[\s,]+/).map(item => item.trim()).filter(Boolean);
const routeForm = (route: Route) => new FormGroup({ id: text(route.id), name: text(route.name), hostname: text(route.hostname), path: text(route.path), url: text(route.upstream.url), connect: number(route.upstream.connectTimeoutSeconds, 1, 60), read: number(route.upstream.readTimeoutSeconds, 1, 3600), serverName: text(route.upstream.tls.serverName), ca: text(route.upstream.tls.caSecretVersionId), groups: text(route.access.groupIds.join('\n')), cidrs: text(route.access.allowCidrs.join('\n')), exceptions: text(route.wafExceptionIds.join('\n')) });
const gatewayForm = (gateway?: Gateway) => new FormGroup({ id: text(gateway?.metadata.id), name: text(gateway?.metadata.name), siteId: text(gateway?.metadata.siteId), labels: text(JSON.stringify(gateway?.metadata.labels ?? {})), ownership: new FormControl<'managed' | 'adopted'>(gateway?.spec.ownership ?? 'managed', { nonNullable: true }), selectorMode: new FormControl<'ids' | 'labels'>(gateway?.spec.nodeSelector.nodeIds ? 'ids' : 'labels', { nonNullable: true }), nodes: text(gateway?.spec.nodeSelector.nodeIds?.join('\n')), matchLabels: text(JSON.stringify(gateway?.spec.nodeSelector.matchLabels ?? {})), componentId: text(gateway?.spec.componentProfileRef.id), componentDigest: text(gateway?.spec.componentProfileRef.digest), certificate: text(gateway?.spec.tls.certificateVersionId), wafPolicy: text(gateway?.spec.waf.policyRevisionId), wafMode: new FormControl<'off' | 'detection' | 'blocking'>(gateway?.spec.waf.mode ?? 'detection', { nonNullable: true }), metrics: flag(gateway?.spec.monitoring.metrics ?? true), logs: flag(gateway?.spec.monitoring.logs ?? true), routes: new FormArray((gateway?.spec.routes ?? []).map(routeForm)) });
@Component({ selector: 'agp-resource-form', standalone: true, imports: [ReactiveFormsModule, ConfigHelp], templateUrl: './resource-form.html' })
export class ResourceForm {
    @Input()
    gatewayOnly = false;
    @Input()
    idPrefix = '';
    private scopedValue = false;
    @Input()
    set scoped(value: boolean) { this.scopedValue = value; if (this.model)
        this.lockInfrastructure(); }
    @Output()
    changed = new EventEmitter<Configuration>();
    @Output()
    invalid = new EventEmitter<boolean>();
    @Output()
    manual = new EventEmitter<Topic>();
    model!: Configuration;
    private emitted?: Configuration;
    selected = signal(0);
    error = signal('');
    header = new FormGroup({ id: text(), name: text(), fleet: flag(false) });
    gateway = gatewayForm();
    assignments = text('[]');
    @Input()
    set content(value: Configuration) {
        if (value === this.emitted)
            return;
        this.model = structuredClone(value);
        this.selected.set(Math.min(this.selected(), Math.max(0, value.gateways.length - 1)));
        this.header.setValue({ id: value.metadata.id, name: value.metadata.name, fleet: value.apiVersion === 'agp.config/v1alpha2' }, { emitEvent: false });
        this.assignments.setValue(JSON.stringify(value.profileAssignments, null, 2), { emitEvent: false });
        this.installGateway();
    }
    constructor() { this.header.valueChanges.subscribe(() => this.publish()); this.assignments.valueChanges.subscribe(() => this.publish()); }
    private installGateway(): void { this.gateway = gatewayForm(this.model.gateways[this.selected()]); this.lockInfrastructure(); this.gateway.valueChanges.subscribe(() => this.publish()); }
    private lockInfrastructure(): void {
        if (!this.scopedValue)
            return;
        for (const key of ['id', 'siteId', 'ownership', 'selectorMode', 'nodes', 'matchLabels', 'componentId', 'componentDigest', 'certificate'] as const)
            this.gateway.controls[key].disable({ emitEvent: false });
    }
    select(index: number): void {
        if (this.error())
            return;
        this.selected.set(index);
        this.installGateway();
    }
    addGateway(): void {
        if (this.error())
            return;
        const id = `gw_${crypto.randomUUID().replaceAll('-', '').slice(0, 12)}`;
        this.model = structuredClone(this.model);
        this.model.gateways.push(newGateway(id));
        this.selected.set(this.model.gateways.length - 1);
        this.installGateway();
        this.publish();
    }
    removeGateway(): void {
        if (!this.model.gateways.length)
            return;
        this.model = structuredClone(this.model);
        this.model.gateways.splice(this.selected(), 1);
        this.selected.set(Math.max(0, this.selected() - 1));
        this.installGateway();
        this.publish();
    }
    addRoute(): void { this.gateway.controls.routes.push(routeForm(newRoute(`route_${crypto.randomUUID().replaceAll('-', '').slice(0, 12)}`))); }
    removeRoute(index: number): void { this.gateway.controls.routes.removeAt(index); }
    private labels(value: string): Record<string, string> {
        const parsed: unknown = JSON.parse(value);
        if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object' || Object.values(parsed).some(item => typeof item !== 'string'))
            throw new Error('Метки должны быть JSON-объектом строк.');
        return parsed as Record<string, string>;
    }
    private publish(): void {
        if (!this.model)
            return;
        try {
            if (this.gateway.invalid)
                throw new Error('Проверьте диапазоны таймаутов.');
            const next = structuredClone(this.model), header = this.header.getRawValue();
            next.metadata = { id: header.id, name: header.name };
            next.apiVersion = header.fleet ? 'agp.config/v1alpha2' : 'agp.config/v1alpha1';
            if (header.fleet)
                next.capacityProfile = 'fleet-10k';
            else
                delete next.capacityProfile;
            const assignments: unknown = JSON.parse(this.assignments.value);
            if (!Array.isArray(assignments))
                throw new Error('Назначения должны быть JSON-массивом.');
            next.profileAssignments = assignments as ProfileAssignment[];
            if (next.gateways.length) {
                const value = this.gateway.getRawValue();
                const gateway: Gateway = { apiVersion: 'agp.config/v1alpha1', kind: 'Gateway', metadata: { id: value.id, name: value.name, siteId: value.siteId, labels: this.labels(value.labels) }, spec: { ownership: value.ownership, nodeSelector: value.selectorMode === 'ids' ? { nodeIds: list(value.nodes) } : { matchLabels: this.labels(value.matchLabels) }, componentProfileRef: { id: value.componentId, digest: value.componentDigest }, tls: { certificateVersionId: value.certificate }, authorization: { mode: 'central', failureMode: 'closed' }, waf: { engine: 'modsecurity', policyRevisionId: value.wafPolicy, mode: value.wafMode }, routes: value.routes.map(route => ({ id: route.id, name: route.name, hostname: route.hostname, path: route.path, upstream: { url: route.url, connectTimeoutSeconds: route.connect, readTimeoutSeconds: route.read, tls: { verify: true, ...(route.serverName ? { serverName: route.serverName } : {}), ...(route.ca ? { caSecretVersionId: route.ca } : {}) } }, access: { groupIds: list(route.groups), allowCidrs: list(route.cidrs) }, wafExceptionIds: list(route.exceptions) })), monitoring: { metrics: value.metrics, logs: value.logs } } };
                next.gateways[this.selected()] = gateway;
            }
            this.error.set('');
            this.invalid.emit(false);
            this.model = next;
            this.emitted = next;
            this.changed.emit(next);
        }
        catch (error) {
            this.error.set(error instanceof Error ? error.message : 'Некорректное поле.');
            this.invalid.emit(true);
        }
    }
}
