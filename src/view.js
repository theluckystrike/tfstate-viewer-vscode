'use strict';
// View model for Terraform State & Plan Viewer: pagination, search/filter, outputs, dependencies and secret masking.

class TfstateViewModel {
  constructor(parsed, name, fileSize, maskSensitive = true) {
    this.parsed = parsed;
    this.name = name;
    this.fileSize = fileSize;
    this.maskSensitive = maskSensitive !== false;
    this.filter = { text: '', provider: '', module: '', mode: '' };
    this.filtered = parsed.resources.slice();
  }

  summary() {
    const s = this.parsed.stats;
    return {
      name: this.name,
      fileSize: this.fileSize,
      kind: this.parsed.kind,
      formatVersion: this.parsed.formatVersion,
      terraformVersion: this.parsed.terraformVersion,
      serial: this.parsed.serial,
      lineage: this.parsed.lineage,
      resourceCount: s.resourceCount,
      outputCount: s.outputCount,
      dependencyCount: s.dependencyCount,
      orphanedDependencyCount: s.orphanedDependencyCount,
      sensitiveResourceCount: s.sensitiveResourceCount,
      moduleCount: s.moduleCount,
      providerCount: s.providerCount,
      errorCount: s.errorCount,
      warningCount: s.warningCount,
      maskSensitive: this.maskSensitive,
      providers: Object.entries(this.parsed.providerCounts).sort((a, b) => b[1] - a[1]),
      modules: Object.entries(this.parsed.moduleCounts).sort((a, b) => b[1] - a[1]),
      modes: Object.entries(this.parsed.modeCounts).sort((a, b) => b[1] - a[1]),
      outputs: this.outputs(),
      edges: this.parsed.edges.slice(0, 500),
      findings: this.parsed.findings.slice(0, 300),
    };
  }

  outputs() {
    return this.parsed.outputs.map((o) => ({
      name: o.name,
      type: o.type,
      sensitive: o.sensitive,
      action: o.action,
      value: this.maskSensitive ? o.maskedValue : o.value,
    }));
  }

  setMaskSensitive(flag) {
    this.maskSensitive = Boolean(flag);
    return this.maskSensitive;
  }

  totalCount() {
    return this.parsed.resources.length;
  }

  count() {
    return this.filtered.length;
  }

  setFilter(f) {
    const text = f && typeof f.text === 'string' ? f.text.trim().toLowerCase() : '';
    const provider = f && typeof f.provider === 'string' ? f.provider.trim() : '';
    const mod = f && typeof f.module === 'string' ? f.module.trim() : '';
    const mode = f && typeof f.mode === 'string' ? f.mode.trim() : '';
    this.filter = { text, provider, module: mod, mode };
    this.filtered = this.parsed.resources.filter((r) => {
      if (provider && r.provider !== provider) return false;
      if (mod && r.module !== mod) return false;
      if (mode && r.action !== mode) return false;
      if (text) {
        const hay = [
          r.address, r.module, r.mode, r.action, r.provider, r.type, r.name, r.id,
          r.dependencies.join(' '),
        ].join(' ').toLowerCase();
        if (!hay.includes(text)) return false;
      }
      return true;
    });
    return this.filtered.length;
  }

  rows(from, limit) {
    const start = Math.max(0, Number(from) || 0);
    const n = Math.max(1, Math.min(500, Number(limit) || 100));
    return this.filtered.slice(start, start + n).map((r) => ({
      index: r.index,
      address: r.address,
      module: r.module,
      mode: r.mode,
      action: r.action,
      provider: r.provider,
      type: r.type,
      name: r.name,
      id: r.id,
      tainted: r.tainted,
      dependencyCount: r.dependencies.length,
      sensitiveCount: r.sensitivePaths.length,
      hasSensitive: r.hasSensitive,
    }));
  }

  detail(index) {
    const r = this.parsed.resources.find((x) => x.index === index) || this.parsed.resources[0] || null;
    if (!r) return null;
    return {
      index: r.index,
      address: r.address,
      module: r.module,
      mode: r.mode,
      action: r.action,
      provider: r.provider,
      providerRaw: r.providerRaw,
      type: r.type,
      name: r.name,
      instanceKey: r.instanceKey,
      id: r.id,
      tainted: r.tainted,
      dependencies: r.dependencies,
      dependents: r.dependents,
      sensitivePaths: r.sensitivePaths,
      hasSensitive: r.hasSensitive,
      masked: this.maskSensitive,
      attributes: this.maskSensitive ? r.maskedAttributes : r.attributes,
    };
  }
}

module.exports = { TfstateViewModel };
