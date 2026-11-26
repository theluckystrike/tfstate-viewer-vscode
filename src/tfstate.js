'use strict';
// Offline parser, sensitive-attribute masker, dependency analyzer, health checker,
// diff report, secret/IAM audit report and CSV/JSON/Mermaid exporter for Terraform
// state (.tfstate, .tfstate.backup) and JSON plan (.tfplan.json) files.

const SENSITIVE_KEY_RE = /(password|passwd|secret|token|private[_-]?key|access[_-]?key|api[_-]?key|auth[_-]?key|client[_-]?secret|connection[_-]?string|master[_-]?password|signing[_-]?key|tls[_-]?key|ssh[_-]?key|credential|bearer|cookie|session[_-]?key)/i;
const MASK_LABEL = '[SENSITIVE - masked]';

function shortProvider(raw) {
  if (!raw || typeof raw !== 'string') return 'unknown';
  const m = raw.match(/provider\["([^"]+)"\]/);
  const inner = m ? m[1] : raw;
  const clean = inner.replace(/^registry\.terraform\.io\//i, '').replace(/^hashicorp\//i, '');
  const parts = clean.split('/');
  return parts[parts.length - 1] || clean || 'unknown';
}

function formatInstanceKey(key) {
  if (key === undefined || key === null || key === '') return '';
  if (typeof key === 'number') return `[${key}]`;
  return `[${JSON.stringify(String(key))}]`;
}

function buildAddress(modulePath, mode, type, name, instanceKey) {
  const parts = [];
  if (modulePath && modulePath !== 'root') parts.push(modulePath);
  if (mode === 'data') parts.push('data');
  parts.push(type);
  parts.push(name);
  return parts.join('.') + formatInstanceKey(instanceKey);
}

function parseSensitivePaths(sensitiveAttributes) {
  const paths = new Set();
  if (!Array.isArray(sensitiveAttributes)) return paths;
  for (const entry of sensitiveAttributes) {
    if (!Array.isArray(entry) || !entry.length) continue;
    const segs = [];
    for (const step of entry) {
      if (step && step.type === 'get_attr' && typeof step.value === 'string') {
        segs.push(step.value);
      } else if (step && step.type === 'index' && step.value && step.value.value !== undefined) {
        segs.push(String(step.value.value));
      } else if (typeof step === 'string') {
        segs.push(step);
      }
    }
    if (segs.length) paths.add(segs.join('.'));
  }
  return paths;
}

function collectHeuristicSensitivePaths(obj, prefix = '', out = new Set()) {
  if (!obj || typeof obj !== 'object') return out;
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      collectHeuristicSensitivePaths(obj[i], prefix ? `${prefix}.${i}` : String(i), out);
    }
    return out;
  }
  for (const [k, v] of Object.entries(obj)) {
    const p = prefix ? `${prefix}.${k}` : k;
    if (SENSITIVE_KEY_RE.test(k) && v !== null && v !== undefined && v !== '') {
      out.add(p);
    } else if (v && typeof v === 'object') {
      collectHeuristicSensitivePaths(v, p, out);
    }
  }
  return out;
}

function maskObject(obj, sensitiveSet, prefix = '') {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) {
    return obj.map((item, i) => {
      const p = prefix ? `${prefix}.${i}` : String(i);
      if (sensitiveSet.has(p)) return MASK_LABEL;
      return maskObject(item, sensitiveSet, p);
    });
  }
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    const p = prefix ? `${prefix}.${k}` : k;
    if (sensitiveSet.has(p) || sensitiveSet.has(k)) {
      out[k] = MASK_LABEL;
    } else if (v && typeof v === 'object') {
      out[k] = maskObject(v, sensitiveSet, p);
    } else {
      out[k] = v;
    }
  }
  return out;
}

function extractSensitivePathsFromPlan(sensitiveValues, prefix = '', out = new Set()) {
  if (!sensitiveValues || typeof sensitiveValues !== 'object') return out;
  if (Array.isArray(sensitiveValues)) {
    for (let i = 0; i < sensitiveValues.length; i++) {
      const p = prefix ? `${prefix}.${i}` : String(i);
      if (sensitiveValues[i] === true) out.add(p);
      else if (sensitiveValues[i] && typeof sensitiveValues[i] === 'object') {
        extractSensitivePathsFromPlan(sensitiveValues[i], p, out);
      }
    }
    return out;
  }
  for (const [k, v] of Object.entries(sensitiveValues)) {
    const p = prefix ? `${prefix}.${k}` : k;
    if (v === true) out.add(p);
    else if (v && typeof v === 'object') extractSensitivePathsFromPlan(v, p, out);
  }
  return out;
}

function normalizePlanAction(actions) {
  if (!Array.isArray(actions) || !actions.length) return 'no-op';
  const joined = actions.join(',');
  if (joined === 'create,delete' || joined === 'delete,create') return 'replace';
  if (actions.includes('create')) return 'create';
  if (actions.includes('delete')) return 'delete';
  if (actions.includes('update')) return 'update';
  if (actions.includes('read')) return 'read';
  return 'no-op';
}

function checkSecurityPatterns(res, findings) {
  const attrs = res.attributes || {};
  const type = String(res.type || '').toLowerCase();

  // 1. Public CIDR 0.0.0.0/0 or ::/0 on ingress security groups / firewalls
  if (/(security_group|firewall|network_security)/.test(type)) {
    const checkCidrs = (list, label) => {
      if (!Array.isArray(list)) return;
      for (const item of list) {
        if (item === '0.0.0.0/0' || item === '::/0') {
          findings.push({
            severity: 'warning',
            category: 'Public Network',
            resource: res.address,
            finding: `${label} allows unrestricted internet CIDR ${item}.`,
          });
        }
      }
    };
    if (Array.isArray(attrs.ingress)) {
      for (const rule of attrs.ingress) {
        if (!rule || typeof rule !== 'object') continue;
        checkCidrs(rule.cidr_blocks, `Ingress port ${rule.from_port ?? '*'}-${rule.to_port ?? '*'}`);
        checkCidrs(rule.ipv6_cidr_blocks, `Ingress IPv6 port ${rule.from_port ?? '*'}-${rule.to_port ?? '*'}`);
      }
    }
    if (attrs.type === 'ingress' || attrs.direction === 'INGRESS' || attrs.direction === 'Inbound') {
      checkCidrs(attrs.cidr_blocks, 'Security rule');
      checkCidrs(attrs.ipv6_cidr_blocks, 'Security rule IPv6');
      checkCidrs(attrs.source_ranges, 'Firewall source_ranges');
      if (attrs.source_address_prefix === '*' || attrs.source_address_prefix === '0.0.0.0/0') {
        findings.push({
          severity: 'warning',
          category: 'Public Network',
          resource: res.address,
          finding: `Inbound rule allows source_address_prefix ${attrs.source_address_prefix}.`,
        });
      }
    }
  }

  // 2. Wildcard IAM policy ("Action": "*" or "Resource": "*" with Allow)
  const policyFields = ['policy', 'assume_role_policy', 'inline_policy'];
  for (const pf of policyFields) {
    const raw = attrs[pf];
    if (!raw) continue;
    const docs = [];
    if (typeof raw === 'string') {
      try { docs.push(JSON.parse(raw)); } catch (_) { /* not json */ }
    } else if (Array.isArray(raw)) {
      for (const item of raw) {
        if (item && typeof item.policy === 'string') {
          try { docs.push(JSON.parse(item.policy)); } catch (_) { /* not json */ }
        }
      }
    }
    for (const doc of docs) {
      const stmts = Array.isArray(doc && doc.Statement) ? doc.Statement : (doc && doc.Statement ? [doc.Statement] : []);
      for (const st of stmts) {
        if (!st || st.Effect !== 'Allow') continue;
        const actions = Array.isArray(st.Action) ? st.Action : [st.Action];
        const resources = Array.isArray(st.Resource) ? st.Resource : [st.Resource];
        const starAct = actions.includes('*');
        const starRes = resources.includes('*');
        if (starAct && starRes) {
          findings.push({
            severity: 'error',
            category: 'IAM Wildcard',
            resource: res.address,
            finding: `IAM ${pf} grants Allow with both Action "*" and Resource "*".`,
          });
        } else if (starAct) {
          findings.push({
            severity: 'warning',
            category: 'IAM Wildcard',
            resource: res.address,
            finding: `IAM ${pf} grants Allow with wildcard Action "*".`,
          });
        }
      }
    }
  }

  // 3. Public S3 / Storage / DB exposure
  if (/s3_bucket/.test(type)) {
    if (attrs.acl === 'public-read' || attrs.acl === 'public-read-write') {
      findings.push({
        severity: 'error',
        category: 'Public Storage',
        resource: res.address,
        finding: `S3 bucket ACL is set to "${attrs.acl}".`,
      });
    }
    if (attrs.block_public_acls === false || attrs.block_public_policy === false) {
      findings.push({
        severity: 'warning',
        category: 'Public Storage',
        resource: res.address,
        finding: 'S3 public access block is disabled (block_public_acls or block_public_policy is false).',
      });
    }
  }
  if (attrs.publicly_accessible === true) {
    findings.push({
      severity: 'error',
      category: 'Public Database',
      resource: res.address,
      finding: 'Resource has publicly_accessible = true.',
    });
  }
  if (attrs.storage_encrypted === false || attrs.encrypted === false) {
    findings.push({
      severity: 'warning',
      category: 'Unencrypted Storage',
      resource: res.address,
      finding: 'Storage encryption is disabled (encrypted / storage_encrypted = false).',
    });
  }
}

function parseTfstateV4(json) {
  const resources = [];
  const findings = [];
  let idx = 0;

  if (json.serial === undefined || json.serial === null) {
    findings.push({ severity: 'warning', category: 'State Metadata', resource: '(root)', finding: 'State file is missing a serial number.' });
  }
  if (!json.lineage) {
    findings.push({ severity: 'warning', category: 'State Metadata', resource: '(root)', finding: 'State file is missing a lineage UUID.' });
  }

  for (const r of Array.isArray(json.resources) ? json.resources : []) {
    const mode = r.mode || 'managed';
    const type = r.type || 'unknown';
    const name = r.name || 'unnamed';
    const modulePath = r.module || 'root';
    const providerRaw = r.provider || '';
    const provider = shortProvider(providerRaw);
    const instances = Array.isArray(r.instances) && r.instances.length ? r.instances : [{ attributes: {} }];

    for (const inst of instances) {
      idx += 1;
      const key = inst.index_key;
      const address = buildAddress(modulePath, mode, type, name, key);
      const attrs = (inst.attributes && typeof inst.attributes === 'object') ? inst.attributes : {};
      const declaredSensitive = parseSensitivePaths(inst.sensitive_attributes);
      const heuristicSensitive = collectHeuristicSensitivePaths(attrs);
      const allSensitive = new Set([...declaredSensitive, ...heuristicSensitive]);
      const deps = Array.isArray(inst.dependencies) ? inst.dependencies.filter((d) => typeof d === 'string') : [];
      const tainted = inst.status === 'tainted';

      const entry = {
        index: idx,
        address,
        baseAddress: buildAddress(modulePath, mode, type, name, ''),
        module: modulePath,
        mode,
        action: mode,
        type,
        name,
        instanceKey: key !== undefined && key !== null ? String(key) : '',
        provider,
        providerRaw,
        id: attrs.id !== undefined && attrs.id !== null ? String(attrs.id) : (attrs.arn ? String(attrs.arn) : ''),
        tainted,
        dependencies: deps,
        dependents: [],
        sensitivePaths: Array.from(allSensitive).sort(),
        declaredSensitivePaths: Array.from(declaredSensitive).sort(),
        hasSensitive: allSensitive.size > 0,
        attributes: attrs,
        maskedAttributes: maskObject(attrs, allSensitive),
      };
      resources.push(entry);

      if (tainted) {
        findings.push({ severity: 'warning', category: 'Tainted Resource', resource: address, finding: 'Resource instance is marked tainted and will be replaced on next apply.' });
      }
      if (allSensitive.size > 0) {
        findings.push({
          severity: 'warning',
          category: 'Sensitive Data',
          resource: address,
          finding: `Contains ${allSensitive.size} sensitive attribute path(s) in plaintext state (${Array.from(allSensitive).slice(0, 4).join(', ')}${allSensitive.size > 4 ? ', ...' : ''}).`,
        });
      }
      checkSecurityPatterns(entry, findings);
    }
  }

  const outputs = [];
  if (json.outputs && typeof json.outputs === 'object') {
    for (const [name, o] of Object.entries(json.outputs)) {
      if (!o || typeof o !== 'object') continue;
      const sensitive = Boolean(o.sensitive) || SENSITIVE_KEY_RE.test(name);
      const typeStr = typeof o.type === 'string' ? o.type : (Array.isArray(o.type) ? JSON.stringify(o.type) : typeof o.value);
      outputs.push({
        name,
        type: typeStr,
        sensitive,
        action: 'output',
        value: o.value,
        maskedValue: sensitive ? MASK_LABEL : o.value,
      });
      if (sensitive) {
        findings.push({
          severity: 'warning',
          category: 'Sensitive Output',
          resource: `output.${name}`,
          finding: `Output "${name}" is marked sensitive and stored in plaintext state.`,
        });
      }
    }
  }

  return {
    kind: 'tfstate-v4',
    formatVersion: String(json.version),
    terraformVersion: json.terraform_version || 'unknown',
    serial: json.serial !== undefined ? json.serial : null,
    lineage: json.lineage || '',
    resources,
    outputs,
    findings,
  };
}

function parseTfstateV3(json) {
  const resources = [];
  const outputs = [];
  const findings = [{
    severity: 'warning',
    category: 'Legacy Version',
    resource: '(root)',
    finding: `State uses legacy format version ${json.version}. Terraform 0.12+ uses state version 4.`,
  }];
  let idx = 0;

  for (const mod of Array.isArray(json.modules) ? json.modules : []) {
    const pathArr = Array.isArray(mod.path) ? mod.path : ['root'];
    const modulePath = pathArr.length <= 1 ? 'root' : `module.${pathArr.slice(1).join('.module.')}`;
    if (mod.resources && typeof mod.resources === 'object') {
      for (const [rk, rv] of Object.entries(mod.resources)) {
        if (!rv || typeof rv !== 'object') continue;
        idx += 1;
        const mode = rk.startsWith('data.') ? 'data' : 'managed';
        const cleanKey = rk.replace(/^data\./, '');
        const dotIdx = cleanKey.indexOf('.');
        const type = rv.type || (dotIdx > 0 ? cleanKey.slice(0, dotIdx) : cleanKey);
        const name = dotIdx > 0 ? cleanKey.slice(dotIdx + 1) : rk;
        const address = buildAddress(modulePath, mode, type, name, '');
        const attrs = (rv.primary && rv.primary.attributes) ? rv.primary.attributes : {};
        const allSensitive = collectHeuristicSensitivePaths(attrs);
        const deps = Array.isArray(rv.depends_on) ? rv.depends_on.filter((d) => typeof d === 'string') : [];
        const entry = {
          index: idx,
          address,
          baseAddress: address,
          module: modulePath,
          mode,
          action: mode,
          type,
          name,
          instanceKey: '',
          provider: shortProvider(rv.provider || type.split('_')[0]),
          providerRaw: rv.provider || '',
          id: (rv.primary && rv.primary.id) ? String(rv.primary.id) : '',
          tainted: false,
          dependencies: deps,
          dependents: [],
          sensitivePaths: Array.from(allSensitive).sort(),
          declaredSensitivePaths: [],
          hasSensitive: allSensitive.size > 0,
          attributes: attrs,
          maskedAttributes: maskObject(attrs, allSensitive),
        };
        resources.push(entry);
        checkSecurityPatterns(entry, findings);
      }
    }
    if (mod.outputs && typeof mod.outputs === 'object') {
      for (const [name, o] of Object.entries(mod.outputs)) {
        const sensitive = Boolean(o && o.sensitive) || SENSITIVE_KEY_RE.test(name);
        outputs.push({
          name: modulePath === 'root' ? name : `${modulePath}.${name}`,
          type: (o && o.type) ? String(o.type) : typeof (o && o.value),
          sensitive,
          action: 'output',
          value: o ? o.value : null,
          maskedValue: sensitive ? MASK_LABEL : (o ? o.value : null),
        });
      }
    }
  }

  return {
    kind: 'tfstate-v3',
    formatVersion: String(json.version),
    terraformVersion: json.terraform_version || 'unknown',
    serial: json.serial !== undefined ? json.serial : null,
    lineage: json.lineage || '',
    resources,
    outputs,
    findings,
  };
}

function parseTfplanJson(json) {
  const resources = [];
  const findings = [];
  let idx = 0;

  const changes = Array.isArray(json.resource_changes) ? json.resource_changes : [];
  for (const rc of changes) {
    idx += 1;
    const change = rc.change || {};
    const action = normalizePlanAction(change.actions);
    const attrs = (change.after && typeof change.after === 'object')
      ? change.after
      : ((change.before && typeof change.before === 'object') ? change.before : {});
    const planSensitive = extractSensitivePathsFromPlan(change.after_sensitive || change.before_sensitive);
    const heuristicSensitive = collectHeuristicSensitivePaths(attrs);
    const allSensitive = new Set([...planSensitive, ...heuristicSensitive]);
    const address = rc.address || buildAddress(rc.module_address || 'root', rc.mode || 'managed', rc.type || 'unknown', rc.name || 'unnamed', rc.index);

    const entry = {
      index: idx,
      address,
      baseAddress: buildAddress(rc.module_address || 'root', rc.mode || 'managed', rc.type || 'unknown', rc.name || 'unnamed', ''),
      module: rc.module_address || 'root',
      mode: rc.mode || 'managed',
      action,
      type: rc.type || 'unknown',
      name: rc.name || 'unnamed',
      instanceKey: rc.index !== undefined && rc.index !== null ? String(rc.index) : '',
      provider: shortProvider(rc.provider_name || ''),
      providerRaw: rc.provider_name || '',
      id: attrs.id !== undefined && attrs.id !== null ? String(attrs.id) : '',
      tainted: action === 'replace',
      dependencies: [],
      dependents: [],
      sensitivePaths: Array.from(allSensitive).sort(),
      declaredSensitivePaths: Array.from(planSensitive).sort(),
      hasSensitive: allSensitive.size > 0,
      attributes: attrs,
      maskedAttributes: maskObject(attrs, allSensitive),
      before: change.before || null,
      after: change.after || null,
    };
    resources.push(entry);

    if (action === 'delete' || action === 'replace') {
      findings.push({
        severity: 'warning',
        category: 'Destructive Plan Action',
        resource: address,
        finding: `Plan will ${action} this resource.`,
      });
    }
    if (allSensitive.size > 0) {
      findings.push({
        severity: 'warning',
        category: 'Sensitive Data',
        resource: address,
        finding: `Plan resource contains ${allSensitive.size} sensitive attribute path(s).`,
      });
    }
    checkSecurityPatterns(entry, findings);
  }

  const outputs = [];
  const outChanges = json.output_changes && typeof json.output_changes === 'object' ? json.output_changes : {};
  for (const [name, oc] of Object.entries(outChanges)) {
    if (!oc || typeof oc !== 'object') continue;
    const sensitive = Boolean(oc.after_sensitive || oc.before_sensitive) || SENSITIVE_KEY_RE.test(name);
    const val = oc.after !== undefined ? oc.after : oc.before;
    outputs.push({
      name,
      type: typeof val,
      sensitive,
      action: normalizePlanAction(oc.actions),
      value: val,
      maskedValue: sensitive ? MASK_LABEL : val,
    });
  }

  return {
    kind: 'tfplan-json',
    formatVersion: String(json.format_version || '1.0'),
    terraformVersion: json.terraform_version || 'unknown',
    serial: null,
    lineage: '',
    resources,
    outputs,
    findings,
  };
}

function parseTfstate(input) {
  const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input || '');
  const trimmed = text.trim();
  if (!trimmed) throw new Error('The file is empty.');

  let json;
  try {
    json = JSON.parse(trimmed);
  } catch (e) {
    throw new Error(`Invalid JSON in Terraform file: ${e.message}`);
  }
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    throw new Error('Expected a Terraform state or plan JSON object at the root.');
  }

  let parsed;
  if (Array.isArray(json.resource_changes) || json.planned_values || json.format_version) {
    parsed = parseTfplanJson(json);
  } else if (json.version === 4 || Array.isArray(json.resources)) {
    parsed = parseTfstateV4(json);
  } else if (Number(json.version) >= 1 && Number(json.version) <= 3 && Array.isArray(json.modules)) {
    parsed = parseTfstateV3(json);
  } else {
    throw new Error('Unrecognized Terraform file format. Expected a .tfstate (v3/v4) or terraform show -json plan file.');
  }

  // Build dependency edges, reverse dependents, and orphaned dependency findings
  const addressSet = new Set();
  const baseAddressSet = new Set();
  const byAddress = new Map();
  for (const r of parsed.resources) {
    addressSet.add(r.address);
    baseAddressSet.add(r.baseAddress);
    byAddress.set(r.address, r);
  }

  const edges = [];
  let orphanedCount = 0;
  for (const r of parsed.resources) {
    for (const dep of r.dependencies) {
      const exists = addressSet.has(dep) || baseAddressSet.has(dep);
      edges.push({ from: r.address, to: dep, orphaned: !exists });
      if (exists) {
        const target = byAddress.get(dep);
        if (target && !target.dependents.includes(r.address)) target.dependents.push(r.address);
      } else {
        orphanedCount += 1;
        parsed.findings.push({
          severity: 'error',
          category: 'Orphaned Dependency',
          resource: r.address,
          finding: `Depends on "${dep}", which does not exist in this state file.`,
        });
      }
    }
  }

  if (parsed.resources.length === 0) {
    parsed.findings.push({
      severity: 'warning',
      category: 'Empty State',
      resource: '(root)',
      finding: 'No resources found in this Terraform file.',
    });
  }

  const providerCounts = {};
  const moduleCounts = {};
  const modeCounts = {};
  let sensitiveResourceCount = 0;
  for (const r of parsed.resources) {
    providerCounts[r.provider] = (providerCounts[r.provider] || 0) + 1;
    moduleCounts[r.module] = (moduleCounts[r.module] || 0) + 1;
    modeCounts[r.action] = (modeCounts[r.action] || 0) + 1;
    if (r.hasSensitive) sensitiveResourceCount += 1;
  }

  const errorCount = parsed.findings.filter((f) => f.severity === 'error').length;
  const warningCount = parsed.findings.filter((f) => f.severity === 'warning').length;

  parsed.edges = edges;
  parsed.providerCounts = providerCounts;
  parsed.moduleCounts = moduleCounts;
  parsed.modeCounts = modeCounts;
  parsed.stats = {
    resourceCount: parsed.resources.length,
    outputCount: parsed.outputs.length,
    dependencyCount: edges.length,
    orphanedDependencyCount: orphanedCount,
    sensitiveResourceCount,
    moduleCount: Object.keys(moduleCounts).length,
    providerCount: Object.keys(providerCounts).length,
    errorCount,
    warningCount,
  };
  return parsed;
}

function csvCell(v) {
  const s = String(v == null ? '' : v);
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function buildResourcesCsv(parsed, fileName = '') {
  const header = ['file', 'index', 'address', 'module', 'mode', 'action', 'provider', 'type', 'name', 'instance_key', 'id', 'tainted', 'dependency_count', 'sensitive_count', 'dependencies'];
  const lines = [header.join(',')];
  for (const r of parsed.resources) {
    lines.push([
      fileName, r.index, r.address, r.module, r.mode, r.action, r.provider, r.type, r.name,
      r.instanceKey, r.id, r.tainted ? 'true' : 'false', r.dependencies.length,
      r.sensitivePaths.length, r.dependencies.join(';'),
    ].map(csvCell).join(','));
  }
  return lines.join('\n') + '\n';
}

function buildOutputsCsv(parsed, fileName = '') {
  const header = ['file', 'name', 'type', 'sensitive', 'action', 'value_masked'];
  const lines = [header.join(',')];
  for (const o of parsed.outputs) {
    const val = o.sensitive ? MASK_LABEL : (typeof o.value === 'object' ? JSON.stringify(o.value) : String(o.value ?? ''));
    lines.push([fileName, o.name, o.type, o.sensitive ? 'true' : 'false', o.action, val].map(csvCell).join(','));
  }
  return lines.join('\n') + '\n';
}

function buildInventoryJson(parsed, fileName = '') {
  return JSON.stringify({
    file: fileName,
    kind: parsed.kind,
    formatVersion: parsed.formatVersion,
    terraformVersion: parsed.terraformVersion,
    serial: parsed.serial,
    lineage: parsed.lineage,
    stats: parsed.stats,
    resources: parsed.resources.map((r) => ({
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
      dependencies: r.dependencies,
      sensitivePaths: r.sensitivePaths,
      attributes: r.maskedAttributes,
    })),
    outputs: parsed.outputs.map((o) => ({
      name: o.name,
      type: o.type,
      sensitive: o.sensitive,
      action: o.action,
      value: o.maskedValue,
    })),
    findings: parsed.findings,
  }, null, 2) + '\n';
}

function mermaidId(addr, map) {
  if (map.has(addr)) return map.get(addr);
  const id = `R${map.size + 1}`;
  map.set(addr, id);
  return id;
}

function buildMermaidGraph(parsed) {
  const lines = ['graph LR'];
  const ids = new Map();
  if (!parsed.edges.length && !parsed.resources.length) {
    lines.push('  empty["No resources in state"]');
    return lines.join('\n') + '\n';
  }
  for (const r of parsed.resources) {
    const id = mermaidId(r.address, ids);
    const label = r.address.replace(/"/g, "'");
    lines.push(`  ${id}["${label}"]`);
  }
  for (const e of parsed.edges) {
    const fromId = mermaidId(e.from, ids);
    const toId = mermaidId(e.to, ids);
    if (e.orphaned) {
      const toLabel = `${e.to.replace(/"/g, "'")} (orphaned)`;
      lines.push(`  ${toId}["${toLabel}"]`);
      lines.push(`  ${fromId} -.-> ${toId}`);
    } else {
      lines.push(`  ${fromId} --> ${toId}`);
    }
  }
  return lines.join('\n') + '\n';
}

function buildDiffMarkdown(leftName, leftParsed, rightName, rightParsed) {
  const leftMap = new Map(leftParsed.resources.map((r) => [r.address, r]));
  const rightMap = new Map(rightParsed.resources.map((r) => [r.address, r]));

  const added = [];
  const removed = [];
  const modified = [];
  let unchanged = 0;

  for (const [addr, r] of rightMap.entries()) {
    if (!leftMap.has(addr)) {
      added.push(r);
    } else {
      const l = leftMap.get(addr);
      const changedKeys = [];
      const allKeys = new Set([...Object.keys(l.maskedAttributes || {}), ...Object.keys(r.maskedAttributes || {})]);
      for (const k of Array.from(allKeys).sort()) {
        const lv = JSON.stringify(l.maskedAttributes[k]);
        const rv = JSON.stringify(r.maskedAttributes[k]);
        if (lv !== rv) {
          changedKeys.push({ key: k, before: l.maskedAttributes[k], after: r.maskedAttributes[k] });
        }
      }
      if (l.tainted !== r.tainted) {
        changedKeys.push({ key: '(tainted)', before: l.tainted, after: r.tainted });
      }
      if (changedKeys.length) modified.push({ address: addr, type: r.type, provider: r.provider, changes: changedKeys });
      else unchanged += 1;
    }
  }
  for (const [addr, l] of leftMap.entries()) {
    if (!rightMap.has(addr)) removed.push(l);
  }

  const lines = [
    '# Terraform State & Plan Drift Report',
    '',
    `- **Left (Baseline):** \`${leftName}\` (${leftParsed.kind}, Terraform ${leftParsed.terraformVersion}, serial ${leftParsed.serial ?? '-'}, ${leftParsed.stats.resourceCount} resources)`,
    `- **Right (Target):** \`${rightName}\` (${rightParsed.kind}, Terraform ${rightParsed.terraformVersion}, serial ${rightParsed.serial ?? '-'}, ${rightParsed.stats.resourceCount} resources)`,
    '',
    '## Summary',
    '',
    '| Category | Count |',
    '| --- | ---: |',
    `| Added resources | ${added.length} |`,
    `| Removed resources | ${removed.length} |`,
    `| Modified resources | ${modified.length} |`,
    `| Unchanged resources | ${unchanged} |`,
    '',
  ];

  if (added.length) {
    lines.push('## Added Resources', '', '| Address | Provider | Type | Mode |', '| --- | --- | --- | --- |');
    for (const r of added) lines.push(`| \`${r.address}\` | ${r.provider} | \`${r.type}\` | ${r.action} |`);
    lines.push('');
  }
  if (removed.length) {
    lines.push('## Removed Resources', '', '| Address | Provider | Type | Mode |', '| --- | --- | --- | --- |');
    for (const r of removed) lines.push(`| \`${r.address}\` | ${r.provider} | \`${r.type}\` | ${r.action} |`);
    lines.push('');
  }
  if (modified.length) {
    lines.push('## Modified Resources (Sensitive Values Masked)', '');
    for (const m of modified) {
      lines.push(`### \`${m.address}\` (${m.provider})`, '', '| Attribute | Baseline | Target |', '| --- | --- | --- |');
      for (const c of m.changes.slice(0, 40)) {
        const b = JSON.stringify(c.before ?? null).slice(0, 120).replace(/\|/g, '\\|');
        const a = JSON.stringify(c.after ?? null).slice(0, 120).replace(/\|/g, '\\|');
        lines.push(`| \`${c.key}\` | \`${b}\` | \`${a}\` |`);
      }
      lines.push('');
    }
  }
  if (!added.length && !removed.length && !modified.length) {
    lines.push('No resource drift detected between the two files.', '');
  }
  return lines.join('\n');
}

function buildAuditMarkdown(entries) {
  const lines = [
    '# Terraform State Secret & Exposure Audit Report',
    '',
    `Scanned ${entries.length} file(s) locally. Raw secret values are redacted in this report.`,
    '',
    '## File Summary',
    '',
    '| File | Format | Terraform | Serial | Resources | Sensitive | Errors | Warnings |',
    '| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |',
  ];

  let totalErrors = 0;
  let totalWarnings = 0;
  let totalSensitive = 0;

  for (const { fileName, parsed } of entries) {
    const s = parsed.stats;
    totalErrors += s.errorCount;
    totalWarnings += s.warningCount;
    totalSensitive += s.sensitiveResourceCount;
    lines.push(`| \`${fileName}\` | ${parsed.kind} | ${parsed.terraformVersion} | ${parsed.serial ?? '-'} | ${s.resourceCount} | ${s.sensitiveResourceCount} | ${s.errorCount} | ${s.warningCount} |`);
  }

  lines.push('', `**Totals:** ${totalErrors} error(s), ${totalWarnings} warning(s), ${totalSensitive} resource(s) containing sensitive attributes.`, '');

  for (const { fileName, parsed } of entries) {
    lines.push(`## \`${fileName}\``, '');
    if (!parsed.findings.length) {
      lines.push('No security, sensitive-attribute or state-health findings detected.', '');
      continue;
    }
    lines.push('| Severity | Category | Resource | Finding |', '| --- | --- | --- | --- |');
    for (const f of parsed.findings) {
      lines.push(`| ${f.severity.toUpperCase()} | ${f.category} | \`${f.resource}\` | ${f.finding.replace(/\|/g, '\\|')} |`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

module.exports = {
  MASK_LABEL,
  shortProvider,
  parseTfstate,
  buildResourcesCsv,
  buildOutputsCsv,
  buildInventoryJson,
  buildMermaidGraph,
  buildDiffMarkdown,
  buildAuditMarkdown,
};
