'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  MASK_LABEL,
  shortProvider,
  parseTfstate,
  buildResourcesCsv,
  buildOutputsCsv,
  buildInventoryJson,
  buildMermaidGraph,
  buildDiffMarkdown,
  buildAuditMarkdown,
} = require('../src/tfstate');
const { TfstateViewModel } = require('../src/view');
const { editorHtml, csp } = require('../src/html');

const SAMPLE_STATE = path.join(__dirname, '..', 'samples', 'sample.tfstate');
const SAMPLE_PLAN = path.join(__dirname, '..', 'samples', 'sample.tfplan.json');

describe('shortProvider', () => {
  it('extracts clean provider name from registry URI', () => {
    assert.equal(shortProvider('provider["registry.terraform.io/hashicorp/aws"]'), 'aws');
    assert.equal(shortProvider('registry.terraform.io/hashicorp/google'), 'google');
    assert.equal(shortProvider(''), 'unknown');
  });
});

describe('parseTfstate (v4 state)', () => {
  it('parses sample.tfstate with resources, outputs, dependencies and findings', () => {
    const parsed = parseTfstate(fs.readFileSync(SAMPLE_STATE));
    assert.equal(parsed.kind, 'tfstate-v4');
    assert.equal(parsed.terraformVersion, '1.9.5');
    assert.equal(parsed.serial, 42);
    assert.equal(parsed.stats.resourceCount, 5);
    assert.equal(parsed.stats.outputCount, 2);
    assert.equal(parsed.stats.dependencyCount, 4);
    assert.equal(parsed.stats.orphanedDependencyCount, 1);
    assert.equal(parsed.stats.sensitiveResourceCount, 1);

    const db = parsed.resources.find((r) => r.type === 'aws_db_instance');
    assert.ok(db);
    assert.equal(db.hasSensitive, true);
    assert.equal(db.maskedAttributes.password, MASK_LABEL);
    assert.equal(db.attributes.password, 'EXAMPLE-DB-PASSWORD-PLACEHOLDER');

    const vpc = parsed.resources.find((r) => r.type === 'aws_vpc');
    assert.ok(vpc.dependents.includes('module.network.aws_security_group.web'));
    assert.ok(vpc.dependents.includes('module.data.aws_db_instance.primary'));

    const sensOut = parsed.outputs.find((o) => o.name === 'db_connection_password');
    assert.equal(sensOut.sensitive, true);
    assert.equal(sensOut.maskedValue, MASK_LABEL);

    assert.ok(parsed.findings.some((f) => f.category === 'Orphaned Dependency'));
    assert.ok(parsed.findings.some((f) => f.category === 'Public Network'));
    assert.ok(parsed.findings.some((f) => f.category === 'Sensitive Data'));
  });

  it('detects IAM wildcard, public S3 ACL, unencrypted DB and tainted resource', () => {
    const state = {
      version: 4,
      terraform_version: '1.8.0',
      serial: 1,
      lineage: 'abc',
      resources: [
        {
          mode: 'managed',
          type: 'aws_iam_policy',
          name: 'admin',
          provider: 'provider["registry.terraform.io/hashicorp/aws"]',
          instances: [{
            status: 'tainted',
            attributes: {
              policy: JSON.stringify({ Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }),
            },
          }],
        },
        {
          mode: 'managed',
          type: 'aws_s3_bucket',
          name: 'open',
          provider: 'provider["registry.terraform.io/hashicorp/aws"]',
          instances: [{ attributes: { acl: 'public-read', storage_encrypted: false, publicly_accessible: true } }],
        },
      ],
    };
    const parsed = parseTfstate(JSON.stringify(state));
    assert.ok(parsed.findings.some((f) => f.category === 'IAM Wildcard' && f.severity === 'error'));
    assert.ok(parsed.findings.some((f) => f.category === 'Tainted Resource'));
    assert.ok(parsed.findings.some((f) => f.category === 'Public Storage' && f.severity === 'error'));
    assert.ok(parsed.findings.some((f) => f.category === 'Public Database' && f.severity === 'error'));
    assert.ok(parsed.findings.some((f) => f.category === 'Unencrypted Storage'));
  });
});

describe('parseTfstate (v3 legacy state and tfplan.json)', () => {
  it('parses legacy v3 state and flags legacy version', () => {
    const v3 = {
      version: 3,
      terraform_version: '0.11.15',
      serial: 5,
      modules: [
        {
          path: ['root'],
          outputs: { endpoint: { value: '10.0.0.5', type: 'string', sensitive: false } },
          resources: {
            'aws_instance.app': {
              type: 'aws_instance',
              primary: { id: 'i-123', attributes: { api_key: 'SECRET-KEY-EXAMPLE' } },
              depends_on: [],
            },
          },
        },
      ],
    };
    const parsed = parseTfstate(JSON.stringify(v3));
    assert.equal(parsed.kind, 'tfstate-v3');
    assert.equal(parsed.stats.resourceCount, 1);
    assert.equal(parsed.resources[0].maskedAttributes.api_key, MASK_LABEL);
    assert.ok(parsed.findings.some((f) => f.category === 'Legacy Version'));
  });

  it('parses terraform show -json plan files', () => {
    const parsed = parseTfstate(fs.readFileSync(SAMPLE_PLAN));
    assert.equal(parsed.kind, 'tfplan-json');
    assert.equal(parsed.stats.resourceCount, 3);
    assert.equal(parsed.stats.outputCount, 2);
    const actions = parsed.resources.map((r) => r.action);
    assert.deepEqual(actions, ['create', 'update', 'replace']);
    const db = parsed.resources.find((r) => r.type === 'aws_db_instance');
    assert.equal(db.maskedAttributes.password, MASK_LABEL);
    assert.ok(parsed.findings.some((f) => f.category === 'Destructive Plan Action'));
  });

  it('throws clear errors on empty, invalid or unrecognized input', () => {
    assert.throws(() => parseTfstate(''), /empty/i);
    assert.throws(() => parseTfstate('{bad json'), /Invalid JSON/i);
    assert.throws(() => parseTfstate('{}'), /Unrecognized Terraform/i);
  });
});

describe('TfstateViewModel', () => {
  it('filters by text, provider, module, mode and toggles secret masking', () => {
    const parsed = parseTfstate(fs.readFileSync(SAMPLE_STATE));
    const vm = new TfstateViewModel(parsed, 'sample.tfstate', 2048, true);
    assert.equal(vm.totalCount(), 5);
    assert.equal(vm.count(), 5);

    const dbRow = vm.rows(0, 10).find((r) => r.type === 'aws_db_instance');
    assert.equal(vm.detail(dbRow.index).attributes.password, MASK_LABEL);
    assert.equal(vm.outputs().find((o) => o.name === 'db_connection_password').value, MASK_LABEL);

    vm.setMaskSensitive(false);
    assert.equal(vm.detail(dbRow.index).attributes.password, 'EXAMPLE-DB-PASSWORD-PLACEHOLDER');
    assert.equal(vm.outputs().find((o) => o.name === 'db_connection_password').value, 'EXAMPLE-PLACEHOLDER-DO-NOT-USE');

    assert.equal(vm.setFilter({ module: 'module.network' }), 2);
    assert.equal(vm.setFilter({ mode: 'data' }), 1);
    assert.equal(vm.setFilter({ text: 'audit_logs' }), 1);
    assert.equal(vm.setFilter({}), 5);
  });
});

describe('Pro reports and exporters', () => {
  it('builds Markdown diff, audit report, CSVs, JSON and Mermaid graph with secrets masked', () => {
    const left = parseTfstate(fs.readFileSync(SAMPLE_STATE));
    const rightObj = JSON.parse(fs.readFileSync(SAMPLE_STATE, 'utf8'));
    rightObj.serial = 43;
    rightObj.resources[0].instances[0].attributes.cidr_block = '10.30.0.0/16';
    rightObj.resources.pop();
    const right = parseTfstate(JSON.stringify(rightObj));

    const diffMd = buildDiffMarkdown('old.tfstate', left, 'new.tfstate', right);
    assert.match(diffMd, /Terraform State & Plan Drift Report/);
    assert.match(diffMd, /Removed Resources/);
    assert.match(diffMd, /Modified Resources/);
    assert.match(diffMd, /10\.30\.0\.0\/16/);
    assert.doesNotMatch(diffMd, /EXAMPLE-DB-PASSWORD-PLACEHOLDER/);

    const auditMd = buildAuditMarkdown([{ fileName: 'sample.tfstate', parsed: left }]);
    assert.match(auditMd, /Terraform State Secret & Exposure Audit Report/);
    assert.match(auditMd, /Orphaned Dependency/);
    assert.doesNotMatch(auditMd, /EXAMPLE-DB-PASSWORD-PLACEHOLDER/);

    const resCsv = buildResourcesCsv(left, 'sample.tfstate');
    assert.match(resCsv, /aws_db_instance/);
    const outCsv = buildOutputsCsv(left, 'sample.tfstate');
    assert.match(outCsv, /\[SENSITIVE - masked\]/);
    assert.doesNotMatch(outCsv, /EXAMPLE-PLACEHOLDER-DO-NOT-USE/);

    const invJson = JSON.parse(buildInventoryJson(left, 'sample.tfstate'));
    assert.equal(invJson.stats.resourceCount, 5);
    assert.equal(invJson.resources.find((r) => r.type === 'aws_db_instance').attributes.password, MASK_LABEL);

    const mmd = buildMermaidGraph(left);
    assert.match(mmd, /^graph LR/);
    assert.match(mmd, /-->/);
    assert.match(mmd, /-\.->/);
  });
});

describe('Webview HTML and strict CSP', () => {
  it('includes nonce-based CSP and no unsafe-inline', () => {
    const policy = csp('vscode-resource:', 'testnonce123');
    assert.match(policy, /default-src 'none'/);
    assert.match(policy, /script-src 'nonce-testnonce123'/);
    assert.doesNotMatch(policy, /unsafe-inline/);

    const html = editorHtml({
      cspSource: 'vscode-resource:',
      script: 'vscode-resource:/viewer.js',
      styleUri: 'vscode-resource:/viewer.css',
      title: 'sample.tfstate',
      nonce: 'testnonce123',
      showSupportLinks: true,
    });
    assert.match(html, /Content-Security-Policy/);
    assert.match(html, /<script nonce="testnonce123" src="vscode-resource:\/viewer\.js"><\/script>/);
  });
});
