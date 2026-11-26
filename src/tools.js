'use strict';
// Pro tools for Terraform State & Plan Viewer:
//   1. diffStates: Compare two .tfstate or .tfplan.json files in a Markdown drift report.
//   2. auditSecrets: Offline sensitive-attribute, IAM wildcard and public-exposure audit report in Markdown.
//   3. exportInventory: Non-destructive CSV, JSON and Mermaid dependency graph export.
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const {
  parseTfstate,
  buildDiffMarkdown,
  buildAuditMarkdown,
  buildResourcesCsv,
  buildOutputsCsv,
  buildInventoryJson,
  buildMermaidGraph,
} = require('./tfstate');

const TF_EXT_RE = /\.(tfstate|tfstate\.backup|tfplan\.json|json)$/i;
const TF_FILTERS = { 'Terraform State / Plan': ['tfstate', 'backup', 'json'] };

function uniquePath(targetPath) {
  if (!fs.existsSync(targetPath)) return targetPath;
  const dir = path.dirname(targetPath);
  const ext = path.extname(targetPath);
  const base = path.basename(targetPath, ext);
  for (let i = 1; i < 10000; i++) {
    const cand = path.join(dir, `${base}-${i}${ext}`);
    if (!fs.existsSync(cand)) return cand;
  }
  return path.join(dir, `${base}-${Date.now()}${ext}`);
}

async function resolveTargetUri(uri, provider, openLabel = 'Select Terraform state or plan file') {
  if (uri && uri.scheme) return uri;
  if (provider && provider.active && provider.active.uri) return provider.active.uri;
  const ed = vscode.window.activeTextEditor;
  if (ed && ed.document && TF_EXT_RE.test(ed.document.uri.fsPath || ed.document.uri.path)) return ed.document.uri;
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    filters: TF_FILTERS,
    openLabel,
  });
  return picked && picked[0] ? picked[0] : null;
}

function listTfFilesInDir(dirPath) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  return entries
    .filter((e) => e.isFile() && /\.(tfstate|tfstate\.backup|tfplan\.json)$/i.test(e.name))
    .map((e) => path.join(dirPath, e.name))
    .sort();
}

function createTools({ provider, pro, reach }) {
  async function diffStates(uri, opts = {}) {
    if (!(await pro.allowed('diffStates', opts))) return undefined;
    const left = await resolveTargetUri(uri, provider, 'Select baseline Terraform state or plan file');
    if (!left) return undefined;

    let right = opts.compareUri || null;
    if (!right) {
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: false,
        filters: TF_FILTERS,
        openLabel: 'Select second Terraform state or plan file to compare',
      });
      right = picked && picked[0] ? picked[0] : null;
    }
    if (!right) return undefined;

    const leftBuf = Buffer.from(await vscode.workspace.fs.readFile(left));
    const rightBuf = Buffer.from(await vscode.workspace.fs.readFile(right));
    const md = buildDiffMarkdown(
      path.basename(left.fsPath || left.path),
      parseTfstate(leftBuf),
      path.basename(right.fsPath || right.path),
      parseTfstate(rightBuf),
    );
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('diffStates');
    if (reach) reach.refresh();
    return { markdown: md };
  }

  async function auditSecrets(uri, opts = {}) {
    if (!(await pro.allowed('auditSecrets', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const isDir = target.scheme === 'file' && fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory();
    const files = isDir ? listTfFilesInDir(targetPath) : [targetPath];
    if (!files.length) {
      vscode.window.showInformationMessage('No Terraform state or plan files were found in this folder.');
      return undefined;
    }

    const entries = [];
    for (const f of files) {
      const buf = f === targetPath && target.scheme !== 'file'
        ? Buffer.from(await vscode.workspace.fs.readFile(target))
        : fs.readFileSync(f);
      entries.push({ fileName: path.basename(f), parsed: parseTfstate(buf) });
    }
    const md = buildAuditMarkdown(entries);
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('auditSecrets');
    if (reach) reach.refresh();
    return { files: files.length, markdown: md };
  }

  async function exportInventory(uri, opts = {}) {
    if (!(await pro.allowed('exportInventory', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const bytes = await vscode.workspace.fs.readFile(target);
    const parsed = parseTfstate(Buffer.from(bytes));
    const baseName = path.basename(targetPath).replace(/\.(tfstate\.backup|tfplan\.json|tfstate|json)$/i, '');
    const defaultOut = uniquePath(path.join(path.dirname(targetPath), `${baseName}-resources.csv`));
    const saveUri = opts.outPath
      ? vscode.Uri.file(uniquePath(opts.outPath))
      : await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(defaultOut),
        filters: { 'CSV file': ['csv'] },
        saveLabel: 'Save resources CSV',
      });
    if (!saveUri) return undefined;

    const resPath = uniquePath(saveUri.fsPath);
    const dir = path.dirname(resPath);
    const stem = path.basename(resPath, '.csv');
    const outPath = uniquePath(path.join(dir, `${stem}-outputs.csv`));
    const jsonPath = uniquePath(path.join(dir, `${stem}.json`));
    const mmdPath = uniquePath(path.join(dir, `${stem}-deps.mmd`));

    fs.writeFileSync(resPath, buildResourcesCsv(parsed, path.basename(targetPath)), 'utf8');
    fs.writeFileSync(outPath, buildOutputsCsv(parsed, path.basename(targetPath)), 'utf8');
    fs.writeFileSync(jsonPath, buildInventoryJson(parsed, path.basename(targetPath)), 'utf8');
    fs.writeFileSync(mmdPath, buildMermaidGraph(parsed), 'utf8');

    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(resPath));
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('exportInventory');
    if (reach) reach.refresh();
    return { files: [resPath, outPath, jsonPath, mmdPath], resources: parsed.stats.resourceCount };
  }

  return { diffStates, auditSecrets, exportInventory };
}

module.exports = { createTools, uniquePath };
