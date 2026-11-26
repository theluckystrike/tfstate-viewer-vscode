/* global acquireVsCodeApi */
(function () {
  'use strict';
  const vscode = acquireVsCodeApi();
  const app = document.getElementById('app');

  let state = {
    name: '',
    summary: null,
    pageSize: 100,
    page: 0,
    total: 0,
    rows: [],
    selected: null,
    tab: 'resources',
    maskSensitive: true,
    req: 0,
  };

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function post(msg) {
    state.req += 1;
    vscode.postMessage({ ...msg, req: state.req });
  }

  function fmtSize(n) {
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  }

  function fmtVal(v) {
    if (v === null || v === undefined) return '-';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  }

  function renderShell() {
    const s = state.summary;
    const errChip = s.errorCount > 0 ? `<span class="chip bad"><b>Errors:</b> ${s.errorCount}</span>` : '<span class="chip"><b>Checks:</b> OK</span>';
    const warnChip = s.warningCount > 0 ? `<span class="chip warn"><b>Warnings:</b> ${s.warningCount}</span>` : '';
    const sensChip = s.sensitiveResourceCount > 0 ? `<span class="chip warn"><b>Sensitive:</b> ${s.sensitiveResourceCount}</span>` : '';
    const provOpts = (s.providers || []).map(([p, n]) => `<option value="${esc(p)}">${esc(p)} (${n})</option>`).join('');
    const modOpts = (s.modules || []).map(([m, n]) => `<option value="${esc(m)}">${esc(m)} (${n})</option>`).join('');
    const modeOpts = (s.modes || []).map(([m, n]) => `<option value="${esc(m)}">${esc(m)} (${n})</option>`).join('');
    const serialText = s.serial !== null && s.serial !== undefined ? ` · Serial #${s.serial}` : '';

    app.innerHTML = `
      <div class="top">
        <div class="title">
          <span class="name">${esc(state.name)}</span>
          <span class="kind">${esc(s.kind)} · Terraform ${esc(s.terraformVersion)}${esc(serialText)} · ${fmtSize(s.fileSize)}</span>
        </div>
        <div class="summary">
          <span class="chip"><b>Resources:</b> ${s.resourceCount}</span>
          <span class="chip"><b>Outputs:</b> ${s.outputCount}</span>
          <span class="chip"><b>Dependencies:</b> ${s.dependencyCount}</span>
          <span class="chip"><b>Modules:</b> ${s.moduleCount}</span>
          ${sensChip}${errChip}${warnChip}
        </div>
        <div class="toolbar">
          <input id="q" type="search" placeholder="Filter by address, type, name, provider, module or ID..." />
          <select id="provFilter">
            <option value="">All providers</option>
            ${provOpts}
          </select>
          <select id="modFilter">
            <option value="">All modules</option>
            ${modOpts}
          </select>
          <select id="modeFilter">
            <option value="">All modes</option>
            ${modeOpts}
          </select>
          <button id="filterBtn" type="button">Filter</button>
          <button id="maskBtn" type="button">${state.maskSensitive ? 'Secrets: Masked' : 'Secrets: Visible'}</button>
          <span class="sep"></span>
          <div id="protools"></div>
        </div>
        <div class="tabs">
          <button class="tab on" data-tab="resources" type="button">Resources (${s.resourceCount})</button>
          <button class="tab" data-tab="outputs" type="button">Outputs (${s.outputCount})</button>
          <button class="tab" data-tab="dependencies" type="button">Dependencies (${s.dependencyCount})</button>
          <button class="tab" data-tab="findings" type="button">Health Findings (${s.errorCount + s.warningCount})</button>
        </div>
        <div id="hint" class="hint"></div>
      </div>
      <div class="main">
        <div id="leftPane" class="tablewrap"></div>
        <div id="detail" class="detail"><p class="muted">Select a resource to inspect its attributes, dependencies and sensitive fields.</p></div>
      </div>
      <div class="pager">
        <button id="prev" type="button">Prev</button>
        <span id="pageInfo"></span>
        <button id="next" type="button">Next</button>
      </div>
    `;

    const q = document.getElementById('q');
    const provSel = document.getElementById('provFilter');
    const modSel = document.getElementById('modFilter');
    const modeSel = document.getElementById('modeFilter');
    const runFilter = () => {
      state.page = 0;
      post({ type: 'filter', filter: { text: q.value, provider: provSel.value, module: modSel.value, mode: modeSel.value } });
    };
    document.getElementById('filterBtn').addEventListener('click', runFilter);
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter') runFilter(); });
    provSel.addEventListener('change', runFilter);
    modSel.addEventListener('change', runFilter);
    modeSel.addEventListener('change', runFilter);

    document.getElementById('maskBtn').addEventListener('click', () => {
      post({ type: 'toggleMask', mask: !state.maskSensitive, selected: state.selected });
    });

    document.querySelectorAll('.tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach((b) => b.classList.remove('on'));
        btn.classList.add('on');
        state.tab = btn.dataset.tab;
        renderPane();
      });
    });

    document.getElementById('prev').addEventListener('click', () => {
      if (state.page > 0) { state.page -= 1; loadPage(); }
    });
    document.getElementById('next').addEventListener('click', () => {
      if ((state.page + 1) * state.pageSize < state.total) { state.page += 1; loadPage(); }
    });
  }

  function loadPage() {
    post({ type: 'page', from: state.page * state.pageSize, n: state.pageSize });
  }

  function renderPane() {
    const left = document.getElementById('leftPane');
    const pager = document.querySelector('.pager');
    const s = state.summary;

    if (state.tab === 'outputs') {
      pager.style.display = 'none';
      const rows = (s.outputs || []).map((o) => `<tr>
        <td><strong>${esc(o.name)}</strong></td>
        <td>${esc(o.type)}</td>
        <td>${esc(o.action)}</td>
        <td class="${o.sensitive ? 'bad' : 'ok'}">${o.sensitive ? 'SENSITIVE' : 'public'}</td>
        <td><code>${esc(fmtVal(o.value))}</code></td>
      </tr>`).join('');
      left.innerHTML = `<table id="grid"><thead><tr><th>Output Name</th><th>Type</th><th>Action</th><th>Sensitivity</th><th>Value</th></tr></thead><tbody>${rows || '<tr><td colspan="5" class="muted">No outputs defined in this file.</td></tr>'}</tbody></table>`;
      return;
    }

    if (state.tab === 'dependencies') {
      pager.style.display = 'none';
      const rows = (s.edges || []).map((e, i) => `<tr>
        <td class="num">${i + 1}</td>
        <td><code>${esc(e.from)}</code></td>
        <td>-&gt;</td>
        <td><code>${esc(e.to)}</code></td>
        <td class="${e.orphaned ? 'bad' : 'ok'}">${e.orphaned ? 'ORPHANED' : 'OK'}</td>
      </tr>`).join('');
      left.innerHTML = `<table id="grid"><thead><tr><th class="num">#</th><th>Resource</th><th></th><th>Depends On</th><th>Status</th></tr></thead><tbody>${rows || '<tr><td colspan="5" class="muted">No explicit resource dependencies recorded.</td></tr>'}</tbody></table>`;
      return;
    }

    if (state.tab === 'findings') {
      pager.style.display = 'none';
      const fRows = (s.findings || []).map((f) => `<tr>
        <td class="${f.severity === 'error' ? 'bad' : ''}">${esc(f.severity.toUpperCase())}</td>
        <td>${esc(f.category)}</td>
        <td><code>${esc(f.resource)}</code></td>
        <td>${esc(f.finding)}</td>
      </tr>`).join('');
      left.innerHTML = fRows
        ? `<table id="grid"><thead><tr><th>Severity</th><th>Category</th><th>Resource</th><th>Finding</th></tr></thead><tbody>${fRows}</tbody></table>`
        : '<p class="muted" style="padding:12px;">All state health, dependency and exposure checks passed.</p>';
      return;
    }

    pager.style.display = 'flex';
    const body = state.rows.map((r) => {
      const sel = state.selected === r.index ? ' class="sel"' : '';
      const sensBadge = r.hasSensitive ? '<span class="badge-mismatch">SENSITIVE</span>' : '';
      const taintBadge = r.tainted ? '<span class="badge-mismatch">TAINTED</span>' : '';
      const modeCls = (r.action === 'delete' || r.action === 'replace') ? 'bad' : (r.action === 'create' ? 'ok' : '');
      return `<tr data-idx="${r.index}"${sel}>
        <td class="num">${r.index}</td>
        <td><strong>${esc(r.address)}</strong>${sensBadge}${taintBadge}</td>
        <td class="${modeCls}">${esc(r.action)}</td>
        <td>${esc(r.provider)}</td>
        <td><code>${esc(r.type)}</code></td>
        <td>${esc(r.name)}</td>
        <td>${esc(r.module)}</td>
        <td class="num">${r.dependencyCount}</td>
      </tr>`;
    }).join('');
    left.innerHTML = `<table id="grid">
      <thead><tr><th class="num">#</th><th>Address</th><th>Mode / Action</th><th>Provider</th><th>Type</th><th>Name</th><th>Module</th><th class="num">Deps</th></tr></thead>
      <tbody>${body || '<tr><td colspan="8" class="muted">No matching resources.</td></tr>'}</tbody>
    </table>`;

    left.querySelectorAll('tbody tr[data-idx]').forEach((tr) => {
      tr.addEventListener('click', () => {
        const idx = Number(tr.dataset.idx);
        state.selected = idx;
        left.querySelectorAll('tbody tr').forEach((row) => row.classList.toggle('sel', Number(row.dataset.idx) === idx));
        post({ type: 'detail', index: idx });
      });
    });

    const pages = Math.max(1, Math.ceil(state.total / state.pageSize));
    document.getElementById('pageInfo').textContent = `Page ${state.page + 1} of ${pages} (${state.total} resources)`;
    document.getElementById('prev').disabled = state.page <= 0;
    document.getElementById('next').disabled = (state.page + 1) * state.pageSize >= state.total;
  }

  function renderDetail(d) {
    const el = document.getElementById('detail');
    if (!d) {
      el.innerHTML = '<p class="muted">No resource selected.</p>';
      return;
    }
    const pairs = [
      ['Address', d.address],
      ['Module', d.module],
      ['Mode / Action', `${d.mode} (${d.action})`],
      ['Provider', d.providerRaw || d.provider],
      ['Type', d.type],
      ['Name', d.name],
      ['ID / ARN', d.id || '-'],
      ['Tainted', d.tainted ? 'YES' : 'no'],
      ['Sensitive Paths', d.sensitivePaths.length ? d.sensitivePaths.join(', ') : 'none'],
      ['Depends On', d.dependencies.length ? d.dependencies.join(', ') : 'none'],
      ['Used By', d.dependents.length ? d.dependents.join(', ') : 'none'],
    ];
    const rows = pairs.map(([k, v]) => `<tr><td><strong>${esc(k)}</strong></td><td><code>${esc(v)}</code></td></tr>`).join('');
    const attrJson = JSON.stringify(d.attributes || {}, null, 2);
    el.innerHTML = `
      <div class="dhead"><strong>#${d.index}: ${esc(d.address)}</strong><span class="muted">${d.masked ? 'Masked' : 'Unmasked'}</span></div>
      <table class="splits"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>
      <div class="attr-head"><strong>Attributes JSON</strong></div>
      <pre class="attr-json">${esc(attrJson)}</pre>
    `;
  }

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (!m || typeof m !== 'object') return;
    switch (m.type) {
      case 'init':
        if (m.error) {
          app.innerHTML = `<div class="error"><strong>Could not open ${esc(m.name)}</strong><p>${esc(m.error)}</p></div>`;
          return;
        }
        state.name = m.name;
        state.summary = m.summary;
        state.maskSensitive = m.summary.maskSensitive !== false;
        state.pageSize = m.pageSize || 100;
        state.page = 0;
        renderShell();
        loadPage();
        return;
      case 'pageResult':
        state.total = m.total;
        state.rows = m.rows || [];
        renderPane();
        if (state.rows.length && state.selected == null) {
          state.selected = state.rows[0].index;
          post({ type: 'detail', index: state.selected });
        }
        return;
      case 'filterResult':
        state.total = m.count;
        document.getElementById('hint').textContent = m.count < m.total ? `Showing ${m.count} of ${m.total} resources.` : '';
        loadPage();
        return;
      case 'detailResult':
        renderDetail(m.detail);
        return;
      case 'maskResult':
        state.maskSensitive = Boolean(m.maskSensitive);
        if (state.summary && Array.isArray(m.outputs)) state.summary.outputs = m.outputs;
        if (document.getElementById('maskBtn')) {
          document.getElementById('maskBtn').textContent = state.maskSensitive ? 'Secrets: Masked' : 'Secrets: Visible';
        }
        if (state.tab === 'outputs') renderPane();
        if (m.detail) renderDetail(m.detail);
        return;
      case 'zovoAlso': {
        const anchor = m.anchor && document.getElementById(m.anchor);
        if (anchor && m.html) {
          const old = document.querySelector('.zovo-also');
          if (old) old.remove();
          anchor.insertAdjacentHTML('afterend', m.html);
        }
        return;
      }
      case 'hint':
        if (document.getElementById('hint')) document.getElementById('hint').textContent = m.text || '';
        return;
      default:
    }
  });

  post({ type: 'ready' });
})();
