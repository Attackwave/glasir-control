'use strict';
// Glasir Control console. Every value from the server reaches the page through
// textContent, never as markup, and the access token lives only in `session`.

const session = { token: null, user: null, admin: false };
const loaded = {};

/* ---- DOM helpers ------------------------------------------------------ */

const $ = (selector, root = document) => root.querySelector(selector);

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function replace(target, ...nodes) {
  (typeof target === 'string' ? $(target) : target).replaceChildren(...nodes.flat(Infinity));
}

function badge(text, tone = '', plain = false) {
  return h('span', { class: `badge ${tone}${plain ? ' plain' : ''}`, text });
}

function chips(values, limit = 16, plain = false) {
  const list = values || [];
  const shown = list.slice(0, limit).map(v => h('span', { class: `chip${plain ? ' plain' : ''}`, text: v }));
  if (list.length > limit) shown.push(h('span', { class: 'more', text: `and ${list.length - limit} more` }));
  return h('div', { class: 'chips' }, shown);
}

function state(title, detail) {
  return h('div', { class: 'state' }, h('strong', { text: title }), detail ? h('span', { text: detail }) : null);
}

function loading(text) {
  return h('div', { class: 'state' }, h('span', { class: 'spinner' }), text);
}

function alertBox(text, tone = '') {
  return h('div', { class: `alert ${tone}`, role: 'alert', text });
}

let toastTimer = null;
function toast(text) {
  const node = $('#toast');
  node.textContent = text;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 4000);
}

function when(seconds) {
  if (!seconds) return '—';
  return new Date(seconds * 1000).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

const plural = (n, one, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;

/* ---- API -------------------------------------------------------------- */

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(path, { method = 'GET', body } = {}) {
  const response = await fetch(path, {
    method,
    headers: {
      Authorization: `Bearer ${session.token}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: 'no-store',
  });
  const text = await response.text();
  if (response.status === 401 && session.token) {
    signOut('Your session is no longer valid. Sign in again.');
    throw new ApiError(401, 'signed out');
  }
  if (response.status === 403 && text.includes('origin')) {
    throw new ApiError(403, `This instance does not accept changes from ${location.origin}. `
      + `The operator has to start Glasir Control with --allowed-origin ${location.origin}.`);
  }
  if (!response.ok) throw new ApiError(response.status, text.trim() || response.statusText);
  try { return text ? JSON.parse(text) : null; } catch { return text; }
}

/* ---- Instance status -------------------------------------------------- */

async function checkHealth() {
  const dot = $('#health-dot');
  try {
    const response = await fetch('/health', { cache: 'no-store' });
    const health = await response.json();
    const ok = health.status === 'ok';
    dot.className = `dot ${ok ? 'ok' : 'bad'}`;
    $('#health-text').textContent = ok
      ? `Operational · ${plural(health.configured_trees, 'repository', 'repositories')}`
      : 'Degraded';
    $('#version-line').textContent = health.version ? `Version ${health.version}` : '';
    $('#instance-line').textContent = ok
      ? `Instance operational · version ${health.version}`
      : 'Instance reports a problem.';
  } catch {
    dot.className = 'dot bad';
    $('#health-text').textContent = 'Unreachable';
    $('#instance-line').textContent = 'The instance did not answer its health check.';
  }
}

/* ---- Sign-in ---------------------------------------------------------- */

async function signIn(event) {
  event.preventDefault();
  const input = $('#token');
  const error = $('#signin-error');
  const button = $('#signin-button');
  error.hidden = true;
  button.disabled = true;
  button.textContent = 'Signing in…';
  session.token = input.value.trim();
  try {
    const me = await api('/api/session');
    session.user = me.user;
    session.admin = !!me.admin;
    input.value = '';
    startApp();
  } catch (e) {
    session.token = null;
    error.textContent = e.status === 401
      ? 'This token was not accepted. Check it, or ask your administrator for a new one.'
      : 'The instance could not be reached. Try again in a moment.';
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = 'Sign in';
  }
}

function signOut(message) {
  session.token = null;
  session.user = null;
  session.admin = false;
  for (const key of Object.keys(loaded)) delete loaded[key];
  for (const id of ['#review-result', '#access-result', '#audit-result', '#policy-list', '#policy-detail']) replace(id);
  $('#app').hidden = true;
  $('#signin').hidden = false;
  const error = $('#signin-error');
  error.hidden = !message;
  error.textContent = message || '';
  $('#token').focus();
}

function startApp() {
  $('#signin').hidden = true;
  $('#app').hidden = false;
  $('#user').textContent = session.user;
  $('#role').textContent = session.admin ? 'Administrator' : 'Reviewer';
  $('#avatar').textContent = (session.user || '?').slice(0, 2).toUpperCase();
  document.querySelectorAll('.admin-only').forEach(node => { node.hidden = !session.admin; });
  route();
}

/* ---- Routing ---------------------------------------------------------- */

const VIEWS = {
  review: { title: 'Impact review', crumb: 'Review', admin: false, load: loadReview },
  access: { title: 'Access review', crumb: 'Governance', admin: true, load: loadAccess },
  audit: { title: 'Audit log', crumb: 'Governance', admin: true, load: loadAudit },
  policy: { title: 'Policy changes', crumb: 'Governance', admin: true, load: loadPolicy },
};

function route() {
  if (!session.token) return;
  let name = location.hash.slice(1);
  if (!VIEWS[name]) name = location.pathname.startsWith('/admin') && session.admin ? 'access' : 'review';
  if (VIEWS[name].admin && !session.admin) name = 'review';
  const view = VIEWS[name];
  document.querySelectorAll('.view').forEach(node => { node.hidden = node.dataset.panel !== name; });
  document.querySelectorAll('nav a').forEach(link => {
    if (link.dataset.view === name) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
  $('#title').textContent = view.title;
  $('#crumb').textContent = view.crumb;
  document.title = `${view.title} · Glasir Control`;
  if (!loaded[name]) {
    loaded[name] = true;
    view.load();
  }
}

/* ---- Impact review ---------------------------------------------------- */

const RISK = { low: ['Low', 'ok', 0], medium: ['Medium', 'warn', 1], high: ['High', 'bad', 2] };

async function loadReview() {
  const select = $('#workspace');
  replace(select, h('option', { text: 'Loading workspaces…', value: '' }));
  try {
    const workspaces = await api('/workspaces');
    const hint = $('#workspace-hint');
    if (!workspaces.length) {
      replace(select, h('option', { text: 'No workspace available', value: '' }));
      hint.textContent = 'A workspace appears only when you may read every repository in it. Ask an administrator to grant the missing ones.';
      hint.hidden = false;
      $('#review-run').disabled = true;
      return;
    }
    hint.hidden = true;
    $('#review-run').disabled = false;
    replace(select, workspaces.map(w =>
      h('option', { value: w.name, text: `${w.name} — ${plural(w.trees.length, 'repository', 'repositories')}` })));
    replace('#review-result', state('No review yet', 'Choose a workspace and a revision to compare against, then run the review.'));
  } catch (e) {
    if (e.status !== 401) replace('#review-result', alertBox(`Workspaces could not be loaded: ${e.message}`));
  }
}

async function runReview(event) {
  event.preventDefault();
  const button = $('#review-run');
  button.disabled = true;
  replace('#review-result', loading('Reviewing every repository in the workspace…'));
  try {
    const result = await api('/api/review/impact', {
      method: 'POST',
      body: { workspace: $('#workspace').value, rev: $('#rev').value.trim(), depth: Number($('#depth').value) },
    });
    replace('#review-result', renderReview(result));
  } catch (e) {
    if (e.status === 400) replace('#review-result', alertBox('The revision is not valid. Use a branch, tag, commit or an expression like HEAD~3.'));
    else if (e.status !== 401) replace('#review-result', alertBox(e.status === 403 ? e.message : `The review failed: ${e.message}`));
  } finally {
    button.disabled = false;
  }
}

function structured(repo) {
  if (repo.error) return { error: repo.error };
  const reply = repo.result || {};
  if (reply.error) return { error: reply.error.message || JSON.stringify(reply.error) };
  const result = reply.result || {};
  if (result.isError) return { error: (result.content || []).map(c => c.text).join(' ') || 'The repository refused the request.' };
  return { data: result.structuredContent || {} };
}

function renderReview(review) {
  const repos = (review.repositories || []).map(repo => ({ repo, ...structured(repo) }));
  const good = repos.filter(r => r.data);
  const worst = good.reduce((acc, r) => {
    const level = (r.data.risk || {}).level || 'low';
    return (RISK[level] || RISK.low)[2] > (RISK[acc] || RISK.low)[2] ? level : acc;
  }, 'low');
  const symbols = good.reduce((n, r) => n + (r.data.changed_symbols || []).length, 0);
  const dependents = good.reduce((n, r) => n + (Number(r.data.dependents) || 0), 0);
  const failed = repos.length - good.length;
  const [riskText, riskTone] = RISK[worst] || RISK.low;

  const kpi = (label, value) => h('div', { class: 'card kpi' }, h('div', { class: 'label', text: label }), h('div', { class: 'value' }, value));
  const summary = h('div', { class: 'kpis' },
    kpi('Overall risk', good.length ? badge(riskText, riskTone) : '—'),
    kpi('Repositories', `${good.length} of ${repos.length}`),
    kpi('Changed symbols', symbols.toLocaleString()),
    kpi('Dependent symbols', dependents.toLocaleString()),
  );

  const nodes = [summary];
  if (failed) nodes.push(alertBox(`${plural(failed, 'repository', 'repositories')} could not be reviewed. The result below is incomplete.`));
  nodes.push(h('p', { class: 'hint', text: `Workspace ${review.workspace} · compared against ${review.rev} · ${review.depth} ${review.depth === 1 ? 'hop' : 'hops'} deep` }));
  nodes.push(h('div', { class: 'repo-grid' }, repos.map(renderRepo)));
  const evidence = review.cross_repo_evidence || {};
  if ((evidence.edges || []).length || (evidence.unresolved || []).length) nodes.push(renderEvidence(evidence));
  return nodes;
}

function renderRepo({ repo, data, error }) {
  if (error) {
    return h('article', { class: 'card repo' },
      h('div', { class: 'card-head' }, h('h2', {}, repo.tree, badge(repo.status === 502 ? 'Not answering' : 'Failed', 'bad'))),
      h('div', { class: 'card-body' }, h('p', { class: 'empty-note', text: error })));
  }
  const risk = data.risk || {};
  const [riskText, riskTone] = RISK[risk.level] || RISK.low;
  const changed = data.changed_symbols || [];

  const reasons = [];
  for (const symbol of risk.untested || []) {
    reasons.push(h('li', {}, h('span', {}, h('code', { text: symbol }), ' has callers and no test reaches it')));
  }
  for (const miss of risk.missed_partners || []) {
    reasons.push(h('li', {}, h('span', {}, h('code', { text: miss.partner }),
      ' usually changes with ', h('code', { text: miss.file }),
      ` (${miss.together} of ${miss.commits} commits) and is not part of this change`)));
  }

  const hops = (data.hops || []).filter(hop => (hop.symbols || []).length);
  return h('article', { class: 'card repo' },
    h('div', { class: 'card-head' },
      h('h2', {}, repo.tree, badge(`${riskText} risk`, riskTone)),
      h('span', { class: 'meta', text: `${plural(data.changed_files || 0, 'file')} · ${plural(changed.length, 'symbol')} · ${plural(Number(data.dependents) || 0, 'dependent')}` })),
    h('div', { class: 'repo-body' },
      h('div', {},
        h('div', { class: 'section-label', text: 'Why this rating' }),
        reasons.length ? h('ul', { class: 'reasons' }, reasons)
          : h('p', { class: 'empty-note', text: changed.length ? 'Nothing that is used goes untested, and no usual partner file is missing.' : 'No change against this revision.' })),
      h('div', {},
        h('div', { class: 'section-label', text: 'Changed symbols' }),
        changed.length ? chips(changed) : h('p', { class: 'empty-note', text: 'None' }),
        (data.files_without_known_symbols || []).length ? h('div', { class: 'section-label', text: 'Other changed files' }) : null,
        (data.files_without_known_symbols || []).length ? chips(data.files_without_known_symbols, 8) : null),
      h('div', {},
        h('div', { class: 'section-label', text: 'Affected code' }),
        hops.length ? hops.map(hop => h('div', { class: 'hop' },
          h('div', { class: 'hop-title', text: `${hop.hop === 1 ? 'Direct' : `${hop.hop} hops away`} · ${plural(hop.symbols.length, 'symbol')}` }),
          chips(hop.symbols, 10))) : h('p', { class: 'empty-note', text: 'Nothing depends on the changed symbols.' }))));
}

function renderEvidence(evidence) {
  const edges = evidence.edges || [];
  const keys = [...new Set(edges.flatMap(e => Object.keys(e)))];
  return h('section', { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', { text: 'Cross-repository contracts' }), badge(plural(edges.length, 'edge'), 'info', true)),
    edges.length ? h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, keys.map(k => h('th', { text: k.replace(/_/g, ' ') })))),
      h('tbody', {}, edges.map(e => h('tr', {}, keys.map(k => h('td', { text: typeof e[k] === 'object' ? JSON.stringify(e[k]) : e[k] ?? '' }))))))) : null,
    (evidence.unresolved || []).length ? h('div', { class: 'card-body' },
      h('div', { class: 'section-label', text: 'Unresolved' }), chips(evidence.unresolved, 30)) : null);
}

/* ---- Access review ---------------------------------------------------- */

let accessData = null;

async function loadAccess() {
  replace('#access-result', loading('Loading the access review…'));
  try {
    accessData = await api('/api/admin/access-review');
    renderAccess();
  } catch (e) {
    if (e.status !== 401) replace('#access-result', alertBox(`The access review could not be loaded: ${e.message}`));
  }
}

function matches(filter, ...values) {
  if (!filter) return true;
  return values.flat().join(' ').toLowerCase().includes(filter);
}

function toolAccess(entries) {
  if (!entries || !entries.length) return badge('All tools', 'ok', true);
  if (Array.isArray(entries) && typeof entries[0] === 'object') {
    return h('div', { class: 'chips' }, entries.map(t => t.mode === 'all'
      ? h('span', { class: 'chip plain', text: `${t.tree}: all tools` })
      : h('span', { class: 'chip plain', text: `${t.tree}: ${t.tools.join(', ')}` })));
  }
  return badge(String(entries), 'ok', true);
}

function renderAccess() {
  if (!accessData) return;
  const filter = $('#access-filter').value.trim().toLowerCase();
  const grants = (accessData.direct_grants || []).filter(g => matches(filter, g.user, g.trees));
  const roles = (accessData.roles || []).filter(r => matches(filter, r.role, r.trees, r.local_members, r.mapped_idp_groups));
  const trees = accessData.trees || [];

  const kpi = (label, value) => h('div', { class: 'card kpi' }, h('div', { class: 'label', text: label }), h('div', { class: 'value', text: value }));
  const people = new Set([...(accessData.direct_grants || []).map(g => g.user), ...(accessData.roles || []).flatMap(r => r.local_members || [])]);
  replace('#access-result',
    h('div', { class: 'kpis' },
      kpi('Repositories', trees.length.toLocaleString()),
      kpi('People with access', people.size.toLocaleString()),
      kpi('Roles', (accessData.roles || []).length.toLocaleString()),
      kpi('Mapped IdP groups', new Set((accessData.roles || []).flatMap(r => r.mapped_idp_groups || [])).size.toLocaleString())),
    h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', { text: 'Roles' }), badge(plural(roles.length, 'role'), '', true)),
      roles.length ? h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, ['Role', 'Repositories', 'Members', 'IdP groups', 'Tool access'].map(t => h('th', { text: t })))),
        h('tbody', {}, roles.map(r => h('tr', {},
          h('td', {}, h('strong', { text: r.role }), r.role === 'admin' ? [' ', badge('Administrators', 'info', true)] : null),
          h('td', {}, chips(r.trees, 8)),
          h('td', {}, (r.local_members || []).length ? chips(r.local_members, 8, true) : h('span', { class: 'muted', text: '—' })),
          h('td', {}, (r.mapped_idp_groups || []).length ? chips(r.mapped_idp_groups, 6, true) : h('span', { class: 'muted', text: '—' })),
          h('td', {}, toolAccess(r.tool_access))))))) : state('No roles match'),
    ),
    h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', { text: 'Direct grants' }), badge(plural(grants.length, 'person', 'people'), '', true)),
      grants.length ? h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, ['Person', 'Repositories', 'Tool access'].map(t => h('th', { text: t })))),
        h('tbody', {}, grants.map(g => h('tr', {},
          h('td', {}, h('strong', { text: g.user })),
          h('td', {}, chips(g.trees, 12)),
          h('td', {}, badge('All tools', 'ok', true)))))))
        : state('No direct grants match'),
    ),
    h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', { text: 'Repositories' }), badge(plural(trees.length, 'repository', 'repositories'), '', true)),
      h('div', { class: 'card-body' }, chips(trees, 200)),
    ),
  );
}

function exportAccess() {
  if (!accessData) return;
  const blob = new Blob([JSON.stringify(accessData, null, 2)], { type: 'application/json' });
  const link = h('a', { href: URL.createObjectURL(blob), download: `access-review-${new Date().toISOString().slice(0, 10)}.json` });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

/* ---- Audit log -------------------------------------------------------- */

let auditEvents = null;

async function loadAudit() {
  replace('#audit-result', loading('Loading recent events…'));
  try {
    const data = await api('/api/admin/audit');
    auditEvents = data.events || [];
    renderAudit();
  } catch (e) {
    if (e.status === 503) replace('#audit-result', state('Audit logging is not enabled on this instance', 'Start Glasir Control with --audit <file> to record every request.'));
    else if (e.status !== 401) replace('#audit-result', alertBox(`The audit log could not be loaded: ${e.message}`));
  }
}

function statusTone(status) {
  if (status >= 500) return 'bad';
  if (status >= 400) return 'warn';
  return 'ok';
}

function renderAudit() {
  if (!auditEvents) return;
  const filter = $('#audit-filter').value.trim().toLowerCase();
  const cls = $('#audit-status').value;
  const rows = auditEvents.filter(e =>
    matches(filter, e.who || 'anonymous', e.path, e.tree || '', e.method, e.client_addr || '') &&
    (!cls || String(e.status).startsWith(cls)));
  replace('#audit-result', h('section', { class: 'card' },
    rows.length ? h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Time', 'Identity', 'Request', 'Repository', 'Outcome', 'Duration', 'Size', 'Client'].map(t => h('th', { text: t })))),
      h('tbody', {}, rows.map(e => h('tr', {},
        h('td', { class: 'time', text: when(e.ts) }),
        h('td', {}, e.who ? h('strong', { text: e.who }) : h('span', { class: 'muted', text: 'anonymous' })),
        h('td', {}, badge(e.method, '', true), ' ', h('code', { text: e.path })),
        h('td', {}, e.tree ? h('code', { text: e.tree }) : h('span', { class: 'muted', text: '—' })),
        h('td', {}, badge(String(e.status), statusTone(e.status))),
        h('td', { class: 'num', text: `${(e.duration_ms ?? 0).toLocaleString()} ms` }),
        h('td', { class: 'num', text: `${(e.bytes ?? 0).toLocaleString()} B` }),
        h('td', {}, h('code', { text: e.client_addr || '' })))))))
      : state('No events match the filter'),
    h('div', { class: 'table-foot', text: `Showing ${rows.length} of the ${auditEvents.length} most recent events` })));
}

/* ---- Policy changes --------------------------------------------------- */

let policy = { proposals: [], active: '', selected: null };

async function loadPolicy(select) {
  replace('#policy-list', loading('Loading proposals…'));
  if (!select) replace('#policy-detail', state('Select a proposal', 'Or start a new one to change who can reach which repository.'));
  try {
    const data = await api('/api/admin/policy/proposals');
    policy.proposals = data.proposals || [];
    policy.active = data.active_rights || '';
    renderProposalList();
    if (select) openProposal(select);
  } catch (e) {
    if (e.status !== 401) replace('#policy-list', alertBox(`Proposals could not be loaded: ${e.message}`));
  }
}

function stateBadge(value) {
  if (value === 'approved') return badge('Approved', 'ok');
  if (value === 'pending') return badge('Awaiting approval', 'warn');
  return badge(value || 'unknown');
}

function renderProposalList() {
  const pending = policy.proposals.filter(p => p.state === 'pending').length;
  replace('#policy-list',
    policy.proposals.length ? [
      h('div', { class: 'card-body' }, h('span', { class: 'hint', text: `${plural(pending, 'proposal')} awaiting approval` })),
      policy.proposals.map(p => h('button', {
        class: 'proposal', type: 'button',
        'aria-current': policy.selected === p.id ? 'true' : null,
        onclick: () => openProposal(p.id),
      },
      h('div', { class: 'row' }, h('span', { class: 'id', text: p.id }), stateBadge(p.state)),
      h('span', { class: 'sub', text: `by ${p.author} · ${when(p.created_at)}` }))),
    ] : state('No proposals yet', 'Proposals you and other administrators create appear here.'));
}

// Longest-common-subsequence line diff; policy files are small.
function lineDiff(before, after) {
  const a = before.replace(/\n$/, '').split('\n');
  const b = after.replace(/\n$/, '').split('\n');
  const n = a.length, m = b.length;
  const lcs = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out = [];
  let i = 0, j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) { out.push([' ', a[i]]); i++; j++; }
    else if (j < m && (i === n || lcs[i][j + 1] >= lcs[i + 1][j])) { out.push(['+', b[j]]); j++; }
    else { out.push(['-', a[i]]); i++; }
  }
  return out;
}

// A tree line carries the backend credential in its fourth column. The diff
// is read on shared screens, so it shows that the credential is there, not it.
function maskCredential(line) {
  const parts = line.split('\t');
  if (parts[0] === 'tree' && parts.length >= 4) parts[3] = '••••••••';
  return parts.join('    ');
}

function renderDiff(before, after) {
  const diff = lineDiff(before, after);
  const added = diff.filter(d => d[0] === '+').length;
  const removed = diff.filter(d => d[0] === '-').length;
  return [
    h('div', { class: 'diff-summary' },
      badge(`+${added} added`, 'ok', true), badge(`−${removed} removed`, 'bad', true),
      h('span', { text: added + removed ? '' : 'Identical to the active policy' })),
    h('div', { class: 'diff', role: 'region', 'aria-label': 'Changes against the active policy', tabindex: '0' },
      diff.map(([sign, line]) => h('div', { class: sign === '+' ? 'add' : sign === '-' ? 'del' : '' },
        h('span', { class: 'sign', text: sign === ' ' ? '' : sign === '-' ? '−' : '+' }), maskCredential(line)))),
  ];
}

async function openProposal(id) {
  policy.selected = id;
  renderProposalList();
  replace('#policy-detail', loading('Loading the proposal…'));
  try {
    const data = await api(`/api/admin/policy/proposals/${encodeURIComponent(id)}`);
    const p = data.proposal;
    const own = p.author === session.user;
    const pending = p.state === 'pending';
    const approve = h('button', {
      class: 'btn btn-primary', type: 'button', disabled: !pending || own,
      onclick: () => approveProposal(p.id),
    }, 'Approve and activate');
    replace('#policy-detail',
      h('div', { class: 'card-head' }, h('h2', {}, h('span', { class: 'mono', text: p.id })), stateBadge(p.state)),
      h('div', { class: 'card-body' },
        h('dl', { class: 'facts' },
          h('div', {}, h('dt', { text: 'Proposed by' }), h('dd', { text: p.author })),
          h('div', {}, h('dt', { text: 'Created' }), h('dd', { text: when(p.created_at) })),
          h('div', {}, h('dt', { text: 'Approved by' }), h('dd', { text: p.approver || '—' })),
          h('div', {}, h('dt', { text: 'Approved' }), h('dd', { text: when(p.approved_at) })))),
      h('div', { class: 'card-body' },
        h('div', { class: 'section-label', text: pending ? 'Changes against the active policy' : 'Changes against the current policy' }),
        renderDiff(data.active_rights || '', p.rights || '')),
      pending ? h('div', { class: 'card-body actions' }, approve,
        own ? h('span', { class: 'hint', text: 'You proposed this change. A different administrator has to approve it.' })
          : h('span', { class: 'hint', text: 'Approving replaces the active policy at once; access changes on the next request.' })) : null);
  } catch (e) {
    if (e.status !== 401) replace('#policy-detail', alertBox(`The proposal could not be loaded: ${e.message}`));
  }
}

async function approveProposal(id) {
  try {
    await api(`/api/admin/policy/proposals/${encodeURIComponent(id)}/approve`, { method: 'POST' });
    toast(`Proposal ${id} approved. The new policy is active.`);
    loaded.access = false;
    loadPolicy(id);
  } catch (e) {
    if (e.status === 403) toast(e.message);
    else if (e.status !== 401) toast('The approval was refused: the proposal is no longer pending, no longer valid, or yours.');
  }
}

function newProposal() {
  policy.selected = null;
  renderProposalList();
  const id = h('input', { id: 'proposal-id', required: true, pattern: '[A-Za-z0-9][A-Za-z0-9_\\-]{0,127}', spellcheck: 'false', autocomplete: 'off', placeholder: 'e.g. grant-anna-payments' });
  const rights = h('textarea', { id: 'proposal-rights', rows: '16', spellcheck: 'false' });
  rights.value = policy.active;
  const preview = h('div', {});
  const refresh = () => replace(preview, renderDiff(policy.active, rights.value));
  rights.addEventListener('input', refresh);
  refresh();
  const error = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const form = h('form', { class: 'card-body', onsubmit: async event => {
    event.preventDefault();
    error.hidden = true;
    try {
      await api('/api/admin/policy/proposals', { method: 'POST', body: { id: id.value.trim(), rights: rights.value } });
      toast(`Proposal ${id.value.trim()} created. Another administrator can now approve it.`);
      loadPolicy(id.value.trim());
    } catch (e) {
      if (e.status === 401) return;
      error.textContent = e.status === 403 ? e.message : 'The proposal was rejected. The policy must validate, and the ID must be new and use only letters, digits, - and _.';
      error.hidden = false;
    }
  } },
  h('label', { class: 'field' }, h('span', { text: 'Proposal ID' }), id),
  h('label', { class: 'field' }, h('span', { text: 'Proposed policy' }), rights),
  h('div', { class: 'section-label', text: 'Changes against the active policy' }),
  preview,
  error,
  h('div', { class: 'actions' }, h('button', { class: 'btn btn-primary', type: 'submit' }, 'Submit for approval'),
    h('span', { class: 'hint', text: 'Nothing changes until a different administrator approves it.' })));
  replace('#policy-detail', h('div', { class: 'card-head' }, h('h2', { text: 'New proposal' })), form);
  id.focus();
}

/* ---- Wiring ----------------------------------------------------------- */

$('#signin-form').addEventListener('submit', signIn);
$('#signout').addEventListener('click', () => signOut());
$('#review-form').addEventListener('submit', runReview);
$('#access-filter').addEventListener('input', renderAccess);
$('#access-refresh').addEventListener('click', loadAccess);
$('#access-export').addEventListener('click', exportAccess);
$('#audit-filter').addEventListener('input', renderAudit);
$('#audit-status').addEventListener('change', renderAudit);
$('#audit-refresh').addEventListener('click', loadAudit);
$('#policy-new').addEventListener('click', newProposal);
window.addEventListener('hashchange', route);
checkHealth();
setInterval(checkHealth, 30000);
$('#token').focus();
