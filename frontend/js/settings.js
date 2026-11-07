// Settings page: local log directory + Splunk HEC destinations.

let _dests = [];          // last-loaded destinations (cached for tab switching)
let activeDestId = null;  // currently-selected destination tab

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function attr(s) {
  return esc(s).replace(/"/g, '&quot;');
}
async function api(method, url, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(url, opts);
  let data = null;
  try { data = await r.json(); } catch (_) {}
  if (!r.ok) {
    const detail = data && (data.detail || JSON.stringify(data));
    throw new Error(detail || ('HTTP ' + r.status));
  }
  return data;
}

// ------------------------------------------------- collapsible sections
// Each top-level card (logs / creds / hec) collapses via a chevron in its header.
// State persists per-section in localStorage so it survives reloads.
const COLLAPSE_KEY = 'medadvice.settings.collapsed';
const SECTIONS = ['controls', 'logs', 'creds', 'aidefense', 'nemo', 'o11y', 'hec'];

function _readCollapsed() {
  try { return JSON.parse(localStorage.getItem(COLLAPSE_KEY)) || {}; } catch (_) { return {}; }
}
function _writeCollapsed(map) {
  try { localStorage.setItem(COLLAPSE_KEY, JSON.stringify(map)); } catch (_) {}
}
function applySection(name, collapsed) {
  const body = document.getElementById('section-' + name);
  const btn = document.querySelector(`[data-toggle="${name}"]`);
  if (body) body.classList.toggle('hidden', collapsed);
  if (btn) {
    btn.setAttribute('aria-expanded', String(!collapsed));
    const chev = btn.querySelector('[data-chevron]');
    if (chev) chev.classList.toggle('-rotate-90', collapsed);  // chevron points right when collapsed
  }
}
function toggleSection(name) {
  const body = document.getElementById('section-' + name);
  if (!body) return;
  const collapsed = !body.classList.contains('hidden');  // currently open -> collapse
  applySection(name, collapsed);
  const map = _readCollapsed(); map[name] = collapsed; _writeCollapsed(map);
}
function initSections() {
  const map = _readCollapsed();
  SECTIONS.forEach(n => applySection(n, !!map[n]));
}

// ------------------------------------------------- Demo Controls visibility
// Which cards the Demo Controls drawer on /app shows. Keys, labels and groups
// come from GET /api/settings/demo-controls — generated from
// backend/settings_store.py DEMO_CONTROLS, the registry every drawer card's
// data-control hook is checked against — so a card added to the drawer shows
// up here without a UI change. One bordered sub-block per drawer group, with
// the drawer's own header text; checked = shown.
let _demoControls = { controls: [], groups: [] };

function demoControlHtml(c) {
  return `<label class="flex items-start gap-2 text-sm text-gray-700">
      <input type="checkbox" data-control-key="${attr(c.key)}" ${c.visible ? 'checked' : ''}
        class="mt-0.5 h-4 w-4 rounded border-gray-300 text-violet-600 focus:ring-2 focus:ring-violet-500">
      <span>${esc(c.label)}</span>
    </label>`;
}

function renderDemoControls() {
  const box = document.getElementById('demoControlsList');
  if (!box) return;
  const controls = _demoControls.controls || [];
  if (!controls.length) {
    box.innerHTML = '<p class="text-sm text-gray-400">No controls registered.</p>';
    return;
  }
  box.innerHTML = (_demoControls.groups || []).map(g => {
    const items = controls.filter(c => c.group === g.key);
    if (!items.length) return '';
    return `<div class="border border-gray-200 rounded-lg p-4">
      <h3 class="text-sm font-semibold text-gray-700 mb-2">${esc(g.label)}</h3>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">${items.map(demoControlHtml).join('')}</div>
    </div>`;
  }).join('');
}

async function loadDemoControls() {
  try {
    _demoControls = await api('GET', '/api/settings/demo-controls');
    renderDemoControls();
  } catch (e) {
    const box = document.getElementById('demoControlsList');
    if (box) box.innerHTML = `<p class="text-red-600 text-sm">Failed to load: ${esc(e.message)}</p>`;
    setControlsStatus('Error: ' + e.message, false);
  }
}

async function saveDemoControls() {
  const visible = {};
  document.querySelectorAll('#demoControlsList [data-control-key]').forEach(cb => {
    visible[cb.dataset.controlKey] = cb.checked;
  });
  try {
    _demoControls = await api('PUT', '/api/settings/demo-controls', { visible });
    renderDemoControls();
    const hidden = (_demoControls.controls || []).filter(c => !c.visible).length;
    setControlsStatus(hidden
      ? `Saved — ${hidden} card${hidden === 1 ? '' : 's'} hidden; the chat page picks it up within 10 s.`
      : 'Saved — every card shown.', true);
  } catch (e) { setControlsStatus('Error: ' + e.message, false); }
}

function setControlsStatus(msg, ok) {
  const el = document.getElementById('controlsStatus');
  if (el) { el.textContent = msg; el.className = 'text-sm mt-3 ' + (ok ? 'text-green-600' : 'text-red-600'); }
}

// ---------------------------------------------------------------- log dir
async function loadLogsDir() {
  try {
    const d = await api('GET', '/api/settings');
    document.getElementById('logsDir').value = d.logs_directory || '';
  } catch (e) { setLogsStatus('Failed to load: ' + e.message, false); }
}
async function saveLogsDir() {
  const path = document.getElementById('logsDir').value.trim();
  try {
    const d = await api('PUT', '/api/settings', { logs_directory: path || 'logs' });
    document.getElementById('logsDir').value = d.logs_directory;
    setLogsStatus('Saved — new governance logs will write to "' + d.logs_directory + '".', true);
  } catch (e) { setLogsStatus('Error: ' + e.message, false); }
}
function setLogsStatus(msg, ok) {
  const el = document.getElementById('logsStatus');
  el.textContent = msg;
  el.className = 'text-sm mt-2 ' + (ok ? 'text-green-600' : 'text-red-600');
}

// --------------------------------------------------- provider credentials
// Provider/model selection + static-emission moved to the /app header. This page
// only shows per-provider access creds (API key / base URL / region) for the
// ACTIVE provider, with a read-only pill of the current provider/model. Saving
// creds here does NOT switch the active provider (PUT /api/settings/provider-creds).
let _providerFields = {};   // provider -> [access-field metadata; secrets = presence only]
let _activeProvider = '';   // provider currently backing the chat (read-only here; change on /app)
let _activeModel = '';      // its model
let _credsDirty = false;    // operator has typed into the creds form since the last render/load

// Optional one-line hint under a field's label (integration fields only).
function credHelpHtml(f) {
  return f.help ? `<p class="text-xs text-gray-500 mt-1">${esc(f.help)}</p>` : '';
}

// One credential input (secret = password that starts EMPTY; "(set)" means one exists).
// A `wide` field spans both grid columns \u2014 for values (a resource-attribute list)
// that are unreadable in a half-width box.
function credFieldHtml(f) {
  const cell = f.wide ? ' class="sm:col-span-2"' : '';
  if (f.boolean) {
    // A checkbox always reports its state, so it is the one field type where an
    // unchecked box means "off" rather than "leave the stored value alone".
    return `<div class="sm:col-span-2 flex items-start gap-2">
      <input data-cred="${attr(f.key)}" type="checkbox" ${String(f.value) === 'true' ? 'checked' : ''}
        class="mt-0.5 h-4 w-4 rounded border-gray-300 text-violet-600 focus:ring-2 focus:ring-violet-500">
      <div>
        <label class="block text-xs font-semibold text-gray-600">${esc(f.label)}</label>
        ${credHelpHtml(f)}
      </div></div>`;
  }
  if (f.secret) {
    const ph = f.present ? '•••••••• (set) — leave blank to keep' : (f.placeholder || ('enter ' + f.label));
    return `<div${cell}>
      <label class="block text-xs font-semibold text-gray-600 mb-1">${esc(f.label)}</label>
      <input data-cred="${attr(f.key)}" type="password" autocomplete="new-password" placeholder="${attr(ph)}"
        class="w-full p-2 border border-gray-300 rounded text-sm font-mono focus:outline-none focus:ring-2 focus:ring-violet-500">
      ${credHelpHtml(f)}</div>`;
  }
  return `<div${cell}>
    <label class="block text-xs font-semibold text-gray-600 mb-1">${esc(f.label)}</label>
    <input data-cred="${attr(f.key)}" type="text" value="${attr(f.value || '')}" placeholder="${attr(f.placeholder || '')}"
      class="w-full p-2 border border-gray-300 rounded text-sm font-mono focus:outline-none focus:ring-2 focus:ring-violet-500">
    ${credHelpHtml(f)}</div>`;
}

// Read-only pill: the provider + model currently backing the chat (change on /app).
function renderProviderPill() {
  const el = document.getElementById('providerPill');
  if (!el) return;
  if (!_activeProvider) { el.innerHTML = ''; return; }
  const prov = `<span class="px-2 py-0.5 rounded-full text-xs font-semibold bg-violet-100 text-violet-700 capitalize">${esc(_activeProvider)}</span>`;
  const model = _activeModel
    ? `<span class="px-2 py-0.5 rounded-full text-xs font-mono bg-slate-100 text-slate-700">${esc(_activeModel)}</span>`
    : '';
  el.innerHTML = prov + model;
}

// Render ONLY the active provider's cred card (the provider shown in the pill).
function renderProviderCreds() {
  const box = document.getElementById('providerCredsList');
  if (!box) return;
  const p = _activeProvider;
  if (!p) { box.innerHTML = '<p class="text-sm text-gray-500">No active provider.</p>'; return; }
  const specs = _providerFields[p] || [];
  const fields = specs.length
    ? `<div data-creds-for="${attr(p)}" class="grid grid-cols-1 sm:grid-cols-2 gap-3">${specs.map(credFieldHtml).join('')}</div>`
    : '<p class="text-sm text-gray-400">No credential fields for this provider.</p>';
  const saveBtn = specs.length
    ? `<button onclick="saveProviderCreds()" class="mt-3 px-4 py-2 bg-violet-600 text-white rounded hover:bg-violet-700 text-sm">Save ${esc(p)} credentials</button>`
    : '';
  box.innerHTML = `<div class="border border-gray-200 rounded-lg p-4">
    <h3 class="text-sm font-semibold text-gray-700 mb-3 capitalize">${esc(p)}</h3>
    ${fields}${saveBtn}
  </div>`;
  _credsDirty = false;  // fresh render = no unsaved edits
}

async function loadProviderCreds() {
  try {
    const d = await api('GET', '/api/settings/ai-provider');
    _providerFields = d.fields || {};
    _activeProvider = d.provider || '';
    _activeModel = d.model || '';
    renderProviderPill();
    renderProviderCreds();
  } catch (e) { setCredsStatus('Failed to load: ' + e.message, false); }
}

// Read every [data-cred] control inside a container into a {key: value} payload.
// Shared by the provider card and the integration cards.
function collectFieldsIn(box) {
  const out = {};
  if (!box) return out;
  box.querySelectorAll('[data-cred]').forEach(el => {
    const key = el.getAttribute('data-cred');
    if (el.type === 'checkbox') { out[key] = el.checked ? 'true' : 'false'; return; }
    const v = el.value.trim();
    if (el.type === 'password') { if (v) out[key] = v; }  // blank secret keeps existing
    else out[key] = v;
  });
  return out;
}

function collectCredsFor(provider) {
  return collectFieldsIn(document.querySelector(`[data-creds-for="${CSS.escape(provider)}"]`));
}

async function saveProviderCreds() {
  const provider = _activeProvider;   // the only card shown; read it rather than interpolate into onclick
  if (!provider) return;
  try {
    const d = await api('PUT', '/api/settings/provider-creds', { provider, fields: collectCredsFor(provider) });
    _providerFields = d.fields || _providerFields;
    if (d.provider) _activeProvider = d.provider;   // unchanged by a creds save, but stay in sync
    if (d.model != null) _activeModel = d.model;
    renderProviderPill();
    renderProviderCreds();  // reset saved secrets back to masked "(set)" + clears _credsDirty
    setCredsStatus(`Saved ${provider} credentials. (Active provider unchanged — switch it from the app page header.)`, true);
  } catch (e) { setCredsStatus('Error: ' + e.message, false); }
}

function setCredsStatus(msg, ok) {
  const el = document.getElementById('credsStatus');
  if (el) { el.textContent = msg; el.className = 'text-sm mt-3 ' + (ok ? 'text-green-600' : 'text-red-600'); }
}

// ------------------------------------------------------------ integrations
// Cisco AI Defense + Splunk Observability Cloud (which also holds Splunk Agent
// Observability). Same field vocabulary as the provider creds above, so
// credFieldHtml / collectFieldsIn are shared rather than duplicated.
//
// Each group saves independently because their save semantics differ: the AI
// Defense fields apply on the next chat turn, the collector-consumed ones are
// written to .env and need a restart, and the Agent Observability ones do both
// (live for the SDK path, .env for the collector fan-out). The server reports
// which in restart_required.
let _integrations = {};   // integration id -> field metadata from the server

// Which container each integration renders into, in display order.
const INTEGRATION_GROUPS = [
  { box: 'aiDefenseFields', ids: ['ai_defense'] },
  { box: 'nemoFields', ids: ['nemo_guardrails'] },
  { box: 'o11yFields', ids: ['splunk_o11y', 'agent_observability'] },
];
// A title turns the group into a bordered sub-card. The AI Defense group has no
// title because it is alone in its card and would just repeat the heading.
const INTEGRATION_TITLES = {
  ai_defense: '',
  nemo_guardrails: '',
  splunk_o11y: 'Splunk Observability Cloud',
  agent_observability: 'Splunk Agent Observability',
};
const INTEGRATION_NOTES = {
  ai_defense: '',
  nemo_guardrails: 'Applies on the next chat turn — no restart. Rails are rebuilt automatically when the active provider/model changes.',
  splunk_o11y: 'Read by a separate process \u2014 the collector (realm, ingest token) or the app at startup (OTLP endpoint, resource attributes). Saving writes .env; the save message names which process to restart. On a fleet replica these are replaced by the next deploy.',
  agent_observability: 'The SDK path picks the ingest token, project and agent stream up on the next chat turn; the collector fan-out reads them from .env at start, so the save message asks for a collector restart. Agent Control credentials apply live.',
};

function integrationHtml(id) {
  const specs = _integrations[id] || [];
  const title = INTEGRATION_TITLES[id] || '';
  const note = INTEGRATION_NOTES[id] || '';
  const fields = specs.length
    ? `<div data-integ-for="${attr(id)}" class="grid grid-cols-1 sm:grid-cols-2 gap-3">${specs.map(credFieldHtml).join('')}</div>`
    : '<p class="text-sm text-gray-400">No fields for this integration.</p>';
  const body =
    (title ? `<h3 class="text-sm font-semibold text-gray-700 mb-1">${esc(title)}</h3>` : '') +
    (note ? `<p class="text-xs text-gray-500 mb-3">${esc(note)}</p>` : '') +
    fields +
    (specs.length
      ? `<button onclick="saveIntegration('${attr(id)}')"
           class="mt-3 px-4 py-2 bg-violet-600 text-white rounded hover:bg-violet-700 text-sm">Save</button>`
      : '') +
    `<p id="integStatus-${attr(id)}" class="text-sm mt-3"></p>`;
  return title ? `<div class="border border-gray-200 rounded-lg p-4">${body}</div>` : body;
}

function renderIntegrations() {
  INTEGRATION_GROUPS.forEach(g => {
    const box = document.getElementById(g.box);
    if (box) box.innerHTML = g.ids.map(integrationHtml).join('');
  });
}

async function loadIntegrations() {
  try {
    const d = await api('GET', '/api/settings/integrations');
    _integrations = d.integrations || {};
    renderIntegrations();
  } catch (e) {
    INTEGRATION_GROUPS.forEach(g => {
      const box = document.getElementById(g.box);
      if (box) box.innerHTML = `<p class="text-red-600 text-sm">Failed to load: ${esc(e.message)}</p>`;
    });
  }
}

async function saveIntegration(id) {
  const box = document.querySelector(`[data-integ-for="${CSS.escape(id)}"]`);
  try {
    const d = await api('PUT', '/api/settings/integration-creds',
                        { integration: id, fields: collectFieldsIn(box) });
    _integrations = d.integrations || _integrations;
    renderIntegrations();  // resets saved secrets back to their masked placeholder
    const restart = d.restart_required || [];
    setIntegStatus(id, restart.length
      ? `Saved to .env. Restart the ${restart.join(' and ')} to apply.`
      : 'Saved \u2014 applied, no restart needed.', true);
  } catch (e) { setIntegStatus(id, 'Error: ' + e.message, false); }
}

function setIntegStatus(id, msg, ok) {
  const el = document.getElementById('integStatus-' + id);
  if (el) { el.textContent = msg; el.className = 'text-sm mt-3 ' + (ok ? 'text-green-600' : 'text-red-600'); }
}

// ------------------------------------------------------------ destinations
async function loadDestinations() {
  try {
    const d = await api('GET', '/api/hec/destinations');
    _dests = d.destinations || [];
    renderDestinations();
  } catch (e) {
    document.getElementById('destinations').innerHTML =
      `<p class="text-red-600 text-sm">Failed to load destinations: ${esc(e.message)}</p>`;
  }
}
function renderDestinations() {
  const box = document.getElementById('destinations');
  if (!_dests.length) {
    box.innerHTML = `<p class="text-gray-400 text-sm">No HEC destinations yet. Click “+ Add destination”.</p>`;
    return;
  }
  if (!activeDestId || !_dests.some(d => d.id === activeDestId)) activeDestId = _dests[0].id;
  const tabs = _dests.map(tabButton).join('');
  const active = _dests.find(d => d.id === activeDestId);
  box.innerHTML =
    `<div class="flex flex-wrap items-end gap-1 border-b border-gray-200 mb-4">${tabs}</div>` +
    cardHTML(active);
}
function tabButton(d) {
  const on = d.id === activeDestId;
  const dot = `<span class="inline-block w-2 h-2 rounded-full mr-2 align-middle ${d.enabled ? 'bg-green-500' : 'bg-gray-300'}"></span>`;
  const cls = on
    ? 'px-4 py-2 text-sm font-semibold text-violet-600 bg-white border border-gray-200 border-b-0 rounded-t-lg -mb-px'
    : 'px-4 py-2 text-sm text-gray-500 hover:text-gray-800';
  return `<button type="button" onclick="selectTab('${attr(d.id)}')" class="${cls}">${dot}${esc(d.name || d.id)}</button>`;
}
function selectTab(id) {
  // preserve in-memory edits of the current tab when switching (Save persists to server)
  const card = cardFor(activeDestId);
  if (card) {
    const cur = _dests.find(d => d.id === activeDestId);
    if (cur) Object.assign(cur, collectDest(card));
  }
  activeDestId = id;
  renderDestinations();
}
function field(label, f, value, type) {
  return `<div>
    <label class="block text-xs font-semibold text-gray-600 mb-1">${label}</label>
    <input data-field="${f}" type="${type || 'text'}" value="${attr(value)}"
      class="w-full p-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-violet-500"></div>`;
}
function num(label, f, value) {
  return `<div>
    <label class="block text-xs font-semibold text-gray-600 mb-1">${label}</label>
    <input data-field="${f}" type="number" value="${attr(value)}"
      class="w-full p-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-violet-500"></div>`;
}
function cardHTML(d) {
  const id = d.id;
  const tokenPh = d.token_present
    ? `•••• ${esc(d.token_last4)} (saved — leave blank to keep)`
    : 'paste HEC token';
  return `<div class="border border-gray-200 rounded-lg p-4" data-dest="${attr(id)}">
    <div class="flex items-center justify-between mb-3 gap-3">
      <input data-field="name" value="${attr(d.name || '')}"
        class="font-semibold text-gray-800 text-lg flex-1 p-1 border border-transparent hover:border-gray-200 rounded focus:outline-none focus:ring-2 focus:ring-violet-500">
      <label class="flex items-center gap-2 text-sm text-gray-700 whitespace-nowrap">
        <input data-field="enabled" type="checkbox" ${d.enabled ? 'checked' : ''}> Enabled</label>
    </div>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
      ${field('HEC URL (https://host:8088)', 'url', d.url || '')}
      <div>
        <label class="block text-xs font-semibold text-gray-600 mb-1">HEC token</label>
        <input data-field="token" type="password" placeholder="${attr(tokenPh)}"
          class="w-full p-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-violet-500"></div>
      ${field('Index', 'index', d.index || '')}
      ${field('Sourcetype', 'sourcetype', d.sourcetype || '')}
      ${field('Source', 'source', d.source || '')}
      ${field('Host', 'host', d.host || '')}
    </div>
    <label class="flex items-center gap-2 text-sm text-gray-700 mb-3">
      <input data-field="verify_tls" type="checkbox" ${d.verify_tls ? 'checked' : ''}> Verify TLS certificate</label>
    <details class="mb-3">
      <summary class="text-sm text-gray-600 cursor-pointer">Performance</summary>
      <div class="grid grid-cols-2 md:grid-cols-5 gap-3 mt-2">
        ${num('Batch size', 'batch_size', d.batch_size)}
        ${num('Flush (s)', 'flush_interval_s', d.flush_interval_s)}
        ${num('Queue max', 'queue_max', d.queue_max)}
        ${num('Timeout (s)', 'request_timeout_s', d.request_timeout_s)}
        ${num('Max retries', 'max_retries', d.max_retries)}
      </div>
    </details>
    <div class="flex items-center gap-2">
      <button onclick="saveDestination('${attr(id)}')" class="px-3 py-1.5 bg-violet-600 text-white rounded text-sm hover:bg-violet-700">Save</button>
      <button onclick="testDestination('${attr(id)}')" class="px-3 py-1.5 bg-slate-600 text-white rounded text-sm hover:bg-slate-700">Test connection</button>
      <button onclick="deleteDestination('${attr(id)}')" class="px-3 py-1.5 bg-red-100 text-red-700 rounded text-sm hover:bg-red-200">Delete</button>
      <button onclick="refreshDestStats('${attr(id)}')" class="px-3 py-1.5 bg-slate-100 text-slate-700 rounded text-sm hover:bg-slate-200">Refresh stats</button>
      <span data-result class="text-sm ml-2"></span>
    </div>
    <div data-stats class="text-xs text-gray-500 mt-3 font-mono"></div>
  </div>`;
}
function cardFor(id) { return document.querySelector(`[data-dest="${CSS.escape(id)}"]`); }
function collectDest(card) {
  const get = (f) => card.querySelector(`[data-field="${f}"]`);
  const patch = {
    name: get('name').value.trim(),
    enabled: get('enabled').checked,
    url: get('url').value.trim(),
    verify_tls: get('verify_tls').checked,
    index: get('index').value.trim(),
    source: get('source').value.trim(),
    sourcetype: get('sourcetype').value.trim(),
    host: get('host').value.trim(),
  };
  const tok = get('token').value.trim();
  if (tok) patch.token = tok;
  for (const [f, kind] of Object.entries({ batch_size: 'i', flush_interval_s: 'f', queue_max: 'i', request_timeout_s: 'f', max_retries: 'i' })) {
    const v = kind === 'i' ? parseInt(get(f).value, 10) : parseFloat(get(f).value);
    if (!Number.isNaN(v)) patch[f] = v;
  }
  return patch;
}
function setResult(id, msg, ok) {
  const card = cardFor(id);
  if (!card) return;   // tab switched while the request was in flight
  const el = card.querySelector('[data-result]');
  el.textContent = msg;
  el.className = 'text-sm ml-2 ' + (ok ? 'text-green-600' : 'text-red-600');
}
async function saveDestination(id) {
  try {
    await api('PUT', '/api/hec/destinations/' + encodeURIComponent(id), collectDest(cardFor(id)));
    // Re-render first: loadDestinations() rebuilds the card's innerHTML, so a
    // result written before it is wiped out (same order as saveIntegration).
    await loadDestinations();
    setResult(id, 'Saved.', true);
  } catch (e) { setResult(id, 'Error: ' + e.message, false); }
}
async function testDestination(id) {
  setResult(id, 'Saving + testing…', true);
  try {
    await api('PUT', '/api/hec/destinations/' + encodeURIComponent(id), collectDest(cardFor(id)));
    const r = await api('POST', '/api/hec/destinations/' + encodeURIComponent(id) + '/test');
    await loadDestinations();
    if (r.ok) setResult(id, `✓ Success (${r.status_code}, ${r.latency_ms} ms)`, true);
    else setResult(id, '✗ ' + (r.error || 'failed'), false);
  } catch (e) { setResult(id, 'Error: ' + e.message, false); }
}
async function deleteDestination(id) {
  if (!confirm('Delete this HEC destination?')) return;
  try { await api('DELETE', '/api/hec/destinations/' + encodeURIComponent(id)); await loadDestinations(); }
  catch (e) { setResult(id, 'Error: ' + e.message, false); }
}
async function addDestination() {
  try {
    const rec = await api('POST', '/api/hec/destinations', { name: 'New destination' });
    activeDestId = rec.id;            // open the new tab
    await loadDestinations();
  } catch (e) { alert('Could not add destination: ' + e.message); }
}

// -------------------------------------------------------------------- stats
// Refresh ONE destination's stats line. Uses GET /api/hec/stats/{id}, which had
// no caller anywhere in the UI, tests, or scripts before this.
async function refreshDestStats(id) {
  const card = cardFor(id);
  if (!card) return;
  const el = card.querySelector('[data-stats]');
  try {
    const s = await api('GET', `/api/hec/stats/${encodeURIComponent(id)}`);
    el.textContent = statsLine(s);
  } catch (e) {
    el.textContent = `could not read stats: ${e.message}`;
  }
}

function statsLine(s) {
  const state = s.running ? 'running' : (s.enabled ? 'enabled (idle)' : 'disabled');
  let line = `sent ${s.events_sent} · failed ${s.events_failed} · dropped ${s.events_dropped} · queue ${s.queue_depth}/${s.queue_capacity} · ${state}`;
  if (s.last_latency_ms != null) line += ` · ${s.last_latency_ms} ms`;
  if (s.last_error) line += `  —  last error: ${s.last_error}`;
  return line;
}

async function loadStats() {
  let data;
  try { data = await api('GET', '/api/hec/stats'); } catch (_) { return; }
  for (const s of (data.destinations || [])) {
    const card = cardFor(s.id);
    if (!card) continue;
    const el = card.querySelector('[data-stats]');
    const state = s.running ? 'running' : (s.enabled ? 'enabled (idle)' : 'disabled');
    let line = `sent ${s.events_sent} · failed ${s.events_failed} · dropped ${s.events_dropped} · queue ${s.queue_depth}/${s.queue_capacity} · ${state}`;
    if (s.last_latency_ms != null) line += ` · ${s.last_latency_ms} ms`;
    // No esc(): this is assigned via textContent below, which does not parse
    // entities — escaping first rendered "&amp;"/"&lt;" literally, which is
    // common in URLs and HTML error bodies.
    if (s.last_error) line += `  —  last error: ${s.last_error}`;
    el.textContent = line;
  }
}

// ------------------------------------------------------------ host capabilities
// What this box can run (GET /api/server-info). Chips are neutral; the reason an
// option is unavailable is the chip tooltip. The rules themselves live server-side
// (backend/host_capabilities.py) — this only renders them.
function capChip(label, ok, title) {
  const cls = ok ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600';
  return `<span class="px-2 py-0.5 rounded-full font-semibold ${cls}" title="${attr(title || '')}">${esc(label)}</span>`;
}

function renderHostCaps(d) {
  const box = document.getElementById('hostCaps');
  if (!box) return;
  const c = d.capabilities || {}, g = d.gated || {};
  const gpu = c.nvidia_gpu || {}, rt = c.container_runtime || {}, nim = c.nim || {};
  const nimGate = g.nim_local || {}, clawGate = g.nemoclaw_runtime || {};
  // Lab 5 Duo sign-in (gated.duo_signin): the reason names what is missing.
  const duoGate = g.duo_signin || {};
  box.innerHTML = [
    capChip(gpu.present ? `GPU: ${gpu.count}x ${gpu.name} (${gpu.vram_mb} MB)` : 'GPU: none', !!gpu.present,
            gpu.present ? `driver ${gpu.driver || '?'} via ${gpu.source}` : (g.provider_nvidia || {}).reason),
    capChip(`runtime: ${rt.name || 'none'}${rt.available ? '' : ' (down)'}`, !!rt.available,
            rt.version ? `version ${rt.version}` : ''),
    capChip(`NIM: ${nimGate.enabled ? 'ready' : 'unavailable'}`, !!nimGate.enabled,
            nimGate.enabled ? nim.base_url : nimGate.reason),
    capChip(`NemoClaw runtime: ${clawGate.enabled ? 'supported' : 'unsupported'}`, !!clawGate.enabled,
            clawGate.reason),
    capChip(`Duo sign-in: ${duoGate.enabled ? 'ready' : 'unavailable'}`, !!duoGate.enabled,
            duoGate.reason),
  ].join('');
}

async function loadHostCaps() {
  try { renderHostCaps(await api('GET', '/api/server-info')); }
  catch (e) {
    const box = document.getElementById('hostCaps');
    if (box) box.innerHTML = `<span class="text-red-600">unavailable: ${esc(e.message)}</span>`;
  }
}

async function refreshHostCaps() {
  try { renderHostCaps(await api('POST', '/api/server-info/refresh', {})); }
  catch (e) { /* keep the last render */ }
}

document.addEventListener('DOMContentLoaded', async () => {
  initSections();
  loadHostCaps();   // independent of the cards below; never blocks them
  // Mark the creds form dirty on the first keystroke so a background refresh never
  // wipes unsaved input. The listener is delegated on the static container, so it
  // survives the innerHTML re-renders of its child inputs.
  const credsBox = document.getElementById('providerCredsList');
  if (credsBox) credsBox.addEventListener('input', () => { _credsDirty = true; });
  await loadDemoControls();
  await loadLogsDir();
  await loadProviderCreds();
  await loadIntegrations();
  await loadDestinations();
  await loadStats();
  setInterval(() => { if (!document.hidden) loadStats(); }, 2500);
});

// When the tab regains focus, refresh the active provider/model pill + creds (the
// active provider may have changed on /app). Skip if the operator has unsaved edits
// (dirty) or an input is focused, so we never clobber a half-typed secret.
document.addEventListener('visibilitychange', () => {
  if (document.hidden) return;
  if (_credsDirty) return;
  const box = document.getElementById('providerCredsList');
  if (box && box.contains(document.activeElement)) return;
  loadProviderCreds();
});
