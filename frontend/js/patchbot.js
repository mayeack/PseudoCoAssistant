/* PatchBot workspace (docs/patchbot.md). All text goes in through textContent. */
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const SEV = ['critical', 'high', 'medium', 'low'];
  const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  const state = { ws: null, view: 'open', detail: null, chat: [], busy: false, poll: null, autoTimer: null };

  function sessionId() {
    try {
      let id = sessionStorage.getItem('patchbot_session');
      if (!id) { id = 'pb-' + Math.random().toString(36).slice(2, 14); sessionStorage.setItem('patchbot_session', id); }
      return id;
    } catch (e) { return 'pb-' + Date.now().toString(36); }
  }
  const SID = sessionId();

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat()) if (kid !== null && kid !== undefined) n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    return n;
  }
  function svgEl(tag, attrs, text) {
    const n = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
    if (text !== undefined) n.textContent = text;
    return n;
  }

  async function api(path, opts) {
    const o = Object.assign({ headers: {} }, opts || {});
    o.headers = Object.assign({ 'x-patchbot-session': SID, 'Accept': 'application/json' }, o.headers);
    if (o.json !== undefined) { o.method = o.method || 'POST'; o.body = JSON.stringify(o.json); o.headers['Content-Type'] = 'application/json'; delete o.json; }
    o.credentials = 'same-origin';
    const r = await fetch('/api/patchbot' + path, o);
    let body = null;
    try { body = await r.json(); } catch (e) { body = null; }
    if (r.status === 401) { showWho(); throw new Error((body && body.detail) || 'Sign in first.'); }
    if (!r.ok) throw new Error((body && body.detail) || ('HTTP ' + r.status));
    return body;
  }

  // ------------------------------------------------------------------ identity
  async function boot() {
    let me;
    try { me = await api('/me'); } catch (e) { return; }
    if (!me.initiator) { showWho(me); return; }
    $('whoPanel').hidden = true;
    $('workspace').hidden = false;
    const chip = $('whoChip');
    chip.hidden = false;
    chip.textContent = me.initiator.role_label + ' · ' + me.initiator.username + (me.initiator.auth_method === 'duo' ? ' · Duo' : ' · role map');
    $('controlsMode').textContent = me.controls_mode === 'local' ? 'the local policy engine (offline mode)' : 'Splunk Agent Observability Controls on the ' + me.agent_stream + ' Agent stream';
    await refresh();
    if (state.poll) clearInterval(state.poll);
    state.poll = setInterval(() => { if (!document.hidden && !state.busy) refresh(true); }, 6000);
  }

  function showWho(me) {
    $('workspace').hidden = true;
    $('whoPanel').hidden = false;
    const list = $('personaList');
    list.textContent = '';
    if (me && me.duo_mode) {
      $('whoHelp').textContent = 'PatchBot acts with the role your Duo groups give you. Sign in with Duo first.';
      list.append(el('a', { href: '/login-duo?next=/patchbot-ui', class: 'pb-btn pb-btn-primary', text: 'Sign in with Duo' }));
      return;
    }
    const personas = (me && me.personas) || [];
    personas.forEach((p) => list.append(el('button', {
      type: 'button', class: 'pb-persona',
      onclick: async () => { await api('/persona', { json: { username: p.username } }); boot(); },
    }, el('b', { text: p.username }), el('span', { text: p.role_label }))));
  }

  // ------------------------------------------------------------------ workspace
  async function refresh(quiet) {
    try {
      state.ws = await api('/workspace');
    } catch (e) { if (!quiet) note(e.message, true); return; }
    renderWorkspace();
    if (state.detail && !quiet) openFinding(state.detail.cve, true);
    else if (state.detail && quiet) openFinding(state.detail.cve, true);
  }

  function renderWorkspace() {
    const ws = state.ws;
    $('hostCount').textContent = ws.hosts.length;
    $('watchLine').textContent = ws.full_read_done ? 'Watching for advisories' : 'Waiting for the first full read';
    renderExposure(ws);
    if (ws.exposure_answered && !$('chatLog').children.length) {
      const h = ws.hosts.find((x) => x.name === 'web-prod-01');
      if (h) pushDoc('Exposure model', 'Document · web-prod-01 is ' + (h.publicly_exposed ? 'reachable from the internet' : 'internal only') + ' (' + h.exposure_source + ')');
    }
    renderFindings(ws);
    renderActivity(ws.activity || []);
    renderResources(ws);
  }

  function renderExposure(ws) {
    const card = $('exposureCard');
    const show = !ws.full_read_done;
    card.hidden = !show;
    if (!show) { if (state.autoTimer) { clearInterval(state.autoTimer); state.autoTimer = null; } return; }
    if (!state.autoTimer) {
      let left = 60;
      $('autoStart').textContent = left;
      state.autoTimer = setInterval(() => {
        left -= 1; $('autoStart').textContent = Math.max(left, 0);
        if (left <= 0) { clearInterval(state.autoTimer); state.autoTimer = null; fullRead(); }
      }, 1000);
    }
  }

  async function answerExposure(answer) {
    if (state.autoTimer) { clearInterval(state.autoTimer); state.autoTimer = null; }
    const exposed = { internet: true, partners: false, internal: false }[answer];
    const label = { internet: 'Anyone on the internet', partners: 'Partners over VPN', internal: 'Only internal staff', unsure: 'Not sure' }[answer];
    pushMsg('user', label);
    if (exposed !== undefined) {
      try {
        const res = await api('/exposure', { json: { server: 'web-prod-01', publicly_exposed: exposed } });
        if (res.denied) pushMsg('bot', 'Not recorded: ' + (res.verdict.message || 'denied by policy'), [res]);
      } catch (e) { note(e.message, true); }
    }
    pushDoc('Exposure model', 'Document · web-prod-01 is ' + (exposed === undefined ? 'rated from asset data (public web tier)' : exposed ? 'reachable from the internet' : 'internal only'));
    await fullRead();
  }

  async function fullRead() {
    if (state.busy) return;
    setBusy(true);
    pushMsg('bot', 'Starting the full read of your estate…');
    try {
      const r = await api('/full-read', { json: {} });
      pushMsg('bot', r.reply);
    } catch (e) { note(e.message, true); }
    setBusy(false);
    await refresh();
  }

  // ------------------------------------------------------------------ findings
  function statusPill(f) {
    if (f.status === 'resolved') {
      if ((f.resolution || '').startsWith('dismissed_')) return el('span', { class: 'pb-pill pill-grey', text: 'Dismissed as ' + f.resolution.replace('dismissed_', '').replace('_', ' ') });
      return el('span', { class: 'pb-pill pill-ok', text: f.resolution === 'fixed_by_change' ? 'Fixed by an approved change' : 'Marked fixed' });
    }
    if (f.change_id) return el('span', { class: 'pb-pill pill-blue', text: 'Awaiting approval · ' + f.change_id });
    const patchedSome = f.open_hosts.length < f.hosts.length;
    if (patchedSome) return el('span', { class: 'pb-pill pill-amber', text: 'Partly patched' });
    return el('span', { class: 'pb-pill pill-grey', text: f.reopened ? 'Reopened' : 'New' });
  }

  function renderFindings(ws) {
    const all = ws.findings || [];
    const open = all.filter((f) => f.status === 'open');
    const resolved = all.filter((f) => f.status !== 'open');
    $('openCount').textContent = open.length + ' open';
    $('nOpen').textContent = open.length;
    $('nResolved').textContent = resolved.length;
    const bar = $('sevBar'); bar.textContent = '';
    const by = ws.counts.by_severity || {};
    SEV.forEach((s) => { if (by[s]) bar.append(el('i', { class: 'sev-' + s, style: 'flex:' + by[s] })); });
    $('sevLegend').textContent = SEV.map((s) => SEV_LABEL[s] + ' ' + (by[s] || 0)).join(' · ');
    const hero = $('hero'); hero.textContent = '';
    if (open.length) hero.append(heroCard(open[0]));
    const rows = $('rows'); rows.textContent = '';
    const shown = state.view === 'open' ? open : resolved;
    shown.forEach((f) => rows.append(el('li', {
      class: 'pb-row', tabindex: '0', role: 'button',
      onclick: () => openFinding(f.cve), onkeydown: (e) => { if (e.key === 'Enter') openFinding(f.cve); },
    }, el('span', { class: 'pb-sevdot sev-' + f.severity, title: SEV_LABEL[f.severity] }),
      el('div', {}, el('div', { class: 't', text: f.title }), el('div', { class: 'm', text: f.lead_host + ' · ' + f.package + ' ' + (f.installed_version || '') + ' · ' + f.cve })),
      statusPill(f))));
    $('emptyFindings').hidden = all.length > 0;
    $('fullReadBtn').hidden = all.length > 0 || ws.full_read_done;
  }

  function heroCard(f) {
    return el('div', { class: 'pb-hero' },
      el('div', {}, el('span', { class: 'pb-pill pill-' + f.severity, text: SEV_LABEL[f.severity] }), ' ', el('span', { class: 'pb-muted pb-small', text: 'PatchBot recommends' })),
      el('h3', { text: f.title }),
      el('p', { class: 'pb-muted pb-small', text: (f.kev ? 'In CISA KEV · ' : '') + 'fix ready: ' + f.package + ' ' + f.installed_version + ' → ' + f.fixed_version + ' · staging first · BOD 26-04: ' + f.bod.bod_timeline }),
      el('div', { class: 'pb-actions' }, patchMenuButton(f), el('button', { type: 'button', class: 'pb-btn', text: 'See details', onclick: () => openFinding(f.cve) })));
  }

  function menuButton(label, items, primary) {
    const wrap = el('span', { style: 'position:relative;display:inline-block' });
    const btn = el('button', { type: 'button', class: 'pb-btn' + (primary ? ' pb-btn-primary' : ''), 'aria-haspopup': 'true', text: label + ' ▾' });
    let menu = null;
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (menu) { menu.remove(); menu = null; return; }
      menu = el('div', { class: 'pb-menu', role: 'menu' });
      items.forEach((it) => menu.append(el('button', { type: 'button', role: 'menuitem', text: it.label, onclick: (ev) => { ev.stopPropagation(); menu.remove(); menu = null; it.run(); } })));
      wrap.append(menu);
      setTimeout(() => document.addEventListener('click', function close() { if (menu) { menu.remove(); menu = null; } document.removeEventListener('click', close); }), 0);
    });
    wrap.append(btn);
    return wrap;
  }

  function patchMenuButton(f) {
    return menuButton('Patch', [
      { label: 'Patch staging', run: () => doPatch(f.cve, 'staging') },
      { label: 'Patch production (needs an approved change)', run: () => doPatch(f.cve, 'production') },
      { label: 'Follow the latest vendor advisory', run: () => doAdvisory(f.cve) },
    ], true);
  }

  async function doPatch(cve, environment) {
    setBusy(true);
    pushMsg('user', 'Patch ' + cve + ' in ' + environment);
    try {
      const r = await api('/findings/' + cve + '/patch', { json: { environment } });
      pushMsg('bot', r.reply, r.tool_calls);
    } catch (e) { note(e.message, true); }
    setBusy(false);
    await refresh();
  }

  async function doAdvisory(cve, source) {
    setBusy(true);
    pushMsg('user', source === 'vendor_mcp' ? 'Follow the vendor\'s advisory for ' + cve + ' (Vendor Advisories MCP server)'
      : 'Follow the latest vendor advisory for ' + cve);
    try {
      const r = await api('/findings/' + cve + '/advisory' + (source ? '?source=' + source : ''), { json: {} });
      pushMsg('bot', r.reply, r.tool_calls);
    } catch (e) { note(e.message, true); }
    setBusy(false);
    await refresh();
  }

  async function doTriage(cve, action, reason) {
    const noteText = action === 'dismiss' ? ($('triageNote') ? $('triageNote').value : '') : '';
    try {
      const r = await api('/findings/' + cve + '/triage', { json: { action, reason, note: noteText } });
      if (r.denied) note('Blocked by policy: ' + (r.verdict.message || 'denied'), true);
      else note(action === 'dismiss' ? 'Dismissed.' : 'Reopened.', false);
    } catch (e) { note(e.message, true); }
    await refresh();
  }

  // ------------------------------------------------------------------ detail
  async function openFinding(cve, quiet) {
    let f;
    try { f = await api('/findings/' + cve); } catch (e) { if (!quiet) note(e.message, true); return; }
    state.detail = f;
    $('findingsList').hidden = true;
    const box = $('findingDetail'); box.hidden = false; box.textContent = '';
    const list = (state.ws && state.ws.findings) || [];
    const idx = list.findIndex((x) => x.cve === cve);
    const go = (d) => { const n = list[idx + d]; if (n) openFinding(n.cve); };
    const triage = menuButton('Triage', [
      { label: 'Dismiss as false positive', run: () => doTriage(cve, 'dismiss', 'false_positive') },
      { label: 'Dismiss as accepted risk', run: () => doTriage(cve, 'dismiss', 'accepted_risk') },
      { label: 'Dismiss as duplicate', run: () => doTriage(cve, 'dismiss', 'duplicate') },
      { label: 'Reopen', run: () => doTriage(cve, 'reopen') },
    ]);
    box.append(el('div', { class: 'pb-actions', style: 'justify-content:space-between' },
      el('span', {}, el('button', { type: 'button', class: 'pb-link', text: '← All findings', onclick: closeFinding }), '  ',
        el('span', { class: 'pb-muted pb-small', text: (idx + 1) + ' / ' + list.length + ' ' }),
        el('button', { type: 'button', class: 'pb-link', 'aria-label': 'Previous finding', text: '∧', onclick: () => go(-1) }), ' ',
        el('button', { type: 'button', class: 'pb-link', 'aria-label': 'Next finding', text: '∨', onclick: () => go(1) })),
      el('span', { class: 'pb-actions', style: 'margin:0' }, triage, patchMenuButton(f),
        el('a', { class: 'pb-btn pb-btn-primary', href: '/change-board-ui' + (f.change_id ? '#' + f.change_id : ''), text: 'Review ↗' }))));
    const main = el('div', {},
      el('h2', { text: f.title }), attackPath(f),
      el('h3', { text: 'What we found' }), el('p', { text: f.what_we_found }),
      el('h3', { text: 'How to fix it' }), el('p', { text: f.how_to_fix }),
      el('h3', { text: 'Evidence' }), evidence(f),
      el('h3', { text: 'Why this rating' }),
      el('ul', { class: 'pb-hist' }, f.checks.map((c) => el('li', { class: 'pb-check' + (c.ok ? '' : ' no'), text: (c.ok ? '✓ ' : '• ') + c.name + ': ' + c.text }))),
      el('p', { class: 'pb-muted pb-small', text: 'Checked ' + f.checks_passed + ' of 3 · ' + f.why_rating }),
      el('div', { class: 'pb-note' }, el('label', { for: 'triageNote', class: 'sr-only', text: 'Triage note' }),
        el('input', { id: 'triageNote', type: 'text', maxlength: '500', placeholder: 'Triage note (used when you dismiss)' })));
    const side = el('aside', { class: 'pb-side' },
      el('div', {}, el('div', { class: 'pb-lbl', text: 'Severity' }), el('span', { class: 'pb-pill pill-' + f.severity, text: SEV_LABEL[f.severity] }), ' ',
        el('a', { href: 'https://nvd.nist.gov/vuln/detail/' + f.cve, target: '_blank', rel: 'noopener', text: f.cve + ' ↗' }),
        el('div', { style: 'margin-top:6px' }, f.kev ? el('span', { class: 'pb-pill pill-critical', text: 'KEV' }) : null, ' ',
          el('span', { class: 'pb-pill pill-grey', text: 'EPSS ' + (typeof f.epss === 'number' ? f.epss.toFixed(2) : '—') }), ' ',
          el('span', { class: 'pb-pill pill-grey', text: 'CVSS ' + (f.cvss || '—') }))),
      el('div', {}, el('div', { class: 'pb-lbl', text: 'Location' }), f.hosts.map((h) => el('div', { class: 'm', style: 'font:500 12px JetBrains Mono,monospace', text: h + ' · ' + (f.open_hosts.includes(h) ? f.package + ' ' + f.installed_version : 'patched') }))),
      el('div', {}, el('div', { class: 'pb-lbl', text: 'Status' }), statusPill(f),
        f.change ? el('div', { class: 'pb-small', style: 'margin-top:4px' }, el('a', { href: '/change-board-ui#' + f.change.id, text: f.change.id + ' ↗' }), ' · ' + f.change.status.replace('_', ' ')) : null),
      el('div', {}, el('div', { class: 'pb-lbl', text: 'Assignee' }), el('div', { text: f.assignee })),
      el('div', {}, el('div', { class: 'pb-lbl', text: 'History' }),
        el('ul', { class: 'pb-hist' }, (f.history || []).map((h) => el('li', { class: /denied|refused/i.test(h.text) ? 'deny' : '', text: h.text + ' · ' + when(h.at) })))));
    box.append(el('div', { class: 'pb-detail' }, main, side));
  }

  function closeFinding() { state.detail = null; $('findingDetail').hidden = true; $('findingsList').hidden = false; }

  function evidence(f) {
    const t = el('table', { class: 'pb-evidence' }, el('thead', {}, el('tr', {}, ['Host', 'Installed', 'Fixed in', 'BOD 26-04'].map((h) => el('th', { text: h })))));
    const tb = el('tbody');
    f.hosts.forEach((h) => {
      const r = f.host_ratings[h] || {};
      tb.append(el('tr', {}, el('td', { text: h }), el('td', { text: f.open_hosts.includes(h) ? f.installed_version : f.fixed_version + ' (patched)' }),
        el('td', { text: f.fixed_version }), el('td', { text: 'row ' + r.bod_row + ' · ' + r.bod_timeline })));
    });
    t.append(tb);
    return el('div', { class: 'pb-tablewrap' }, t,
      el('p', { class: 'pb-muted pb-small', text: (f.kev ? 'In CISA KEV since ' + f.kev_date_added + '. ' : 'Not in CISA KEV. ') + 'Automatable: ' + f.automatable + '. Technical impact: ' + f.technical_impact + '.' }));
  }

  function attackPath(f) {
    const p = f.attack_path;
    const svg = svgEl('svg', { viewBox: '0 0 640 150', role: 'img', 'aria-label': 'Attack path: ' + p.actor + ', ' + p.service + ', ' + p.vulnerable + ', ' + p.asset });
    const defs = svgEl('defs');
    const m = svgEl('marker', { id: 'pbah', viewBox: '0 0 8 8', refX: '7', refY: '4', markerWidth: '8', markerHeight: '8', orient: 'auto-start-reverse' });
    m.append(svgEl('path', { d: 'M0,0 L8,4 L0,8 z', class: 'ap-head' })); defs.append(m); svg.append(defs);
    const nodes = [[p.actor, p.actor_note, 'ap-node'], [p.service, p.service_host, 'ap-node'], [p.vulnerable, f.cve, 'ap-bad'], [p.asset, 'the asset', 'ap-node']];
    const labels = ['reaches', 'feeds', 'exposes'];
    nodes.forEach((n, i) => {
      const x = 8 + i * 158;
      svg.append(svgEl('rect', { x, y: 18, width: 140, height: 50, rx: 6, class: n[2] }));
      svg.append(svgEl('text', { x: x + 70, y: 39, 'text-anchor': 'middle', class: 'ap-t1' }, trunc(n[0], 24)));
      svg.append(svgEl('text', { x: x + 70, y: 56, 'text-anchor': 'middle', class: 'ap-t2' }, trunc(n[1] || '', 24)));
      if (i < 3) {
        svg.append(svgEl('line', { x1: x + 140, y1: 43, x2: x + 156, y2: 43, class: 'ap-edge', 'marker-end': 'url(#pbah)' }));
        svg.append(svgEl('text', { x: x + 148, y: 12, 'text-anchor': 'middle', class: 'ap-elab' }, labels[i]));
      }
    });
    if (p.missing_control) {
      svg.append(svgEl('line', { x1: 156, y1: 68, x2: 156, y2: 92, class: 'ap-edge', 'stroke-dasharray': '3 3' }));
      svg.append(svgEl('rect', { x: 26, y: 92, width: 300, height: 28, rx: 5, class: 'ap-dash' }));
      svg.append(svgEl('text', { x: 176, y: 110, 'text-anchor': 'middle', class: 'ap-deny' }, 'missing: ' + trunc(p.missing_control, 44)));
    }
    return el('div', { class: 'pb-path' }, svg);
  }
  function trunc(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; }

  // ------------------------------------------------------------------ chat
  function pushMsg(who, text, calls) {
    state.chat.push({ role: who === 'user' ? 'user' : 'assistant', content: text });
    const m = el('div', { class: 'pb-msg ' + (who === 'user' ? 'user' : 'bot'), text: text });
    if (calls && calls.length) {
      m.append(el('div', { class: 'pb-calls' }, calls.map((c) => el('span', {
        class: 'pb-call ' + (c.decision === 'deny' || c.decision === 'steer' ? c.decision : ''),
        title: (c.controls || []).join(', '), text: (c.name || 'tool') + ' · ' + (c.decision === 'deny' ? 'denied' : c.decision === 'steer' ? 'steered' : 'allowed'),
      }))));
    }
    $('chatLog').append(m); $('chatLog').scrollTop = $('chatLog').scrollHeight;
  }
  function pushDoc(title, sub) { $('chatLog').append(el('div', { class: 'pb-msg doc' }, el('b', { text: title }), el('span', { class: 'pb-muted', text: sub }))); }

  async function sendChat(e) {
    e.preventDefault();
    const input = $('chatInput'); const text = input.value.trim();
    if (!text || state.busy) return;
    input.value = '';
    const history = state.chat.slice(-6);
    pushMsg('user', text);
    setBusy(true);
    try {
      const r = await api('/chat', { json: { message: text, history } });
      pushMsg('bot', r.reply, r.tool_calls);
    } catch (err) { note(err.message, true); }
    setBusy(false);
    await refresh();
  }

  function setBusy(b) { state.busy = b; $('chatSend').disabled = b; $('chatSend').textContent = b ? 'Working…' : 'Send'; }
  function note(text, bad) { const n = el('div', { class: 'pb-banner' + (bad ? '' : ' ok'), role: 'status', text }); $('chatLog').append(n); $('chatLog').scrollTop = $('chatLog').scrollHeight; setTimeout(() => n.remove(), 9000); }

  // ------------------------------------------------------------------ activity / resources
  function when(iso) {
    const d = new Date(iso); if (isNaN(d)) return '';
    const mins = Math.round((Date.now() - d.getTime()) / 60000);
    if (mins < 1) return 'just now'; if (mins < 60) return mins + ' min ago';
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  function renderActivity(items) {
    const counts = { scan: 0, change: 0, denied: 0 };
    items.forEach((a) => { if (a.kind in counts) counts[a.kind] += 1; });
    $('activityTimeline').textContent = 'Scans ' + counts.scan + ' · Change Board ' + counts.change + ' · Denied by policy ' + counts.denied;
    const feed = $('activityFeed'); feed.textContent = '';
    const groups = {};
    items.forEach((a) => { const d = new Date(a.at); const key = isNaN(d) ? 'Earlier' : (d.toDateString() === new Date().toDateString() ? 'Today' : d.toLocaleDateString()); (groups[key] = groups[key] || []).push(a); });
    const wrap = el('div', { class: 'pb-feed' });
    Object.entries(groups).forEach(([k, list]) => {
      wrap.append(el('h4', { text: k }));
      wrap.append(el('ul', {}, list.map((a) => el('li', {}, el('span', { text: a.text + (a.actor ? ' · ' + a.actor : '') }), el('span', { class: 'when', text: when(a.at) })))));
    });
    if (!items.length) wrap.append(el('p', { class: 'pb-empty', text: 'Nothing yet.' }));
    feed.append(wrap);
  }
  function renderResources(ws) {
    const body = $('hostsBody'); body.textContent = '';
    ws.hosts.forEach((h) => body.append(el('tr', {}, el('td', { text: h.name }), el('td', { text: h.os }), el('td', { text: h.environment }),
      el('td', { text: (h.publicly_exposed ? 'internet' : 'internal') + ' (' + h.exposure_source + ')' }), el('td', { text: h.purpose }))));
    const src = ws.catalog_source || {};
    $('catalogSource').textContent = 'CISA KEV catalog ' + (src.kev_catalog_version || '?') + ', FIRST EPSS ' + (src.epss_date || '?') + ', ' + (src.ssvc || 'CISA Vulnrichment') + '; read ' + (src.fetched || '?') + '.';
    const sel = $('demoCve');
    if (!sel.options.length) (ws.findings.length ? ws.findings : []).forEach((f) => sel.append(el('option', { value: f.cve, text: f.cve + ' · ' + f.short })));
    if (!sel.options.length) ['CVE-2021-41773'].forEach((c) => sel.append(el('option', { value: c, text: c })));
  }

  // ------------------------------------------------------------------ toolchain (MCP servers, Cisco MCP Scanner)
  const SEV_PILL = { SAFE: 'pill-ok', HIGH: 'pill-high', MEDIUM: 'pill-medium', LOW: 'pill-low', INFO: 'pill-low', UNKNOWN: 'pill-low' };
  function pill(text, cls) { return el('span', { class: 'pb-pill ' + cls, text }); }

  async function loadToolchain() {
    try { renderToolchain(await api('/mcp')); } catch (e) { note(e.message, true); }
  }

  function renderToolchain(o) {
    $('mcpScanner').textContent = o.scanner.installed ? 'Analyzers on this box: ' + o.scanner.analyzers.join(', ') + '.'
      : 'The scanner is not installed on this box (pip install cisco-ai-mcp-scanner).';
    $('vendorPoison').checked = !!o.vendor.poisoned;
    const box = $('mcpServers'); box.textContent = '';
    o.servers.forEach((s) => {
      const scan = s.scan;
      const verdict = !scan ? pill('not scanned', 'pill-grey') : scan.is_safe ? pill('SAFE', 'pill-ok')
        : pill(scan.severity, SEV_PILL[scan.severity] || 'pill-high');
      const head = el('div', { class: 'pb-mcp-head' }, el('b', { text: s.title }),
        el('span', { class: 'pb-muted pb-small', text: s.publisher }), verdict,
        scan && !s.scan_current ? pill('catalogue changed since the scan', 'pill-amber') : null,
        s.kind === 'vendor' ? pill(o.vendor.connected ? (o.vendor.forced ? 'connected without a clean scan' : 'connected') : 'not connected',
          o.vendor.connected ? (o.vendor.forced ? 'pill-deny' : 'pill-blue') : 'pill-grey') : null);
      const meta = el('div', { class: 'pb-muted pb-small', text: s.tools.length + ' tools · ' + (scan
        ? 'scanned ' + scan.scanned_at.replace('T', ' ').slice(0, 16) + ' UTC · analyzers ' + (scan.analyzers_ran.join(', ') || 'none')
        : 'not scanned yet') });
      const unsafe = scan ? scan.tools.filter((t) => !t.is_safe) : [];
      const list = unsafe.length ? el('ul', { class: 'pb-mcp-findings' }, unsafe.map((t) => el('li', {}, el('code', { text: t.tool }), ': ',
        t.threats.join(', ') || t.severity, t.compensated_by ? el('span', { class: 'pb-muted', text: ' · denied at runtime by ' + t.compensated_by }) : null))) : null;
      box.append(el('div', { class: 'pb-card pb-mcp' }, head, meta, list,
        el('button', { type: 'button', class: 'pb-btn pb-btn-quiet', text: 'Scan', onclick: () => scanMcp(s.id) })));
    });
  }

  async function scanMcp(server) {
    note('Cisco MCP Scanner is scanning ' + (server || 'every server') + '…', false);
    try {
      const r = await api('/mcp/scan', { json: server ? { server } : {} });
      renderToolchain(r.overview);
      const errs = Object.values(r.results).filter((x) => x.error);
      note(errs.length ? errs[0].error : 'Scan complete.', !!errs.length);
    } catch (e) { note(e.message, true); }
    refresh(true);
  }

  async function vendor(action, force) {
    try {
      const r = await api('/mcp/vendor', { json: { action, force: !!force } });
      renderToolchain(r.overview);
      if (r.message) note(r.message, !r.ok);
    } catch (e) { note(e.message, true); }
    refresh(true);
  }

  let resetArmed = false;
  function wire() {
    document.querySelectorAll('.pb-opt').forEach((b) => b.addEventListener('click', () => answerExposure(b.dataset.answer)));
    document.querySelectorAll('.pb-tab').forEach((t) => t.addEventListener('click', () => {
      document.querySelectorAll('.pb-tab').forEach((x) => x.setAttribute('aria-selected', String(x === t)));
      ['findings', 'activity', 'toolchain', 'resources'].forEach((k) => { $('tab-' + k).hidden = k !== t.dataset.tab; });
      if (t.dataset.tab === 'toolchain') loadToolchain();
    }));
    $('mcpScanAll').addEventListener('click', () => scanMcp(null));
    $('vendorConnect').addEventListener('click', () => vendor('connect', false));
    $('vendorForce').addEventListener('click', () => vendor('connect', true));
    $('vendorDisconnect').addEventListener('click', () => vendor('disconnect'));
    $('followVendor').addEventListener('click', () => doAdvisory($('demoCve').value, 'vendor_mcp'));
    $('vendorPoison').addEventListener('change', async (e) => {
      try {
        const r = await api('/demo/vendor-mcp', { json: { poisoned: e.target.checked } });
        renderToolchain(r.overview);
        note(e.target.checked ? 'The vendor now ships a poisoned tool description.' : 'The vendor\'s tool description is clean again.', false);
      } catch (err) { note(err.message, true); }
    });
    document.querySelectorAll('.pb-toggle button').forEach((b) => b.addEventListener('click', () => {
      state.view = b.dataset.view;
      document.querySelectorAll('.pb-toggle button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      if (state.ws) renderFindings(state.ws);
    }));
    $('chatForm').addEventListener('submit', sendChat);
    $('fullReadBtn').addEventListener('click', fullRead);
    $('publishAdvisory').addEventListener('click', async () => {
      try { const a = await api('/demo/advisory', { json: { cve: $('demoCve').value, poisoned: $('demoPoison').checked } }); note('Advisory ' + a.id + ' published' + (a.poisoned ? ' (poisoned)' : '') + '.', false); } catch (e) { note(e.message, true); }
      refresh(true);
    });
    $('followAdvisory').addEventListener('click', () => doAdvisory($('demoCve').value));
    $('rollBack').addEventListener('click', async () => {
      try { const r = await api('/demo/rollback', { json: { cve: $('demoCve').value } }); note(r.rolled_back.server + ' rolled back; the watch rescan found ' + r.rescan.open.length + ' open.', false); } catch (e) { note(e.message, true); }
      refresh();
    });
    $('resetEstate').addEventListener('click', async (e) => {
      if (!resetArmed) { resetArmed = true; e.target.textContent = 'Click again to reset'; setTimeout(() => { resetArmed = false; e.target.textContent = 'Reset my estate'; }, 4000); return; }
      resetArmed = false; e.target.textContent = 'Reset my estate';
      try { await api('/reset', { json: {} }); state.chat = []; $('chatLog').textContent = ''; closeFinding(); note('Estate reset.', false); } catch (err) { note(err.message, true); }
      refresh();
    });
    $('schemeToggle').addEventListener('click', () => {
      const dark = !document.documentElement.classList.contains('dark');
      document.documentElement.classList.toggle('dark', dark);
      try { localStorage.setItem('medadvice_color_scheme', dark ? 'dark' : 'light'); } catch (e) {}
    });
  }

  wire();
  boot();
})();
