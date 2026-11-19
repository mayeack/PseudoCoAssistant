/* Change Board (docs/patchbot.md): a person approves or rejects PatchBot's changes. */
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  let scope = 'awaiting';
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
  async function api(path, opts) {
    const o = Object.assign({ headers: { Accept: 'application/json' }, credentials: 'same-origin' }, opts || {});
    if (o.json !== undefined) { o.method = 'POST'; o.body = JSON.stringify(o.json); o.headers['Content-Type'] = 'application/json'; delete o.json; }
    const r = await fetch('/api/patchbot' + path, o);
    let body = null; try { body = await r.json(); } catch (e) { body = null; }
    if (!r.ok) { const err = new Error((body && body.detail) || ('HTTP ' + r.status)); err.status = r.status; throw err; }
    return body;
  }
  async function boot(override) {
    const me = override || await api('/me');
    if (!me.initiator) {
      $('board').hidden = true; $('whoPanel').hidden = false;
      const list = $('personaList'); list.textContent = '';
      if (me.duo_mode) { $('whoHelp').textContent = 'Sign in with Duo to review changes.'; list.append(el('a', { href: '/login-duo?next=/change-board-ui', class: 'pb-btn pb-btn-primary', text: 'Sign in with Duo' })); return; }
      me.personas.forEach((p) => list.append(el('button', { type: 'button', class: 'pb-persona', onclick: async () => { await api('/persona', { json: { username: p.username } }); boot(); } },
        el('b', { text: p.username }), el('span', { text: p.role_label }))));
      return;
    }
    $('whoPanel').hidden = true; $('board').hidden = false;
    const chip = $('whoChip'); chip.hidden = false;
    chip.textContent = me.initiator.role_label + ' · ' + me.initiator.username + (me.initiator.auth_method === 'duo' ? ' · Duo' : ' · role map · Switch');
    // Role-map personas switch here (the requester hands the change to an approver); with Duo the sign-in decides.
    chip.onclick = me.duo_mode ? null : () => boot(Object.assign({}, me, { initiator: null }));
    load();
  }
  let loadSeq = 0;
  async function load() {
    // Only the newest request may draw: a slower reload (after Approve, or the
    // 8 s refresh) must not overwrite the tab the person just picked.
    const seq = ++loadSeq;
    const data = await api('/changes?scope=' + scope);
    if (seq !== loadSeq) return;
    $('boardHelp').textContent = data.can_decide ? 'You can approve or reject changes you did not request.' : 'Your role can read changes; a Change Approver decides them.';
    const ul = $('changes'); ul.textContent = '';
    data.changes.forEach((c) => ul.append(card(c, data.can_decide, data.initiator.username)));
    $('emptyChanges').hidden = data.changes.length > 0;
    const hash = decodeURIComponent((location.hash || '').slice(1));
    if (hash) { const t = document.getElementById('chg-' + hash); if (t) t.scrollIntoView({ block: 'center' }); }
  }
  function pill(status) {
    const cls = { awaiting_approval: 'pill-blue', approved: 'pill-ok', rejected: 'pill-deny', closed: 'pill-grey', withdrawn: 'pill-grey' }[status] || 'pill-grey';
    return el('span', { class: 'pb-pill ' + cls, text: status.replace('_', ' ') });
  }
  // Standard changes are pre-approved by their template; normal changes wait for a Change Approver.
  const std = (c) => c.change_model === 'standard';
  function model(c) {
    return el('div', { class: 'pb-small' },
      el('span', { class: 'pb-pill ' + (std(c) ? 'pill-ok' : 'pill-blue'), text: std(c) ? 'Standard change' : 'Normal change' }), ' ',
      std(c) ? 'Pre-approved under ' + (c.template || 'a standard change template') + (c.template_title ? ': ' + c.template_title + '.' : '.')
          : (c.status === 'awaiting_approval' ? 'A Change Approver decides it on this board.' : 'A Change Approver decided it on this board.'));
  }
  function card(c, canDecide, me) {
    const noteId = 'note-' + c.id;
    const li = el('li', { id: 'chg-' + c.id, class: 'pb-card', style: 'display:grid;gap:6px' },
      el('div', { style: 'display:flex;flex-wrap:wrap;gap:8px;justify-content:space-between;align-items:center' },
        el('b', { text: c.id + ' · ' + c.cve + ' · ' + (c.priority || '') }), pill(c.status)),
      model(c),
      (c.es_requested_by || c.investigation_id) ? el('div', { class: 'pb-small pb-muted', text: 'Opened from Splunk SOAR' + (c.es_requested_by ? ' for ' + c.es_requested_by : '') + (c.investigation_id ? ' · ES investigation ' + c.investigation_id : '') + (c.auto_execute && !std(c) && c.status === 'awaiting_approval' ? ' · PatchBot runs it once approved' : '') }) : null,
      el('div', { class: 'pb-small', text: 'Hosts: ' + c.servers.join(', ') + ' · ' + c.environment + ' · window ' + (c.window_start || '').slice(11, 16) + '–' + (c.window_end || '').slice(11, 16) + ' UTC' }),
      el('div', { class: 'pb-small', text: 'Requested by ' + c.requested_by + ' (' + (c.requester_role || '').replace(/_/g, ' ') + ') for the estate of ' + c.owner }),
      el('div', { class: 'pb-msg', text: c.plan || '' }),
      c.approver ? el('div', { class: 'pb-small pb-muted', text: (c.status === 'rejected' ? 'Rejected' : 'Approved') + ' by ' + c.approver + (c.decision_note ? ': ' + c.decision_note : '') }) : null);
    if (canDecide && c.status === 'awaiting_approval') {
      const self = c.requested_by === me;
      const msg = el('div', { class: 'pb-small', role: 'status' });
      const act = async (decision) => {
        try { await api('/changes/' + c.id + '/decision', { json: { decision, note: document.getElementById(noteId).value } }); load(); }
        catch (e) { msg.className = 'pb-banner'; msg.textContent = e.message; }
      };
      li.append(el('div', { class: 'pb-note' }, el('label', { for: noteId, class: 'sr-only', text: 'Decision note' }),
        el('input', { id: noteId, type: 'text', maxlength: '1000', placeholder: 'Decision note' }),
        el('button', { type: 'button', class: 'pb-btn pb-btn-primary', text: 'Approve', onclick: () => act('approve') }),
        el('button', { type: 'button', class: 'pb-btn', text: 'Reject', onclick: () => act('reject') })), msg);
      if (self) msg.textContent = 'You requested this change, so the Change Board will refuse your approval.';
    }
    return li;
  }
  document.querySelectorAll('.pb-toggle button').forEach((b) => b.addEventListener('click', () => {
    scope = b.dataset.scope;
    document.querySelectorAll('.pb-toggle button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    load();
  }));
  boot();
  // The refresh redraws every card, so it waits while an approver writes a decision note.
  const writing = () => [...document.querySelectorAll('.pb-note input')].some((i) => i.value || i === document.activeElement);
  setInterval(() => { if (!document.hidden && !$('board').hidden && !writing()) load(); }, 8000);
})();
