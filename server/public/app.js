'use strict';
const $ = (s, r = document) => r.querySelector(s);
const el = (t, p = {}, ...kids) => { const n = Object.assign(document.createElement(t), p); for (const k of kids) n.append(k?.nodeType ? k : document.createTextNode(k ?? '')); return n; };
const api = async (m, path, body) => {
  const r = await fetch('/admin/api' + path, { method: m, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  if (r.status === 401 && !path.startsWith('/login')) { showLogin(); throw new Error('unauthorized'); }
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || r.statusText);
  return d;
};
const LEVELS = { 1: 'Monitor', 2: 'Filtered', 3: 'Lockdown' };

function showLogin() { $('#app').classList.add('hidden'); $('#login').classList.remove('hidden'); }
function showApp() { $('#login').classList.add('hidden'); $('#app').classList.remove('hidden'); }

// ---------- modal ----------
function modal(node) { const m = $('#modal'); const b = $('.modal-body', m); b.innerHTML = ''; b.append(node); m.classList.remove('hidden'); }
function closeModal() { $('#modal').classList.add('hidden'); }
$('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });

// ---------- auth ----------
$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try { await api('POST', '/login', { username: f.get('username'), password: f.get('password') }); await boot(); }
  catch (err) { $('#loginErr').textContent = err.message; }
});
$('#logout').addEventListener('click', async () => { await api('POST', '/logout'); showLogin(); });

// ---------- tabs ----------
document.querySelectorAll('header nav button').forEach((b) => b.addEventListener('click', () => {
  document.querySelectorAll('header nav button').forEach((x) => x.classList.remove('active'));
  b.classList.add('active');
  document.querySelectorAll('.tab').forEach((t) => t.classList.add('hidden'));
  $('#tab-' + b.dataset.tab).classList.remove('hidden');
  render(b.dataset.tab);
}));

async function render(tab) {
  if (tab === 'devices') return renderDevices();
  if (tab === 'policies') return renderPolicies();
  if (tab === 'keys') return renderKeys();
  if (tab === 'android') return renderAndroid();
  if (tab === 'ios') return renderIos();
}

// ---------- devices ----------
async function renderDevices() {
  const root = $('#tab-devices'); root.innerHTML = '';
  const [devices, policies] = await Promise.all([api('GET', '/devices'), api('GET', '/policies')]);
  root.append(el('div', { className: 'between' }, el('h2', {}, `Devices (${devices.length})`),
    el('button', { className: 'small ghost', onclick: () => renderDevices() }, 'Refresh')));
  if (!devices.length) { root.append(el('p', { className: 'muted' }, 'No devices enrolled yet. Create an enrollment key and run the installer on an endpoint.')); return; }
  const t = el('table');
  t.append(el('thead', {}, tr(['Host', 'Status', 'Policy', 'Sync', 'Agent', 'Last seen', ''], true)));
  const tb = el('tbody');
  for (const d of devices) {
    const synced = d.policyVersion >= (d.policyTargetVersion || 0);
    const sel = el('select', { onchange: async (e) => { await api('PUT', `/devices/${d.id}/policy`, { policyId: e.target.value ? +e.target.value : null }); renderDevices(); } });
    sel.append(el('option', { value: '' }, '— none —'));
    for (const p of policies) sel.append(el('option', { value: p.id, selected: p.id === d.policyId }, `${p.name} (L${p.body.level})`));
    tb.append(el('tr', {},
      td(el('div', {}, el('strong', {}, d.hostname || d.id), el('br'), el('small', { className: 'muted mono' }, d.id))),
      td(el('span', { className: 'pill ' + (d.revoked ? 'off' : d.online ? 'on' : '') }, d.revoked ? 'revoked' : d.online ? 'online' : 'offline')),
      td(sel),
      td(el('span', { className: 'pill ' + (synced ? 'on' : 'off') }, synced ? `v${d.policyVersion}` : `v${d.policyVersion}→v${d.policyTargetVersion}`)),
      td(d.agentVersion || '—'),
      td(d.lastSeen ? new Date(d.lastSeen + 'Z').toLocaleString() : '—'),
      td(el('div', { className: 'row' },
        el('button', { className: 'small ghost', onclick: () => deviceActions(d) }, '⋯'))),
    ));
  }
  t.append(tb); root.append(t);
}

function deviceActions(d) {
  const box = el('div', {});
  box.append(el('h2', {}, d.hostname || d.id), el('p', { className: 'muted mono' }, d.id));
  if (d.status) box.append(el('pre', { className: 'mono card' }, JSON.stringify(d.status, null, 2)));
  const cmd = (type, label, cls = 'ghost') => el('button', { className: 'small ' + cls, onclick: async () => { await api('POST', `/devices/${d.id}/command`, { type }); alert(`${label} queued — delivered on next heartbeat`); } }, label);
  box.append(el('div', { className: 'row' },
    cmd('refresh', 'Force policy refresh'),
    cmd('unlock', 'Temporary unlock (15m)'),
    cmd('uninstall', 'Authorize uninstall', 'danger'),
    el('button', { className: 'small danger', onclick: async () => { if (confirm('Revoke this device? Its token stops working.')) { await api('POST', `/devices/${d.id}/revoke`); closeModal(); renderDevices(); } } }, 'Revoke token'),
  ));
  box.append(el('h3', {}, 'Recent events'));
  const log = el('div', { className: 'mono muted' }, 'loading…'); box.append(log);
  api('GET', `/devices/${d.id}/events`).then((evs) => {
    log.innerHTML = '';
    if (!evs.length) return log.append('no events');
    for (const e of evs.slice(0, 60)) log.append(el('div', {}, `${new Date(e.at + 'Z').toLocaleTimeString()}  [${e.kind}]  ${e.detail || ''}`));
  });
  box.append(el('div', { className: 'row', style: 'margin-top:14px' }, el('button', { className: 'ghost', onclick: closeModal }, 'Close')));
  modal(box);
}

// ---------- policies ----------
async function renderPolicies() {
  const root = $('#tab-policies'); root.innerHTML = '';
  const policies = await api('GET', '/policies');
  root.append(el('div', { className: 'between' }, el('h2', {}, 'Policies'),
    el('button', { onclick: () => editPolicy() }, '+ New policy')));
  const t = el('table');
  t.append(el('thead', {}, tr(['Name', 'Level', 'Apps', 'Web', 'VPN', 'Ver', ''], true)));
  const tb = el('tbody');
  for (const p of policies) {
    const b = p.body;
    tb.append(el('tr', {},
      td(el('strong', {}, p.name)),
      td(el('span', { className: 'lvl' + b.level }, `L${b.level} · ${LEVELS[b.level]}`)),
      td(`${b.apps.mode}${b.apps.mode === 'whitelist' ? ` (${b.apps.allow.length})` : b.apps.mode === 'blacklist' ? ` (${b.apps.deny.length})` : ''}`),
      td(`${b.web.mode}${b.web.categories.length ? ' +' + b.web.categories.length + 'cat' : ''}`),
      td(el('span', { className: 'pill ' + (b.vpn.block ? 'on' : 'off') }, b.vpn.block ? 'blocked' : 'allowed')),
      td('v' + p.version),
      td(el('div', { className: 'row' },
        el('button', { className: 'small ghost', onclick: () => editPolicy(p) }, 'Edit'),
        el('button', { className: 'small danger', onclick: async () => { if (confirm('Delete policy?')) { await api('DELETE', '/policies/' + p.id); renderPolicies(); } } }, 'Del'))),
    ));
  }
  t.append(tb); root.append(t);
}

function editPolicy(p) {
  const isNew = !p;
  const b = p ? structuredClone(p.body) : { level: 3, apps: { allow: [], deny: [] }, web: { allowDomains: [], denyDomains: [], categories: [], forceSafeSearch: true }, vpn: { block: true }, tamper: { preventUninstall: true, watchdog: true } };
  const box = el('div', {});
  box.append(el('h2', {}, isNew ? 'New policy' : 'Edit ' + p.name));
  const name = el('input', { value: p?.name || '', placeholder: 'e.g. Kiosk lockdown' });
  box.append(el('label', {}, 'Name', name));

  const level = el('select', {});
  for (const [v, lbl] of Object.entries(LEVELS)) level.append(el('option', { value: v, selected: +v === b.level }, `Level ${v} — ${lbl}`));
  box.append(el('label', {}, 'Enforcement level', level));
  box.append(el('small', { className: 'hint' }, '1 = monitor only · 2 = open internet, block listed sites/categories · 3 = lockdown: only allow-listed apps & sites'));

  const g = el('div', { className: 'grid2' });
  const appAllow = ta(b.apps.allow, 'chrome.exe\nC:\\Program Files\\App\\app.exe');
  const appDeny = ta(b.apps.deny, 'steam.exe\ndiscord.exe');
  const webAllow = ta(b.web.allowDomains, 'school.edu\n*.wikipedia.org');
  const webDeny = ta(b.web.denyDomains, 'facebook.com\ntiktok.com');
  g.append(
    el('label', {}, 'Allowed apps (whitelist)', appAllow),
    el('label', {}, 'Blocked apps (blacklist)', appDeny),
    el('label', {}, 'Allowed domains (whitelist)', webAllow),
    el('label', {}, 'Blocked domains (blacklist)', webDeny),
  );
  box.append(g);

  box.append(el('label', {}, 'Blocked categories'));
  const cats = el('div', { className: 'row' });
  for (const c of ['pornography', 'gambling', 'malware', 'social', 'streaming', 'proxies']) {
    const id = 'cat_' + c;
    const cb = el('input', { type: 'checkbox', id, checked: b.web.categories.includes(c), style: 'width:auto' });
    cats.append(el('label', { htmlFor: id, style: 'margin:0;display:flex;gap:6px;align-items:center' }, cb, c));
  }
  box.append(cats);

  const vpn = el('input', { type: 'checkbox', checked: !!b.vpn.block, style: 'width:auto' });
  const uninst = el('input', { type: 'checkbox', checked: !!b.tamper?.preventUninstall, style: 'width:auto' });
  const safe = el('input', { type: 'checkbox', checked: !!b.web.forceSafeSearch, style: 'width:auto' });
  box.append(el('div', { className: 'row', style: 'margin:12px 0' },
    lblc(vpn, 'Block VPNs'), lblc(uninst, 'Prevent uninstall'), lblc(safe, 'Force SafeSearch')));

  const unlock = el('input', { type: 'password', placeholder: isNew ? 'set an unlock key' : 'leave blank to keep current' });
  box.append(el('label', {}, 'Admin unlock key', unlock));
  box.append(el('small', { className: 'hint' }, 'Required on the endpoint to pause/uninstall locally. Stored only as a hash. Keep it safe — this is your recovery path.'));

  const err = el('p', { className: 'err' });
  box.append(err);
  box.append(el('div', { className: 'row', style: 'margin-top:8px' },
    el('button', { onclick: save }, isNew ? 'Create' : 'Save changes'),
    el('button', { className: 'ghost', onclick: closeModal }, 'Cancel')));
  modal(box);

  async function save() {
    const body = {
      level: +level.value,
      apps: { mode: +level.value === 3 ? 'whitelist' : +level.value === 2 ? 'blacklist' : 'off', allow: lines(appAllow), deny: lines(appDeny) },
      web: { mode: +level.value === 3 ? 'whitelist' : +level.value === 2 ? 'blacklist' : 'off', allowDomains: lines(webAllow), denyDomains: lines(webDeny), categories: [...cats.querySelectorAll('input:checked')].map((c) => c.id.slice(4)), forceSafeSearch: safe.checked },
      vpn: { block: vpn.checked },
      tamper: { preventUninstall: uninst.checked, watchdog: uninst.checked },
    };
    try {
      if (isNew) {
        const { id } = await api('POST', '/policies', { name: name.value, level: +level.value, body });
        if (unlock.value) await api('PUT', '/policies/' + id, { body, unlockKey: unlock.value });
      } else {
        await api('PUT', '/policies/' + p.id, { name: name.value, body, unlockKey: unlock.value || undefined });
      }
      closeModal(); renderPolicies();
    } catch (e) { err.textContent = e.message; }
  }
}

// ---------- enrollment keys ----------
async function renderKeys() {
  const root = $('#tab-keys'); root.innerHTML = '';
  const [keys, policies] = await Promise.all([api('GET', '/enrollment-keys'), api('GET', '/policies')]);
  root.append(el('div', { className: 'between' }, el('h2', {}, 'Enrollment keys'),
    el('button', { onclick: () => newKey(policies) }, '+ New key')));
  root.append(el('p', { className: 'muted' }, 'Bake a key into an installer package; every machine that runs it enrolls into the chosen policy.'));
  const t = el('table');
  t.append(el('thead', {}, tr(['Key', 'Label', 'Default policy', 'State', ''], true)));
  const tb = el('tbody');
  for (const k of keys) {
    const pol = policies.find((p) => p.id === k.policy_id);
    tb.append(el('tr', {},
      td(el('span', { className: 'key mono' }, k.key)),
      td(k.label || '—'),
      td(pol ? pol.name : '—'),
      td(el('span', { className: 'pill ' + (k.revoked ? 'off' : 'on') }, k.revoked ? 'revoked' : 'active')),
      td(k.revoked ? '' : el('button', { className: 'small danger', onclick: async () => { await api('POST', `/enrollment-keys/${k.id}/revoke`); renderKeys(); } }, 'Revoke')),
    ));
  }
  t.append(tb); root.append(t);
}

function newKey(policies) {
  const box = el('div', {});
  box.append(el('h2', {}, 'New enrollment key'));
  const label = el('input', { placeholder: 'e.g. Library PCs' });
  const pol = el('select', {});
  pol.append(el('option', { value: '' }, '— assign later —'));
  for (const p of policies) pol.append(el('option', { value: p.id }, `${p.name} (L${p.body.level})`));
  box.append(el('label', {}, 'Label', label), el('label', {}, 'Default policy', pol));
  box.append(el('div', { className: 'row' },
    el('button', { onclick: async () => { const { key } = await api('POST', '/enrollment-keys', { label: label.value, policyId: pol.value ? +pol.value : null }); box.innerHTML = ''; box.append(el('h2', {}, 'Key created'), el('p', {}, 'Use this in the installer:'), el('p', {}, el('span', { className: 'key mono' }, key)), el('button', { onclick: () => { closeModal(); renderKeys(); } }, 'Done')); } }, 'Create'),
    el('button', { className: 'ghost', onclick: closeModal }, 'Cancel')));
  modal(box);
}

// ---------- android ----------
async function renderAndroid() {
  const root = $('#tab-android'); root.innerHTML = '';
  const [status, policies] = await Promise.all([api('GET', '/android/status'), api('GET', '/policies')]);
  root.append(el('h2', {}, 'Android (managed devices)'));
  root.append(el('p', { className: 'muted' }, 'Enforced by Google’s Android Management API on managed (Device Owner) devices.'));

  const pill = el('span', { className: 'pill ' + (status.configured ? 'on' : 'off') }, status.configured ? 'configured' : 'not configured');
  root.append(el('div', { className: 'card' },
    el('div', { className: 'row' }, el('strong', {}, 'AMAPI status:'), pill),
    el('div', { className: 'muted', style: 'margin-top:6px' },
      `enterprise: ${status.enterprise || '—'} · credentials: ${status.hasCredentials ? 'yes' : 'no'} · SDK: ${status.sdkLoaded ? 'loaded' : 'not installed'}`),
    status.configured ? '' : el('small', { className: 'hint', style: 'margin-top:8px' },
      'Set GOOGLE_APPLICATION_CREDENTIALS + ENTERPRISE_NAME and run npm install in android/ to enable live push. Preview works without it.')));

  root.append(el('h3', {}, 'Policies → Android'));
  const t = el('table');
  t.append(el('thead', {}, tr(['Policy', 'Level', 'Actions'], true)));
  const tb = el('tbody');
  for (const p of policies) {
    tb.append(el('tr', {},
      td(el('strong', {}, p.name)),
      td('L' + p.body.level),
      td(el('div', { className: 'row' },
        el('button', { className: 'small ghost', onclick: () => previewAndroid(p) }, 'Preview AMAPI'),
        el('button', { className: 'small', disabled: !status.configured, onclick: () => pushAndroid(p) }, 'Push'),
        el('button', { className: 'small', disabled: !status.configured, onclick: () => enrollAndroid(p) }, 'Enrollment QR'))),
    ));
  }
  t.append(tb); root.append(t);
}

async function previewAndroid(p) {
  const mapped = await api('GET', `/android/policies/${p.id}/preview`);
  const box = el('div', {});
  box.append(el('h2', {}, 'AMAPI Policy — ' + p.name),
    el('p', { className: 'muted' }, 'What Android Management API receives for this policy:'),
    el('pre', { className: 'mono card', style: 'max-height:60vh;overflow:auto' }, JSON.stringify(mapped, null, 2)),
    el('div', { className: 'row' }, el('button', { className: 'ghost', onclick: closeModal }, 'Close')));
  modal(box);
}
async function pushAndroid(p) {
  try { await api('POST', `/android/policies/${p.id}/push`); alert('Pushed to Android Management API.'); }
  catch (e) { alert('Push failed: ' + e.message); }
}
async function enrollAndroid(p) {
  try {
    const tok = await api('POST', `/android/policies/${p.id}/enrollment-token`, {});
    const box = el('div', {});
    box.append(el('h2', {}, 'Enrollment token'), el('p', {}, 'Scan on a factory-reset device (tap 6× on setup):'));
    if (tok.qrCode) box.append(el('pre', { className: 'mono card', style: 'white-space:pre-wrap;word-break:break-all' }, tok.qrCode));
    box.append(el('p', {}, el('span', { className: 'key mono' }, tok.value || '(no value)')),
      el('button', { className: 'ghost', onclick: closeModal }, 'Close'));
    modal(box);
  } catch (e) { alert('Token failed: ' + e.message); }
}

// ---------- ios ----------
async function renderIos() {
  const root = $('#tab-ios'); root.innerHTML = '';
  const [status, policies, devices] = await Promise.all([
    api('GET', '/ios/status'), api('GET', '/policies'), api('GET', '/ios/devices'),
  ]);
  root.append(el('h2', {}, 'iOS / iPadOS (MDM)'));
  root.append(el('p', { className: 'muted' }, 'Enforced by Apple MDM configuration profiles on supervised devices.'));

  const pill = el('span', { className: 'pill ' + (status.ready ? 'on' : 'off') }, status.ready ? 'ready' : 'not configured');
  root.append(el('div', { className: 'card' },
    el('div', { className: 'row' }, el('strong', {}, 'MDM status:'), pill),
    el('div', { className: 'muted', style: 'margin-top:6px' },
      `server: ${status.serverUrl || '—'} · topic: ${status.topic || '—'} · APNs: ${status.apnsConfigured ? 'configured' : 'not configured'} · devices: ${status.deviceCount}`),
    status.ready
      ? el('div', { style: 'margin-top:8px' }, el('a', { href: '/mdm/enroll', target: '_blank' }, 'Download enrollment profile (.mobileconfig)'))
      : el('small', { className: 'hint', style: 'margin-top:8px' }, 'Set MDM_SERVER_URL + MDM_TOPIC (and APNS_CERT/APNS_KEY for push). Profile preview works without them.')));

  root.append(el('h3', {}, 'Enrolled devices'));
  if (!devices.length) root.append(el('p', { className: 'muted' }, 'No iOS devices enrolled yet.'));
  else {
    const t = el('table'); t.append(el('thead', {}, tr(['UDID', 'Policy', 'Last seen', 'Apply policy'], true)));
    const tb = el('tbody');
    for (const d of devices) {
      const sel = el('select', {});
      sel.append(el('option', { value: '' }, '— choose —'));
      for (const p of policies) sel.append(el('option', { value: p.id }, `${p.name} (L${p.body.level})`));
      tb.append(el('tr', {},
        td(el('span', { className: 'mono' }, d.udid)),
        td(d.policy_id || '—'),
        td(d.last_seen ? new Date(d.last_seen + 'Z').toLocaleString() : '—'),
        td(el('div', { className: 'row' }, sel,
          el('button', { className: 'small', onclick: async () => { if (!sel.value) return; try { await api('POST', `/ios/devices/${encodeURIComponent(d.udid)}/apply/${sel.value}`); alert('Profile queued + device woken.'); } catch (e) { alert(e.message); } } }, 'Apply'))),
      ));
    }
    t.append(tb); root.append(t);
  }

  root.append(el('h3', {}, 'Policies → iOS profile'));
  const t2 = el('table'); t2.append(el('thead', {}, tr(['Policy', 'Level', ''], true)));
  const tb2 = el('tbody');
  for (const p of policies) {
    tb2.append(el('tr', {},
      td(el('strong', {}, p.name)), td('L' + p.body.level),
      td(el('button', { className: 'small ghost', onclick: () => previewIos(p) }, 'Preview .mobileconfig'))));
  }
  t2.append(tb2); root.append(t2);
}
async function previewIos(p) {
  const r = await fetch(`/admin/api/ios/policies/${p.id}/preview`);
  const xml = await r.text();
  const box = el('div', {});
  box.append(el('h2', {}, 'iOS profile — ' + p.name),
    el('pre', { className: 'mono card', style: 'max-height:60vh;overflow:auto;white-space:pre-wrap' }, xml),
    el('div', { className: 'row' }, el('button', { className: 'ghost', onclick: closeModal }, 'Close')));
  modal(box);
}

// ---------- helpers ----------
function tr(cells, head) { const r = el('tr'); for (const c of cells) r.append(el(head ? 'th' : 'td', {}, c)); return r; }
function td(...k) { return el('td', {}, ...k); }
function ta(arr, ph) { return el('textarea', { value: (arr || []).join('\n'), placeholder: ph }); }
function lines(t) { return t.value.split('\n').map((s) => s.trim()).filter(Boolean); }
function lblc(cb, text) { return el('label', { style: 'margin:0;display:flex;gap:6px;align-items:center' }, cb, text); }

async function boot() {
  try { const me = await api('GET', '/me'); $('#who').textContent = me.username; showApp(); render('devices'); }
  catch { showLogin(); }
}
boot();
