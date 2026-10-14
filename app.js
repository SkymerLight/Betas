'use strict';

// ===== Configuração =====
const REPO = 'SkymerLight/Betas';
const BRANCH = 'main';
const DATA_FILE = 'data.enc.json';
const ITERATIONS = 250000;
const CATS = { betas: 'Betas', similar: 'Similar' };
const PLATFORMS = {
  android: { label: 'Android', icon: '🤖' },
  tablet: { label: 'Android · Tablet', icon: '📱' },
  ios: { label: 'iOS', icon: '' },
  desktop: { label: 'Desktop', icon: '🖥️' },
};

const LS = {
  local: 'vip.localBlob',   // cópia local criptografada (sempre a mais recente)
  dirty: 'vip.dirty',       // '1' quando há alterações não enviadas ao GitHub
  pw: 'vip.pw',             // senha, só se "lembrar neste aparelho"
  token: 'vip.ghToken',     // token do GitHub para salvar
  tab: 'vip.tab',
};

// ===== Estado =====
let state = null;          // { updatedAt, members: [...] }
let password = null;
let remoteBlob = null;     // blob criptografado lido do repo
let currentCat = lsGet(LS.tab) || 'betas';
let viewMonth = monthKey(new Date());

const $ = (s) => document.querySelector(s);

// ===== Utilidades =====
function lsGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
function lsSet(k, v) { try { localStorage.setItem(k, v); } catch {} }
function lsDel(k) { try { localStorage.removeItem(k); } catch {} }

function monthKey(d) { return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`; }
function monthLabel(key) {
  const [y, m] = key.split('-').map(Number);
  const s = new Date(y, m - 1, 1).toLocaleDateString('pt-BR', { month: 'long', year: 'numeric' });
  return s[0].toUpperCase() + s.slice(1);
}
function shiftMonth(key, delta) {
  const [y, m] = key.split('-').map(Number);
  return monthKey(new Date(y, m - 1 + delta, 1));
}
function fmtDate(iso) {
  return new Date(iso).toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function uid() { return Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4); }
function cleanDiscord(v) {
  // aceita "<@123>", "<@!123>" ou só o número
  const digits = String(v).match(/\d{5,}/);
  return digits ? digits[0] : String(v).trim();
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, 2200);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}

// ===== Criptografia (PBKDF2 + AES-GCM) =====
const te = new TextEncoder();
const td = new TextDecoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function deriveKey(pw, salt, iter) {
  const base = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptData(obj, pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pw, salt, ITERATIONS);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj)));
  return { v: 1, iter: ITERATIONS, salt: b64(salt), iv: b64(iv), data: b64(ct) };
}

async function decryptData(blob, pw) {
  const key = await deriveKey(pw, unb64(blob.salt), blob.iter);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, key, unb64(blob.data));
  return JSON.parse(td.decode(pt));
}

// ===== GitHub =====
function ghHeaders() {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${lsGet(LS.token)}`,
    'X-GitHub-Api-Version': '2022-11-28',
  };
}

async function ghGetFile() {
  const r = await fetch(`https://api.github.com/repos/${REPO}/contents/${DATA_FILE}?ref=${BRANCH}`,
    { headers: ghHeaders(), cache: 'no-store' });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`GitHub ${r.status}`);
  const j = await r.json();
  return { sha: j.sha, blob: JSON.parse(atob(j.content.replace(/\n/g, ''))) };
}

async function loadRemote() {
  // Com token lê direto pela API (sem atraso do Pages); senão lê o arquivo publicado.
  if (lsGet(LS.token)) {
    try { const f = await ghGetFile(); if (f) return f.blob; } catch {}
  }
  const r = await fetch(`${DATA_FILE}?t=${Date.now()}`, { cache: 'no-store' });
  if (!r.ok) throw new Error('Não foi possível carregar os dados.');
  return r.json();
}

async function saveToGitHub() {
  if (!lsGet(LS.token)) { openTokenModal(true); return; }
  const btn = $('#saveGh');
  btn.disabled = true;
  btn.textContent = 'Salvando…';
  try {
    const current = await ghGetFile();
    const blob = await encryptData(state, password);
    const body = {
      message: `Atualiza membros (${new Date().toLocaleString('pt-BR')})`,
      content: btoa(JSON.stringify(blob, null, 2) + '\n'),
      branch: BRANCH,
    };
    if (current) body.sha = current.sha;
    const r = await fetch(`https://api.github.com/repos/${REPO}/contents/${DATA_FILE}`,
      { method: 'PUT', headers: ghHeaders(), body: JSON.stringify(body) });
    if (r.status === 401 || r.status === 403) throw new Error('Token sem permissão ou inválido.');
    if (!r.ok) throw new Error(`GitHub respondeu ${r.status}`);
    remoteBlob = blob;
    lsDel(LS.dirty);
    toast('Salvo no GitHub ✓');
  } catch (e) {
    toast('Erro ao salvar: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Salvar no GitHub';
    renderSync();
  }
}

// ===== Persistência local =====
async function commit() {
  state.updatedAt = new Date().toISOString();
  lsSet(LS.local, JSON.stringify(await encryptData(state, password)));
  lsSet(LS.dirty, '1');
  render();
}

// ===== Desbloqueio =====
async function unlock(pw, remember) {
  if (!remoteBlob) remoteBlob = await loadRemote();
  const remote = await decryptData(remoteBlob, pw); // lança erro se a senha estiver errada

  let local = null;
  const raw = lsGet(LS.local);
  if (raw) { try { local = await decryptData(JSON.parse(raw), pw); } catch {} }

  // Usa a versão mais nova entre o repo e a cópia local
  if (local && local.updatedAt > remote.updatedAt) {
    state = local;
    lsSet(LS.dirty, '1');
  } else {
    state = remote;
    lsDel(LS.dirty);
    lsSet(LS.local, JSON.stringify(remoteBlob));
  }
  password = pw;
  if (remember) lsSet(LS.pw, pw);

  $('#lock').hidden = true;
  $('#app').hidden = false;
  render();
}

$('#lockForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#lockErr');
  err.hidden = true;
  try {
    await unlock($('#lockPw').value, $('#lockRemember').checked);
  } catch (ex) {
    err.textContent = ex instanceof DOMException || ex.name === 'OperationError'
      ? 'Senha incorreta.' : ex.message;
    err.hidden = false;
  }
});

// ===== Renderização =====
function platTag(key) {
  const p = PLATFORMS[key];
  if (!p) return '<span class="ptag none">Sem plataforma</span>';
  return `<span class="ptag ${key}">${p.icon ? `<span class="pico">${p.icon}</span>` : ''}${p.label}</span>`;
}

function isDone(m) { return Boolean(m.delivered && m.delivered[viewMonth]); }

function renderSync() {
  const el = $('#syncState');
  if (lsGet(LS.dirty)) {
    el.textContent = '● Alterações não salvas no GitHub';
    el.className = 'sync dirty';
  } else {
    el.textContent = '✓ Sincronizado';
    el.className = 'sync';
  }
}

function render() {
  $('#monthLabel').textContent = monthLabel(viewMonth);
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.cat === currentCat));

  for (const cat of Object.keys(CATS)) {
    const ms = state.members.filter((m) => m.cat === cat);
    $(`#count-${cat}`).textContent = `${ms.filter(isDone).length}/${ms.length}`;
  }

  const q = $('#search').value.trim().toLowerCase();
  const filter = $('#filter').value;
  const plat = $('#platFilter').value;
  const items = state.members.filter((m) => {
    if (m.cat !== currentCat) return false;
    if (q && !`${m.name || ''} ${m.discord} ${m.email} ${m.note || ''}`.toLowerCase().includes(q)) return false;
    if (filter === 'pending' && isDone(m)) return false;
    if (filter === 'done' && !isDone(m)) return false;
    if (plat !== 'all' && (m.platform || 'none') !== plat) return false;
    return true;
  });

  $('#list').innerHTML = items.map((m) => {
    const done = isDone(m);
    const field = (lbl, val, kind) => `
      <div class="field">
        <span class="lbl">${lbl}</span>
        <span class="val ${val ? '' : 'empty'}" title="${esc(val)}">${val ? esc(val) : 'vazio'}</span>
        ${val ? `<button class="btn small" data-act="copy" data-kind="${kind}" data-uid="${m.uid}"${kind === 'id' ? ' title="Copia como &lt;@id&gt;"' : ''}>Copiar</button>` : ''}
      </div>`;
    return `
      <li class="item ${done ? 'done' : ''}">
        ${platTag(m.platform)}
        <div class="name ${m.name ? '' : 'empty'}" title="${esc(m.name)}">${m.name ? esc(m.name) : 'sem nome'}</div>
        ${field('ID', m.discord, 'id')}
        ${field('E-mail', m.email, 'email')}
        <div class="side">
          <span class="pill ${done ? 'done' : 'pending'}">${done ? `✓ Entregue ${fmtDate(m.delivered[viewMonth])}` : 'Pendente'}</span>
          ${done
            ? `<button class="btn small" data-act="toggle" data-uid="${m.uid}" title="Voltar para pendente">Desfazer</button>`
            : `<button class="btn small ok" data-act="toggle" data-uid="${m.uid}">✓ Marcar entregue</button>`}
          <button class="btn small" data-act="edit" data-uid="${m.uid}">Editar</button>
        </div>
        ${m.note ? `<div class="note">${esc(m.note)}</div>` : ''}
      </li>`;
  }).join('');
  $('#empty').hidden = items.length > 0;
  renderSync();
}

// ===== Modal =====
function openModal(title, bodyHtml, actions) {
  $('#modalTitle').textContent = title;
  $('#modalBody').innerHTML = bodyHtml;
  const box = $('#modalActions');
  box.innerHTML = '';
  for (const a of actions) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn ' + (a.cls || '');
    b.textContent = a.label;
    b.addEventListener('click', async () => {
      if (a.onClick && (await a.onClick()) === false) return; // false mantém o modal aberto
      $('#modal').close();
    });
    box.appendChild(b);
  }
  $('#modal').showModal();
  const first = $('#modalBody input');
  if (first) first.focus();
}

// Copiar → confirmar entrega
async function onCopy(m, kind) {
  const text = kind === 'email' ? m.email : `<@${m.discord}>`;
  await copyText(text);
  toast(`Copiado: ${text}`);
}

async function setDelivered(m, on) {
  m.delivered = m.delivered || {};
  if (on) m.delivered[viewMonth] = new Date().toISOString();
  else delete m.delivered[viewMonth];
  await commit();
}

function onToggle(m) {
  if (!isDone(m)) { setDelivered(m, true); return; }
  openModal('Desmarcar entrega?', `<p>Voltar este membro para <b>Pendente</b> em ${esc(monthLabel(viewMonth))}?</p>`, [
    { label: 'Cancelar' },
    { label: 'Desmarcar', cls: 'danger', onClick: () => setDelivered(m, false) },
  ]);
}

function openEdit(m) {
  const isNew = !m;
  const opts = Object.entries(CATS).map(([k, v]) =>
    `<option value="${k}" ${(m ? m.cat : currentCat) === k ? 'selected' : ''}>${v}</option>`).join('');
  const platOpts = Object.entries(PLATFORMS).map(([k, v]) =>
    `<option value="${k}" ${m && m.platform === k ? 'selected' : ''}>${v.label}</option>`).join('');
  const actions = [];
  if (!isNew) {
    actions.push({
      label: 'Excluir', cls: 'danger left', onClick: async () => {
        if (!confirm('Excluir este membro?')) return false;
        state.members = state.members.filter((x) => x.uid !== m.uid);
        await commit();
        toast('Membro excluído');
      },
    });
  }
  actions.push({ label: 'Cancelar' });
  actions.push({
    label: 'Salvar', cls: 'primary', onClick: async () => {
      const discord = cleanDiscord($('#fDiscord').value);
      const email = $('#fEmail').value.trim();
      if (!discord && !email) { toast('Preencha o ID ou o e-mail'); return false; }
      const target = m || { uid: uid(), delivered: {} };
      target.cat = $('#fCat').value;
      target.name = $('#fName').value.trim();
      target.discord = discord;
      target.email = email;
      target.note = $('#fNote').value.trim();
      target.platform = $('#fPlat').value;
      if (isNew) state.members.push(target);
      await commit();
      toast(isNew ? 'Membro adicionado' : 'Alterações salvas');
    },
  });
  openModal(isNew ? 'Adicionar membro' : 'Editar membro', `
    <label>Categoria <select id="fCat">${opts}</select></label>
    <label>Plataforma <select id="fPlat"><option value="">Sem plataforma</option>${platOpts}</select></label>
    <label>Nome <input id="fName" value="${esc(m ? m.name : '')}" placeholder="Nome ou apelido"></label>
    <label>ID do Discord <input id="fDiscord" value="${esc(m ? m.discord : '')}" placeholder="123456789012345678 ou <@123…>"></label>
    <label>E-mail / usuário <input id="fEmail" value="${esc(m ? m.email : '')}" placeholder="email@exemplo.com"></label>
    <label>Observação (opcional) <input id="fNote" value="${esc(m ? m.note : '')}"></label>`, actions);
}

function openTokenModal(thenSave) {
  openModal('Token do GitHub', `
    <p>Para salvar direto no repositório, cole um <b>fine-grained token</b> com acesso só ao repo
      <code>${REPO}</code> e permissão <b>Contents: Read and write</b>.</p>
    <p class="muted">Crie em github.com → Settings → Developer settings → Personal access tokens → Fine-grained tokens.
      Ele fica salvo só neste navegador.</p>
    <label>Token <input id="fToken" type="password" placeholder="github_pat_…" value="${esc(lsGet(LS.token) || '')}"></label>`, [
    { label: 'Remover token', cls: 'danger left', onClick: () => { lsDel(LS.token); toast('Token removido'); } },
    { label: 'Cancelar' },
    {
      label: 'Salvar', cls: 'primary', onClick: () => {
        const v = $('#fToken').value.trim();
        if (!v) return false;
        lsSet(LS.token, v);
        toast('Token salvo');
        if (thenSave) setTimeout(saveToGitHub, 0);
      },
    },
  ]);
}

function openSettings() {
  openModal('Configurações', `
    <p class="muted">Edições ficam salvas neste navegador na hora. Use “Salvar no GitHub” para gravar no repositório
      (e ver em outros aparelhos).</p>`, [
    { label: 'Token do GitHub', onClick: () => { setTimeout(() => openTokenModal(false), 0); } },
    { label: 'Trocar senha', onClick: () => { setTimeout(openChangePw, 0); } },
    { label: 'Exportar backup', onClick: exportBackup },
    {
      label: 'Sair', cls: 'danger', onClick: () => { lsDel(LS.pw); location.reload(); },
    },
  ]);
}

function openChangePw() {
  openModal('Trocar senha', `
    <label>Nova senha <input id="fPw1" type="password" autocomplete="new-password"></label>
    <label>Repita a nova senha <input id="fPw2" type="password" autocomplete="new-password"></label>
    <p class="muted">Depois clique em “Salvar no GitHub” para a nova senha valer no site publicado.</p>`, [
    { label: 'Cancelar' },
    {
      label: 'Trocar', cls: 'primary', onClick: async () => {
        const a = $('#fPw1').value, b = $('#fPw2').value;
        if (a.length < 6) { toast('Use pelo menos 6 caracteres'); return false; }
        if (a !== b) { toast('As senhas não conferem'); return false; }
        password = a;
        if (lsGet(LS.pw)) lsSet(LS.pw, a);
        await commit();
        toast('Senha trocada — salve no GitHub');
      },
    },
  ]);
}

function exportBackup() {
  const blob = new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `vip-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ===== Eventos =====
$('#list').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-act]');
  if (!b) return;
  const m = state.members.find((x) => x.uid === b.dataset.uid);
  if (!m) return;
  if (b.dataset.act === 'copy') onCopy(m, b.dataset.kind);
  if (b.dataset.act === 'toggle') onToggle(m);
  if (b.dataset.act === 'edit') openEdit(m);
});

document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => {
  currentCat = t.dataset.cat;
  lsSet(LS.tab, currentCat);
  render();
}));
$('#search').addEventListener('input', render);
$('#filter').addEventListener('change', render);
$('#platFilter').addEventListener('change', render);
$('#addBtn').addEventListener('click', () => openEdit(null));
$('#prevMonth').addEventListener('click', () => { viewMonth = shiftMonth(viewMonth, -1); render(); });
$('#nextMonth').addEventListener('click', () => { viewMonth = shiftMonth(viewMonth, 1); render(); });
$('#saveGh').addEventListener('click', saveToGitHub);
$('#settingsBtn').addEventListener('click', openSettings);
window.addEventListener('beforeunload', (e) => {
  if (state && lsGet(LS.dirty)) { e.preventDefault(); e.returnValue = ''; }
});

// Abre sozinho se a senha estiver lembrada
(async () => {
  const saved = lsGet(LS.pw);
  if (!saved) return;
  try { await unlock(saved, true); } catch { lsDel(LS.pw); }
})();
