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
  last: 'vip.lastCopied',  // último ID/e-mail copiado (para destacar)
};

// ===== Estado =====
let state = null;          // { updatedAt, members: [...] }
let password = null;
let remoteBlob = null;     // blob criptografado lido do repo
let baseUpdatedAt = null;  // updatedAt da versão do GitHub que serviu de base para as edições
let currentCat = lsGet(LS.tab) || 'betas';
let viewMonth = monthKey(new Date());
let lastCopied = (() => { try { return JSON.parse(lsGet(LS.last)) || {}; } catch { return {}; } })();

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
function toLocalInput(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
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
// Os dados são cifrados com uma chave aleatória (DEK). Cada senha tem um "slot" que guarda
// essa chave cifrada com a senha — assim mais de uma pessoa abre o mesmo painel.
const te = new TextEncoder();
const td = new TextDecoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

let dekRaw = null;   // chave dos dados (32 bytes)
let slots = [];      // [{ id, label, iter, salt, iv, key }]
let mySlotId = null; // slot da senha usada para entrar

async function pwKey(pw, salt, iter) {
  const base = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
const dataKey = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);

async function makeSlot(label, pw, id = uid(), role = 'member') {
  const salt = rand(16);
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await pwKey(pw, salt, ITERATIONS), dekRaw);
  return { id, label, role, iter: ITERATIONS, salt: b64(salt), iv: b64(iv), key: b64(ct) };
}

async function encryptData(obj) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await dataKey(dekRaw), te.encode(JSON.stringify(obj)));
  return { v: 2, slots, iv: b64(iv), data: b64(ct) };
}

// Abre um blob com a senha → { data, dek, slots, slotId }. Lança OperationError se nenhuma senha bater.
async function openBlob(blob, pw) {
  if (blob.v !== 2) {
    // formato antigo: uma senha só, sem slots
    const key = await pwKey(pw, unb64(blob.salt), blob.iter);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, key, unb64(blob.data));
    return { data: JSON.parse(td.decode(pt)), dek: null, slots: null, slotId: null };
  }
  for (const sl of blob.slots) {
    let dek;
    try {
      const k = await pwKey(pw, unb64(sl.salt), sl.iter);
      dek = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(sl.iv) }, k, unb64(sl.key)));
    } catch { continue; }
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, await dataKey(dek), unb64(blob.data));
    return { data: JSON.parse(td.decode(pt)), dek, slots: blob.slots, slotId: sl.id };
  }
  throw new DOMException('Senha incorreta', 'OperationError');
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

async function saveToGitHub(force = false) {
  if (!lsGet(LS.token)) { openTokenModal(true); return; }
  const btn = $('#saveGh');
  btn.disabled = true;
  btn.querySelector('span').textContent = 'Salvando…';
  try {
    const current = await ghGetFile();
    if (current && !force) {
      let remote;
      try { remote = await openBlob(current.blob, password); } catch {
        throw new Error('sua senha não abre mais a versão do GitHub (foi removida ou trocada).');
      }
      // Outra pessoa salvou depois que você abriu o painel?
      if (remote.data.updatedAt > baseUpdatedAt && remote.data.updatedAt !== state.updatedAt) {
        openConflict(remote, current.blob);
        return;
      }
    }
    const blob = await encryptData(state);
    const body = {
      message: `Atualiza membros (${new Date().toLocaleString('pt-BR')})`,
      content: btoa(JSON.stringify(blob, null, 2) + '\n'),
      branch: BRANCH,
    };
    if (current) body.sha = current.sha;
    const r = await fetch(`https://api.github.com/repos/${REPO}/contents/${DATA_FILE}`,
      { method: 'PUT', headers: ghHeaders(), body: JSON.stringify(body) });
    if (r.status === 401 || r.status === 403 || r.status === 404) throw new Error('token sem permissão de escrita neste repositório.');
    if (r.status === 409) throw new Error('o arquivo mudou no GitHub enquanto salvava, tente de novo.');
    if (!r.ok) throw new Error(`GitHub respondeu ${r.status}`);
    remoteBlob = blob;
    baseUpdatedAt = state.updatedAt;
    lsDel(LS.dirty);
    toast('Salvo no GitHub ✓');
  } catch (e) {
    toast('Erro ao salvar: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.querySelector('span').textContent = 'Salvar no GitHub';
    renderSync();
  }
}

function openConflict(remote, blob) {
  const who = remote.data.updatedBy ? ` por <b>${esc(remote.data.updatedBy)}</b>` : '';
  openModal('Outra pessoa salvou antes', `
    <p>O painel foi salvo no GitHub${who} em <b>${esc(fmtDate(remote.data.updatedAt))}</b>, depois que você abriu.</p>
    <p class="muted">Se você sobrescrever, as alterações dessa pessoa serão perdidas. Se carregar a versão do GitHub,
      as suas alterações não salvas é que serão perdidas.</p>`, [
    {
      label: 'Carregar versão do GitHub', cls: 'left', onClick: () => {
        applyOpened(remote);
        remoteBlob = blob;
        baseUpdatedAt = remote.data.updatedAt;
        lsSet(LS.local, JSON.stringify(blob));
        lsDel(LS.dirty);
        render();
        toast('Versão do GitHub carregada');
      },
    },
    { label: 'Cancelar' },
    { label: 'Sobrescrever', cls: 'danger', onClick: () => { setTimeout(() => saveToGitHub(true), 0); } },
  ]);
}

// ===== Persistência local =====
async function commit() {
  state.updatedAt = new Date().toISOString();
  const me = slots.find((x) => x.id === mySlotId);
  if (me) state.updatedBy = me.label;
  lsSet(LS.local, JSON.stringify(await encryptData(state)));
  lsSet(LS.dirty, '1');
  render();
}

function applyOpened(o) {
  state = o.data;
  if (o.dek) {
    dekRaw = o.dek;
    // Senhas antigas sem papel: a primeira (a original) é a principal
    slots = o.slots.map((x, i) => (x.role ? x : { ...x, role: i === 0 ? 'admin' : 'member' }));
    mySlotId = o.slotId;
  }
}

function mySlot() { return slots.find((x) => x.id === mySlotId); }
function isAdmin() { const me = mySlot(); return Boolean(me && me.role === 'admin'); }

// ===== Desbloqueio =====
async function unlock(pw, remember) {
  if (!remoteBlob) remoteBlob = await loadRemote();
  const remote = await openBlob(remoteBlob, pw); // lança erro se a senha estiver errada

  let local = null;
  const raw = lsGet(LS.local);
  if (raw) { try { local = await openBlob(JSON.parse(raw), pw); } catch {} }

  // Usa a versão mais nova entre o repo e a cópia local
  const useLocal = local && local.data.updatedAt > remote.data.updatedAt;
  applyOpened(useLocal ? local : remote);
  baseUpdatedAt = remote.data.updatedAt;
  password = pw;

  if (!dekRaw) {
    // Dados no formato antigo (uma senha só): converte para o formato com várias senhas
    dekRaw = rand(32);
    const sl = await makeSlot('Principal', pw, uid(), 'admin');
    slots = [sl];
    mySlotId = sl.id;
    lsSet(LS.local, JSON.stringify(await encryptData(state)));
    lsSet(LS.dirty, '1');
    setTimeout(() => toast('Formato atualizado — clique em “Salvar no GitHub”'), 400);
  } else if (useLocal) {
    lsSet(LS.dirty, '1');
  } else {
    lsDel(LS.dirty);
    lsSet(LS.local, JSON.stringify(remoteBlob));
  }
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

function initials(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return '?';
  return (parts[0][0] + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase();
}

function isDone(m) { return Boolean(m.delivered && m.delivered[viewMonth]); }

function renderSync() {
  const el = $('#syncState');
  if (lsGet(LS.dirty)) {
    el.textContent = '● Não salvo no GitHub';
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

  const inTab = state.members.filter((m) => m.cat === currentCat);
  const doneCount = inTab.filter(isDone).length;
  const pct = inTab.length ? Math.round((doneCount / inTab.length) * 100) : 0;
  $('#statDone').textContent = doneCount;
  $('#statPending').textContent = inTab.length - doneCount;
  $('#statPct').textContent = `${pct}%`;
  $('#statBar').style.width = `${pct}%`;

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

  const copyIc = '<svg class="ic" viewBox="0 0 24 24"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';
  $('#list').innerHTML = items.map((m, i) => {
    const done = isDone(m);
    const pkey = PLATFORMS[m.platform] ? m.platform : 'none';
    const isLast = lastCopied.uid === m.uid;
    const field = (lbl, val, kind) => `
      <div class="field f-${kind} ${isLast && lastCopied.kind === kind ? 'last-field' : ''}">
        <div class="field-text">
          <span class="lbl">${lbl}</span>
          <span class="val ${val ? '' : 'empty'}" title="${esc(val)}">${val ? esc(val) : 'vazio'}</span>
        </div>
        ${val ? `<button class="btn small copy" data-act="copy" data-kind="${kind}" data-uid="${m.uid}"${kind === 'id' ? ' title="Copia como &lt;@id&gt;"' : ''}>${copyIc}Copiar</button>` : ''}
      </div>`;
    return `
      <li class="item p-${pkey} ${done ? 'done' : ''} ${isLast ? 'last' : ''}" data-uid="${m.uid}" style="animation-delay:${Math.min(i, 15) * 25}ms">
        <div class="who">
          <div class="avatar">${esc(initials(m.name))}</div>
          <div class="who-text">
            <div class="name ${m.name ? '' : 'empty'}" title="${esc(m.name)}">${m.name ? esc(m.name) : 'sem nome'}</div>
            <div class="tags">${platTag(m.platform)}<span class="last-badge">Último copiado</span></div>
          </div>
        </div>
        ${field('Discord', m.discord, 'id')}
        ${field('E-mail', m.email, 'email')}
        <div class="side">
          <div class="status">
            <span class="pill ${done ? 'done' : 'pending'}">${done ? 'Entregue' : 'Pendente'}</span>
            ${done ? `<span class="when">${fmtDate(m.delivered[viewMonth])}</span>` : ''}
          </div>
          ${done
            ? `<button class="btn small ghost" data-act="toggle" data-uid="${m.uid}" title="Voltar para pendente">Desfazer</button>`
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

// Destaca o último membro copiado (sem redesenhar a lista)
function markLastCopied(memberUid, kind) {
  kind = kind === 'email' ? 'email' : 'id';
  lastCopied = { uid: memberUid, kind };
  lsSet(LS.last, JSON.stringify(lastCopied));
  document.querySelectorAll('.item.last').forEach((el) => el.classList.remove('last'));
  document.querySelectorAll('.field.last-field').forEach((el) => el.classList.remove('last-field'));
  const li = document.querySelector(`.item[data-uid="${memberUid}"]`);
  if (!li) return;
  li.classList.add('last');
  li.querySelector(`.f-${kind}`)?.classList.add('last-field');
  // reinicia a animação de pulso
  li.style.animation = 'none';
  void li.offsetWidth;
  li.style.animation = '';
}

// Copiar
async function onCopy(m, kind, btn) {
  const text = kind === 'email' ? m.email : `<@${m.discord}>`;
  await copyText(text);
  toast(`Copiado: ${text}`);
  markLastCopied(m.uid, kind);
  if (btn) {
    const html = btn.innerHTML;
    btn.classList.add('copied');
    btn.textContent = '✓ Copiado';
    setTimeout(() => { btn.classList.remove('copied'); btn.innerHTML = html; }, 1400);
  }
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
      target.delivered = target.delivered || {};
      const del = $('#fDel').value;
      if (del) target.delivered[viewMonth] = new Date(del).toISOString();
      else delete target.delivered[viewMonth];
      if (isNew) state.members.push(target);
      await commit();
      toast(isNew ? 'Membro adicionado' : 'Alterações salvas');
    },
  });
  openModal(isNew ? 'Adicionar membro' : 'Editar membro', `
    <div class="row2">
      <label>Categoria <select id="fCat">${opts}</select></label>
      <label>Plataforma <select id="fPlat"><option value="">Sem plataforma</option>${platOpts}</select></label>
    </div>
    <label>Nome <input id="fName" value="${esc(m ? m.name : '')}" placeholder="Nome ou apelido"></label>
    <label>ID do Discord <input id="fDiscord" value="${esc(m ? m.discord : '')}" placeholder="123456789012345678 ou <@123…>"></label>
    <label>E-mail / usuário <input id="fEmail" value="${esc(m ? m.email : '')}" placeholder="email@exemplo.com"></label>
    <label>Observação (opcional) <input id="fNote" value="${esc(m ? m.note : '')}"></label>
    <div class="del-box">
      <label>Entrega de ${esc(monthLabel(viewMonth))}
        <input id="fDel" type="datetime-local" value="${toLocalInput(m && m.delivered && m.delivered[viewMonth])}">
      </label>
      <div class="del-actions">
        <button type="button" class="btn small" id="fDelNow">Agora</button>
        <button type="button" class="btn small" id="fDelClear">Limpar (pendente)</button>
      </div>
    </div>`, actions);
  $('#fDelNow').addEventListener('click', () => { $('#fDel').value = toLocalInput(new Date().toISOString()); });
  $('#fDelClear').addEventListener('click', () => { $('#fDel').value = ''; });
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
  const me = mySlot();
  const admin = isAdmin();
  const actions = [];
  if (admin) {
    actions.push({ label: 'Senhas de acesso', onClick: () => { setTimeout(openPasswords, 0); } });
    actions.push({ label: 'Token do GitHub', onClick: () => { setTimeout(() => openTokenModal(false), 0); } });
  }
  actions.push({ label: 'Trocar minha senha', onClick: () => { setTimeout(openChangePw, 0); } });
  actions.push({ label: 'Exportar backup', onClick: exportBackup });
  actions.push({ label: 'Sair', cls: 'danger', onClick: () => { lsDel(LS.pw); location.reload(); } });
  openModal('Configurações', `
    <p class="muted">Você entrou como <b>${esc(me ? me.label : '—')}</b>${admin ? ' <span class="you gold">principal</span>' : ''}.
      Edições ficam salvas neste navegador na hora; use “Salvar no GitHub” para gravar no repositório
      (e aparecer para os outros).</p>`, actions);
}

function pwValid(a, b) {
  if (a.length < 6) { toast('Use pelo menos 6 caracteres'); return false; }
  if (a !== b) { toast('As senhas não conferem'); return false; }
  return true;
}

function openPasswords() {
  if (!isAdmin()) return;
  const list = slots.map((sl) => `
    <div class="slot">
      <div class="slot-ic">${esc(initials(sl.label))}</div>
      <div class="slot-name">${esc(sl.label)}${sl.id === mySlotId ? ' <span class="you">você</span>' : ''}${sl.role === 'admin' ? ' <span class="you gold">principal</span>' : ''}</div>
      <button type="button" class="btn small ghost" data-rn="${sl.id}">Renomear</button>
      ${sl.id === mySlotId ? '' : `<button type="button" class="btn small danger" data-rm="${sl.id}">Remover</button>`}
    </div>`).join('');
  openModal('Senhas de acesso', `
    <p class="muted">Cada pessoa tem a própria senha e todas abrem o mesmo painel.</p>
    <div class="slots">${list}</div>
    <div class="add-box">
      <strong>Adicionar senha</strong>
      <label>Nome de quem vai usar <input id="fLabel" placeholder="Ex.: João"></label>
      <div class="row2">
        <label>Senha <input id="fPw1" type="password" autocomplete="new-password"></label>
        <label>Repita <input id="fPw2" type="password" autocomplete="new-password"></label>
      </div>
    </div>
    <p class="muted">Depois de adicionar ou remover, clique em “Salvar no GitHub” para valer no site publicado.</p>`, [
    { label: 'Fechar' },
    {
      label: 'Adicionar', cls: 'primary', onClick: async () => {
        const label = $('#fLabel').value.trim();
        if (!label) { toast('Coloque o nome de quem vai usar'); return false; }
        if (!pwValid($('#fPw1').value, $('#fPw2').value)) return false;
        slots = [...slots, await makeSlot(label, $('#fPw1').value, uid(), 'member')];
        await commit();
        toast(`Senha de ${label} adicionada — salve no GitHub`);
        setTimeout(openPasswords, 0);
      },
    },
  ]);
  $('#modalBody').querySelectorAll('[data-rm]').forEach((b) => b.addEventListener('click', async () => {
    const sl = slots.find((x) => x.id === b.dataset.rm);
    if (!sl || !confirm(`Remover a senha de ${sl.label}?`)) return;
    slots = slots.filter((x) => x.id !== sl.id);
    await commit();
    toast(`Senha de ${sl.label} removida — salve no GitHub`);
    openPasswords();
  }));
  $('#modalBody').querySelectorAll('[data-rn]').forEach((b) => b.addEventListener('click', async () => {
    const sl = slots.find((x) => x.id === b.dataset.rn);
    const name = sl && prompt('Novo nome:', sl.label);
    if (!name || !name.trim()) return;
    slots = slots.map((x) => (x.id === sl.id ? { ...x, label: name.trim() } : x));
    await commit();
    openPasswords();
  }));
  const label = $('#fLabel');
  if (label) label.focus();
}

function openChangePw() {
  openModal('Trocar minha senha', `
    <label>Nova senha <input id="fPw1" type="password" autocomplete="new-password"></label>
    <label>Repita a nova senha <input id="fPw2" type="password" autocomplete="new-password"></label>
    <p class="muted">Só a sua senha muda; as outras pessoas continuam com as delas.
      Depois clique em “Salvar no GitHub” para valer no site publicado.</p>`, [
    { label: 'Cancelar' },
    {
      label: 'Trocar', cls: 'primary', onClick: async () => {
        const a = $('#fPw1').value;
        if (!pwValid(a, $('#fPw2').value)) return false;
        const me = slots.find((x) => x.id === mySlotId);
        const fresh = await makeSlot(me ? me.label : 'Principal', a, mySlotId, me ? me.role : 'member');
        slots = slots.map((x) => (x.id === mySlotId ? fresh : x));
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
  if (b.dataset.act === 'copy') onCopy(m, b.dataset.kind, b);
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
