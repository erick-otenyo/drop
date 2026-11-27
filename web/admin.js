// The host's admin page: start and end sessions, the live thread, history.
'use strict';
(() => {
  const labels = { mineDir: 'out', mineLabel: 'This computer', theirLabel: 'Guest', onDelete: deleteMessage };
  const shown = new Map();    // message id -> element, for the live thread
  const liveMsgs = new Map(); // message id -> message, for "Copy all"
  let app = { phase: 'idle', version: -1 };
  let sessVersion = -1;
  let cursor = 0;
  let tracked = 0;   // history id of the session the thread belongs to
  let view = 'session';
  let openSession = null;
  let gone = false;

  async function call(method, path, body) {
    const r = await fetch(path, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || 'Request failed');
    return data;
  }

  function setStatus(text, cls) {
    $('status').hidden = !text;
    $('status').textContent = text;
    $('status').className = 'badge ' + (cls || '');
  }

  // One block of text for a whole session, as it would read aloud.
  function sessionText(msgs) {
    return msgs.map((m) => (m.dir === 'out' ? 'Host' : 'Guest') + ':\n' + m.body).join('\n\n');
  }

  // Lines Tailscale printed; links in them become clickable.
  function noticeEl(lines) {
    const box = $('notice');
    box.replaceChildren();
    for (const line of lines) {
      const p = el('div');
      for (const part of line.split(/(https:\/\/\S+)/)) {
        if (part.startsWith('https://')) p.append(el('a', { href: part, textContent: part, target: '_blank', rel: 'noopener noreferrer' }));
        else p.append(part);
      }
      box.append(p);
    }
    box.hidden = lines.length === 0;
  }

  function render() {
    const live = app.phase === 'live';
    const starting = app.phase === 'starting';
    $('nav').hidden = !live;
    $('tab-session').classList.toggle('on', view === 'session');
    $('tab-history').classList.toggle('on', view === 'history');
    $('session').hidden = !live || view !== 'session';
    $('start').hidden = live;
    $('history').hidden = live && view !== 'history';

    const busy = starting || app.phase === 'stopping';
    $('start-lan').hidden = $('start-net').hidden = starting;
    $('start-lan').disabled = $('start-net').disabled = busy;
    $('cancel').hidden = !starting;
    $('start-title').textContent = starting
      ? (app.mode === 'net' ? 'Starting internet session…' : 'Starting LAN session…')
      : app.phase === 'stopping' ? 'Closing the session…' : 'Start a session';
    $('start-sub').hidden = busy;
    noticeEl(live ? [] : (app.notice || []));
    $('start-error').hidden = !app.error;
    $('start-error').textContent = app.error || '';

    if (!live) setStatus(starting ? 'Starting' : app.phase === 'stopping' ? 'Closing' : '');
    else renderSession(app.session);
  }

  // ---- Live session ----

  function renderSession(s) {
    $('addr').textContent = s.url.replace(/^https?:\/\//, '');
    $('code').textContent = s.code.slice(0, 3) + '-' + s.code.slice(3);
    const joined = s.status === 'joined';
    $('pair-addr').hidden = joined;
    $('pair-code').hidden = joined || s.status === 'locked';
    $('newcode').hidden = s.status !== 'locked';
    let note = '';
    if (joined) note = 'A guest is connected. No one else can join this session.';
    else if (s.status === 'locked') note = 'Locked after 5 wrong codes. Make a new code to let the guest try again.';
    else if (s.attemptsLeft < 5) note = s.attemptsLeft + ' of 5 code attempts left.';
    // Instructions for a guest that only has a terminal.
    const clients = app.clients || [];
    const addr = s.url.replace(/^https?:\/\//, '');
    $('term').hidden = joined || clients.length === 0;
    $('term-get').textContent = 'curl -fo drop ' + s.url + '/get/linux-$(uname -m) && chmod +x drop';
    $('term-join').textContent = './drop join ' + addr;
    $('term-sums').textContent = clients.map((c) => c.sha256 + '  ' + c.platform).join('\n');
    $('pair-note').textContent = note;
    $('pair-note').hidden = !note;
    if (joined) setStatus('Guest connected', 'ok');
    else if (s.status === 'locked') setStatus('Locked', 'bad');
    else setStatus(s.mode === 'net' ? 'Waiting · internet' : 'Waiting · LAN', 'warn');
  }

  function resetThread() {
    shown.clear();
    liveMsgs.clear();
    cursor = 0;
    sessVersion = -1;
    $('thread').replaceChildren(el('p', { className: 'empty', textContent: 'Nothing sent yet.' }));
  }

  function apply(e) {
    if (e.t === 'msg' && !shown.has(e.id)) {
      const node = messageEl(e, labels);
      shown.set(e.id, node);
      liveMsgs.set(e.id, e);
      $('thread').querySelector('.empty')?.remove();
      $('thread').append(node);
      node.scrollIntoView({ block: 'end' });
    } else if (e.t === 'del') {
      shown.get(e.id)?.remove();
      shown.delete(e.id);
      liveMsgs.delete(e.id);
    }
  }

  function showGone(text) {
    gone = true;
    for (const id of ['start', 'session', 'history', 'nav', 'quit']) $(id).hidden = true;
    setStatus('');
    $('gone-msg').textContent = text;
    $('gone').hidden = false;
  }

  async function poll() {
    let fails = 0;
    while (!gone) {
      let data;
      try {
        data = await call('GET', `/api/poll?av=${app.version}&sv=${sessVersion}&after=${cursor}&sid=${tracked}`);
        fails = 0;
      } catch (_) {
        if (gone) return;
        fails += 1;
        if (fails >= 3) return showGone('drop is no longer running.');
        await sleep(1000);
        continue;
      }
      const before = app.phase;
      app = data.app;
      if (app.session) {
        if (app.session.sessionId !== tracked) {
          tracked = app.session.sessionId;
          resetThread();
          view = 'session';
        }
        sessVersion = app.session.version;
        for (const e of data.events) {
          cursor = Math.max(cursor, e.seq);
          apply(e);
        }
      }
      render();
      if (app.phase === 'live' && before !== 'live') $('text').focus();
      if (app.phase !== 'live' && before === 'live') {
        // Back to the home view, with the session that just ended on top.
        tracked = 0;
        view = 'session';
        openSession = app.session ? app.session.sessionId : app.lastEnded;
        render();
        loadHistory();
      } else if (app.phase === 'idle' && before === 'stopping') {
        loadHistory();
      }
    }
  }

  async function send() {
    const body = $('text').value;
    if (!body.trim()) return;
    $('send-msg').textContent = '';
    try {
      await call('POST', '/api/send', { body });
      $('text').value = '';
    } catch (err) {
      $('send-msg').textContent = 'Not sent: ' + err.message + '.';
    }
  }

  async function deleteMessage(m) {
    await call('DELETE', '/api/message/' + m.id);
    if (!$('history').hidden) loadHistory();
  }

  // ---- History ----

  async function loadHistory() {
    let rows;
    try {
      rows = await call('GET', '/api/history?q=' + encodeURIComponent($('search').value.trim()));
    } catch (_) {
      return;
    }
    const nodes = [];
    for (const s of rows) nodes.push(await sessionEl(s));
    if (!nodes.length) {
      nodes.push(el('p', { className: 'empty', textContent: $('search').value ? 'No messages match.' : 'No history yet.' }));
    }
    $('sessions').replaceChildren(...nodes);
  }

  async function sessionEl(s) {
    const live = s.endedAt === 0;
    const row = el('div', { className: 'row' },
      el('span', { className: 'when', textContent: new Date(s.startedAt).toLocaleString() }),
      el('span', { className: 'badge' + (live ? ' ok' : ''), textContent: live ? 'live' : (s.mode === 'net' ? 'internet' : 'LAN') }),
      el('span', { className: 'preview', textContent: s.preview.replace(/\s+/g, ' ') }),
      el('span', { className: 'muted', textContent: s.count + (s.count === 1 ? ' message' : ' messages') }));
    const node = el('div', { className: 'session' }, row);
    row.addEventListener('click', () => {
      openSession = openSession === s.id ? null : s.id;
      loadHistory();
    });
    if (openSession !== s.id) return node;

    const msgs = await call('GET', '/api/history/' + s.id);
    const copyAll = el('button', { className: 'small', type: 'button', textContent: 'Copy whole session' });
    copyAll.addEventListener('click', async () => { await copyText(sessionText(msgs)); flash(copyAll, 'Copied'); });
    const tools = el('div', { className: 'session-tools' }, copyAll);
    if (!live) {
      tools.append(confirmButton('Delete session', async () => {
        await call('DELETE', '/api/history/' + s.id);
        openSession = null;
        loadHistory();
      }));
    }
    const opts = Object.assign({ fullDate: true }, labels);
    node.append(el('div', { className: 'body' }, tools, ...msgs.map((m) => messageEl(m, opts))));
    return node;
  }

  // ---- Wiring ----

  const start = (mode) => call('POST', '/api/start', { mode }).catch(() => {});
  $('start-lan').addEventListener('click', () => start('lan'));
  $('start-net').addEventListener('click', () => start('net'));
  $('cancel').addEventListener('click', () => call('POST', '/api/cancel').catch(() => {}));
  $('end').addEventListener('click', () => call('POST', '/api/end').catch(() => {}));
  $('newcode').addEventListener('click', () => call('POST', '/api/newcode').catch(() => {}));
  for (const id of ['term-get', 'term-join']) {
    $(id + '-copy').addEventListener('click', async () => {
      await copyText($(id).textContent);
      flash($(id + '-copy'), 'Copied');
    });
  }
  $('copy-live').addEventListener('click', async () => {
    await copyText(sessionText([...liveMsgs.values()]));
    flash($('copy-live'), 'Copied');
  });
  $('quit').addEventListener('click', async () => {
    gone = true;
    await call('POST', '/api/quit').catch(() => {});
    showGone('drop has quit. Any session was ended.');
  });
  $('tab-session').addEventListener('click', () => { view = 'session'; render(); });
  $('tab-history').addEventListener('click', () => { view = 'history'; render(); loadHistory(); });
  $('compose').addEventListener('submit', (ev) => { ev.preventDefault(); send(); });
  $('text').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); send(); }
  });
  let searchTimer = null;
  $('search').addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(loadHistory, 200);
  });
  $('delete-all').append(confirmButton('Delete all history', async () => {
    await call('DELETE', '/api/history');
    openSession = null;
    loadHistory();
  }));

  render();
  loadHistory();
  poll();
})();
