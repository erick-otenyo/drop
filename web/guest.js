// The guest's page: join with the code, then a live thread.
// Every message is encrypted with keys derived from the join handshake.
'use strict';
(() => {
  const C = DropCrypto;
  const STORE = 'drop-session';
  const msgOpts = { mineDir: 'in', mineLabel: 'This computer', theirLabel: 'Host' };

  let sid = '';
  let keys = null;
  let cursor = 0;
  let stopped = false;
  const shown = new Map();

  function show(view) {
    for (const v of ['join', 'thread-view', 'ended']) $(v).hidden = v !== view;
  }

  function setStatus(text, cls) {
    $('status').hidden = !text;
    $('status').textContent = text;
    $('status').className = 'badge ' + (cls || '');
  }

  // Wipe everything this page holds about the session.
  function end(text) {
    stopped = true;
    keys = null;
    sessionStorage.removeItem(STORE);
    shown.clear();
    $('thread').replaceChildren();
    $('text').value = '';
    $('code').value = '';
    $('ended-msg').textContent = text;
    setStatus('');
    show('ended');
  }

  // Keys live in sessionStorage so a reload keeps the thread; they go when
  // the tab closes or the session ends.
  function save() {
    sessionStorage.setItem(STORE, JSON.stringify({
      sid, c2s: C.b64(keys.c2s), s2c: C.b64(keys.s2c), token: keys.token,
    }));
  }

  function restore() {
    try {
      const s = JSON.parse(sessionStorage.getItem(STORE));
      if (s && s.sid === sid) return { c2s: C.unb64(s.c2s), s2c: C.unb64(s.s2c), token: s.token };
    } catch (_) { /* fall through */ }
    sessionStorage.removeItem(STORE);
    return null;
  }

  async function post(path, body, headers) {
    return fetch(path, {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, headers),
      body: JSON.stringify(body),
    });
  }

  function joinMessageFor(status) {
    if (status === 409) return 'Another device has already joined this session.';
    if (status === 423) return 'Too many wrong codes. Ask for a new code on the host.';
    if (status === 403) return 'Wrong code.';
    return 'Could not join. Try again.';
  }

  async function join() {
    const code = $('code').value.toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (code.length !== 6) {
      $('join-msg').textContent = 'The code has 6 characters.';
      return;
    }
    $('join-btn').disabled = true;
    $('join-msg').textContent = '';
    try {
      const hs = C.joinStart(sid, code);
      const r1 = await post('/api/join', { x: C.b64(hs.X) });
      if (r1.status === 410) return end('The session has ended.');
      if (!r1.ok) { $('join-msg').textContent = joinMessageFor(r1.status); return; }
      const { id, y } = await r1.json();
      const k = hs.finish(C.unb64(y));
      const r2 = await post('/api/confirm', { id, mac: C.b64(k.clientMac) });
      if (r2.status === 410) return end('The session has ended.');
      if (!r2.ok) { $('join-msg').textContent = joinMessageFor(r2.status); $('code').select(); return; }
      const { mac } = await r2.json();
      if (!C.equalBytes(C.unb64(mac), k.hostMac)) {
        $('join-msg').textContent = 'Could not verify the host. Do not use this connection.';
        return;
      }
      keys = { c2s: k.c2s, s2c: k.s2c, token: k.token };
      save();
      startThread();
    } catch (_) {
      $('join-msg').textContent = 'Could not reach the host.';
    } finally {
      $('join-btn').disabled = false;
    }
  }

  function apply(e) {
    if (e.t === 'msg' && !shown.has(e.id)) {
      const node = messageEl(e, msgOpts);
      shown.set(e.id, node);
      $('thread').querySelector('.empty')?.remove();
      $('thread').append(node);
      node.scrollIntoView({ block: 'end' });
    } else if (e.t === 'del') {
      shown.get(e.id)?.remove();
      shown.delete(e.id);
    } else if (e.t === 'end') {
      end(e.body === 'idle' ? 'The session ended after 15 idle minutes.' : 'The session was ended on the host.');
    }
  }

  async function poll() {
    let fails = 0;
    while (!stopped) {
      try {
        const r = await fetch('/api/poll?after=' + cursor, { headers: { 'X-Drop-Token': keys.token } });
        if (stopped) return;
        if (r.status === 401 || r.status === 410) return end('The session has ended.');
        if (!r.ok) throw new Error('poll failed');
        const { box } = await r.json();
        const events = C.open(keys.s2c, 's2c', box);
        fails = 0;
        setStatus('Connected', 'ok');
        for (const e of events) {
          cursor = Math.max(cursor, e.seq);
          apply(e);
          if (stopped) return;
        }
      } catch (_) {
        if (stopped) return;
        fails += 1;
        setStatus('Reconnecting', 'warn');
        if (fails >= 4) return end('Lost contact with the host, so the session was closed here.');
        await sleep(1500);
      }
    }
  }

  async function send() {
    const body = $('text').value;
    if (!body.trim() || !keys) return;
    $('send-msg').textContent = '';
    try {
      const r = await post('/api/send', C.seal(keys.c2s, 'c2s', { body }), { 'X-Drop-Token': keys.token });
      if (r.ok) { $('text').value = ''; return; }
      $('send-msg').textContent =
        r.status === 413 ? 'Too long (64 KB limit).' :
        r.status === 429 ? 'Too many messages; wait a moment.' :
        'Not sent.';
    } catch (_) {
      $('send-msg').textContent = 'Not sent; cannot reach the host.';
    }
  }

  function startThread() {
    show('thread-view');
    setStatus('Connected', 'ok');
    $('thread').replaceChildren(el('p', { className: 'empty', textContent: 'Connected. Messages from the host appear here.' }));
    $('text').focus();
    poll();
  }

  async function init() {
    let hello;
    try {
      hello = await (await fetch('/api/hello')).json();
    } catch (_) {
      return end('Cannot reach the host.');
    }
    sid = hello.sid;
    if (hello.status === 'ended') return end('The session has ended.');
    keys = restore();
    if (keys) return startThread();
    show('join');
    if (hello.status === 'busy') $('join-msg').textContent = joinMessageFor(409);
    if (hello.status === 'locked') $('join-msg').textContent = joinMessageFor(423);
    // A scanned QR carries the code after the #; use it once and drop it
    // from the address bar.
    const frag = location.hash.slice(1);
    if (frag) {
      history.replaceState(null, '', location.pathname);
      $('code').value = frag;
      join();
    }
  }

  $('join-form').addEventListener('submit', (ev) => { ev.preventDefault(); join(); });
  $('compose').addEventListener('submit', (ev) => { ev.preventDefault(); send(); });
  $('text').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); send(); }
  });
  init();
})();
