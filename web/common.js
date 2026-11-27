// Shared by the admin page and the guest page.
'use strict';

const $ = (id) => document.getElementById(id);

function el(tag, props, ...children) {
  const node = document.createElement(tag);
  Object.assign(node, props || {});
  node.append(...children);
  return node;
}

// navigator.clipboard needs HTTPS, which LAN mode does not have, so fall back
// to the old selection-based copy there.
async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  const ta = el('textarea', { value: text });
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.append(ta);
  ta.select();
  try { document.execCommand('copy'); } finally { ta.remove(); }
}

function flash(button, text) {
  const old = button.textContent;
  button.textContent = text;
  setTimeout(() => { button.textContent = old; }, 1200);
}

// A button that only acts on a second click within three seconds.
function confirmButton(label, action) {
  const b = el('button', { className: 'small', textContent: label, type: 'button' });
  let armed = null;
  b.addEventListener('click', (ev) => {
    ev.stopPropagation();
    const disarm = () => {
      clearTimeout(armed);
      armed = null;
      b.textContent = label;
      b.classList.remove('danger');
    };
    if (armed) {
      disarm();
      action();
      return;
    }
    b.textContent = 'Really delete?';
    b.classList.add('danger');
    armed = setTimeout(disarm, 3000);
  });
  return b;
}

// Message text is only ever set as textContent, never parsed as HTML.
function messageEl(m, opts) {
  const mine = m.dir === opts.mineDir;
  const copy = el('button', { className: 'small', textContent: 'Copy', type: 'button' });
  copy.addEventListener('click', async () => { await copyText(m.body); flash(copy, 'Copied'); });
  const tools = el('span', { className: 'tools' }, copy);
  if (opts.onDelete) tools.append(confirmButton('Delete', () => opts.onDelete(m)));
  const when = new Date(m.ts);
  return el('div', { className: 'msg' + (mine ? ' mine' : '') },
    el('div', { className: 'meta' },
      el('span', { className: 'who', textContent: mine ? opts.mineLabel : opts.theirLabel }),
      el('span', { textContent: opts.fullDate ? when.toLocaleString() : when.toLocaleTimeString() }),
      tools),
    el('pre', { textContent: m.body }));
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
