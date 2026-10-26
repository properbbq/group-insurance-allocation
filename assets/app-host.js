// The app page: opens the encrypted app with the signed-in session and runs it here. The app
// finds the workbook template in globalThis.giaHost. "Change password" is password.html.

import { $, el, loadSession, clearSession, openSession } from './common.js?v=d21e555d9b2d';

const session = loadSession();

function notice(tone, ...content) {
  const box = el('div', { class: `notice notice-${tone}` }, el('div', { class: 'notice-text' }, ...content));
  $('#notices').append(box);
  return box;
}

// The app's page, built from the tree tools/gia_build.py made of site/index.html (so it needs
// no innerHTML).
const SVG = 'http://www.w3.org/2000/svg';
function build(node, inSvg = false) {
  if (typeof node === 'string') return document.createTextNode(node);
  const [tag, attributes, ...children] = node;
  const svg = inSvg || tag === 'svg';
  const element = svg ? document.createElementNS(SVG, tag) : document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) element.setAttribute(name, value);
  for (const child of children) element.append(build(child, svg));
  return element;
}

// The app's modules, each from a blob: address, with every import pointed at the module it names.
async function runModules(modules, entry) {
  const urls = new Map();
  const loading = new Set();
  const load = (name) => {
    if (urls.has(name)) return urls.get(name);
    if (loading.has(name) || !Object.hasOwn(modules, name)) throw new Error(`the app is incomplete (${name})`);
    loading.add(name);
    const code = modules[name].replace(/from '\.\/([\w-]+\.js)'/g, (match, dependency) => `from '${load(dependency)}'`);
    const url = URL.createObjectURL(new Blob([code], { type: 'text/javascript' }));
    urls.set(name, url);
    return url;
  };
  await import(load(entry));
}

async function start() {
  let opened;
  try {
    opened = await openSession(session);
  } catch (error) {
    if (error.code === 'signin') {
      clearSession();
      location.replace(`index.html?why=${error.reason || 'again'}`);
      return;
    }
    $('#app').replaceChildren(el('div', { class: 'page' }, el('div', { class: 'notice notice-error' },
      el('div', { class: 'notice-text' }, error.message),
      el('button', { class: 'btn btn-sm', type: 'button', onclick: () => location.reload() }, 'Try again'))));
    return;
  }
  const { profile, app } = opened;
  $('#user-name').textContent = profile.name;
  $('#user').hidden = false;
  if (profile.first) {
    notice('warn', el('strong', {}, 'Choose your own password. '),
      'You’re still using the one you were given, which others could guess. ',
      el('a', { class: 'btn btn-sm btn-primary', href: 'password.html' }, 'Change password'));
  }
  globalThis.giaHost = { template: app.template };
  $('#app').replaceChildren(build(app.markup));
  try {
    await runModules(app.modules, app.entry);
  } catch (error) {
    notice('error', `The app couldn’t start (${error.message}). Try reloading the page.`);
  }
}

if (!session) location.replace('index.html');
else start();
