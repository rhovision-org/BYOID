// rnode choices shared by the BYOID browser app.
//
// The built-in list mirrors r-wallet (rhovision-org/r-wallet):
//   RChain: playground, testnet, history
//   Local: localhost-0 … localhost-4
// Custom nodes are stored only in this browser.

const SELECTED_KEY = 'byoid.rnode.selected.v1';
const CUSTOM_KEY = 'byoid.rnode.custom.v1';

function localNode(index) {
  return {
    id: `local-${index}`,
    group: 'Local',
    network: 'localhost',
    name: `localhost-${index}`,
    url: 'http://localhost',
    port: 40403 + index * 10,
    note: 'A local rnode / rholo node.',
  };
}

export const BUILT_IN_NODES = [
  {
    id: 'rchain-playground',
    group: 'RChain',
    network: 'rhobot',
    name: 'Rholang Playground',
    url: 'https://rnodeapi.rhobot.net',
    note: 'Single-node dev chain that proposes on every deploy. Test data only.',
  },
  {
    id: 'rchain-testnet',
    group: 'RChain',
    network: 'testnet',
    name: 'Rhobot Testnet',
    url: 'https://testnet.rhobot.net',
    note: 'The real Rhobot testnet. Blocks are produced when deploys arrive.',
  },
  {
    id: 'rchain-history',
    group: 'RChain',
    network: 'history',
    name: 'History (REV allocation)',
    url: 'https://history.rhobot.net',
    note: 'Read-only REV allocation snapshot. Deploys and faucet calls are refused.',
    readOnly: true,
  },
  ...Array.from({ length: 5 }, (_, index) => localNode(index)),
];

export const DEFAULT_NODE = BUILT_IN_NODES[0];

export function nodeUrl(node) {
  if (!node || typeof node.url !== 'string') return '';
  let base = node.url.trim().replace(/\/+$/, '');
  const port = node.port === undefined || node.port === null ? '' : String(node.port).trim();
  if (port) base = `${base}:${port}`;
  return base;
}

function isNode(value) {
  return Boolean(
    value &&
      typeof value === 'object' &&
      typeof value.id === 'string' &&
      typeof value.name === 'string' &&
      typeof value.url === 'string',
  );
}

export function loadCustomNodes() {
  try {
    const parsed = JSON.parse(localStorage.getItem(CUSTOM_KEY) || '[]');
    return (Array.isArray(parsed) ? parsed : [])
      .filter(isNode)
      .map((node) => ({ ...node, group: 'Custom', editable: true }));
  } catch {
    return [];
  }
}

export function saveCustomNodes(nodes) {
  try {
    localStorage.setItem(
      CUSTOM_KEY,
      JSON.stringify((nodes || []).filter(isNode).map((node) => ({ ...node, group: 'Custom' }))),
    );
  } catch {
    // Best effort; custom nodes still work for this page life.
  }
}

export function allNodes(customNodes = loadCustomNodes()) {
  return [...BUILT_IN_NODES, ...customNodes];
}

export function findNode(id, customNodes = loadCustomNodes()) {
  return allNodes(customNodes).find((node) => node.id === id) || null;
}

export function loadSelectedNode(customNodes = loadCustomNodes()) {
  try {
    const parsed = JSON.parse(localStorage.getItem(SELECTED_KEY) || 'null');
    if (parsed && typeof parsed.id === 'string') {
      const found = findNode(parsed.id, customNodes);
      if (found) return found;
    }
    if (isNode(parsed)) return parsed;
  } catch {
    // Fall through to the default.
  }
  return DEFAULT_NODE;
}

export function saveSelectedNode(node) {
  try {
    localStorage.setItem(SELECTED_KEY, JSON.stringify(node));
  } catch {
    // Best effort.
  }
}

export function newCustomNode() {
  return {
    id: `custom:${crypto.randomUUID()}`,
    group: 'Custom',
    network: 'custom',
    name: 'New node',
    url: '',
    port: '',
    editable: true,
  };
}

export function validateNodeDraft({ id, name, url, port }) {
  const trimmedName = String(name || '').trim();
  if (!trimmedName) return { ok: false, error: 'A node name is required.' };

  let parsed;
  try {
    parsed = new URL(String(url || '').trim());
  } catch {
    return { ok: false, error: 'Enter a valid http:// or https:// URL.' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, error: 'The node URL must start with http:// or https://.' };
  }

  const portText = String(port || '').trim();
  let portNumber = null;
  if (portText) {
    if (!/^\d+$/.test(portText)) return { ok: false, error: 'Port must be a number from 0 to 65535.' };
    portNumber = Number.parseInt(portText, 10);
    if (!Number.isInteger(portNumber) || portNumber < 0 || portNumber > 65535) {
      return { ok: false, error: 'Port must be a number from 0 to 65535.' };
    }
    if (parsed.port) {
      return { ok: false, error: 'The URL already includes a port; leave the port field blank.' };
    }
    if (parsed.pathname !== '/' && parsed.pathname !== '') {
      return { ok: false, error: 'Put the port in the URL when the node has a path.' };
    }
  }

  return {
    ok: true,
    node: {
      id: id || newCustomNode().id,
      group: 'Custom',
      network: 'custom',
      name: trimmedName,
      url: nodeUrl({ url: parsed.toString(), port: null }),
      port: portNumber,
      editable: true,
    },
  };
}
