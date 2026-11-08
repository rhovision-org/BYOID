import test from 'node:test';
import assert from 'node:assert/strict';

import {
  BUILT_IN_NODES,
  DEFAULT_NODE,
  nodeUrl,
  validateNodeDraft,
} from '../public/nodes.js';

test('built-in rnode choices mirror r-wallet', () => {
  assert.equal(DEFAULT_NODE.id, 'rchain-playground');
  assert.deepEqual(
    BUILT_IN_NODES.filter((node) => node.group === 'RChain').map((node) => node.name),
    ['Rholang Playground', 'Rhobot Testnet', 'History (REV allocation)'],
  );
  assert.equal(BUILT_IN_NODES.filter((node) => node.group === 'Local').length, 5);
  assert.equal(nodeUrl(BUILT_IN_NODES.find((node) => node.id === 'local-2')), 'http://localhost:40423');
});

test('nodeUrl trims trailing slashes and appends a port', () => {
  assert.equal(nodeUrl({ url: 'https://example.com/', port: 4443 }), 'https://example.com:4443');
  assert.equal(nodeUrl({ url: 'https://example.com/base/', port: null }), 'https://example.com/base');
});

test('validateNodeDraft accepts a custom http(s) node', () => {
  const result = validateNodeDraft({
    id: 'custom:test',
    name: 'My node',
    url: 'https://node.example.net',
    port: '40403',
  });
  assert.equal(result.ok, true);
  assert.equal(result.node.id, 'custom:test');
  assert.equal(result.node.name, 'My node');
  assert.equal(nodeUrl(result.node), 'https://node.example.net:40403');
});

test('validateNodeDraft rejects bad URLs and ports', () => {
  assert.equal(
    validateNodeDraft({ name: 'bad', url: 'ftp://example.com', port: '' }).ok,
    false,
  );
  assert.equal(
    validateNodeDraft({ name: 'bad', url: 'https://example.com', port: '70000' }).ok,
    false,
  );
  assert.equal(
    validateNodeDraft({ name: 'bad', url: 'https://example.com:40403', port: '40404' }).ok,
    false,
  );
  assert.equal(
    validateNodeDraft({ name: 'bad', url: 'https://example.com/api', port: '40403' }).ok,
    false,
  );
  assert.equal(validateNodeDraft({ name: '', url: 'https://example.com', port: '' }).ok, false);
});
