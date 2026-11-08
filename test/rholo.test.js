import test from 'node:test';
import assert from 'node:assert/strict';

import {
  deployerFromPrivateKey,
  encodeDeployData,
  revAddressFromPublicKey,
} from '../src/crypto.js';
import {
  decodeDataValues,
  makeAnchorTerm,
  parseDeployStatus,
  RholoClient,
} from '../src/rholo.js';

const DEVNET_KEY = 'a68a6e6cca30f81bd24a719f3145d20e8424bd7b396309b0708a16c7d8000b76';
const DEVNET_ADDRESS = '11112VYAt8rUGNRRZX3eJdgagaAhtWTK8Js7F7X5iqddMVqyDTtYau';

test('REV address derivation matches the rholo devnet fixture', () => {
  const deployer = deployerFromPrivateKey(DEVNET_KEY);
  assert.equal(deployer.address, DEVNET_ADDRESS);
  assert.equal(deployer.publicKeyHex.length, 130);
  assert.equal(deployer.publicKeyHex.slice(0, 2), '04');
  assert.equal(revAddressFromPublicKey(Buffer.from(deployer.publicKeyHex, 'hex')), DEVNET_ADDRESS);
});

test('DeployDataProto encoding is the deterministic protobuf byte sequence', () => {
  const encoded = encodeDeployData({
    term: '1+1',
    timestamp: 1,
    phloPrice: 1,
    phloLimit: 2,
    validAfterBlockNumber: 0,
    shardId: '/root',
  });
  assert.equal(
    Buffer.from(encoded).toString('hex'),
    '1203312b3118013801400250005a052f726f6f74',
  );
});

test('makeAnchorTerm emits a safe public-name send', () => {
  assert.equal(makeAnchorTerm('byoid:did:zabc', 'aGVsbG8'), '@"byoid:did:zabc"!("aGVsbG8")');
  assert.throws(() => makeAnchorTerm('bad name', 'aGVsbG8'), /invalid anchor name/);
  assert.throws(() => makeAnchorTerm('byoid:did:zabc', 'not/base64'), /invalid anchor value/);
});

test('decodeDataValues unwraps ExprString and ExprBytes', () => {
  assert.deepEqual(
    decodeDataValues([
      { ExprString: { data: 'hello' } },
      { ExprBytes: { data: Buffer.from('world').toString('hex') } },
      { ExprInt: { data: 1 } },
    ]),
    ['hello', 'world'],
  );
});

test('parseDeployStatus understands every tag on the evidence ladder', () => {
  assert.equal(parseDeployStatus({ NotProcessed: { status: 'in pool' } }).state, 'pending');
  const success = parseDeployStatus({
    ProcessedWithSuccess: { deployResult: [], block: { blockNumber: 7 } },
  });
  assert.equal(success.state, 'success');
  assert.equal(success.block.blockNumber, 7);
  const failure = parseDeployStatus({ ProcessedWithError: { deployError: 'boom' } });
  assert.equal(failure.state, 'error');
  assert.equal(failure.error, 'boom');
});

test('RholoClient climbs the evidence ladder and observes the anchor', async () => {
  const deployer = deployerFromPrivateKey(DEVNET_KEY);
  const faucetDeployId = 'cd'.repeat(70);
  const anchorDeployId = 'ab'.repeat(70);
  const block = {
    blockHash: '11'.repeat(32),
    blockNumber: 11,
    preStateHash: '22'.repeat(32),
    postStateHash: '33'.repeat(32),
  };
  const value = Buffer.from('hello').toString('base64url');
  let deployed = false;
  const calls = [];

  const mockFetch = async (url, init = {}) => {
    const path = new URL(url).pathname;
    calls.push(path);
    const json = (body, status = 200) =>
      new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
    if (path === '/api/v1/status') {
      return json({
        networkId: 'playground',
        shardId: '/playground',
        latestBlockNumber: 10,
        autopropose: false,
        proposeOnDeploy: true,
        devMode: true,
      });
    }
    if (path === '/api/v1/faucet') {
      return json({ deployId: faucetDeployId, status: 'pending' });
    }
    if (path === `/api/v1/deploy-status/${faucetDeployId}`) {
      return json({
        ProcessedWithSuccess: {
          deployResult: [],
          block: { blockHash: '44'.repeat(32), blockNumber: 9 },
        },
      });
    }
    if (path === '/api/v1/deploy') {
      deployed = true;
      const body = JSON.parse(init.body);
      assert.equal(body.data.shardId, '/playground');
      assert.equal(body.sigAlgorithm, 'secp256k1');
      assert.equal(body.signature.length > 100, true);
      return new Response(JSON.stringify(`Success!\nDeployId is: ${anchorDeployId}`), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (path === `/api/v1/deploy-status/${anchorDeployId}`) {
      return json({ ProcessedWithSuccess: { deployResult: [], block } });
    }
    if (path === '/api/v1/data-at-name-by-block-hash') {
      const body = JSON.parse(init.body);
      assert.equal(body.name.ExprString.data, 'byoid:did:test');
      assert.equal(body.blockHash, block.blockHash);
      return json({ expr: [{ ExprString: { data: value } }], block });
    }
    return json({ error: 'unexpected path' }, 500);
  };

  const client = new RholoClient({
    url: 'https://playground.invalid',
    deployerKey: deployer,
    needsFaucet: true,
    faucet: true,
    fetchImpl: mockFetch,
    logger: { info: () => {}, warn: () => {} },
  });

  const progress = [];
  const receipt = await client.anchorValue('byoid:did:test', value, {
    onProgress: (event) => progress.push(event.step),
  });
  assert.equal(deployed, true);
  assert.equal(receipt.visible, true);
  assert.equal(receipt.blockNumber, 11);
  assert.equal(receipt.deployId, anchorDeployId);
  assert.deepEqual(progress, ['submitting', 'submitted', 'executed', 'included', 'observed']);
  assert.equal(calls.includes('/api/v1/faucet'), true);
});

test('RholoClient surface errors retain their code and status', async () => {
  const deployer = deployerFromPrivateKey(DEVNET_KEY);
  const client = new RholoClient({
    url: 'https://playground.invalid',
    deployerKey: deployer,
    needsFaucet: false,
    faucet: true,
    fetchImpl: async () =>
      new Response(JSON.stringify({ error: 'down' }), {
        status: 503,
        headers: { 'content-type': 'application/json' },
      }),
    logger: { info: () => {}, warn: () => {} },
  });
  await assert.rejects(client.getStatus(), (error) => {
    assert.equal(error.code, 'http');
    assert.equal(error.status, 503);
    assert.equal(error.retryable, true);
    return true;
  });
});
