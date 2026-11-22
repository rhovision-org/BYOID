import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import {
  installedUri,
  publishProgram,
  readProgram,
  registryRefusal,
  registryUriFor,
} from '../public/rev-registry.js';

const URI = 'rho:id:abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr';
const ADDRESS = '11112VYAt8rUGNRRZX3eJdgagaAhtWTK8Js7F7X5iqddMVqyDTtYau';
const CONTRACT = fs.readFileSync(new URL('../contracts/rev-proof-registry.rho', import.meta.url), 'utf8');
// The contract minus comments, so prose about v1 does not count as code.
const CODE = CONTRACT.split('\n').filter((line) => !line.trim().startsWith('//')).join('\n');

test('the v2 contract has no public listener and registers by URI', () => {
  assert.doesNotMatch(CODE, /@"byoid:rev:registry"/);
  assert.match(CODE, /insertArbitrary!\(\{"publish": bundle\+\{\*publishFacet\}, "read": bundle\+\{\*readFacet\}\}/);
  assert.match(CODE, /deployId!\(\["installed", "byoid-rev-registry", 2, uri\]\)/);
});

test('publish derives the caller from deployerId and compares it to the address', () => {
  assert.match(CODE, /contract publishFacet\(_id, @args, ret\)/);
  assert.match(CODE, /revAddr!\("fromDeployerId", \*_id, \*a\)/);
  assert.match(CODE, /match me == address/);
  // The state cell is consumed and restored, never written beside itself.
  assert.match(CODE, /for \(@store <- state\) \{\s*state!\(store\.set\(address, card\)\)/);
});

test('every contract answer is one the client recognises', () => {
  const errors = [...CODE.matchAll(/"error": "([^"]+)"/g)].map((match) => match[1]);
  assert.ok(errors.length >= 4);
  for (const error of errors) {
    assert.equal(registryRefusal([{ ExprString: { data: error } }]), error);
  }
  assert.equal(registryRefusal([{ ExprMap: { data: { ok: { ExprBool: { data: true } } } } }]), null);
});

test('publishProgram signs through deployerId, writes the direct name, answers on deployId', () => {
  const program = publishProgram(URI, ADDRESS, 'eyJ2IjoxfQ');
  assert.match(program, new RegExp(`^@"byoid:rev:${ADDRESS}"!\\("eyJ2IjoxfQ"\\)`));
  assert.match(program, /deployerId\(`rho:rchain:deployerId`\)/);
  assert.match(program, new RegExp(`lookup!\\(\`${URI}\`, \\*stored\\)`));
  assert.match(program, new RegExp(`@found!\\(\\*deployerId, \\["${ADDRESS}", "eyJ2IjoxfQ"\\], \\*ret\\)`));
  assert.match(program, /for \(@answer <- ret\) \{ deployId!\(answer\) \}/);
});

test('readProgram needs no deployer', () => {
  const program = readProgram(URI, ADDRESS);
  assert.doesNotMatch(program, /deployerId/);
  assert.match(program, new RegExp(`@found!\\(\\["${ADDRESS}"\\], \\*ret\\)`));
});

test('program builders refuse input that could escape the Rholang string', () => {
  assert.throws(() => publishProgram(URI, `${ADDRESS}") | evil!("`, 'eyJ2IjoxfQ'), /REV address/);
  assert.throws(() => publishProgram(URI, ADDRESS, 'abc") | evil!("x'), /base64url/);
  assert.throws(() => publishProgram('rho:id:x`) | evil', ADDRESS, 'abc'), /registry URI/);
  assert.throws(() => publishProgram(URI, ADDRESS, 'a'.repeat(19_001)), /too large/);
});

test('registry URIs are looked up per node and validated', () => {
  const uris = { 'https://playground.rhobot.net': URI, 'https://bad.example': 'rho:id:`x' };
  assert.equal(registryUriFor('https://playground.rhobot.net/', uris), URI);
  assert.equal(registryUriFor('https://bad.example', uris), null);
  assert.equal(registryUriFor('https://testnet.rhobot.net', uris), null);
});

test('installedUri finds the URI in an install deploy result', () => {
  const result = [{ ExprList: { data: [{ ExprString: { data: 'installed' } }, { ExprUri: { data: URI } }] } }];
  assert.equal(installedUri(result), URI);
  assert.equal(installedUri([]), null);
});
