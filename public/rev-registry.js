// Rholang programs for the BYOID REV proof registry, version 2
// (contracts/rev-proof-registry.rho).
//
// The registry is reached by its rho:registry URI, never a public string name,
// and a publish must be deployed by the key that owns the REV address: the
// contract derives the caller's address from rho:rchain:deployerId and refuses
// any other address. Answers go to a channel the program creates with `new`
// and are forwarded to the deploy's rho:rchain:deployId.

import { isRevAddress, revAnchorName } from './shared.js';
import { REV_REGISTRY_URIS } from './rev-registry-uris.js';

const URI_RE = /^rho:id:[a-z0-9]{20,80}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
export const MAX_CARD_CHARS = 19_000;

/** The registry URI for a node URL, or null when none is installed there. */
export function registryUriFor(nodeUrl, uris = REV_REGISTRY_URIS) {
  const key = String(nodeUrl || '').trim().replace(/\/+$/, '');
  const uri = uris[key];
  return typeof uri === 'string' && URI_RE.test(uri) ? uri : null;
}

function checkUri(uri) {
  if (!URI_RE.test(String(uri || ''))) throw new Error('invalid registry URI');
  return uri;
}

function checkAddress(address) {
  if (!isRevAddress(address)) throw new Error('invalid REV address');
  return String(address).trim();
}

function checkCardValue(value) {
  const text = String(value || '');
  if (!B64URL_RE.test(text)) throw new Error('card value must be base64url');
  if (text.length > MAX_CARD_CHARS) throw new Error('proof card is too large');
  return text;
}

// rholo answers a lookup of an insertArbitrary value with the bare value; the
// Scala node wraps it in a tuple. Accept both (rgov-core measured this).
const unwrapLookup = 'match record { (_, c) => { capsCh!(c) } c => { capsCh!(c) } }';

function callProgram(uri, facet, call, { signed }) {
  const missing = `{"ok": false, "error": "no BYOID registry at ${uri}"}`;
  const names = signed
    ? 'lookup(`rho:registry:lookup`), deployerId(`rho:rchain:deployerId`), deployId(`rho:rchain:deployId`), stored, ret'
    : 'lookup(`rho:registry:lookup`), deployId(`rho:rchain:deployId`), stored, ret';
  return `new ${names} in {
  lookup!(\`${uri}\`, *stored) |
  for (@record <- stored) {
    new capsCh in {
      ${unwrapLookup} |
      for (@caps <- capsCh) {
        match caps {
          {"${facet}": found, ..._} => {
            ${call} |
            for (@answer <- ret) { deployId!(answer) }
          }
          _ => { deployId!(${missing}) }
        }
      }
    }
  }
}`;
}

/**
 * A publish deploy. It must be signed by the REV key for `address`. It also
 * writes the card to the direct name byoid:rev:<address>, which readers use
 * without a deploy; both go in one block.
 */
export function publishProgram(uri, address, value) {
  checkUri(uri);
  const addr = checkAddress(address);
  const card = checkCardValue(value);
  const publish = callProgram(
    uri,
    'publish',
    `@found!(*deployerId, ["${addr}", "${card}"], *ret)`,
    { signed: true },
  );
  return `@"${revAnchorName(addr)}"!("${card}") |\n${publish}`;
}

/** A read deploy for the stored card of `address`. */
export function readProgram(uri, address) {
  checkUri(uri);
  const addr = checkAddress(address);
  return callProgram(uri, 'read', `@found!(["${addr}"], *ret)`, { signed: false });
}

function strings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((item) => strings(item, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((item) => strings(item, out));
  return out;
}

/** The registry URI an install deploy answered, or null. */
export function installedUri(deployResult) {
  for (const text of strings(deployResult)) {
    const match = text.match(/rho:id:[a-z0-9]{20,80}/);
    if (match) return match[0];
  }
  return null;
}

// The refusals the contract and the call programs can answer.
const REFUSALS = [
  'only the key that owns this REV address may publish its card',
  'address must be',
  'address and card must be strings',
  'publish takes',
  'read takes',
  'no BYOID registry at',
];

/** The refusal in a call's deploy result, or null when it was accepted. */
export function registryRefusal(deployResult) {
  return strings(deployResult).find((text) => REFUSALS.some((prefix) => text.startsWith(prefix))) || null;
}
