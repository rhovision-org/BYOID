// OAuth 2.0 / OIDC adapters for the BYOID POC.
//
// The provider catalog itself lives in public/provider-catalog.js so the same
// metadata can power both this server and the browser-only GitHub Pages demo.
// Each provider has a live mode (client id/secret, or Apple's Services ID +
// signing key) and a demo mode (a clearly-labelled local simulation) so the POC
// is usable with zero credentials.

import { createPrivateKey, sign as nodeSign } from 'node:crypto';
import { PROVIDER_CATALOG, PROVIDER_IDS } from '../public/provider-catalog.js';
import { base64url, unb64url, utf8, verifyEs256 } from './crypto.js';

export { PROVIDER_CATALOG, PROVIDER_IDS };

const USER_AGENT = 'BYOID-POC/0.1 (+https://github.com/rhovision-org/BYOID)';
let appleJwksCache = { at: 0, keys: [] };

/** Public provider metadata for the browser (never contains a client secret). */
export function publicProviderInfo(provider, configured, mode, redirectUri) {
  const extraEnv = Object.entries(provider.env)
    .filter(([key]) => key !== 'clientId' && key !== 'clientSecret')
    .map(([, value]) => value);
  return {
    id: provider.id,
    name: provider.name,
    kind: provider.kind,
    description: provider.description,
    scopes: provider.scopes,
    docsUrl: provider.docsUrl,
    configure: {
      clientIdEnv: provider.env.clientId,
      clientSecretEnv: provider.env.clientSecret,
      extraEnv,
      redirectUri,
    },
    mode,
    configured,
    demoProfiles: provider.demoProfiles.map((p) => ({
      id: p.id,
      label: p.label,
      handle: p.handle,
      email: p.email,
    })),
  };
}

export function getProvider(providerId) {
  const provider = PROVIDER_CATALOG[providerId];
  if (!provider) throw new Error(`Unknown identity provider: ${providerId}`);
  return provider;
}

/** Build the authorization-code URL for a provider. */
export function buildAuthorizationUrl(
  provider,
  cfg,
  { state, codeChallenge, redirectUri, nonce },
) {
  const url = new URL(provider.authorizeUrl);
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', provider.scopes.join(' '));
  url.searchParams.set('state', state);
  if (provider.pkce && codeChallenge) {
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
  }
  if (provider.id === 'apple') {
    url.searchParams.set('response_mode', provider.responseMode || 'form_post');
    if (nonce) url.searchParams.set('nonce', nonce);
  }
  if (provider.id === 'google') {
    url.searchParams.set('access_type', 'online');
    url.searchParams.set('prompt', 'select_account');
  }
  return url.toString();
}

async function readJsonResponse(res, label) {
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`${label} returned a non-JSON response (HTTP ${res.status})`);
  }
  if (!res.ok) {
    const detail = body.error_description || body.error?.message || body.error || text.slice(0, 300);
    throw new Error(`${label} failed (HTTP ${res.status}): ${detail}`);
  }
  return body;
}

/** Generate the short-lived JWT Apple requires as its OAuth client secret. */
export function appleClientSecret(provider, cfg, { now = Math.floor(Date.now() / 1000) } = {}) {
  if (cfg.clientSecret) return cfg.clientSecret;
  if (!cfg.applePrivateKey || !cfg.appleTeamId || !cfg.appleKeyId) {
    throw new Error(
      'Apple needs APPLE_CLIENT_SECRET, or APPLE_TEAM_ID + APPLE_KEY_ID + APPLE_PRIVATE_KEY.',
    );
  }
  const header = { alg: 'ES256', kid: cfg.appleKeyId };
  const payload = {
    iss: cfg.appleTeamId,
    iat: now,
    exp: now + 150 * 24 * 60 * 60,
    aud: provider.issuer || 'https://appleid.apple.com',
    sub: cfg.clientId,
  };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const keyText = String(cfg.applePrivateKey).replaceAll('\\n', '\n');
  const key = createPrivateKey(keyText);
  const signature = nodeSign('sha256', Buffer.from(signingInput), {
    key,
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${signature.toString('base64url')}`;
}

/** Exchange an authorization code for tokens. Never returns tokens to the browser. */
export async function exchangeCode(provider, cfg, { code, codeVerifier, redirectUri, fetchImpl = fetch }) {
  const clientSecret =
    provider.id === 'apple' ? appleClientSecret(provider, cfg) : cfg.clientSecret;
  const body = new URLSearchParams({
    code,
    client_id: cfg.clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
  });
  if (provider.pkce && codeVerifier) body.set('code_verifier', codeVerifier);

  const headers = {
    'content-type': 'application/x-www-form-urlencoded',
    accept: 'application/json',
    'user-agent': USER_AGENT,
  };
  const res = await fetchImpl(provider.tokenUrl, { method: 'POST', headers, body });
  return readJsonResponse(res, `${provider.name} token exchange`);
}

/** Verify a Sign in with Apple identity token with Apple's rotating JWKS. */
export async function verifyAppleIdToken(
  idToken,
  { clientId, nonce, fetchImpl = fetch, now = Math.floor(Date.now() / 1000) } = {},
) {
  const parts = String(idToken || '').split('.');
  if (parts.length !== 3) throw new Error('Apple returned an invalid identity token');
  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    throw new Error('Apple identity token is not valid base64url JSON');
  }
  if (header.alg !== 'ES256' || !header.kid) {
    throw new Error('Apple identity token uses an unexpected signing algorithm');
  }

  if (!appleJwksCache.keys.length || Date.now() - appleJwksCache.at > 60 * 60 * 1000) {
    const response = await fetchImpl('https://appleid.apple.com/auth/keys');
    const body = await readJsonResponse(response, 'Apple JWKS');
    appleJwksCache = {
      at: Date.now(),
      keys: Array.isArray(body.keys) ? body.keys : [],
    };
  }
  const jwk = appleJwksCache.keys.find((candidate) => candidate.kid === header.kid);
  if (!jwk) throw new Error('Apple identity token names an unknown signing key');
  const publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const signatureOk = await verifyEs256(
    publicJwk,
    utf8(`${parts[0]}.${parts[1]}`),
    unb64url(parts[2]),
  );
  if (!signatureOk) throw new Error('Apple identity token signature does not verify');
  if (payload.iss !== 'https://appleid.apple.com') {
    throw new Error('Apple identity token has the wrong issuer');
  }
  const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audience.includes(clientId)) {
    throw new Error('Apple identity token has the wrong audience');
  }
  if (!Number.isFinite(payload.exp) || payload.exp <= now) {
    throw new Error('Apple identity token has expired');
  }
  if (nonce && payload.nonce !== nonce) {
    throw new Error('Apple identity token nonce did not match');
  }
  return payload;
}

/** Fetch and normalize a provider profile. Only normalized fields leave this module. */
export async function fetchProfile(provider, tokens, { fetchImpl = fetch } = {}) {
  if (provider.id === 'apple') {
    if (!tokens.id_token) throw new Error('Apple did not return an identity token');
    const claims = await verifyAppleIdToken(tokens.id_token, {
      clientId: tokens.clientId,
      nonce: tokens.nonce,
      fetchImpl,
    });
    let user = null;
    if (tokens.user) {
      try {
        user = typeof tokens.user === 'string' ? JSON.parse(tokens.user) : tokens.user;
      } catch {
        user = null;
      }
    }
    const name = [user?.name?.firstName, user?.name?.lastName].filter(Boolean).join(' ').trim();
    const email = claims.email || user?.email || null;
    const handle = email
      ? String(email).split('@')[0]
      : name
        ? name.toLowerCase().replace(/\s+/g, '.')
        : `apple-${String(claims.sub).slice(0, 8)}`;
    return {
      provider: 'apple',
      subject: String(claims.sub),
      handle,
      name,
      email,
      emailVerified: claims.email_verified === true || claims.email_verified === 'true',
      avatarUrl: null,
    };
  }

  const accessToken = tokens.access_token;
  if (!accessToken) throw new Error(`${provider.name} did not return an access token`);

  const headers = {
    authorization: `Bearer ${accessToken}`,
    accept: 'application/json',
    'user-agent': USER_AGENT,
  };

  if (provider.id === 'google') {
    const res = await fetchImpl(provider.userinfoUrl, { headers });
    const json = await readJsonResponse(res, 'Google userinfo');
    if (!json.sub) throw new Error('Google userinfo did not contain a subject');
    return {
      provider: 'google',
      subject: String(json.sub),
      handle: json.email ? String(json.email).split('@')[0] : String(json.name || 'google-user'),
      name: json.name || '',
      email: json.email || null,
      emailVerified: json.email_verified === true,
      avatarUrl: json.picture || null,
    };
  }

  if (provider.id === 'github') {
    const userRes = await fetchImpl(provider.userinfoUrl, { headers });
    const user = await readJsonResponse(userRes, 'GitHub user');
    let email = user.email || null;
    let emailVerified = false;
    try {
      const emailsRes = await fetchImpl(provider.emailsUrl, { headers });
      const emails = await readJsonResponse(emailsRes, 'GitHub emails');
      const primary = Array.isArray(emails)
        ? emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified)
        : null;
      if (primary) {
        email = primary.email;
        emailVerified = true;
      }
    } catch {
      // The profile is still useful without the email scope; keep the public email.
    }
    return {
      provider: 'github',
      subject: String(user.id),
      handle: user.login || `github-${user.id}`,
      name: user.name || user.login || '',
      email,
      emailVerified,
      avatarUrl: user.avatar_url || null,
    };
  }

  if (provider.id === 'facebook') {
    const res = await fetchImpl(provider.userinfoUrl, { headers });
    const json = await readJsonResponse(res, 'Facebook profile');
    if (!json.id) throw new Error('Facebook profile did not contain an id');
    return {
      provider: 'facebook',
      subject: String(json.id),
      handle: json.name || `facebook-${json.id}`,
      name: json.name || '',
      email: json.email || null,
      // The Graph API does not assert that an email is verified, so we do not claim it.
      emailVerified: false,
      avatarUrl: json.picture?.data?.url || null,
    };
  }

  throw new Error(`No profile adapter for ${provider.id}`);
}

/** Look up a demo profile by id. */
export function demoProfile(providerId, profileId) {
  const provider = getProvider(providerId);
  const profile = provider.demoProfiles.find((p) => p.id === profileId);
  if (!profile) throw new Error('Unknown demo profile');
  return {
    provider: provider.id,
    subject: profile.subject,
    handle: profile.handle,
    name: profile.name,
    email: profile.email,
    emailVerified: profile.emailVerified,
    avatarUrl: profile.avatarUrl,
    demo: true,
  };
}
