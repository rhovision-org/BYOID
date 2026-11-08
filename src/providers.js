// OAuth 2.0 / OIDC adapters for the BYOID POC.
//
// The provider catalog itself lives in public/provider-catalog.js so the same
// metadata can power both this server and the browser-only GitHub Pages demo.
// Each provider has a live mode (when a client id/secret pair is configured)
// and a demo mode (a clearly-labelled local simulation) so the POC is usable
// with zero credentials.

import { PROVIDER_CATALOG, PROVIDER_IDS } from '../public/provider-catalog.js';

export { PROVIDER_CATALOG, PROVIDER_IDS };

const USER_AGENT = 'BYOID-POC/0.1 (+https://github.com/rhovision-org/BYOID)';

/** Public provider metadata for the browser (never contains a client secret). */
export function publicProviderInfo(provider, configured, mode, redirectUri) {
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
export function buildAuthorizationUrl(provider, cfg, { state, codeChallenge, redirectUri }) {
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

/** Exchange an authorization code for tokens. Never returns tokens to the browser. */
export async function exchangeCode(provider, cfg, { code, codeVerifier, redirectUri, fetchImpl = fetch }) {
  const body = new URLSearchParams({
    code,
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
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

/** Fetch and normalize a provider profile. Only normalized fields leave this module. */
export async function fetchProfile(provider, tokens, { fetchImpl = fetch } = {}) {
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
