// Registry URIs of the BYOID REV proof registry (contracts/rev-proof-registry.rho),
// one per rnode URL. scripts/deploy-rev-registry.js rewrites this file after it
// installs the contract; edit it by hand only to remove a network.
//
// A network with no URI here has no v2 registry yet. The app then writes proof
// cards to their direct name, byoid:rev:<address>, and skips the index.

export const REV_REGISTRY_URIS = {
  "https://playground.rhobot.net": "rho:id:j9w4zceqomwzuf9nafxbqp1yudbc7jpw6orhhxy6gmt7ssamn3eo"
};
