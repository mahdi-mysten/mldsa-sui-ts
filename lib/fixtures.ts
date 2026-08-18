// Interop fixtures shared with the Rust implementation.
//
// TRIPLES are the exact values pinned by `test_mnemonics_mldsa65` in
// sui/crates/sui/src/unit_tests/keytool_tests.rs. INTERMEDIATES are the stage
// outputs dumped from the Rust derivation for the first mnemonic; they exist
// so a mismatch can be localized to one stage (BIP-39, salt, HKDF) rather
// than just "the addresses differ".
//
// Changing any value here is wallet-breaking derivation drift, not a test to
// update. Both sides must move together.

export type Triple = { mnemonic: string; suiPrivkey: string; address: string }

export const TRIPLES: Triple[] = [
  {
    mnemonic: 'act wing dilemma glory episode region allow mad tourist humble muffin oblige',
    suiPrivkey: 'suiprivkey1qah96ucnaywtjzymj4pkckev7dg5wvcfycvrj922wvr3pp28tt9m795esdx',
    address: '0x3e1f67390afc595591a5caf7af6dc47175fd8356d53f889cb6c4c74488c4dced',
  },
  {
    mnemonic: 'flag rebel cabbage captain minimum purpose long already valley horn enrich salt',
    suiPrivkey: 'suiprivkey1qluasgyaufa87p6da96e7pxqfyk2vnk8ft2fzq547z6fhu2a3x7m5ry4027',
    address: '0x090eb2772d62dddc25875890af599edd856a771b791827563418d8a691b7b596',
  },
  {
    mnemonic: 'area renew bar language pudding trial small host remind supreme cabbage era',
    suiPrivkey: 'suiprivkey1qu8ydhmx70q3tfgnq5mqe0ssl6m60w2q32m570zktxsqf3q24fakqlf0q9l',
    address: '0x399f7c5a82969ec23a92862792ca18ea34cf515888fa95d7751927bde39cc2f3',
  },
]

/// Stage outputs from Rust for TRIPLES[0], at the default path.
export const INTERMEDIATES = {
  bip39Seed:
    '37def74b498b96684ba3d628314a0ba03e7df29abce1b39c0dd82322f8959f2c' +
    '498cd8bacedfb3ff18e83c460b699723fe12a3a171faa5b98321ce7caaf0c690',
  salt: "m/94'/784'/0'/0'/0'",
  info: 'mldsa65-keygen-v1',
  keygenSeed: '6e5d7313e91cb9089b95436c5b2cf351473309261839154a73071085475acbbf',
}

