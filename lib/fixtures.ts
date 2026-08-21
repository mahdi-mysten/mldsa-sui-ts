// Interop fixtures shared with the Rust implementation.
//
// TRIPLES are the exact values pinned by `test_mnemonics_mldsa65` in
// sui/crates/sui/src/unit_tests/keytool_tests.rs. INTERMEDIATES are the stage
// outputs dumped from the Rust derivation for the first mnemonic; they exist
// so a mismatch can be localized to one stage (BIP-39, the SLIP-10 walk) rather
// than just "the addresses differ".
//
// Changing any value here is wallet-breaking derivation drift, not a test to
// update. Both sides must move together.

export type Triple = { mnemonic: string; suiPrivkey: string; address: string }

export const TRIPLES: Triple[] = [
  {
    mnemonic: 'act wing dilemma glory episode region allow mad tourist humble muffin oblige',
    suiPrivkey: 'suiprivkey1qamkapjn935cx32r206gvzh9u0cscydaf09we9z4uxc9crs5j3c82q5m0tk',
    address: '0xd0f33625a23608ac4f3fd938a461ab15ed688af783eb4c54c19ab68e37a420dd',
  },
  {
    mnemonic: 'flag rebel cabbage captain minimum purpose long already valley horn enrich salt',
    suiPrivkey: 'suiprivkey1ql7gkea080ddh5f3gae0lnfw6t7vhcylupgucp7rcpwnnyhdegax6hx9cww',
    address: '0xd6de2b6e6d68114bbb6c4bbe3af4f174dcf51b27e5393b7606203cda8c933a93',
  },
  {
    mnemonic: 'area renew bar language pudding trial small host remind supreme cabbage era',
    suiPrivkey: 'suiprivkey1q7xkhwyu7a60pjrevj9gatlk3ju3x8svkx5gcgy6zdznafwvxp54swwyjt4',
    address: '0x48e9fcc44df5766d6be8e824c2781c40dd196f6a6b2e7244b78b02ab05249d66',
  },
]

/// Stage outputs from Rust for TRIPLES[0], at the default path.
export const INTERMEDIATES = {
  bip39Seed:
    '37def74b498b96684ba3d628314a0ba03e7df29abce1b39c0dd82322f8959f2c' +
    '498cd8bacedfb3ff18e83c460b699723fe12a3a171faa5b98321ce7caaf0c690',
  slip10Key: 'ML-DSA-65 seed',
  keygenSeed: '776e86532c6983454353f4860ae5e3f10c11bd4bcaec9455e1b05c0e14947075',
}

