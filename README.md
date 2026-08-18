# ML-DSA-65 Sui Accounts

A browser demo of post-quantum Sui accounts. Paste a BIP-39 mnemonic, derive an
ML-DSA-65 (FIPS 204) keypair and Sui address, sign a transaction digest, verify
it. Everything runs client-side, and each operation reports how long it took.

It exists to give the wallet team something runnable, and to pin the derivation
contract that a real `@mysten/sui` keypair class has to implement.

```bash
npm install
npm run dev      # http://localhost:3000
npm run interop  # CI gate: fails if TS and Rust would derive different keys
```

## The derivation contract

Mirrors `crates/sui-keys/src/key_derive.rs` (the `SignatureScheme::MLDSA65`
arm) in the Sui repo. All of it has to match, or the same mnemonic yields an
address the user cannot spend from.

| Stage | Value |
|---|---|
| flag | `0x07` |
| path | `m/94'/784'/account'/change'/address'`, every level hardened |
| BIP-39 seed | `mnemonicToSeedSync(mnemonic, '')`, **64 bytes**, passed to HKDF whole |
| HKDF | `hkdf(sha3_256, ikm = bip39Seed, salt = path string, info = "mldsa65-keygen-v1", 32)` |
| keygen | `ml_dsa65.keygen(seed32)`, where the HKDF output is the FIPS 204 seed |
| address | `blake2b256(0x07 \|\| pk)`, first 32 bytes |
| private key | `bech32("suiprivkey", 0x07 \|\| seed32)`, 33 bytes, about 70 chars |
| envelope | `0x07 \|\| sig \|\| pk` = 1 + 3309 + 1952 = **5262 bytes** |

Three details are easy to get wrong, and each one produces keys that look
valid but are not:

1. **Do not truncate the BIP-39 seed to 32 bytes.** fastcrypto's `HkdfIkm` is
   `PrivateSeed<32, FIXED_LENGTH_ONLY = false>`, so the 32 is a recommendation
   rather than a length check, and Rust feeds all 64 bytes in.
2. **The path is an HKDF salt, not a BIP-32 chain.** It is consumed as the
   exact string Rust's `DerivationPath` Display produces, with apostrophes
   rather than `h`. There is no child-key walk. That is also why every level
   must be hardened: ML-DSA has no tweakable algebra, so there is no xpub
   notion to preserve.
3. **SHA3-256, not SHA-256.**

## Interop

`lib/fixtures.ts` holds the triples pinned by `test_mnemonics_mldsa65` in
`crates/sui/src/unit_tests/keytool_tests.rs`, plus the Rust stage outputs for
the first vector. Those intermediates let a mismatch be traced to BIP-39, the
salt, or HKDF, instead of only showing that two addresses differ. The same
check runs as `npm run interop`.

Mnemonics are 12 words, matching the Sui CLI default, and reuse the phrases
from the repo's secp256r1 mnemonic test.

Cross-check against the CLI:

```bash
sui keytool import "act wing dilemma glory episode region allow mad tourist humble muffin oblige" mldsa65
# 0x3e1f67390afc595591a5caf7af6dc47175fd8356d53f889cb6c4c74488c4dced
```

## Status

Derivation, signing and verification work and match the Rust implementation.

Submitting an ML-DSA transaction from JS/TS does not work yet. The gRPC v2
ingest path parses signatures through `sui_sdk_types::UserSignature`, whose
scheme enum has no `0x07`, so a `sui-rust-sdk` release has to land before any
SDK can broadcast one. Validators themselves accept the scheme today, behind
the devnet-only `mldsa65_auth` protocol flag.

Two existing `ts-sdk` issues will surface once an ML-DSA keypair class exists:
`toSuiAddress()` uses a 653-byte scratch buffer, which a 1952-byte key
overflows, and `combinePartialSignatures` caps at 8192 bytes.

## Deploying

Vercel, no configuration needed. `vercel.json` sets `next build` and the output
is fully static. Push to a repo and import it, or run `npx vercel`.

## Layout

```
app/globals.css     theme, copied verbatim from pq-sigs-ts
app/page.tsx        the four-section UI
lib/mldsa-sui.ts    derivation and signing, the part worth porting to ts-sdk
lib/fixtures.ts     Rust interop vectors
scripts/interop.ts  CI gate
```

`@noble/post-quantum` is pinned to an exact version: 0.7 takes
`sign(msg, sk)` and `verify(sig, msg, pk)`, while 0.5-era releases used the
reverse argument order.
