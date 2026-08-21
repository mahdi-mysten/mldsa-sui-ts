// ML-DSA-65 (FIPS 204) key derivation and signing for Sui accounts.
//
// This is the TypeScript mirror of `derive_key_pair_from_path` in
// sui/crates/sui-keys/src/key_derive.rs (the `SignatureScheme::MLDSA65`
// arm). The two implementations must agree byte for byte: a mnemonic that
// derives address A in the Sui CLI has to derive address A here, or a wallet
// built on this code hands users an address they cannot spend from.
// `lib/fixtures.ts` pins the values that prove it; run `npm run interop`.
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { blake2b } from '@noble/hashes/blake2.js'
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { bech32 } from '@scure/base'

/// Sui signature scheme flag for ML-DSA-65. Prefixes both the public key when
/// hashing an address and the private key in its bech32 form.
export const MLDSA65_FLAG = 0x07

/// The purpose node that separates ML-DSA from the classical schemes
/// (44' ed25519, 54' secp256k1, 74' secp256r1).
export const PURPOSE = 94
export const COIN_TYPE = 784

/// Master HMAC key for the SLIP-0010 walk, byte for byte the string from
/// satoshilabs/slips#1968 (also NEAR and QIP-0002), so hardware wallets can
/// serve all adopters with one code path. Must equal MLDSA65_SLIP10_KEY in
/// key_derive.rs.
export const SLIP10_KEY = new TextEncoder().encode('ML-DSA-65 seed')

export const PUBLIC_KEY_BYTES = 1952
export const SECRET_KEY_BYTES = 4032
export const SIGNATURE_BYTES = 3309
export const KEYGEN_SEED_BYTES = 32
/// A Sui account signature travels as `flag || sig || pk`.
export const ENVELOPE_BYTES = 1 + SIGNATURE_BYTES + PUBLIC_KEY_BYTES

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

export function hexToBytes(hex: string): Uint8Array {
  // Strip whitespace (terminal copy-paste wraps lines), then validate:
  // parseInt would silently turn bad pairs into NaN -> byte 0.
  hex = hex.replace(/\s+/g, '')
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string (odd length)')
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error('Invalid hex string (non-hex characters)')
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/// The canonical derivation path: every level hardened (ML-DSA has no
/// tweakable algebra, so no public derivation exists), apostrophe form.
export function mldsa65Path(account = 0, change = 0, address = 0): string {
  return `m/${PURPOSE}'/${COIN_TYPE}'/${account}'/${change}'/${address}'`
}

/// All levels must be hardened: ML-DSA has no tweakable algebra, so there is
/// no public-derivation (xpub) notion that unhardened levels would enable.
/// Mirrors the `validate_path` MLDSA65 arm.
export function validatePath(path: string): void {
  const m = path.trim().match(/^m(\/\d+')+$/)
  const levels = path.trim().split('/').slice(1)
  if (!m || levels.length !== 5) {
    throw new Error("Path must be m/94'/784'/account'/change'/address' with all levels hardened")
  }
  if (levels[0] !== `${PURPOSE}'`) throw new Error(`Purpose node must be ${PURPOSE}' for ML-DSA-65`)
  if (levels[1] !== `${COIN_TYPE}'`) throw new Error(`Coin type must be ${COIN_TYPE}'`)
}

export function randomMnemonic(words: 12 | 24 = 12): string {
  return generateMnemonic(wordlist, words === 24 ? 256 : 128)
}

export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic.trim(), wordlist)
}

export type Derived = {
  bip39Seed: Uint8Array
  keygenSeed: Uint8Array
  publicKey: Uint8Array
  secretKey: Uint8Array
  address: string
  suiPrivkey: string
  path: string
}

/// Derive a Sui ML-DSA-65 account from a BIP-39 mnemonic.
///
/// SLIP-0010 hardened walk keyed "ML-DSA-65 seed" (slips#1968); the final
/// node secret I_L is the FIPS 204 keygen seed. Mirrors
/// derive_mldsa65_slip10 in key_derive.rs.
///
/// Throws if the mnemonic fails its BIP-39 checksum or the path is malformed.
export function deriveAccount(mnemonic: string, path = mldsa65Path()): Derived {
  const phrase = mnemonic.trim().replace(/\s+/g, ' ')
  if (!validateMnemonic(phrase, wordlist)) {
    throw new Error('Invalid BIP-39 mnemonic (bad word or checksum)')
  }
  validatePath(path)

  const bip39Seed = mnemonicToSeedSync(phrase, '')
  let node = hmac(sha512, SLIP10_KEY, bip39Seed)
  for (const level of path.trim().split('/').slice(1)) {
    const index = (Number(level.replace(/['h]$/, '')) + 0x80000000) >>> 0
    const data = new Uint8Array(37)
    data.set(node.subarray(0, 32), 1)
    new DataView(data.buffer).setUint32(33, index)
    node = hmac(sha512, node.subarray(32), data)
  }
  const keygenSeed = node.slice(0, KEYGEN_SEED_BYTES)
  const { publicKey, secretKey } = ml_dsa65.keygen(keygenSeed)
  return {
    bip39Seed,
    keygenSeed,
    publicKey,
    secretKey,
    address: toSuiAddress(publicKey),
    suiPrivkey: toSuiPrivkey(keygenSeed),
    path,
  }
}

/// address = first 32 bytes of blake2b256(flag || pk).
/// The flag is inside the hash, so two schemes holding the same key bytes
/// still land on different addresses.
export function toSuiAddress(publicKey: Uint8Array): string {
  const buf = new Uint8Array(1 + publicKey.length)
  buf[0] = MLDSA65_FLAG
  buf.set(publicKey, 1)
  return '0x' + bytesToHex(blake2b(buf, { dkLen: 32 }))
}

/// Bech32 of `flag || 32-byte seed` (33 bytes), the keystore/export form.
/// Only the seed is ever serialized; the 4,032-byte expanded key is re-derived,
/// which is what makes a mismatched pk/sk pair unrepresentable.
export function toSuiPrivkey(keygenSeed: Uint8Array): string {
  const buf = new Uint8Array(1 + keygenSeed.length)
  buf[0] = MLDSA65_FLAG
  buf.set(keygenSeed, 1)
  return bech32.encode('suiprivkey', bech32.toWords(buf))
}

/// Inverse of `toSuiPrivkey`; returns the 32-byte keygen seed.
export function fromSuiPrivkey(privkey: string): Uint8Array {
  const { prefix, words } = bech32.decode(privkey.trim() as `${string}1${string}`)
  if (prefix !== 'suiprivkey') throw new Error(`Expected "suiprivkey" prefix, got "${prefix}"`)
  const bytes = bech32.fromWords(words)
  if (bytes[0] !== MLDSA65_FLAG) throw new Error(`Not an ML-DSA-65 key (flag 0x${bytes[0].toString(16)})`)
  if (bytes.length !== 1 + KEYGEN_SEED_BYTES) throw new Error(`Expected 33 bytes, got ${bytes.length}`)
  return Uint8Array.from(bytes.slice(1))
}

// @noble/post-quantum takes (msg, secretKey) and (sig, msg, publicKey).
// Older 0.5-era releases used the reverse order, so the version is pinned
// exactly in package.json rather than floated.
export function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_dsa65.sign(message, secretKey)
}

export function verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  // noble is permissive about length; Sui parses a fixed-size envelope, so
  // reject non-canonical sizes here or the UI would show a green check for
  // something a validator refuses at parse time.
  if (signature.length !== SIGNATURE_BYTES) return false
  if (publicKey.length !== PUBLIC_KEY_BYTES) return false
  return ml_dsa65.verify(signature, message, publicKey)
}

/// The bytes a Sui transaction actually carries: `flag || sig || pk`.
export function toEnvelope(signature: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const buf = new Uint8Array(ENVELOPE_BYTES)
  buf[0] = MLDSA65_FLAG
  buf.set(signature, 1)
  buf.set(publicKey, 1 + signature.length)
  return buf
}
