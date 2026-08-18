// Sui's classical schemes: ed25519 via SLIP-0010, secp256k1/r1 via BIP-32.
import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { p256 } from '@noble/curves/nist.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { blake2b } from '@noble/hashes/blake2.js'
import { mnemonicToSeedSync } from '@scure/bip39'
import { bech32 } from '@scure/base'

export type Scheme = 'ed25519' | 'secp256k1' | 'secp256r1'

export const SCHEMES: Record<Scheme, { flag: number; purpose: number; label: string; defaultPath: string }> = {
  ed25519: { flag: 0x00, purpose: 44, label: 'Ed25519', defaultPath: "m/44'/784'/0'/0'/0'" },
  secp256k1: { flag: 0x01, purpose: 54, label: 'Secp256k1', defaultPath: "m/54'/784'/0'/0/0" },
  secp256r1: { flag: 0x02, purpose: 74, label: 'Secp256r1', defaultPath: "m/74'/784'/0'/0/0" },
}

const HARDENED = 0x80000000
const bytesToHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const enc = (s: string) => new TextEncoder().encode(s)

function parsePath(path: string): { index: number; hardened: boolean }[] {
  const parts = path.trim().split('/')
  if (parts[0] !== 'm') throw new Error('Path must start with m/')
  return parts.slice(1).map((p) => {
    const hardened = p.endsWith("'") || p.endsWith('h')
    const n = Number(hardened ? p.slice(0, -1) : p)
    if (!Number.isInteger(n) || n < 0 || n >= HARDENED) throw new Error(`Bad path level: ${p}`)
    return { index: n, hardened }
  })
}

function ser32(n: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n)
  return b
}

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

function slip10Ed25519(seed: Uint8Array, path: string): Uint8Array {
  let I = hmac(sha512, enc('ed25519 seed'), seed)
  let key = I.slice(0, 32)
  let chain = I.slice(32)
  for (const { index, hardened } of parsePath(path)) {
    if (!hardened) throw new Error('Ed25519 requires every level hardened')
    I = hmac(sha512, chain, cat(new Uint8Array([0]), key, ser32(index + HARDENED)))
    key = I.slice(0, 32)
    chain = I.slice(32)
  }
  return key
}

// Sui derives secp256r1 with the secp256k1 BIP-32 walk and reinterprets the
// scalar as a P-256 key (bip32::XPrv is k1-only; ts-sdk does the same).
function bip32(seed: Uint8Array, path: string): Uint8Array {
  const toBig = (b: Uint8Array) => BigInt('0x' + bytesToHex(b))
  const toBytes = (x: bigint) => {
    const h = x.toString(16).padStart(64, '0')
    return Uint8Array.from(h.match(/../g)!.map((p) => parseInt(p, 16)))
  }
  const n = secp256k1.Point.CURVE().n
  let I = hmac(sha512, enc('Bitcoin seed'), seed)
  let key = I.slice(0, 32)
  let chain = I.slice(32)
  for (const { index, hardened } of parsePath(path)) {
    const data = hardened
      ? cat(new Uint8Array([0]), key, ser32(index + HARDENED))
      : cat(secp256k1.getPublicKey(key, true), ser32(index))
    I = hmac(sha512, chain, data)
    const IL = toBig(I.slice(0, 32))
    if (IL >= n) throw new Error('Invalid child (IL >= n)')
    const child = (IL + toBig(key)) % n
    if (child === BigInt(0)) throw new Error('Invalid child (zero key)')
    key = toBytes(child)
    chain = I.slice(32)
  }
  return key
}

export type ClassicalDerived = {
  scheme: Scheme
  path: string
  privateKey: Uint8Array
  publicKey: Uint8Array
  address: string
  suiPrivkey: string
}

export function deriveClassical(mnemonic: string, scheme: Scheme, path?: string): ClassicalDerived {
  const p = path ?? SCHEMES[scheme].defaultPath
  const seed = mnemonicToSeedSync(mnemonic.trim().replace(/\s+/g, ' '), '')
  let privateKey: Uint8Array
  let publicKey: Uint8Array
  if (scheme === 'ed25519') {
    privateKey = slip10Ed25519(seed, p)
    publicKey = ed25519.getPublicKey(privateKey)
  } else if (scheme === 'secp256k1') {
    privateKey = bip32(seed, p)
    publicKey = secp256k1.getPublicKey(privateKey, true)
  } else {
    privateKey = bip32(seed, p)
    publicKey = p256.getPublicKey(privateKey, true)
  }
  const flag = SCHEMES[scheme].flag
  const address = '0x' + bytesToHex(blake2b(cat(new Uint8Array([flag]), publicKey), { dkLen: 32 }))
  const suiPrivkey = bech32.encode('suiprivkey', bech32.toWords(cat(new Uint8Array([flag]), privateKey)))
  return { scheme, path: p, privateKey, publicKey, address, suiPrivkey }
}
