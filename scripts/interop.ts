// CI gate: fails (non-zero exit) if this TypeScript implementation would
// derive different keys than the Rust one. Run with `npm run interop`.
import { deriveAccount, bytesToHex, mldsa65Path, sign, verify, SIGNATURE_BYTES } from '../lib/mldsa-sui.ts'
import { TRIPLES, INTERMEDIATES } from '../lib/fixtures.ts'

let failures = 0
function check(label: string, got: string, want: string) {
  const ok = got === want
  if (!ok) failures++
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`)
  if (!ok) console.log(`        got  ${got}\n        want ${want}`)
}

console.log('### stages against the Rust intermediates (vector 0)')
const v0 = deriveAccount(TRIPLES[0].mnemonic)
check('BIP-39 seed (64 B)', bytesToHex(v0.bip39Seed), INTERMEDIATES.bip39Seed)
check('HKDF salt string', mldsa65Path(), INTERMEDIATES.salt)
check('HKDF output / keygen seed (32 B)', bytesToHex(v0.keygenSeed), INTERMEDIATES.keygenSeed)

console.log('\n### full triples against the Rust keytool fixtures')
for (const t of TRIPLES) {
  const d = deriveAccount(t.mnemonic)
  const tag = t.mnemonic.split(' ')[0]
  check(`address  ${tag}...`, d.address, t.address)
  check(`privkey  ${tag}...`, d.suiPrivkey, t.suiPrivkey)
  const msg = new TextEncoder().encode('pq interop')
  const sig = sign(msg, d.secretKey)
  if (sig.length !== SIGNATURE_BYTES || !verify(sig, msg, d.publicKey)) {
    failures++
    console.log(`  FAIL  sign/verify ${tag}...`)
  } else {
    console.log(`  PASS  sign+verify ${tag}...`)
  }
}

console.log(
  failures === 0
    ? '\nTypeScript matches Rust on every vector.'
    : `\n${failures} MISMATCH(ES) - TypeScript and Rust would derive different keys.`,
)
process.exit(failures === 0 ? 0 : 1)
