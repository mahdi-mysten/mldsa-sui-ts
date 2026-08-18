// Guards against cross-repo drift.
//
// lib/fixtures.ts duplicates values that live in the Sui repo's
// test_mnemonics_mldsa65. The normal interop run only proves this code agrees
// with that local copy, so if the Rust fixtures are ever regenerated, CI here
// would stay green while the two stacks silently diverged. This fetches the
// Rust test and compares the mnemonic/privkey/address triples directly.
//
// Configure with SUI_FIXTURES_URL (raw URL of keytool_tests.rs).
import { TRIPLES } from '../lib/fixtures.ts'

const URL_ =
  process.env.SUI_FIXTURES_URL ??
  'https://raw.githubusercontent.com/MystenLabs/sui/main/crates/sui/src/unit_tests/keytool_tests.rs'

// A local path is allowed so the check can run against a working tree before
// the Rust side is pushed, and so CI can point at a checkout instead of a URL.
let src
if (/^https?:/.test(URL_)) {
  const res = await fetch(URL_)
  if (!res.ok) {
    console.error(`Could not fetch ${URL_}: ${res.status} ${res.statusText}`)
    console.error('A slashed branch name needs a commit SHA in the raw URL.')
    process.exit(2)
  }
  src = await res.text()
} else {
  src = (await import('node:fs')).readFileSync(URL_, 'utf8')
}

const fn = src.match(/fn test_mnemonics_mldsa65[\s\S]*?\n}/)
if (!fn) {
  console.error('test_mnemonics_mldsa65 not found. Has the Rust derivation landed on that branch?')
  process.exit(2)
}
const quoted = [...fn[0].matchAll(/"([^"]+)"/g)].map((m) => m[1])
const rust = []
for (let i = 0; i + 2 < quoted.length; i++) {
  if (/^[0-9a-f]{64}$/.test(quoted[i + 2]) && quoted[i + 1].startsWith('suiprivkey')) {
    rust.push({ mnemonic: quoted[i], suiPrivkey: quoted[i + 1], address: '0x' + quoted[i + 2] })
    i += 2
  }
}

let failures = 0
if (rust.length !== TRIPLES.length) {
  failures++
  console.log(`FAIL  vector count: rust ${rust.length}, ts ${TRIPLES.length}`)
}
for (const r of rust) {
  const ours = TRIPLES.find((t) => t.mnemonic === r.mnemonic)
  const tag = r.mnemonic.split(' ')[0]
  if (!ours) {
    failures++
    console.log(`FAIL  ${tag}...  present in Rust, missing here`)
    continue
  }
  for (const field of ['address', 'suiPrivkey']) {
    if (ours[field] !== r[field]) {
      failures++
      console.log(`FAIL  ${tag}... ${field}\n        rust ${r[field]}\n        ts   ${ours[field]}`)
    } else {
      console.log(`PASS  ${tag}... ${field}`)
    }
  }
}

console.log(
  failures === 0
    ? `\nFixtures match the Rust repo (${rust.length} vectors).`
    : `\n${failures} fixture(s) drifted from the Rust repo.`,
)
process.exit(failures === 0 ? 0 : 1)
