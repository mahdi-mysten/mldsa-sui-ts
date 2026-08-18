'use client'

import { useState } from 'react'
import {
  ENVELOPE_BYTES,
  PUBLIC_KEY_BYTES,
  SECRET_KEY_BYTES,
  SIGNATURE_BYTES,
  bytesToHex,
  deriveAccount,
  hexToBytes,
  mldsa65Path,
  randomMnemonic,
  sign,
  toEnvelope,
  verify,
} from '@/lib/mldsa-sui'
import { TRIPLES } from '@/lib/fixtures'
import { SCHEMES, type Scheme, deriveClassical } from '@/lib/classical'

type Status = { text: string; kind: '' | 'success' | 'error' }
const EMPTY: Status = { text: '', kind: '' }

// Sui signs the BLAKE2b-256 hash of the intent message: a 32-byte digest.
// A representative sample so the demo signs realistic input, not a string.
const SAMPLE_SUI_DIGEST = 'e04563cdd50029097cca468622181d4bfe02f85ff9c4eb53f472cf114ba0b60b'

export default function Page() {
  const [mnemonic, setMnemonic] = useState(TRIPLES[0].mnemonic)
  const [path, setPath] = useState(mldsa65Path())
  const scheme = schemeFromPath(path)
  const isPq = scheme === 'mldsa65'
  const [deriveStatus, setDeriveStatus] = useState<Status>(EMPTY)
  const [address, setAddress] = useState('')
  const [suiPrivkey, setSuiPrivkey] = useState('')
  const [keygenSeed, setKeygenSeed] = useState('')
  const [pubkey, setPubkey] = useState('')
  const [privkey, setPrivkey] = useState('')

  const [signMsg, setSignMsg] = useState(SAMPLE_SUI_DIGEST)
  const [signPrivkey, setSignPrivkey] = useState('')
  const [signature, setSignature] = useState('')
  const [envelope, setEnvelope] = useState('')
  const [signStatus, setSignStatus] = useState<Status>(EMPTY)

  const [verifyMsg, setVerifyMsg] = useState(SAMPLE_SUI_DIGEST)
  const [verifySig, setVerifySig] = useState('')
  const [verifyPubkey, setVerifyPubkey] = useState('')
  const [verifyStatus, setVerifyStatus] = useState<Status>(EMPTY)

  function handleDerive() {
    try {
      if (!scheme) throw new Error('Purpose must be one of 94, 44, 74, 54')
      setDeriveStatus({ text: 'Deriving...', kind: '' })
      const t0 = performance.now()
      if (isPq) {
        const d = deriveAccount(mnemonic, path)
        const ms = performance.now() - t0
        const pubHex = bytesToHex(d.publicKey)
        setAddress(d.address)
        setSuiPrivkey(d.suiPrivkey)
        setKeygenSeed(bytesToHex(d.keygenSeed))
        setPubkey(pubHex)
        setPrivkey(bytesToHex(d.secretKey))
        setSignPrivkey(bytesToHex(d.secretKey))
        setVerifyPubkey(pubHex)
        setDeriveStatus({
          text: `\u2713 Derived in ${ms.toFixed(2)} ms (HKDF-SHA3-256 + FIPS 204 keygen).`,
          kind: 'success',
        })
      } else {
        const d = deriveClassical(mnemonic, scheme, path)
        const ms = performance.now() - t0
        setAddress(d.address)
        setSuiPrivkey(d.suiPrivkey)
        setKeygenSeed('')
        setPubkey(bytesToHex(d.publicKey))
        setPrivkey(bytesToHex(d.privateKey))
        setSignPrivkey('')
        setVerifyPubkey('')
        setDeriveStatus({
          text: `\u2713 Derived in ${ms.toFixed(2)} ms (${SCHEMES[scheme].label}). Same mnemonic, same address as sui keytool.`,
          kind: 'success',
        })
      }
      setSignature('')
      setEnvelope('')
      setVerifySig('')
      setSignStatus(EMPTY)
      setVerifyStatus(EMPTY)
    } catch (err: any) {
      setDeriveStatus({ text: 'Error: ' + err.message, kind: 'error' })
    }
  }

  function onPathChange(next: string) {
    const nextScheme = schemeFromPath(next)
    if (nextScheme !== scheme) {
      if (nextScheme) {
        // Purpose changed: swap the rest of the path to that scheme's shape,
        // keeping the account/change/address indexes the user already typed.
        const idx = next.split('/').slice(3).map((l) => parseInt(l, 10))
        next = nextScheme === 'mldsa65'
          ? mldsa65Path(idx[0] || 0, idx[1] || 0, idx[2] || 0)
          : SCHEMES[nextScheme].defaultPath.replace(/0'?\/0'?\/0'?$/, (m) =>
              m.split('/').map((l, i) => `${idx[i] || 0}${l.endsWith("'") ? "'" : ''}`).join('/'))
      }
      setAddress('')
      setSuiPrivkey('')
      setKeygenSeed('')
      setPubkey('')
      setPrivkey('')
      setSignPrivkey('')
      setVerifyPubkey('')
      setSignature('')
      setEnvelope('')
      setVerifySig('')
      setDeriveStatus(EMPTY)
      setSignStatus(EMPTY)
      setVerifyStatus(EMPTY)
    }
    setPath(next)
  }

  function handleRandom() {
    setMnemonic(randomMnemonic(12))
    setAddress('')
    setSuiPrivkey('')
    setKeygenSeed('')
    setPubkey('')
    setPrivkey('')
    setSignPrivkey('')
    setVerifyPubkey('')
    setSignature('')
    setEnvelope('')
    setVerifySig('')
    setDeriveStatus({ text: 'New random mnemonic. Click Derive Account.', kind: '' })
    setSignStatus(EMPTY)
    setVerifyStatus(EMPTY)
  }

  function handleSign() {
    try {
      if (!signPrivkey.trim()) throw new Error('Derive an account first, or paste a secret key.')
      const sk = hexToBytes(signPrivkey.trim())
      // Hex, not UTF-8: Sui signs a raw 32-byte digest, so the demo must
      // sign the same bytes a validator will check.
      const msg = hexToBytes(signMsg.trim())

      const t0 = performance.now()
      const sig = sign(msg, sk)
      const ms = performance.now() - t0
      const sigHex = bytesToHex(sig)

      setSignature(sigHex)
      setVerifySig(sigHex)
      setVerifyMsg(signMsg)
      if (pubkey) setEnvelope(bytesToHex(toEnvelope(sig, hexToBytes(pubkey))))
      setSignStatus({
        text: `\u2713 Signed in ${ms.toFixed(2)} ms. ML-DSA signing is hedged, so the bytes differ every run.`,
        kind: 'success',
      })
    } catch (err: any) {
      setSignStatus({ text: 'Error: ' + err.message, kind: 'error' })
    }
  }

  function handleVerify() {
    try {
      if (!verifySig.trim() || !verifyPubkey.trim()) throw new Error('Missing signature or public key.')
      const sig = hexToBytes(verifySig.trim())
      const msg = hexToBytes(verifyMsg.trim())
      const pk = hexToBytes(verifyPubkey.trim())
      if (sig.length !== SIGNATURE_BYTES) {
        throw new Error(`Signature must be ${SIGNATURE_BYTES} bytes, got ${sig.length}.`)
      }

      const t0 = performance.now()
      const ok = verify(sig, msg, pk)
      const ms = performance.now() - t0
      setVerifyStatus({
        text: ok
          ? `\u2713 Signature is VALID. Verified in ${ms.toFixed(2)} ms.`
          : `\u2717 Signature is INVALID. Checked in ${ms.toFixed(2)} ms.`,
        kind: ok ? 'success' : 'error',
      })
    } catch (err: any) {
      setVerifyStatus({ text: 'Error: ' + err.message, kind: 'error' })
    }
  }

  return (
    <div style={{ minHeight: '100vh', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      <main style={{ margin: '2rem auto', maxWidth: 800, color: '#333', padding: '0 1.5rem', width: '100%' }}>
        <h1 style={{ textAlign: 'center', marginBottom: '0.25rem' }}>ML-DSA-65 Sui Accounts</h1>
        <p style={{ textAlign: 'center', color: '#666', fontSize: '0.9rem', marginTop: 0 }}>
          Derive an account from a mnemonic, sign a transaction digest, verify it. Nothing leaves the browser.
        </p>

        <Section title="1. Mnemonic to Sui account">
          <Label htmlFor="mnemonic">BIP-39 mnemonic (12 or 24 words):</Label>
          <textarea
            id="mnemonic"
            rows={3}
            value={mnemonic}
            onChange={(e) => setMnemonic(e.target.value)}
            style={inputStyle}
            placeholder="Enter or paste a mnemonic..."
          />
          <Label htmlFor="path">
            Derivation path: {scheme ? SCHEME_LABEL[scheme] : 'unknown scheme'}. Purpose 94, 44, 74 or 54, default 94.
          </Label>
          <input id="path" type="text" value={path} onChange={(e) => onPathChange(e.target.value)} style={inputStyle} />
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <button onClick={handleDerive} style={buttonStyle}>
              Derive Account
            </button>
            <button onClick={handleRandom} style={{ ...buttonStyle, background: '#6c757d' }}>
              Random Mnemonic
            </button>
          </div>
          <StatusLine status={deriveStatus} />

          <Label htmlFor="address">Sui address, blake2b256(flag || pk):</Label>
          <textarea id="address" rows={1} readOnly value={address} style={{ ...inputStyle, fontWeight: 700 }} placeholder="0x..." />
          <Label htmlFor="suiprivkey">Private key (bech32 of flag || 32-byte secret):</Label>
          <textarea id="suiprivkey" rows={2} readOnly value={suiPrivkey} style={inputStyle} placeholder="suiprivkey1..." />
          {isPq && (
            <>
              <Label htmlFor="keygenseed">HKDF output = FIPS 204 keygen seed (32 bytes):</Label>
              <textarea id="keygenseed" rows={1} readOnly value={keygenSeed} style={inputStyle} placeholder="32-byte seed in hex..." />
            </>
          )}
          <Label htmlFor="pubkey">Public key{isPq ? ` (${PUBLIC_KEY_BYTES} bytes)` : ''}:</Label>
          <textarea id="pubkey" rows={isPq ? 4 : 1} readOnly value={pubkey} style={inputStyle} placeholder="Public key will appear here..." />
          <Label htmlFor="privkey">
            {isPq ? `Expanded secret key (${SECRET_KEY_BYTES} bytes, never serialized by Sui):` : 'Secret key (32 bytes):'}
          </Label>
          <textarea id="privkey" rows={isPq ? 4 : 1} readOnly value={privkey} style={inputStyle} placeholder="Secret key will appear here..." />
        </Section>

        <Section title="2. Sign">
          <Label htmlFor="sign-msg">Message (Sui transaction digest, BLAKE2b-256 hex):</Label>
          <textarea id="sign-msg" rows={2} value={signMsg} onChange={(e) => setSignMsg(e.target.value)} style={inputStyle} />
          <Label htmlFor="sign-privkey">Secret key ({SECRET_KEY_BYTES} bytes):</Label>
          <textarea
            id="sign-privkey"
            rows={4}
            value={signPrivkey}
            onChange={(e) => setSignPrivkey(e.target.value)}
            style={inputStyle}
            placeholder="Derive an account above, or paste a secret key..."
          />
          <button onClick={handleSign} style={buttonStyle}>
            Sign Message
          </button>
          <StatusLine status={signStatus} />
          <Label htmlFor="signature">Signature ({SIGNATURE_BYTES} bytes):</Label>
          <textarea id="signature" rows={4} readOnly value={signature} style={inputStyle} placeholder="Signature will appear here..." />
          <Label htmlFor="envelope">Sui signature envelope: flag || sig || pk ({ENVELOPE_BYTES} bytes):</Label>
          <textarea id="envelope" rows={4} readOnly value={envelope} style={inputStyle} placeholder="The bytes a transaction carries..." />
        </Section>

        <Section title="3. Verify">
          <Label htmlFor="verify-msg">Message (BLAKE2b-256 hex):</Label>
          <textarea id="verify-msg" rows={2} value={verifyMsg} onChange={(e) => setVerifyMsg(e.target.value)} style={inputStyle} />
          <Label htmlFor="verify-sig">Signature ({SIGNATURE_BYTES} bytes):</Label>
          <textarea id="verify-sig" rows={4} value={verifySig} onChange={(e) => setVerifySig(e.target.value)} style={inputStyle} placeholder="Paste a signature..." />
          <Label htmlFor="verify-pubkey">Public key ({PUBLIC_KEY_BYTES} bytes):</Label>
          <textarea id="verify-pubkey" rows={4} value={verifyPubkey} onChange={(e) => setVerifyPubkey(e.target.value)} style={inputStyle} placeholder="Paste a public key..." />
          <button onClick={handleVerify} style={buttonStyle}>
            Verify
          </button>
          <StatusLine status={verifyStatus} />
        </Section>

        <footer
          style={{
            marginTop: '2rem',
            padding: '1.25rem 1.5rem',
            background: '#fff',
            border: '1px solid #ddd',
            borderRadius: 8,
            fontSize: '0.85rem',
            lineHeight: 1.6,
            color: '#555',
          }}
        >
          <p style={{ margin: '0 0 0.5rem' }}>
            Everything runs <strong>entirely client-side</strong>. No key material leaves the browser,
            and nothing is sent to a server. Still, treat this as a demo: use throwaway mnemonics.
          </p>
          <p style={{ margin: '0 0 0.5rem' }}>
            Derivation: <code>HKDF-SHA3-256(ikm = BIP-39 seed, salt = path, info = &quot;mldsa65-keygen-v1&quot;)</code>{' '}
            gives the 32-byte FIPS 204 keygen seed.
          </p>
          <p style={{ margin: '0 0 0.5rem' }}>
            Purpose node <code>94&apos;</code> separates ML-DSA
            from ed25519 (<code>44&apos;</code>), secp256k1 (<code>54&apos;</code>) and secp256r1 (<code>74&apos;</code>).
          </p>
          <p style={{ margin: 0 }}>
            Primitives from{' '}
            <a href="https://github.com/paulmillr/noble-post-quantum" target="_blank" rel="noopener noreferrer" style={{ color: '#007bff' }}>
              @noble/post-quantum
            </a>
            . Mirrors <code>crates/sui-keys/src/key_derive.rs</code> in Sui.
          </p>
        </footer>
      </main>
    </div>
  )
}

const SCHEME_LABEL = { mldsa65: 'ML-DSA-65', ed25519: 'Ed25519', secp256k1: 'Secp256k1', secp256r1: 'Secp256r1' } as const

function schemeFromPath(path: string): 'mldsa65' | Scheme | null {
  const purpose = path.trim().split('/')[1]?.replace(/['h]$/, '')
  if (purpose === '94') return 'mldsa65'
  return (Object.keys(SCHEMES) as Scheme[]).find((k) => String(SCHEMES[k].purpose) === purpose) ?? null
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div
      style={{
        background: '#fff',
        border: '1px solid #ddd',
        padding: '1.5rem',
        marginBottom: '1.5rem',
        borderRadius: 8,
        boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
      }}
    >
      <h2 style={{ marginTop: 0 }}>{title}</h2>
      {children}
    </div>
  )
}

function Label({ htmlFor, children }: { htmlFor: string; children: React.ReactNode }) {
  return (
    <label htmlFor={htmlFor} style={{ display: 'block', marginTop: '1rem', fontWeight: 600, fontSize: '0.9rem' }}>
      {children}
    </label>
  )
}

function StatusLine({ status }: { status: Status }) {
  const color = status.kind === 'success' ? '#28a745' : status.kind === 'error' ? '#dc3545' : '#333'
  return <div style={{ marginTop: '1rem', fontWeight: 'bold', fontSize: '0.95rem', color }}>{status.text}</div>
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  boxSizing: 'border-box',
  marginTop: '0.5rem',
  marginBottom: '0.25rem',
  padding: '0.5rem',
  fontFamily: 'monospace',
  fontSize: '0.9rem',
  border: '1px solid #ccc',
  borderRadius: 4,
  resize: 'vertical',
  wordBreak: 'break-all',
}

const buttonStyle: React.CSSProperties = {
  marginTop: '1rem',
  padding: '0.5rem 1rem',
  cursor: 'pointer',
  background: '#007bff',
  color: 'white',
  fontWeight: 'bold',
  border: 'none',
  borderRadius: 4,
}
