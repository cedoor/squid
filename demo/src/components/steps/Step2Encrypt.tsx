import { Card } from '@/components/atoms/Card'
import { Chip } from '@/components/atoms/Chip'
import { Btn } from '@/components/atoms/Btn'
import { Fingerprint } from '@/components/atoms/Fingerprint'
import { NoiseMeter } from '@/components/atoms/NoiseMeter'
import { NumberPad } from '@/components/atoms/NumberPad'
import { StripePlaceholder } from '@/components/atoms/StripePlaceholder'
import { StepHeader } from '@/components/atoms/StepHeader'
import { formatBytes } from '@/lib/pack'
import type { Phase } from '@/lib/fhe-types'

interface Step2EncryptProps {
  hasKeys: boolean
  a: number
  b: number
  ctA: Uint8Array | null
  ctB: Uint8Array | null
  phase: Phase
  onSelectA: (n: number) => void
  onSelectB: (n: number) => void
  onEncrypt: () => void
}

function EncryptSlot({
  label,
  value,
  setValue,
  ct,
  disabled,
}: {
  label: string
  value: number
  setValue: (n: number) => void
  ct: Uint8Array | null
  disabled: boolean
}) {
  return (
    <div
      style={{
        border: '1px solid var(--rule)',
        borderRadius: 10,
        padding: 14,
        background: 'var(--card)',
        opacity: disabled ? 0.5 : 1,
      }}
    >
      <NumberPad value={value} onChange={setValue} label={label} disabled={disabled} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12 }}>
        <div
          style={{
            fontFamily: 'var(--font-serif)',
            fontSize: 40,
            lineHeight: 1,
            color: 'var(--plain)',
            fontWeight: 500,
            width: 54,
            textAlign: 'center',
          }}
        >
          {value}
        </div>
        <div style={{ color: 'var(--ink-faint)', fontFamily: 'var(--font-mono)', fontSize: 13 }}>
          → Enc →
        </div>
        <div style={{ flex: 1 }}>
          {ct ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Fingerprint bytes={ct} size={56} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <Chip tone="cipher" style={{ fontSize: 10 }}>
                  ct_{label.split(' ')[1]}
                </Chip>
                <div
                  style={{
                    fontSize: 11,
                    color: 'var(--ink-faint)',
                    fontFamily: 'var(--font-mono)',
                    marginTop: 4,
                  }}
                >
                  {formatBytes(ct.byteLength)}
                </div>
              </div>
            </div>
          ) : (
            <StripePlaceholder label="ciphertext" height={56} />
          )}
        </div>
      </div>
      {ct && (
        <div style={{ marginTop: 10 }}>
          <NoiseMeter bytes={ct} opCount={0} label="initial noise" />
        </div>
      )}
    </div>
  )
}

export function Step2Encrypt({
  hasKeys,
  a,
  b,
  ctA,
  ctB,
  phase,
  onSelectA,
  onSelectB,
  onEncrypt,
}: Step2EncryptProps) {
  const busy = phase !== 'idle'
  const done = !!ctA && !!ctB

  return (
    <Card accent="var(--plain)">
      <StepHeader
        n="2"
        title="Choose two numbers, then encrypt"
        subtitle="Each integer (0–15) becomes an LWE ciphertext. Same value encrypts differently every time."
        accent="var(--plain)"
        done={done}
      />

      <div className="demo-card-2col" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <EncryptSlot
          label="input a"
          value={a}
          setValue={onSelectA}
          ct={ctA}
          disabled={!hasKeys || busy}
        />
        <EncryptSlot
          label="input b"
          value={b}
          setValue={onSelectB}
          ct={ctB}
          disabled={!hasKeys || busy}
        />
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 16 }}>
        <Btn onClick={onEncrypt} disabled={!hasKeys || busy} primary>
          {phase === 'encrypting' ? 'Encrypting…' : done ? 'Re-encrypt' : 'Encrypt a & b'}
        </Btn>
        {!hasKeys && (
          <span style={{ fontSize: 12, color: 'var(--ink-faint)' }}>↑ Generate keys first</span>
        )}
      </div>
    </Card>
  )
}
