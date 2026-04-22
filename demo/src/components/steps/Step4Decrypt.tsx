import { Card } from '@/components/atoms/Card'
import { Chip } from '@/components/atoms/Chip'
import { Btn } from '@/components/atoms/Btn'
import { Fingerprint } from '@/components/atoms/Fingerprint'
import { StepHeader } from '@/components/atoms/StepHeader'
import type { Phase } from '@/lib/fhe-types'

interface Step4DecryptProps {
  ctSum: Uint8Array | null
  result: number | null
  phase: Phase
  a: number
  b: number
  onDecrypt: () => void
}

export function Step4Decrypt({ ctSum, result, phase, a, b, onDecrypt }: Step4DecryptProps) {
  const busy = phase !== 'idle'
  const ready = !!ctSum
  const done = result !== null
  const expected = a + b

  return (
    <Card accent="var(--plain)">
      <StepHeader
        n="4"
        title="Decrypt on the client"
        subtitle="Apply sk to the encrypted result. Works while noise stays under the 50% margin."
        accent="var(--plain)"
        done={done}
      />

      <div className="demo-decrypt-row" style={{ display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap' }}>
        {/* The encrypted result */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {ctSum ? (
            <Fingerprint bytes={ctSum} size={54} />
          ) : (
            <div
              style={{
                width: 54,
                height: 54,
                borderRadius: 6,
                background: 'var(--bg-tint)',
                border: '1px dashed var(--rule)',
              }}
            />
          )}
          <div>
            <Chip tone="cipher" style={{ fontSize: 10 }}>
              ct_sum
            </Chip>
            <div
              style={{
                fontSize: 11,
                color: 'var(--ink-faint)',
                fontFamily: 'var(--font-mono)',
                marginTop: 4,
              }}
            >
              {ctSum ? `${ctSum.byteLength} B` : '—'}
            </div>
          </div>
        </div>

        {/* Dec arrow */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            fontFamily: 'var(--font-mono)',
            color: 'var(--ink-faint)',
            fontSize: 13,
            flexShrink: 0,
          }}
        >
          <span>⟶ Dec(</span>
          <svg width="18" height="18" viewBox="0 0 18 18">
            <circle cx="6" cy="9" r="3.5" fill="oklch(0.35 0.12 290)" stroke="oklch(0.35 0.12 290)" strokeWidth="1.5" />
            <path d="M 9.5 9 L 16 9 M 14 9 L 14 12 M 12 9 L 12 11.5" stroke="oklch(0.35 0.12 290)" strokeWidth="1.5" fill="none" strokeLinecap="round" />
          </svg>
          <span>sk) ⟶</span>
        </div>

        {/* Big result number */}
        <div
          className="demo-decrypt-big"
          data-testid="decrypt-result"
          style={{
            fontFamily: 'var(--font-serif)',
            fontSize: 72,
            lineHeight: 1,
            color:
              done ? 'var(--plain)' : 'var(--rule-strong)',
            fontWeight: 500,
            textAlign: 'center',
            minWidth: 80,
            transition: 'color 0.3s ease',
            flexShrink: 0,
          }}
        >
          {done ? result : '·'}
        </div>

        {/* Explanation */}
        <div className="demo-decrypt-explain" style={{ fontSize: 12, color: 'var(--ink-soft)', flex: '1 1 240px', minWidth: 220 }}>
          {done ? (
            <>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--ink)' }}>
                {a} + {b} = <b>{result}</b>
              </div>
              <div style={{ marginTop: 2, color: 'var(--ink-faint)' }}>
                Matches the plaintext sum ({expected}) — the server never saw either operand.
              </div>
            </>
          ) : (
            'The server returned ct_sum. Press below to recover the plaintext locally.'
          )}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 18 }}>
        <Btn onClick={onDecrypt} disabled={!ready || busy} primary>
          {phase === 'decrypting' ? 'Decrypting…' : done ? 'Decrypt again' : 'Decrypt result'}
        </Btn>
      </div>
    </Card>
  )
}
