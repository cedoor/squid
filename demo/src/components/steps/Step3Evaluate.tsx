import { Card } from '@/components/atoms/Card'
import { Chip } from '@/components/atoms/Chip'
import { Btn } from '@/components/atoms/Btn'
import { Fingerprint } from '@/components/atoms/Fingerprint'
import { ByteViewer } from '@/components/atoms/ByteViewer'
import { NoiseMeter } from '@/components/atoms/NoiseMeter'
import { StepHeader } from '@/components/atoms/StepHeader'
import { formatBytes } from '@/lib/pack'
import type { Phase } from '@/lib/fhe-types'

interface Step3EvaluateProps {
  ctA: Uint8Array | null
  ctB: Uint8Array | null
  ctSum: Uint8Array | null
  phase: Phase
  onEvaluate: () => void
}

function PayloadRow({
  icon,
  label,
  value,
  tone,
}: {
  icon: React.ReactNode
  label: string
  value: string
  tone: 'key' | 'cipher'
}) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '6px 8px',
        borderRadius: 6,
        background: 'var(--card)',
        border: '1px solid var(--rule)',
      }}
    >
      <div style={{ width: 18, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        {icon}
      </div>
      <Chip tone={tone} style={{ fontSize: 10 }}>
        {label}
      </Chip>
      <div style={{ flex: 1 }} />
      <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--ink-soft)' }}>
        {value}
      </div>
    </div>
  )
}

export function Step3Evaluate({ ctA, ctB, ctSum, phase, onEvaluate }: Step3EvaluateProps) {
  const busy = phase !== 'idle'
  const ready = !!ctA && !!ctB
  const sending = phase === 'sending' || phase === 'evaluating'
  const done = !!ctSum

  return (
    <Card accent="var(--cipher)">
      <StepHeader
        n="3"
        title="Send ciphertexts, add homomorphically"
        subtitle="Client sends only ctₐ and ct_b — the server already holds the EK. It never sees the plaintext values."
        accent="var(--cipher)"
        done={done}
      />

      {/* Transit diagram */}
      <div
        className="demo-send-grid"
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr auto 1fr',
          alignItems: 'center',
          gap: 16,
          padding: '8px 4px 12px',
        }}
      >
        {/* Outbound payload */}
        <div
          style={{
            border: '1px dashed var(--rule-strong)',
            borderRadius: 10,
            padding: 12,
            background: 'var(--bg-tint)',
          }}
        >
          <div
            style={{
              fontSize: 11,
              textTransform: 'uppercase',
              letterSpacing: 1.2,
              color: 'var(--ink-faint)',
              marginBottom: 6,
            }}
          >
            outbound payload
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            <PayloadRow
              icon={ctA ? <Fingerprint bytes={ctA} size={14} /> : null}
              label="ctₐ"
              value={ctA ? formatBytes(ctA.byteLength) : '—'}
              tone="cipher"
            />
            <PayloadRow
              icon={ctB ? <Fingerprint bytes={ctB} size={14} /> : null}
              label="ct_b"
              value={ctB ? formatBytes(ctB.byteLength) : '—'}
              tone="cipher"
            />
          </div>
          {/* EK note */}
          <div
            style={{
              marginTop: 8,
              fontSize: 10.5,
              color: 'var(--ink-faint)',
              fontFamily: 'var(--font-mono)',
              display: 'flex',
              alignItems: 'center',
              gap: 5,
            }}
          >
            <svg width="11" height="11" viewBox="0 0 18 18">
              <circle cx="6" cy="9" r="3.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
              <path d="M 9.5 9 L 16 9 M 14 9 L 14 12 M 12 9 L 12 11.5" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" />
            </svg>
            ek pre-loaded on server · not sent
          </div>
        </div>

        {/* Transit arrow + parcel animation */}
        <div
          className="demo-send-arrow"
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 4,
            minWidth: 90,
          }}
        >
          <div style={{ position: 'relative', width: 80, height: 28 }}>
            <svg width="80" height="28" viewBox="0 0 80 28" style={{ overflow: 'visible' }}>
              <path
                d="M 2 14 L 78 14"
                stroke="var(--rule-strong)"
                strokeWidth="1.2"
                strokeDasharray="3 3"
              />
              <polygon points="78,14 72,10 72,18" fill="var(--rule-strong)" />
            </svg>
            {sending && (
              <div
                style={{
                  position: 'absolute',
                  top: 6,
                  left: 0,
                  animation: 'parcel 1.2s linear infinite',
                }}
              >
                <div
                  style={{
                    width: 16,
                    height: 16,
                    borderRadius: 3,
                    background: 'var(--cipher)',
                    boxShadow: '0 2px 6px oklch(0 0 0 / 0.15)',
                  }}
                />
              </div>
            )}
          </div>
          <div
            style={{
              fontSize: 10,
              textTransform: 'uppercase',
              letterSpacing: 1.5,
              color: 'var(--ink-faint)',
            }}
          >
            https
          </div>
        </div>

        {/* Server compute box */}
        <div
          style={{
            border: '1px dashed var(--rule-strong)',
            borderRadius: 10,
            padding: 12,
            background: 'var(--term-bg)',
            color: 'var(--term-ink)',
          }}
        >
          <div
            style={{
              fontSize: 11,
              textTransform: 'uppercase',
              letterSpacing: 1.2,
              color: 'var(--term-dim)',
              marginBottom: 6,
            }}
          >
            server computes
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 13,
              color: 'var(--term-ink)',
              padding: '8px 0',
              textAlign: 'center',
            }}
          >
            <span style={{ color: 'var(--term-dim)' }}>out ←</span>{' '}
            <span style={{ color: 'oklch(0.8 0.12 210)' }}>ctₐ ⊞ ct_b</span>
          </div>
          <div
            style={{
              fontSize: 11,
              color: 'var(--term-dim)',
              fontFamily: 'var(--font-mono)',
              textAlign: 'center',
            }}
          >
            {ctSum ? 'done · ' + formatBytes(ctSum.byteLength) : 'awaiting input…'}
          </div>
        </div>
      </div>

      {/* Result ciphertext */}
      <div
        style={{
          marginTop: 10,
          padding: 14,
          borderRadius: 10,
          background: ctSum ? 'var(--cipher-soft)' : 'var(--bg-tint)',
          border: '1px solid var(--rule)',
          opacity: ctSum ? 1 : 0.55,
          transition: 'all 0.4s ease',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ flexShrink: 0 }}>
            {ctSum ? (
              <Fingerprint bytes={ctSum} size={64} />
            ) : (
              <div
                style={{
                  width: 64,
                  height: 64,
                  background: 'var(--card)',
                  border: '1px dashed var(--rule)',
                  borderRadius: 6,
                }}
              />
            )}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                marginBottom: 6,
                flexWrap: 'wrap',
              }}
            >
              <span style={{ fontFamily: 'var(--font-serif)', fontSize: 18, fontWeight: 500 }}>
                Encrypted result
              </span>
              {ctSum && (
                <Chip tone="cipher" style={{ fontSize: 10 }}>
                  ct_sum
                </Chip>
              )}
            </div>
            {ctSum ? (
              <>
                <ByteViewer bytes={ctSum} />
                <div style={{ marginTop: 8 }}>
                  <NoiseMeter bytes={ctSum} opCount={1} label="accumulated noise" />
                </div>
              </>
            ) : (
              <div style={{ fontSize: 12, color: 'var(--ink-faint)' }}>
                The server will return a fresh ciphertext encoding the sum.
              </div>
            )}
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 14 }}>
        <Btn onClick={onEvaluate} disabled={!ready || busy} primary tone="cipher">
          {phase === 'sending' || phase === 'evaluating'
            ? 'Computing on server…'
            : done
            ? 'Run again'
            : 'Send & evaluate'}
        </Btn>
        {!ready && !done && (
          <span style={{ fontSize: 12, color: 'var(--ink-faint)' }}>↑ Encrypt inputs first</span>
        )}
      </div>
    </Card>
  )
}
