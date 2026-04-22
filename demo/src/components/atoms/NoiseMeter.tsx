import { deriveNoise } from '@/lib/fingerprint'

interface NoiseMeterProps {
  bytes: Uint8Array
  opCount?: number
  label?: string
}

export function NoiseMeter({ bytes, opCount = 0, label = 'noise' }: NoiseMeterProps) {
  const noise = deriveNoise(bytes, opCount)
  const pct = Math.min(1, Math.max(0, noise))
  const danger = pct > 0.4
  const color = danger ? 'var(--warn)' : 'var(--ok)'
  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          fontSize: 11,
          color: 'var(--ink-faint)',
        }}
      >
        <span style={{ textTransform: 'uppercase', letterSpacing: 1 }}>{label}</span>
        <span style={{ fontFamily: 'var(--font-mono)' }}>
          {(pct * 100).toFixed(1)}%{' '}
          <span style={{ color: 'var(--ink-faint)' }}>/ 50% margin</span>
        </span>
      </div>
      <div
        style={{
          marginTop: 4,
          height: 6,
          borderRadius: 999,
          background: 'var(--bg-tint)',
          border: '1px solid var(--rule)',
          overflow: 'hidden',
          position: 'relative',
        }}
      >
        <div
          style={{
            position: 'absolute',
            left: '50%',
            top: -2,
            bottom: -2,
            width: 1,
            background: 'var(--rule-strong)',
          }}
        />
        <div
          style={{
            width: `${pct * 100}%`,
            height: '100%',
            background: color,
            transition: 'width 0.5s ease',
          }}
        />
      </div>
    </div>
  )
}
