import { useMemo } from 'react'
import { deriveGrid } from '@/lib/fingerprint'

interface FingerprintProps {
  bytes: Uint8Array
  size?: number
  accent?: string
  active?: boolean
}

export function Fingerprint({ bytes, size = 64, accent = 'var(--cipher)', active = true }: FingerprintProps) {
  const cells = useMemo(() => deriveGrid(bytes), [bytes])
  const cell = size / 8
  return (
    <svg width={size} height={size} style={{ display: 'block', borderRadius: 6 }}>
      <rect width={size} height={size} fill="var(--bg-tint)" />
      {cells.map((b, i) => {
        const x = (i % 8) * cell
        const y = Math.floor(i / 8) * cell
        const alpha = (b / 255) * (active ? 1 : 0.4)
        return (
          <rect
            key={i}
            x={x + 0.5}
            y={y + 0.5}
            width={cell - 1}
            height={cell - 1}
            fill={accent}
            opacity={0.15 + alpha * 0.75}
          />
        )
      })}
    </svg>
  )
}
