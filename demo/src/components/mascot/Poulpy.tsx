import type { CSSProperties } from 'react'
import type { MascotMood } from '@/lib/fhe-types'

interface PouplypProps {
  size?: number
  mood?: MascotMood
  tint?: string
}

export function Poulpy({ size = 120, mood = 'idle', tint = 'var(--plain)' }: PouplypProps) {
  const eyeShift = mood === 'thinking' ? -1.2 : 0
  const eyeY = mood === 'happy' ? 38 : 40
  const eyeScaleY = mood === 'happy' ? 0.25 : 1
  const mouth =
    mood === 'happy'
      ? 'M 46 54 Q 60 62 74 54'
      : mood === 'thinking'
      ? 'M 52 56 Q 60 56 68 56'
      : mood === 'locked'
      ? 'M 52 56 L 68 56'
      : 'M 52 56 Q 60 58 68 56'

  const tentacles: Array<{ d: string; delay: number }> = [
    { d: 'M 22 60 Q 10 76 14 96 Q 20 108 12 116', delay: 0 },
    { d: 'M 32 70 Q 24 92 32 108 Q 38 116 32 122', delay: 0.2 },
    { d: 'M 48 76 Q 46 100 52 116 Q 56 122 50 128', delay: 0.4 },
    { d: 'M 72 76 Q 74 100 68 116 Q 64 122 70 128', delay: 0.3 },
    { d: 'M 88 70 Q 96 92 88 108 Q 82 116 88 122', delay: 0.1 },
    { d: 'M 98 60 Q 110 76 106 96 Q 100 108 108 116', delay: 0.5 },
  ]

  return (
    <svg
      viewBox="0 0 120 140"
      width={size}
      height={size * (140 / 120)}
      style={{ display: 'block', overflow: 'visible' }}
      aria-hidden
    >
      <ellipse cx="60" cy="128" rx="34" ry="4" fill="oklch(0 0 0 / 0.08)" />
      <g fill="none" stroke={tint} strokeWidth="8" strokeLinecap="round" opacity="0.9">
        {tentacles.map((t, i) => (
          <path
            key={i}
            d={t.d}
            style={
              {
                transformOrigin: '60px 60px',
                animation: `poulpy-wiggle 3.2s ease-in-out ${t.delay}s infinite`,
              } as CSSProperties
            }
          />
        ))}
      </g>
      <path
        d="M 18 56 Q 18 22 60 22 Q 102 22 102 56 Q 102 72 88 76 L 32 76 Q 18 72 18 56 Z"
        fill={tint}
      />
      <ellipse cx="44" cy="36" rx="10" ry="6" fill="oklch(1 0 0 / 0.35)" />
      <g fill="oklch(0.2 0.015 60)">
        <ellipse cx={48 + eyeShift} cy={eyeY} rx="3" ry={3 * eyeScaleY} />
        <ellipse cx={72 + eyeShift} cy={eyeY} rx="3" ry={3 * eyeScaleY} />
      </g>
      {mood !== 'happy' && (
        <g fill="oklch(1 0 0 / 0.9)">
          <circle cx={49 + eyeShift} cy={eyeY - 1} r="0.8" />
          <circle cx={73 + eyeShift} cy={eyeY - 1} r="0.8" />
        </g>
      )}
      <path
        d={mouth}
        stroke="oklch(0.2 0.015 60)"
        strokeWidth="1.8"
        fill="none"
        strokeLinecap="round"
      />
      <circle cx="38" cy="52" r="3.5" fill="oklch(0.75 0.12 20 / 0.35)" />
      <circle cx="82" cy="52" r="3.5" fill="oklch(0.75 0.12 20 / 0.35)" />
      {mood === 'locked' && (
        <g transform="translate(50, 62)">
          <rect x="0" y="5" width="20" height="14" rx="3" fill="oklch(0.5 0.12 290)" />
          <path
            d="M 4 5 Q 4 0 10 0 Q 16 0 16 5"
            stroke="oklch(0.5 0.12 290)"
            strokeWidth="2.5"
            fill="none"
          />
          <circle cx="10" cy="12" r="2" fill="var(--bg)" />
        </g>
      )}
    </svg>
  )
}
