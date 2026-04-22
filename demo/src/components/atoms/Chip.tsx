import type { CSSProperties, ReactNode } from 'react'

type Tone = 'default' | 'plain' | 'cipher' | 'key' | 'ink' | 'ok' | 'warn'

const toneStyles: Record<Tone, CSSProperties> = {
  default: {},
  plain: { background: 'var(--plain-soft)', color: 'oklch(0.35 0.1 25)', borderColor: 'transparent' },
  cipher: { background: 'var(--cipher-soft)', color: 'oklch(0.32 0.08 210)', borderColor: 'transparent' },
  key: { background: 'var(--key-soft)', color: 'oklch(0.32 0.08 290)', borderColor: 'transparent' },
  ink: { background: 'var(--ink)', color: 'var(--bg)', borderColor: 'transparent' },
  ok: { background: 'oklch(0.92 0.06 150)', color: 'oklch(0.28 0.08 150)', borderColor: 'transparent' },
  warn: { background: 'oklch(0.92 0.06 70)', color: 'oklch(0.38 0.1 70)', borderColor: 'transparent' },
}

interface ChipProps {
  children: ReactNode
  tone?: Tone
  style?: CSSProperties
}

export function Chip({ children, tone = 'default', style }: ChipProps) {
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '3px 9px',
        borderRadius: 999,
        fontSize: 11.5,
        fontWeight: 500,
        letterSpacing: 0.2,
        border: '1px solid var(--rule)',
        background: 'var(--bg-tint)',
        color: 'var(--ink-soft)',
        fontFamily: 'var(--font-mono)',
        ...toneStyles[tone],
        ...style,
      }}
    >
      {children}
    </span>
  )
}
