import type { CSSProperties, ReactNode } from 'react'

interface CardProps {
  children: ReactNode
  accent?: string
  style?: CSSProperties
}

export function Card({ children, accent, style }: CardProps) {
  return (
    <div
      className={accent ? 'demo-card demo-card-accent' : 'demo-card'}
      style={{
        background: 'var(--card)',
        border: '1px solid var(--rule)',
        borderRadius: 14,
        padding: 18,
        position: 'relative',
        ...(accent
          ? { boxShadow: `inset 4px 0 0 0 ${accent}`, paddingLeft: 22 }
          : {}),
        ...style,
      }}
    >
      {children}
    </div>
  )
}
