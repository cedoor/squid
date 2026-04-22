'use client'

import { useState, type CSSProperties, type ReactNode } from 'react'

interface BtnProps {
  children: ReactNode
  onClick?: () => void
  disabled?: boolean
  primary?: boolean
  tone?: 'cipher' | 'plain' | 'key' | 'default'
  small?: boolean
  style?: CSSProperties
}

export function Btn({ children, onClick, disabled, primary, tone = 'default', small, style }: BtnProps) {
  const [hover, setHover] = useState(false)

  const base: CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 8,
    border: '1px solid var(--rule-strong)',
    borderRadius: 999,
    padding: small ? '6px 14px' : '9px 18px',
    background: 'var(--card)',
    color: 'var(--ink)',
    fontWeight: 500,
    fontSize: small ? 13 : 14,
    cursor: disabled ? 'not-allowed' : 'pointer',
    opacity: disabled ? 0.45 : 1,
    transition: 'transform 0.08s ease, background 0.15s ease, border-color 0.15s ease',
    transform: hover && !disabled ? 'translateY(-1px)' : 'none',
    fontFamily: 'var(--font-sans)',
  }

  const primaryStyle: CSSProperties = primary
    ? {
        background:
          tone === 'cipher'
            ? 'var(--cipher)'
            : tone === 'plain'
            ? 'var(--plain)'
            : tone === 'key'
            ? 'var(--key)'
            : 'var(--ink)',
        color: 'var(--bg)',
        borderColor: 'transparent',
      }
    : {}

  return (
    <button
      onClick={disabled ? undefined : onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      disabled={disabled}
      style={{ ...base, ...primaryStyle, ...style }}
    >
      {children}
    </button>
  )
}
