'use client'

interface NumberPadProps {
  value: number
  onChange: (n: number) => void
  accent?: string
  label?: string
  disabled?: boolean
}

export function NumberPad({ value, onChange, accent = 'var(--plain)', label, disabled }: NumberPadProps) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {label && (
        <div
          style={{
            fontSize: 11.5,
            color: 'var(--ink-faint)',
            textTransform: 'uppercase',
            letterSpacing: 1,
          }}
        >
          {label}
        </div>
      )}
      <div
        className="demo-numpad"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(8, 1fr)',
          gap: 4,
        }}
      >
        {Array.from({ length: 16 }, (_, i) => i).map((n) => {
          const selected = n === value
          return (
            <button
              key={n}
              onClick={() => !disabled && onChange(n)}
              disabled={disabled}
              style={{
                aspectRatio: '1',
                border: '1px solid var(--rule)',
                background: selected ? accent : 'var(--card)',
                color: selected ? 'var(--bg)' : 'var(--ink-soft)',
                borderColor: selected ? 'transparent' : 'var(--rule)',
                borderRadius: 8,
                fontFamily: 'var(--font-mono)',
                fontSize: 13,
                fontWeight: 500,
                cursor: disabled ? 'not-allowed' : 'pointer',
                transition: 'all 0.12s ease',
                opacity: disabled ? 0.5 : 1,
              }}
            >
              {n}
            </button>
          )
        })}
      </div>
    </div>
  )
}
