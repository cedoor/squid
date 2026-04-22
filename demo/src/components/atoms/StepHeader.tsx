interface StepHeaderProps {
  n: string | number
  title: string
  subtitle?: string
  accent?: string
  done?: boolean
}

export function StepHeader({ n, title, subtitle, accent = 'var(--ink)', done }: StepHeaderProps) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, marginBottom: 16 }}>
      <div
        style={{
          width: 34,
          height: 34,
          borderRadius: '50%',
          background: done ? accent : 'var(--card)',
          color: done ? 'var(--bg)' : accent,
          border: `1.5px solid ${accent}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontFamily: 'var(--font-serif)',
          fontSize: 18,
          fontWeight: 500,
          flexShrink: 0,
          transition: 'all 0.3s ease',
        }}
      >
        {done ? '✓' : n}
      </div>
      <div style={{ flex: 1, paddingTop: 2 }}>
        <h3
          style={{
            margin: 0,
            fontFamily: 'var(--font-serif)',
            fontWeight: 500,
            fontSize: 22,
            letterSpacing: -0.2,
            lineHeight: 1.15,
          }}
        >
          {title}
        </h3>
        {subtitle && (
          <div style={{ fontSize: 13, color: 'var(--ink-soft)', marginTop: 3 }}>{subtitle}</div>
        )}
      </div>
    </div>
  )
}
