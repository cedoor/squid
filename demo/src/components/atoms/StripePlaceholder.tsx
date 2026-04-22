interface StripePlaceholderProps {
  label: string
  height?: number
}

export function StripePlaceholder({ label, height = 80 }: StripePlaceholderProps) {
  return (
    <div
      style={{
        height,
        borderRadius: 8,
        background:
          'repeating-linear-gradient(45deg, var(--bg-tint), var(--bg-tint) 8px, var(--rule) 8px, var(--rule) 9px)',
        border: '1px dashed var(--rule-strong)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: 'var(--font-mono)',
        fontSize: 11,
        color: 'var(--ink-faint)',
        letterSpacing: 1,
        textTransform: 'uppercase',
      }}
    >
      {label}
    </div>
  )
}
