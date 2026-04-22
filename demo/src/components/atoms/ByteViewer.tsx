import { bytesToHexPreview } from '@/lib/fingerprint'

interface ByteViewerProps {
  bytes: Uint8Array
  label?: string
  accent?: string
  maxBytes?: number
}

export function ByteViewer({ bytes, label, accent = 'var(--cipher)', maxBytes = 24 }: ByteViewerProps) {
  const hex = bytesToHexPreview(bytes, maxBytes)
  return (
    <div
      style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 11,
        color: 'var(--ink-soft)',
        background: 'var(--bg-tint)',
        border: '1px dashed var(--rule)',
        borderRadius: 8,
        padding: '8px 10px',
        lineHeight: 1.5,
        wordBreak: 'break-all',
      }}
    >
      {label && (
        <span style={{ color: accent, fontWeight: 500 }}>{label} </span>
      )}
      <span style={{ color: 'var(--ink-faint)' }}>{hex}</span>
    </div>
  )
}
