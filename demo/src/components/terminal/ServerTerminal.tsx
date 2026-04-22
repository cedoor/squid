'use client'

import { useEffect, useRef } from 'react'
import type { LogEntry, LogKind } from '@/lib/fhe-types'

interface ServerTerminalProps {
  logs: LogEntry[]
  running: boolean
}

const colorFor: Record<LogKind, string> = {
  info: 'var(--term-ink)',
  dim: 'var(--term-dim)',
  ok: 'oklch(0.78 0.14 150)',
  warn: 'oklch(0.82 0.14 70)',
  err: 'oklch(0.7 0.18 25)',
  in: 'oklch(0.78 0.12 210)',
  out: 'oklch(0.78 0.12 290)',
}

const prefixFor: Record<LogKind, string> = {
  info: '·',
  dim: ' ',
  ok: '✓',
  warn: '!',
  err: '✗',
  in: '←',
  out: '→',
}

function Caret() {
  return (
    <span
      style={{
        display: 'inline-block',
        width: 7,
        height: 13,
        background: 'var(--term-ink)',
        verticalAlign: 'text-bottom',
        animation: 'blink 1s step-end infinite',
      }}
    />
  )
}

function TermLine({ line }: { line: LogEntry }) {
  return (
    <div style={{ color: colorFor[line.kind], whiteSpace: 'pre-wrap' }}>
      <span style={{ color: 'var(--term-dim)', marginRight: 8 }}>[{line.ts}]</span>
      <span style={{ marginRight: 6 }}>{prefixFor[line.kind]}</span>
      {line.text}
    </div>
  )
}

export function ServerTerminal({ logs, running }: ServerTerminalProps) {
  const scrollerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = scrollerRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [logs])

  return (
    <div
      style={{
        background: 'var(--term-bg)',
        color: 'var(--term-ink)',
        borderRadius: 14,
        border: '1px solid oklch(0.28 0.02 260)',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        minHeight: 420,
      }}
    >
      {/* Terminal chrome */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          padding: '10px 14px',
          borderBottom: '1px solid oklch(0.28 0.02 260)',
          background: 'oklch(0.16 0.015 260)',
        }}
      >
        <div style={{ display: 'flex', gap: 6 }}>
          <div style={{ width: 10, height: 10, borderRadius: '50%', background: 'oklch(0.68 0.16 25)' }} />
          <div style={{ width: 10, height: 10, borderRadius: '50%', background: 'oklch(0.82 0.14 85)' }} />
          <div style={{ width: 10, height: 10, borderRadius: '50%', background: 'oklch(0.7 0.14 150)' }} />
        </div>
        <div
          style={{
            flex: 1,
            textAlign: 'center',
            fontFamily: 'var(--font-mono)',
            fontSize: 11.5,
            color: 'var(--term-dim)',
            letterSpacing: 0.5,
          }}
        >
          server ~ poulpy-eval · cggi
        </div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 5,
            fontFamily: 'var(--font-mono)',
            fontSize: 10.5,
            color: running ? 'oklch(0.75 0.15 150)' : 'var(--term-dim)',
          }}
        >
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: running ? 'oklch(0.75 0.15 150)' : 'var(--term-dim)',
              animation: running ? 'pulse 1.1s ease-in-out infinite' : 'none',
            }}
          />
          {running ? 'busy' : 'idle'}
        </div>
      </div>

      {/* Log area */}
      <div
        ref={scrollerRef}
        style={{
          flex: 1,
          padding: '14px 16px',
          fontFamily: 'var(--font-mono)',
          fontSize: 12,
          lineHeight: 1.65,
          overflowY: 'auto',
        }}
      >
        {logs.length === 0 && (
          <div style={{ color: 'var(--term-dim)' }}>
            <span style={{ color: 'oklch(0.75 0.15 150)' }}>$</span> ./poulpy-server --scheme cggi --listen :3001
            <br />
            <span style={{ color: 'var(--term-dim)' }}>waiting for client… </span>
            <Caret />
          </div>
        )}
        {logs.map((l) => (
          <TermLine key={l.id} line={l} />
        ))}
        {running && (
          <div style={{ color: 'var(--term-dim)' }}>
            <Caret />
          </div>
        )}
      </div>
    </div>
  )
}
