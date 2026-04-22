export type Phase =
  | 'idle'
  | 'keygen'
  | 'encrypting'
  | 'sending'
  | 'evaluating'
  | 'decrypting'

export type MascotMood = 'idle' | 'thinking' | 'happy' | 'locked'

export type LogKind = 'info' | 'dim' | 'ok' | 'warn' | 'err' | 'in' | 'out'

export interface LogEntry {
  id: number
  ts: string
  kind: LogKind
  text: string
}

export interface FheState {
  phase: Phase
  // Step 1 — Keygen
  skPreview: Uint8Array | null
  ekBytes: Uint8Array | null
  // Step 2 — Encrypt
  a: number
  b: number
  ctA: Uint8Array | null
  ctB: Uint8Array | null
  // Step 3 — Evaluate
  ctSum: Uint8Array | null
  // Step 4 — Decrypt
  result: number | null
  // Terminal
  logs: LogEntry[]
  error: string | null
}
