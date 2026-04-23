'use client'

import { useCallback, useEffect, useReducer, useRef } from 'react'
import type { FheState, LogEntry, LogKind, Phase } from '@/lib/fhe-types'
import { DEMO_KEY_SEED } from '@/lib/demo-seed'
import { formatBytes, packCiphertexts } from '@/lib/pack'

const API_BASE = '/api'
const PARAMS_SET =
  (process.env.NEXT_PUBLIC_POULPY_PARAMS_SET as string | undefined) ?? 'test'
const OCTET = 'application/octet-stream'

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

type Action =
  | { type: 'SET_PHASE'; phase: Phase }
  | { type: 'KEYGEN_DONE'; skPreview: Uint8Array; ekBytes: Uint8Array }
  | { type: 'ENCRYPT_DONE'; ctA: Uint8Array; ctB: Uint8Array }
  | { type: 'EVALUATE_DONE'; ctSum: Uint8Array }
  | { type: 'DECRYPT_DONE'; result: number }
  | { type: 'SET_A'; a: number }
  | { type: 'SET_B'; b: number }
  | { type: 'LOG'; entry: LogEntry }
  | { type: 'ERROR'; message: string }
  | { type: 'RESET' }

const initial: FheState = {
  phase: 'idle',
  skPreview: null,
  ekBytes: null,
  a: 7,
  b: 5,
  ctA: null,
  ctB: null,
  ctSum: null,
  result: null,
  logs: [],
  error: null,
}

function reducer(state: FheState, action: Action): FheState {
  switch (action.type) {
    case 'SET_PHASE':
      return { ...state, phase: action.phase, error: null }
    case 'KEYGEN_DONE':
      return {
        ...state,
        phase: 'idle',
        skPreview: action.skPreview,
        ekBytes: action.ekBytes,
        ctA: null,
        ctB: null,
        ctSum: null,
        result: null,
        error: null,
      }
    case 'ENCRYPT_DONE':
      return { ...state, phase: 'idle', ctA: action.ctA, ctB: action.ctB, ctSum: null, result: null, error: null }
    case 'EVALUATE_DONE':
      return { ...state, phase: 'idle', ctSum: action.ctSum, result: null, error: null }
    case 'DECRYPT_DONE':
      return { ...state, phase: 'idle', result: action.result, error: null }
    case 'SET_A':
      return { ...state, a: action.a, ctA: null, ctB: null, ctSum: null, result: null }
    case 'SET_B':
      return { ...state, b: action.b, ctA: null, ctB: null, ctSum: null, result: null }
    case 'LOG':
      return { ...state, logs: [...state.logs, action.entry] }
    case 'ERROR':
      return { ...state, phase: 'idle', error: action.message }
    case 'RESET':
      return { ...initial, logs: [] }
    default:
      return state
  }
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useFhe() {
  const [state, dispatch] = useReducer(reducer, initial)
  const clientRef = useRef<import('@cedoor/squid/client').PoulpyClient | null>(null)
  const logIdRef = useRef(0)
  const startRef = useRef(Date.now())

  const log = useCallback((kind: LogKind, text: string) => {
    const elapsed = (Date.now() - startRef.current) / 1000
    dispatch({
      type: 'LOG',
      entry: { id: logIdRef.current++, ts: elapsed.toFixed(2) + 's', kind, text },
    })
  }, [])

  const doKeygen = useCallback(async () => {
    dispatch({ type: 'SET_PHASE', phase: 'keygen' })
    startRef.current = Date.now()
    logIdRef.current = 0
    log('info', 'client: building CGGI session from demo seed (deterministic)…')
    log('dim', `  scheme=CGGI  paramsSet=${PARAMS_SET}`)
    try {
      const { PoulpyClient } = await import('@cedoor/squid/client')
      const client = await PoulpyClient.create({ paramsSet: PARAMS_SET, seeds: DEMO_KEY_SEED })
      clientRef.current = client

      const seeds = await client.exportSeeds()
      const skPreview = seeds.slice(0, 48)
      const ekBytes = client.evaluationKey

      log('ok', `client: sk ready (${formatBytes(seeds.byteLength)}) — stays local`)
      log('info', 'client: EK matches server (same seed; server loads demo-ek at deploy)')
      log('dim', 'server: stateless /api/add, waiting for ciphertexts…')

      dispatch({ type: 'KEYGEN_DONE', skPreview, ekBytes })
    } catch (err) {
      log('err', `client: keygen failed — ${(err as Error).message}`)
      dispatch({ type: 'ERROR', message: (err as Error).message })
    }
  }, [log])

  const doEncrypt = useCallback(
    async (a: number, b: number) => {
      const client = clientRef.current
      if (!client) return
      dispatch({ type: 'SET_PHASE', phase: 'encrypting' })
      log('info', `client: encrypting a=${a}`)
      try {
        const ctA = await client.encryptU32(a)
        log('ok', `client: ctₐ ready (${formatBytes(ctA.byteLength)})`)
        log('info', `client: encrypting b=${b}`)
        const ctB = await client.encryptU32(b)
        log('ok', `client: ct_b ready (${formatBytes(ctB.byteLength)})`)
        dispatch({ type: 'ENCRYPT_DONE', ctA, ctB })
      } catch (err) {
        log('err', `client: encrypt failed — ${(err as Error).message}`)
        dispatch({ type: 'ERROR', message: (err as Error).message })
      }
    },
    [log],
  )

  const doEvaluate = useCallback(
    async (ctA: Uint8Array, ctB: Uint8Array) => {
      dispatch({ type: 'SET_PHASE', phase: 'sending' })
      const payloadSize = formatBytes(ctA.byteLength + ctB.byteLength)
      log('info', `client → server: POST /api/add (${payloadSize})`)
      try {
        const body = packCiphertexts(ctA, ctB)
        dispatch({ type: 'SET_PHASE', phase: 'evaluating' })
        log('in', 'server: received ciphertexts, computing ctₐ ⊞ ct_b')
        const resp = await fetch(`${API_BASE}/add`, {
          method: 'POST',
          headers: { 'Content-Type': OCTET },
          body: body as BodyInit,
        })
        if (!resp.ok) {
          const body2 = (await resp.json().catch(() => ({}))) as { error?: string }
          throw new Error(body2.error ?? `/add failed (${resp.status})`)
        }
        const ctSum = new Uint8Array(await resp.arrayBuffer())
        log('ok', `server: ct_sum ready (${formatBytes(ctSum.byteLength)})`)
        log('out', 'server → client: 200 OK')
        dispatch({ type: 'EVALUATE_DONE', ctSum })
      } catch (err) {
        log('err', `evaluate failed — ${(err as Error).message}`)
        dispatch({ type: 'ERROR', message: (err as Error).message })
      }
    },
    [log],
  )

  const doDecrypt = useCallback(
    async (ctSum: Uint8Array) => {
      const client = clientRef.current
      if (!client) return
      dispatch({ type: 'SET_PHASE', phase: 'decrypting' })
      log('info', 'client: Dec(sk, ct_sum)…')
      try {
        const result = await client.decryptU32(ctSum)
        log('ok', `client: plaintext = ${result}`)
        dispatch({ type: 'DECRYPT_DONE', result })
      } catch (err) {
        log('err', `client: decrypt failed — ${(err as Error).message}`)
        dispatch({ type: 'ERROR', message: (err as Error).message })
      }
    },
    [log],
  )

  const doReset = useCallback(() => {
    clientRef.current = null
    dispatch({ type: 'RESET' })
  }, [])

  const setA = useCallback((a: number) => dispatch({ type: 'SET_A', a }), [])
  const setB = useCallback((b: number) => dispatch({ type: 'SET_B', b }), [])

  // Cleanup worker on unmount
  useEffect(() => {
    return () => {
      clientRef.current = null
    }
  }, [])

  return {
    state,
    doKeygen,
    doEncrypt,
    doEvaluate,
    doDecrypt,
    doReset,
    setA,
    setB,
  }
}
