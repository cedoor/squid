/**
 * Returns 64 byte values (0–255) deterministically from ciphertext bytes.
 * Used to render the 8×8 fingerprint grid.
 */
export function deriveGrid(bytes: Uint8Array): number[] {
  const out: number[] = []
  for (let i = 0; i < 64; i++) {
    out.push(bytes[(i * 7 + 3) % bytes.length])
  }
  return out
}

/**
 * Returns a simulated noise fraction (0–1) from ciphertext bytes.
 * Fresh ciphertexts land at ~6–12%. After homomorphic add: ~14–22%.
 * opCount=0 → fresh, opCount=1 → after one server add.
 */
export function deriveNoise(bytes: Uint8Array, opCount = 0): number {
  let h = 0
  for (let i = 0; i < Math.min(bytes.length, 16); i++) {
    h = ((h * 31) ^ bytes[i]) >>> 0
  }
  const base = opCount === 0 ? 0.05 : 0.13
  const spread = 0.07
  const frac = (h % 1000) / 1000
  return Math.min(0.48, base + frac * spread)
}

/** Returns the first maxBytes bytes as a hex string, e.g. "0a 3f c1 …" */
export function bytesToHexPreview(bytes: Uint8Array, maxBytes = 24): string {
  const len = Math.min(bytes.length, maxBytes)
  const parts: string[] = []
  for (let i = 0; i < len; i++) {
    parts.push(bytes[i].toString(16).padStart(2, '0'))
  }
  return parts.join(' ') + (bytes.length > maxBytes ? ' …' : '')
}
