/** Pack two ciphertexts as u32-le(a.length) || a || b. */
export function packCiphertexts(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + a.length + b.length)
  new DataView(out.buffer).setUint32(0, a.length, true)
  out.set(a, 4)
  out.set(b, 4 + a.length)
  return out
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`
}
