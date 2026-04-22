/** 96-byte keygen seeds — must match `scripts/generate-demo-ek.mjs` and `data/demo-ek.test.bin`. */
export const DEMO_KEY_SEED = ((() => {
  const s = new Uint8Array(96)
  for (let i = 0; i < 96; i++) {
    s[i] = (i * 13 + 1) & 0xff
  }
  return s
})())
