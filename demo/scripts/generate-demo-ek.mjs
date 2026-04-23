#!/usr/bin/env node
/**
 * Builds `data/demo-ek.test.bin` from the same 96-byte seed as `src/lib/demo-seed.ts`.
 * Requires built squid-js wasm (workspace / published package).
 */
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

import init, { Session } from '@cedoor/squid/wasm/squid_wasm.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const outDir = join(__dirname, '..', 'data')
const outFile = join(outDir, 'demo-ek.test.bin')

const require = createRequire(import.meta.url)
const wasmPath = require.resolve('@cedoor/squid/wasm/squid_wasm_bg.wasm')

const seeds = new Uint8Array(96)
for (let i = 0; i < 96; i++) {
  seeds[i] = (i * 13 + 1) & 0xff
}

const paramsSet = process.env.POULPY_PARAMS_SET ?? 'test'

await init({ module_or_path: readFileSync(wasmPath) })
const session = Session.fromSeeds(seeds, paramsSet)
const ek = session.evaluationKeyBytes()
mkdirSync(outDir, { recursive: true })
writeFileSync(outFile, Buffer.from(ek))
console.log(`wrote ${outFile} (${ek.length} bytes) for paramsSet=${paramsSet}`)
