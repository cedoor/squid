import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { Evaluator } from 'squid-js/server'

const PARAMS_SET = process.env.POULPY_PARAMS_SET ?? 'test'

const ekPath =
  process.env.POULPY_DEMO_EK_PATH ?? join(process.cwd(), 'data', 'demo-ek.test.bin')

let cached: Evaluator | null = null

export function getDemoEvaluator(): Evaluator {
  if (cached) return cached
  if (!existsSync(ekPath)) {
    throw new Error(
      `Missing demo evaluation key at ${ekPath}. Run: pnpm --filter @squid-js/demo run gen-demo-ek`,
    )
  }
  cached = Evaluator.load(readFileSync(ekPath), PARAMS_SET)
  return cached
}
