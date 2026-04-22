import { existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const f = join(root, 'data', 'demo-ek.test.bin')
if (!existsSync(f)) {
  console.log('demo: generating data/demo-ek.test.bin (one-time, ~30 MiB)…')
  const r = spawnSync(process.execPath, [join(root, 'scripts', 'generate-demo-ek.mjs')], {
    stdio: 'inherit',
    cwd: root,
  })
  process.exit(r.status ?? 1)
}
