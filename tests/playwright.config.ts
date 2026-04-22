import { defineConfig } from "@playwright/test";

// The root `pnpm dev` runs the Next.js demo; reuseExistingServer lets a
// developer keep it open and just run `pnpm test` on the side.
export default defineConfig({
  testDir: ".",
  timeout: 120_000,
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: "http://localhost:3000",
  },
  webServer: {
    command: "pnpm -w dev",
    url: "http://localhost:3000",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
