import { test, expect } from "@playwright/test";

// Keygen runs in a wasm worker; duration depends on the chosen `paramsSet`
// (demo default `test`). Allow extra time for cold CI / slow runners.
const KEYGEN_TIMEOUT_MS = 30_000;
const COMPUTE_TIMEOUT_MS = 15_000;

test.setTimeout(KEYGEN_TIMEOUT_MS + COMPUTE_TIMEOUT_MS + 30_000);

test("browser keygen → server FHE add → browser decrypt", async ({ page }) => {
  page.on("pageerror", (err) => console.log(`[e2e] pageerror: ${err.message}`));
  page.on("requestfailed", (req) =>
    console.log(
      `[e2e] requestfailed: ${req.method()} ${req.url()} — ${req.failure()?.errorText}`,
    ),
  );

  await page.goto("/");

  // Step 1 — derive keys from demo seed (WASM keygen in worker, may take a while)
  await page.getByRole("button", { name: /Derive keys/i }).click();
  await expect(
    page.getByRole("button", { name: /Encrypt a & b/i }),
  ).toBeEnabled({ timeout: KEYGEN_TIMEOUT_MS });

  // Step 2 — encrypt (defaults: a=7, b=5)
  await page.getByRole("button", { name: /Encrypt a & b/i }).click();
  await expect(
    page.getByRole("button", { name: /Send & evaluate/i }),
  ).toBeEnabled({ timeout: 10_000 });

  // Step 3 — send to server and evaluate homomorphically
  await page.getByRole("button", { name: /Send & evaluate/i }).click();
  await expect(
    page.getByRole("button", { name: /Decrypt result/i }),
  ).toBeEnabled({ timeout: COMPUTE_TIMEOUT_MS });

  // Step 4 — decrypt result locally; 7 + 5 = 12
  await page.getByRole("button", { name: /Decrypt result/i }).click();
  await expect(page.getByTestId("decrypt-result")).toHaveText("12", {
    timeout: 10_000,
  });
});
