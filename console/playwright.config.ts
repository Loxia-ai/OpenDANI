import { defineConfig } from "@playwright/test";

// E2E smoke against a LIVE dani-agent controller serving the embedded console (not a dev server):
// start one first, e.g.
//   dani-agent controller --gateway 127.0.0.1:8081 ... --console-auth
// then: DANI_GATEWAY=http://127.0.0.1:8081 npx playwright test
export default defineConfig({
  testDir: "./e2e",
  timeout: 30000,
  use: {
    baseURL: process.env.DANI_GATEWAY ?? "http://127.0.0.1:8081",
  },
});
