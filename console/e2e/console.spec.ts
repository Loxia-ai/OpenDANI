import { expect, test } from "@playwright/test";

// The whole console, served from inside the Go binary, against the real gateway.
test("console renders live data from the embedded bundle", async ({ page }) => {
  await page.goto("/console/");
  await expect(page).toHaveTitle(/DANI Console/);
  // all six tabs
  for (const tab of ["Overview", "Nodes", "Datasets", "Training", "Models", "Audit"]) {
    await expect(page.getByRole("tab", { name: tab })).toBeVisible();
  }
  // live fleet + verified audit chain on the overview
  await expect(page.getByRole("heading", { name: /Live fleet/ })).toBeVisible();
  await expect(page.getByText("chain verified")).toBeVisible();
});

test("nodes tab shows the merged registry with actions", async ({ page }) => {
  await page.goto("/console/");
  await page.getByRole("tab", { name: "Nodes" }).click();
  await expect(page.getByText("Fleet nodes")).toBeVisible();
  await expect(page.getByRole("button", { name: "Drain", exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Revoke" }).first()).toBeVisible();
});

test("datasets tab offers sources and the upload form", async ({ page }) => {
  await page.goto("/console/");
  await page.getByRole("tab", { name: "Datasets" }).click();
  await expect(page.getByText("Upload a dataset")).toBeVisible();
  await expect(page.getByLabel("upload-docs")).toBeVisible();
});

test("operator sign-in reflects identity and roles in the header", async ({ page }) => {
  const token = process.env.DANI_OPERATOR_TOKEN;
  test.skip(!token, "DANI_OPERATOR_TOKEN not set (controller without --console-auth)");
  await page.goto("/console/");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByLabel("operator token").fill(token!);
  await page.getByRole("button", { name: "Sign in" }).last().click();
  await expect(page.getByText("Sign out")).toBeVisible();
});

test("topology tab renders the interactive React Flow graph", async ({ page }) => {
  await page.goto("/console/");
  await page.getByRole("tab", { name: "Topology" }).click();
  await expect(page.getByText("Network topology")).toBeVisible();
  // React Flow canvas mounts, the controller hub renders, and the overlay toggle works
  await expect(page.locator(".react-flow")).toBeVisible();
  await expect(page.getByText("ctrl-001")).toBeVisible();
  await page.getByRole("button", { name: "WireGuard" }).click();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
});

test("nodes tab shows renewal-status buckets", async ({ page }) => {
  await page.goto("/console/");
  await page.getByRole("tab", { name: "Nodes" }).click();
  await expect(page.getByText("Fleet nodes")).toBeVisible();
  await expect(page.getByText("cert due soon")).toBeVisible();
  // at least one node shows a renewal-status badge (healthy for fresh 90d certs)
  await expect(page.getByText("healthy").first()).toBeVisible();
});

test("playground: pick a model, chat, see the routing proof", async ({ page }) => {
  await page.goto("/console/");
  await page.getByRole("tab", { name: "Playground" }).click();
  await page.getByLabel("message").fill("summarize the parental leave policy");
  await page.getByRole("button", { name: "Send" }).click();
  await expect(page.getByText(/answered by/)).toBeVisible({ timeout: 15000 });
});

test("help drawer + api access card guide a new user", async ({ page }) => {
  await page.goto("/console/");
  await page.getByLabel("help").click();
  await expect(page.getByText("How DANI works")).toBeVisible();
  await expect(page.getByText(/console-operators.json/)).toBeVisible();
  await page.getByText("✕ close").click();
  await expect(page.getByText("Connect your applications")).toBeVisible();
});

test("training wizard walks data → model → train (guided, plain language)", async ({ page }) => {
  const token = process.env.DANI_OPERATOR_TOKEN;
  await page.goto("/console/");
  if (token) {
    await page.evaluate((t) => localStorage.setItem("dani-operator-token", t), token);
    await page.reload();
  }
  await page.getByRole("tab", { name: "Training" }).click();
  await expect(page.getByText("Teach a model")).toBeVisible();
  // bring-my-own path with the format picker (facts / Q&A / conversations / tool-calling)
  await page.getByRole("button", { name: /Bring my own/ }).click();
  await expect(page.getByText(/What do you want to teach it/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Tool calling (agents)" })).toBeVisible();
  await page.getByLabel("dataset-name").fill("e2e-demo");
  await page.getByLabel("dataset-text").fill("# note\nRefunds within 30 days.\nSupport is Mon-Fri.");
  await expect(page.getByText(/2 examples/)).toBeVisible();
  await page.getByText("Next →").click();
  await expect(page.getByText(/Which model should we teach/)).toBeVisible();
  await page.getByText("Next →").click();
  await expect(page.getByText(/Start training/)).toBeVisible();
});
