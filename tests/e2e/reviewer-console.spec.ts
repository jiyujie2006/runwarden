import { expect, test } from "@playwright/test";
import {
  renderDemoReviewerConsoleHtml,
  type DemoScenarioInput
} from "../../packages/webui/src/index";

const demoInputs: DemoScenarioInput[] = [
  {
    scenario: "prompt-injection-file-exfil",
    provider_calls: [
      {
        provider: "runwarden.input.inspect",
        action: "inspect",
        decision: "allowed",
        execution_status: "completed",
        side_effect_executed: false,
        obs_ref: "obs_prompt_file_inspect"
      },
      {
        provider: "external.mcp.filesystem.read_file",
        action: "read_file",
        decision: "requires_review",
        execution_status: "not_executed",
        side_effect_executed: false,
        obs_ref: "obs_prompt_file_read_review"
      },
      {
        provider: "external.api.request",
        action: "request",
        decision: "denied",
        execution_status: "not_executed",
        side_effect_executed: false,
        obs_ref: "obs_prompt_file_exfil_denied"
      }
    ],
    denials: [
      {
        provider: "external.api.request",
        action: "request",
        decision: "denied",
        execution_status: "not_executed",
        side_effect_executed: false,
        obs_ref: "obs_prompt_file_exfil_denied"
      }
    ],
    metrics: {
      trace_completeness: 1,
      report_citation_accuracy: 1
    },
    report: {
      claims: [
        {
          id: "file-exfil-denied",
          text: "The external API exfiltration request was denied before side effects.",
          obs_refs: ["obs_prompt_file_exfil_denied"]
        }
      ]
    },
    trace: [{ obs_id: "obs_prompt_file_exfil_denied" }],
    trace_verification: { verified: true },
    lint: { ok: true }
  },
  {
    scenario: "environment-local-web-risk",
    provider_calls: [
      {
        provider: "runwarden.input.inspect",
        action: "inspect",
        decision: "allowed",
        execution_status: "completed",
        side_effect_executed: false,
        obs_ref: "obs_local_web_inspect"
      },
      {
        provider: "external.mcp.browser.open_page",
        action: "open_page",
        decision: "denied",
        execution_status: "not_executed",
        side_effect_executed: false,
        obs_ref: "obs_local_web_browser_denied"
      }
    ],
    denials: [
      {
        provider: "external.mcp.browser.open_page",
        action: "open_page",
        decision: "denied",
        execution_status: "not_executed",
        side_effect_executed: false,
        obs_ref: "obs_local_web_browser_denied"
      }
    ],
    metrics: {
      trace_completeness: 1,
      report_citation_accuracy: 1
    },
    report: {
      claims: [
        {
          id: "local-web-denied",
          text: "Local/private network access was blocked before side effects.",
          obs_refs: ["obs_local_web_browser_denied"]
        }
      ]
    },
    trace: [{ obs_id: "obs_local_web_browser_denied" }],
    trace_verification: { verified: true },
    lint: { ok: true }
  }
];

const html = renderDemoReviewerConsoleHtml(demoInputs);

test.beforeEach(async ({ page }) => {
  await page.setContent(html, { waitUntil: "domcontentloaded" });
});

test("desktop reviewer console shows static scenario evidence without active control plane", async ({
  page
}, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "desktop layout check");

  await expect(page.locator(".rail")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Contest Reviewer Console" })).toBeVisible();
  await expect(page.locator(".summary .status-pill")).toHaveCount(5);
  await expect(page.locator(".scenario-card")).toHaveCount(2);
  await expect(page.getByLabel("prompt-injection-file-exfil")).toContainText("Requires review");
  await expect(page.getByLabel("prompt-injection-file-exfil")).toContainText(
    "obs_prompt_file_exfil_denied"
  );
  await expect(page.getByLabel("environment-local-web-risk")).toContainText("Denials");
  await expect(page.locator(".trace-verified")).toHaveCount(2);
  await expect(page.locator("script")).toHaveCount(0);
  await expect(page.locator("button")).toHaveCount(0);
  await expect(page.locator("form")).toHaveCount(0);

  const background = await page
    .locator("body")
    .evaluate((body) => getComputedStyle(body).backgroundImage);
  expect(background).toContain("linear-gradient");
  expect(background).not.toContain("radial-gradient");

  const railBox = await page.locator(".rail").boundingBox();
  const workspaceBox = await page.locator(".workspace").boundingBox();
  expect(railBox).not.toBeNull();
  expect(workspaceBox).not.toBeNull();
  expect(railBox!.x + railBox!.width).toBeLessThanOrEqual(workspaceBox!.x + 1);

  for (const pill of await page.locator(".status-pill").all()) {
    const box = await pill.boundingBox();
    expect(box?.height).toBeGreaterThanOrEqual(44);
  }

  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
    await page.evaluate(() => window.innerWidth + 1)
  );
});

test("mobile reviewer console stacks navigation and scenario cards without horizontal overflow", async ({
  page
}, testInfo) => {
  test.skip(testInfo.project.name !== "mobile", "mobile layout check");

  await expect(page.locator(".rail")).toHaveCSS("position", "sticky");
  await expect(page.locator(".summary")).toBeVisible();
  await expect(page.locator(".scenario-card")).toHaveCount(2);

  const railBox = await page.locator(".rail").boundingBox();
  const workspaceBox = await page.locator(".workspace").boundingBox();
  expect(railBox).not.toBeNull();
  expect(workspaceBox).not.toBeNull();
  expect(railBox!.y + railBox!.height).toBeLessThanOrEqual(workspaceBox!.y + 1);

  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  await expect(page.locator(".rail")).toBeInViewport();
  const scrolledRailBox = await page.locator(".rail").boundingBox();
  expect(scrolledRailBox).not.toBeNull();
  expect(scrolledRailBox!.y).toBeGreaterThanOrEqual(-1);
  expect(scrolledRailBox!.y).toBeLessThanOrEqual(1);

  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
    await page.evaluate(() => window.innerWidth + 1)
  );
});
