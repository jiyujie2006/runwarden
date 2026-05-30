import { expect, test } from "@playwright/test";
import { renderReviewerConsoleHtml } from "../../packages/webui/src/index";

const html = renderReviewerConsoleHtml(
  {
    sessionId: "session-1",
    riskStatus: "requires_review",
    traceIntegrity: "verified",
    pendingApprovalCount: 1,
    fastGateStatus: "passed",
    fullGateStatus: "missing",
    moduleStates: {
      agentBoundary: {
        state: "success",
        count: 1,
        message: "Runwarden-only agent config verified"
      },
      providers: {
        state: "partial",
        count: 12,
        message: "12 providers visible through kernel contracts"
      },
      trace: {
        state: "success",
        count: 42,
        message: "42 verified obs events"
      },
      accountability: {
        state: "success",
        message: "requester -> agent -> reviewer"
      },
      reports: {
        state: "partial",
        count: 2,
        message: "2 reports ready for citation review"
      },
      artifacts: {
        state: "success",
        count: 6,
        message: "6 sealed artifacts"
      },
      assurance: {
        state: "partial",
        message: "Fast gate passed, full gate missing"
      }
    }
  },
  [
    {
      approvalId: "approval-1",
      provider: "runwarden.report.render",
      action: "render",
      risk: "report_claim",
      target: "artifacts/reports/submission-report.html",
      sideEffects: ["artifact_write"],
      argumentHash: "arg_hash_1",
      authzId: "authz-1",
      actorId: "agent-1",
      obsRefs: ["obs_1", "obs_2"]
    }
  ]
);

test.beforeEach(async ({ page }) => {
  await page.setContent(html, { waitUntil: "domcontentloaded" });
});

test("desktop reviewer console keeps review regions visible and separated", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "desktop layout check");

  await expect(page.locator(".nav-brand")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Reviewer Console" })).toBeVisible();
  await expect(page.locator(".top-status-strip .status-pill")).toHaveCount(6);
  await expect(page.locator(".approval-module")).toContainText("1 pending");
  await expect(page.locator(".approval-row .risk-chip")).toHaveText("report_claim");
  await expect(page.locator("script")).toHaveCount(0);

  const background = await page.locator("body").evaluate((body) => getComputedStyle(body).backgroundImage);
  expect(background).toContain("repeating-linear-gradient");
  expect(background).not.toContain("radial-gradient");

  const navBox = await page.locator(".left-nav").boundingBox();
  const mainBox = await page.locator(".workbench-main").boundingBox();
  const drawerBox = await page.locator(".details-drawer").boundingBox();
  expect(navBox).not.toBeNull();
  expect(mainBox).not.toBeNull();
  expect(drawerBox).not.toBeNull();
  expect(navBox!.x + navBox!.width).toBeLessThanOrEqual(mainBox!.x + 1);
  expect(mainBox!.x + mainBox!.width).toBeLessThanOrEqual(drawerBox!.x + 1);

  for (const button of await page.locator("button").all()) {
    const box = await button.boundingBox();
    expect(box?.height).toBeGreaterThanOrEqual(44);
  }

  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
    await page.evaluate(() => window.innerWidth + 1)
  );
});

test("mobile reviewer console uses bottom navigation without horizontal overflow", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile", "mobile layout check");

  await expect(page.locator(".left-nav")).toHaveCSS("position", "fixed");
  await expect(page.locator(".nav-brand")).toBeHidden();
  await expect(page.locator(".command-bar")).toBeVisible();
  await expect(page.locator(".approval-row")).toBeVisible();

  const navBox = await page.locator(".left-nav").boundingBox();
  const commandBox = await page.locator(".command-bar").boundingBox();
  expect(navBox).not.toBeNull();
  expect(commandBox).not.toBeNull();
  expect(navBox!.y).toBeGreaterThan(commandBox!.y + commandBox!.height);

  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(
    await page.evaluate(() => window.innerWidth + 1)
  );
});
