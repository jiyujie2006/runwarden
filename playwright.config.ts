import { defineConfig, devices } from "@playwright/test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function chromiumExecutable(): string | undefined {
  const explicit = process.env.RUNWARDEN_PLAYWRIGHT_CHROMIUM;
  if (explicit) {
    if (!fs.existsSync(explicit)) {
      throw new Error(`RUNWARDEN_PLAYWRIGHT_CHROMIUM does not exist: ${explicit}`);
    }
    return explicit;
  }

  const cacheRoot =
    process.env.PLAYWRIGHT_BROWSERS_PATH && process.env.PLAYWRIGHT_BROWSERS_PATH !== "0"
      ? process.env.PLAYWRIGHT_BROWSERS_PATH
      : path.join(os.homedir(), ".cache", "ms-playwright");
  if (!fs.existsSync(cacheRoot)) {
    return undefined;
  }

  return fs
    .readdirSync(cacheRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .flatMap((entry) => {
      const root = path.join(cacheRoot, entry.name);
      return [
        path.join(root, "chrome-linux64", "chrome"),
        path.join(root, "chrome-headless-shell-linux64", "chrome-headless-shell")
      ];
    })
    .filter((candidate) => fs.existsSync(candidate))
    .sort()
    .at(-1);
}

const executablePath = chromiumExecutable();

export default defineConfig({
  testDir: "tests/e2e",
  fullyParallel: true,
  reporter: "list",
  use: {
    browserName: "chromium",
    trace: "retain-on-failure",
    launchOptions: executablePath ? { executablePath } : {}
  },
  projects: [
    {
      name: "desktop",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 960 } }
    },
    {
      name: "mobile",
      use: { ...devices["Pixel 5"], viewport: { width: 393, height: 851 } }
    }
  ]
});
