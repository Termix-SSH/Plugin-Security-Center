import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
import {
  renderWithApp,
  type RenderedPluginApp,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import * as plugin from "../../src/frontend/index";
import {
  enabled,
  rowTone,
  severityTone,
  shortPrint,
  timeAgo,
} from "../../src/frontend/format";
import { findingsOf } from "../../src/backend/conditions";
import { parseReading } from "../../src/backend/parsers";
import manifestJson from "../../manifest.json";
import locales from "../../locales/en.json";
import { ED25519_FP, keysOutput } from "../backend/fixtures";

const manifest = manifestJson as unknown as PluginManifest;

let rendered: RenderedPluginApp | null = null;

afterEach(async () => {
  await rendered?.deactivate();
  rendered = null;
});

const reading = parseReading(keysOutput());
for (const key of reading.keys) key.known = key.kind !== "authorized";
const findings = findingsOf(reading);

const vulns = {
  at: Date.now(),
  ecosystem: "Debian:13",
  packages: 120,
  pending: 0,
  unsupported: "",
  error: "",
  kevChecked: true,
  vulns: [
    {
      id: "DSA-1",
      cves: ["CVE-2024-0001"],
      package: "openssh",
      version: "1:10.0p1-7",
      fixed: "1:10.0p1-8",
      severity: "critical",
      score: 9.8,
      kev: true,
      summary: "openssh update",
      ignored: false,
      ignoreNote: "",
    },
    {
      id: "DSA-2",
      cves: [],
      package: "bash",
      version: "5.2",
      fixed: "",
      severity: "low",
      score: 3.1,
      kev: false,
      summary: "bash update",
      ignored: false,
      ignoreNote: "",
    },
  ],
};

const view = (canManage = true) => ({
  hostId: 1,
  canEdit: canManage,
  canManage,
  useSudo: true,
  scanEnabled: true,
  config: {
    hostId: 1,
    alerts: true,
    intervalMin: 60,
    vulnIntervalH: 24,
    minRsaBits: 3072,
    keyMaxAgeDays: 0,
  },
  status: "fail",
  score: 42,
  reading,
  findings,
  error: "",
  readAt: Date.now(),
  active: [],
  seenOn: { [ED25519_FP]: 2 },
  scan: {
    at: vulns.at,
    ecosystem: "Debian:13",
    packages: 120,
    pending: 0,
    unsupported: "",
    error: "",
    kevChecked: true,
    total: 2,
    critical: 1,
    kev: 1,
  },
  scanning: false,
});

function api(data: unknown) {
  return {
    get: vi.fn(async (url: string) => {
      const path = url.split("?")[0];
      if (path.endsWith("/events")) return { data: [] };
      if (path.endsWith("/vulns"))
        return { data: { scan: vulns, scanning: false } };
      if (path.endsWith("/summary")) return { data: [] };
      return { data };
    }),
    post: vi.fn(async () => ({ data: { ok: true, message: "Done" } })),
    put: vi.fn(async () => ({ data: {} })),
    delete: vi.fn(async () => ({ data: {} })),
  } as never;
}

const host = {
  id: 1,
  name: "web",
  ip: "10.0.0.1",
  enableSsh: true,
  pluginSettings: { "security-center": { enableSecurity: true } },
};

async function openTab(name: string) {
  const found = await screen.findAllByText(name);
  fireEvent.click(found.find((el) => el.closest("button"))!);
}

const post = (mock: unknown) =>
  (mock as { post: ReturnType<typeof vi.fn> }).post;

describe(`${manifest.id} frontend`, () => {
  it("registers the tab and the dashboard card", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales });
    expect(rendered.registered.tabs()).toEqual(["security-center"]);
    expect(rendered.registered.dashboardCards()).toEqual(["security-hosts"]);
  });

  it("only offers the tab on hosts that turned it on", () => {
    expect(enabled(host)).toBe(true);
    expect(enabled({ pluginSettings: {} })).toBe(false);
    expect(enabled(null)).toBe(false);
  });

  it("shows the score and the findings, worst first", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: api(view()),
    });
    rendered.renderTab("security-center", { isVisible: true, host });
    expect(await screen.findByText("42")).toBeTruthy();
    expect(screen.getByText(/DSA key in/)).toBeTruthy();
    expect(
      screen.getAllByText(locales.severity.critical).length,
    ).toBeGreaterThan(0);
  });

  it("lists the keys and offers to remove one", async () => {
    const mock = api(view());
    rendered = await renderWithApp(plugin, { manifest, locales, api: mock });
    rendered.renderTab("security-center", { isVisible: true, host });
    await openTab(locales.tab.viewKeys);
    expect(await screen.findByText(locales.keys.kind.authorized)).toBeTruthy();
    expect(screen.getByText(locales.keys.kind.host)).toBeTruthy();
    expect(screen.getByText(locales.keys.kind.private)).toBeTruthy();
    expect(screen.getAllByText(locales.keys.noPassphrase).length).toBe(1);
    const remove = screen.getAllByLabelText(locales.keys.revoke)[0];
    fireEvent.click(remove);
    expect(await screen.findByText(locales.keys.revokeTitle)).toBeTruthy();
    const revoke = screen.getAllByText(locales.keys.revoke);
    fireEvent.click(revoke[revoke.length - 1]);
    await vi.waitFor(() =>
      expect(post(mock)).toHaveBeenCalledWith(
        "/1/revoke",
        expect.objectContaining({
          fingerprint: expect.stringContaining("SHA256:"),
        }),
      ),
    );
  });

  it("rotates the login key after a confirm", async () => {
    const mock = api(view());
    rendered = await renderWithApp(plugin, { manifest, locales, api: mock });
    rendered.renderTab("security-center", { isVisible: true, host });
    await openTab(locales.tab.viewKeys);
    fireEvent.click(await screen.findByText(locales.keys.rotate));
    expect(await screen.findByText(locales.keys.rotateTitle)).toBeTruthy();
    const rotate = screen.getAllByText(locales.keys.rotate);
    fireEvent.click(rotate[rotate.length - 1]);
    await vi.waitFor(() =>
      expect(post(mock)).toHaveBeenCalledWith("/1/rotate-login-key", {}),
    );
  });

  it("disables key changes without manage access", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: api(view(false)),
    });
    rendered.renderTab("security-center", { isVisible: true, host });
    await openTab(locales.tab.viewKeys);
    const button = (await screen.findByText(locales.keys.rotate)).closest(
      "button",
    );
    expect(button?.disabled).toBe(true);
  });

  it("shows vulnerabilities, worst first, and can ignore one", async () => {
    const mock = api(view());
    rendered = await renderWithApp(plugin, { manifest, locales, api: mock });
    rendered.renderTab("security-center", { isVisible: true, host });
    await openTab(locales.tab.viewVulns);
    expect(await screen.findByText(/DSA-1 \| openssh/)).toBeTruthy();
    expect(screen.getAllByText(locales.vulns.exploited)[0]).toBeTruthy();
    expect(screen.getByText(/DSA-2 \| bash/)).toBeTruthy();
    fireEvent.click(screen.getAllByText(locales.vulns.ignore)[0]);
    await vi.waitFor(() =>
      expect(post(mock)).toHaveBeenCalledWith("/1/ignore", {
        advisory: "DSA-1",
        note: "",
      }),
    );
  });

  it("filters vulnerabilities by severity", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: api(view()),
    });
    rendered.renderTab("security-center", { isVisible: true, host });
    await openTab(locales.tab.viewVulns);
    await screen.findByText(/DSA-1 \| openssh/);
    fireEvent.click(screen.getByText(locales.vulns.filter.low));
    expect(screen.queryByText(/DSA-1 \| openssh/)).toBeNull();
    expect(screen.getByText(/DSA-2 \| bash/)).toBeTruthy();
  });

  it("starts a scan", async () => {
    const mock = api(view());
    rendered = await renderWithApp(plugin, { manifest, locales, api: mock });
    rendered.renderTab("security-center", { isVisible: true, host });
    await openTab(locales.tab.viewVulns);
    fireEvent.click(await screen.findByText(locales.vulns.scan));
    await vi.waitFor(() =>
      expect(post(mock)).toHaveBeenCalledWith("/1/scan", {}),
    );
  });

  it("shows why a host cannot be read", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: api({
        ...view(),
        reading: null,
        error: "Connection lost",
        status: "unknown",
        score: null,
      }),
    });
    rendered.renderTab("security-center", { isVisible: true, host });
    expect(await screen.findByText(/Connection lost/)).toBeTruthy();
  });
});

describe("formatting", () => {
  it("picks tones", () => {
    expect(rowTone("fail")).toBe("destructive");
    expect(rowTone("warn")).toBe("warning");
    expect(rowTone("ok")).toBe("success");
    expect(rowTone("unknown")).toBe("muted");
    expect(severityTone("critical")).toBe("destructive");
    expect(severityTone("medium")).toBe("warning");
    expect(severityTone("low")).toBe("muted");
  });

  it("writes ages and short fingerprints", () => {
    expect(timeAgo(null)).toBe("");
    expect(timeAgo(1000, 31_000)).toBe("30s");
    expect(timeAgo(1, 7_200_001)).toBe("2h");
    expect(shortPrint(ED25519_FP)).toBe("SHA256:+DiY3wv...UvCOqU");
    expect(shortPrint("short")).toBe("short");
  });
});
