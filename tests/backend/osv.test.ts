import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import {
  Osv,
  cvssScore,
  detailOf,
  ecosystemOf,
  severityOfScore,
} from "../../src/backend/osv";

describe("ecosystems", () => {
  it("maps supported systems", () => {
    expect(ecosystemOf({ id: "debian", version: "13" })).toBe("Debian:13");
    expect(ecosystemOf({ id: "ubuntu", version: "24.04" })).toBe(
      "Ubuntu:24.04:LTS",
    );
    expect(ecosystemOf({ id: "ubuntu", version: "25.04" })).toBe(
      "Ubuntu:25.04",
    );
    expect(ecosystemOf({ id: "alpine", version: "3.20.3" })).toBe(
      "Alpine:v3.20",
    );
    expect(ecosystemOf({ id: "rocky", version: "9.4" })).toBe("Rocky Linux:9");
    expect(ecosystemOf({ id: "almalinux", version: "9.3" })).toBe(
      "AlmaLinux:9",
    );
  });

  it("returns null for the rest", () => {
    expect(ecosystemOf({ id: "fedora", version: "40" })).toBeNull();
    expect(ecosystemOf({ id: "debian", version: "" })).toBeNull();
    expect(ecosystemOf({ id: "arch", version: "" })).toBeNull();
  });
});

describe("CVSS", () => {
  it("scores known vectors", () => {
    expect(cvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")).toBe(10);
    expect(cvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvssScore("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")).toBe(7.8);
    expect(cvssScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(6.1);
    expect(cvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBe(0);
  });

  it("ignores other versions and junk", () => {
    expect(cvssScore("CVSS:4.0/AV:N/AC:L")).toBeNull();
    expect(cvssScore("nonsense")).toBeNull();
    expect(
      cvssScore("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ).toBeNull();
  });

  it("names severities", () => {
    expect(severityOfScore(9.8)).toBe("critical");
    expect(severityOfScore(7)).toBe("high");
    expect(severityOfScore(5)).toBe("medium");
    expect(severityOfScore(2)).toBe("low");
    expect(severityOfScore(0)).toBe("unknown");
    expect(severityOfScore(null)).toBe("unknown");
  });
});

describe("advisory details", () => {
  it("reads score, cves and the fix for the package", () => {
    const detail = detailOf({
      id: "DSA-5000-1",
      aliases: ["CVE-2024-0001", "OTHER-1"],
      summary: "openssh security update\nmore",
      severity: [
        {
          type: "CVSS_V3",
          score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
      ],
      affected: [
        {
          package: { name: "openssh" },
          ranges: [{ events: [{ introduced: "0" }, { fixed: "1:10.0p1-8" }] }],
        },
      ],
    });
    expect(detail).toMatchObject({
      cves: ["CVE-2024-0001"],
      summary: "openssh security update",
      severity: "critical",
      score: 9.8,
      fixed: { openssh: "1:10.0p1-8" },
      withdrawn: false,
    });
  });

  it("falls back to a named severity", () => {
    expect(
      detailOf({ id: "USN-1", severity: [{ type: "Ubuntu", score: "medium" }] })
        .severity,
    ).toBe("medium");
    expect(
      detailOf({ id: "RLSA-1", database_specific: { severity: "Important" } })
        .severity,
    ).toBe("high");
    expect(detailOf({ id: "X" }).severity).toBe("unknown");
  });

  it("marks withdrawn records", () => {
    expect(detailOf({ id: "X", withdrawn: "2024-01-01" }).withdrawn).toBe(true);
  });
});

function fakeCtx(routes: Record<string, (body?: unknown) => unknown>) {
  const calls: string[] = [];
  const fetch = vi.fn(async (url: string, init?: { body?: string }) => {
    calls.push(url);
    const key = Object.keys(routes).find((k) => url.includes(k));
    if (!key) return new Response("{}", { status: 404 });
    const body = init?.body ? JSON.parse(init.body) : undefined;
    return new Response(JSON.stringify(routes[key](body)), { status: 200 });
  });
  const ctx = {
    fetch,
    log: { debug: vi.fn(), warn: vi.fn(), info: vi.fn() },
  } as unknown as PluginContext;
  return { ctx, calls, fetch };
}

describe("scanning", () => {
  const dir = () => mkdtempSync(path.join(os.tmpdir(), "osv-test-"));

  const routes = {
    "/v1/querybatch": (body: unknown) => {
      const queries = (
        body as { queries: Array<{ package: { name: string } }> }
      ).queries;
      return {
        results: queries.map((q) =>
          q.package.name === "openssh"
            ? { vulns: [{ id: "DSA-1" }, { id: "DSA-2" }] }
            : {},
        ),
      };
    },
    "/v1/vulns/DSA-1": () => ({
      id: "DSA-1",
      aliases: ["CVE-2024-0001"],
      summary: "bad",
      severity: [
        {
          type: "CVSS_V3",
          score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
      ],
      affected: [
        {
          package: { name: "openssh" },
          ranges: [{ events: [{ fixed: "2" }] }],
        },
      ],
    }),
    "/v1/vulns/DSA-2": () => ({ id: "DSA-2", summary: "meh" }),
    known_exploited: () => ({
      vulnerabilities: [{ cveID: "CVE-2024-0001" }],
    }),
  };

  it("finds advisories, marks exploited ones and sorts worst first", async () => {
    const { ctx } = fakeCtx(routes);
    const osv = new Osv(ctx, dir());
    const result = await osv.scan(
      "https://osv.test",
      "Debian:13",
      [
        { name: "openssh", version: "1" },
        { name: "bash", version: "5" },
      ],
      { checkKev: true, ignored: new Map([["DSA-2", "later"]]) },
    );
    expect(result.kevChecked).toBe(true);
    expect(result.pending).toBe(0);
    expect(result.vulns.map((v) => v.id)).toEqual(["DSA-1", "DSA-2"]);
    expect(result.vulns[0]).toMatchObject({
      package: "openssh",
      fixed: "2",
      severity: "critical",
      score: 9.8,
      kev: true,
      cves: ["CVE-2024-0001"],
      ignored: false,
    });
    expect(result.vulns[1]).toMatchObject({
      severity: "unknown",
      fixed: "",
      ignored: true,
      ignoreNote: "later",
    });
  });

  it("reuses cached details on the next scan", async () => {
    const { ctx, calls } = fakeCtx(routes);
    const osv = new Osv(ctx, dir());
    const input = [{ name: "openssh", version: "1" }];
    const options = { checkKev: false, ignored: new Map<string, string>() };
    await osv.scan("https://osv.test", "Debian:13", input, options);
    const first = calls.filter((c) => c.includes("/v1/vulns/")).length;
    await osv.scan("https://osv.test", "Debian:13", input, options);
    expect(calls.filter((c) => c.includes("/v1/vulns/")).length).toBe(first);
  });

  it("keeps the cache on disk", async () => {
    const where = dir();
    const first = fakeCtx(routes);
    const osv = new Osv(first.ctx, where);
    await osv.scan(
      "https://osv.test",
      "Debian:13",
      [{ name: "openssh", version: "1" }],
      { checkKev: true, ignored: new Map() },
    );
    const second = fakeCtx(routes);
    const again = new Osv(second.ctx, where);
    await again.load();
    await again.scan(
      "https://osv.test",
      "Debian:13",
      [{ name: "openssh", version: "1" }],
      { checkKev: true, ignored: new Map() },
    );
    expect(second.calls.some((c) => c.includes("/v1/vulns/"))).toBe(false);
    expect(second.calls.some((c) => c.includes("known_exploited"))).toBe(false);
  });

  it("still returns results when the exploited list cannot load", async () => {
    const { ctx } = fakeCtx({ ...routes, known_exploited: () => ({}) });
    const osv = new Osv(ctx, dir());
    const result = await osv.scan(
      "https://osv.test",
      "Debian:13",
      [{ name: "openssh", version: "1" }],
      { checkKev: true, ignored: new Map() },
    );
    expect(result.kevChecked).toBe(false);
    expect(result.vulns).toHaveLength(2);
  });

  it("follows pages of results", async () => {
    let page = 0;
    const { ctx } = fakeCtx({
      ...routes,
      "/v1/querybatch": () => {
        page += 1;
        return page === 1
          ? { results: [{ vulns: [{ id: "DSA-1" }], next_page_token: "t" }] }
          : { results: [{ vulns: [{ id: "DSA-2" }] }] };
      },
    });
    const osv = new Osv(ctx, dir());
    const result = await osv.scan(
      "https://osv.test",
      "Debian:13",
      [{ name: "openssh", version: "1" }],
      { checkKev: false, ignored: new Map() },
    );
    expect(result.vulns.map((v) => v.id).sort()).toEqual(["DSA-1", "DSA-2"]);
  });

  it("fails when OSV answers with an error", async () => {
    const ctx = {
      fetch: async () => new Response("no", { status: 500 }),
      log: { debug: vi.fn(), warn: vi.fn() },
    } as unknown as PluginContext;
    const osv = new Osv(ctx, dir());
    await expect(
      osv.scan("https://osv.test", "Debian:13", [{ name: "a", version: "1" }], {
        checkKev: false,
        ignored: new Map(),
      }),
    ).rejects.toThrow("OSV answered 500");
  });
});
