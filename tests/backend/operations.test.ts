import { afterEach, describe, expect, it } from "vitest";
import { parseManifest } from "@termix-ssh/plugin-sdk/manifest";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import manifest from "../../manifest.json";
import { registerOperations } from "../../src/backend/operations";
import {
  ALL,
  startServer,
  type StartOptions,
  type TestServer,
} from "./helpers";
import { ED25519_FP, PACKAGES_DPKG, keysOutput } from "./fixtures";

type Actions = {
  id: string;
  risk: string;
  hostAccess?: string;
  permission?: string;
}[];
const actions = () =>
  (manifest.contributes as unknown as { operations: { actions: Actions } })
    .operations.actions;

describe("declared actions", () => {
  it("is a valid manifest", () => {
    expect(parseManifest(manifest).errors ?? []).toEqual([]);
  });

  it("has a handler for every declared action and nothing else", () => {
    const registered: string[] = [];
    const ctx = {
      operations: {
        register: (id: string) => {
          registered.push(id);
        },
      },
    } as unknown as PluginContext;
    (registerOperations as (...args: unknown[]) => void)(ctx, {});
    expect([...registered].sort()).toEqual(
      actions()
        .map((a) => a.id)
        .sort(),
    );
  });

  it("needs the right permission and access for anything that changes", () => {
    for (const action of actions()) {
      if (action.risk === "read") continue;
      if (action.risk === "destructive") {
        expect(action.permission).toBe("rotate");
        expect(action.hostAccess).toBe("manage");
      } else {
        expect(action.permission).toBe("scan-vulns");
        expect(["edit", "manage"]).toContain(action.hostAccess);
      }
    }
  });

  it("emits only events it declares", () => {
    const events = (
      manifest.contributes as unknown as {
        operations: { events: { id: string }[] };
      }
    ).operations.events.map((e) => e.id);
    expect(events).toEqual([
      "security-center.vuln-found",
      "security-center.key-weak",
      "security-center.rotated",
    ]);
  });
});

let server: TestServer | null = null;

afterEach(async () => {
  await server?.close();
  server = null;
});

const osv = async (url: string) => {
  const json = (data: unknown) =>
    new Response(JSON.stringify(data), { status: 200 });
  if (url.endsWith("/v1/querybatch")) {
    return json({ results: [{ vulns: [{ id: "DSA-1" }] }, {}] });
  }
  return json({
    id: "DSA-1",
    aliases: ["CVE-2024-0001"],
    severity: [
      {
        type: "CVSS_V3",
        score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      },
    ],
    affected: [
      { package: { name: "openssh" }, ranges: [{ events: [{ fixed: "2" }] }] },
    ],
  });
};

async function start(options: StartOptions = {}): Promise<TestServer> {
  server = await startServer({ permissions: ALL, fetch: osv, ...options });
  server.ssh.replies.push(
    { match: "@@sshdver", stdout: keysOutput() },
    { match: "@@kernel", stdout: PACKAGES_DPKG },
  );
  return server;
}

async function run(
  s: TestServer,
  id: string,
  input: Record<string, unknown> = {},
  hostId: number | null = 1,
) {
  return s.mock.ctx.operations.run(id, { hostId: hostId ?? undefined, input });
}

describe("handlers", () => {
  it("lists keys, findings and advisories", async () => {
    const s = await start();
    await run(s, "security-center.scan");
    const keys = await run(s, "security-center.keys");
    expect(
      (keys.data as { rows: Array<{ fingerprint: string }> }).rows.some(
        (r) => r.fingerprint === ED25519_FP,
      ),
    ).toBe(true);
    const findings = await run(s, "security-center.findings");
    expect((findings.data as { rows: unknown[] }).rows.length).toBeGreaterThan(
      3,
    );
    const vulns = await run(s, "security-center.vulns");
    expect((vulns.data as { rows: unknown[] }).rows).toHaveLength(1);
  });

  it("answers the signals", async () => {
    const s = await start();
    await run(s, "security-center.scan");
    const status = await run(s, "security-center.status");
    expect((status.data as { status: string }).status).toBe("fail");
    const critical = await run(s, "security-center.critical-vulns");
    expect((critical.data as { value: number }).value).toBe(1);
    const weak = await run(s, "security-center.weak-keys");
    expect((weak.data as { value: number }).value).toBeGreaterThan(0);
  });

  it("refuses a host that has the plugin off", async () => {
    const s = await start({ hostSettings: { enableSecurity: false } });
    await expect(run(s, "security-center.keys")).rejects.toThrow("turned off");
  });

  it("refuses changes on a read only host", async () => {
    const s = await start({ hostSettings: { readOnly: true } });
    await expect(run(s, "security-center.scan")).rejects.toThrow("read only");
    await expect(run(s, "security-center.rotate-host-keys")).rejects.toThrow(
      "read only",
    );
  });

  it("needs a host", async () => {
    const s = await start();
    await expect(run(s, "security-center.keys", {}, null)).rejects.toThrow(
      "needs a host",
    );
  });

  it("removes a key by fingerprint", async () => {
    const s = await start();
    s.ssh.replies.unshift({ match: "ssh-keygen -lf", stdout: "removed 1\n" });
    const result = await run(s, "security-center.revoke-key", {
      fingerprint: ED25519_FP,
      path: "/home/bob/.ssh/authorized_keys",
    });
    expect(result.changed).toBe(true);
  });

  it("describes what a dry run would do", () => {
    const registered = new Map<
      string,
      { describe?: (input: Record<string, unknown>) => string }
    >();
    const ctx = {
      operations: {
        register: (id: string, handler: never) => registered.set(id, handler),
      },
    } as unknown as PluginContext;
    (registerOperations as (...args: unknown[]) => void)(ctx, {});
    expect(
      registered.get("security-center.revoke-key")!.describe!({
        fingerprint: ED25519_FP,
        path: "/x/authorized_keys",
      }),
    ).toContain(ED25519_FP);
    expect(
      registered.get("security-center.rotate-host-keys")!.describe!({}),
    ).toContain("host key");
  });
});

describe("alerts and events", () => {
  it("alerts once for new critical advisories and again only for new ones", async () => {
    const s = await start();
    await run(s, "security-center.scan");
    const first = s.mock.notifications.filter((n) =>
      n.notification.title.includes("critical"),
    );
    expect(first).toHaveLength(1);
    expect(first[0].notification.severity).toBe("critical");
    expect(first[0].notification.title).toContain("DSA-1");
    expect(
      s.mock.operationEvents.filter(
        (e) => e.eventId === "security-center.vuln-found",
      ),
    ).toHaveLength(1);
    await run(s, "security-center.scan");
    expect(
      s.mock.notifications.filter((n) =>
        n.notification.title.includes("critical"),
      ),
    ).toHaveLength(1);
  });

  it("alerts for critical key problems and emits the weak key event", async () => {
    const s = await start();
    await s.request("GET", "/1");
    const titles = s.mock.notifications.map((n) => n.notification.title);
    expect(titles.some((t) => t.includes("DSA key"))).toBe(true);
    expect(
      s.mock.operationEvents.some(
        (e) => e.eventId === "security-center.key-weak",
      ),
    ).toBe(true);
    // Medium and low findings stay quiet.
    expect(titles.some((t) => t.includes("sshd allows password logins"))).toBe(
      false,
    );
    const count = s.mock.notifications.length;
    await s.request("POST", "/1/refresh");
    expect(s.mock.notifications).toHaveLength(count);
  });

  it("does not alert when the host turned alerts off", async () => {
    const s = await start();
    await s.request("GET", "/1");
    await s.request("PUT", "/1/config", { alerts: false });
    const before = s.mock.notifications.length;
    await run(s, "security-center.scan");
    expect(s.mock.notifications).toHaveLength(before);
  });
});
