import { afterEach, describe, expect, it } from "vitest";
import { generateSshKeyPair } from "@termix-ssh/plugin-sdk/ssh-keys";
import { keyBlob, parsePublicKey } from "../../src/backend/parsers";
import { PROBE_COMMAND } from "../../src/backend/scripts";
import {
  ALL,
  startServer,
  type StartOptions,
  type TestServer,
} from "./helpers";
import {
  ED25519_FP,
  ED25519_LINE,
  PACKAGES_DPKG,
  keysOutput,
} from "./fixtures";

let server: TestServer | null = null;

afterEach(async () => {
  await server?.close();
  server = null;
});

async function start(options: StartOptions = {}): Promise<TestServer> {
  server = await startServer({ permissions: ALL, ...options });
  server.ssh.replies.push(
    { match: "@@sshdver", stdout: keysOutput() },
    { match: "@@kernel", stdout: PACKAGES_DPKG },
  );
  return server;
}

const osvFetch =
  (severity = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") =>
  async (url: string) => {
    const json = (data: unknown) =>
      new Response(JSON.stringify(data), { status: 200 });
    if (url.endsWith("/v1/querybatch")) {
      return json({ results: [{ vulns: [{ id: "DSA-1" }] }, {}] });
    }
    if (url.includes("/v1/vulns/DSA-1")) {
      return json({
        id: "DSA-1",
        aliases: ["CVE-2024-0001"],
        summary: "openssh update",
        severity: [{ type: "CVSS_V3", score: severity }],
        affected: [
          {
            package: { name: "openssh" },
            ranges: [{ events: [{ fixed: "2" }] }],
          },
        ],
      });
    }
    return new Response("{}", { status: 404 });
  };

describe("reading a host", () => {
  it("reads keys and reports findings", async () => {
    const s = await start();
    const res = await s.request("GET", "/1");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("fail");
    expect(res.body.canEdit).toBe(true);
    expect(res.body.canManage).toBe(true);
    expect(res.body.reading.keys.length).toBeGreaterThan(5);
    const kinds = res.body.findings.map((f: { kind: string }) => f.kind);
    expect(kinds).toContain("key-dsa");
    expect(kinds).toContain("sshd-root-login");
    expect(res.body.score).toBeLessThan(100);
    expect(res.body.config.intervalMin).toBe(60);
    const dsa = res.body.findings.find(
      (f: { kind: string }) => f.kind === "key-dsa",
    );
    expect(res.body.active).toContain(`key-dsa|${dsa.subject}`);
  });

  it("sends the reader script on stdin, never as the command", async () => {
    const s = await start();
    await s.request("GET", "/1");
    expect(s.ssh.calls[0].stdin).toContain("@@sshdver");
    expect(s.ssh.calls[0].command).not.toContain("@@sshdver");
  });

  it("reuses a fresh reading and reads again on refresh", async () => {
    const s = await start();
    await s.request("GET", "/1");
    await s.request("GET", "/1");
    expect(s.ssh.calls).toHaveLength(1);
    await s.request("POST", "/1/refresh");
    expect(s.ssh.calls).toHaveLength(2);
  });

  it("marks keys Termix has saved as known", async () => {
    const s = await start({
      savedKeys: [{ id: 5, name: "Laptop key", publicKey: ED25519_LINE }],
    });
    const res = await s.request("GET", "/1");
    const known = res.body.reading.keys.filter(
      (k: { fingerprint: string; kind: string }) =>
        k.fingerprint === ED25519_FP && k.kind === "authorized",
    );
    expect(known.length).toBeGreaterThan(0);
    expect(known[0].known).toBe(true);
    expect(known[0].knownAs).toBe("Laptop key");
    const unknown = res.body.findings.filter(
      (f: { kind: string }) => f.kind === "key-unknown",
    );
    expect(unknown.length).toBeGreaterThan(0);
    expect(
      unknown.some((f: { subject: string }) => f.subject.includes(ED25519_FP)),
    ).toBe(false);
  });

  it("does not flag unknown keys when the credential list is unavailable", async () => {
    const s = await start();
    (
      s.mock.ctx.credentials as unknown as { listSshKeys: () => Promise<never> }
    ).listSshKeys = async () => {
      throw new Error("no access");
    };
    const res = await s.request("GET", "/1");
    expect(
      res.body.findings.some((f: { kind: string }) => f.kind === "key-unknown"),
    ).toBe(false);
  });

  it("falls back to the login user when sudo is refused", async () => {
    let n = 0;
    const s = await start({
      exec: async () => {
        n += 1;
        return n === 1
          ? {
              stdout: "",
              stderr: "sudo: a password is required",
              code: 1,
              truncated: false,
              timedOut: false,
            }
          : {
              stdout: keysOutput({ root: false }),
              stderr: "",
              code: 0,
              truncated: false,
              timedOut: false,
            };
      },
    });
    const res = await s.request("GET", "/1");
    expect(res.status).toBe(200);
    expect(res.body.reading.root).toBe(false);
    expect(n).toBe(2);
  });

  it("keeps the last reading when a later read fails", async () => {
    let fail = false;
    const s = await start({
      exec: async () =>
        fail
          ? {
              stdout: "",
              stderr: "connection lost",
              code: 255,
              truncated: false,
              timedOut: false,
            }
          : {
              stdout: keysOutput(),
              stderr: "",
              code: 0,
              truncated: false,
              timedOut: false,
            },
    });
    await s.request("GET", "/1");
    fail = true;
    const res = await s.request("POST", "/1/refresh");
    expect(res.status).toBe(200);
    expect(res.body.reading).not.toBeNull();
    expect(res.body.error).toContain("connection lost");
  });
});

describe("access", () => {
  it("is off until the host turns it on", async () => {
    const s = await start({ hostSettings: { enableSecurity: false } });
    const res = await s.request("GET", "/1");
    expect(res.status).toBe(403);
    expect(res.body.code).toBe("disabled");
    expect(s.ssh.calls).toHaveLength(0);
  });

  it("hides hosts the user cannot reach", async () => {
    const s = await start({ level: "none" });
    expect((await s.request("GET", "/1")).status).toBe(404);
  });

  it("needs edit access to change settings and scan", async () => {
    const s = await start({ level: "connect" });
    expect((await s.request("GET", "/1")).status).toBe(200);
    expect(
      (await s.request("PUT", "/1/config", { alerts: false })).status,
    ).toBe(403);
    expect((await s.request("POST", "/1/scan")).status).toBe(403);
    expect((await s.request("POST", "/1/rotate-login-key")).status).toBe(403);
  });

  it("needs the matching permission", async () => {
    const s = await start({ permissions: ["security-center.use"] });
    expect((await s.request("POST", "/1/scan")).status).toBe(403);
    expect((await s.request("POST", "/1/rotate-login-key")).status).toBe(403);
    expect(
      (await s.request("POST", "/1/revoke", { path: "/a", fingerprint: "x" }))
        .status,
    ).toBe(403);
    expect((await s.request("POST", "/1/rotate-host-keys")).status).toBe(403);
  });

  it("blocks changes on a read only host", async () => {
    const s = await start({ hostSettings: { readOnly: true } });
    expect((await s.request("POST", "/1/scan")).status).toBe(403);
    expect((await s.request("POST", "/1/rotate-host-keys")).status).toBe(403);
    expect((await s.request("GET", "/1")).body.canEdit).toBe(false);
  });
});

describe("settings", () => {
  it("saves limits and rejects bad ones", async () => {
    const s = await start();
    const ok = await s.request("PUT", "/1/config", {
      alerts: false,
      intervalMin: 30,
      vulnIntervalH: 12,
      minRsaBits: 4096,
      keyMaxAgeDays: 90,
    });
    expect(ok.status).toBe(200);
    const view = await s.request("GET", "/1");
    expect(view.body.config).toMatchObject({
      alerts: false,
      intervalMin: 30,
      vulnIntervalH: 12,
      minRsaBits: 4096,
      keyMaxAgeDays: 90,
    });
    expect(
      (await s.request("PUT", "/1/config", { intervalMin: 5 })).status,
    ).toBe(400);
    expect(
      (await s.request("PUT", "/1/config", { minRsaBits: 512 })).status,
    ).toBe(400);
    expect((await s.request("GET", "/abc")).status).toBe(400);
  });
});

describe("vulnerability scans", () => {
  it("scans packages, finds a critical advisory and logs it", async () => {
    const s = await start({ fetch: osvFetch() });
    const res = await s.request("POST", "/1/scan");
    expect(res.status).toBe(200);
    expect(res.body.scan.ecosystem).toBe("Debian:13");
    expect(res.body.scan.packages).toBe(2);
    expect(res.body.scan.vulns).toHaveLength(1);
    expect(res.body.scan.vulns[0]).toMatchObject({
      id: "DSA-1",
      package: "openssh",
      fixed: "2",
      severity: "critical",
    });
    expect(s.fetches.every((u) => u.startsWith("https://osv.test"))).toBe(true);
    const events = await s.request("GET", "/1/events");
    expect(events.body.map((e: { type: string }) => e.type)).toContain(
      "vuln-new",
    );
    const view = await s.request("GET", "/1");
    expect(view.body.scan).toMatchObject({ total: 1, critical: 1, kev: 0 });
  });

  it("sends the package list on stdin and only names and versions to OSV", async () => {
    const s = await start({ fetch: osvFetch() });
    let body = "";
    const inner = osvFetch();
    (s.mock.ctx as unknown as { fetch: unknown }).fetch = async (
      url: string,
      init?: { body?: string },
    ) => {
      if (init?.body) body += init.body;
      return inner(url);
    };
    await s.request("POST", "/1/scan");
    expect(body).toContain('"name":"openssh"');
    expect(body).toContain('"version":"1:10.0p1-7"');
    expect(body).not.toContain("bob");
    expect(body).not.toContain("10.0.0.1");
  });

  it("hides and shows an ignored advisory", async () => {
    const s = await start({ fetch: osvFetch() });
    await s.request("POST", "/1/scan");
    expect(
      (
        await s.request("POST", "/1/ignore", {
          advisory: "DSA-1",
          note: "later",
        })
      ).status,
    ).toBe(200);
    let vulns = (await s.request("GET", "/1/vulns")).body.scan.vulns;
    expect(vulns[0]).toMatchObject({ ignored: true, ignoreNote: "later" });
    expect((await s.request("GET", "/1")).body.scan.critical).toBe(0);
    await s.request("DELETE", "/1/ignore/DSA-1");
    vulns = (await s.request("GET", "/1/vulns")).body.scan.vulns;
    expect(vulns[0].ignored).toBe(false);
    expect(
      (await s.request("POST", "/1/ignore", { advisory: "bad id!" })).status,
    ).toBe(400);
  });

  it("keeps ignored advisories across the next scan", async () => {
    const s = await start({ fetch: osvFetch() });
    await s.request("POST", "/1/scan");
    await s.request("POST", "/1/ignore", { advisory: "DSA-1", note: "" });
    const again = await s.request("POST", "/1/scan");
    expect(again.body.scan.vulns[0].ignored).toBe(true);
  });

  it("does nothing when an admin turns scanning off", async () => {
    const s = await start({
      fetch: osvFetch(),
      adminSettings: { scanVulns: false },
    });
    const res = await s.request("POST", "/1/scan");
    expect(res.body.scan.error).toBe("disabled");
    expect(s.fetches).toHaveLength(0);
    expect((await s.request("GET", "/1")).body.scanEnabled).toBe(false);
  });

  it("says when the system has no vulnerability data", async () => {
    const s = await start({ fetch: osvFetch() });
    s.ssh.replies.unshift({
      match: "@@kernel",
      stdout:
        '@@os\n> ID=fedora\n> VERSION_ID=40\n> PRETTY_NAME="Fedora Linux 40"\n@@pkgs rpm\nbash\t0\t5.2\tx86_64\n',
    });
    const res = await s.request("POST", "/1/scan");
    expect(res.body.scan.unsupported).toBe("Fedora Linux 40");
    expect(s.fetches).toHaveLength(0);
  });

  it("keeps the old results when a scan fails", async () => {
    let broken = false;
    const inner = osvFetch();
    const s = await start({
      fetch: async (url, init) =>
        broken ? new Response("no", { status: 500 }) : inner(url),
    });
    await s.request("POST", "/1/scan");
    broken = true;
    const res = await s.request("POST", "/1/scan");
    expect(res.body.scan.error).toContain("OSV answered 500");
    expect(res.body.scan.vulns).toHaveLength(1);
  });
});

describe("removing a key", () => {
  const PATH = "/home/bob/.ssh/authorized_keys";

  it("removes a key by fingerprint as root", async () => {
    const s = await start();
    s.ssh.replies.unshift({ match: "ssh-keygen -lf", stdout: "removed 1\n" });
    const res = await s.request("POST", "/1/revoke", {
      path: PATH,
      fingerprint: ED25519_FP,
    });
    expect(res.status).toBe(200);
    expect(res.body.message).toContain(PATH);
    const call = s.ssh.calls.find((c) => c.stdin.includes("ssh-keygen -lf"))!;
    expect(call.stdin).toContain(ED25519_FP);
    expect(call.command).not.toContain(ED25519_FP);
  });

  it("refuses bad input and keys that are not there", async () => {
    const s = await start();
    expect(
      (
        await s.request("POST", "/1/revoke", {
          path: PATH,
          fingerprint: "nope",
        })
      ).status,
    ).toBe(400);
    const gone = "SHA256:" + "A".repeat(43);
    expect(
      (await s.request("POST", "/1/revoke", { path: PATH, fingerprint: gone }))
        .status,
    ).toBe(404);
    expect(
      (
        await s.request("POST", "/1/revoke", {
          path: "/etc/passwd",
          fingerprint: ED25519_FP,
        })
      ).status,
    ).toBe(404);
  });

  it("never removes the key Termix logs in with", async () => {
    const pair = generateSshKeyPair("ssh-ed25519", { comment: "login" });
    const print = parsePublicKey(pair.publicKey)!.fingerprint;
    const s = await start({
      resolved: {
        id: 1,
        ip: "10.0.0.1",
        port: 22,
        username: "bob",
        authType: "key",
        key: pair.privateKey,
      },
    });
    s.ssh.replies.unshift(
      {
        match: "@@sshdver",
        stdout: keysOutput().replace(
          `${ED25519_LINE} laptop`,
          `${pair.publicKey} laptop`,
        ),
      },
      { match: "ssh-keygen -lf", stdout: "removed 1\n" },
    );
    const res = await s.request("POST", "/1/revoke", {
      path: PATH,
      fingerprint: print,
    });
    expect(res.status).toBe(409);
    expect(res.body.code).toBe("login-key");
    expect(s.ssh.calls.some((c) => c.stdin.includes("ssh-keygen -lf"))).toBe(
      false,
    );
  });
});

describe("rotating the login key", () => {
  function keyHost() {
    const old = generateSshKeyPair("ssh-ed25519", { comment: "old" });
    return {
      old,
      resolved: {
        id: 1,
        ip: "10.0.0.1",
        port: 22,
        username: "bob",
        authType: "key",
        key: old.privateKey,
        name: "web",
      },
    };
  }

  const ok = {
    stdout: "termix-key-ok\n",
    stderr: "",
    code: 0,
    truncated: false,
    timedOut: false,
  };

  it("adds the new key, checks it, switches the host and removes the old key", async () => {
    const { old, resolved } = keyHost();
    const s = await start({
      resolved,
      exec: async (host, command) =>
        command === PROBE_COMMAND ? ok : { ...ok, stdout: "done\n" },
    });
    const res = await s.request("POST", "/1/rotate-login-key");
    expect(res.status).toBe(200);
    expect(res.body.message).toContain("Rotated");

    const adds = s.ssh.calls.filter((c) => c.stdin.includes("grep -qxF"));
    expect(adds).toHaveLength(1);
    const custom = s.ssh.calls.filter((c) => c.hostId === "custom");
    expect(custom).toHaveLength(1);
    expect(custom[0].host?.authType).toBe("key");
    expect(String(custom[0].host?.key)).toContain("BEGIN OPENSSH PRIVATE KEY");
    expect(custom[0].host?.key).not.toBe(old.privateKey);

    expect(s.created).toHaveLength(1);
    expect(s.created[0]).toMatchObject({
      username: "bob",
      keyType: "ssh-ed25519",
    });
    expect(s.updates).toEqual([
      {
        hostId: 1,
        patch: {
          authType: "credential",
          credentialId: 901,
          key: null,
          keyPassword: null,
          keyType: null,
        },
      },
    ]);

    const oldBlob = keyBlob(old.publicKey)!;
    const removal = s.ssh.calls.find((c) => c.stdin.includes(oldBlob))!;
    expect(removal.stdin).toContain("awk");
    const events = await s.request("GET", "/1/events");
    expect(events.body[0].type).toBe("rotated");
  });

  it("changes nothing when the new key cannot log in", async () => {
    const { old, resolved } = keyHost();
    const s = await start({
      resolved,
      exec: async (host, command) =>
        typeof host === "object"
          ? { ...ok, stdout: "", code: 255 }
          : command === PROBE_COMMAND
            ? ok
            : { ...ok, stdout: "done\n" },
    });
    const res = await s.request("POST", "/1/rotate-login-key");
    expect(res.status).toBe(502);
    expect(res.body.code).toBe("verify");
    expect(s.created).toHaveLength(0);
    expect(s.updates).toHaveLength(0);
    const oldBlob = keyBlob(old.publicKey)!;
    expect(s.ssh.calls.some((c) => c.stdin.includes(oldBlob))).toBe(false);
    const removal = s.ssh.calls.at(-1)!;
    expect(removal.stdin).toContain("awk");
    const added = s.ssh.calls.find((c) => c.stdin.includes("grep -qxF"))!;
    expect(added).toBeTruthy();
  });

  it("takes the new key back out when the host cannot be switched", async () => {
    const { old, resolved } = keyHost();
    const s = await start({
      resolved,
      updateFails: true,
      exec: async (host, command) =>
        command === PROBE_COMMAND ? ok : { ...ok, stdout: "done\n" },
    });
    const res = await s.request("POST", "/1/rotate-login-key");
    expect(res.status).toBe(502);
    expect(s.updates).toHaveLength(0);
    const oldBlob = keyBlob(old.publicKey)!;
    expect(s.ssh.calls.some((c) => c.stdin.includes(oldBlob))).toBe(false);
    expect(s.ssh.calls.at(-1)!.stdin).toContain("awk");
    const events = await s.request("GET", "/1/events");
    expect(events.body[0].type).toBe("rotate-failed");
  });

  it("puts the old login back when the normal login fails after the switch", async () => {
    const { old, resolved } = keyHost();
    let probes = 0;
    const s = await start({
      resolved,
      exec: async (host, command) => {
        if (command !== PROBE_COMMAND) return { ...ok, stdout: "done\n" };
        probes += 1;
        return probes === 1 ? ok : { ...ok, stdout: "", code: 255 };
      },
    });
    const res = await s.request("POST", "/1/rotate-login-key");
    expect(res.status).toBe(502);
    expect(s.updates).toHaveLength(2);
    expect(s.updates[1].patch).toMatchObject({
      authType: "key",
      key: old.privateKey,
    });
  });

  it("keeps working when only the old key could not be removed", async () => {
    const { resolved } = keyHost();
    let adds = 0;
    const s = await start({
      resolved,
      exec: async (host, command, stdin) => {
        if (command === PROBE_COMMAND) return ok;
        if (stdin.includes("grep -qxF")) {
          adds += 1;
          return { ...ok, stdout: "done\n" };
        }
        return { ...ok, stdout: "", stderr: "disk full", code: 1 };
      },
    });
    const res = await s.request("POST", "/1/rotate-login-key");
    expect(adds).toBe(1);
    expect(res.status).toBe(200);
    expect(res.body.message).toContain("old key is still on the host");
  });

  it("only works for hosts that log in with a key and for their owner", async () => {
    const s = await start();
    const res = await s.request("POST", "/1/rotate-login-key");
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("no-key");
    await s.close();
    const { resolved } = keyHost();
    server = await startServer({ permissions: ALL, resolved, owner: false });
    const shared = await server.request("POST", "/1/rotate-login-key");
    expect(shared.status).toBe(403);
    expect(server.ssh.calls).toHaveLength(0);
  });
});

describe("host keys and the summary", () => {
  it("makes new host keys as root", async () => {
    const s = await start();
    s.ssh.replies.unshift({
      match: "ssh_host_",
      stdout: "done /var/lib/termix-security/hostkeys-1\n",
    });
    const res = await s.request("POST", "/1/rotate-host-keys");
    expect(res.status).toBe(200);
    expect(res.body.message).toContain("/var/lib/termix-security/hostkeys-1");
  });

  it("lists watched hosts with their scores", async () => {
    const s = await start();
    await s.request("GET", "/1");
    const res = await s.request("GET", "/summary");
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0]).toMatchObject({ hostId: 1, status: "fail" });
    expect(res.body[0].score).toBeLessThan(100);
    expect(res.body[0].keys).toBeGreaterThan(5);
  });
});
