import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import express, { type Router } from "express";
import {
  createMockCtx,
  createTestDb,
  type MockPluginContext,
} from "@termix-ssh/plugin-sdk/testing";
import type {
  PluginHostAccess,
  PluginSshExecResult,
} from "@termix-ssh/plugin-sdk/backend";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import manifestJson from "../../manifest.json";

export const manifest = manifestJson as unknown as PluginManifest;
const pluginDir = fileURLToPath(new URL("../..", import.meta.url));

export interface Call {
  /** The host id, or "custom" when a host object was passed. */
  hostId: number | "custom";
  command: string;
  stdin: string;
  host?: Record<string, unknown>;
}

export interface Reply {
  match: string;
  stdout?: string;
  stderr?: string;
  code?: number;
}

export interface FakeSsh {
  calls: Call[];
  /** Replies by a piece of the script text. The first match wins. */
  replies: Reply[];
}

export interface FakeHostUpdate {
  hostId: number;
  patch: Record<string, unknown>;
}

export interface TestServer {
  mock: MockPluginContext;
  ssh: FakeSsh;
  hostSettings: Record<string, unknown>;
  adminSettings: Record<string, unknown>;
  updates: FakeHostUpdate[];
  created: Array<Record<string, unknown>>;
  fetches: string[];
  request: (
    method: string,
    path: string,
    body?: unknown,
    // Route bodies vary per test; asserting on them is the point.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ) => Promise<{ status: number; body: any; text: string }>;
  close: () => Promise<void>;
}

export interface StartOptions {
  permissions?: string[];
  level?: PluginHostAccess["permissionLevel"] | "none";
  owner?: boolean;
  hostSettings?: Record<string, unknown>;
  adminSettings?: Record<string, unknown>;
  /** The host as ctx.ssh.resolveHost returns it. */
  resolved?: Record<string, unknown> | null;
  savedKeys?: Array<{ id: number; name: string; publicKey: string | null }>;
  exec?: (
    host: number | Record<string, unknown>,
    command: string,
    stdin: string,
  ) => Promise<PluginSshExecResult>;
  fetch?: (url: string, init?: { body?: string }) => Promise<Response>;
  updateFails?: boolean;
}

export const ALL = [
  "security-center.use",
  "security-center.scan-vulns",
  "security-center.rotate",
];

/** The plugin on a real express app, with ssh, hosts and fetch played by fakes. */
export async function startServer(
  options: StartOptions = {},
): Promise<TestServer> {
  let router: Router | null = null;
  const db = await createTestDb(pluginDir);
  db.sqlite.exec(
    "INSERT INTO users (id) VALUES ('user-1'), ('user-2'); INSERT INTO ssh_data (id) VALUES (1), (2), (3);",
  );
  const mock = createMockCtx({
    sandbox: true,
    pluginId: manifest.id,
    manifest,
    capabilities: manifest.capabilities,
    db: db.database,
    router: () => (router = express.Router()),
    permissions: options.permissions ?? ["security-center.use"],
    dataDir: mkdtempSync(path.join(os.tmpdir(), "security-test-")),
  });
  mock.setActor("user-1");

  const hostSettings: Record<string, unknown> = {
    enableSecurity: true,
    ...options.hostSettings,
  };
  const adminSettings: Record<string, unknown> = {
    scanVulns: true,
    osvUrl: "https://osv.test",
    checkKev: false,
    ...options.adminSettings,
  };
  Object.assign(mock.ctx.settings, {
    getAll: async (scope: string) => (scope === "host" ? hostSettings : {}),
    get: async (key: string) => adminSettings[key],
  });

  const rank = { connect: 1, view: 2, edit: 3, manage: 4 } as const;
  const level = options.level ?? "manage";
  const updates: FakeHostUpdate[] = [];
  Object.assign(mock.ctx.hosts, {
    checkAccess: async (
      _id: number,
      need: keyof typeof rank = "connect",
    ): Promise<PluginHostAccess> => ({
      hasAccess: level !== "none" && rank[level] >= rank[need],
      isOwner: options.owner !== false,
      isShared: false,
      permissionLevel: level === "none" ? undefined : level,
    }),
    get: async (id: number) => ({
      id,
      port: 22,
      name: `host${id}`,
      ip: "10.0.0.1",
      userId: "user-1",
    }),
    list: async () => [{ id: 1, name: "host1", ip: "10.0.0.1", port: 22 }],
    update: async (hostId: number, patch: Record<string, unknown>) => {
      if (options.updateFails) throw new Error("update refused");
      updates.push({ hostId, patch });
      return { id: hostId };
    },
  });

  const created: Array<Record<string, unknown>> = [];
  Object.assign(mock.ctx.credentials, {
    listSshKeys: async () => options.savedKeys ?? [],
    createSshKey: async (input: Record<string, unknown>) => {
      created.push(input);
      return { id: 900 + created.length };
    },
  });

  const ssh: FakeSsh = { calls: [], replies: [] };
  Object.assign(mock.ctx.ssh, {
    resolveHost: async (id: number) =>
      options.resolved === null
        ? null
        : (options.resolved ?? {
            id,
            ip: "10.0.0.1",
            port: 22,
            username: "bob",
            authType: "password",
            name: `host${id}`,
          }),
    exec: async (
      host: number | Record<string, unknown>,
      command: string,
      opts?: { stdin?: string },
    ) => {
      const stdin = opts?.stdin ?? "";
      ssh.calls.push({
        hostId: typeof host === "number" ? host : "custom",
        command,
        stdin,
        host: typeof host === "number" ? undefined : host,
      });
      if (options.exec) return options.exec(host, command, stdin);
      const reply = ssh.replies.find(
        (r) => stdin.includes(r.match) || command.includes(r.match),
      );
      return {
        stdout: reply?.stdout ?? "",
        stderr: reply?.stderr ?? "",
        code: reply?.code ?? 0,
        truncated: false,
        timedOut: false,
      };
    },
  });

  const fetches: string[] = [];
  Object.assign(mock.ctx, {
    fetch: async (url: string, init?: { body?: string }) => {
      fetches.push(url);
      if (options.fetch) return options.fetch(url, init);
      return new Response("{}", { status: 404 });
    },
  });

  const { activate } = await import("../../src/backend/index.js");
  await activate(mock.ctx);

  const app = express();
  app.use(express.json());
  app.use((req, res, next) => router!(req, res, next));
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as AddressInfo).port;

  return {
    mock,
    ssh,
    hostSettings,
    adminSettings,
    updates,
    created,
    fetches,
    async request(method, path, body) {
      const res = await fetch(`http://127.0.0.1:${port}${path}`, {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await res.text();
      let parsed: unknown = null;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch {
        parsed = null;
      }
      return { status: res.status, body: parsed, text };
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}
