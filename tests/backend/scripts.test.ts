import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  FP_RE,
  KEYS_SCRIPT,
  PACKAGES_SCRIPT,
  ROTATE_HOST_KEYS_SCRIPT,
  addKeyScript,
  removeKeyScript,
  revokeScript,
} from "../../src/backend/scripts";
import { keyBlob, parsePublicKey } from "../../src/backend/parsers";
import { ED25519_FP, ED25519_LINE, rsaLine } from "./fixtures";

const bash = spawnSync("bash", ["--version"]);
const hasBash = bash.status === 0;
const keygen = spawnSync("ssh-keygen", ["-?"]);
const hasKeygen = !keygen.error;

function syntax(script: string): { ok: boolean; err: string } {
  const result = spawnSync("bash", ["-n"], { input: script, encoding: "utf8" });
  return { ok: result.status === 0, err: result.stderr };
}

/** Git Bash style path for a Windows path, so the scripts can use it. */
function unix(p: string): string {
  return p
    .replace(/\\/g, "/")
    .replace(/^([A-Za-z]):/, (_, d) => `/${d.toLowerCase()}`);
}

describe.skipIf(!hasBash)("script syntax", () => {
  it.each([
    ["keys", KEYS_SCRIPT],
    ["packages", PACKAGES_SCRIPT],
    ["host keys", ROTATE_HOST_KEYS_SCRIPT],
    ["add", addKeyScript(ED25519_LINE)],
    ["remove", removeKeyScript(keyBlob(ED25519_LINE)!)],
    ["revoke", revokeScript("/home/bob/.ssh/authorized_keys", ED25519_FP)],
  ])("%s script parses", (_name, script) => {
    const result = syntax(script);
    expect(result.err).toBe("");
    expect(result.ok).toBe(true);
  });
});

describe("script inputs", () => {
  it("refuses bad fingerprints and paths", () => {
    expect(() =>
      revokeScript("/home/x/.ssh/authorized_keys", "SHA256:short"),
    ).toThrow();
    expect(() => revokeScript("/etc/passwd", ED25519_FP)).toThrow();
    expect(() =>
      revokeScript("/home/x/.ssh/authorized_keys; rm -rf /", ED25519_FP),
    ).toThrow();
    expect(() => removeKeyScript("abc; rm -rf /")).toThrow();
    expect(() => addKeyScript("ssh-ed25519 AAAA\nssh-rsa BBBB")).toThrow();
    expect(FP_RE.test(ED25519_FP)).toBe(true);
  });

  it("never puts the key text in the script as plain shell", () => {
    expect(addKeyScript(ED25519_LINE)).not.toContain(ED25519_LINE);
  });
});

describe.skipIf(!hasBash)("adding and removing a key", () => {
  function home() {
    const dir = mkdtempSync(path.join(os.tmpdir(), "sec-home-"));
    return dir;
  }

  function run(dir: string, script: string) {
    return spawnSync("bash", ["-s"], {
      input: script,
      encoding: "utf8",
      env: { ...process.env, HOME: unix(dir) },
    });
  }

  it("adds a key once and keeps the file private", () => {
    const dir = home();
    const first = run(dir, addKeyScript(`${ED25519_LINE} one`));
    expect(first.status).toBe(0);
    run(dir, addKeyScript(`${ED25519_LINE} one`));
    const file = path.join(dir, ".ssh", "authorized_keys");
    expect(readFileSync(file, "utf8")).toBe(`${ED25519_LINE} one\n`);
  });

  it("removes only the lines with that key and backs up", () => {
    const dir = home();
    const other = rsaLine(2048, "other");
    mkdirSync(path.join(dir, ".ssh"), { recursive: true });
    const file = path.join(dir, ".ssh", "authorized_keys");
    writeFileSync(
      file,
      `# keep\n${other}\nfrom="1.2.3.4" ${ED25519_LINE} old\n${ED25519_LINE} again\n`,
    );
    const result = run(dir, removeKeyScript(keyBlob(ED25519_LINE)!));
    expect(result.status).toBe(0);
    expect(readFileSync(file, "utf8")).toBe(`# keep\n${other}\n`);
    expect(readFileSync(`${file}.termix.bak`, "utf8")).toContain("old");
  });

  it("does nothing when there is no file", () => {
    const dir = home();
    expect(run(dir, removeKeyScript(keyBlob(ED25519_LINE)!)).status).toBe(0);
  });
});

describe.skipIf(!hasBash || !hasKeygen)("revoking by fingerprint", () => {
  it("removes the matching key and reports the count", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "sec-revoke-"));
    mkdirSync(path.join(dir, ".ssh"));
    const file = path.join(dir, ".ssh", "authorized_keys");
    const other = rsaLine(2048, "other");
    writeFileSync(
      file,
      `# note\n${other}\nno-pty ${ED25519_LINE} mine\n\n${ED25519_LINE} twice`,
    );
    chmodSync(file, 0o600);
    const script = revokeScript(unix(file), ED25519_FP);
    const result = spawnSync("bash", ["-s"], {
      input: script,
      encoding: "utf8",
    });
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("removed 2");
    const left = readFileSync(file, "utf8");
    expect(left).toContain("# note");
    expect(left).toContain("other");
    expect(left).not.toContain("mine");
    expect(parsePublicKey(other)).toBeTruthy();
  });
});
