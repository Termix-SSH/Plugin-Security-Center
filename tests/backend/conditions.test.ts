import { describe, expect, it } from "vitest";
import {
  DEFAULT_LIMITS,
  diff,
  findingsOf,
  loud,
  overall,
  scoreOf,
} from "../../src/backend/conditions";
import { parseReading } from "../../src/backend/parsers";
import type { Vuln } from "../../src/shared/types";
import { ED25519_LINE, keysOutput } from "./fixtures";

const NOW = 1_700_000_000_000 + 400 * 86_400_000;

function kinds(output: string, limits = DEFAULT_LIMITS): string[] {
  return findingsOf(parseReading(output), limits, NOW).map((f) => f.kind);
}

function vuln(over: Partial<Vuln> = {}): Vuln {
  return {
    id: "DSA-1",
    cves: [],
    package: "p",
    version: "1",
    fixed: "2",
    severity: "high",
    score: null,
    kev: false,
    summary: "",
    ignored: false,
    ignoreNote: "",
    ...over,
  };
}

describe("key findings", () => {
  const found = kinds(keysOutput());

  it("flags weak and exposed keys", () => {
    expect(found).toContain("key-dsa");
    expect(found).toContain("key-rsa-small");
    expect(found).toContain("key-unprotected");
    expect(found).toContain("key-private-perms");
    expect(found).toContain("authkeys-writable");
    expect(found).toContain("ssh-dir-writable");
  });

  it("flags risky sshd settings", () => {
    expect(found).toContain("sshd-root-login");
    expect(found).toContain("sshd-password-auth");
    expect(found).toContain("sshd-weak-crypto");
    expect(found).not.toContain("sshd-empty-passwords");
    expect(kinds(keysOutput({ sshd: "permitemptypasswords yes" }))).toContain(
      "sshd-empty-passwords",
    );
  });

  it("applies the RSA limit", () => {
    const loose = kinds(keysOutput(), { ...DEFAULT_LIMITS, minRsaBits: 2048 });
    const strict = findingsOf(parseReading(keysOutput()), DEFAULT_LIMITS, NOW);
    expect(strict.filter((f) => f.kind === "key-rsa-small")).toHaveLength(3);
    expect(loose.filter((k) => k === "key-rsa-small")).toHaveLength(1);
  });

  it("only reports stale keys when a limit is set", () => {
    expect(found).not.toContain("key-stale");
    expect(
      kinds(keysOutput(), { ...DEFAULT_LIMITS, keyMaxAgeDays: 365 }),
    ).toContain("key-stale");
  });

  it("flags keys Termix does not know, only when it could check", () => {
    const reading = parseReading(keysOutput());
    for (const key of reading.keys) key.known = false;
    expect(findingsOf(reading).map((f) => f.kind)).toContain("key-unknown");
    for (const key of reading.keys) key.known = true;
    expect(findingsOf(reading).map((f) => f.kind)).not.toContain("key-unknown");
  });

  it("flags an open key for root", () => {
    expect(found).toContain("root-key-open");
    const closed = keysOutput().replace(
      `${ED25519_LINE} root-key`,
      `from="10.0.0.1" ${ED25519_LINE} root-key`,
    );
    expect(kinds(closed)).not.toContain("root-key-open");
  });

  it("is quiet for a clean host", () => {
    const clean = keysOutput({
      sshd: "permitrootlogin no\npasswordauthentication no",
    })
      .split("\n")
      .filter(
        (l) =>
          !l.includes("ssh-dss") &&
          !l.startsWith("@@dir") &&
          !l.includes("from="),
      )
      .join("\n")
      .replace("664 1600000000", "600 1600000000")
      .replace("644 1600000000\t0", "600 1600000000\t1");
    const reading = parseReading(clean);
    for (const key of reading.keys) key.known = true;
    const result = findingsOf(reading, {
      ...DEFAULT_LIMITS,
      minRsaBits: 2048,
    });
    expect(result.map((f) => f.kind)).toEqual([]);
  });
});

describe("health and score", () => {
  it("is unknown without a reading", () => {
    expect(overall(null, [], [])).toBe("unknown");
  });

  it("fails on a critical finding or an exploited vulnerability", () => {
    const reading = parseReading(keysOutput());
    const findings = findingsOf(reading);
    expect(overall(reading, findings, [])).toBe("fail");
    expect(overall(reading, [], [vuln({ kev: true })])).toBe("fail");
    expect(overall(reading, [], [vuln({ severity: "critical" })])).toBe("fail");
  });

  it("warns on high vulnerabilities and ignores hidden ones", () => {
    const reading = parseReading(keysOutput());
    expect(overall(reading, [], [vuln()])).toBe("warn");
    expect(overall(reading, [], [vuln({ ignored: true, kev: true })])).toBe(
      "ok",
    );
  });

  it("only fails for critical vulnerabilities that have a fix", () => {
    const reading = parseReading(keysOutput({ sshd: "permitrootlogin no" }));
    const clean = findingsOf(reading).filter((f) => f.severity === "low");
    expect(
      overall(reading, clean, [vuln({ severity: "critical", fixed: "" })]),
    ).toBe("warn");
    expect(overall(reading, clean, [vuln({ severity: "critical" })])).toBe(
      "fail",
    );
    expect(
      overall(reading, clean, [vuln({ severity: "high", fixed: "" })]),
    ).toBe("ok");
  });

  it("counts a fixable vulnerability more than an unfixable one", () => {
    const fixable = scoreOf([], [vuln({ severity: "critical" })]);
    const unfixable = scoreOf([], [vuln({ severity: "critical", fixed: "" })]);
    expect(fixable).toBeLessThan(unfixable);
    expect(unfixable).toBeGreaterThan(95);
    const many = Array.from({ length: 500 }, () =>
      vuln({ severity: "critical", fixed: "" }),
    );
    expect(scoreOf([], many)).toBeGreaterThanOrEqual(40);
  });

  it("scores from 100 down to 0", () => {
    expect(scoreOf([], [])).toBe(100);
    const findings = findingsOf(parseReading(keysOutput()));
    expect(scoreOf(findings, [])).toBeLessThan(100);
    expect(scoreOf(findings, Array(20).fill(vuln({ kev: true })))).toBe(0);
    expect(scoreOf([], [vuln({ ignored: true, kev: true })])).toBe(100);
  });
});

describe("changes", () => {
  it("lists what started and what cleared", () => {
    const changes = diff(
      new Set(["key-dsa|a", "key-stale|b"]),
      new Set(["key-dsa|a", "key-unknown|c"]),
    );
    expect(changes).toEqual([
      { kind: "key-unknown", subject: "c", on: true },
      { kind: "key-stale", subject: "b", on: false },
    ]);
  });

  it("alerts for critical and high only", () => {
    expect(loud("critical")).toBe(true);
    expect(loud("high")).toBe(true);
    expect(loud("medium")).toBe(false);
    expect(loud("low")).toBe(false);
  });
});
