import { describe, expect, it } from "vitest";
import {
  keyBlob,
  parsePackages,
  parsePublicKey,
  parseReading,
} from "../../src/backend/parsers";
import {
  ED25519_FP,
  ED25519_LINE,
  PACKAGES_DPKG,
  keysOutput,
  rsaLine,
} from "./fixtures";

describe("public keys", () => {
  it("reads the fingerprint and size of an ed25519 key", () => {
    const key = parsePublicKey(`${ED25519_LINE} me@laptop`)!;
    expect(key.type).toBe("ssh-ed25519");
    expect(key.fingerprint).toBe(ED25519_FP);
    expect(key.bits).toBe(256);
    expect(key.comment).toBe("me@laptop");
    expect(key.options).toBe("");
  });

  it("reads the size of an RSA key", () => {
    expect(parsePublicKey(rsaLine(2048))?.bits).toBe(2048);
    expect(parsePublicKey(rsaLine(1024))?.bits).toBe(1024);
  });

  it("splits options from the key", () => {
    const key = parsePublicKey(
      `command="echo ssh-ed25519 x",no-pty ${ED25519_LINE} ci`,
    )!;
    expect(key.fingerprint).toBe(ED25519_FP);
    expect(key.options).toBe('command="echo ssh-ed25519 x",no-pty');
    expect(key.comment).toBe("ci");
  });

  it("ignores comments, blanks and junk", () => {
    expect(parsePublicKey("# ssh-ed25519 AAAA")).toBeNull();
    expect(parsePublicKey("")).toBeNull();
    expect(parsePublicKey("ssh-ed25519 AAAA")).toBeNull();
    expect(parsePublicKey("not a key")).toBeNull();
  });

  it("finds the base64 part for removal", () => {
    expect(keyBlob(`${ED25519_LINE} me`)).toBe(ED25519_LINE.split(" ")[1]);
    expect(keyBlob("nothing")).toBeNull();
  });
});

describe("key reading", () => {
  const reading = parseReading(keysOutput());

  it("reads the system", () => {
    expect(reading.root).toBe(true);
    expect(reading.os).toMatchObject({ id: "debian", version: "13" });
    expect(reading.sshdVersion).toContain("OpenSSH_10");
    expect(reading.sshdRead).toBe(true);
    expect(reading.sshd.permitrootlogin).toBe("yes");
    expect(reading.rebootRequired).toBe(true);
  });

  it("reads every key with its file", () => {
    const auth = reading.keys.filter((k) => k.kind === "authorized");
    expect(auth).toHaveLength(5);
    expect(reading.keys.filter((k) => k.kind === "host")).toHaveLength(1);
    expect(reading.keys.filter((k) => k.kind === "private")).toHaveLength(1);
    const bob = auth.find((k) => k.comment === "laptop")!;
    expect(bob.user).toBe("bob");
    expect(bob.path).toBe("/home/bob/.ssh/authorized_keys");
    expect(bob.mode).toBe("664");
    expect(bob.mtime).toBe(1600000000);
  });

  it("marks restricted keys and unprotected private keys", () => {
    const restricted = reading.keys.filter((k) => k.restricted);
    expect(restricted).toHaveLength(1);
    expect(restricted[0].options).toContain("from=");
    expect(reading.keys.find((k) => k.kind === "private")?.unprotected).toBe(
      true,
    );
  });

  it("gives each key a different id even when the same key repeats", () => {
    const twice = parseReading(
      keysOutput({ rsaBig: ED25519_LINE, rsaSmall: ED25519_LINE }),
    );
    const ids = twice.keys.map((k) => k.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("notes folders others can write to", () => {
    expect(reading.notes).toContain("dir-writable|bob|/home/bob/.ssh|775");
  });

  it("cannot be fooled by a line that looks like a section", () => {
    const forged = keysOutput().replace(
      "> # a comment",
      "> @@file\tauthorized\troot\t/root/.ssh/authorized_keys\t600 1",
    );
    const parsed = parseReading(forged);
    expect(
      parsed.keys.filter((k) => k.kind === "authorized" && k.user === "root"),
    ).toHaveLength(1);
  });

  it("falls back to the sshd config when sshd -T gave nothing", () => {
    const out = keysOutput().replace(
      "@@sshd\n",
      "@@sshdconf\n> PermitRootLogin yes\n@@sshd\n",
    );
    expect(parseReading(out).sshd.permitrootlogin).toBe("yes");
    const only = keysOutput({ sshd: "x" })
      .replace("@@sshd\n> x", "@@sshdconf\n> PasswordAuthentication yes")
      .replace("@@sshd\n", "");
    const parsed = parseReading(only);
    expect(parsed.sshdRead).toBe(false);
    expect(parsed.sshd.passwordauthentication).toBe("yes");
  });

  it("handles empty output", () => {
    const empty = parseReading("");
    expect(empty.keys).toEqual([]);
    expect(empty.root).toBe(false);
  });
});

describe("package reading", () => {
  it("lists source packages once", () => {
    const list = parsePackages(PACKAGES_DPKG);
    expect(list.manager).toBe("dpkg");
    expect(list.os).toMatchObject({ id: "debian", version: "13" });
    expect(list.kernel).toBe("6.12.48");
    expect(list.packages).toEqual([
      { name: "openssh", version: "1:10.0p1-7" },
      { name: "bash", version: "5.2.37-2" },
    ]);
  });

  it("reads rpm and apk lists", () => {
    const rpm = parsePackages(
      "@@pkgs rpm\nbash\t0\t5.1.8-9.el9\tx86_64\nkernel\t2\t5.14-1\tx86_64\ngpg-pubkey\t(none)\t1-2\t\n",
    );
    expect(rpm.packages).toEqual([
      { name: "bash", version: "5.1.8-9.el9" },
      { name: "kernel", version: "2:5.14-1" },
    ]);
    const apk = parsePackages(
      "@@pkgs apk\nmusl-1.2.5-r1\nopenssl-dev-3.3.2-r0\n",
    );
    expect(apk.packages).toEqual([
      { name: "musl", version: "1.2.5-r1" },
      { name: "openssl-dev", version: "3.3.2-r0" },
    ]);
  });
});
