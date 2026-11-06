import { generateKeyPairSync } from "node:crypto";

/** The public host key GitHub publishes, and its known fingerprint. */
export const ED25519_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
export const ED25519_FP = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU";

function sshString(data: Buffer): Buffer {
  const head = Buffer.alloc(4);
  head.writeUInt32BE(data.length);
  return Buffer.concat([head, data]);
}

function mpint(data: Buffer): Buffer {
  let start = 0;
  while (start < data.length - 1 && data[start] === 0) start += 1;
  const trimmed = data.subarray(start);
  return sshString(
    trimmed[0] & 0x80 ? Buffer.concat([Buffer.from([0]), trimmed]) : trimmed,
  );
}

/** A real RSA public key line of the given size. */
export function rsaLine(bits: number, comment = ""): string {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: bits });
  const jwk = publicKey.export({ format: "jwk" });
  const blob = Buffer.concat([
    sshString(Buffer.from("ssh-rsa")),
    mpint(Buffer.from(jwk.e as string, "base64url")),
    mpint(Buffer.from(jwk.n as string, "base64url")),
  ]);
  return `ssh-rsa ${blob.toString("base64")}${comment ? ` ${comment}` : ""}`;
}

/** A DSA looking blob: only the type and the first number matter to the parser. */
export function dsaLine(comment = ""): string {
  const blob = Buffer.concat([
    sshString(Buffer.from("ssh-dss")),
    mpint(Buffer.alloc(128, 0xab)),
    mpint(Buffer.alloc(20, 0x11)),
    mpint(Buffer.alloc(128, 0x22)),
    mpint(Buffer.alloc(128, 0x33)),
  ]);
  return `ssh-dss ${blob.toString("base64")}${comment ? ` ${comment}` : ""}`;
}

const prefix = (text: string) =>
  text
    .split("\n")
    .map((l) => `> ${l}`)
    .join("\n");

export interface KeysOptions {
  root?: boolean;
  sshd?: string;
  rsaBig?: string;
  rsaSmall?: string;
  dsa?: string;
  privatePub?: string;
}

/** What KEYS_SCRIPT would print for a small host with a few problems. */
export function keysOutput(o: KeysOptions = {}): string {
  const rsaSmall = o.rsaSmall ?? rsaLine(1024, "old@laptop");
  const rsaBig = o.rsaBig ?? rsaLine(2048, "work@desktop");
  const dsa = o.dsa ?? dsaLine("ancient");
  const privatePub = o.privatePub ?? rsaLine(2048, "");
  const sshd =
    o.sshd ??
    [
      "permitrootlogin yes",
      "passwordauthentication yes",
      "permitemptypasswords no",
      "ciphers aes256-gcm@openssh.com,3des-cbc",
    ].join("\n");
  return [
    `@@root ${o.root === false ? 1000 : 0}`,
    "@@os",
    prefix(
      'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"',
    ),
    "@@sshdver",
    "OpenSSH_10.0p2 Debian-7, OpenSSL 3.5.1 1 Jul 2025",
    "@@sshd",
    prefix(sshd),
    "@@file\thost\troot\t/etc/ssh/ssh_host_ed25519_key.pub\t600 1700000000",
    prefix(`${ED25519_LINE} root@host`),
    "@@dir\tbob\t/home/bob/.ssh\t775",
    "@@file\tauthorized\tbob\t/home/bob/.ssh/authorized_keys\t664 1600000000",
    prefix(
      [
        `${ED25519_LINE} laptop`,
        `from="10.0.0.0/8",no-pty ${rsaSmall}`,
        rsaBig,
        dsa,
        "# a comment",
        "",
      ].join("\n"),
    ),
    "@@file\tauthorized\troot\t/root/.ssh/authorized_keys\t600 1700000000",
    prefix(`${ED25519_LINE} root-key`),
    "@@file\tprivate\tbob\t/home/bob/.ssh/id_rsa\t644 1600000000\t0",
    prefix(privatePub),
    "@@reboot 1",
    "@@end",
    "",
  ].join("\n");
}

export const PACKAGES_DPKG = [
  "@@root 0",
  "@@os",
  prefix('ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13"'),
  "@@kernel",
  "6.12.48",
  "@@pkgs dpkg",
  "ii \topenssh\t1:10.0p1-7\topenssh-server\t1:10.0p1-7",
  "ii \topenssh\t1:10.0p1-7\topenssh-client\t1:10.0p1-7",
  "ii \tbash\t5.2.37-2\tbash\t5.2.37-2",
  "rc \told\t1\told\t1",
  "@@end",
  "",
].join("\n");
