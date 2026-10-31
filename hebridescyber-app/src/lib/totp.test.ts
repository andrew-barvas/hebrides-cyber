import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { base32Decode, generateTotp, isValidTotpSecret, msUntilNextTotp, normaliseTotpSecret } from "./totp";
import { decryptSecret, isEncryptedSecret, revealSecrets, sealSecrets } from "./credentialEncryption";

// RFC 6238 appendix B: the SHA-1 secret is ASCII "12345678901234567890". The
// RFC's vectors are 8 digits; the 6-digit code is the last six of them.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const VECTORS: Array<[number, string]> = [
  [59, "287082"],
  [1111111109, "081804"],
  [1111111111, "050471"],
  [1234567890, "005924"],
  [2000000000, "279037"],
  [20000000000, "353130"],
];

describe("generateTotp", () => {
  it.each(VECTORS)("matches the RFC 6238 SHA-1 vector at t=%i", (seconds, code) => {
    expect(generateTotp(RFC_SECRET, seconds * 1000)).toBe(code);
  });

  it("is stable within a 30 s step and changes at the boundary", () => {
    expect(generateTotp(RFC_SECRET, 30_000)).toBe(generateTotp(RFC_SECRET, 59_999));
    expect(generateTotp(RFC_SECRET, 59_999)).not.toBe(generateTotp(RFC_SECRET, 60_000));
  });

  it("accepts lower case, spaces, dashes and padding as authenticator apps display them", () => {
    expect(generateTotp("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq====", 59_000)).toBe("287082");
  });

  it("throws on an invalid secret rather than inventing a code", () => {
    expect(() => generateTotp("not*base32", 0)).toThrow();
    expect(() => generateTotp("MFRGG", 0)).toThrow();
  });
});

describe("secret helpers", () => {
  it("validates length and alphabet", () => {
    expect(isValidTotpSecret(RFC_SECRET)).toBe(true);
    expect(isValidTotpSecret("")).toBe(false);
    expect(isValidTotpSecret("MFRGG")).toBe(false);
    expect(isValidTotpSecret("1890" + RFC_SECRET)).toBe(false);
  });
  it("decodes base32 and normalises", () => {
    expect(base32Decode("MFRGG===")?.toString()).toBe("abc");
    expect(normaliseTotpSecret(" ab-cd ef== ")).toBe("ABCDEF");
  });
  it("reports time to the next step", () => {
    expect(msUntilNextTotp(0)).toBe(30_000);
    expect(msUntilNextTotp(29_000)).toBe(1_000);
  });
});

describe("stored TOTP secret", () => {
  const original = process.env.CREDENTIALS_ENC_KEY;
  beforeEach(() => {
    process.env.CREDENTIALS_ENC_KEY = Buffer.alloc(32, 7).toString("base64");
  });
  afterEach(() => {
    if (original === undefined) delete process.env.CREDENTIALS_ENC_KEY;
    else process.env.CREDENTIALS_ENC_KEY = original;
  });

  it("round-trips through AES-256-GCM and never stores the plaintext", () => {
    const sealed = sealSecrets({ totp_secret: RFC_SECRET }, ["totp_secret"]);
    expect(isEncryptedSecret(sealed.totp_secret)).toBe(true);
    expect(sealed.totp_secret).not.toContain(RFC_SECRET);
    expect(decryptSecret(sealed.totp_secret)).toBe(RFC_SECRET);
    expect(generateTotp(revealSecrets(sealed, ["totp_secret"])!.totp_secret, 59_000)).toBe("287082");
  });

  it("is unusable (null), not plaintext, once the key changes", () => {
    const sealed = sealSecrets({ totp_secret: RFC_SECRET }, ["totp_secret"]);
    process.env.CREDENTIALS_ENC_KEY = Buffer.alloc(32, 9).toString("base64");
    expect(revealSecrets(sealed, ["totp_secret"])).toBeNull();
  });
});
