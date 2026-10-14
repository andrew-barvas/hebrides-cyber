import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  encryptCredentials,
  decryptCredentials,
  isEncryptedBlob,
  isCredentialEncryptionConfigured,
  encryptSecret,
  decryptSecret,
  isEncryptedSecret,
  sealSecrets,
  revealSecrets,
} from "./credentialEncryption";

// 32-byte base64 key for the suite.
const TEST_KEY = Buffer.alloc(32, 7).toString("base64");

describe("credentialEncryption", () => {
  const original = process.env.CREDENTIALS_ENC_KEY;
  beforeEach(() => {
    process.env.CREDENTIALS_ENC_KEY = TEST_KEY;
  });
  afterEach(() => {
    if (original === undefined) delete process.env.CREDENTIALS_ENC_KEY;
    else process.env.CREDENTIALS_ENC_KEY = original;
  });

  it("round-trips a credentials object", () => {
    const creds = { accessKeyId: "AKIA123", secretAccessKey: "s3cr3t", region: "eu-west-1" };
    const blob = encryptCredentials(creds);
    expect(isEncryptedBlob(blob)).toBe(true);
    expect(decryptCredentials(blob)).toEqual(creds);
  });

  it("produces a different ciphertext each time (random IV)", () => {
    const a = encryptCredentials({ x: "1" });
    const b = encryptCredentials({ x: "1" });
    expect(a.data === b.data && a.iv === b.iv).toBe(false);
    expect(decryptCredentials(a)).toEqual(decryptCredentials(b));
  });

  it("passes legacy plaintext objects through unchanged", () => {
    const legacy = { accessKeyId: "AKIA", secretAccessKey: "x" };
    expect(isEncryptedBlob(legacy)).toBe(false);
    expect(decryptCredentials(legacy)).toEqual(legacy);
  });

  it("rejects tampered ciphertext (auth tag)", () => {
    const blob = encryptCredentials({ secret: "value" });
    const tampered = { ...blob, data: Buffer.from("tampered").toString("base64") };
    expect(() => decryptCredentials(tampered)).toThrow();
  });

  it("reports configured / not configured correctly", () => {
    expect(isCredentialEncryptionConfigured()).toBe(true);
    delete process.env.CREDENTIALS_ENC_KEY;
    expect(isCredentialEncryptionConfigured()).toBe(false);
    expect(() => encryptCredentials({ a: "b" })).toThrow(/CREDENTIALS_ENC_KEY/);
  });

  it("cannot decrypt an encrypted blob once the key is removed", () => {
    const blob = encryptCredentials({ a: "b" });
    delete process.env.CREDENTIALS_ENC_KEY;
    expect(() => decryptCredentials(blob)).toThrow(/CREDENTIALS_ENC_KEY/);
  });
});

describe("single-string secrets", () => {
  const original = process.env.CREDENTIALS_ENC_KEY;
  beforeEach(() => {
    process.env.CREDENTIALS_ENC_KEY = TEST_KEY;
  });
  afterEach(() => {
    if (original === undefined) delete process.env.CREDENTIALS_ENC_KEY;
    else process.env.CREDENTIALS_ENC_KEY = original;
  });

  it("round-trips a secret, including characters that break naive encodings", () => {
    for (const secret of ["abc", "with:colons:in:it", "ünï©ode ✓", "x".repeat(5000), "session=a; Path=/; HttpOnly"]) {
      const enc = encryptSecret(secret);
      expect(isEncryptedSecret(enc)).toBe(true);
      expect(decryptSecret(enc)).toBe(secret);
    }
  });

  it("uses a fresh IV each time", () => {
    expect(encryptSecret("same")).not.toBe(encryptSecret("same"));
  });

  it("passes a legacy plaintext secret through unchanged", () => {
    expect(isEncryptedSecret("plain-token")).toBe(false);
    expect(decryptSecret("plain-token")).toBe("plain-token");
  });

  it("rejects tampered ciphertext and a wrong key", () => {
    const enc = encryptSecret("secret");
    const [prefix, iv, tag, data] = [enc.slice(0, 7), ...enc.slice(7).split(":")];
    const flipped = Buffer.from(data, "base64");
    flipped[0] ^= 1;
    expect(() => decryptSecret(`${prefix}${iv}:${tag}:${flipped.toString("base64")}`)).toThrow();
    process.env.CREDENTIALS_ENC_KEY = Buffer.alloc(32, 9).toString("base64");
    expect(() => decryptSecret(enc)).toThrow();
  });

  it("rejects a malformed encrypted value", () => {
    expect(() => decryptSecret("enc:v1:only-one-part")).toThrow(/Malformed/);
  });

  it("refuses to encrypt, and to decrypt, once the key is removed", () => {
    const enc = encryptSecret("secret");
    delete process.env.CREDENTIALS_ENC_KEY;
    expect(() => encryptSecret("secret")).toThrow(/CREDENTIALS_ENC_KEY/);
    expect(() => decryptSecret(enc)).toThrow(/CREDENTIALS_ENC_KEY/);
  });

  it("sealSecrets encrypts only the named, non-empty string fields", () => {
    const row = { owner: "o1", token: "tok", other: "visible", empty: "", missing: null as string | null };
    const sealed = sealSecrets(row, ["token", "empty", "missing"]);
    expect(isEncryptedSecret(sealed.token)).toBe(true);
    expect(sealed.owner).toBe("o1");
    expect(sealed.other).toBe("visible");
    expect(sealed.empty).toBe("");
    expect(sealed.missing).toBeNull();
    expect(row.token).toBe("tok");
  });

  it("revealSecrets decrypts sealed and legacy fields, and returns null when any cannot be decrypted", () => {
    const sealed = sealSecrets({ a: "one", b: "two" }, ["a"]);
    expect(revealSecrets(sealed, ["a", "b"])).toEqual({ a: "one", b: "two" });
    delete process.env.CREDENTIALS_ENC_KEY;
    expect(revealSecrets(sealed, ["a", "b"])).toBeNull();
    expect(revealSecrets({ a: "legacy" }, ["a"])).toEqual({ a: "legacy" });
  });
});
