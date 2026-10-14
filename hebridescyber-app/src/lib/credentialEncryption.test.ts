import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  encryptCredentials,
  decryptCredentials,
  isEncryptedBlob,
  isCredentialEncryptionConfigured,
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
