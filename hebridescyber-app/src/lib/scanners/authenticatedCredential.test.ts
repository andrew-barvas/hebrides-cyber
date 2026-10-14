import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { resolveAuthCredential, type StoredAuthCredential } from "./authenticatedCheck";
import { sealSecrets } from "../credentialEncryption";

const TEST_KEY = Buffer.alloc(32, 7).toString("base64");

const cookieRow: StoredAuthCredential = { auth_type: "cookie", cookie_value: "session=PLAIN", basic_username: null, basic_password: null };
const basicRow: StoredAuthCredential = { auth_type: "basic", cookie_value: null, basic_username: "svc", basic_password: "pw-PLAIN" };

describe("resolveAuthCredential", () => {
  const original = process.env.CREDENTIALS_ENC_KEY;
  beforeEach(() => {
    process.env.CREDENTIALS_ENC_KEY = TEST_KEY;
  });
  afterEach(() => {
    if (original === undefined) delete process.env.CREDENTIALS_ENC_KEY;
    else process.env.CREDENTIALS_ENC_KEY = original;
  });

  it("decrypts a stored cookie and Basic Auth password", () => {
    expect(resolveAuthCredential(sealSecrets(cookieRow, ["cookie_value"]))).toEqual({
      credential: { type: "cookie", cookieValue: "session=PLAIN" },
      decrypted: true,
    });
    expect(resolveAuthCredential(sealSecrets(basicRow, ["basic_password"]))).toEqual({
      credential: { type: "basic", username: "svc", password: "pw-PLAIN" },
      decrypted: true,
    });
  });

  it("still uses a legacy plaintext credential that hasn't been re-saved", () => {
    expect(resolveAuthCredential(cookieRow).credential).toEqual({ type: "cookie", cookieValue: "session=PLAIN" });
    expect(resolveAuthCredential(basicRow).credential).toEqual({ type: "basic", username: "svc", password: "pw-PLAIN" });
  });

  it("returns no credential, flagged as undecryptable, when the key is missing or rotated — never ciphertext", () => {
    const sealed = sealSecrets(cookieRow, ["cookie_value"]);
    delete process.env.CREDENTIALS_ENC_KEY;
    expect(resolveAuthCredential(sealed)).toEqual({ credential: null, decrypted: false });
    process.env.CREDENTIALS_ENC_KEY = Buffer.alloc(32, 9).toString("base64");
    expect(resolveAuthCredential(sealed)).toEqual({ credential: null, decrypted: false });
  });

  it("returns nothing, without flagging a decryption problem, when there is no row or the row is incomplete", () => {
    expect(resolveAuthCredential(null)).toEqual({ credential: null, decrypted: true });
    expect(resolveAuthCredential({ ...cookieRow, cookie_value: null })).toEqual({ credential: null, decrypted: true });
    expect(resolveAuthCredential({ ...basicRow, basic_username: null })).toEqual({ credential: null, decrypted: true });
    expect(resolveAuthCredential({ ...cookieRow, auth_type: "oauth" })).toEqual({ credential: null, decrypted: true });
  });
});
