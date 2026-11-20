import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

const { blobState } = vi.hoisted(() => ({
  blobState: { data: new Map<string, Buffer>(), created: 0, failGet: null as null | { statusCode?: number; message: string } },
}));

vi.mock("@azure/storage-blob", () => ({
  BlobServiceClient: {
    fromConnectionString: () => ({
      getContainerClient: () => ({
        createIfNotExists: async () => {
          blobState.created++;
        },
        getBlockBlobClient: (key: string) => ({
          downloadToBuffer: async () => {
            if (blobState.failGet) throw Object.assign(new Error(blobState.failGet.message), { statusCode: blobState.failGet.statusCode });
            const v = blobState.data.get(key);
            if (!v) throw Object.assign(new Error("BlobNotFound"), { statusCode: 404 });
            return v;
          },
          uploadData: async (data: Buffer) => {
            blobState.data.set(key, data);
          },
        }),
      }),
    }),
  },
}));

import { azureObjectStore, cveIndexObjectStore, memoryObjectStore, supabaseObjectStore } from "./objectStore";

function supabaseClient(opts: { download?: { data?: Blob; error?: unknown }; upload?: { error?: unknown }; createBucket?: { error?: unknown } } = {}) {
  const calls = { createBucket: 0, uploads: [] as string[] };
  const client = {
    storage: {
      createBucket: async () => {
        calls.createBucket++;
        return opts.createBucket ?? { error: null };
      },
      from: () => ({
        download: async () => opts.download ?? { data: new Blob([Buffer.from("hello")]), error: null },
        upload: async (key: string) => {
          calls.uploads.push(key);
          return opts.upload ?? { error: null };
        },
      }),
    },
  } as unknown as SupabaseClient;
  return { client, calls };
}

describe("supabaseObjectStore", () => {
  it("reads an object's bytes", async () => {
    const { client } = supabaseClient();
    expect((await supabaseObjectStore(client).get("k"))?.toString()).toBe("hello");
  });

  it.each([{ statusCode: "404", message: "x" }, { status: 400, message: "x" }, { message: "Object not found" }])("treats a missing object as null (%o)", async (error) => {
    const { client } = supabaseClient({ download: { error } });
    expect(await supabaseObjectStore(client).get("k")).toBeNull();
  });

  it("throws on any other read failure", async () => {
    const { client } = supabaseClient({ download: { error: { statusCode: "500", message: "boom" } } });
    await expect(supabaseObjectStore(client).get("k")).rejects.toThrow("storage get k failed: boom");
  });

  it("creates the private bucket once, then uploads", async () => {
    const { client, calls } = supabaseClient({ createBucket: { error: { message: "The resource already exists" } } });
    const store = supabaseObjectStore(client);
    await store.put("a", Buffer.from("1"));
    await store.put("b", Buffer.from("2"));
    expect(calls.createBucket).toBe(1);
    expect(calls.uploads).toEqual(["a", "b"]);
  });

  it("throws when the bucket can't be created or an upload fails", async () => {
    await expect(supabaseObjectStore(supabaseClient({ createBucket: { error: { message: "quota" } } }).client).put("a", Buffer.from("1"))).rejects.toThrow("storage bucket cve-index: quota");
    await expect(supabaseObjectStore(supabaseClient({ upload: { error: { message: "too big" } } }).client).put("a", Buffer.from("1"))).rejects.toThrow("storage put a failed: too big");
  });
});

describe("azureObjectStore", () => {
  beforeEach(() => {
    blobState.data.clear();
    blobState.created = 0;
    blobState.failGet = null;
  });

  it("round-trips objects, creating the container once, and treats 404 as missing", async () => {
    const store = await azureObjectStore("UseDevelopmentStorage=true");
    expect(await store.get("k")).toBeNull();
    await store.put("k", Buffer.from("v"));
    await store.put("k2", Buffer.from("w"));
    expect((await store.get("k"))?.toString()).toBe("v");
    expect(blobState.created).toBe(1);
  });

  it("throws on other read failures", async () => {
    blobState.failGet = { statusCode: 403, message: "AuthorizationFailure" };
    const store = await azureObjectStore("conn");
    await expect(store.get("k")).rejects.toThrow("blob get k failed: AuthorizationFailure");
  });
});

describe("cveIndexObjectStore", () => {
  it("uses Supabase Storage by default and Azure only when asked", async () => {
    const { client, calls } = supabaseClient();
    await (await cveIndexObjectStore(client, {})).put("x", Buffer.from("1"));
    expect(calls.uploads).toEqual(["x"]);
    const azure = await cveIndexObjectStore(client, { CVE_INDEX_STORE: "azure", AZURE_STORAGE_CONNECTION_STRING: "conn" });
    await azure.put("y", Buffer.from("2"));
    expect(calls.uploads).toEqual(["x"]);
  });

  it("refuses Azure without a connection string", async () => {
    await expect(cveIndexObjectStore(supabaseClient().client, { CVE_INDEX_STORE: "azure" })).rejects.toThrow("AZURE_STORAGE_CONNECTION_STRING is not set");
  });
});

describe("memoryObjectStore", () => {
  it("counts writes and lists keys", async () => {
    const store = memoryObjectStore({ b: Buffer.from("1") });
    await store.put("a", Buffer.from("2"));
    expect(store.keys()).toEqual(["a", "b"]);
    expect(store.puts).toBe(1);
    expect(await store.get("missing")).toBeNull();
  });
});
