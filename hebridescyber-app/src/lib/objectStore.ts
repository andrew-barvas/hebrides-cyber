// A minimal key/value object store for bulk reference data that must not sit
// in the Postgres database (the Supabase Free plan's 500 MB limit counts
// tables, not file storage). Used by cveIndexObjects.ts.
//
// Two backends, chosen explicitly by CVE_INDEX_STORE (never switched
// implicitly, because a new backend starts empty):
//   - "supabase" (default): a private Supabase Storage bucket, reached with
//     the service-role client every worker already has.
//   - "azure": an Azure Blob container, via AZURE_STORAGE_CONNECTION_STRING.
import type { SupabaseClient } from "@supabase/supabase-js";

export interface ObjectStore {
  /** The object's bytes, or null when it doesn't exist. Throws on any other failure. */
  get(key: string): Promise<Buffer | null>;
  put(key: string, data: Buffer, contentType?: string): Promise<void>;
}

export const CVE_INDEX_BUCKET = "cve-index";

export function supabaseObjectStore(client: SupabaseClient, bucket: string = CVE_INDEX_BUCKET): ObjectStore {
  let ensured = false;
  return {
    async get(key) {
      const { data, error } = await client.storage.from(bucket).download(key);
      if (error) {
        const status = (error as { statusCode?: string | number; status?: number }).statusCode ?? (error as { status?: number }).status;
        if (String(status) === "404" || String(status) === "400" || /not found/i.test(error.message)) return null;
        throw new Error(`storage get ${key} failed: ${error.message}`);
      }
      return Buffer.from(await data.arrayBuffer());
    },
    async put(key, data, contentType = "application/octet-stream") {
      if (!ensured) {
        // Private bucket; idempotent (an "already exists" error is fine).
        const { error } = await client.storage.createBucket(bucket, { public: false });
        if (error && !/already exists|duplicate/i.test(error.message)) throw new Error(`storage bucket ${bucket}: ${error.message}`);
        ensured = true;
      }
      const { error } = await client.storage.from(bucket).upload(key, data, { upsert: true, contentType });
      if (error) throw new Error(`storage put ${key} failed: ${error.message}`);
    },
  };
}

export async function azureObjectStore(connectionString: string, container: string = CVE_INDEX_BUCKET): Promise<ObjectStore> {
  const { BlobServiceClient } = await import("@azure/storage-blob");
  const client = BlobServiceClient.fromConnectionString(connectionString).getContainerClient(container);
  let ensured = false;
  return {
    async get(key) {
      try {
        return await client.getBlockBlobClient(key).downloadToBuffer();
      } catch (err) {
        if ((err as { statusCode?: number }).statusCode === 404) return null;
        throw new Error(`blob get ${key} failed: ${(err as Error).message}`);
      }
    },
    async put(key, data, contentType = "application/octet-stream") {
      if (!ensured) {
        await client.createIfNotExists();
        ensured = true;
      }
      await client.getBlockBlobClient(key).uploadData(data, { blobHTTPHeaders: { blobContentType: contentType } });
    },
  };
}

/** The configured store for the CVE index (see the header). */
export async function cveIndexObjectStore(supabaseAdmin: SupabaseClient, env: Record<string, string | undefined> = process.env): Promise<ObjectStore> {
  if (env.CVE_INDEX_STORE === "azure") {
    const conn = env.AZURE_STORAGE_CONNECTION_STRING;
    if (!conn) throw new Error("CVE_INDEX_STORE=azure but AZURE_STORAGE_CONNECTION_STRING is not set");
    return azureObjectStore(conn);
  }
  return supabaseObjectStore(supabaseAdmin);
}

/** For tests and local runs. */
export function memoryObjectStore(seed: Record<string, Buffer> = {}): ObjectStore & { keys(): string[]; puts: number } {
  const data = new Map(Object.entries(seed));
  const store = {
    puts: 0,
    async get(key: string) {
      return data.get(key) ?? null;
    },
    async put(key: string, value: Buffer) {
      store.puts++;
      data.set(key, value);
    },
    keys: () => [...data.keys()].sort(),
  };
  return store;
}
