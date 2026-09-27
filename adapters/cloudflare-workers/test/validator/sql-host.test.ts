import { env } from "cloudflare:workers";
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("DO SQL host seam", () => {
  it("keeps content-addressed blobs immutable across genuine eviction", async () => {
    const stub = env.SQL_PROBE.getByName("blob-immutability");
    const digest: string = "ab".repeat(34);
    await runInDurableObject(stub, (instance) => {
      expect(instance.blobs.putIfAbsent(digest, new Uint8Array([1, 2]))).toBe(true);
      expect(instance.blobs.putIfAbsent(digest, new Uint8Array([1, 2]))).toBe(false);
      expect(() => instance.blobs.putIfAbsent(digest, new Uint8Array([2, 1]))).toThrow("conflict");
      expect(() => instance.blobs.putIfAbsent("invalid", new Uint8Array([2]))).toThrow("key");
    });
    await evictDurableObject(stub);
    await runInDurableObject(stub, (instance) => {
      expect(instance.blobs.getBlob(digest)).toEqual(new Uint8Array([1, 2]));
      expect(instance.blobs.getBlob("cd".repeat(34))).toBeUndefined();
    });
  });

  it("preserves exact u64 BLOBs through genuine eviction/recreation", async () => {
    const stub = env.SQL_PROBE.getByName("exact-u64");
    const bytes: Uint8Array = new Uint8Array(8).fill(255);
    await runInDurableObject(stub, (instance) => {
      const outcome = instance.host.transaction(() => instance.host.exec(
        "INSERT INTO test_records VALUES (?, ?)", [bytes, bytes], 0,
      ));
      expect(outcome).toMatchObject({ rowsAffected: 1 });
    });
    await evictDurableObject(stub);
    await runInDurableObject(stub, (instance) => {
      const rows = instance.host.exec("SELECT id, value FROM test_records", [], 1).rows;
      expect(rows).toHaveLength(1);
      expect(rows[0]).toHaveLength(2);
      for (const value of rows[0] ?? []) {
        expect(value).toBeInstanceOf(ArrayBuffer);
        if (!(value instanceof ArrayBuffer)) throw new Error("not a blob");
        expect(new Uint8Array(value)).toEqual(bytes);
      }
    });
  });

  it("rolls back partial SQL work on an explicit callback error", async () => {
    const stub = env.SQL_PROBE.getByName("rollback");
    await runInDurableObject(stub, (instance) => {
      expect(() => instance.host.transaction(() => {
        instance.host.exec("INSERT INTO test_records VALUES (?, ?)", [new Uint8Array([1]), new Uint8Array([2])], 0);
        throw new Error("deliberate-abort");
      })).toThrow("deliberate-abort");
      expect(instance.host.exec("SELECT id FROM test_records", [], 1).rows).toEqual([]);
      expect(() => instance.host.transaction(() => Promise.resolve())).toThrow("asynchronous");
    });
  });

  it("matches native SELECT change counts and accepts the exact 1025-row bound", async () => {
    const stub = env.SQL_PROBE.getByName("native-row-semantics");
    await runInDurableObject(stub, (instance) => {
      const write = instance.host.exec("INSERT INTO test_records VALUES (?, ?)",
        [new Uint8Array([1]), new Uint8Array([2])], 0);
      expect(write.rowsAffected).toBe(1);
      expect(instance.host.exec("SELECT id FROM test_records", [], 1).rowsAffected).toBe(0);
      const scan: string = "WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?) SELECT n FROM seq";
      expect(instance.host.exec(scan, [1025], 1025).rows).toHaveLength(1025);
      expect(() => instance.host.exec(scan, [1026], 1025)).toThrow("row bound");
    });
  });

  it("bounds scans and refuses lossy SQL integers or oversized rows", async () => {
    const stub = env.SQL_PROBE.getByName("bounds");
    await runInDurableObject(stub, (instance) => {
      expect(() => instance.host.exec("SELECT 9007199254740993", [], 1)).toThrow("exactly representable");
      expect(() => instance.host.exec("SELECT ?", [1.5], 1)).toThrow("parameter");
      expect(() => instance.host.exec("SELECT 1 UNION ALL SELECT 2", [], 1)).toThrow("row bound");
      expect(() => instance.host.exec("SELECT zeroblob(1000000) UNION ALL SELECT zeroblob(1000000)", [], 2)).toThrow("byte bound");
      expect(() => instance.host.exec("INSERT INTO test_records VALUES (?, ?)", [new Uint8Array([3]), new Uint8Array(1_900_001)], 0)).toThrow("host profile");
      expect(instance.host.exec("SELECT id FROM test_records", [], 1).rows).toEqual([]);
    });
  });
});
