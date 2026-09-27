/** Synchronous SQL bridge owned by a single trusted validator DO.
 * No method is an RPC endpoint: only the embedded Rust store receives it.
 */
export class DurableSqlHost {
  constructor(private readonly storage: DurableObjectStorage) {}

  nowMillis(): number {
    return Date.now();
  }

  /** Rust callbacks must return synchronously; throwing rolls back every row. */
  transaction(callback: () => unknown): unknown {
    return this.storage.transactionSync(() => {
      const result: unknown = callback();
      if (result instanceof Promise) {
        throw new Error("asynchronous SQL callback is forbidden");
      }
      return result;
    });
  }

  /** All query text comes from the embedded store, never an HTTP request.
   * SQL u64s are BLOBs, not JavaScript numbers. The row ceiling additionally
   * bounds a buggy/corrupt query without draining an unbounded cursor.
   */
  exec(sql: string, parameters: unknown[], rowLimit: number): {
    rows: SqlStorageValue[][];
    rowsWritten: number;
    rowsAffected: number;
  } {
    if (new TextEncoder().encode(sql).byteLength > 100_000
      || parameters.length > 100
      || !Number.isSafeInteger(rowLimit) || rowLimit < 0 || rowLimit > 1025) {
      throw new Error("SQL operation exceeds the validator host profile");
    }
    const bindings: SqlStorageValue[] = parameters.map((value: unknown) => {
      if (value === null || typeof value === "string") return value;
      if (typeof value === "number" && Number.isSafeInteger(value)) return value;
      if (value instanceof ArrayBuffer) return value;
      if (value instanceof Uint8Array) {
        const bytes: Uint8Array<ArrayBuffer> = new Uint8Array(value.byteLength);
        bytes.set(value);
        return bytes.buffer;
      }
      throw new Error("unsupported SQL parameter");
    });
    // Keep below the provider's 2 MB physical-row ceiling. This is a local
    // host-profile limit, not a new protocol envelope size or truncation rule.
    const representedBytes: number = bindings.reduce((total: number, value) =>
      total + (typeof value === "string" ? new TextEncoder().encode(value).byteLength
        : value instanceof ArrayBuffer ? value.byteLength : 8), 0);
    if (representedBytes > 1_900_000) {
      throw new Error("SQL row exceeds the validator host profile");
    }
    const cursor: SqlStorageCursor<Record<string, SqlStorageValue>> =
      this.storage.sql.exec(sql, ...bindings);
    const rows: SqlStorageValue[][] = [];
    let resultBytes: number = 0;
    for (const row of cursor.raw<SqlStorageValue[]>()) {
      if (rows.length === rowLimit) throw new Error("SQL result row bound exceeded");
      for (const value of row) {
        if (typeof value === "number" && !Number.isSafeInteger(value)) {
          throw new Error("SQL integer is not exactly representable");
        }
        resultBytes += typeof value === "string" ? new TextEncoder().encode(value).byteLength
          : value instanceof ArrayBuffer ? value.byteLength : 8;
        if (resultBytes > 1_900_000) throw new Error("SQL result byte bound exceeded");
      }
      rows.push(row);
    }
    const rowsWritten: number = cursor.rowsWritten;
    if (!Number.isSafeInteger(rowsWritten) || rowsWritten < 0) {
      throw new Error("invalid SQL change count");
    }
    // Billing rowsWritten may include index work. Match the native backend:
    // row-returning statements report zero, not a previous write's changes().
    // For ordinary DML, engine CAS decisions use SQLite's affected-row count.
    const rowsAffected: number = cursor.columnNames.length > 0 ? 0
      : this.storage.sql.exec<{ count: number }>("SELECT changes() AS count").one().count;
    if (!Number.isSafeInteger(rowsAffected) || rowsAffected < 0) {
      throw new Error("invalid SQL affected-row count");
    }
    return { rows, rowsWritten, rowsAffected };
  }
}
