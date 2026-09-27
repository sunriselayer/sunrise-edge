/** Immutable content-addressed bytes in the same validator actor.
 * This host stores digests supplied by Rust; it selects no hash algorithm.
 */
export class DurableBlobHost {
  constructor(private readonly storage: DurableObjectStorage) {}

  private initialize(): void {
    this.storage.sql.exec("CREATE TABLE IF NOT EXISTS validator_blobs (digest TEXT PRIMARY KEY, bytes BLOB NOT NULL)");
  }

  private validateKey(digest: string): void {
    if (!/^(?:[0-9a-f]{2}){1,128}$/.test(digest)) {
      throw new Error("invalid content-addressed blob key");
    }
  }

  putIfAbsent(digest: string, bytes: Uint8Array): boolean {
    this.validateKey(digest);
    if (bytes.byteLength > 1_900_000) throw new Error("blob exceeds the validator host profile");
    return this.storage.transactionSync(() => {
      this.initialize();
      const rows = this.storage.sql.exec<{ bytes: ArrayBuffer }>(
        "SELECT bytes FROM validator_blobs WHERE digest = ?", digest,
      ).toArray();
      if (rows.length > 1) throw new Error("corrupt blob identity");
      const row = rows[0];
      if (row !== undefined) {
        if (!(row.bytes instanceof ArrayBuffer)) throw new Error("invalid blob storage type");
        const observed: Uint8Array = new Uint8Array(row.bytes);
        if (observed.byteLength !== bytes.byteLength
          || observed.some((value: number, index: number) => value !== bytes[index])) {
          throw new Error("content-addressed blob conflict");
        }
        return false;
      }
      const stored: Uint8Array<ArrayBuffer> = new Uint8Array(bytes.byteLength);
      stored.set(bytes);
      this.storage.sql.exec("INSERT INTO validator_blobs VALUES (?, ?)", digest, stored.buffer);
      return true;
    });
  }

  getBlob(digest: string): Uint8Array | undefined {
    this.validateKey(digest);
    this.initialize();
    const rows = this.storage.sql.exec<{ bytes: ArrayBuffer }>(
      "SELECT bytes FROM validator_blobs WHERE digest = ?", digest,
    ).toArray();
    if (rows.length > 1) throw new Error("corrupt blob identity");
    const row = rows[0];
    if (row === undefined) return undefined;
    if (!(row.bytes instanceof ArrayBuffer) || row.bytes.byteLength > 1_900_000) {
      throw new Error("invalid blob storage type or size");
    }
    return new Uint8Array(row.bytes);
  }
}
