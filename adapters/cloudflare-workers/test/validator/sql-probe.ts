import { DurableObject } from "cloudflare:workers";
import { DurableSqlHost } from "../../src/validator/sql-host";
import { DurableBlobHost } from "../../src/validator/blob-host";

/** Test-only binding. Never exported by either production Worker entrypoint. */
export class SqlProbe extends DurableObject {
  readonly host: DurableSqlHost;
  readonly blobs: DurableBlobHost;

  constructor(ctx: DurableObjectState, env: Cloudflare.Env) {
    super(ctx, env);
    this.host = new DurableSqlHost(ctx.storage);
    this.blobs = new DurableBlobHost(ctx.storage);
    this.host.exec("CREATE TABLE IF NOT EXISTS test_records (id BLOB PRIMARY KEY, value BLOB)", [], 0);
  }
}

export default {
  fetch(): Response { return new Response(null, { status: 404 }); },
};
