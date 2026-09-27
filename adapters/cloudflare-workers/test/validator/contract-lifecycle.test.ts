/* eslint-disable @typescript-eslint/unbound-method -- Fault hooks deliberately save/restore prototype methods and invoke them with explicit .call(this). */
import { env } from "cloudflare:workers";
import { evictDurableObject, reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";
import validatorWorker from "../../src/validator/index";
import { DurableSqlHost } from "../../src/validator/sql-host";
import { DurableBlobHost } from "../../src/validator/blob-host";
import { ValidatorHost } from "../../src/validator/generated/sunrise_edge_cloudflare_validator";
import fixture from "../../src/validator/generated/contract-fixture.json";
import { TEST_ACTOR, TEST_BEARER } from "./contract-worker";

function hex(bytes: ArrayBuffer | Uint8Array): string {
  return Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes),
    (byte: number) => byte.toString(16).padStart(2, "0")).join("");
}

function unhex(value: string): Uint8Array<ArrayBuffer> {
  if (!/^(?:[0-9a-f]{2})*$/.test(value)) throw new Error("invalid oracle hex");
  const bytes: Uint8Array<ArrayBuffer> = new Uint8Array(value.length / 2);
  for (let index: number = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function query(path: string): Request {
  return new Request(`https://validator.example${path}`, {
    headers: { authorization: `Bearer ${TEST_BEARER}` },
  });
}

function mutation(path: string, bodyHex: string): Request {
  const bytes: Uint8Array<ArrayBuffer> = unhex(bodyHex);
  return new Request(`https://validator.example${path}`, {
    method: "POST", body: bytes, headers: {
      authorization: `Bearer ${TEST_BEARER}`,
      "content-type": "application/vnd.sunrise-edge.node-event",
      "content-length": bytes.byteLength.toString(),
    },
  });
}

// Drain responses before eviction: an unread response body keeps the actor
// referenced. A status-only assertion must not accidentally prevent restart.
async function statusOf(response: Response): Promise<number> {
  await response.arrayBuffer();
  return response.status;
}

// Include every shared SQL table (including local prepared votes, tombstones,
// typed receipts and outbox rows); blobs can be included for exact replay.
async function snapshot(stub: DurableObjectStub, includeBlobs: boolean = true): Promise<string> {
  return runInDurableObject(stub, (_instance, state): string => {
    const tables = state.storage.sql.exec<{ name: string }>(
      "SELECT name FROM sqlite_schema WHERE type = 'table' AND (name LIKE 'durable_%' OR name = 'validator_blobs') ORDER BY name",
    ).toArray();
    const result: Array<[string, string[]]> = [];
    for (const { name } of tables) {
      if (!/^(?:durable_[a-z_]+|validator_blobs)$/.test(name)) throw new Error("invalid test table");
      if (!includeBlobs && name === "validator_blobs") continue;
      const rows = state.storage.sql.exec(`SELECT * FROM ${name}`).raw<SqlStorageValue[]>();
      const normalized: string[] = Array.from(rows, (row) => JSON.stringify(row.map((value) =>
        value instanceof ArrayBuffer ? { blob: hex(value) } : value))).sort();
      result.push([name, normalized]);
    }
    return JSON.stringify(result);
  });
}

describe("embedded paid Wasmi validator in real SQLite Durable Objects", () => {
  // The pinned actor name is deliberately identical between cases. Reset only
  // these local Miniflare test bindings; production placement is unchanged.
  afterEach(async () => { await reset(); });
  it("matches native canonical votes, fees/results and queries on four independent stores, then replays across eviction", async () => {
    const stubs: DurableObjectStub[] = [env.VALIDATOR_ZERO, env.VALIDATOR_ONE,
      env.VALIDATOR_TWO, env.VALIDATOR_THREE].map((namespace) => namespace.getByName(TEST_ACTOR));
    expect(fixture.steps.map((step) => step.label)).toContain("publish");
    expect(fixture.steps.map((step) => step.label)).toContain("instantiate-create-asset");
    expect(fixture.steps.map((step) => step.label)).toContain("trap");
    for (const stub of stubs) {
      for (const [path, expected] of [["/v1/context", fixture.context_query_hex],
        ["/v1/contracts/paid-fee-policy", fixture.paid_fee_policy_hex]]) {
        if (path === undefined || expected === undefined) throw new Error("missing native query");
        const response: Response = await stub.fetch(query(path));
        expect(response.status).toBe(200);
        expect(hex(await response.arrayBuffer())).toBe(expected);
      }
    }
    for (const step of fixture.steps) {
      for (let index: number = 0; index < 3; index += 1) {
        const stub = stubs[index];
        if (stub === undefined) throw new Error("missing signer");
        const response: Response = await stub.fetch(mutation("/v1/fastvote/prepare", step.signed_paid_intent_hex));
        expect(response.status, `${step.label}: prepare ${index}`).toBe(200);
        expect(hex(await response.arrayBuffer()), `${step.label}: native vote ${index}`).toBe(step.votes_hex[index]);
      }
      // Validator 3 never prepares: it reconstructs each lifecycle prerequisite
      // from the actual intent/certificate using the real recovery pipeline.
      for (const stub of stubs) {
        const response: Response = await stub.fetch(mutation("/v1/fastvote/certificates", step.apply_request_hex));
        expect(response.status, `${step.label}: apply`).toBe(200);
        expect(hex(await response.arrayBuffer()), `${step.label}: native result/gas/fee bytes`).toBe(step.expected_http_node_result_hex);
        const receipt: Response = await stub.fetch(query(`/v1/receipts/${step.request_id_hex}`));
        expect(receipt.status).toBe(200);
        expect(hex(await receipt.arrayBuffer())).toBe(step.receipt_query_hex);
        const nonce: Response = await stub.fetch(query(`/v1/senders/${step.sender_hex}/next-nonce`));
        expect(nonce.status).toBe(200);
        expect(hex(await nonce.arrayBuffer())).toBe(step.next_nonce_query_hex);
        for (const object of step.queried_objects) {
          const response: Response = await stub.fetch(query(`/v1/objects/${object.id_hex}`));
          expect(response.status).toBe(200);
          expect(hex(await response.arrayBuffer()), `${step.label}: object ${object.id_hex}`).toBe(object.query_hex);
        }
        const before: string = await snapshot(stub);
        const replay: Response = await stub.fetch(mutation("/v1/fastvote/certificates", step.apply_request_hex));
        expect(replay.status).toBe(200);
        expect(hex(await replay.arrayBuffer())).toBe(step.expected_http_node_result_hex);
        expect(await snapshot(stub), `${step.label}: replay changed SQL/blob state`).toBe(before);
      }
    }
    for (const stub of stubs) {
      for (const [path, expected] of [[fixture.publication_query_path, fixture.publication_query_hex],
        [fixture.instance_query_path, fixture.instance_query_hex]]) {
        if (path === undefined || expected === undefined) throw new Error("missing native query");
        const response: Response = await stub.fetch(query(path));
        expect(response.status).toBe(200);
        expect(hex(await response.arrayBuffer())).toBe(expected);
      }
    }
    // Actual eviction, not a second facade over a still-live host. Replay old
    // receipts after later mutations, including the charged failure.
    for (const stub of stubs) {
      const before: string = await snapshot(stub);
      await evictDurableObject(stub);
      for (const step of fixture.steps) {
        const replay: Response = await stub.fetch(mutation("/v1/fastvote/certificates", step.apply_request_hex));
        expect(replay.status, `${step.label}: reopened replay`).toBe(200);
        expect(hex(await replay.arrayBuffer())).toBe(step.expected_http_node_result_hex);
      }
      expect(await snapshot(stub)).toBe(before);
    }
    for (const [index, stub] of stubs.entries()) {
      const before: string = await snapshot(stub);
      for (const negative of fixture.negatives) {
        expect(negative.rejected_by_validator[index]).toBe(true);
        const applyHex = negative.apply_request_hex;
        const response: Response = await stub.fetch(applyHex === null
          ? mutation("/v1/fastvote/prepare", negative.signed_paid_intent_hex)
          : mutation("/v1/fastvote/certificates", applyHex));
        expect(await statusOf(response), negative.label).toBe(negative.expected_status_by_validator[index]);
        expect(await snapshot(stub), `${negative.label}: changed durable state`).toBe(before);
      }
    }
  });

  it("authorizes and bounds the public Worker ingress before any actor lookup", async () => {
    let actorTouched: boolean = false;
    const namespace: ValidatorEnv["VALIDATOR_STATE"] = new Proxy(
      {} as ValidatorEnv["VALIDATOR_STATE"], {
        get(): never { actorTouched = true; throw new Error("actor must not be accessed"); },
      },
    );
    const trusted: ValidatorEnv = {
      VALIDATOR_STATE: namespace, VALIDATOR_ACTOR_NAME: TEST_ACTOR,
      VALIDATOR_BEARER_TOKEN: TEST_BEARER, VALIDATOR_CONFIG: "", VALIDATOR_GENESIS: "",
    };
    expect(await statusOf(await validatorWorker.fetch(new Request("https://validator.example/v1/context"), trusted))).toBe(401);
    expect(await statusOf(await validatorWorker.fetch(new Request("https://validator.example/health/live"), trusted))).toBe(204);
    const invalid = mutation("/v1/events", "00");
    expect(await statusOf(await validatorWorker.fetch(invalid, trusted))).toBe(404);
    expect(actorTouched).toBe(false);
  });

  it("rolls back a real prepare after partial shared-engine SQL writes", async () => {
    const stub = env.VALIDATOR_ZERO.getByName(TEST_ACTOR);
    const first = fixture.steps[0];
    if (first === undefined) throw new Error("missing native request");
    expect(await statusOf(await stub.fetch(query("/v1/context")))).toBe(200);
    const before: string = await snapshot(stub, false);
    await runInDurableObject(stub, async (instance) => {
      const original = DurableSqlHost.prototype.exec;
      let writes: number = 0;
      DurableSqlHost.prototype.exec = function(sql, parameters, rowLimit) {
        const result = original.call(this, sql, parameters, rowLimit);
        if (/^\s*(?:INSERT INTO|UPDATE) durable_state\b/.test(sql) && ++writes === 2) {
          throw new Error("synthetic-after-second-state-write");
        }
        return result;
      };
      try {
        const response: Response = await instance.fetch(mutation("/v1/fastvote/prepare", first.signed_paid_intent_hex));
        expect(await statusOf(response)).toBe(503);
        expect(writes).toBe(2);
      } finally {
        DurableSqlHost.prototype.exec = original;
      }
    });
    // Immutable, unreferenced content may have been inserted before commit;
    // no visible state/head/receipt/outbox mutation may survive the failure.
    expect(await snapshot(stub, false)).toBe(before);
    const retry: Response = await stub.fetch(mutation("/v1/fastvote/prepare", first.signed_paid_intent_hex));
    expect(retry.status).toBe(200);
    expect(hex(await retry.arrayBuffer())).toBe(first.votes_hex[0]);
  });

  it("rejects an invalid transaction signature before reading the host clock or storage", async () => {
    const stub = env.VALIDATOR_ZERO.getByName(TEST_ACTOR);
    const first = fixture.steps[0];
    if (first === undefined) throw new Error("missing native request");
    expect(await statusOf(await stub.fetch(query("/v1/context")))).toBe(200);
    const before: string = await snapshot(stub);
    const bytes: Uint8Array<ArrayBuffer> = unhex(first.signed_paid_intent_hex);
    bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 1;
    await runInDurableObject(stub, async (instance) => {
      const clock = DurableSqlHost.prototype.nowMillis;
      const exec = DurableSqlHost.prototype.exec;
      let calls: number = 0;
      DurableSqlHost.prototype.nowMillis = function(): never { calls += 1; throw new Error("clock-before-auth"); };
      DurableSqlHost.prototype.exec = function(): never { calls += 1; throw new Error("storage-before-auth"); };
      try {
        const response: Response = await instance.fetch(mutation("/v1/fastvote/prepare", hex(bytes)));
        expect(await statusOf(response)).toBe(400);
        expect(calls).toBe(0);
      } finally {
        DurableSqlHost.prototype.nowMillis = clock;
        DurableSqlHost.prototype.exec = exec;
      }
    });
    expect(await snapshot(stub)).toBe(before);
  });

  it("does not let a caller choose another actor in the trusted validator namespace", async () => {
    const wrongActor = env.VALIDATOR_ZERO.getByName("attacker-selected-actor");
    await expect(wrongActor.fetch(query("/v1/context"))).rejects.toThrow("placement");
  });

  it("withholds a committed result on confirmation failure, then reconciles without charging again", async () => {
    const stub = env.VALIDATOR_ZERO.getByName(TEST_ACTOR);
    const first = fixture.steps[0];
    if (first === undefined) throw new Error("missing native request");
    expect(await statusOf(await stub.fetch(query("/v1/context")))).toBe(200);
    const before: string = await snapshot(stub);
    await runInDurableObject(stub, async (instance, state) => {
      const original = state.storage.sync;
      state.storage.sync = function(): Promise<never> {
        // Deliberately resembles a definite-rejection adapter error. The
        // post-dispatch boundary must still report an ambiguous 503.
        return Promise.reject(Object.assign(new Error("synthetic-confirmation-failure"), { httpStatus: 400 }));
      };
      try {
        const response: Response = await instance.fetch(mutation("/v1/fastvote/certificates", first.apply_request_hex));
        expect(response.status).toBe(503);
        expect(await response.text()).toBe("validator-unavailable-or-outcome-indeterminate");
      } finally {
        state.storage.sync = original;
      }
    });
    const committed: string = await snapshot(stub);
    expect(committed).not.toBe(before);
    const receipt: Response = await stub.fetch(query(`/v1/receipts/${first.request_id_hex}`));
    expect(hex(await receipt.arrayBuffer())).toBe(first.receipt_query_hex);
    const replay: Response = await stub.fetch(mutation("/v1/fastvote/certificates", first.apply_request_hex));
    expect(replay.status).toBe(200);
    expect(hex(await replay.arrayBuffer())).toBe(first.expected_http_node_result_hex);
    expect(await snapshot(stub)).toBe(committed);
  });

  it("rejects malformed signed frames without changing durable state", async () => {
    const stub = env.VALIDATOR_ZERO.getByName(TEST_ACTOR);
    expect(await statusOf(await stub.fetch(query("/v1/context")))).toBe(200);
    const before: string = await snapshot(stub);
    expect(await statusOf(await stub.fetch(mutation("/v1/fastvote/prepare", "00")))).toBe(400);
    expect(await statusOf(await stub.fetch(mutation("/v1/fastvote/certificates", "00")))).toBe(400);
    expect(await snapshot(stub)).toBe(before);
  });

  it("does not recreate deleted namespace metadata during eviction/reopen", async () => {
    const stub = env.VALIDATOR_ZERO.getByName(TEST_ACTOR);
    expect(await statusOf(await stub.fetch(query("/v1/context")))).toBe(200);
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("DELETE FROM durable_metadata");
    });
    await evictDurableObject(stub);
    await expect(stub.fetch(query("/v1/context"))).rejects.toThrow();
  });

  it("checks the writer generation on reads as well as mutations", async () => {
    const stub = env.VALIDATOR_ZERO.getByName(TEST_ACTOR);
    expect(await statusOf(await stub.fetch(query("/v1/context")))).toBe(200);
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("UPDATE durable_metadata SET writer_fence = ?", unhex("0000000000000002").buffer);
    });
    const before: string = await snapshot(stub);
    expect(await statusOf(await stub.fetch(query("/v1/context")))).toBe(503);
    expect(await snapshot(stub)).toBe(before);
    await evictDurableObject(stub);
    await expect(stub.fetch(query("/v1/context"))).rejects.toThrow();
  });

  it("rolls back when a fresh host clock expires the budget after partial writes", async () => {
    const stub = env.VALIDATOR_ZERO.getByName(TEST_ACTOR);
    const first = fixture.steps[0];
    if (first === undefined) throw new Error("missing native request");
    expect(await statusOf(await stub.fetch(query("/v1/context")))).toBe(200);
    const before: string = await snapshot(stub, false);
    await runInDurableObject(stub, async (instance) => {
      const clock = DurableSqlHost.prototype.nowMillis;
      const exec = DurableSqlHost.prototype.exec;
      let writes: number = 0;
      let expiredReads: number = 0;
      DurableSqlHost.prototype.exec = function(sql, parameters, rowLimit) {
        const result = exec.call(this, sql, parameters, rowLimit);
        if (/^\s*(?:INSERT INTO|UPDATE) durable_state\b/.test(sql)) writes += 1;
        return result;
      };
      DurableSqlHost.prototype.nowMillis = function(): number {
        if (writes >= 2) { expiredReads += 1; return clock.call(this) + 60_000; }
        return clock.call(this);
      };
      try {
        expect(await statusOf(await instance.fetch(mutation("/v1/fastvote/prepare", first.signed_paid_intent_hex)))).toBe(503);
        expect(writes).toBeGreaterThanOrEqual(2);
        expect(expiredReads).toBeGreaterThan(0);
      } finally {
        DurableSqlHost.prototype.exec = exec;
        DurableSqlHost.prototype.nowMillis = clock;
      }
    });
    expect(await snapshot(stub, false)).toBe(before);
    const retry = await stub.fetch(mutation("/v1/fastvote/prepare", first.signed_paid_intent_hex));
    expect(retry.status).toBe(200);
    expect(hex(await retry.arrayBuffer())).toBe(first.votes_hex[0]);
  });

  it("rejects another configured domain without repairing or changing the existing namespace", async () => {
    const stub = env.VALIDATOR_ZERO.getByName(TEST_ACTOR);
    expect(await statusOf(await stub.fetch(query("/v1/context")))).toBe(200);
    const before: string = await snapshot(stub);
    await runInDurableObject(stub, (_instance, state) => {
      const encoded = fixture.trusted_adapter_config_hex[0];
      if (encoded === undefined) throw new Error("missing trusted config");
      const config = unhex(encoded);
      const chainLength: number = ((config[4] ?? 0) << 8) | (config[5] ?? 0);
      const domainOffset: number = 6 + chainLength + 4 + 8;
      config[domainOffset] = (config[domainOffset] ?? 0) ^ 1;
      expect(() => new ValidatorHost(config, new DurableSqlHost(state.storage),
        new DurableBlobHost(state.storage))).toThrow();
    });
    expect(await snapshot(stub)).toBe(before);
  });

  it("does not reinstall a tombstoned genesis marker during eviction/reopen", async () => {
    const stub = env.VALIDATOR_ZERO.getByName(TEST_ACTOR);
    expect(await statusOf(await stub.fetch(query("/v1/context")))).toBe(200);
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("UPDATE durable_state SET value = NULL WHERE instr(key, ?) > 0",
        new TextEncoder().encode("v1/genesis-marker/").buffer);
      expect(state.storage.sql.exec<{ count: number }>("SELECT changes() AS count").one().count).toBe(1);
    });
    await evictDurableObject(stub);
    await expect(stub.fetch(query("/v1/context"))).rejects.toThrow();
  });

  it.each(["immutable-version", "tombstone"])("fails closed on %s corruption without repairing state", async (kind) => {
    const stub = env.VALIDATOR_ZERO.getByName(TEST_ACTOR);
    const first = fixture.steps[0];
    const object = first?.queried_objects[0];
    if (object === undefined) throw new Error("missing genesis object");
    expect(await statusOf(await stub.fetch(query(`/v1/objects/${object.id_hex}`)))).toBe(200);
    await runInDurableObject(stub, (_instance, state) => {
      if (kind === "immutable-version") {
        state.storage.sql.exec("UPDATE durable_object_versions SET type_id = type_id + 1 WHERE object_id = ?",
          unhex(object.id_hex).buffer);
      } else {
        // A valid tombstone has no current-only columns. Retaining them must
        // fail, never expose the old object as current or silently normalize it.
        state.storage.sql.exec("UPDATE durable_object_heads SET status = 2 WHERE object_id = ?",
          unhex(object.id_hex).buffer);
      }
      expect(state.storage.sql.exec<{ count: number }>("SELECT changes() AS count").one().count).toBe(1);
    });
    const before: string = await snapshot(stub);
    expect(await statusOf(await stub.fetch(query(`/v1/objects/${object.id_hex}`)))).toBe(503);
    expect(await snapshot(stub)).toBe(before);
    await evictDurableObject(stub);
    // Reopen validates retained genesis objects too: refusing construction
    // is stronger than serving an unavailable object from a corrupt store.
    await expect(stub.fetch(query(`/v1/objects/${object.id_hex}`))).rejects.toThrow();
  });
});
