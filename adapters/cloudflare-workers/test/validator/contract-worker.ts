import { ValidatorObject } from "../../src/validator/index";
import fixture from "../../src/validator/generated/contract-fixture.json";

// Public DEVELOPMENT seeds only. This module is never imported by production
// entrypoints. Each binding owns a distinct SQL store and signing identity.
export const TEST_ACTOR = "closed-contract-fixture";
export const TEST_BEARER = "public-development-transport-token-0123456789";

function trustedEnv(namespace: ValidatorEnv["VALIDATOR_STATE"], index: number): ValidatorEnv {
  const selected = fixture.trusted_adapter_config_hex[index];
  if (selected === undefined) throw new Error("missing fixture validator");
  return {
    VALIDATOR_STATE: namespace,
    VALIDATOR_ACTOR_NAME: TEST_ACTOR,
    VALIDATOR_BEARER_TOKEN: TEST_BEARER,
    VALIDATOR_GENESIS: fixture.genesis_manifest_hex,
    VALIDATOR_CONFIG: selected,
  };
}

export class ValidatorZero extends ValidatorObject {
  constructor(ctx: DurableObjectState, env: Cloudflare.Env) {
    super(ctx, trustedEnv(env.VALIDATOR_ZERO, 0));
  }
}
export class ValidatorOne extends ValidatorObject {
  constructor(ctx: DurableObjectState, env: Cloudflare.Env) {
    super(ctx, trustedEnv(env.VALIDATOR_ONE, 1));
  }
}
export class ValidatorTwo extends ValidatorObject {
  constructor(ctx: DurableObjectState, env: Cloudflare.Env) {
    super(ctx, trustedEnv(env.VALIDATOR_TWO, 2));
  }
}
export class ValidatorThree extends ValidatorObject {
  constructor(ctx: DurableObjectState, env: Cloudflare.Env) {
    super(ctx, trustedEnv(env.VALIDATOR_THREE, 3));
  }
}

export default {
  fetch(): Response { return new Response(null, { status: 404 }); },
};
