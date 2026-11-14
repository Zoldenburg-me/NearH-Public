// What the scripts read from the mandate contract on NEAR: the agent's EOA, its sweep target
// and its float caps. Reuses the O1 plumbing (../near) for config and views.
// The NEAR RPC view is unauthenticated, so it never picks where money goes: the EOA is derived
// locally from the pinned MPC root and the token is the owner's pinned address. A view that
// disagrees is refused. Only float_cap is taken from the view, as advisory (see agentFloat).

import { assertAgentEvmAddress } from "../../near/src/derive.ts";
import { assertAgentId, pinnedTokens, view, type Config } from "../../near/src/near.ts";
import type { Mandate, SweepConfig } from "../../near/src/borsh.ts";
import { assertAddress } from "./base.ts";
import type { TokenName } from "./float.ts";
import { loadPasskey } from "./passkey.ts";

export type AgentRecord = {
  agent: string;
  public_key: string | null;
  sweep_config: SweepConfig;
  evm_address: string | null;
  revoked: boolean;
};

/** The agent record, refusing one whose EOA is not derive(contract, agent) or whose sweep target is not this owner's passkey Safe. */
export async function loadAgent(cfg: Config, agentArg: string | undefined) {
  const agent = assertAgentId(agentArg);
  const record = await view<AgentRecord | null>(cfg, cfg.contractId, "get_agent", { agent });
  if (!record) throw new Error(`no agent ${agent} on ${cfg.contractId}`);
  assertAddress("agent evm_address", record.evm_address ?? undefined);
  const eoa = assertAgentEvmAddress(cfg, agent, record.evm_address);
  const safe = loadPasskey().safe_address.toLowerCase();
  if (record.sweep_config.safe_address.toLowerCase() !== safe) {
    throw new Error(`agent ${agent} sweeps to ${record.sweep_config.safe_address}, not this owner's Safe ${safe}`);
  }
  return { agent, record, eoa, safe };
}

/**
 * For a top-up: the owner's pinned token address (the mandate must name the same one) and
 * `float_cap` from the agent's mandate. No mandate, no top-up. The cap comes from the RPC view
 * and is advisory: a lying RPC can raise it, so the owner also checks the amount on the passkey
 * summary. The recipient and token never come from the view.
 */
export async function agentFloat(cfg: Config, agentArg: string | undefined, token: TokenName) {
  const a = await loadAgent(cfg, agentArg);
  if (a.record.revoked) throw new Error(`agent ${a.agent} is revoked; sweep its float instead`);
  const mandate = await view<Mandate | null>(cfg, cfg.contractId, "get_mandate", { agent: a.agent });
  if (!mandate) throw new Error(`agent ${a.agent} has no mandate, so no float_cap; refusing the top-up`);
  const reported = assertAddress(`mandate ${token}_address`, token === "usdc" ? mandate.usdc_address : mandate.eure_address);
  const asset = pinnedTokens()[token];
  if (reported.toLowerCase() !== asset) {
    throw new Error(`mandate ${token}_address ${reported} is not the pinned ${token.toUpperCase()} ${asset}; refusing the top-up`);
  }
  return { ...a, asset, cap: BigInt(mandate.float_cap[token]) };
}
