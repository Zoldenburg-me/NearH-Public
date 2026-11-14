//! The mandate contract: holds each agent's signing power through Chain Signatures and signs
//! only what fits the owner's mandate. C2 implements the owner methods, state and views; C3
//! the request pipeline (`request.rs`); the remaining stubs are C4, C6 and C7 (shapes).
//!
//! Callers:
//! - **Owner methods** take `assertion: Option<OwnerAssertion>` as their last argument:
//!   `Some` in passkey mode (any account may submit), `None` in wallet mode (the predecessor
//!   must be the owner account and attach exactly 1 yoctoNEAR, so they are `#[payable]`).
//! - **Agent methods** (`request_signature`, `sweep`, `revoke_self`) are called with the
//!   agent's function-call key, which lives on this contract's own account. The predecessor
//!   is therefore this contract, and the agent is found by `env::signer_account_pk()` in the
//!   key-to-agent map. Agent methods take no `agent` argument (`sweep` takes one, and an
//!   optional owner assertion, because the owner and the relayer call it too).
//! - `#[private]` alone does not keep agents out of callbacks, because agent calls also have
//!   this contract as predecessor; the agent key's `method_names` do.

use near_sdk::json_types::U128;
use near_sdk::store::{IterableMap, LookupMap, LookupSet};
use near_sdk::{
    env, near, AccountId, Allowance, BorshStorageKey, PanicOnDefault, Promise, PromiseOrValue,
    PublicKey,
};

pub mod errors;
pub mod events;
pub mod owner;
pub mod request;
pub mod shapes;
pub mod state;
pub mod types;

#[cfg(test)]
mod interface_tests;

use errors::{not_implemented, ContractError};
use events::MandateEvent;
use request::{now_secs, validate_request_id};
use shapes::{eip3009_nonce, payout, private_payout, x402};
use state::{
    is_id, normalize_address, normalize_commitment, normalize_payee, normalize_sweep_config,
    now_ms, validate_agent_id, validate_supplier_id, AGENT_KEY_ALLOWANCE, KEY_CALLBACK_GAS,
};
use types::{
    AgentId, AgentRecord, BudgetView, Caller, ConfigView, EvmAddress, EvmTxParams, Mandate,
    OwnerAssertion, OwnerMode, Payee, PayoutRequest, PendingIban, PrivatePayoutRequest,
    PrivateSepaConfig, Rail, RequestKey, RequestStatus, Reservation, ResolveOutcome, RevokeResult,
    RevokedBy, Shape, ShapeKind, SignedPayload, Supplier, SupplierId, SweepConfig, Token,
    UnknownReason, AGENT_METHOD_NAMES, DEFAULT_COOLING_OFF_SECS, MAX_COOLING_OFF_SECS,
    MIN_COOLING_OFF_SECS, MPC_CONTRACT, NETWORK,
};

#[near]
#[derive(BorshStorageKey)]
enum StorageKey {
    Agents,
    AgentKeys,
    Mandates,
    Payees,
    PeriodStarts,
    Requests,
    SignedPayouts,
    PendingSweeps,
    UndeletedKeys,
    BudgetUsed,
    AgentRequestCounts,
    UndeletedKeySet,
    RequestIndex,
    AgentRequestTotals,
    Suppliers,
    PaidInvoices,
    PrivateSuppliers,
}

/// Contract state. The layout is internal (C2 and C3 may reshape it); the interface is
/// the methods and the types in `types`.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: OwnerMode,
    /// The last owner nonce used; 0 before the first owner call.
    owner_nonce: u64,
    network: String,
    mpc_contract: AccountId,
    relayer: Option<AccountId>,
    /// Every agent ever added, revoked ones included (ids are never reused).
    agents: IterableMap<AgentId, AgentRecord>,
    /// Live agent keys only: written by `add_agent`, removed by revoke or a failed `AddKey`.
    agent_keys: LookupMap<PublicKey, AgentId>,
    mandates: LookupMap<AgentId, Mandate>,
    /// x402 payees only; SEPA payees are in `suppliers`.
    payees: LookupMap<AgentId, Vec<Payee>>,
    /// SEPA suppliers per agent, in the order added, with IBAN commitments only (PRIV1).
    /// Stored unsettled; read them through `suppliers_at`.
    suppliers: LookupMap<AgentId, Vec<Supplier>>,
    /// `invoice_key` of every (supplier, invoice id) a payout was requested for (AP1).
    paid_invoices: LookupSet<[u8; 32]>,
    /// Cooling-off of a new supplier IBAN, `MIN_COOLING_OFF_SECS..=MAX_COOLING_OFF_SECS`.
    cooling_off_secs: u64,
    /// Per (agent, rail): start (unix ms) and length (s) of the current budget window. Set at
    /// the agent's first `set_mandate`, rolled forward back to back at request time (D7).
    period_starts: LookupMap<(AgentId, Rail), (u64, u64)>,
    requests: IterableMap<RequestKey, Reservation>,
    /// `payout_dedupe_key` of every payout signed, per agent (D3).
    signed_payouts: LookupSet<[u8; 32]>,
    /// At most one pending sweep per (agent, token).
    pending_sweeps: LookupSet<(AgentId, Token)>,
    /// Keys of revoked agents whose `DeleteKey` has not succeeded yet; a later revoke of
    /// the same agent retries it.
    undeleted_keys: LookupMap<AgentId, PublicKey>,
    /// Per (agent, rail): the window start (unix ms) and the sum of the counting reservations
    /// made in that window. Booked at request time, reduced when one is released (D7, D8).
    budget_used: LookupMap<(AgentId, Rail), (u64, u128)>,
    /// Requests each agent's key has stored, final ones included (`MAX_AGENT_REQUESTS`).
    agent_request_counts: LookupMap<AgentId, u32>,
    /// The keys in `undeleted_keys`, so `add_agent` can refuse one that is still on the account.
    undeleted_key_set: LookupSet<PublicKey>,
    /// Per agent, its requests by any caller in order: (agent, n) → the n-th key.
    request_index: LookupMap<(AgentId, u32), RequestKey>,
    /// Requests per agent by any caller: the length of its `request_index`.
    agent_request_totals: LookupMap<AgentId, u32>,
    /// The pinned worker of the private SEPA path (PRIV2); `None`: that path is off.
    private_sepa: Option<PrivateSepaConfig>,
    /// (agent, supplier) pairs the owner opted in to the private SEPA path (PRIV2).
    private_suppliers: LookupSet<(AgentId, SupplierId)>,
}

/// True if the single key action this callback follows succeeded. Never panics.
fn key_action_succeeded() -> bool {
    env::promise_results_count() == 1 && env::promise_result_checked(0, 64).is_ok()
}

/// `validate_request_id`, plus the `link-` prefix is reserved for `link_agent`'s own ids
/// (`ERR_INVALID_REQUEST_ID`), so a caller-chosen id never takes a link key's slot.
fn validate_caller_request_id(request_id: &str) {
    validate_request_id(request_id);
    if request_id.starts_with("link-") {
        ContractError::InvalidRequestId.panic("request_id prefix link- is reserved");
    }
}

#[near]
impl Contract {
    /// Deploy-time init, callable only by this account (in the deploy tx). `owner` picks
    /// passkey or wallet mode once; `network` must be `testnet` (the string in owner
    /// challenges) and `mpc_contract` `v1.signer-prod.testnet` (`ERR_WRONG_NETWORK`). Rejects
    /// `OwnerMode::Wallet` naming this contract's own account, and a passkey that is not a
    /// 33-byte compressed key or has an empty `rp_id` or `origin` (`ERR_NOT_OWNER`).
    #[init]
    #[private]
    pub fn new(owner: OwnerMode, network: String, mpc_contract: AccountId) -> Self {
        match &owner {
            OwnerMode::Wallet { account } => {
                if *account == env::current_account_id() {
                    ContractError::NotOwner.panic("owner account cannot be this contract");
                }
            }
            OwnerMode::Passkey {
                public_key,
                rp_id,
                origin,
            } => {
                let key = &public_key.0;
                if key.len() != 33 || !matches!(key[0], 2 | 3) {
                    ContractError::NotOwner.panic("public_key must be 33-byte compressed SEC1");
                }
                if rp_id.is_empty() || origin.is_empty() {
                    ContractError::NotOwner.panic("rp_id and origin must be set");
                }
            }
        }
        if network != NETWORK {
            ContractError::WrongNetwork.panic(&format!("network must be {NETWORK}"));
        }
        if mpc_contract.as_str() != MPC_CONTRACT {
            ContractError::WrongNetwork.panic(&format!("mpc_contract must be {MPC_CONTRACT}"));
        }
        Self {
            owner,
            owner_nonce: 0,
            network,
            mpc_contract,
            relayer: None,
            agents: IterableMap::new(StorageKey::Agents),
            agent_keys: LookupMap::new(StorageKey::AgentKeys),
            mandates: LookupMap::new(StorageKey::Mandates),
            payees: LookupMap::new(StorageKey::Payees),
            suppliers: LookupMap::new(StorageKey::Suppliers),
            paid_invoices: LookupSet::new(StorageKey::PaidInvoices),
            cooling_off_secs: DEFAULT_COOLING_OFF_SECS,
            period_starts: LookupMap::new(StorageKey::PeriodStarts),
            requests: IterableMap::new(StorageKey::Requests),
            signed_payouts: LookupSet::new(StorageKey::SignedPayouts),
            pending_sweeps: LookupSet::new(StorageKey::PendingSweeps),
            undeleted_keys: LookupMap::new(StorageKey::UndeletedKeys),
            budget_used: LookupMap::new(StorageKey::BudgetUsed),
            agent_request_counts: LookupMap::new(StorageKey::AgentRequestCounts),
            undeleted_key_set: LookupSet::new(StorageKey::UndeletedKeySet),
            request_index: LookupMap::new(StorageKey::RequestIndex),
            agent_request_totals: LookupMap::new(StorageKey::AgentRequestTotals),
            private_sepa: None,
            private_suppliers: LookupSet::new(StorageKey::PrivateSuppliers),
        }
    }

    // ---- Owner methods ----

    /// Registers `agent`, adds `public_key` as a function-call key on this account with
    /// `AGENT_METHOD_NAMES` and `AGENT_KEY_ALLOWANCE`, and stores `sweep_config`. Rejects an
    /// existing agent id (including revoked ones) or key, live or still waiting for its
    /// `DeleteKey`. `evm_address` is the agent EOA the owner derived off chain from (this
    /// contract, `agent`) as the MPC does; it is checked for format only and stored
    /// lowercase. A wrong one cannot redirect funds: `on_signature` records only signatures
    /// that recover to it, so every request then ends `unknown`. The key-to-agent entry is
    /// written before `AddKey`, so a second `add_agent` with the same key fails at once; if
    /// `AddKey` fails, `on_agent_key_added` clears it again and returns false
    /// (spikes/deletekey).
    #[payable]
    pub fn add_agent(
        &mut self,
        agent: AgentId,
        public_key: PublicKey,
        sweep_config: SweepConfig,
        evm_address: EvmAddress,
        assertion: Option<OwnerAssertion>,
    ) -> Promise {
        self.assert_owner(
            "add_agent",
            &(&agent, &public_key, &sweep_config, &evm_address),
            assertion,
        );
        validate_agent_id(&agent);
        if self.agents.contains_key(&agent) {
            ContractError::AgentExists.panic(&agent);
        }
        if self.agent_keys.contains_key(&public_key) || self.undeleted_key_set.contains(&public_key)
        {
            ContractError::KeyExists.panic("public_key");
        }
        let sweep_config = normalize_sweep_config(sweep_config);
        let evm_address = normalize_address("evm_address", &evm_address);
        self.agent_keys.insert(public_key.clone(), agent.clone());
        self.agents.insert(
            agent.clone(),
            AgentRecord {
                agent: agent.clone(),
                public_key: Some(public_key.clone()),
                sweep_config: sweep_config.clone(),
                evm_address: Some(evm_address),
                linked: false,
                revoked: false,
            },
        );
        MandateEvent::AgentAdded {
            agent: agent.clone(),
            public_key: public_key.clone(),
            sweep_config,
        }
        .emit();

        let me = env::current_account_id();
        let allowance = Allowance::limited(AGENT_KEY_ALLOWANCE)
            .unwrap_or_else(|| env::panic_str("AGENT_KEY_ALLOWANCE is zero"));
        Promise::new(me.clone())
            .add_access_key_allowance(
                public_key.clone(),
                allowance,
                me.clone(),
                AGENT_METHOD_NAMES.join(","),
            )
            .then(
                Self::ext(me)
                    .with_static_gas(KEY_CALLBACK_GAS)
                    .on_agent_key_added(agent, public_key),
            )
    }

    /// Names the one relayer account allowed to request sweeps; `None` removes it. Rejects
    /// this contract's own account, which agent calls have as predecessor
    /// (`ERR_SWEEP_CALLER_NOT_ALLOWED`).
    #[payable]
    pub fn set_relayer(&mut self, account: Option<AccountId>, assertion: Option<OwnerAssertion>) {
        self.assert_owner("set_relayer", &(&account,), assertion);
        if account.as_ref() == Some(&env::current_account_id()) {
            ContractError::SweepCallerNotAllowed.panic("relayer cannot be this contract");
        }
        self.relayer = account.clone();
        MandateEvent::RelayerSet { account }.emit();
    }

    /// Sets or replaces the agent's mandate. Pending reservations are untouched and the
    /// budget window does not restart; a changed `period_secs` applies from the next window
    /// boundary (D7, D10). The mandate's addresses and chain id must match the sweep config.
    #[payable]
    pub fn set_mandate(
        &mut self,
        agent: AgentId,
        mandate: Mandate,
        assertion: Option<OwnerAssertion>,
    ) {
        self.assert_owner("set_mandate", &(&agent, &mandate), assertion);
        let record = self.live_agent_record(&agent);
        let mandate = self.normalize_mandate(&record, mandate);
        let now = now_ms();
        let old = self.mandates.get(&agent).cloned();
        for (rail, period) in [
            (Rail::X402, mandate.x402.period_secs),
            (Rail::Sepa, mandate.sepa.period_secs),
        ] {
            // Roll the stored window to now under the old period first, so the new period
            // applies only from the next boundary and never rewrites elapsed windows. A
            // window that starts exactly now already takes the new period.
            let window = match (&old, self.period_starts.get(&(agent.clone(), rail))) {
                (Some(old), Some(&(_, secs))) => {
                    let old_period = match rail {
                        Rail::X402 => old.x402.period_secs,
                        Rail::Sepa => old.sepa.period_secs,
                    };
                    self.budget_window(&agent, rail, old_period, now)
                        .unwrap_or((now, secs))
                }
                (_, Some(&w)) => w,
                (_, None) => (now, period),
            };
            let window = if window.0 == now {
                (now, period)
            } else {
                window
            };
            self.period_starts.insert((agent.clone(), rail), window);
        }
        self.mandates.insert(agent.clone(), mandate.clone());
        MandateEvent::MandateSet { agent, mandate }.emit();
    }

    /// Adds an x402 `payTo` or a SEPA supplier to the agent's allowlist (D5). Adding a payee
    /// that is already listed changes nothing. A new supplier's IBAN commitment is pending
    /// for the cooling-off (`supplier_iban_pending`) before payouts to it are signed; a
    /// supplier id already listed with other fields fails (`ERR_SUPPLIER_EXISTS`): a new IBAN
    /// goes through `change_supplier_iban`.
    #[payable]
    pub fn add_payee(&mut self, agent: AgentId, payee: Payee, assertion: Option<OwnerAssertion>) {
        self.assert_owner("add_payee", &(&agent, &payee), assertion);
        self.live_agent_record(&agent);
        let payee = normalize_payee(payee);
        let Payee::Sepa {
            supplier,
            name,
            iban_commitment,
            cap,
        } = payee.clone()
        else {
            let mut list = self.payees.get(&agent).cloned().unwrap_or_default();
            if list.contains(&payee) {
                return;
            }
            list.push(payee.clone());
            self.payees.insert(agent.clone(), list);
            MandateEvent::PayeeAdded { agent, payee }.emit();
            return;
        };
        let now = now_secs();
        let mut list = self.suppliers_at(&agent, now);
        if let Some(s) = list.iter().find(|s| s.supplier == supplier) {
            let latest = s
                .pending
                .as_ref()
                .map(|p| &p.iban_commitment)
                .or(s.iban_commitment.as_ref());
            if s.name == name && s.cap == cap && latest == Some(&iban_commitment) {
                return;
            }
            ContractError::SupplierExists.panic(&supplier);
        }
        let effective_at = now + self.cooling_off_secs;
        list.push(Supplier {
            supplier: supplier.clone(),
            name,
            cap,
            iban_commitment: None,
            pending: Some(PendingIban {
                iban_commitment: iban_commitment.clone(),
                effective_at,
            }),
        });
        self.suppliers.insert(agent.clone(), list);
        MandateEvent::PayeeAdded {
            agent: agent.clone(),
            payee,
        }
        .emit();
        MandateEvent::SupplierIbanPending {
            agent,
            supplier,
            iban_commitment,
            effective_at,
        }
        .emit();
    }

    /// Removes a payee; one that is not listed fails (`ERR_PAYEE_NOT_ALLOWED` or
    /// `ERR_IBAN_NOT_ALLOWED`) so the owner sees a typo. A supplier is matched by its id
    /// alone and removed with any pending IBAN; adding it again starts a new cooling-off.
    #[payable]
    pub fn remove_payee(
        &mut self,
        agent: AgentId,
        payee: Payee,
        assertion: Option<OwnerAssertion>,
    ) {
        self.assert_owner("remove_payee", &(&agent, &payee), assertion);
        self.live_agent_record(&agent);
        let payee = normalize_payee(payee);
        let removed = match &payee {
            Payee::X402 { .. } => {
                let mut list = self.payees.get(&agent).cloned().unwrap_or_default();
                let Some(i) = list.iter().position(|p| *p == payee) else {
                    ContractError::PayeeNotAllowed.panic("payee not listed")
                };
                list.remove(i);
                self.payees.insert(agent.clone(), list);
                payee
            }
            Payee::Sepa { supplier, .. } => {
                let mut list = self.suppliers_at(&agent, now_secs());
                let Some(i) = list.iter().position(|s| s.supplier == *supplier) else {
                    ContractError::IbanNotAllowed.panic("payee not listed")
                };
                let s = list.remove(i);
                self.suppliers.insert(agent.clone(), list);
                self.private_suppliers
                    .remove(&(agent.clone(), s.supplier.clone()));
                Payee::Sepa {
                    iban_commitment: s
                        .pending
                        .map(|p| p.iban_commitment)
                        .or(s.iban_commitment)
                        .unwrap_or_default(),
                    supplier: s.supplier,
                    name: s.name,
                    cap: s.cap,
                }
            }
        };
        MandateEvent::PayeeRemoved {
            agent,
            payee: removed,
        }
        .emit();
    }

    /// Changes a supplier's bank details (AP1): `iban_commitment` becomes payable only after
    /// the cooling-off, and until then payouts to the new IBAN are refused with
    /// `ERR_BANK_CHANGE_COOLING_OFF` while the current one stays payable. A second change
    /// replaces the pending one and restarts the window; changing to the commitment already
    /// pending (or, with none pending, already payable) changes nothing, and changing back to
    /// the payable one while another is pending cancels that (`supplier_iban_cancelled`).
    #[payable]
    pub fn change_supplier_iban(
        &mut self,
        agent: AgentId,
        supplier: SupplierId,
        iban_commitment: String,
        assertion: Option<OwnerAssertion>,
    ) {
        self.assert_owner(
            "change_supplier_iban",
            &(&agent, &supplier, &iban_commitment),
            assertion,
        );
        self.live_agent_record(&agent);
        validate_supplier_id(&supplier);
        let iban_commitment = normalize_commitment("iban_commitment", &iban_commitment);
        let now = now_secs();
        let mut list = self.suppliers_at(&agent, now);
        let s = list
            .iter_mut()
            .find(|s| s.supplier == supplier)
            .unwrap_or_else(|| ContractError::UnknownSupplier.panic(&supplier));
        let latest = s
            .pending
            .as_ref()
            .map(|p| &p.iban_commitment)
            .or(s.iban_commitment.as_ref());
        if latest == Some(&iban_commitment) {
            return;
        }
        // Back to the payable IBAN while another is pending: that is a cancel.
        if s.iban_commitment.as_ref() == Some(&iban_commitment) {
            let pending = s
                .pending
                .take()
                .map(|p| p.iban_commitment)
                .unwrap_or_default();
            self.suppliers.insert(agent.clone(), list);
            MandateEvent::SupplierIbanCancelled {
                agent,
                supplier,
                iban_commitment: pending,
            }
            .emit();
            return;
        }
        let effective_at = now + self.cooling_off_secs;
        s.pending = Some(PendingIban {
            iban_commitment: iban_commitment.clone(),
            effective_at,
        });
        self.suppliers.insert(agent.clone(), list);
        MandateEvent::SupplierIbanPending {
            agent,
            supplier,
            iban_commitment,
            effective_at,
        }
        .emit();
    }

    /// Withdraws a supplier's pending IBAN before it takes effect (`ERR_NO_BANK_CHANGE` if
    /// none is pending). The payable one, if any, stays.
    #[payable]
    pub fn cancel_supplier_iban_change(
        &mut self,
        agent: AgentId,
        supplier: SupplierId,
        assertion: Option<OwnerAssertion>,
    ) {
        self.assert_owner(
            "cancel_supplier_iban_change",
            &(&agent, &supplier),
            assertion,
        );
        self.live_agent_record(&agent);
        let mut list = self.suppliers_at(&agent, now_secs());
        let s = list
            .iter_mut()
            .find(|s| s.supplier == supplier)
            .unwrap_or_else(|| ContractError::UnknownSupplier.panic(&supplier));
        let pending = s
            .pending
            .take()
            .unwrap_or_else(|| ContractError::NoBankChange.panic(&supplier));
        self.suppliers.insert(agent.clone(), list);
        MandateEvent::SupplierIbanCancelled {
            agent,
            supplier,
            iban_commitment: pending.iban_commitment,
        }
        .emit();
    }

    /// Sets the cooling-off for later IBAN additions and changes, in seconds
    /// (`MIN_COOLING_OFF_SECS..=MAX_COOLING_OFF_SECS`, `ERR_INVALID_COOLING_OFF`). Pending
    /// changes keep their `effective_at`.
    #[payable]
    pub fn set_bank_change_cooling_off(&mut self, secs: u64, assertion: Option<OwnerAssertion>) {
        self.assert_owner("set_bank_change_cooling_off", &(&secs,), assertion);
        if !(MIN_COOLING_OFF_SECS..=MAX_COOLING_OFF_SECS).contains(&secs) {
            ContractError::InvalidCoolingOff.panic(&format!(
                "secs must be {MIN_COOLING_OFF_SECS}..={MAX_COOLING_OFF_SECS}"
            ));
        }
        self.cooling_off_secs = secs;
        MandateEvent::BankChangeCoolingOffSet { secs }.emit();
    }

    /// Pins the private SEPA worker (PRIV2), or with `None` turns that path off. Passkey mode
    /// only: a wallet-mode owner is refused (`ERR_PASSKEY_REQUIRED`), and so is a passkey
    /// call without an assertion (`ERR_ASSERTION_REQUIRED`). Fields are checked as in
    /// `private_payout::normalize_config`. A private payout whose worker result arrives after
    /// the pin changed is refused (`worker_unverified`).
    pub fn set_private_sepa_config(
        &mut self,
        config: Option<PrivateSepaConfig>,
        assertion: Option<OwnerAssertion>,
    ) {
        if !matches!(self.owner, OwnerMode::Passkey { .. }) {
            ContractError::PasskeyRequired.panic("the worker pin is set with the owner passkey");
        }
        self.assert_owner("set_private_sepa_config", &(&config,), assertion);
        let me = env::current_account_id();
        let config = config.map(|c| private_payout::normalize_config(c, &me));
        self.private_sepa = config.clone();
        MandateEvent::PrivateSepaConfigSet { config }.emit();
    }

    /// Opts a listed supplier in to (`true`) or out of the private SEPA path (PRIV2)
    /// (`ERR_UNKNOWN_SUPPLIER` if it is not listed). Shape 3 payouts to it are unaffected.
    /// Removing the supplier opts it out.
    #[payable]
    pub fn set_supplier_private(
        &mut self,
        agent: AgentId,
        supplier: SupplierId,
        private: bool,
        assertion: Option<OwnerAssertion>,
    ) {
        self.assert_owner(
            "set_supplier_private",
            &(&agent, &supplier, &private),
            assertion,
        );
        self.live_agent_record(&agent);
        validate_supplier_id(&supplier);
        if !self
            .suppliers_at(&agent, now_secs())
            .iter()
            .any(|s| s.supplier == supplier)
        {
            ContractError::UnknownSupplier.panic(&supplier);
        }
        let slot = (agent.clone(), supplier.clone());
        if private {
            self.private_suppliers.insert(slot);
        } else {
            self.private_suppliers.remove(&slot);
        }
        MandateEvent::SupplierPrivacySet {
            agent,
            supplier,
            private,
        }
        .emit();
    }

    /// Signs the Monerium link message for the agent EOA, once. Returns the MPC promise;
    /// the callback returns the `Reservation` with the signature.
    #[payable]
    pub fn link_agent(&mut self, agent: AgentId, assertion: Option<OwnerAssertion>) -> Promise {
        self.assert_owner("link_agent", &(&agent,), assertion);
        let mut record = self.live_agent_record(&agent);
        let built = shapes::link::build_link(record.linked).unwrap_or_else(|e| e.panic(&agent));
        record.linked = true;
        self.agents.insert(agent.clone(), record);
        let created_at_ms = now_ms();
        let mut suffix = created_at_ms;
        let key = loop {
            let k = RequestKey {
                agent: agent.clone(),
                caller: Caller::Owner,
                request_id: format!("link-{suffix}"),
            };
            if !self.requests.contains_key(&k) {
                break k;
            }
            suffix += 1;
        };
        let digest = format!("0x{}", hex::encode(built.digest));
        let reservation = Reservation {
            key: key.clone(),
            shape: ShapeKind::Link,
            rail: None,
            amount: 0.into(),
            period_start_ms: 0,
            created_at_ms,
            valid_before: 0,
            release_after: 0,
            digest: digest.clone(),
            payload: built.payload,
            status: RequestStatus::Pending,
            counts_against_budget: false,
            signature: None,
        };
        self.requests.insert(key.clone(), reservation);
        self.index_request(&key);
        MandateEvent::SignatureRequested {
            key: key.clone(),
            shape: ShapeKind::Link,
            rail: None,
            amount: 0.into(),
            digest,
            valid_before: 0,
        }
        .emit();
        let args = near_sdk::serde_json::json!({
            "request": {
                "payload_v2": { "Ecdsa": hex::encode(built.digest) },
                "path": agent,
                "domain_id": 0,
            }
        });
        let args = near_sdk::serde_json::to_vec(&args)
            .unwrap_or_else(|_| ContractError::NotImplemented.panic("json args for MPC sign"));
        Promise::new(self.mpc_contract.clone())
            .function_call(
                "sign".to_string(),
                args,
                request::MPC_SIGN_DEPOSIT,
                request::MPC_SIGN_GAS,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(request::SIGNATURE_CALLBACK_GAS)
                    .on_link_signature(key.clone()),
            )
    }

    /// Clears the agent's mandate, payees and key-to-agent entry, then deletes its
    /// function-call key (D1). The sweep config stays. A failed `DeleteKey` is not an error:
    /// the result comes from `on_agent_key_deleted`, which never fails. An agent that is
    /// already revoked returns `{revoked: true, key_deleted: false}` with no key action,
    /// unless an earlier `DeleteKey` of its key failed: then it retries that `DeleteKey`.
    #[payable]
    pub fn revoke(
        &mut self,
        agent: AgentId,
        assertion: Option<OwnerAssertion>,
    ) -> PromiseOrValue<RevokeResult> {
        self.assert_owner("revoke", &(&agent,), assertion);
        self.revoke_agent(agent, RevokedBy::Owner)
    }

    /// Resolves an `unknown` reservation (D4). `Released` is refused until
    /// `Reservation::release_after` (`ERR_VALIDITY_NOT_ENDED`).
    #[payable]
    pub fn resolve_reservation(
        &mut self,
        key: RequestKey,
        outcome: ResolveOutcome,
        assertion: Option<OwnerAssertion>,
    ) {
        self.assert_owner("resolve_reservation", &(&key, &outcome), assertion);
        self.resolve(key, outcome);
    }

    // ---- Agent methods (the agent key's method_names) ----

    /// Shapes 2 and 3 and the private payout (`x402`, `payout`, `private_payout`;
    /// `ERR_SHAPE_NOT_ALLOWED` otherwise). A private payout goes to the pinned worker first
    /// and resolves through `on_worker_result` (PRIV2). The agent
    /// is the one behind the signer key, never an argument. Dedupes `request_id` per (agent
    /// caller, agent), checks the shape against the agent's mandate as it stands now,
    /// reserves the amount on the shape's rail (D7, D8) and calls the MPC. The promise
    /// resolves to the `Reservation` returned by `on_signature`.
    pub fn request_signature(&mut self, request_id: String, shape: Shape) -> Promise {
        let agent = self.calling_agent();
        let record = self.live_agent_record(&agent);
        validate_caller_request_id(&request_id);
        let key = RequestKey {
            agent: agent.clone(),
            caller: Caller::Agent,
            request_id,
        };
        self.assert_new_request(&key);
        let mandate = self
            .mandates
            .get(&agent)
            .cloned()
            .unwrap_or_else(|| ContractError::NoMandate.panic(&agent));
        let now = now_secs();
        let kind = shape.kind();
        let built = match &shape {
            Shape::X402(req) => {
                let payees = self.payees.get(&agent).cloned().unwrap_or_default();
                let from = record
                    .evm_address
                    .as_ref()
                    .unwrap_or_else(|| ContractError::InvalidAddress.panic("agent evm_address"));
                let nonce = eip3009_nonce(&key, ShapeKind::X402);
                x402::build_x402(req, &mandate, &payees, from, nonce, now)
                    .unwrap_or_else(|e| e.panic(error_field(e)))
            }
            Shape::Payout(req) => self.check_payout(&key, req, &mandate, now),
            Shape::PrivatePayout(req) => {
                let config = self.private_sepa_for(&agent, &req.supplier);
                let built = self.check_private_payout(&key, req, &mandate, now);
                let period_start_ms =
                    self.reserve_budget(&agent, &mandate, Rail::Sepa, built.amount);
                return self.reserve_and_call_worker(key, built, period_start_ms, config);
            }
            Shape::Sweep { .. } | Shape::Link => {
                ContractError::ShapeNotAllowed.panic("request_signature takes x402 or payout")
            }
        };
        let rail = built
            .rail
            .unwrap_or_else(|| env::panic_str("payment shape without a rail"));
        let period_start_ms = self.reserve_budget(&agent, &mandate, rail, built.amount);
        self.reserve_and_sign(key, kind, built, period_start_ms)
    }

    /// Shape 1. Callable by the agent itself (agent key), the relayer, or the owner: with
    /// `assertion: Some` in passkey mode (any account may submit it), or from the owner
    /// account with `None` in wallet mode. Agents and the relayer pass `None`. Works after
    /// revoke; at most one pending sweep per (agent, token). `evm_tx` is required for EURe
    /// (raw-transfer sweep) and must be `None` for USDC (EIP-3009).
    #[payable]
    pub fn sweep(
        &mut self,
        agent: AgentId,
        token: Token,
        amount: U128,
        request_id: String,
        evm_tx: Option<EvmTxParams>,
        assertion: Option<OwnerAssertion>,
    ) -> Promise {
        let (record, caller) = match assertion {
            Some(a) => {
                self.assert_owner(
                    "sweep",
                    &(&agent, &token, &amount, &request_id, &evm_tx),
                    Some(a),
                );
                (self.agent_record(&agent), Caller::Owner)
            }
            None if matches!(&self.owner, OwnerMode::Wallet { account } if *account == env::predecessor_account_id()) =>
            {
                self.assert_owner(
                    "sweep",
                    &(&agent, &token, &amount, &request_id, &evm_tx),
                    None,
                );
                (self.agent_record(&agent), Caller::Owner)
            }
            None if Some(env::predecessor_account_id()) == self.relayer => (
                self.agent_record(&agent),
                Caller::Relayer {
                    account: env::predecessor_account_id(),
                },
            ),
            None => {
                // `calling_agent` repeats this check, but would answer ERR_NOT_AGENT_KEY;
                // sweep must refuse a third account with its own code (interfaces.md §1).
                if env::predecessor_account_id() != env::current_account_id() {
                    ContractError::SweepCallerNotAllowed.panic("sweep caller");
                }
                let signer = self.calling_agent();
                if signer != agent {
                    ContractError::SweepCallerNotAllowed.panic("sweep caller");
                }
                (self.live_agent_record(&agent), Caller::Agent)
            }
        };
        validate_caller_request_id(&request_id);
        let key = RequestKey {
            agent: agent.clone(),
            caller: caller.clone(),
            request_id,
        };
        self.assert_new_request(&key);
        if !self.pending_sweeps.insert((agent.clone(), token)) {
            ContractError::SweepPending
                .panic("pending sweep already exists for this agent and token");
        }
        let amount = amount.0;
        let nonce = eip3009_nonce(&key, ShapeKind::Sweep);
        let now = now_secs();
        let built = shapes::sweep::build_sweep(&record, token, amount, evm_tx.as_ref(), nonce, now)
            .unwrap_or_else(|e| e.panic("sweep"));
        self.reserve_and_sign(key, ShapeKind::Sweep, built, 0)
    }

    /// Revokes the calling agent only: clears its mandate and map entry, deletes its key.
    /// Returns like `revoke`.
    pub fn revoke_self(&mut self) -> PromiseOrValue<RevokeResult> {
        let agent = self.calling_agent();
        self.revoke_agent(agent, RevokedBy::Agent)
    }

    // ---- Anyone ----

    /// Marks a `pending` reservation `unknown` once `MPC_TIMEOUT_MS` has passed (D4).
    pub fn expire_pending(&mut self, key: RequestKey) {
        self.expire(key);
    }

    // ---- Callbacks ----

    /// After `AddKey`: keeps the key-to-agent entry on success. On failure it removes the
    /// entry and retires the agent id like a revoke (the id may already have been used as a
    /// derivation path), logs `agent_add_failed` and returns false. Never panics, so the tx
    /// status shows success either way; clients read the return value or `get_agent`.
    #[private]
    pub fn on_agent_key_added(&mut self, agent: AgentId, public_key: PublicKey) -> bool {
        if key_action_succeeded() {
            return true;
        }
        if self.agents.get(&agent).and_then(|r| r.public_key.as_ref()) == Some(&public_key) {
            self.clear_agent(&agent);
        }
        MandateEvent::AgentAddFailed { agent, public_key }.emit();
        false
    }

    /// After `DeleteKey` (`revoke`, `revoke_self`). Never panics; reports whether the key
    /// receipt succeeded. The state was already cleared before the key action.
    #[private]
    pub fn on_agent_key_deleted(&mut self, agent: AgentId) -> RevokeResult {
        let key_deleted = key_action_succeeded();
        if key_deleted {
            if let Some(key) = self.undeleted_keys.remove(&agent) {
                self.undeleted_key_set.remove(&key);
            }
        }
        RevokeResult {
            agent,
            revoked: true,
            key_deleted,
        }
    }

    /// MPC callback for `link_agent`: on success, ecrecover-check the signer against the
    /// agent's `evm_address`, return the `Reservation` with the parsed signature. On
    /// failure or mismatch it marks the reservation `Unknown` from `Pending` only, resets
    /// `linked` if the reservation is `Pending`, `Unknown` or `Released` so the owner can
    /// retry (logging `agent_unlinked`), and leaves `Signed`, `Spent`, `Revoked` and their
    /// `linked` alone. Returns the reservation without a signature.
    /// `resolve_reservation(.., Released)` itself keeps `linked`: this callback may still
    /// bring a valid signature, and resetting earlier would allow a second link signature.
    /// Only a callback without one frees the agent.
    #[private]
    pub fn on_link_signature(&mut self, key: RequestKey) -> Reservation {
        let mut res = self.reservation(&key);
        let signature = request::callback_signature();
        let by_agent = signature.as_ref().is_some_and(|sig| {
            let expected = self
                .agents
                .get(&key.agent)
                .and_then(|r| r.evm_address.clone());
            expected.is_some() && request::signer_address(&res.digest, sig) == expected
        });
        match signature {
            Some(sig) if by_agent && res.status.can_become(RequestStatus::Signed) => {
                res.status = RequestStatus::Signed;
                res.signature = Some(sig.clone());
                self.requests.insert(key.clone(), res.clone());
                MandateEvent::SignatureRecorded {
                    key,
                    status: RequestStatus::Signed,
                    signature: sig,
                }
                .emit();
            }
            _ if matches!(
                res.status,
                RequestStatus::Pending | RequestStatus::Unknown | RequestStatus::Released
            ) =>
            {
                if res.status == RequestStatus::Pending {
                    let reason = if signature.is_some() {
                        UnknownReason::SignatureMismatch
                    } else {
                        UnknownReason::CallbackFailed
                    };
                    self.mark_unknown(&mut res, reason);
                }
                if let Some(mut record) = self.agents.get(&key.agent).cloned() {
                    if record.linked {
                        record.linked = false;
                        self.agents.insert(key.agent.clone(), record);
                        MandateEvent::AgentUnlinked {
                            agent: key.agent.clone(),
                            key: key.clone(),
                        }
                        .emit();
                    }
                }
            }
            _ => {}
        }
        res
    }

    /// OutLayer callback of a private payout (PRIV2). Asks the MPC to sign the worker's
    /// digest only if the reservation is still `pending`, the agent is live, the pinned
    /// worker is still the one the request ran (`code_hash`), the supplier is still opted in
    /// with the same payable commitment, and `private_payout::verify_worker_result` accepts
    /// the result against the pinned `worker_pk`. Otherwise it signs nothing: a `pending`
    /// reservation becomes `unknown` (`worker_unverified`) and is resolved like any other
    /// (D4); a late result for an expired one is ignored. Never panics.
    #[private]
    pub fn on_worker_result(
        &mut self,
        key: RequestKey,
        code_hash: String,
    ) -> PromiseOrValue<Reservation> {
        let mut res = self.reservation(&key);
        if res.status != RequestStatus::Pending {
            return PromiseOrValue::Value(res);
        }
        match self.verified_worker_digest(&res, &code_hash) {
            Ok(digest) => {
                res.digest = format!("0x{}", hex::encode(digest));
                self.requests.insert(key.clone(), res.clone());
                request::emit_signature_requested(&res);
                PromiseOrValue::Promise(self.mpc_sign(key, digest))
            }
            Err(why) => {
                env::log_str(&format!("worker result refused: {why}"));
                self.mark_unknown(&mut res, UnknownReason::WorkerUnverified);
                PromiseOrValue::Value(res)
            }
        }
    }

    /// MPC callback. Never panics: it reads the promise result itself, records `signed`
    /// (or `revoked`), or marks the reservation `unknown`.
    #[private]
    pub fn on_signature(&mut self, key: RequestKey) -> Reservation {
        self.record_signature(key)
    }

    // ---- Views ----

    pub fn get_config(&self) -> ConfigView {
        ConfigView {
            owner: self.owner.clone(),
            owner_nonce: self.owner_nonce,
            network: self.network.clone(),
            mpc_contract: self.mpc_contract.clone(),
            relayer: self.relayer.clone(),
            bank_change_cooling_off_secs: self.cooling_off_secs,
            private_sepa: self.private_sepa.clone(),
        }
    }

    pub fn get_agent(&self, agent: AgentId) -> Option<AgentRecord> {
        self.agents.get(&agent).cloned()
    }

    /// The live agent a key belongs to; `None` once the agent is revoked.
    pub fn agent_of_key(&self, public_key: PublicKey) -> Option<AgentId> {
        self.agent_keys.get(&public_key).cloned()
    }

    /// Agents in the order they were added, revoked ones included.
    pub fn list_agents(&self, from_index: u32, limit: u32) -> Vec<AgentRecord> {
        self.agents
            .values()
            .skip(from_index as usize)
            .take(limit as usize)
            .cloned()
            .collect()
    }

    pub fn get_mandate(&self, agent: AgentId) -> Option<Mandate> {
        self.mandates.get(&agent).cloned()
    }

    /// x402 payees, then the suppliers payable now with their payable commitment. A supplier
    /// whose first IBAN is still cooling off is not listed; `get_suppliers` shows it.
    pub fn get_payees(&self, agent: AgentId) -> Vec<Payee> {
        let mut list = self.payees.get(&agent).cloned().unwrap_or_default();
        list.extend(
            self.suppliers_at(&agent, now_secs())
                .into_iter()
                .filter_map(|s| {
                    Some(Payee::Sepa {
                        iban_commitment: s.iban_commitment?,
                        supplier: s.supplier,
                        name: s.name,
                        cap: s.cap,
                    })
                }),
        );
        list
    }

    /// The agent's suppliers as of now, pending IBAN commitments included (AP1).
    pub fn get_suppliers(&self, agent: AgentId) -> Vec<Supplier> {
        self.suppliers_at(&agent, now_secs())
    }

    /// Whether the owner opted the agent's supplier in to the private SEPA path (PRIV2).
    pub fn is_supplier_private(&self, agent: AgentId, supplier: SupplierId) -> bool {
        self.private_suppliers.contains(&(agent, supplier))
    }

    /// Whether a payout was requested for (supplier, invoice id); such an invoice is refused
    /// with `ERR_DUPLICATE_INVOICE`.
    pub fn is_invoice_paid(&self, supplier: SupplierId, invoice_id: String) -> bool {
        self.paid_invoices
            .contains(&payout::invoice_key(&supplier, &invoice_id))
    }

    /// The rail's current window (rolled forward to now, D7) and what counts against it.
    /// `None` without a mandate.
    pub fn get_budget(&self, agent: AgentId, rail: Rail) -> Option<BudgetView> {
        let mandate = self.mandates.get(&agent)?;
        let rail_mandate = match rail {
            Rail::X402 => &mandate.x402,
            Rail::Sepa => &mandate.sepa,
        };
        let (start, secs) = self.budget_window(&agent, rail, rail_mandate.period_secs, now_ms())?;
        let reserved = self.budget_used_in(&agent, rail, start);
        Some(BudgetView {
            rail,
            period_start_ms: start,
            period_secs: secs,
            budget: rail_mandate.budget,
            reserved: U128(reserved),
        })
    }

    pub fn get_request(&self, key: RequestKey) -> Option<Reservation> {
        self.requests.get(&key).cloned()
    }

    /// Requests of one agent, oldest first.
    pub fn list_requests(&self, agent: AgentId, from_index: u32, limit: u32) -> Vec<Reservation> {
        self.requests_of(&agent, from_index, limit)
    }
}

impl Contract {
    /// Shape 3's checks (AP1, PRIV1, D3) for `request_signature`: the supplier and invoice id
    /// formats (`ERR_INVALID_SUPPLIER`, `ERR_INVALID_INVOICE`), `build_payout`, then exactly
    /// once per (supplier, invoice id) (`ERR_DUPLICATE_INVOICE`) and never the same (iban,
    /// amount, timestamp) twice for one agent (`ERR_DUPLICATE_PAYOUT`). Logs `payout_approved`,
    /// or `payout_refused` with the reason code just before it panics. An invoice id is used
    /// up once requested, whatever then becomes of the reservation.
    fn check_payout(
        &mut self,
        key: &RequestKey,
        req: &PayoutRequest,
        mandate: &Mandate,
        now: u64,
    ) -> shapes::BuiltRequest {
        self.approve_payout(
            key,
            &req.supplier,
            &req.invoice_id,
            Some(&req.iban),
            req.timestamp,
            |s| payout::build_payout(req, mandate, s, now),
        )
    }

    /// The private payout's checks (PRIV2): the same as `check_payout`, with
    /// `private_payout::build_private_payout` for `build_payout`. The D3 dedupe has only the
    /// commitment here, which shape 3 records too, so one order is never signed on both paths.
    fn check_private_payout(
        &mut self,
        key: &RequestKey,
        req: &PrivatePayoutRequest,
        mandate: &Mandate,
        now: u64,
    ) -> shapes::BuiltRequest {
        self.approve_payout(
            key,
            &req.supplier,
            &req.invoice_id,
            None,
            req.timestamp,
            |s| private_payout::build_private_payout(req, mandate, s, now),
        )
    }

    /// Body of `check_payout` and `check_private_payout` (AP1, D3), with `build` the path's
    /// builder and `iban` the plaintext IBAN, which only shape 3 has. D3 records the payable
    /// commitment on both paths and the IBAN too when known; a payout is refused if any of
    /// its keys was already signed.
    fn approve_payout(
        &mut self,
        key: &RequestKey,
        supplier_id: &SupplierId,
        invoice_id: &str,
        iban: Option<&str>,
        timestamp: u64,
        build: impl FnOnce(Option<&Supplier>) -> Result<shapes::BuiltRequest, ContractError>,
    ) -> shapes::BuiltRequest {
        validate_supplier_id(supplier_id);
        if !is_id(invoice_id) {
            ContractError::InvalidInvoice.panic("invoice_id must be 1-64 chars of [A-Za-z0-9._:-]");
        }
        let refuse = |err: ContractError, field: &str| -> ! {
            MandateEvent::PayoutRefused {
                key: key.clone(),
                supplier: supplier_id.clone(),
                invoice_id: invoice_id.to_string(),
                reason: err.code().to_string(),
            }
            .emit();
            err.panic(field)
        };
        let supplier = self
            .suppliers_at(&key.agent, now_secs())
            .into_iter()
            .find(|s| s.supplier == *supplier_id);
        let built = build(supplier.as_ref()).unwrap_or_else(|e| refuse(e, error_field(e)));
        if !self
            .paid_invoices
            .insert(payout::invoice_key(supplier_id, invoice_id))
        {
            refuse(
                ContractError::DuplicateInvoice,
                "supplier and invoice_id already paid",
            );
        }
        let SignedPayload::PayoutMessage {
            amount,
            invoice_amount,
            iban_commitment,
            ..
        } = &built.payload
        else {
            env::panic_str("payout without a payout message")
        };
        // D3: never sign the same (iban, amount, timestamp) twice for one agent, on either path.
        for payee in std::iter::once(iban_commitment.as_str()).chain(iban) {
            let dedupe = payout::payout_dedupe_key(&key.agent, payee, amount, timestamp);
            if !self.signed_payouts.insert(dedupe) {
                refuse(
                    ContractError::DuplicatePayout,
                    "agent, iban, amount and timestamp already signed",
                );
            }
        }
        MandateEvent::PayoutApproved {
            key: key.clone(),
            supplier: supplier_id.clone(),
            invoice_id: invoice_id.to_string(),
            amount: amount.clone(),
            invoice_amount: invoice_amount.clone(),
        }
        .emit();
        built
    }

    /// The pinned worker config, if the private path is on (`ERR_PRIVATE_SEPA_OFF`) and the
    /// agent's `supplier` is opted in (`ERR_SUPPLIER_NOT_PRIVATE`). Checked before any state
    /// change, so a refused request uses up no invoice id.
    fn private_sepa_for(&self, agent: &AgentId, supplier: &SupplierId) -> PrivateSepaConfig {
        let config = self
            .private_sepa
            .clone()
            .unwrap_or_else(|| ContractError::PrivateSepaOff.panic("no worker pinned"));
        if !self
            .private_suppliers
            .contains(&(agent.clone(), supplier.clone()))
        {
            ContractError::SupplierNotPrivate.panic(supplier);
        }
        config
    }

    /// Stores a private payout's reservation (`pending`, empty digest) and asks OutLayer to
    /// run the pinned worker on it, with `on_worker_result` as the callback. The contract
    /// pays OutLayer's fee from its balance (`OUTLAYER_DEPOSIT`; the rest is refunded to it).
    fn reserve_and_call_worker(
        &mut self,
        key: RequestKey,
        built: shapes::BuiltRequest,
        period_start_ms: u64,
        config: PrivateSepaConfig,
    ) -> Promise {
        let res = self.store_reservation(
            key.clone(),
            ShapeKind::PrivatePayout,
            built,
            period_start_ms,
            String::new(),
        );
        let input = self.worker_input(&res);
        let me = env::current_account_id();
        let input_data = near_sdk::serde_json::to_string(&input)
            .unwrap_or_else(|_| env::panic_str("worker input"));
        let args = near_sdk::serde_json::json!({
            "source": { "WasmUrl": {
                "url": config.wasm_url,
                "hash": config.code_hash,
                "build_target": "wasm32-wasip2",
            }},
            "resource_limits": {
                "max_instructions": 1_000_000_000u64,
                "max_memory_mb": 128,
                "max_execution_seconds": 30,
            },
            "input_data": input_data,
            "secrets_ref": {
                "profile": config.secrets_profile,
                "account_id": config.secrets_owner,
            },
            "response_format": "Json",
            "payer_account_id": me,
        });
        let args =
            near_sdk::serde_json::to_vec(&args).unwrap_or_else(|_| env::panic_str("outlayer args"));
        MandateEvent::WorkerRequested {
            key: key.clone(),
            code_hash: config.code_hash.clone(),
            nonce: input.nonce,
        }
        .emit();
        Promise::new(config.outlayer)
            .function_call(
                "request_execution".to_string(),
                args,
                private_payout::OUTLAYER_DEPOSIT,
                private_payout::OUTLAYER_REQUEST_GAS,
            )
            .then(
                Self::ext(me)
                    .with_static_gas(private_payout::WORKER_CALLBACK_GAS)
                    .on_worker_result(key, config.code_hash),
            )
    }

    /// The worker input for a private payout reservation, from its own stored fields.
    fn worker_input(&self, res: &Reservation) -> private_payout::WorkerInput {
        let SignedPayload::PayoutMessage {
            amount,
            at,
            supplier,
            iban_commitment,
            ..
        } = &res.payload
        else {
            env::panic_str("private payout without a payout message")
        };
        private_payout::WorkerInput {
            nonce: private_payout::worker_nonce(&res.key),
            supplier: supplier.clone(),
            iban_commitment: iban_commitment.clone(),
            amount: amount.clone(),
            at: at.clone(),
        }
    }

    /// Body of `on_worker_result`'s checks: the digest to sign, or why not. Never panics.
    fn verified_worker_digest(
        &self,
        res: &Reservation,
        code_hash: &str,
    ) -> Result<[u8; 32], &'static str> {
        if res.shape != ShapeKind::PrivatePayout {
            return Err("not a private payout");
        }
        let config = self
            .private_sepa
            .as_ref()
            .ok_or("private path turned off")?;
        if config.code_hash != code_hash {
            return Err("pinned worker changed");
        }
        let agent = &res.key.agent;
        if self.agents.get(agent).map_or(true, |r| r.revoked) {
            return Err("agent revoked");
        }
        let input = self.worker_input(res);
        if !self
            .private_suppliers
            .contains(&(agent.clone(), input.supplier.clone()))
        {
            return Err("supplier opted out");
        }
        let payable = self
            .suppliers_at(agent, now_secs())
            .into_iter()
            .find(|s| s.supplier == input.supplier)
            .and_then(|s| s.iban_commitment);
        if payable.as_deref() != Some(input.iban_commitment.as_str()) {
            return Err("supplier commitment changed");
        }
        if env::promise_results_count() != 1 {
            return Err("no worker result");
        }
        let output = env::promise_result_checked(0, private_payout::MAX_WORKER_RESPONSE_LEN)
            .map_err(|_| "worker call failed")?;
        private_payout::verify_worker_result(&config.worker_pk, &input, &output)
    }

    /// Shared by `revoke` and `revoke_self`: clear the state first, then delete the key in a
    /// second receipt whose outcome `on_agent_key_deleted` reports (spikes/deletekey).
    fn revoke_agent(&mut self, agent: AgentId, by: RevokedBy) -> PromiseOrValue<RevokeResult> {
        let key = if self.agent_record(&agent).revoked {
            // Retry a failed DeleteKey, unless the key now belongs to a live agent.
            self.undeleted_keys
                .get(&agent)
                .cloned()
                .filter(|k| !self.agent_keys.contains_key(k))
        } else {
            let key = self.clear_agent(&agent);
            MandateEvent::AgentRevoked {
                agent: agent.clone(),
                by,
            }
            .emit();
            key
        };
        match key {
            Some(key) => {
                self.undeleted_keys.insert(agent.clone(), key.clone());
                self.undeleted_key_set.insert(key.clone());
                let me = env::current_account_id();
                PromiseOrValue::Promise(
                    Promise::new(me.clone()).delete_key(key).then(
                        Self::ext(me)
                            .with_static_gas(KEY_CALLBACK_GAS)
                            .on_agent_key_deleted(agent),
                    ),
                )
            }
            None => PromiseOrValue::Value(RevokeResult {
                agent,
                revoked: true,
                key_deleted: false,
            }),
        }
    }
}

/// The decoded field a shape builder's error is about, for the panic detail (§7).
fn error_field(err: ContractError) -> &'static str {
    use ContractError::*;
    match err {
        WrongScheme => "scheme",
        PayeeNotAllowed => "payTo",
        WrongAsset => "asset",
        WrongNetwork => "network",
        InvalidTimeout => "maxTimeoutSeconds",
        BelowMinimum | OverPerPaymentCap | InvalidAmount => "amount",
        IbanNotAllowed | InvalidIban | InvalidCommitment | BankChangeCoolingOff => "iban",
        UnknownSupplier | OverSupplierCap => "supplier",
        InvalidInvoice | OverInvoiceAmount => "invoice_amount",
        TimestampStale | TimestampFuture => "timestamp",
        DuplicatePayout => "iban, amount and timestamp",
        _ => "mandate",
    }
}
