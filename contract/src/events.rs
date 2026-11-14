//! NEP-297 events, logged as `EVENT_JSON:{"standard":"zold-mandate","version":"1.0.0",
//! "event":"<name>","data":{...}}`. A rejected call panics, so its state changes and events
//! do not count; the one exception is `payout_refused`, which a refused payout logs just
//! before it panics so the reason code shows in the failed receipt's logs (NEAR keeps the
//! logs of a failed receipt). Indexers that skip failed receipts never see it.

use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId, PublicKey};

use crate::types::{
    AgentId, EvmSignature, Mandate, Payee, PrivateSepaConfig, Rail, RequestKey, RequestStatus,
    ResolveOutcome, RevokedBy, ShapeKind, SupplierId, SweepConfig, UnknownReason,
};

pub const EVENT_STANDARD: &str = "zold-mandate";
pub const EVENT_VERSION: &str = "1.0.0";

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum MandateEvent {
    /// The key-to-agent entry is written and `AddKey` was sent.
    AgentAdded {
        agent: AgentId,
        public_key: PublicKey,
        sweep_config: SweepConfig,
    },
    /// `AddKey` failed; the key-to-agent entry was removed again (spikes/deletekey).
    AgentAddFailed {
        agent: AgentId,
        public_key: PublicKey,
    },
    RelayerSet {
        account: Option<AccountId>,
    },
    MandateSet {
        agent: AgentId,
        mandate: Mandate,
    },
    PayeeAdded {
        agent: AgentId,
        payee: Payee,
    },
    PayeeRemoved {
        agent: AgentId,
        payee: Payee,
    },
    /// A supplier IBAN commitment was added (new supplier) or changed, and waits out the
    /// cooling-off: payouts to it are refused until `effective_at` (unix seconds).
    SupplierIbanPending {
        agent: AgentId,
        supplier: SupplierId,
        iban_commitment: String,
        effective_at: u64,
    },
    /// The owner withdrew a pending IBAN commitment before it took effect.
    SupplierIbanCancelled {
        agent: AgentId,
        supplier: SupplierId,
        iban_commitment: String,
    },
    BankChangeCoolingOffSet {
        secs: u64,
    },
    /// A payout passed the supplier and invoice checks; `signature_requested` follows.
    /// Amounts are canonical decimal euros.
    PayoutApproved {
        key: RequestKey,
        supplier: SupplierId,
        invoice_id: String,
        amount: String,
        invoice_amount: String,
    },
    /// A payout was refused; `reason` is the error code the call then panics with.
    PayoutRefused {
        key: RequestKey,
        supplier: SupplierId,
        invoice_id: String,
        reason: String,
    },
    /// A reservation was made and the digest sent to the MPC (all shapes, including link).
    SignatureRequested {
        key: RequestKey,
        shape: ShapeKind,
        rail: Option<Rail>,
        amount: U128,
        digest: String,
        valid_before: u64,
    },
    /// The MPC callback delivered a signature; `status` is `signed` or `revoked`.
    SignatureRecorded {
        key: RequestKey,
        status: RequestStatus,
        signature: EvmSignature,
    },
    RequestUnknown {
        key: RequestKey,
        reason: UnknownReason,
    },
    ReservationResolved {
        key: RequestKey,
        outcome: ResolveOutcome,
    },
    /// A failed or wrong-key link callback reset `linked`; the owner may call `link_agent` again.
    AgentUnlinked {
        agent: AgentId,
        key: RequestKey,
    },
    AgentRevoked {
        agent: AgentId,
        by: RevokedBy,
    },
    /// A passkey owner pinned (or with `None` removed) the private SEPA worker (PRIV2).
    PrivateSepaConfigSet {
        config: Option<PrivateSepaConfig>,
    },
    /// A supplier was opted in to (or out of) the private SEPA path (PRIV2).
    SupplierPrivacySet {
        agent: AgentId,
        supplier: SupplierId,
        private: bool,
    },
    /// A private payout was approved and sent to the pinned worker; `signature_requested`
    /// follows once its result is verified, or `request_unknown` (`worker_unverified`).
    WorkerRequested {
        key: RequestKey,
        code_hash: String,
        nonce: String,
    },
}

/// The full NEP-297 log object.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct EventLog {
    pub standard: String,
    pub version: String,
    #[serde(flatten)]
    pub event: MandateEvent,
}

impl MandateEvent {
    pub fn to_log(&self) -> EventLog {
        EventLog {
            standard: EVENT_STANDARD.to_string(),
            version: EVENT_VERSION.to_string(),
            event: self.clone(),
        }
    }

    pub fn emit(&self) {
        let json = near_sdk::serde_json::to_string(&self.to_log())
            .unwrap_or_else(|_| env::panic_str("event serialization failed"));
        env::log_str(&format!("EVENT_JSON:{json}"));
    }
}
