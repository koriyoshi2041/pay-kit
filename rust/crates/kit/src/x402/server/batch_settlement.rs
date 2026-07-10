//! Server-side handler for the x402 `batch-settlement` scheme (payment-channel).
//!
//! High-throughput channel payments: the client opens an escrow channel
//! ([`X402BatchSettlement::verify_payment`] with a `deposit` payload), then signs
//! cumulative vouchers per request (`voucher` payloads) that the server accepts
//! off-chain via [`crate::core::session::accept_voucher`] and serves
//! immediately. The operator redeems the latest voucher per channel on-chain
//! later, in batches ([`X402BatchSettlement::settle_batch`]), and sweeps the
//! proceeds ([`X402BatchSettlement::distribute`]). Cooperative close refunds the
//! unused deposit.
//!
//! v1: fixed per-request price; explicit operator-driven settlement (no
//! automatic cron / forced-close watchdog yet).

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex as AsyncMutex;

use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::Transaction;

use crate::core::payment_channels as pc;
use crate::core::payment_channels::generated::accounts::Channel;
use crate::core::session::{accept_voucher, VoucherAcceptance};
use crate::core::settlement::packing::{pack, ChannelInstructions, DEFAULT_MAX_CHANNELS_PER_TX};
use crate::core::store::{ChannelState, ChannelStore, MemoryChannelStore, StoreError};
use crate::core::voucher::verify_voucher_signature;

use crate::x402::error::Error;
use crate::x402::protocol::schemes::batch_settlement::{
    check_profile, BatchChannelSnapshot, BatchExtra, BatchPayload, BatchRequiredEnvelope,
    BatchRequirements, BatchSettlementResponse, BatchSplit, BatchVoucher, BATCH_SETTLEMENT_SCHEME,
    PROFILE_PAYMENT_CHANNEL,
};
use crate::x402::protocol::schemes::exact::{
    caip2_network_for_cluster, default_rpc_url, default_token_program_for_currency,
    resolve_stablecoin_mint, ResourceInfo,
};
use crate::x402::server::upto::{
    cosign_operator_fee_payer, decode_transaction, validate_open_instruction,
};
use crate::x402::server::MAX_PAYMENT_SIGNATURE_HEADER_LEN;
use crate::x402::{PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, X402_VERSION_V2};

/// `ChannelStatus::Open` discriminant in the generated client.
const CHANNEL_STATUS_OPEN: u8 = 0;

/// Default forced-close grace period (seconds).
const DEFAULT_GRACE_PERIOD_SECONDS: u32 = 900;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Server configuration for the Solana x402 `batch-settlement` scheme.
#[derive(Clone)]
pub struct BatchConfig {
    /// Base58 channel payee (proceeds recipient).
    pub recipient: String,
    /// Currency symbol (`"USDC"`) or mint address.
    pub currency: String,
    /// Token decimals.
    pub decimals: u8,
    /// Solana cluster: `mainnet-beta`, `devnet`, or `localnet`.
    pub cluster: String,
    /// RPC URL override (defaults per cluster).
    pub rpc_url: Option<String>,
    /// Resource identifier for the 402 challenge.
    pub resource: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// Completion window in seconds.
    pub max_timeout_seconds: u64,
    /// Forced-close grace period (seconds, non-zero).
    pub grace_period_seconds: u32,
    /// Minimum cumulative increment between accepted vouchers (base units).
    pub min_voucher_delta: u64,
    /// Token program override.
    pub token_program: Option<String>,
    /// Channel program id override (defaults to the canonical deployment).
    pub program_id: Option<String>,
    /// Operator signer — co-signs `open` as fee payer and signs settlement txs.
    pub operator_signer: Arc<dyn SolanaSigner>,
    /// Merchant-side splits committed at open (recipient base58, share bps).
    pub splits: Vec<(String, u16)>,
}

impl BatchConfig {
    /// Minimal config with sane defaults.
    pub fn new(
        recipient: impl Into<String>,
        cluster: impl Into<String>,
        operator_signer: Arc<dyn SolanaSigner>,
    ) -> Self {
        Self {
            recipient: recipient.into(),
            currency: "USDC".to_string(),
            decimals: 6,
            cluster: cluster.into(),
            rpc_url: None,
            resource: String::new(),
            description: None,
            max_timeout_seconds: 3600,
            grace_period_seconds: DEFAULT_GRACE_PERIOD_SECONDS,
            min_voucher_delta: 0,
            token_program: None,
            program_id: None,
            operator_signer,
            splits: vec![],
        }
    }
}

/// Outcome of verifying a `batch-settlement` payment.
#[derive(Debug)]
pub struct BatchOutcome {
    /// Whether the gate should run the protected handler (false for refunds).
    pub serve: bool,
    /// The settlement response to surface in `PAYMENT-RESPONSE`.
    pub response: BatchSettlementResponse,
}

/// Server-side payment handler for the Solana x402 `batch-settlement` scheme.
#[derive(Clone)]
pub struct X402BatchSettlement {
    rpc: Arc<RpcClient>,
    config: BatchConfig,
    operator: Pubkey,
    store: Arc<dyn ChannelStore>,
    /// Per-channel serialization gates. A voucher acceptance must decide `serve`
    /// on the watermark delta it actually *commits*, not on a watermark read
    /// before the commit. Two concurrent vouchers on one channel would otherwise
    /// each read the same stale watermark, both compute a `>= price` delta from
    /// it, and both be served while only the larger cumulative is committed —
    /// under-paying for one served request. Holding this per-channel gate across
    /// the read → price-gate → accept span serializes those requests so the read
    /// is the in-lock prior watermark and the committed delta is authoritative.
    ///
    /// Entries are refcounted and evicted once no holder or waiter remains
    /// (see [`X402BatchSettlement::voucher_gate`] / [`VoucherGate`]), so an
    /// unauthenticated client posting vouchers with random channel ids cannot
    /// grow this map without bound.
    voucher_gates: Arc<Mutex<HashMap<String, GateEntry>>>,
    /// Test-only seam: fires in `process_deposit` after the fresh channel is
    /// written (`put_channel`, watermark 0) but before the first voucher is
    /// accepted — the exact window a concurrent voucher must not be able to
    /// interleave into. A test parks the deposit here and drives a concurrent
    /// voucher's acceptance to prove the deposit holds the per-channel gate
    /// across the watermark write and the first accept.
    #[cfg(test)]
    post_put_hook: Arc<Mutex<Option<PreGateHook>>>,
    /// Test-only seam: fires in `process_voucher` after the in-lock prior
    /// watermark (`prev`) is read but before the price gate and accept — i.e.
    /// with the per-channel gate held. A test parks a voucher here (holding the
    /// gate) so a concurrent voucher on the same channel is forced to wait,
    /// proving the gate serializes the read → price-gate → accept span. When the
    /// gate lock is removed the concurrent voucher instead interleaves and reads
    /// the same stale watermark, changing the serve outcome.
    #[cfg(test)]
    post_read_hook: Arc<Mutex<Option<PreGateHook>>>,
}

/// A refcounted per-channel serialization gate entry. `refs` counts holders plus
/// waiters and is guarded by [`X402BatchSettlement::voucher_gates`]'s outer
/// `Mutex`, so the last releaser observing `refs == 0` can evict the map entry.
struct GateEntry {
    lock: Arc<AsyncMutex<()>>,
    refs: usize,
}

/// Guard returned by [`X402BatchSettlement::voucher_gate`]. Holds the acquired
/// `Arc<AsyncMutex>` so the caller can `.lock().await` it, and on drop
/// decrements the entry's refcount under the map lock — evicting the entry once
/// no holder or waiter remains. Mirrors Go's acquireChannelLock /
/// releaseChannelLock so the gate map stays bounded by the number of
/// concurrently active channels rather than every channel id ever seen.
struct VoucherGate {
    gates: Arc<Mutex<HashMap<String, GateEntry>>>,
    channel_id: String,
    lock: Arc<AsyncMutex<()>>,
}

impl VoucherGate {
    /// The `Arc<AsyncMutex>` to `.lock().await` for the serialized section.
    fn lock(&self) -> &Arc<AsyncMutex<()>> {
        &self.lock
    }
}

impl Drop for VoucherGate {
    fn drop(&mut self) {
        let mut gates = self.gates.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = gates.get_mut(&self.channel_id) {
            entry.refs -= 1;
            // Evict only when this is still the same entry we bumped — a late
            // acquirer that recreated the entry after eviction owns a distinct
            // `Arc`, so compare by pointer identity before deleting.
            if entry.refs == 0 && Arc::ptr_eq(&entry.lock, &self.lock) {
                gates.remove(&self.channel_id);
            }
        }
    }
}

/// Test-only seam payload for the `post_put_hook` / `post_read_hook` seams: the
/// call that consumes the hook signals `entered` (so the test knows it reached
/// the seam) and then parks on `release` until the test drops its guard.
#[cfg(test)]
struct PreGateHook {
    entered: tokio::sync::oneshot::Sender<()>,
    release: Arc<AsyncMutex<()>>,
}

impl X402BatchSettlement {
    /// Build a handler with an in-memory channel store.
    pub fn new(config: BatchConfig) -> Result<Self, Error> {
        let localnet = matches!(
            config.cluster.trim().to_ascii_lowercase().as_str(),
            "localnet" | "solana_localnet"
        );
        if !localnet && std::env::var("PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE").as_deref() != Ok("1") {
            return Err(Error::Other(
                "non-localnet x402 batch settlement requires a shared channel store; use X402BatchSettlement::with_store or set PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1 to acknowledge process-local replay protection"
                    .into(),
            ));
        }
        Self::with_store(config, Arc::new(MemoryChannelStore::new()))
    }

    /// Build a handler with a caller-provided (e.g. durable) channel store.
    pub fn with_store(config: BatchConfig, store: Arc<dyn ChannelStore>) -> Result<Self, Error> {
        if config.recipient.is_empty() {
            return Err(Error::Other("recipient is required".into()));
        }
        Pubkey::from_str(&config.recipient)
            .map_err(|e| Error::Other(format!("Invalid recipient pubkey: {e}")))?;
        let operator = config.operator_signer.pubkey();
        let rpc_url = config
            .rpc_url
            .clone()
            .unwrap_or_else(|| default_rpc_url(&config.cluster).to_string());
        Ok(Self {
            rpc: Arc::new(RpcClient::new(rpc_url)),
            config,
            operator,
            store,
            voucher_gates: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            post_put_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            post_read_hook: Arc::new(Mutex::new(None)),
        })
    }

    /// Acquire (or create) the per-channel serialization gate for `channel_id`,
    /// bumping its refcount so a concurrent releaser cannot evict the entry
    /// while this caller is still queued on it. Returns a [`VoucherGate`] guard
    /// that decrements the refcount on drop and evicts the entry once idle, so
    /// the gate map never grows with channel ids that no request currently
    /// holds. The caller `.lock().await`s the returned guard for the serialized
    /// section. The (potentially contended) async lock is taken outside the
    /// outer map `Mutex`, so the `std::sync::Mutex` is never held across `.await`.
    fn voucher_gate(&self, channel_id: &str) -> VoucherGate {
        let lock = {
            let mut gates = self.voucher_gates.lock().unwrap_or_else(|e| e.into_inner());
            let entry = gates
                .entry(channel_id.to_string())
                .or_insert_with(|| GateEntry {
                    lock: Arc::new(AsyncMutex::new(())),
                    refs: 0,
                });
            entry.refs += 1;
            entry.lock.clone()
        };
        VoucherGate {
            gates: self.voucher_gates.clone(),
            channel_id: channel_id.to_string(),
            lock,
        }
    }

    /// Atomically create the persisted channel state without replacing an
    /// already-open channel. A retry of the same confirmed open is idempotent;
    /// a conflicting state is rejected instead of resetting its watermark.
    async fn create_channel_if_absent(
        &self,
        channel_id: &str,
        expected: ChannelState,
    ) -> Result<bool, Error> {
        let created = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let created_in_update = Arc::clone(&created);
        self.store
            .update_channel(
                channel_id,
                Box::new(move |existing| match existing {
                    None => {
                        created_in_update.store(true, std::sync::atomic::Ordering::SeqCst);
                        Ok(expected)
                    }
                    Some(state)
                        if state.channel_id == expected.channel_id
                            && state.authorized_signer == expected.authorized_signer
                            && state.deposit == expected.deposit
                            && state.open_slot == expected.open_slot
                            && state.operator == expected.operator =>
                    {
                        created_in_update.store(false, std::sync::atomic::Ordering::SeqCst);
                        Ok(state)
                    }
                    Some(_) => Err(StoreError::Internal(
                        "existing channel state does not match confirmed open".to_string(),
                    )),
                }),
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;
        Ok(created.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// Operator/facilitator pubkey (base58).
    pub fn operator(&self) -> String {
        pc::pubkey_string(&self.operator)
    }

    fn program_id(&self) -> Result<Pubkey, Error> {
        match &self.config.program_id {
            Some(v) => {
                Pubkey::from_str(v).map_err(|e| Error::Other(format!("invalid programId: {e}")))
            }
            None => Ok(pc::default_program_id()),
        }
    }

    fn mint(&self) -> Result<Pubkey, Error> {
        let mint = resolve_stablecoin_mint(&self.config.currency, Some(&self.config.cluster))
            .ok_or_else(|| Error::Other("batch-settlement requires an SPL token".into()))?;
        Pubkey::from_str(mint).map_err(|e| Error::Other(format!("invalid mint: {e}")))
    }

    fn token_program(&self) -> Result<Pubkey, Error> {
        let tp = self.config.token_program.clone().unwrap_or_else(|| {
            default_token_program_for_currency(&self.config.currency, Some(&self.config.cluster))
                .to_string()
        });
        Pubkey::from_str(&tp).map_err(|e| Error::Other(format!("invalid token program: {e}")))
    }

    fn distributions(&self) -> Result<Vec<pc::Distribution>, Error> {
        self.config
            .splits
            .iter()
            .map(|(recipient, bps)| {
                Ok(pc::Distribution {
                    recipient: Pubkey::from_str(recipient)
                        .map_err(|e| Error::Other(format!("invalid split recipient: {e}")))?,
                    bps: *bps,
                })
            })
            .collect()
    }

    /// Build the `batch-settlement` requirement (pure; no RPC).
    pub fn requirements(&self, amount: &str) -> Result<BatchRequirements, Error> {
        let base_units = crate::x402::server::exact::parse_units(amount, self.config.decimals)?;
        let splits = self
            .config
            .splits
            .iter()
            .map(|(recipient, bps)| BatchSplit {
                recipient: recipient.clone(),
                share_bps: *bps,
            })
            .collect();
        Ok(BatchRequirements {
            scheme: BATCH_SETTLEMENT_SCHEME.to_string(),
            network: caip2_network_for_cluster(&self.config.cluster).to_string(),
            amount: base_units,
            asset: pc::pubkey_string(&self.mint()?),
            pay_to: self.config.recipient.clone(),
            max_timeout_seconds: self.config.max_timeout_seconds,
            extra: BatchExtra {
                profiles: vec![PROFILE_PAYMENT_CHANNEL.to_string()],
                channel_program: pc::pubkey_string(&self.program_id()?),
                grace_period_seconds: self.config.grace_period_seconds,
                decimals: Some(self.config.decimals),
                token_program: Some(pc::pubkey_string(&self.token_program()?)),
                fee_payer: self.operator(),
                recent_blockhash: None,
                recent_slot: None,
                suggested_deposit: None,
                minimum_deposit: None,
                min_voucher_delta: (self.config.min_voucher_delta > 0)
                    .then(|| self.config.min_voucher_delta.to_string()),
                distribution_splits: splits,
            },
        })
    }

    /// Build the full 402 challenge envelope. Fetches a recent blockhash and
    /// the current slot in ONE `getLatestBlockhash` call (its response context
    /// carries the slot) — `recentSlot` is the hint clients must use as the
    /// program's `openSlot` when building the channel `open`; they never fetch
    /// a slot themselves.
    pub fn challenge(&self, amount: &str) -> Result<BatchRequiredEnvelope, Error> {
        let mut requirement = self.requirements(amount)?;
        let hint =
            crate::core::blockhash::fetch_blockhash_with_slot(&self.rpc, self.rpc.commitment())
                .map_err(|e| Error::Rpc(format!("failed to fetch recent blockhash: {e}")))?;
        requirement.extra.recent_blockhash = Some(hint.blockhash);
        requirement.extra.recent_slot = Some(hint.slot.to_string());
        let resource = (!self.config.resource.is_empty()).then(|| ResourceInfo {
            url: self.config.resource.clone(),
            description: self.config.description.clone(),
            mime_type: None,
        });
        Ok(BatchRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource,
            accepts: vec![requirement],
            error: None,
        })
    }

    /// `(header-name, base64-value)` for the 402 challenge.
    pub fn payment_required_header(&self, amount: &str) -> Result<(String, String), Error> {
        let envelope = self.challenge(amount)?;
        let json = serde_json::to_string(&envelope)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        Ok((
            PAYMENT_REQUIRED_HEADER.to_string(),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json.as_bytes()),
        ))
    }

    /// `(header-name, base64-value)` for the `PAYMENT-RESPONSE` settlement
    /// result, ready to set on the route's response.
    pub fn settlement_header(
        &self,
        response: &BatchSettlementResponse,
    ) -> Result<(String, String), Error> {
        let json = serde_json::to_string(response)
            .map_err(|e| Error::Other(format!("settlement serialization failed: {e}")))?;
        Ok((
            PAYMENT_RESPONSE_HEADER.to_string(),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json.as_bytes()),
        ))
    }

    /// Decode a `PAYMENT-SIGNATURE` header into a `batch-settlement` payload.
    pub fn parse_payment(&self, header: &str) -> Result<BatchPayload, Error> {
        use crate::x402::protocol::schemes::batch_settlement::BatchSignatureEnvelope;
        // Cap the header before any base64 / JSON work, matching the `exact` and
        // `upto` parsers' 16 KiB `MAX_PAYMENT_SIGNATURE_HEADER_LEN`. A
        // batch-settlement header additionally embeds a full base64 transaction,
        // so without this an oversized credential header drives proportionally
        // larger decode + parse work.
        if header.len() > MAX_PAYMENT_SIGNATURE_HEADER_LEN {
            return Err(Error::InvalidPaymentRequired(format!(
                "PAYMENT-SIGNATURE header exceeds maximum length of {MAX_PAYMENT_SIGNATURE_HEADER_LEN} bytes"
            )));
        }
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, header)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        let envelope: BatchSignatureEnvelope = serde_json::from_slice(&decoded)
            .map_err(|e| Error::InvalidPaymentRequired(e.to_string()))?;
        if envelope.scheme != BATCH_SETTLEMENT_SCHEME {
            return Err(Error::InvalidPayloadType(envelope.scheme));
        }
        Ok(envelope.payload)
    }

    /// Verify a `batch-settlement` payment for a route priced at `amount`.
    ///
    /// `deposit` broadcasts + confirms the channel open and accepts the first
    /// voucher; `voucher` accepts a cumulative voucher off-chain; `refund`
    /// cooperatively settles + seals (and is not served).
    pub async fn verify_payment(&self, header: &str, amount: &str) -> Result<BatchOutcome, Error> {
        let payload = self.parse_payment(header)?;
        let requirements = self.requirements(amount)?;
        check_profile(&requirements.extra.profiles)?;
        let per_request = requirements.amount()?;

        match payload {
            BatchPayload::Deposit {
                channel_config,
                transaction,
                voucher,
            } => {
                self.process_deposit(channel_config, transaction, voucher, per_request)
                    .await
            }
            BatchPayload::Voucher {
                channel_id,
                voucher,
            } => {
                self.process_voucher(&channel_id, voucher, per_request)
                    .await
            }
            BatchPayload::Refund {
                channel_id,
                voucher,
            } => self.process_refund(&channel_id, voucher).await,
        }
    }

    async fn process_deposit(
        &self,
        config: crate::x402::protocol::schemes::batch_settlement::BatchChannelConfig,
        transaction: String,
        voucher: Option<BatchVoucher>,
        per_request: u64,
    ) -> Result<BatchOutcome, Error> {
        // The first voucher (if any) pays for the request being served; reject
        // an underpriced one before opening the channel on-chain.
        if let Some(v) = &voucher {
            let charged = v.cumulative()?;
            if charged < per_request {
                return Err(Error::Other(format!(
                    "first voucher charge {charged} is below the required {per_request}"
                )));
            }
        }
        let program_id = self.program_id()?;
        let expected_mint = self.mint()?;
        let token_program = self.token_program()?;
        let expected_payee = Pubkey::from_str(&self.config.recipient)
            .map_err(|e| Error::Other(format!("invalid recipient: {e}")))?;
        let payer = Pubkey::from_str(&config.payer)
            .map_err(|e| Error::Other(format!("invalid payer: {e}")))?;
        let authorized_signer = Pubkey::from_str(&config.authorized_signer)
            .map_err(|e| Error::Other(format!("invalid authorizedSigner: {e}")))?;
        let salt: u64 = config
            .salt
            .parse()
            .map_err(|_| Error::Other(format!("invalid salt: {}", config.salt)))?;
        // The config's recentSlot is the program's openSlot (a PDA seed).
        let open_slot: u64 = config
            .recent_slot
            .parse()
            .map_err(|_| Error::Other(format!("invalid recentSlot: {}", config.recent_slot)))?;

        // Derive the expected channel PDA and validate the open transaction binds
        // it (SOL-drain guard) before the operator co-signs as fee payer.
        let (channel_id, _) = pc::find_channel_pda(
            &payer,
            &expected_payee,
            &expected_mint,
            &authorized_signer,
            salt,
            open_slot,
            &program_id,
        );
        let mut tx = decode_transaction(&transaction)?;
        // In `batch-settlement` the client signs vouchers, so the open's
        // authorized-signer account is the channel's `authorized_signer`
        // (the payer by default) — not the operator as in `upto`.
        validate_open_instruction(
            &tx,
            &program_id,
            // Gasless: the operator funds the rent and co-signs as fee payer, so
            // the rentPayer is the operator. The authorized_signer is the
            // channel's voucher signer (the payer in batch client mode), checked
            // independently — see the two-key rationale in `validate_open_instruction`.
            &self.operator,
            &authorized_signer,
            &payer,
            &expected_payee,
            &expected_mint,
            &token_program,
            &channel_id,
            // Deposit is validated against the on-chain channel post-broadcast
            // (batch has no single authorized maximum at open time).
            None,
            None,
            None,
            None,
            // The config's recentSlot IS the expected openSlot: the args-derived
            // PDA above already pins it exactly, and the window check keeps the
            // pre-broadcast failure mode explicit.
            Some(open_slot),
        )?;
        cosign_operator_fee_payer(
            self.config.operator_signer.as_ref(),
            &self.operator,
            &mut tx,
        )
        .await?;
        self.rpc
            .send_and_confirm_transaction(&tx)
            .map_err(|e| Error::Rpc(format!("open broadcast failed: {e}")))?;
        let open_sig = tx
            .signatures
            .first()
            .map(|s| s.to_string())
            .unwrap_or_default();

        // Bind the confirmed channel state.
        let channel = self.fetch_channel(&channel_id)?;
        if channel.status != CHANNEL_STATUS_OPEN {
            return Err(Error::Other("channel is not open after broadcast".into()));
        }
        if pc::from_address(&channel.mint) != expected_mint {
            return Err(Error::MintMismatch {
                expected: pc::pubkey_string(&expected_mint),
                actual: pc::pubkey_string(&pc::from_address(&channel.mint)),
            });
        }
        if pc::from_address(&channel.payee) != expected_payee {
            return Err(Error::RecipientMismatch {
                expected: pc::pubkey_string(&expected_payee),
                actual: pc::pubkey_string(&pc::from_address(&channel.payee)),
            });
        }
        if pc::from_address(&channel.authorized_signer) != authorized_signer {
            return Err(Error::Other("channel authorized_signer mismatch".into()));
        }
        if pc::from_address(&channel.payer) != payer {
            return Err(Error::Other("channel payer mismatch".into()));
        }
        // Bind the economically-relevant channel terms to what we advertised, so
        // a client can't open an under-funded channel, a different forced-close
        // window, or splits that redirect proceeds away from the payee.
        if channel.deposit < per_request {
            return Err(Error::Other(format!(
                "channel deposit {} is below one request's price {per_request}",
                channel.deposit
            )));
        }
        if channel.grace_period != self.config.grace_period_seconds {
            return Err(Error::Other(format!(
                "channel grace_period {} does not match advertised {}",
                channel.grace_period, self.config.grace_period_seconds
            )));
        }
        if channel.distribution_hash != pc::distribution_hash(&self.distributions()?) {
            return Err(Error::Other(
                "channel distribution does not match advertised splits".into(),
            ));
        }

        let channel_b58 = pc::pubkey_string(&channel_id);

        // Serialize the watermark write and the first-voucher accept under the
        // per-channel gate. Without holding it, a concurrent `process_voucher`
        // could acquire the gate, read this fresh channel's watermark (0), pass
        // the price gate and commit a larger cumulative between our `put_channel`
        // and our first accept — leaving both the deposit and the voucher served
        // for a combined committed delta below two requests' price. Holding the
        // gate across both makes the deposit's write and first accept atomic with
        // respect to concurrent voucher acceptances on this channel.
        let gate = self.voucher_gate(&channel_b58);
        let _held = gate.lock().lock().await;

        let expected_state = ChannelState {
            channel_id: channel_b58.clone(),
            authorized_signer: pc::pubkey_string(&authorized_signer),
            deposit: channel.deposit,
            cumulative: 0,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            // Persisted for PDA re-derivation and the reclaim gate.
            open_slot: Some(open_slot),
            salt: Some(channel.salt),
            open_signature: Some(open_sig.clone()),
            // Stash the payer here so settlement/distribute can refund it
            // without an extra account fetch.
            operator: Some(pc::pubkey_string(&payer)),
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
        };
        let created = self
            .create_channel_if_absent(&channel_b58, expected_state)
            .await?;

        // Test-only seam: fires with the gate held, after the fresh channel is
        // written but before the first voucher is accepted — the exact window a
        // concurrent voucher must not be able to interleave into.
        #[cfg(test)]
        {
            let hook = self
                .post_put_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(hook) = hook {
                let _ = hook.entered.send(());
                let _ = hook.release.lock().await;
            }
        }

        // A retried open keeps the existing watermark. Its first voucher is
        // therefore accepted idempotently (serve=false) or as a genuinely new
        // paid increment; it can never reset cumulative to zero.
        let (serve, charged) = if let Some(v) = voucher {
            let acceptance = self.accept(&channel_b58, &v, per_request).await?;
            (
                !acceptance.replay && acceptance.charged >= per_request,
                Some(acceptance.charged),
            )
        } else {
            (created, None)
        };
        drop(_held);
        drop(gate);

        Ok(BatchOutcome {
            serve,
            response: BatchSettlementResponse {
                success: true,
                error_reason: None,
                payer: Some(pc::pubkey_string(&payer)),
                transaction: open_sig,
                network: caip2_network_for_cluster(&self.config.cluster).to_string(),
                amount: channel.deposit.to_string(),
                charged_amount: charged.map(|c| c.to_string()),
                channel_state: Some(
                    self.snapshot(&channel_b58, channel.deposit, 0, "open")
                        .await,
                ),
            },
        })
    }

    async fn process_voucher(
        &self,
        channel_id: &str,
        voucher: BatchVoucher,
        per_request: u64,
    ) -> Result<BatchOutcome, Error> {
        // Serialize acceptances on this channel so the watermark that gates the
        // price and the paid serve is the in-lock prior watermark this voucher
        // commits against. Without this, two concurrent vouchers could both read
        // the same stale watermark before either commits, both pass the price
        // gate, and both be served while only the larger cumulative is committed
        // — under-paying for one served request.
        let gate = self.voucher_gate(channel_id);
        let _held = gate.lock().lock().await;

        // Test-only seam: fires while the handler-local gate is held and before
        // the atomic store acceptance. It lets tests exercise local contention;
        // the store transaction remains the cross-handler correctness boundary.
        #[cfg(test)]
        {
            let hook = self
                .post_read_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(hook) = hook {
                let _ = hook.entered.send(());
                let _ = hook.release.lock().await;
            }
        }

        // The store transaction computes the committed delta from its in-lock
        // watermark and applies the price floor there. Handler-local gates only
        // reduce contention; correctness therefore holds across independently
        // constructed handlers and replicas sharing one atomic store.
        let acceptance = self.accept(channel_id, &voucher, per_request).await?;
        let charged = acceptance.charged;
        // A fresh paid serve requires committing at least one request's price and
        // not being an idempotent replay. An idempotent replay (`replay == true`,
        // delta 0) is NOT a fresh paid serve: the route was already paid for on
        // the original voucher. The `!replay` clause also guards the
        // `per_request == 0` edge so a replay can never re-serve for free.
        let serve = !acceptance.replay && charged >= per_request;
        let deposit = self
            .store
            .get_channel(channel_id)
            .await
            .ok()
            .flatten()
            .map(|s| s.deposit)
            .unwrap_or(0);
        Ok(BatchOutcome {
            serve,
            response: BatchSettlementResponse {
                success: true,
                error_reason: None,
                payer: None,
                transaction: String::new(),
                network: caip2_network_for_cluster(&self.config.cluster).to_string(),
                amount: String::new(),
                charged_amount: Some(charged.to_string()),
                channel_state: Some(self.snapshot(channel_id, deposit, 0, "open").await),
            },
        })
    }

    /// Accept a voucher off-chain via the shared core acceptance logic.
    ///
    /// Returns the full [`VoucherAcceptance`] so callers can distinguish a fresh
    /// charge from an idempotent replay (`charged == 0`, `replay == true`) and
    /// never grant a fresh paid serve for a replay. The settlement window is the
    /// configured forced-close grace period: a non-zero voucher expiry must
    /// outlast it so the voucher can still settle on-chain after the async
    /// forced-close delay.
    async fn accept(
        &self,
        channel_id: &str,
        voucher: &BatchVoucher,
        required_delta: u64,
    ) -> Result<VoucherAcceptance, Error> {
        let cumulative = voucher.cumulative()?;
        accept_voucher(
            self.store.as_ref(),
            channel_id,
            cumulative,
            voucher.expires_at,
            &voucher.signature,
            now_unix(),
            self.config.min_voucher_delta.max(required_delta),
            self.config.grace_period_seconds as i64,
        )
        .await
        .map_err(Into::into)
    }

    async fn process_refund(
        &self,
        channel_id: &str,
        voucher: Option<BatchVoucher>,
    ) -> Result<BatchOutcome, Error> {
        // A refund cooperatively closes the channel and bypasses the route, so
        // it must prove control of the channel: the request has to carry a
        // voucher signed by the channel's authorized signer. The channel id
        // travels in every voucher header and is not secret, so without this
        // anyone who observes one could force a close and evict the client.
        let voucher = voucher.ok_or_else(|| {
            Error::Other(
                "refund requires a voucher signed by the channel's authorized signer".into(),
            )
        })?;
        let state = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;
        let cumulative = voucher.cumulative()?;
        if cumulative > state.cumulative {
            // Advances the watermark: accept it so the final amount settles in
            // the close. `accept` verifies the signature against the signer.
            self.accept(channel_id, &voucher, 0).await?;
        } else {
            // Proof-of-ownership only (at or below the watermark — nothing to
            // advance): still verify the signature to authorize the close.
            verify_voucher_signature(
                channel_id,
                cumulative,
                voucher.expires_at,
                &voucher.signature,
                &state.authorized_signer,
                now_unix(),
                self.config.grace_period_seconds as i64,
            )?;
        }

        // Freeze the channel before any on-chain work. Once `close_requested_at`
        // is set, `accept_voucher` rejects further vouchers, so a concurrent
        // request can no longer advance the watermark past what
        // `settle_and_seal` is about to read — an advance that would
        // otherwise be accepted off-chain yet be unrecoverable on-chain after
        // the channel is sealed at the earlier watermark.
        let frozen = self
            .store
            .update_channel(
                channel_id,
                Box::new(|s| {
                    let mut state =
                        s.ok_or_else(|| StoreError::Internal("Channel not found".to_string()))?;
                    state.close_requested_at.get_or_insert(now_unix() as u64);
                    Ok(state)
                }),
            )
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;

        let sig = self.settle_and_seal(channel_id).await?;
        // Skip the sweep when nothing was ever settled — `distribute` would just
        // broadcast a second transaction that moves zero, wasting fees.
        let distribute_sig = if frozen.cumulative > 0 {
            self.distribute(channel_id).await?
        } else {
            None
        };
        self.store
            .mark_sealed(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?;
        // `distribute` sweeps the full settled pool, so once it lands the
        // on-chain `paidOut` equals the settled watermark.
        let paid_out = if distribute_sig.is_some() {
            frozen.cumulative
        } else {
            0
        };
        Ok(BatchOutcome {
            serve: false,
            response: BatchSettlementResponse {
                success: true,
                error_reason: None,
                payer: None,
                transaction: distribute_sig.unwrap_or(sig),
                network: caip2_network_for_cluster(&self.config.cluster).to_string(),
                amount: String::new(),
                charged_amount: None,
                channel_state: Some(
                    self.snapshot(channel_id, frozen.deposit, paid_out, "sealed")
                        .await,
                ),
            },
        })
    }

    /// Redeem the latest voucher of each channel on-chain, packing channels into
    /// `<=1232`-byte transactions via the shared
    /// [`crate::core::settlement::packing::pack`]. Returns the broadcast
    /// signatures. Channels without an accepted voucher are skipped.
    pub async fn settle_batch(&self, channel_ids: &[String]) -> Result<Vec<String>, Error> {
        let program_id = self.program_id()?;
        let mut pending = Vec::new();
        for id in channel_ids {
            let Some(state) = self
                .store
                .get_channel(id)
                .await
                .map_err(|e| Error::Other(format!("store error: {e}")))?
            else {
                continue;
            };
            let (Some(sig_b58), Some(expires_at)) = (
                state.highest_voucher_signature.as_ref(),
                state.highest_voucher_expires_at,
            ) else {
                continue; // no voucher accepted yet
            };
            if state.cumulative == 0 {
                continue;
            }
            // An expired voucher can never settle on-chain; skip it so it can't
            // fail — and atomically abort — a transaction it shares with
            // still-valid channels.
            if expires_at <= now_unix() {
                continue;
            }
            let channel = Pubkey::from_str(&state.channel_id)
                .map_err(|e| Error::Other(format!("invalid channelId: {e}")))?;
            let signer = Pubkey::from_str(&state.authorized_signer)
                .map_err(|e| Error::Other(format!("invalid authorizedSigner: {e}")))?;
            let sig_bytes: [u8; 64] = bs58::decode(sig_b58)
                .into_vec()
                .map_err(|e| Error::Other(format!("invalid voucher signature: {e}")))?
                .try_into()
                .map_err(|_| Error::Other("voucher signature is not 64 bytes".into()))?;
            let ixs = pc::build_settle_instructions(
                &channel,
                &signer,
                &sig_bytes,
                state.cumulative,
                expires_at,
                &program_id,
            )?;
            pending.push(ChannelInstructions {
                channel_id: state.channel_id.clone(),
                instructions: ixs,
            });
        }

        // Shared, byte-bounded packing (same as the mpp settlement worker) —
        // groups channels into <=1232-byte legacy transactions.
        let mut signatures = Vec::new();
        for group in pack(pending, &self.operator, DEFAULT_MAX_CHANNELS_PER_TX) {
            let instructions: Vec<_> = group.into_iter().flat_map(|c| c.instructions).collect();
            let blockhash = self
                .rpc
                .get_latest_blockhash()
                .map_err(|e| Error::Rpc(format!("blockhash fetch failed: {e}")))?;
            let message =
                Message::new_with_blockhash(&instructions, Some(&self.operator), &blockhash);
            let mut tx = Transaction::new_unsigned(message);
            self.config
                .operator_signer
                .sign_transaction(&mut tx)
                .await
                .map_err(|e| Error::Other(format!("settle signing failed: {e}")))?;
            let sig = self
                .rpc
                .send_and_confirm_transaction(&tx)
                .map_err(|e| Error::Rpc(format!("settle broadcast failed: {e}")))?;
            signatures.push(sig.to_string());
        }
        Ok(signatures)
    }

    /// Sweep a channel's accrued pool (`settled − paidOut`) to payee / splits /
    /// treasury via the program's `distribute` instruction.
    pub async fn distribute(&self, channel_id: &str) -> Result<Option<String>, Error> {
        let state = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;
        let payer = Pubkey::from_str(
            state
                .operator
                .as_deref()
                .ok_or_else(|| Error::Other("channel payer unknown".into()))?,
        )
        .map_err(|e| Error::Other(format!("invalid payer: {e}")))?;
        let channel = Pubkey::from_str(&state.channel_id)
            .map_err(|e| Error::Other(format!("invalid channelId: {e}")))?;
        let payee = Pubkey::from_str(&self.config.recipient)
            .map_err(|e| Error::Other(format!("invalid recipient: {e}")))?;
        let ix = pc::build_distribute_instruction(
            &channel,
            &payer,
            // rentPayer is pinned to the operator (the fee payer).
            &self.operator,
            &payee,
            &pc::treasury_owner(),
            &self.mint()?,
            &self.distributions()?,
            &self.token_program()?,
            &self.program_id()?,
        );
        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .map_err(|e| Error::Rpc(format!("blockhash fetch failed: {e}")))?;
        let message = Message::new_with_blockhash(&[ix], Some(&self.operator), &blockhash);
        let mut tx = Transaction::new_unsigned(message);
        self.config
            .operator_signer
            .sign_transaction(&mut tx)
            .await
            .map_err(|e| Error::Other(format!("distribute signing failed: {e}")))?;
        let sig = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .map_err(|e| Error::Rpc(format!("distribute broadcast failed: {e}")))?;
        Ok(Some(sig.to_string()))
    }

    async fn settle_and_seal(&self, channel_id: &str) -> Result<String, Error> {
        let state = self
            .store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Other(format!("store error: {e}")))?
            .ok_or_else(|| Error::Other(format!("Channel {channel_id} not found")))?;
        let channel = Pubkey::from_str(&state.channel_id)
            .map_err(|e| Error::Other(format!("invalid channelId: {e}")))?;
        let signer = Pubkey::from_str(&state.authorized_signer)
            .map_err(|e| Error::Other(format!("invalid authorizedSigner: {e}")))?;

        // Settle the latest accepted voucher (if any) in the seal.
        let (sig_bytes, cumulative, expires_at) = match (
            state.highest_voucher_signature.as_ref(),
            state.highest_voucher_expires_at,
        ) {
            (Some(s), Some(exp)) if state.cumulative > 0 => {
                let arr: [u8; 64] = bs58::decode(s)
                    .into_vec()
                    .map_err(|e| Error::Other(format!("invalid voucher signature: {e}")))?
                    .try_into()
                    .map_err(|_| Error::Other("voucher signature is not 64 bytes".into()))?;
                (Some(arr), state.cumulative, exp)
            }
            _ => (None, 0, 0),
        };
        let instructions = pc::build_settle_and_seal_instructions(
            &self.operator,
            &channel,
            &signer,
            sig_bytes.as_ref(),
            cumulative,
            expires_at,
            &self.program_id()?,
        )?;
        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .map_err(|e| Error::Rpc(format!("blockhash fetch failed: {e}")))?;
        let message = Message::new_with_blockhash(&instructions, Some(&self.operator), &blockhash);
        let mut tx = Transaction::new_unsigned(message);
        self.config
            .operator_signer
            .sign_transaction(&mut tx)
            .await
            .map_err(|e| Error::Other(format!("settle_and_seal signing failed: {e}")))?;
        let sig = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .map_err(|e| Error::Rpc(format!("settle_and_seal broadcast failed: {e}")))?;
        Ok(sig.to_string())
    }

    fn fetch_channel(&self, channel_id: &Pubkey) -> Result<Channel, Error> {
        let data = self
            .rpc
            .get_account_data(channel_id)
            .map_err(|e| Error::Rpc(format!("channel account fetch failed: {e}")))?;
        Channel::from_bytes(&data).map_err(|e| Error::Other(format!("channel decode failed: {e}")))
    }

    /// Build a channel snapshot for a settlement response.
    ///
    /// `paid_out` is the amount the server has swept on-chain via `distribute`
    /// (`0` while the channel is open / un-swept). It is the server's own
    /// accounting, not a fresh read of the on-chain `paidOut`.
    async fn snapshot(
        &self,
        channel_id: &str,
        deposit: u64,
        paid_out: u64,
        status: &str,
    ) -> BatchChannelSnapshot {
        let cumulative = self
            .store
            .get_channel(channel_id)
            .await
            .ok()
            .flatten()
            .map(|s| s.cumulative)
            .unwrap_or(0);
        BatchChannelSnapshot {
            channel_id: channel_id.to_string(),
            deposit: deposit.to_string(),
            settled: cumulative.to_string(),
            paid_out: paid_out.to_string(),
            status: status.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::client::batch_settlement::sign_voucher;
    use ed25519_dalek::SigningKey;
    use solana_keychain::memory::MemorySigner;

    const FAR_FUTURE: i64 = 4_102_444_800; // 2100-01-01

    fn memory_signer(seed: u8) -> MemorySigner {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        MemorySigner::from_bytes(&sk.to_keypair_bytes()).unwrap()
    }

    fn handler(store: Arc<MemoryChannelStore>) -> X402BatchSettlement {
        let config = BatchConfig::new(
            "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            "devnet",
            Arc::new(memory_signer(1)),
        );
        X402BatchSettlement::with_store(config, store).unwrap()
    }

    #[test]
    fn nonlocalnet_constructor_requires_explicit_channel_store() {
        if std::env::var("PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE").as_deref() == Ok("1") {
            return;
        }
        let config = BatchConfig::new(
            "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            "devnet",
            Arc::new(memory_signer(1)),
        );
        assert!(X402BatchSettlement::new(config).is_err());
    }

    fn seeded_state(channel_id: &str, authorized_signer: &str, cumulative: u64) -> ChannelState {
        ChannelState {
            channel_id: channel_id.to_string(),
            authorized_signer: authorized_signer.to_string(),
            deposit: 1_000_000,
            cumulative,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            open_slot: None,
            salt: None,
            open_signature: None,
            operator: None,
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
        }
    }

    #[tokio::test]
    async fn retried_open_does_not_reset_existing_cumulative() {
        let owner = memory_signer(3);
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);
        let signer = pc::pubkey_string(&owner.pubkey());
        let store = Arc::new(MemoryChannelStore::new());
        let mut existing = seeded_state(&channel_b58, &signer, 700);
        existing.open_slot = Some(42);
        existing.operator = Some("payer".to_string());
        existing.highest_voucher_signature = Some("already-accepted".to_string());
        store
            .put_channel(&channel_b58, existing.clone())
            .await
            .unwrap();

        let mut replayed_open = existing.clone();
        replayed_open.cumulative = 0;
        replayed_open.highest_voucher_signature = None;
        let created = handler(store.clone())
            .create_channel_if_absent(&channel_b58, replayed_open)
            .await
            .unwrap();

        assert!(!created, "the repeated open must be an idempotent no-op");
        let after = store.get_channel(&channel_b58).await.unwrap().unwrap();
        assert_eq!(after.cumulative, existing.cumulative);
        assert_eq!(
            after.highest_voucher_signature, existing.highest_voucher_signature,
            "an open replay must preserve cumulative and voucher replay state"
        );
    }

    // A steady-state voucher whose delta is below the advertised price must be
    // rejected — and must not advance the watermark.
    #[tokio::test]
    async fn underpriced_voucher_is_rejected_without_advancing() {
        let owner = memory_signer(4);
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);

        let store = Arc::new(MemoryChannelStore::new());
        store
            .put_channel(
                &channel_b58,
                seeded_state(&channel_b58, &pc::pubkey_string(&owner.pubkey()), 0),
            )
            .await
            .unwrap();

        // Route priced at 100; voucher only advances by 1.
        let voucher = sign_voucher(&owner, &channel, 1, FAR_FUTURE).await.unwrap();
        let result = handler(store.clone())
            .process_voucher(&channel_b58, voucher, 100)
            .await;
        assert!(result.is_err());
        assert_eq!(
            store
                .get_channel(&channel_b58)
                .await
                .unwrap()
                .unwrap()
                .cumulative,
            0,
            "watermark must not advance for a rejected voucher"
        );
    }

    // Replaying the latest voucher (delta 0) must not grant another free serve.
    #[tokio::test]
    async fn replayed_voucher_is_rejected() {
        let owner = memory_signer(5);
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);

        let store = Arc::new(MemoryChannelStore::new());
        // Watermark already at 100 (a prior voucher was accepted).
        store
            .put_channel(
                &channel_b58,
                seeded_state(&channel_b58, &pc::pubkey_string(&owner.pubkey()), 100),
            )
            .await
            .unwrap();

        let replay = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
            .await
            .unwrap();
        let result = handler(store)
            .process_voucher(&channel_b58, replay, 100)
            .await;
        assert!(result.is_err());
    }

    // Even for a free route (per_request == 0) — where the price check cannot
    // reject a delta-0 replay — an exact idempotent replay of the latest voucher
    // must NOT be treated as a fresh paid serve (`serve == false`, charged 0).
    #[tokio::test]
    async fn idempotent_replay_is_accepted_but_not_served() {
        let owner = memory_signer(6);
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);

        let store = Arc::new(MemoryChannelStore::new());
        store
            .put_channel(
                &channel_b58,
                seeded_state(&channel_b58, &pc::pubkey_string(&owner.pubkey()), 0),
            )
            .await
            .unwrap();
        let h = handler(store.clone());

        // First voucher: a fresh charge on a free route → served.
        let v1 = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
            .await
            .unwrap();
        let first = h
            .process_voucher(&channel_b58, v1.clone(), 0)
            .await
            .unwrap();
        assert!(first.serve, "fresh charge must be served");
        assert_eq!(first.response.charged_amount.as_deref(), Some("100"));

        // Exact replay (same cumulative + same signature): accepted as a no-op
        // but not served, and it must not charge again or advance the watermark.
        let replay = h.process_voucher(&channel_b58, v1, 0).await.unwrap();
        assert!(!replay.serve, "idempotent replay must not be a fresh serve");
        assert_eq!(replay.response.charged_amount.as_deref(), Some("0"));
        assert_eq!(
            store
                .get_channel(&channel_b58)
                .await
                .unwrap()
                .unwrap()
                .cumulative,
            100,
            "replay must not advance the watermark"
        );
    }

    // ── Concurrency: the paid serve must be gated on the in-lock committed delta ─
    //
    // Two vouchers on one channel (cumulative 100 and 150, priced at 100, from a
    // zero watermark) commit a combined delta of 150 — one-and-a-half requests'
    // worth. Only one may be served. The bug: `process_voucher` decided `serve`
    // from a watermark read *before* the commit, so both vouchers read the same
    // stale `0`, both computed a `>= price` delta, and both were served while only
    // 150 total was committed — the second request was served for 50.

    // Deterministic regression guard that genuinely gates the per-channel lock.
    //
    // The seam parks voucher B (cumulative 150) *inside* the gate — after B has
    // read the prior watermark (0) but before it accepts — so B holds the gate
    // while parked. Voucher A (cumulative 100) then races on the same channel:
    //
    //   * With the gate: A blocks acquiring it. When B is released, B accepts
    //     from prev 0 (150 >= price 100) and is served, then A acquires the gate,
    //     reads the in-lock prior watermark of 150, and its increment (100 - 150
    //     saturates to 0 < 100) is refused — exactly one request served.
    //   * Without the gate lock: A does not block. It reads the same stale
    //     watermark of 0, commits 100, and is served *concurrently* with B, which
    //     also read 0 and commits 150 — two requests served for a combined 150.
    //
    // So deleting `let _held = gate.lock().lock().await` flips the served count
    // from 1 to 2 and fails this test. `A` is given a bounded head start to reach
    // (and, with the fix, block on) the gate before B is released; with the fix
    // no sleep can unblock A, and without it A completes its in-memory accept in
    // microseconds, so the outcome is deterministic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_voucher_not_served_when_gate_serializes_accept() {
        let owner = memory_signer(7);
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);

        let store = Arc::new(MemoryChannelStore::new());
        store
            .put_channel(
                &channel_b58,
                seeded_state(&channel_b58, &pc::pubkey_string(&owner.pubkey()), 0),
            )
            .await
            .unwrap();
        let h = handler(store.clone());

        // Arm the in-lock seam: the voucher that takes it has already read the
        // prior watermark and holds the gate; it signals `entered`, then parks on
        // `release` until the test drops its guard.
        let release = Arc::new(AsyncMutex::new(()));
        let release_guard = release.clone().lock_owned().await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        *h.post_read_hook.lock().unwrap() = Some(PreGateHook {
            entered: entered_tx,
            release: release.clone(),
        });

        // Spawn B (cumulative 150). It acquires the gate, reads prev 0, consumes
        // the seam, and parks — holding the gate.
        let voucher_b = sign_voucher(&owner, &channel, 150, FAR_FUTURE)
            .await
            .unwrap();
        let hb = h.clone();
        let cb = channel_b58.clone();
        let task_b = tokio::spawn(async move { hb.process_voucher(&cb, voucher_b, 100).await });

        // Wait until B has reached the seam (so B, not A, holds it). Now A cannot
        // consume the seam and runs straight through to commit cumulative 100.
        entered_rx.await.unwrap();

        // Spawn A (cumulative 100). With the gate it blocks on acquisition; the
        // bounded sleep gives it time to either commit (no gate) or park on the
        // lock (fix).
        let voucher_a = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
            .await
            .unwrap();
        let (ha, ca) = (h.clone(), channel_b58.clone());
        let task_a = tokio::spawn(async move { ha.process_voucher(&ca, voucher_a, 100).await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Release B and join both.
        drop(release_guard);
        let outcome_b = task_b.await.unwrap();
        let outcome_a = task_a.await.unwrap();

        // Count paid serves. With the gate this is exactly 1; deleting the gate
        // lock lets both A and B decide `serve` off the stale watermark of 0.
        let served = [outcome_a, outcome_b]
            .into_iter()
            .flatten()
            .filter(|o| o.serve)
            .count();
        assert_eq!(
            served, 1,
            "the per-channel gate must serialize accept so only one request is served"
        );

        // The channel advanced to 150 (B's cumulative), never past it.
        assert_eq!(
            store
                .get_channel(&channel_b58)
                .await
                .unwrap()
                .unwrap()
                .cumulative,
            150,
            "the watermark must be the larger cumulative, committed exactly once"
        );
    }

    // Stochastic guard: race two concurrent vouchers (cumulative 100 and 150,
    // priced at 100) from a zero watermark, many times, over a multi-thread
    // runtime. Whatever the scheduling, at most one may be served, and any served
    // voucher must have committed a delta of at least the price. This catches a
    // regression that the deterministic seam's fixed ordering would miss.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_vouchers_serve_at_most_one_paid_request() {
        for iter in 0..64u8 {
            let owner = memory_signer(8);
            let channel = Pubkey::new_unique();
            let channel_b58 = pc::pubkey_string(&channel);

            let store = Arc::new(MemoryChannelStore::new());
            store
                .put_channel(
                    &channel_b58,
                    seeded_state(&channel_b58, &pc::pubkey_string(&owner.pubkey()), 0),
                )
                .await
                .unwrap();
            // Independent handlers model separate replicas: their local gate
            // maps are distinct, so only the shared store transaction can keep
            // both vouchers from serving against the same committed delta.
            let h1 = handler(store.clone());
            let h2 = handler(store.clone());

            let v100 = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
                .await
                .unwrap();
            let v150 = sign_voucher(&owner, &channel, 150, FAR_FUTURE)
                .await
                .unwrap();

            let (c1, c2) = (channel_b58.clone(), channel_b58.clone());
            let t1 = tokio::spawn(async move { h1.process_voucher(&c1, v100, 100).await });
            let t2 = tokio::spawn(async move { h2.process_voucher(&c2, v150, 100).await });
            let (r1, r2) = (t1.await.unwrap(), t2.await.unwrap());

            // Count served requests; every served request must have committed at
            // least the price. A served request reports its committed delta as
            // `charged_amount`.
            let mut served = 0;
            for outcome in [r1, r2].into_iter().flatten() {
                if outcome.serve {
                    served += 1;
                    let charged: u64 = outcome
                        .response
                        .charged_amount
                        .as_deref()
                        .unwrap_or("0")
                        .parse()
                        .unwrap();
                    assert!(
                        charged >= 100,
                        "iter {iter}: a served voucher committed only {charged} (< price 100)"
                    );
                }
            }
            assert!(
                served <= 1,
                "iter {iter}: {served} requests served for a combined 150 committed (price 100)"
            );
        }
    }

    // ── Gate-map eviction: unauthenticated vouchers must not leak gate entries ─
    //
    // `process_voucher` acquires the per-channel gate before it can learn the
    // channel does not exist. A client posting vouchers with random, nonexistent
    // channel ids must not grow the gate map: each gate entry is refcounted and
    // evicted once the request that created it drops its guard, so the map
    // returns to empty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn voucher_gate_map_evicts_entries_for_nonexistent_channels() {
        let owner = memory_signer(41);
        let store = Arc::new(MemoryChannelStore::new());
        let h = handler(store);

        // Post vouchers against many distinct channel ids that were never opened.
        for _ in 0..32u32 {
            let channel = Pubkey::new_unique();
            let channel_b58 = pc::pubkey_string(&channel);
            let voucher = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
                .await
                .unwrap();
            // The channel does not exist in the store, so `prev` reads 0 and the
            // accept fails (or the serve is a no-op); either way the request
            // returns and its gate guard is dropped.
            let _ = h.process_voucher(&channel_b58, voucher, 100).await;
        }

        // Every gate entry must have been evicted once its request finished: the
        // grow-only map (pre-fix) would hold 32 entries here.
        let remaining = h
            .voucher_gates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        assert_eq!(
            remaining, 0,
            "gate entries for nonexistent channels must be evicted, found {remaining}"
        );
    }

    // A contended gate entry is evicted once the last holder releases it: two
    // vouchers race on one channel, and after both finish the map is empty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn voucher_gate_map_evicts_contended_entry_after_last_release() {
        let owner = memory_signer(42);
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);

        let store = Arc::new(MemoryChannelStore::new());
        store
            .put_channel(
                &channel_b58,
                seeded_state(&channel_b58, &pc::pubkey_string(&owner.pubkey()), 0),
            )
            .await
            .unwrap();
        let h = handler(store);

        let v100 = sign_voucher(&owner, &channel, 100, FAR_FUTURE)
            .await
            .unwrap();
        let v150 = sign_voucher(&owner, &channel, 150, FAR_FUTURE)
            .await
            .unwrap();
        let (h1, c1) = (h.clone(), channel_b58.clone());
        let (h2, c2) = (h.clone(), channel_b58.clone());
        let t1 = tokio::spawn(async move { h1.process_voucher(&c1, v100, 100).await });
        let t2 = tokio::spawn(async move { h2.process_voucher(&c2, v150, 100).await });
        let _ = t1.await.unwrap();
        let _ = t2.await.unwrap();

        let remaining = h
            .voucher_gates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        assert_eq!(
            remaining, 0,
            "a contended gate entry must be evicted once its last holder releases, found {remaining}"
        );
    }

    // ── Header cap: an oversized PAYMENT-SIGNATURE header is rejected up front ─
    //
    // A batch-settlement header additionally embeds a full base64 transaction, so
    // an unbounded header drives proportionally large base64 + JSON work. Cap it
    // at 16 KiB before any decode, matching the `exact` / `upto` parsers.
    #[test]
    fn parse_payment_rejects_oversized_header() {
        let h = handler(Arc::new(MemoryChannelStore::new()));
        // 16 KiB + 1 byte: one over the cap.
        let header = "A".repeat(16 * 1024 + 1);
        assert_eq!(header.len(), 16 * 1024 + 1);
        let err = h
            .parse_payment(&header)
            .expect_err("oversized header must be rejected");
        assert!(
            err.to_string().contains("exceeds maximum length"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_payment_accepts_at_max_header_size() {
        // A header of exactly 16 KiB must pass the size gate. Its contents are
        // not valid base64 JSON, so it still fails — but with a decode/parse
        // error, NOT the size error. This pins the boundary at exactly the cap.
        let h = handler(Arc::new(MemoryChannelStore::new()));
        let at_max = "A".repeat(16 * 1024);
        assert_eq!(at_max.len(), 16 * 1024);
        let err = h
            .parse_payment(&at_max)
            .expect_err("invalid payload still errors");
        assert!(
            !err.to_string().contains("exceeds maximum length"),
            "size gate must not fire at exactly the cap: {err}"
        );
    }

    // A refund with no voucher carries no proof of ownership and must be
    // rejected before any on-chain work (no RPC is reachable in this test).
    #[tokio::test]
    async fn refund_without_voucher_is_rejected() {
        let store = Arc::new(MemoryChannelStore::new());
        let result = handler(store).process_refund("Chan1", None).await;
        assert!(result.is_err());
    }

    // A refund whose voucher is signed by a key other than the channel's
    // authorized signer must be rejected, and must not freeze the channel.
    #[tokio::test]
    async fn refund_with_unauthorized_signer_is_rejected() {
        let owner = memory_signer(2);
        let attacker = memory_signer(3);
        let channel = Pubkey::new_unique();
        let channel_b58 = pc::pubkey_string(&channel);

        let store = Arc::new(MemoryChannelStore::new());
        store
            .put_channel(
                &channel_b58,
                seeded_state(&channel_b58, &pc::pubkey_string(&owner.pubkey()), 0),
            )
            .await
            .unwrap();

        let forged = sign_voucher(&attacker, &channel, 100, FAR_FUTURE)
            .await
            .unwrap();
        let result = handler(store.clone())
            .process_refund(&channel_b58, Some(forged))
            .await;
        assert!(result.is_err());

        // The rejected attempt left the channel open.
        let state = store.get_channel(&channel_b58).await.unwrap().unwrap();
        assert!(state.close_requested_at.is_none());
        assert!(!state.sealed);
    }
}
