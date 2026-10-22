//! Pure StandardAsset `transfer` preparation and review (no network, no
//! signing) for the publication-only local custody slice.
//!
//! [`AssetTransferTrust`] binds one locally pinned [`CustodyConfig`] to one
//! independently [`VerifiedGenesisRoot`]: every protocol-context field, the
//! one publisher identity ever signed for, and the exact in-tree genesis
//! Standard Asset code/instance/policy are fixed once at construction, never
//! renegotiated from a caller. `VerifiedGenesisRoot` authenticates the outer
//! genesis-authority signature over the whole manifest, but never
//! independently authenticates the nested publication submission; this
//! module performs that authentication itself before trusting the embedded
//! code artifact. [`AssetTransferTrust::prepare`] then takes two bounded,
//! caller-supplied canonical `Object` preimages (never a peer-reported
//! digest or amount) and builds one [`PreparedPaidExecution`] transferring
//! the whole coin, plus a bounded human-readable review of every signed
//! field.

use protocol_types::HashPurpose;

use sunrise_edge_client::call::CallIntent;
use sunrise_edge_client::local_execution::generic_object_result_semantics;
use sunrise_edge_client::package_types::{ScopedTypeArg, ScopedTypeTag, verify_scoped_type_id};
use sunrise_edge_client::publication::{
    AuthenticatedPublicationCandidate, artifact_commitment, authenticate_publication_submission,
};
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Address, Amount, ArtifactParts, CodeArtifact,
    Digest32, Epoch, ExpectedProtocolContext, FeeSourceConsent, HashSuiteResolver,
    MAX_AUTHENTICATED_OBJECT_BODY_BYTES, Object, ObjectId, ObjectRef, Owner, PackageOrigin,
    PaidApplication, PaidFeePolicy, PreparedPaidExecution, PublicationContext,
    PublicationSubmission, RequestId, ReservationAccessKind, UnverifiedDependencyRef,
    VerifiedGenesisRoot, decode_object, encode_object,
};

use public_standard_asset::{
    ASSET_OPAQUE_DOMAIN, REQUIRED_WASM_PROFILE, SCHEMA_VERSION, asset_type_argument, build_package,
    coin_amount, coin_type_tag, transfer_arguments,
};

use crate::error::CliError;
use crate::hex::encode_hex;

use super::config::CustodyConfig;

/// One bounded full canonical `Object` preimage's maximum accepted size:
/// the same per-object body/overhead allowance one genesis object entry is
/// bounded to (see `node_core::genesis::MAX_GENESIS_MANIFEST_BYTES`'s
/// `MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 4096` term), reused here rather
/// than inventing a fresh ceiling for the same kind of preimage.
const MAX_TRANSFER_OBJECT_BYTES: usize = MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 4096;

/// Maximum bytes of the rendered, bounded, display-only review.
const MAX_TRANSFER_REVIEW_BYTES: usize = 64 * 1024;

const TRANSFER_ENTRYPOINT: &str = "transfer";

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// One caller-supplied whole-coin transfer request: two bounded canonical
/// `Object` preimages (never a queried digest or amount), the recipient,
/// signed replay fields and the fee ceiling. `coin_bytes` is consumed
/// entirely; this profile never splits or mutates an amount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AssetTransferRequest {
    pub(super) coin_bytes: Vec<u8>,
    pub(super) fee_bytes: Vec<u8>,
    pub(super) recipient: [u8; 32],
    pub(super) nonce: u64,
    pub(super) request_id: RequestId,
    pub(super) max_fee: u64,
    pub(super) gas_limit: u64,
}

/// One immutable prepared whole-coin transfer plus its bounded review.
pub(super) struct PreparedAssetTransfer {
    pub(super) prepared: PreparedPaidExecution,
    pub(super) review: String,
    pub(super) amount: u64,
    pub(super) fee_balance: u64,
}

/// Immutable locally pinned configuration plus verified genesis-derived
/// Standard Asset policy. Every field below is fixed once by [`Self::new`];
/// no caller input can replace the resolver, context, publisher, code,
/// instance, or policy afterward.
pub(super) struct AssetTransferTrust {
    resolver: HashSuiteResolver,
    expected: ExpectedProtocolContext,
    context: PublicationContext,
    publisher: Address,
    genesis_digest: Digest32,
    fee_policy: PaidFeePolicy,
    origin: PackageOrigin,
    asset: ObjectId,
    coin_tag: ScopedTypeTag,
}

impl AssetTransferTrust {
    /// Binds `config` to `root`. Fails closed if the config's chain,
    /// protocol version or epoch differs from the verified genesis root, if
    /// the genesis fee policy is not the Standard Asset profile, or if the
    /// genesis publication's embedded code artifact is not exactly the
    /// in-tree `public_standard_asset::build_package` output for its own
    /// origin under the generic-object-result profile.
    pub(super) fn new(config: CustodyConfig, root: VerifiedGenesisRoot) -> Result<Self, CliError> {
        let expected: ExpectedProtocolContext = config.expected_context()?;
        let context: PublicationContext = PublicationContext::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
        )
        .map_err(failure)?;
        if &context != root.genesis_context() {
            return Err(invalid(
                "custody config chain id, protocol version or epoch does not match the verified genesis root",
            ));
        }
        let resolver: HashSuiteResolver = root.genesis_resolver().clone();
        if resolver.chain_id() != expected.chain_id()
            || resolver.protocol_version() != expected.protocol_version()
        {
            return Err(invalid(
                "genesis resolver chain id or protocol version does not match the custody config",
            ));
        }

        let fee_policy: PaidFeePolicy = root.manifest().fee_policy.clone();
        let publication: PublicationSubmission = root.manifest().publication.clone();
        if fee_policy.context != context {
            return Err(invalid(
                "genesis fee policy context does not match the expected context",
            ));
        }
        if fee_policy.schema != SCHEMA_VERSION {
            return Err(invalid(
                "genesis fee policy is not the Standard Asset schema version",
            ));
        }
        let asset: ObjectId = match fee_policy.type_arguments.as_slice() {
            [ScopedTypeArg::Opaque { domain, value }] if *domain == ASSET_OPAQUE_DOMAIN => {
                ObjectId::new(*value)
            }
            _ => {
                return Err(invalid(
                    "genesis fee policy is not the Standard Asset profile",
                ));
            }
        };
        let origin: PackageOrigin = fee_policy.code.origin().clone();
        let coin_tag: ScopedTypeTag = coin_type_tag(&origin, &asset).map_err(failure)?;
        if fee_policy.asset_type != coin_tag {
            return Err(invalid(
                "genesis fee policy Standard Asset identity mismatch",
            ));
        }

        let semantics: Digest32 = generic_object_result_semantics(&resolver, &context)
            .map_err(failure)?;
        let candidate: AuthenticatedPublicationCandidate = authenticate_publication_submission(
            &resolver,
            &context,
            &semantics,
            publication,
        )
        .map_err(failure)?;

        let package: public_standard_asset::StandardAssetPackage =
            build_package(&origin).map_err(failure)?;
        let rebuilt_artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
            context: context.clone(),
            origin: origin.clone(),
            revision: 1,
            wasm_profile: REQUIRED_WASM_PROFILE,
            semantics,
            wasm: package.wasm,
            unverified_abi: package.encoded_abi,
            exports: package.exports,
            unverified_dependencies: Vec::new(),
        })
        .map_err(failure)?;
        if &rebuilt_artifact != candidate.artifact() {
            return Err(invalid(
                "genesis publication artifact is not the in-tree public Standard Asset package",
            ));
        }
        let artifact_digest: Digest32 =
            artifact_commitment(&resolver, &context, &rebuilt_artifact).map_err(failure)?;
        if artifact_digest != *candidate.digest() {
            return Err(invalid(
                "recomputed artifact commitment does not match the authenticated genesis publication",
            ));
        }
        let expected_code: UnverifiedDependencyRef =
            UnverifiedDependencyRef::new(origin.clone(), 1, context.clone(), artifact_digest)
                .map_err(failure)?;
        if fee_policy.code != expected_code {
            return Err(invalid(
                "genesis fee policy code reference does not match the rebuilt genesis artifact",
            ));
        }

        let genesis_digest: Digest32 = root.digest();
        Ok(Self {
            resolver,
            expected,
            context,
            publisher: config.publisher(),
            genesis_digest,
            fee_policy,
            origin,
            asset,
            coin_tag,
        })
    }

    fn decode_bounded_object(
        &self,
        bytes: &[u8],
        size_message: &'static str,
        canonical_message: &'static str,
    ) -> Result<Object, CliError> {
        if bytes.len() > MAX_TRANSFER_OBJECT_BYTES {
            return Err(invalid(size_message));
        }
        let object: Object = decode_object(bytes).map_err(failure)?;
        if encode_object(&object).map_err(failure)? != bytes {
            return Err(invalid(canonical_message));
        }
        Ok(object)
    }

    fn validate_owned_coin(
        &self,
        object: &Object,
        owner_message: &'static str,
        schema_message: &'static str,
        type_message: &'static str,
    ) -> Result<(), CliError> {
        if object.owner != Owner::Address(self.publisher) {
            return Err(invalid(owner_message));
        }
        if object.schema_version != SCHEMA_VERSION {
            return Err(invalid(schema_message));
        }
        let matches: bool = verify_scoped_type_id(
            &self.resolver,
            &object.type_hash,
            self.expected.epoch(),
            &self.coin_tag,
        )
        .map_err(failure)?;
        if !matches {
            return Err(invalid(type_message));
        }
        Ok(())
    }

    /// Prepares one whole-coin `transfer` paid Call. Never mutates, splits
    /// or peeks any amount beyond what `coin_bytes`/`fee_bytes` themselves
    /// canonically decode to, and never trusts a peer-reported digest: the
    /// `ObjectRef` digest is always recomputed locally from the exact
    /// preimage bytes under this trust's own pinned resolver and epoch.
    pub(super) fn prepare(
        &self,
        request: &AssetTransferRequest,
    ) -> Result<PreparedAssetTransfer, CliError> {
        let coin_object: Object = self.decode_bounded_object(
            &request.coin_bytes,
            "transfer coin preimage exceeds the maximum accepted size",
            "transfer coin preimage is not the exact canonical object encoding",
        )?;
        let fee_object: Object = self.decode_bounded_object(
            &request.fee_bytes,
            "fee source preimage exceeds the maximum accepted size",
            "fee source preimage is not the exact canonical object encoding",
        )?;
        self.validate_owned_coin(
            &coin_object,
            "transfer coin is not owned by the pinned custody publisher",
            "transfer coin schema does not match the genesis Standard Asset schema",
            "transfer coin is not the genesis Standard Asset Coin type",
        )?;
        self.validate_owned_coin(
            &fee_object,
            "fee source is not owned by the pinned custody publisher",
            "fee source schema does not match the genesis Standard Asset schema",
            "fee source is not the genesis Standard Asset Coin type",
        )?;
        if coin_object.id == fee_object.id {
            return Err(invalid(
                "transfer coin and fee source must be distinct objects",
            ));
        }
        if request.recipient == *self.publisher.as_bytes() {
            return Err(invalid(
                "transfer recipient must differ from the pinned custody publisher",
            ));
        }
        if request.gas_limit == 0 {
            return Err(invalid("gas limit must be positive"));
        }
        if request.max_fee == 0 {
            return Err(invalid("max fee must be positive"));
        }

        let amount: u64 = coin_amount(&coin_object.data).map_err(failure)?;
        let fee_balance: u64 = coin_amount(&fee_object.data).map_err(failure)?;
        if request.max_fee >= fee_balance {
            return Err(invalid(
                "max fee must be strictly less than the fee source balance",
            ));
        }

        let epoch: Epoch = self.expected.epoch();
        let coin_digest: Digest32 = self
            .resolver
            .hash_for_purpose(epoch, HashPurpose::Object, &request.coin_bytes)
            .map_err(failure)?;
        let fee_digest: Digest32 = self
            .resolver
            .hash_for_purpose(epoch, HashPurpose::Object, &request.fee_bytes)
            .map_err(failure)?;
        let coin_ref: ObjectRef = ObjectRef {
            id: coin_object.id,
            version: coin_object.version,
            digest: coin_digest,
        };
        let fee_ref: ObjectRef = ObjectRef {
            id: fee_object.id,
            version: fee_object.version,
            digest: fee_digest,
        };

        let consent: FeeSourceConsent = FeeSourceConsent {
            source: fee_ref.clone(),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(request.max_fee),
            refund_recipient: *self.publisher.as_bytes(),
        };
        let mut access: AccessManifest = AccessManifest::new();
        access.entries.push(AccessEntry {
            object_ref: coin_ref.clone(),
            mode: AccessMode::Write,
        });
        let call: CallIntent = CallIntent {
            context: self.context.clone(),
            request_id: *request.request_id.as_bytes(),
            sender: *self.publisher.as_bytes(),
            nonce: request.nonce,
            code: self.fee_policy.code.clone(),
            instance: self.fee_policy.instance.clone(),
            entrypoint: TRANSFER_ENTRYPOINT.to_owned(),
            type_arguments: vec![asset_type_argument(&self.asset)],
            access,
            arguments: transfer_arguments(&request.recipient).map_err(failure)?,
            gas_limit: request.gas_limit,
        };
        let prepared: PreparedPaidExecution = PreparedPaidExecution::prepare(
            self.publisher,
            &self.resolver,
            &self.expected,
            &self.fee_policy,
            consent,
            PaidApplication::Call(call),
            request.request_id,
            request.nonce,
            request.gas_limit,
            Vec::new(),
        )?;

        let review: String =
            self.render_review(request, &coin_ref, amount, &fee_ref, fee_balance, &prepared)?;
        Ok(PreparedAssetTransfer {
            prepared,
            review,
            amount,
            fee_balance,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn render_review(
        &self,
        request: &AssetTransferRequest,
        coin_ref: &ObjectRef,
        amount: u64,
        fee_ref: &ObjectRef,
        fee_balance: u64,
        prepared: &PreparedPaidExecution,
    ) -> Result<String, CliError> {
        let mut out: String = String::new();
        out.push_str(&format!(
            "chain_id={}\n",
            safe_ascii(self.expected.chain_id().as_str())
        ));
        out.push_str(&format!(
            "protocol_version={}\n",
            self.expected.protocol_version().get()
        ));
        out.push_str(&format!("epoch={}\n", self.expected.epoch().get()));
        out.push_str(&format!("domain={}\n", self.expected.domain()));
        out.push_str(&format!("genesis_digest={}\n", self.genesis_digest));
        out.push_str(&format!(
            "code_origin_publisher={}\n",
            encode_hex(self.origin.publisher())
        ));
        out.push_str(&format!(
            "code_origin_seed={}\n",
            encode_hex(self.origin.seed())
        ));
        out.push_str(&format!(
            "code_revision={}\n",
            self.fee_policy.code.revision()
        ));
        out.push_str(&format!(
            "code_artifact_digest={}\n",
            self.fee_policy.code.artifact_digest()
        ));
        out.push_str(&format!("asset={}\n", self.asset));
        out.push_str(&format!("schema={SCHEMA_VERSION}\n"));
        out.push_str(&format!(
            "instance_creator={}\n",
            encode_hex(&self.fee_policy.instance.creator)
        ));
        out.push_str(&format!(
            "instance_seed={}\n",
            encode_hex(&self.fee_policy.instance.seed)
        ));
        out.push_str(&format!(
            "instance_revision={}\n",
            self.fee_policy.instance.revision
        ));
        out.push_str(&format!(
            "instance_record_digest={}\n",
            self.fee_policy.instance.record_digest
        ));
        out.push_str(&format!(
            "coin_id={} coin_version={} coin_digest={}\n",
            coin_ref.id, coin_ref.version, coin_ref.digest
        ));
        out.push_str(&format!("amount={amount}\n"));
        out.push_str("transfer=whole-coin-unchanged\n");
        out.push_str(&format!(
            "recipient={}\n",
            encode_hex(&request.recipient)
        ));
        out.push_str(&format!(
            "fee_source_id={} fee_source_version={} fee_source_digest={}\n",
            fee_ref.id, fee_ref.version, fee_ref.digest
        ));
        out.push_str(&format!("fee_balance={fee_balance}\n"));
        out.push_str(&format!("max_fee={}\n", request.max_fee));
        out.push_str(&format!("refund_recipient={}\n", self.publisher));
        out.push_str(&format!(
            "reserve_entrypoint={}\n",
            safe_ascii(&self.fee_policy.reserve_entrypoint)
        ));
        out.push_str(&format!(
            "settle_entrypoint={}\n",
            safe_ascii(&self.fee_policy.settle_entrypoint)
        ));
        out.push_str(&format!(
            "fee_recipient={}\n",
            encode_hex(&self.fee_policy.fee_recipient)
        ));
        out.push_str(&format!(
            "base_policy_digest={}\n",
            self.fee_policy.base_policy_digest
        ));
        out.push_str(&format!(
            "conversion_divisor={}\n",
            self.fee_policy.conversion_divisor
        ));
        out.push_str(&format!(
            "reserve_allowance={}\n",
            self.fee_policy.reserve_allowance
        ));
        out.push_str(&format!(
            "settle_allowance={}\n",
            self.fee_policy.settle_allowance
        ));
        out.push_str(&format!("gas_limit={}\n", request.gas_limit));
        out.push_str(&format!("nonce={}\n", request.nonce));
        out.push_str(&format!("request_id={}\n", request.request_id));
        out.push_str("freshness=enforced-at-execution-not-preparation\n");
        out.push_str(&format!(
            "signing_frame={}\n",
            encode_hex(prepared.signable_frame())
        ));
        if out.len() > MAX_TRANSFER_REVIEW_BYTES {
            return Err(invalid(
                "asset transfer review exceeds the maximum accepted display size",
            ));
        }
        Ok(out)
    }
}

/// Renders `value` as ASCII, hex-escaping every byte that is not a plain
/// printable ASCII character or space. `value` is already bounded local
/// configuration (the pinned chain id, or a fixed package entrypoint name),
/// never an untrusted peer response; this still never passes a raw
/// non-printable or control byte through to the rendered review.
fn safe_ascii(value: &str) -> String {
    let mut out: String = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_graphic() || *byte == b' ' {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("\\x{byte:02x}"));
        }
    }
    out
}
