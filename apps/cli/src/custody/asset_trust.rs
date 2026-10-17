//! Shared pinned genesis/code/instance/fee-policy trust for every Standard
//! Asset custody family (DR-0246 transfer; DR-0249 split/merge; DR-0253
//! mint/burn).
//!
//! [`PinnedAssetTrust::new`] binds one locally pinned [`CustodyConfig`] to
//! one independently [`VerifiedGenesisRoot`]: every protocol-context field,
//! the one publisher identity ever signed for, and the exact in-tree genesis
//! Standard Asset code/instance/policy are fixed once here, never
//! renegotiated from a caller. Each family's own trust module (`asset_transfer`,
//! `asset_split_merge`, `asset_mint_burn`) wraps one `PinnedAssetTrust` and
//! adds only its own per-entrypoint argument/amount/overflow checks and
//! `CallIntent` shape; the genesis chain is verified exactly once, in
//! exactly one place, for every family. The genesis `TreasuryCap` nominal
//! type is derived from the same verified origin/asset as `coin_tag`.
//! Mint/burn now uses the shared explicit-tag
//! validator for both its default and optional locally pinned application.

use sunrise_edge_client::local_execution::generic_object_result_semantics;
use sunrise_edge_client::package_types::{ScopedTypeArg, ScopedTypeTag, verify_scoped_type_id};
use sunrise_edge_client::publication::{
    AuthenticatedPublicationCandidate, artifact_commitment, authenticate_publication_submission,
};
use sunrise_edge_client::{
    Address, ArtifactParts, CodeArtifact, Digest32, ExpectedProtocolContext, HashSuiteResolver,
    MAX_AUTHENTICATED_OBJECT_BODY_BYTES, Object, ObjectId, Owner, PackageOrigin, PaidFeePolicy,
    PublicationContext, PublicationSubmission, UnverifiedDependencyRef, VerifiedGenesisRoot,
    decode_object, encode_object,
};

use public_standard_asset::{
    ASSET_OPAQUE_DOMAIN, REQUIRED_WASM_PROFILE, SCHEMA_VERSION, build_package, coin_type_tag,
    treasury_cap_type_tag,
};

use crate::error::CliError;

use super::config::CustodyConfig;

/// The node's existing authenticated inline-object bound, shared by every
/// family's request codec and private preimage reader.
pub(super) const MAX_ASSET_OBJECT_BYTES: usize = MAX_AUTHENTICATED_OBJECT_BODY_BYTES;

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// Immutable locally pinned configuration plus verified genesis-derived
/// Standard Asset policy, shared by every custody family's own trust module.
/// Every field below is fixed once by [`Self::new`]; no caller input can
/// replace the resolver, context, publisher, code, instance, or policy
/// afterward.
pub(super) struct PinnedAssetTrust {
    pub(super) resolver: HashSuiteResolver,
    pub(super) expected: ExpectedProtocolContext,
    pub(super) context: PublicationContext,
    pub(super) publisher: Address,
    pub(super) genesis_digest: Digest32,
    pub(super) fee_policy: PaidFeePolicy,
    pub(super) origin: PackageOrigin,
    pub(super) asset: ObjectId,
    pub(super) coin_tag: ScopedTypeTag,
    /// The genesis Standard Asset `TreasuryCap` nominal type for this asset,
    /// used only by the mint/burn family (DR-0253); every other family
    /// leaves this unused. Computed once here, alongside `coin_tag`, from
    /// the same verified `origin`/`asset`, never re-derived per request.
    pub(super) cap_tag: ScopedTypeTag,
}

impl PinnedAssetTrust {
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
        if fee_policy.reserve_entrypoint != "reserve"
            || fee_policy.reserve_all_entrypoint != "reserve_all"
            || fee_policy.settle_entrypoint != "settle"
        {
            return Err(invalid(
                "genesis fee policy does not use the known Standard Asset fee roles",
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
        if fee_policy.reservation_type
            != public_standard_asset::reservation_type_tag(&origin, &asset).map_err(failure)?
        {
            return Err(invalid("genesis fee policy reservation type mismatch"));
        }

        let semantics: Digest32 =
            generic_object_result_semantics(&resolver, &context).map_err(failure)?;
        let candidate: AuthenticatedPublicationCandidate =
            authenticate_publication_submission(&resolver, &context, &semantics, publication)
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

        let base_policy =
            sunrise_edge_client::local_execution::LocalExecutionPolicy::generic_object_results(
                context.clone(),
            );
        if fee_policy.base_policy_digest != base_policy.digest(&resolver).map_err(failure)? {
            return Err(invalid("genesis fee policy base execution policy mismatch"));
        }
        let initialization = &root.manifest().initialization;
        sunrise_edge_client::local_execution::authenticate_local_execution(
            &resolver,
            &base_policy,
            &sunrise_edge_client::local_execution::encode_signed_local_execution(initialization)
                .map_err(failure)?,
        )
        .map_err(failure)?;
        let call = &initialization.intent.call;
        let record = sunrise_edge_client::local_execution::InstanceRecord {
            context: context.clone(),
            creator: call.sender,
            seed: call.instance.seed,
            code: expected_code.clone(),
            revision: 1,
            initializer: public_standard_asset::INITIALIZER.to_owned(),
        };
        let instance = sunrise_edge_client::local_execution::instance_target(&resolver, &record)
            .map_err(failure)?;
        if initialization.intent.mode
            != sunrise_edge_client::local_execution::LocalExecutionMode::Instantiate
            || call.context != context
            || call.code != expected_code
            || call.instance != instance
            || fee_policy.instance != instance
            || call.entrypoint != public_standard_asset::INITIALIZER
            || !call.type_arguments.is_empty()
            || !call.access.entries.is_empty()
            || call.arguments != public_standard_asset::no_arguments().map_err(failure)?
            || !initialization.intent.authorizations.is_empty()
        {
            return Err(invalid(
                "genesis fee instance does not match the known Standard Asset initializer",
            ));
        }

        let genesis_digest: Digest32 = root.digest();
        let cap_tag: ScopedTypeTag = treasury_cap_type_tag(&origin, &asset).map_err(failure)?;
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
            cap_tag,
        })
    }

    pub(super) fn decode_bounded_object(
        &self,
        bytes: &[u8],
        size_message: &'static str,
        canonical_message: &'static str,
    ) -> Result<Object, CliError> {
        if bytes.len() > MAX_ASSET_OBJECT_BYTES {
            return Err(invalid(size_message));
        }
        let object: Object = decode_object(bytes).map_err(failure)?;
        if encode_object(&object).map_err(failure)? != bytes {
            return Err(invalid(canonical_message));
        }
        Ok(object)
    }

    pub(super) fn validate_owned_coin(
        &self,
        object: &Object,
        owner_message: &'static str,
        schema_message: &'static str,
        type_message: &'static str,
    ) -> Result<(), CliError> {
        self.validate_owned_object(
            object,
            &self.coin_tag,
            owner_message,
            schema_message,
            type_message,
        )
    }

    /// Owner/schema/nominal-type check against an explicit `tag`, rather than
    /// one of this trust's own fixed `coin_tag`/`cap_tag` fields. Used by
    /// [`Self::validate_owned_coin`] (the genesis nominal type) and, separately,
    /// by the asset families' optional application pin (DR-0258/0261), which
    /// derives its own `Coin`/
    /// `TreasuryCap` nominal types from a locally pinned, non-genesis asset.
    pub(super) fn validate_owned_object(
        &self,
        object: &Object,
        tag: &ScopedTypeTag,
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
            tag,
        )
        .map_err(failure)?;
        if !matches {
            return Err(invalid(type_message));
        }
        Ok(())
    }
}

/// Renders `value` as ASCII, hex-escaping every byte that is not a plain
/// printable ASCII character or space. `value` is already bounded local
/// configuration (the pinned chain id, or a fixed package entrypoint name),
/// never an untrusted peer response; this still never passes a raw
/// non-printable or control byte through to the rendered review.
pub(super) fn safe_ascii(value: &str) -> String {
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
