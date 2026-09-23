//! Bounded, invocation-local authority for contract-produced protocol-custody effects.
//!
//! This module does not grant storage authority. It lets one already admitted
//! typed-WASM invocation (a) resolve one otherwise non-address 32-byte transfer
//! operand to one exact custody scope, or (b) write and release one exact
//! custody input to one exact address. The returned effects remain provisional
//! and must be checked and committed by the protocol operation that constructed
//! the capability.

use crate::call::{CallIntent, InstanceTarget};
use crate::local_execution::{LocalExecutionError, ScopedResolvedObject};
use crate::publication::{PublicationContext, UnverifiedDependencyRef};
use abi::package_types::{ScopedTypeArg, ScopedTypeTag};
use canonical_encoding::CanonicalStruct;
use crypto::{Ed25519OwnerAddressPolicy, validate_ed25519_owner_address};
use hashing::HashSuiteResolver;
use objects::{
    AccessMode, Address, ObjectId, Owner, ProtocolCustodyPurpose, ProtocolCustodyScope,
    encode_object_id, encode_protocol_custody_scope,
};
use protocol_types::{Digest32, HashPurpose};

const OWNER_TOKEN_PREIMAGE_TYPE_ID: u16 = 0x642E;
const OWNER_TOKEN_PREIMAGE_VERSION: u16 = 1;
/// Maximum deterministic attempts to derive a transfer operand that cannot
/// be parsed as a canonical prime-order Ed25519 address.
const MAX_OWNER_TOKEN_DERIVATION_ATTEMPTS: u32 = 64;

/// One exact typed-contract target admitted for a protocol-custody operation.
///
/// Fields are private so callers cannot widen a capability after construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolCustodyTarget {
    instance: InstanceTarget,
    code: UnverifiedDependencyRef,
    ty: ScopedTypeTag,
    schema: u32,
    entrypoint: String,
}

impl ProtocolCustodyTarget {
    /// Constructs a bounded target. Full ABI and object binding still happens
    /// in the ordinary typed-WASM admission path.
    pub fn new(
        instance: InstanceTarget,
        code: UnverifiedDependencyRef,
        ty: ScopedTypeTag,
        schema: u32,
        entrypoint: String,
    ) -> Result<Self, LocalExecutionError> {
        if ty.origin() != code.origin()
            || schema == 0
            || entrypoint.is_empty()
            || entrypoint.len() > crate::call::MAX_ENTRYPOINT_BYTES
        {
            return Err(LocalExecutionError::Invalid(
                "protocol custody contract target",
            ));
        }
        Ok(Self {
            instance,
            code,
            ty,
            schema,
            entrypoint,
        })
    }
}

/// Closed direction of one protocol-custody invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolCustodyDirection {
    /// Move one exact sender-owned object into one exact custody scope.
    Deposit {
        /// Exact source object.
        source: ObjectId,
        /// Exact resulting custody scope.
        scope: ProtocolCustodyScope,
    },
    /// Mutate and/or release one exact custody object to one exact recipient.
    Release {
        /// Exact custody object.
        custody: ObjectId,
        /// Exact current custody scope.
        scope: ProtocolCustodyScope,
        /// Exact address permitted as the release target.
        recipient: Address,
    },
}

/// Private mapping from one non-address transfer operand to one exact owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PinnedOwnerTarget {
    token: [u8; 32],
    owner: Owner,
}

/// Bounded protocol-custody authority for exactly one typed-WASM invocation.
///
/// The capability is not canonical protocol state and is never persisted. Its
/// private fields bind the current context, authenticated sender, exact
/// instance/code/type/schema/entrypoint and one closed direction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolCustodyCapability {
    context: PublicationContext,
    target: ProtocolCustodyTarget,
    direction: ProtocolCustodyDirection,
    sender: [u8; 32],
    expected_event_digest: Digest32,
    owner_target: Option<PinnedOwnerTarget>,
}

impl ProtocolCustodyCapability {
    /// Constructs one invocation-local capability from trusted protocol policy.
    pub fn new(
        resolver: &HashSuiteResolver,
        context: PublicationContext,
        target: ProtocolCustodyTarget,
        direction: ProtocolCustodyDirection,
        sender: [u8; 32],
        expected_event_digest: Digest32,
    ) -> Result<Self, LocalExecutionError> {
        if resolver.chain_id() != context.chain_id()
            || resolver.protocol_version() != context.protocol_version()
            || target.code.origin().chain_id() != context.chain_id()
            || target.code.context().protocol_version() != context.protocol_version()
        {
            return Err(LocalExecutionError::Invalid(
                "protocol custody execution context",
            ));
        }
        validate_ed25519_owner_address(&sender, Ed25519OwnerAddressPolicy::CanonicalPrimeOrder)?;
        let (source, scope): (ObjectId, &ProtocolCustodyScope) = match &direction {
            ProtocolCustodyDirection::Deposit { source, scope } => (*source, scope),
            ProtocolCustodyDirection::Release {
                custody,
                scope,
                recipient,
            } => {
                validate_ed25519_owner_address(
                    recipient.as_bytes(),
                    Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
                )?;
                (*custody, scope)
            }
        };
        if scope.chain_id != *context.chain_id()
            || scope.purpose != ProtocolCustodyPurpose::BondCollateral
            || !matches!(
                target.ty.args(),
                [ScopedTypeArg::Opaque { value, .. }] if value == &scope.resource
            )
        {
            return Err(LocalExecutionError::Invalid(
                "protocol custody resource scope",
            ));
        }

        let owner_target: Option<PinnedOwnerTarget> = match &direction {
            ProtocolCustodyDirection::Deposit { scope, .. } => {
                let token: [u8; 32] =
                    derive_deposit_owner_token(resolver, &context, source, scope)?;
                Some(PinnedOwnerTarget {
                    token,
                    owner: Owner::ProtocolCustody(scope.clone()),
                })
            }
            ProtocolCustodyDirection::Release { .. } => None,
        };
        Ok(Self {
            context,
            target,
            direction,
            sender,
            expected_event_digest,
            owner_target,
        })
    }

    /// Returns the non-authorizing transfer operand for a deposit capability.
    #[must_use]
    pub fn owner_token(&self) -> Option<[u8; 32]> {
        self.owner_target.as_ref().map(|target| target.token)
    }

    /// Pre-bind check: true exactly when `object_id`/`owner` is this exact
    /// capability's own release target. Node-core admission calls this to
    /// admit one non-sender-owned protocol-custody input before the full
    /// typed-WASM [`Self::bind`] runs; `bind` still independently
    /// re-validates the exact input's authority, mode and index, so this
    /// accessor alone grants no execution or storage authority.
    #[must_use]
    pub fn admits_release_input(&self, object_id: ObjectId, owner: &Owner) -> bool {
        matches!(
            &self.direction,
            ProtocolCustodyDirection::Release { custody, scope, .. }
                if *custody == object_id && owner == &Owner::ProtocolCustody(scope.clone())
        )
    }

    pub(crate) fn bind(
        &self,
        call: &CallIntent,
        inputs: &[ScopedResolvedObject],
        event_digest: Digest32,
    ) -> Result<BoundProtocolCustodyCapability, LocalExecutionError> {
        if call.context != self.context
            || call.sender != self.sender
            || call.instance != self.target.instance
            || call.code != self.target.code
            || call.entrypoint != self.target.entrypoint
            || event_digest != self.expected_event_digest
        {
            return Err(LocalExecutionError::Invalid(
                "protocol custody invocation target",
            ));
        }
        let (object_id, scope, recipient): (ObjectId, &ProtocolCustodyScope, Option<Address>) =
            match &self.direction {
                ProtocolCustodyDirection::Deposit { source, scope } => (*source, scope, None),
                ProtocolCustodyDirection::Release {
                    custody,
                    scope,
                    recipient,
                } => (*custody, scope, Some(*recipient)),
            };
        let mut matching: Option<usize> = None;
        for (index, input) in inputs.iter().enumerate() {
            if input.resolved.object.id == object_id && matching.replace(index).is_some() {
                return Err(LocalExecutionError::Invalid(
                    "duplicate protocol custody input",
                ));
            }
        }
        let index: usize = matching.ok_or(LocalExecutionError::Invalid(
            "missing protocol custody input",
        ))?;
        let input: &ScopedResolvedObject = &inputs[index];
        if input.resolved.mode != AccessMode::Write
            || input.resolved.object.schema_version != self.target.schema
            || input.authority.object_id != object_id
            || input.authority.instance != self.target.instance
            || input.authority.code != self.target.code
            || input.authority.ty != self.target.ty
        {
            return Err(LocalExecutionError::Invalid(
                "protocol custody input target",
            ));
        }
        let (deposit_source, custody_input): (Option<usize>, Option<PinnedCustodyInput>) =
            match (&self.direction, &input.resolved.object.owner) {
                (ProtocolCustodyDirection::Deposit { .. }, Owner::Address(owner))
                    if owner.as_bytes() == &self.sender =>
                {
                    (Some(index), None)
                }
                (ProtocolCustodyDirection::Release { .. }, Owner::ProtocolCustody(owner_scope))
                    if owner_scope == scope =>
                {
                    (
                        None,
                        Some(PinnedCustodyInput {
                            index,
                            scope: scope.clone(),
                            recipient: recipient.ok_or(LocalExecutionError::Invalid(
                                "protocol custody release recipient",
                            ))?,
                        }),
                    )
                }
                _ => {
                    return Err(LocalExecutionError::Invalid("protocol custody input owner"));
                }
            };
        Ok(BoundProtocolCustodyCapability {
            deposit_source,
            owner_target: self.owner_target.clone(),
            custody_input,
        })
    }
}

fn owner_token_preimage(
    context: &PublicationContext,
    scope: &ProtocolCustodyScope,
    source: ObjectId,
    counter: u32,
) -> Result<Vec<u8>, LocalExecutionError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(OWNER_TOKEN_PREIMAGE_TYPE_ID, OWNER_TOKEN_PREIMAGE_VERSION);
    frame.field_str(1, context.chain_id().as_str())?;
    frame.field_bytes(
        2,
        encode_protocol_custody_scope(scope)
            .map_err(crate::ExecutionError::Object)
            .map_err(LocalExecutionError::Execution)?,
    )?;
    frame.field_bytes(
        3,
        encode_object_id(&source)
            .map_err(crate::ExecutionError::Object)
            .map_err(LocalExecutionError::Execution)?,
    )?;
    frame.field_u32(4, counter)?;
    Ok(frame.finish()?)
}

/// Derives the non-authorizing deposit transfer operand. Counter zero is tried
/// first; address-shaped results are skipped deterministically. Exhausting all
/// 64 attempts fails closed. With each digest independently having at most the
/// Ed25519 address acceptance probability, exhaustion is negligible while
/// remaining strictly bounded.
pub fn derive_deposit_owner_token(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    source: ObjectId,
    scope: &ProtocolCustodyScope,
) -> Result<[u8; 32], LocalExecutionError> {
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
        || scope.chain_id != *context.chain_id()
    {
        return Err(LocalExecutionError::Invalid(
            "protocol custody token context",
        ));
    }
    for counter in 0..MAX_OWNER_TOKEN_DERIVATION_ATTEMPTS {
        let preimage: Vec<u8> = owner_token_preimage(context, scope, source, counter)?;
        let token: [u8; 32] = resolver
            .hash_for_purpose(context.epoch(), HashPurpose::Object, &preimage)?
            .bytes();
        if validate_ed25519_owner_address(&token, Ed25519OwnerAddressPolicy::CanonicalPrimeOrder)
            .is_err()
        {
            return Ok(token);
        }
    }
    Err(LocalExecutionError::Invalid(
        "protocol custody token derivation exhausted",
    ))
}

#[derive(Clone, Debug)]
pub(crate) struct PinnedCustodyInput {
    index: usize,
    scope: ProtocolCustodyScope,
    recipient: Address,
}

/// Arena-bound capability. The indices are created only after the request's
/// complete input list and exact target have passed validation.
#[derive(Clone, Debug, Default)]
pub(crate) struct BoundProtocolCustodyCapability {
    deposit_source: Option<usize>,
    owner_target: Option<PinnedOwnerTarget>,
    custody_input: Option<PinnedCustodyInput>,
}

impl BoundProtocolCustodyCapability {
    pub(crate) fn admits_input_owner(&self, index: usize, owner: &Owner) -> bool {
        self.custody_input.as_ref().is_some_and(|input| {
            input.index == index && owner == &Owner::ProtocolCustody(input.scope.clone())
        })
    }

    pub(crate) fn admits_custody_write(&self, index: usize, consume: bool) -> bool {
        !consume
            && self
                .custody_input
                .as_ref()
                .is_some_and(|input| input.index == index)
    }

    pub(crate) fn transfer_owner(
        &self,
        index: usize,
        operand: &[u8; 32],
    ) -> Result<Option<Owner>, LocalExecutionError> {
        if let Some(input) = &self.custody_input
            && input.index == index
        {
            if operand != input.recipient.as_bytes() {
                return Err(LocalExecutionError::Invalid(
                    "protocol custody release recipient",
                ));
            }
            return Ok(Some(Owner::Address(input.recipient)));
        }
        if let Some(target) = &self.owner_target
            && self.deposit_source == Some(index)
        {
            if target.token != *operand {
                return Err(LocalExecutionError::Invalid(
                    "protocol custody deposit target",
                ));
            }
            return Ok(Some(target.owner.clone()));
        }
        if self
            .owner_target
            .as_ref()
            .is_some_and(|target| target.token == *operand)
        {
            return Err(LocalExecutionError::Invalid(
                "ambient protocol custody target",
            ));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResolvedObject;
    use abi::AccessManifest;
    use abi::package_types::PackageOrigin;
    use ed25519_zebra::{SigningKey, VerificationKey};
    use objects::Object;
    use protocol_types::{
        ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
    };

    struct CapabilityFixture {
        resolver: HashSuiteResolver,
        context: PublicationContext,
        target: ProtocolCustodyTarget,
        sender: [u8; 32],
        scope: ProtocolCustodyScope,
        source: ObjectId,
        event: Digest32,
    }

    fn capability_fixture() -> CapabilityFixture {
        let chain_id: ChainId = ChainId::new("custody-adversarial").expect("chain");
        let version: ProtocolVersion = ProtocolVersion::new(9);
        let context: PublicationContext =
            PublicationContext::new(chain_id.clone(), version, Epoch::new(7)).expect("context");
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            chain_id.clone(),
            version,
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .expect("resolver");
        let sender: [u8; 32] = VerificationKey::from(&SigningKey::from([0x41; 32])).into();
        let origin: PackageOrigin =
            PackageOrigin::unverified(chain_id.clone(), sender, [0x42; 32]).expect("origin");
        let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
            origin.clone(),
            1,
            context.clone(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x43; 32]),
        )
        .expect("code");
        let ty: ScopedTypeTag = ScopedTypeTag::new(
            origin,
            7,
            vec![ScopedTypeArg::Opaque {
                domain: 9,
                value: [0x44; 32],
            }],
        )
        .expect("type");
        let target: ProtocolCustodyTarget = ProtocolCustodyTarget::new(
            InstanceTarget {
                creator: sender,
                seed: [0x45; 32],
                revision: 1,
                record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x46; 32]),
            },
            code,
            ty,
            1,
            "transfer".to_owned(),
        )
        .expect("target");
        CapabilityFixture {
            resolver,
            context,
            target,
            sender,
            scope: ProtocolCustodyScope {
                purpose: ProtocolCustodyPurpose::BondCollateral,
                chain_id,
                subject: [0x47; 32],
                resource: [0x44; 32],
            },
            source: ObjectId::new([0x48; 32]),
            event: Digest32::new(HashAlgorithmId::Sha2_256, [0x49; 32]),
        }
    }

    fn deposit_capability(fixture: &CapabilityFixture) -> ProtocolCustodyCapability {
        ProtocolCustodyCapability::new(
            &fixture.resolver,
            fixture.context.clone(),
            fixture.target.clone(),
            ProtocolCustodyDirection::Deposit {
                source: fixture.source,
                scope: fixture.scope.clone(),
            },
            fixture.sender,
            fixture.event,
        )
        .expect("capability")
    }

    fn fixture_call(fixture: &CapabilityFixture) -> CallIntent {
        CallIntent {
            context: fixture.context.clone(),
            request_id: [0x50; 32],
            sender: fixture.sender,
            nonce: 1,
            code: fixture.target.code.clone(),
            instance: fixture.target.instance.clone(),
            entrypoint: fixture.target.entrypoint.clone(),
            type_arguments: Vec::new(),
            access: AccessManifest {
                entries: Vec::new(),
            },
            arguments: Vec::new(),
            gas_limit: 1,
        }
    }

    fn fixture_input(fixture: &CapabilityFixture, mode: AccessMode) -> ScopedResolvedObject {
        ScopedResolvedObject {
            resolved: ResolvedObject {
                object: Object {
                    id: fixture.source,
                    version: 1,
                    owner: Owner::Address(Address::new(fixture.sender)),
                    type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x51; 32]),
                    schema_version: fixture.target.schema,
                    data: Vec::new(),
                },
                mode,
            },
            authority: crate::local_execution::ObjectAuthority {
                object_id: fixture.source,
                instance_context: fixture.context.clone(),
                instance: fixture.target.instance.clone(),
                code: fixture.target.code.clone(),
                ty: fixture.target.ty.clone(),
            },
        }
    }

    #[test]
    fn stable_owner_token_preimage_vector() {
        let context: PublicationContext = PublicationContext::new(
            ChainId::new("custody-vector").expect("chain"),
            ProtocolVersion::new(9),
            Epoch::new(7),
        )
        .expect("context");
        let scope: ProtocolCustodyScope = ProtocolCustodyScope {
            purpose: ProtocolCustodyPurpose::BondCollateral,
            chain_id: context.chain_id().clone(),
            subject: [0x22; 32],
            resource: [0x33; 32],
        };
        let bytes: Vec<u8> =
            owner_token_preimage(&context, &scope, ObjectId::new([0x44; 32]), 0).expect("preimage");
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "534e52452e640100040001000e000000637573746f64792d766563746f72020072000000534e5245074001000400010002000000010002000e000000637573746f64792d766563746f7203002000000022222222222222222222222222222222222222222222222222222222222222220400200000003333333333333333333333333333333333333333333333333333333333333333030030000000534e5245014001000100010020000000444444444444444444444444444444444444444444444444444444444444444404000400000000000000"
        );
    }

    #[test]
    fn constructor_rejects_wrong_context_scope_and_keys() {
        let fixture: CapabilityFixture = capability_fixture();
        let wrong_origin: PackageOrigin = PackageOrigin::unverified(
            fixture.context.chain_id().clone(),
            fixture.sender,
            [0x99; 32],
        )
        .expect("wrong origin");
        let wrong_origin_ty: ScopedTypeTag = ScopedTypeTag::new(
            wrong_origin,
            fixture.target.ty.constructor(),
            fixture.target.ty.args().to_vec(),
        )
        .expect("wrong-origin type");
        for target in [
            ProtocolCustodyTarget::new(
                fixture.target.instance.clone(),
                fixture.target.code.clone(),
                wrong_origin_ty,
                fixture.target.schema,
                fixture.target.entrypoint.clone(),
            ),
            ProtocolCustodyTarget::new(
                fixture.target.instance.clone(),
                fixture.target.code.clone(),
                fixture.target.ty.clone(),
                0,
                fixture.target.entrypoint.clone(),
            ),
            ProtocolCustodyTarget::new(
                fixture.target.instance.clone(),
                fixture.target.code.clone(),
                fixture.target.ty.clone(),
                fixture.target.schema,
                String::new(),
            ),
            ProtocolCustodyTarget::new(
                fixture.target.instance.clone(),
                fixture.target.code.clone(),
                fixture.target.ty.clone(),
                fixture.target.schema,
                "x".repeat(crate::call::MAX_ENTRYPOINT_BYTES + 1),
            ),
        ] {
            assert!(matches!(
                target,
                Err(LocalExecutionError::Invalid(
                    "protocol custody contract target"
                ))
            ));
        }
        let wrong_resolver: HashSuiteResolver = HashSuiteResolver::new(
            ChainId::new("other-chain").expect("chain"),
            fixture.context.protocol_version(),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .expect("resolver");
        let direction = || ProtocolCustodyDirection::Deposit {
            source: fixture.source,
            scope: fixture.scope.clone(),
        };
        assert!(matches!(
            ProtocolCustodyCapability::new(
                &wrong_resolver,
                fixture.context.clone(),
                fixture.target.clone(),
                direction(),
                fixture.sender,
                fixture.event,
            ),
            Err(LocalExecutionError::Invalid(
                "protocol custody execution context"
            ))
        ));
        assert!(
            ProtocolCustodyCapability::new(
                &fixture.resolver,
                fixture.context.clone(),
                fixture.target.clone(),
                direction(),
                [0; 32],
                fixture.event,
            )
            .is_err()
        );

        let mut wrong_chain: ProtocolCustodyScope = fixture.scope.clone();
        wrong_chain.chain_id = ChainId::new("other-chain").expect("chain");
        assert!(matches!(
            ProtocolCustodyCapability::new(
                &fixture.resolver,
                fixture.context.clone(),
                fixture.target.clone(),
                ProtocolCustodyDirection::Deposit {
                    source: fixture.source,
                    scope: wrong_chain,
                },
                fixture.sender,
                fixture.event,
            ),
            Err(LocalExecutionError::Invalid(
                "protocol custody resource scope"
            ))
        ));

        let mut wrong_purpose: ProtocolCustodyScope = fixture.scope.clone();
        wrong_purpose.purpose = ProtocolCustodyPurpose::FeeEscrow;
        assert!(matches!(
            ProtocolCustodyCapability::new(
                &fixture.resolver,
                fixture.context.clone(),
                fixture.target.clone(),
                ProtocolCustodyDirection::Deposit {
                    source: fixture.source,
                    scope: wrong_purpose,
                },
                fixture.sender,
                fixture.event,
            ),
            Err(LocalExecutionError::Invalid(
                "protocol custody resource scope"
            ))
        ));
        let mut wrong_resource: ProtocolCustodyScope = fixture.scope.clone();
        wrong_resource.resource = [0x99; 32];
        assert!(matches!(
            ProtocolCustodyCapability::new(
                &fixture.resolver,
                fixture.context.clone(),
                fixture.target.clone(),
                ProtocolCustodyDirection::Deposit {
                    source: fixture.source,
                    scope: wrong_resource,
                },
                fixture.sender,
                fixture.event,
            ),
            Err(LocalExecutionError::Invalid(
                "protocol custody resource scope"
            ))
        ));
        assert!(
            ProtocolCustodyCapability::new(
                &fixture.resolver,
                fixture.context.clone(),
                fixture.target.clone(),
                ProtocolCustodyDirection::Release {
                    custody: fixture.source,
                    scope: fixture.scope.clone(),
                    recipient: Address::new([0; 32]),
                },
                fixture.sender,
                fixture.event,
            )
            .is_err()
        );
    }

    #[test]
    fn capability_binds_exact_invocation_and_rejects_consume_and_duplicates() {
        let fixture: CapabilityFixture = capability_fixture();
        let call: CallIntent = fixture_call(&fixture);
        let write: ScopedResolvedObject = fixture_input(&fixture, AccessMode::Write);
        let capability: ProtocolCustodyCapability = deposit_capability(&fixture);
        assert!(
            capability
                .bind(&call, std::slice::from_ref(&write), fixture.event)
                .is_ok()
        );

        let mut wrong_context: CallIntent = call.clone();
        wrong_context.context = PublicationContext::new(
            fixture.context.chain_id().clone(),
            fixture.context.protocol_version(),
            Epoch::new(fixture.context.epoch().get() + 1),
        )
        .expect("context");
        let mut wrong_sender: CallIntent = call.clone();
        wrong_sender.sender = VerificationKey::from(&SigningKey::from([0x52; 32])).into();
        let mut wrong_instance: CallIntent = call.clone();
        wrong_instance.instance.seed = [0x53; 32];
        let mut wrong_code: CallIntent = call.clone();
        wrong_code.code = UnverifiedDependencyRef::new(
            call.code.origin().clone(),
            2,
            call.code.context().clone(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x54; 32]),
        )
        .expect("code");
        let mut wrong_entrypoint: CallIntent = call.clone();
        wrong_entrypoint.entrypoint = "split".to_owned();
        for wrong_call in [
            wrong_context,
            wrong_sender,
            wrong_instance,
            wrong_code,
            wrong_entrypoint,
        ] {
            assert!(matches!(
                capability.bind(&wrong_call, std::slice::from_ref(&write), fixture.event),
                Err(LocalExecutionError::Invalid(
                    "protocol custody invocation target"
                ))
            ));
        }
        assert!(matches!(
            capability.bind(
                &call,
                std::slice::from_ref(&write),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32]),
            ),
            Err(LocalExecutionError::Invalid(
                "protocol custody invocation target"
            ))
        ));
        assert!(matches!(
            capability.bind(&call, &[write.clone(), write.clone()], fixture.event,),
            Err(LocalExecutionError::Invalid(
                "duplicate protocol custody input"
            ))
        ));
        assert!(matches!(
            capability.bind(
                &call,
                &[fixture_input(&fixture, AccessMode::Consume)],
                fixture.event,
            ),
            Err(LocalExecutionError::Invalid(
                "protocol custody input target"
            ))
        ));
    }

    #[test]
    fn constructor_and_opaque_domain_are_part_of_the_exact_target() {
        let fixture: CapabilityFixture = capability_fixture();
        let call: CallIntent = fixture_call(&fixture);
        let input: ScopedResolvedObject = fixture_input(&fixture, AccessMode::Write);
        for ty in [
            ScopedTypeTag::new(
                fixture.target.ty.origin().clone(),
                fixture.target.ty.constructor() + 1,
                fixture.target.ty.args().to_vec(),
            )
            .expect("constructor target"),
            ScopedTypeTag::new(
                fixture.target.ty.origin().clone(),
                fixture.target.ty.constructor(),
                vec![ScopedTypeArg::Opaque {
                    domain: 10,
                    value: fixture.scope.resource,
                }],
            )
            .expect("domain target"),
        ] {
            let target: ProtocolCustodyTarget = ProtocolCustodyTarget::new(
                fixture.target.instance.clone(),
                fixture.target.code.clone(),
                ty,
                fixture.target.schema,
                fixture.target.entrypoint.clone(),
            )
            .expect("target");
            let capability: ProtocolCustodyCapability = ProtocolCustodyCapability::new(
                &fixture.resolver,
                fixture.context.clone(),
                target,
                ProtocolCustodyDirection::Deposit {
                    source: fixture.source,
                    scope: fixture.scope.clone(),
                },
                fixture.sender,
                fixture.event,
            )
            .expect("capability");
            assert!(matches!(
                capability.bind(&call, std::slice::from_ref(&input), fixture.event),
                Err(LocalExecutionError::Invalid(
                    "protocol custody input target"
                ))
            ));
        }
    }

    #[test]
    fn address_shaped_counter_zero_token_advances_deterministically() {
        let chain_id: ChainId = ChainId::new("custody-alias").expect("chain");
        let version: ProtocolVersion = ProtocolVersion::new(9);
        let context: PublicationContext =
            PublicationContext::new(chain_id.clone(), version, Epoch::new(7)).expect("context");
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            chain_id.clone(),
            version,
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .expect("resolver");
        let signing_key: SigningKey = SigningKey::from([0x71; 32]);
        let sender: [u8; 32] = VerificationKey::from(&signing_key).into();
        let origin: PackageOrigin =
            PackageOrigin::unverified(chain_id.clone(), sender, [0x72; 32]).expect("origin");
        let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
            origin.clone(),
            1,
            context.clone(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x73; 32]),
        )
        .expect("code");
        let ty: ScopedTypeTag = ScopedTypeTag::new(
            origin,
            1,
            vec![ScopedTypeArg::Opaque {
                domain: 9,
                value: [0x74; 32],
            }],
        )
        .expect("type");
        let target: ProtocolCustodyTarget = ProtocolCustodyTarget::new(
            InstanceTarget {
                creator: sender,
                seed: [0x75; 32],
                revision: 1,
                record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x76; 32]),
            },
            code,
            ty,
            1,
            "transfer".to_owned(),
        )
        .expect("target");
        let scope: ProtocolCustodyScope = ProtocolCustodyScope {
            purpose: ProtocolCustodyPurpose::BondCollateral,
            chain_id,
            subject: [0x77; 32],
            resource: [0x74; 32],
        };
        let source: ObjectId = (0u8..=u8::MAX)
            .map(|byte| ObjectId::new([byte; 32]))
            .find(|source| {
                let preimage: Vec<u8> =
                    owner_token_preimage(&context, &scope, *source, 0).expect("preimage");
                let token: [u8; 32] = resolver
                    .hash_for_purpose(context.epoch(), HashPurpose::Object, &preimage)
                    .expect("token")
                    .bytes();
                validate_ed25519_owner_address(
                    &token,
                    Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
                )
                .is_ok()
            })
            .expect("bounded search finds an address-shaped digest");
        let counter_zero: [u8; 32] = resolver
            .hash_for_purpose(
                context.epoch(),
                HashPurpose::Object,
                &owner_token_preimage(&context, &scope, source, 0).expect("preimage"),
            )
            .expect("counter-zero token")
            .bytes();
        let capability: ProtocolCustodyCapability = ProtocolCustodyCapability::new(
            &resolver,
            context,
            target,
            ProtocolCustodyDirection::Deposit { source, scope },
            sender,
            Digest32::new(HashAlgorithmId::Sha2_256, [0x78; 32]),
        )
        .expect("bounded rejection sampling advances");
        let selected: [u8; 32] = capability.owner_token().expect("deposit token");
        assert_ne!(selected, counter_zero);
        assert!(
            validate_ed25519_owner_address(
                &selected,
                Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
            )
            .is_err()
        );
    }
}
