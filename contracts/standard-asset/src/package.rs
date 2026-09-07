//! Fallible builder for the package's executable ABI and WASM artifact
//! inputs.
//!
//! Building succeeds only if every declaration this package relies on is
//! structurally valid and canonically encodable. It performs no
//! publication, signs nothing, and confers no instance authority; the
//! caller still authenticates a publication submission and an instance.

use abi::call_values::{CallAbi, ValueLayout};
use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::package_types::PackageOrigin;
use abi::public_abi::{
    ArgumentKind, ConstructorDeclaration, EntrypointDeclaration, ObjectMode, ObjectParameter,
    ObjectResultDeclaration, PackageAbi,
};

use crate::source::{contract_wasm, contract_wat};
use crate::types::{
    bound_pattern, coin_body_layout, definition_body_layout, empty_argument_layout,
    mint_argument_layout, reservation_body_layout, reserve_argument_layout, settle_argument_layout,
    split_argument_layout, transfer_argument_layout, treasury_cap_body_layout,
};
use crate::{
    ASSET_OPAQUE_DOMAIN, CONSTRUCTOR_COIN, CONSTRUCTOR_DEFINITION, CONSTRUCTOR_RESERVATION,
    CONSTRUCTOR_TREASURY_CAP, ENTRYPOINTS, INITIALIZER, SCHEMA_VERSION, StandardAssetError,
};

/// The complete set of publication inputs for the public Standard Asset.
#[derive(Clone, Debug)]
pub struct StandardAssetPackage {
    /// Exact WAT source of the package.
    pub wat: String,
    /// Parsed core WASM bytes.
    pub wasm: Vec<u8>,
    /// Signed executable metadata, including typed object result slots.
    pub abi: ExecutableAbi,
    /// Canonically encoded `abi`, as submitted with the artifact.
    pub encoded_abi: Vec<u8>,
    /// Declared export names, in the ABI's strictly ascending order.
    pub exports: Vec<String>,
}

fn object(mode: ObjectMode, origin: &PackageOrigin, constructor: u16) -> ObjectParameter {
    ObjectParameter {
        mode,
        schema: SCHEMA_VERSION,
        ty: bound_pattern(origin, constructor),
    }
}

fn result(
    mode: ObjectMode,
    origin: &PackageOrigin,
    constructor: u16,
    optional: bool,
) -> ObjectResultDeclaration {
    ObjectResultDeclaration {
        mode,
        schema: SCHEMA_VERSION,
        ty: bound_pattern(origin, constructor),
        optional,
    }
}

fn entrypoint(name: &str, generic: bool, objects: Vec<ObjectParameter>) -> EntrypointDeclaration {
    EntrypointDeclaration {
        name: name.to_owned(),
        type_parameters: if generic {
            vec![ArgumentKind::Opaque(ASSET_OPAQUE_DOMAIN)]
        } else {
            Vec::new()
        },
        objects,
    }
}

/// Builds the signed executable ABI for one publisher origin.
///
/// Entrypoints, argument layouts, result slots, and constructor bodies are
/// all positionally aligned here, so a mismatch fails before publication
/// rather than at execution.
pub fn executable_abi(origin: &PackageOrigin) -> Result<ExecutableAbi, StandardAssetError> {
    let coin: u16 = CONSTRUCTOR_COIN;
    let cap: u16 = CONSTRUCTOR_TREASURY_CAP;
    let reservation: u16 = CONSTRUCTOR_RESERVATION;
    let entrypoints: Vec<EntrypointDeclaration> = vec![
        entrypoint(
            "burn",
            true,
            vec![
                object(ObjectMode::Write, origin, cap),
                object(ObjectMode::Consume, origin, coin),
            ],
        ),
        entrypoint("init", false, Vec::new()),
        entrypoint(
            "merge",
            true,
            vec![
                object(ObjectMode::Write, origin, coin),
                object(ObjectMode::Consume, origin, coin),
            ],
        ),
        entrypoint("mint", true, vec![object(ObjectMode::Write, origin, cap)]),
        entrypoint(
            "reserve",
            true,
            vec![object(ObjectMode::Write, origin, coin)],
        ),
        entrypoint(
            "reserve_all",
            true,
            vec![object(ObjectMode::Consume, origin, coin)],
        ),
        entrypoint(
            "settle",
            true,
            vec![object(ObjectMode::Consume, origin, reservation)],
        ),
        entrypoint("split", true, vec![object(ObjectMode::Write, origin, coin)]),
        entrypoint(
            "transfer",
            true,
            vec![object(ObjectMode::Write, origin, coin)],
        ),
    ];
    if entrypoints.len() != ENTRYPOINTS.len()
        || entrypoints
            .iter()
            .zip(ENTRYPOINTS)
            .any(|(declared, name)| declared.name != name)
    {
        return Err(StandardAssetError::Invalid(
            "entrypoint declarations must match the published export order",
        ));
    }
    let arguments: Vec<ValueLayout> = vec![
        empty_argument_layout(),
        empty_argument_layout(),
        empty_argument_layout(),
        mint_argument_layout(),
        reserve_argument_layout(),
        reserve_argument_layout(),
        settle_argument_layout(),
        split_argument_layout(),
        transfer_argument_layout(),
    ];
    // Only Coin is transferable; Definition, TreasuryCap and Reservation
    // remain restricted to their defining contract.
    let constructors: Vec<ConstructorDeclaration> = vec![
        ConstructorDeclaration {
            local_id: CONSTRUCTOR_DEFINITION,
            schema: SCHEMA_VERSION,
            arguments: Vec::new(),
        },
        ConstructorDeclaration {
            local_id: coin,
            schema: SCHEMA_VERSION,
            arguments: vec![ArgumentKind::Opaque(ASSET_OPAQUE_DOMAIN)],
        },
        ConstructorDeclaration {
            local_id: cap,
            schema: SCHEMA_VERSION,
            arguments: vec![ArgumentKind::Opaque(ASSET_OPAQUE_DOMAIN)],
        },
        ConstructorDeclaration {
            local_id: reservation,
            schema: SCHEMA_VERSION,
            arguments: vec![ArgumentKind::Opaque(ASSET_OPAQUE_DOMAIN)],
        },
    ];
    let bodies: Vec<ValueLayout> = vec![
        definition_body_layout(),
        coin_body_layout(),
        treasury_cap_body_layout(),
        reservation_body_layout(),
    ];
    // Mint and split return the freshly created Coin as Read, which works
    // for a foreign recipient and grants no mutation authority. Reserve
    // returns one required sender-owned Reservation Consume slot. Settle
    // returns the fee Coin in required slot zero and the refund Coin in
    // optional slot one, absent exactly when the refund is zero.
    let results: Vec<Vec<ObjectResultDeclaration>> = vec![
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![result(ObjectMode::Read, origin, coin, false)],
        vec![result(ObjectMode::Consume, origin, reservation, false)],
        vec![result(ObjectMode::Consume, origin, reservation, false)],
        vec![
            result(ObjectMode::Read, origin, coin, false),
            result(ObjectMode::Read, origin, coin, true),
        ],
        vec![result(ObjectMode::Read, origin, coin, false)],
        Vec::new(),
    ];
    let abi: ExecutableAbi = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors,
                entrypoints,
            },
            arguments,
            bodies,
        },
        initializer: Some(INITIALIZER.to_owned()),
        transferable_constructors: vec![CONSTRUCTOR_COIN],
        results,
    };
    abi.validate()?;
    Ok(abi)
}

/// Canonically encodes the executable ABI for one publisher origin.
pub fn encoded_executable_abi(origin: &PackageOrigin) -> Result<Vec<u8>, StandardAssetError> {
    Ok(encode_executable_abi(&executable_abi(origin)?)?)
}

/// Builds every publication input for one publisher origin.
pub fn build_package(origin: &PackageOrigin) -> Result<StandardAssetPackage, StandardAssetError> {
    let abi: ExecutableAbi = executable_abi(origin)?;
    let encoded_abi: Vec<u8> = encode_executable_abi(&abi)?;
    let exports: Vec<String> = abi
        .call
        .objects
        .entrypoints
        .iter()
        .map(|entry| entry.name.clone())
        .collect();
    Ok(StandardAssetPackage {
        wat: contract_wat()?,
        wasm: contract_wasm()?,
        abi,
        encoded_abi,
        exports,
    })
}
