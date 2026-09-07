//! DR-0124 typed object-result fixtures: a `resource` dependency library that
//! declares ordered result slots on several entrypoints, and a `coordinator`
//! root package that exercises `call_dependency`/`call_dependency_with_results`
//! and `return_object` against it. Both packages are wasm profile four.

use abi::call_values::{CallAbi, CallValue, ValueLayout, encode_call_value};
use abi::package_types::{PackageOrigin, ScopedTypeTag, encode_scoped_type_tag};
use abi::public_abi::{
    ConstructorDeclaration, EntrypointDeclaration, ObjectMode, ObjectParameter,
    ObjectResultDeclaration, PackageAbi, TypePattern,
};

/// Source and ABI metadata, including per-entrypoint typed object results.
pub struct ResultsPackage {
    pub wat: String,
    pub wasm: Vec<u8>,
    pub abi: CallAbi,
    pub initializer: Option<String>,
    pub transferable_constructors: Vec<u16>,
    pub results: Vec<Vec<ObjectResultDeclaration>>,
}

pub fn tuple0_bytes() -> Vec<u8> {
    encode_call_value(&ValueLayout::Tuple(vec![]), &CallValue::Tuple(vec![])).unwrap()
}

pub fn u64_bytes(value: u64) -> Vec<u8> {
    encode_call_value(&ValueLayout::U64, &CallValue::U64(value)).unwrap()
}

fn tag(origin: &PackageOrigin, id: u16) -> Vec<u8> {
    encode_scoped_type_tag(&ScopedTypeTag::new(origin.clone(), id, vec![]).unwrap()).unwrap()
}

fn data(address: u32, bytes: &[u8]) -> String {
    let escaped: String = bytes.iter().map(|byte| format!("\\{byte:02x}")).collect();
    format!("(data (i32.const {address}) \"{escaped}\")")
}

fn resource_pattern(origin: &PackageOrigin) -> TypePattern {
    TypePattern {
        origin: origin.clone(),
        constructor: 1,
        arguments: vec![],
    }
}

fn result_slot(
    origin: &PackageOrigin,
    mode: ObjectMode,
    optional: bool,
) -> ObjectResultDeclaration {
    ObjectResultDeclaration {
        mode,
        schema: 1,
        ty: resource_pattern(origin),
        optional,
    }
}

fn entry(name: &str, objects: Vec<ObjectParameter>) -> EntrypointDeclaration {
    EntrypointDeclaration {
        name: name.to_owned(),
        type_parameters: vec![],
        objects,
    }
}

// Shared guest-side canonical-struct field walker and typed host bindings.
// `$field`/`$size`/`$scalar` are the exact generic parser used by the
// existing general-call inventory fixture; they assert no business meaning
// beyond CanonicalStruct field framing.
const COMMON: &str = r#"
(func $require (param $ok i32)
 (if (i32.eqz (local.get $ok)) (then (call $abort (i32.const 0) (i32.const 0)) unreachable)))
(func $zero (param $status i32) (call $require (i32.eqz (local.get $status))))
(func $field (param $p i32) (param $n i32) (param $id i32) (result i32)
 (local $end i32) (local $at i32) (local $left i32) (local $size i32)
 (call $require (i32.ge_u (local.get $n) (i32.const 10)))
 (local.set $end (i32.add (local.get $p) (local.get $n)))
 (call $require (i32.ge_u (local.get $end) (local.get $p)))
 (call $require (i32.le_u (local.get $end) (i32.const 65536)))
 (call $require (i32.eq (i32.load (local.get $p)) (i32.const 1163021907)))
 (call $require (i32.eq (i32.load16_u offset=6 (local.get $p)) (i32.const 1)))
 (local.set $left (i32.load16_u offset=8 (local.get $p)))
 (local.set $at (i32.add (local.get $p) (i32.const 10)))
 (block $missing (loop $fields
  (br_if $missing (i32.eqz (local.get $left)))
  (call $require (i32.ge_u (i32.sub (local.get $end) (local.get $at)) (i32.const 6)))
  (local.set $size (i32.load offset=2 (local.get $at)))
  (call $require (i32.le_u (local.get $size) (i32.sub (i32.sub (local.get $end) (local.get $at)) (i32.const 6))))
  (if (i32.eq (i32.load16_u (local.get $at)) (local.get $id)) (then (return (i32.add (local.get $at) (i32.const 6)))))
  (local.set $at (i32.add (i32.add (local.get $at) (i32.const 6)) (local.get $size)))
  (local.set $left (i32.sub (local.get $left) (i32.const 1))) (br $fields)))
 unreachable)
(func $size (param $p i32) (result i32) (i32.load (i32.sub (local.get $p) (i32.const 4))))
(func $scalar (param $p i32) (param $n i32) (result i32) (local $v i32)
 (local.set $v (call $field (local.get $p) (local.get $n) (i32.const 2)))
 (call $require (i32.eq (call $size (local.get $v)) (i32.const 8))) (local.get $v))
(func $prepare (param $expected i32)
 (call $require (i32.eq (call $count) (local.get $expected)))
 (global.set $al (call $args_len))
 (call $require (i32.le_u (global.get $al) (i32.const 4096)))
 (call $require (i32.eq (call $args (i32.const 0) (i32.const 8192) (global.get $al)) (global.get $al))))
"#;

/// Dependency library: declares ordered typed object result slots (DR-0124).
/// Constructor 1 is `Resource` (empty body). Entrypoints (ascending):
/// `dup_slot` (0 params, 2 required Read slots, same handle returned twice —
/// duplicate-result rejection), `issue_foreign` (0 params, 1 required Read
/// slot, creates a foreign-owned object — permits Read of a foreign owner),
/// `issue_four` (0 params, 4 required Consume slots, the maximum declarable
/// arity, used by the cumulative handle-bound case),
/// `issue_optional` (0 params, 1 optional Read slot, U64 flag argument;
/// creates and returns only when the flag is nonzero), `issue_self` (0
/// params, 1 required Consume slot, sender-owned), `issue_skip` (0 params, 1
/// required Consume slot, never calls `return_object` — required-slot
/// violation), `relay` (1 Read object param, 1 required Read slot, forwards
/// the supplied handle — non-defining relay when the caller is another
/// package), `return_then_consume`/`return_then_transfer` (0 params, 1
/// required Consume slot; return the freshly created object then invalidate
/// it before frame exit — final revalidation must reject the stale slot).
pub fn resource(origin: &PackageOrigin) -> ResultsPackage {
    let entrypoints = vec![
        entry("dup_slot", vec![]),
        entry("issue_foreign", vec![]),
        entry("issue_four", vec![]),
        entry("issue_optional", vec![]),
        entry("issue_self", vec![]),
        entry("issue_skip", vec![]),
        entry(
            "relay",
            vec![ObjectParameter {
                mode: ObjectMode::Read,
                schema: 1,
                ty: resource_pattern(origin),
            }],
        ),
        entry("return_then_consume", vec![]),
        entry("return_then_transfer", vec![]),
    ];
    let abi = CallAbi {
        objects: PackageAbi {
            origin: origin.clone(),
            constructors: vec![ConstructorDeclaration {
                local_id: 1,
                schema: 1,
                arguments: vec![],
            }],
            entrypoints,
        },
        arguments: vec![
            ValueLayout::Tuple(vec![]),
            ValueLayout::Tuple(vec![]),
            ValueLayout::Tuple(vec![]),
            ValueLayout::U64,
            ValueLayout::Tuple(vec![]),
            ValueLayout::Tuple(vec![]),
            ValueLayout::Tuple(vec![]),
            ValueLayout::Tuple(vec![]),
            ValueLayout::Tuple(vec![]),
        ],
        bodies: vec![ValueLayout::Tuple(vec![])],
    };
    let results: Vec<Vec<ObjectResultDeclaration>> = vec![
        vec![
            result_slot(origin, ObjectMode::Read, false),
            result_slot(origin, ObjectMode::Read, false),
        ],
        vec![result_slot(origin, ObjectMode::Read, false)],
        vec![result_slot(origin, ObjectMode::Consume, false); 4],
        vec![result_slot(origin, ObjectMode::Read, true)],
        vec![result_slot(origin, ObjectMode::Consume, false)],
        vec![result_slot(origin, ObjectMode::Consume, false)],
        vec![result_slot(origin, ObjectMode::Read, false)],
        vec![result_slot(origin, ObjectMode::Consume, false)],
        vec![result_slot(origin, ObjectMode::Consume, false)],
    ];
    let tag_bytes: Vec<u8> = tag(origin, 1);
    let body: Vec<u8> = tuple0_bytes();
    let foreign: [u8; 32] =
        ed25519_zebra::VerificationKey::from(&ed25519_zebra::SigningKey::from([9; 32])).into();
    let segments: String = [
        data(1024, &tag_bytes),
        data(2048, &body),
        data(3072, &foreign),
    ]
    .concat();
    let tag_len = tag_bytes.len();
    let body_len = body.len();
    let wat = format!(
        r#"(module
(import "sunrise" "get_object_count" (func $count (result i32)))
(import "sunrise" "get_args_len" (func $args_len (result i32)))
(import "sunrise" "read_args" (func $args (param i32 i32 i32) (result i32)))
(import "sunrise" "create_object" (func $create (param i32 i32 i32 i32 i32) (result i32)))
(import "sunrise" "consume_object" (func $consume (param i32) (result i32)))
(import "sunrise" "transfer_object" (func $transfer (param i32 i32) (result i32)))
(import "sunrise" "get_caller" (func $caller (param i32) (result i32)))
(import "sunrise" "return_object" (func $return_object (param i32 i32) (result i32)))
(import "sunrise" "abort" (func $abort (param i32 i32)))
(memory (export "memory") 1 2)
(global $al (mut i32) (i32.const 0))
{COMMON}
{segments}
(func (export "dup_slot") (local $h i32)
 (call $prepare (i32.const 0))
 (call $require (i32.eq (call $caller (i32.const 256)) (i32.const 32)))
 (local.set $h (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 256) (i32.const 2048) (i32.const {body_len})))
 (call $zero (call $return_object (i32.const 0) (local.get $h)))
 (call $zero (call $return_object (i32.const 1) (local.get $h))))
(func (export "issue_foreign")
 (call $prepare (i32.const 0))
 (call $zero (call $return_object (i32.const 0)
   (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 3072) (i32.const 2048) (i32.const {body_len})))))
(func (export "issue_four")
 (call $prepare (i32.const 0))
 (call $require (i32.eq (call $caller (i32.const 256)) (i32.const 32)))
 (call $zero (call $return_object (i32.const 0)
   (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 256) (i32.const 2048) (i32.const {body_len}))))
 (call $zero (call $return_object (i32.const 1)
   (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 256) (i32.const 2048) (i32.const {body_len}))))
 (call $zero (call $return_object (i32.const 2)
   (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 256) (i32.const 2048) (i32.const {body_len}))))
 (call $zero (call $return_object (i32.const 3)
   (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 256) (i32.const 2048) (i32.const {body_len})))))
(func (export "issue_optional") (local $flag i64)
 (call $prepare (i32.const 0))
 (local.set $flag (i64.load (call $scalar (i32.const 8192) (global.get $al))))
 (if (i64.ne (local.get $flag) (i64.const 0))
  (then
   (call $require (i32.eq (call $caller (i32.const 256)) (i32.const 32)))
   (call $zero (call $return_object (i32.const 0)
     (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 256) (i32.const 2048) (i32.const {body_len})))))))
(func (export "issue_self")
 (call $prepare (i32.const 0))
 (call $require (i32.eq (call $caller (i32.const 256)) (i32.const 32)))
 (call $zero (call $return_object (i32.const 0)
   (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 256) (i32.const 2048) (i32.const {body_len})))))
(func (export "issue_skip")
 (call $prepare (i32.const 0))
 (call $require (i32.eq (call $caller (i32.const 256)) (i32.const 32)))
 (drop (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 256) (i32.const 2048) (i32.const {body_len}))))
(func (export "relay")
 (call $prepare (i32.const 1))
 (call $zero (call $return_object (i32.const 0) (i32.const 0))))
(func (export "return_then_consume") (local $h i32)
 (call $prepare (i32.const 0))
 (call $require (i32.eq (call $caller (i32.const 256)) (i32.const 32)))
 (local.set $h (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 256) (i32.const 2048) (i32.const {body_len})))
 (call $zero (call $return_object (i32.const 0) (local.get $h)))
 (call $zero (call $consume (local.get $h))))
(func (export "return_then_transfer") (local $h i32)
 (call $prepare (i32.const 0))
 (call $require (i32.eq (call $caller (i32.const 256)) (i32.const 32)))
 (local.set $h (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 256) (i32.const 2048) (i32.const {body_len})))
 (call $zero (call $return_object (i32.const 0) (local.get $h)))
 (call $zero (call $transfer (local.get $h) (i32.const 256)))))"#
    );
    let wasm = wat::parse_str(&wat).unwrap();
    ResultsPackage {
        wat,
        wasm,
        abi,
        initializer: None,
        // `return_then_transfer` must reach a real self-transfer so frame-exit
        // revalidation, not the transfer guard, is what rejects the slot.
        transferable_constructors: vec![1],
        results,
    }
}

/// Middle hop of the two-hop relay used by the cumulative handle-bound case.
/// `relay_four` (0 params, 4 required Consume slots) calls the resource
/// library's `issue_four` with results and immediately re-returns all four
/// delivered handles through its own slots. Each batch therefore allocates
/// three handles per created object — one at creation, one on delivery into
/// this frame, one on delivery into the root — so the cumulative handle bound
/// is reached well before the creation or call bounds.
pub fn courier(origin: &PackageOrigin, resource_origin: &PackageOrigin) -> ResultsPackage {
    let abi = CallAbi {
        objects: PackageAbi {
            origin: origin.clone(),
            constructors: vec![],
            entrypoints: vec![entry("relay_four", vec![])],
        },
        arguments: vec![ValueLayout::Tuple(vec![])],
        bodies: vec![],
    };
    let results: Vec<Vec<ObjectResultDeclaration>> =
        vec![vec![
            result_slot(resource_origin, ObjectMode::Consume, false);
            4
        ]];
    let tuple0 = tuple0_bytes();
    let types: Vec<u8> =
        abi::package_types::encode_scoped_type_arguments(origin.chain_id(), &[]).unwrap();
    let segments: String = [
        data(6000, b"issue_four"),
        data(7100, &tuple0),
        data(7300, &types),
    ]
    .concat();
    let ta: String = format!("(i32.const 7300) (i32.const {})", types.len());
    let tuple0_len = tuple0.len();
    let wat = format!(
        r#"(module
(import "sunrise" "get_object_count" (func $count (result i32)))
(import "sunrise" "get_args_len" (func $args_len (result i32)))
(import "sunrise" "read_args" (func $args (param i32 i32 i32) (result i32)))
(import "sunrise" "return_object" (func $return_object (param i32 i32) (result i32)))
(import "sunrise" "call_dependency_with_results" (func $call_dep_res (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
(import "sunrise" "abort" (func $abort (param i32 i32)))
(memory (export "memory") 1 2)
(global $al (mut i32) (i32.const 0))
{COMMON}
{segments}
(func (export "relay_four")
 (call $prepare (i32.const 0))
 (call $require (i32.eq (call $call_dep_res (i32.const 0)
   (i32.const 6000) (i32.const 10) {ta} (i32.const 0) (i32.const 0)
   (i32.const 7100) (i32.const {tuple0_len}) (i32.const 8000) (i32.const 16)) (i32.const 16)))
 (call $zero (call $return_object (i32.const 0) (i32.load (i32.const 8000))))
 (call $zero (call $return_object (i32.const 1) (i32.load (i32.const 8004))))
 (call $zero (call $return_object (i32.const 2) (i32.load (i32.const 8008))))
 (call $zero (call $return_object (i32.const 3) (i32.load (i32.const 8012))))))"#
    );
    let wasm = wat::parse_str(&wat).unwrap();
    ResultsPackage {
        wat,
        wasm,
        abi,
        initializer: None,
        transferable_constructors: vec![],
        results,
    }
}

/// Root coordinator: no object parameters of its own; every scenario drives
/// the dependency library through `call_dependency`/`call_dependency_with_results`
/// and, for `call_relay_dependency_defined`, forwards a delivered
/// dependency-defined handle through its own `return_object` (non-defining
/// relay, DR-0124's returning-a-grant-is-not-a-write fix).
///
/// `call_contract_results` drives the same-instance signed-authorization path
/// through `call_contract_with_results`; the caller supplies the authorization
/// table, so every unauthorized variation is expressed from the test side
/// without changing this source. `stress` repeats the two-hop `courier`
/// relay a signed U64 number of times for the cumulative handle bound.
///
/// Dependency selectors are positional over the artifact's strictly ascending
/// dependency list, so the indices are derived here from the two dependency
/// origins rather than assumed.
pub fn coordinator(
    origin: &PackageOrigin,
    resource_origin: &PackageOrigin,
    courier_origin: &PackageOrigin,
) -> ResultsPackage {
    let entrypoints = vec![
        entry("call_consume_trap", vec![]),
        entry("call_contract_results", vec![]),
        entry("call_drop", vec![]),
        entry("call_duplicate_trap", vec![]),
        entry("call_foreign_read", vec![]),
        entry("call_optional_absent", vec![]),
        entry("call_receiver_alias", vec![]),
        entry("call_relay_dependency_defined", vec![]),
        entry("call_required_missing", vec![]),
        entry("call_small_buffer", vec![]),
        entry("call_transfer_trap", vec![]),
        entry("init", vec![]),
        entry("stress", vec![]),
    ];
    let abi = CallAbi {
        objects: PackageAbi {
            origin: origin.clone(),
            constructors: vec![],
            entrypoints,
        },
        arguments: {
            let mut arguments = vec![ValueLayout::Tuple(vec![]); 13];
            arguments[12] = ValueLayout::U64;
            arguments
        },
        bodies: vec![],
    };
    let results: Vec<Vec<ObjectResultDeclaration>> = vec![
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![result_slot(resource_origin, ObjectMode::Consume, false)],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    ];
    let (dep_resource, dep_courier): (u32, u32) = if resource_origin < courier_origin {
        (0, 1)
    } else {
        (1, 0)
    };
    let tuple0 = tuple0_bytes();
    let flag0 = u64_bytes(0);
    let names: [(&str, u32); 9] = [
        ("issue_self", 6000),
        ("relay", 6032),
        ("return_then_consume", 6064),
        ("return_then_transfer", 6096),
        ("issue_optional", 6128),
        ("dup_slot", 6160),
        ("issue_foreign", 6192),
        ("issue_skip", 6224),
        ("relay_four", 6256),
    ];
    let mut segments: String = names
        .iter()
        .map(|(name, address)| data(*address, name.as_bytes()))
        .collect();
    segments.push_str(&data(7100, &tuple0));
    segments.push_str(&data(7200, &flag0));
    // Every dependency call passes a canonically encoded EMPTY type-argument
    // list; a null pointer with zero length is not a valid encoding and the
    // host rejects it before the frame is prepared.
    let types: Vec<u8> =
        abi::package_types::encode_scoped_type_arguments(origin.chain_id(), &[]).unwrap();
    segments.push_str(&data(7300, &types));
    let ta: String = format!("(i32.const 7300) (i32.const {})", types.len());
    let tuple0_len = tuple0.len();
    let flag0_len = flag0.len();
    let wat = format!(
        r#"(module
(import "sunrise" "get_object_count" (func $count (result i32)))
(import "sunrise" "get_args_len" (func $args_len (result i32)))
(import "sunrise" "read_args" (func $args (param i32 i32 i32) (result i32)))
(import "sunrise" "get_caller" (func $caller (param i32) (result i32)))
(import "sunrise" "return_object" (func $return_object (param i32 i32) (result i32)))
(import "sunrise" "call_dependency" (func $call_dep (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
(import "sunrise" "call_dependency_with_results" (func $call_dep_res (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
(import "sunrise" "call_contract_with_results" (func $call_contract_res (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
(import "sunrise" "abort" (func $abort (param i32 i32)))
(memory (export "memory") 1 2)
(global $al (mut i32) (i32.const 0))
{COMMON}
{segments}
(func (export "call_consume_trap")
 (call $prepare (i32.const 0))
 (drop (call $call_dep_res (i32.const {dep_resource})
   (i32.const 6064) (i32.const 19) {ta} (i32.const 0) (i32.const 0)
   (i32.const 7100) (i32.const {tuple0_len}) (i32.const 8000) (i32.const 16))))
(func (export "call_contract_results")
 (call $prepare (i32.const 0))
 (call $require (i32.eq (call $call_contract_res (i32.const 0) (i32.const 0) (i32.const 0)
   (i32.const 7100) (i32.const {tuple0_len}) (i32.const 8000) (i32.const 16)) (i32.const 4))))
(func (export "call_drop")
 (call $prepare (i32.const 0))
 (call $zero (call $call_dep (i32.const {dep_resource})
   (i32.const 6000) (i32.const 10) {ta} (i32.const 0) (i32.const 0)
   (i32.const 7100) (i32.const {tuple0_len}))))
(func (export "call_duplicate_trap")
 (call $prepare (i32.const 0))
 (drop (call $call_dep_res (i32.const {dep_resource})
   (i32.const 6160) (i32.const 8) {ta} (i32.const 0) (i32.const 0)
   (i32.const 7100) (i32.const {tuple0_len}) (i32.const 8000) (i32.const 16))))
(func (export "call_foreign_read")
 (call $prepare (i32.const 0))
 (call $require (i32.eq (call $call_dep_res (i32.const {dep_resource})
   (i32.const 6192) (i32.const 13) {ta} (i32.const 0) (i32.const 0)
   (i32.const 7100) (i32.const {tuple0_len}) (i32.const 8000) (i32.const 16)) (i32.const 4))))
(func (export "call_optional_absent")
 (call $prepare (i32.const 0))
 (call $require (i32.eq (call $call_dep_res (i32.const {dep_resource})
   (i32.const 6128) (i32.const 14) {ta} (i32.const 0) (i32.const 0)
   (i32.const 7200) (i32.const {flag0_len}) (i32.const 8000) (i32.const 16)) (i32.const 4)))
 (call $require (i32.eq (i32.load (i32.const 8000)) (i32.const -1))))
(func (export "call_receiver_alias") (local $h i32)
 (call $prepare (i32.const 0))
 (call $require (i32.eq (call $call_dep_res (i32.const {dep_resource})
   (i32.const 6000) (i32.const 10) {ta} (i32.const 0) (i32.const 0)
   (i32.const 7100) (i32.const {tuple0_len}) (i32.const 8000) (i32.const 16)) (i32.const 4)))
 (local.set $h (i32.load (i32.const 8000)))
 (i32.store (i32.const 7000) (local.get $h))
 (drop (call $call_dep_res (i32.const {dep_resource})
   (i32.const 6032) (i32.const 5) {ta} (i32.const 7000) (i32.const 1)
   (i32.const 7100) (i32.const {tuple0_len}) (i32.const 8000) (i32.const 16))))
(func (export "call_relay_dependency_defined") (local $h i32)
 (call $prepare (i32.const 0))
 (call $require (i32.eq (call $call_dep_res (i32.const {dep_resource})
   (i32.const 6000) (i32.const 10) {ta} (i32.const 0) (i32.const 0)
   (i32.const 7100) (i32.const {tuple0_len}) (i32.const 8000) (i32.const 16)) (i32.const 4)))
 (local.set $h (i32.load (i32.const 8000)))
 (call $zero (call $return_object (i32.const 0) (local.get $h))))
(func (export "call_required_missing")
 (call $prepare (i32.const 0))
 (drop (call $call_dep_res (i32.const {dep_resource})
   (i32.const 6224) (i32.const 10) {ta} (i32.const 0) (i32.const 0)
   (i32.const 7100) (i32.const {tuple0_len}) (i32.const 8000) (i32.const 16))))
(func (export "call_small_buffer")
 (call $prepare (i32.const 0))
 (drop (call $call_dep_res (i32.const {dep_resource})
   (i32.const 6000) (i32.const 10) {ta} (i32.const 0) (i32.const 0)
   (i32.const 7100) (i32.const {tuple0_len}) (i32.const 8000) (i32.const 3))))
(func (export "call_transfer_trap")
 (call $prepare (i32.const 0))
 (drop (call $call_dep_res (i32.const {dep_resource})
   (i32.const 6096) (i32.const 20) {ta} (i32.const 0) (i32.const 0)
   (i32.const 7100) (i32.const {tuple0_len}) (i32.const 8000) (i32.const 16))))
(func (export "init")
 (call $prepare (i32.const 0)))
(func (export "stress") (local $left i64)
 (call $prepare (i32.const 0))
 (local.set $left (i64.load (call $scalar (i32.const 8192) (global.get $al))))
 (block $done (loop $again
  (br_if $done (i64.eqz (local.get $left)))
  (call $require (i32.eq (call $call_dep_res (i32.const {dep_courier})
    (i32.const 6256) (i32.const 10) {ta} (i32.const 0) (i32.const 0)
    (i32.const 7100) (i32.const {tuple0_len}) (i32.const 8000) (i32.const 16)) (i32.const 16)))
  (local.set $left (i64.sub (local.get $left) (i64.const 1)))
  (br $again)))))"#
    );
    let wasm = wat::parse_str(&wat).unwrap();
    ResultsPackage {
        wat,
        wasm,
        abi,
        initializer: Some("init".to_owned()),
        transferable_constructors: vec![],
        results,
    }
}
