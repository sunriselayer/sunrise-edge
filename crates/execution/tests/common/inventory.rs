//! Reusable generic-host inventory fixture. No executable-profile implementation dependencies.

use abi::call_values::{CallAbi, CallValue, ValueLayout, encode_call_value};
use abi::package_types::{
    PackageOrigin, ScopedTypeTag, encode_scoped_type_arguments, encode_scoped_type_tag,
};
use abi::public_abi::{
    ConstructorDeclaration, EntrypointDeclaration, ObjectMode, ObjectParameter, PackageAbi,
    TypePattern,
};

/// Source and metadata for the executable ABI used by VM and product regressions.
pub struct InventoryPackage {
    pub wat: String,
    pub wasm: Vec<u8>,
    pub abi: CallAbi,
    pub initializer: Option<String>,
    pub transferable_constructors: Vec<u16>,
}

pub fn tuple_layout(count: usize) -> ValueLayout {
    ValueLayout::Tuple(vec![ValueLayout::U64; count])
}

pub fn tuple_arguments(values: &[u64]) -> Vec<u8> {
    encode_call_value(
        &tuple_layout(values.len()),
        &CallValue::Tuple(values.iter().copied().map(CallValue::U64).collect()),
    )
    .unwrap()
}

pub fn scalar_argument(value: u64) -> Vec<u8> {
    encode_call_value(&ValueLayout::U64, &CallValue::U64(value)).unwrap()
}

pub fn recipient_argument(address: [u8; 32]) -> Vec<u8> {
    encode_call_value(
        &ValueLayout::Bytes {
            min_len: 32,
            max_len: 32,
        },
        &CallValue::Bytes(address.to_vec()),
    )
    .unwrap()
}

fn param(origin: &PackageOrigin, constructor: u16, mode: ObjectMode) -> ObjectParameter {
    ObjectParameter {
        mode,
        schema: 1,
        ty: TypePattern {
            origin: origin.clone(),
            constructor,
            arguments: vec![],
        },
    }
}

fn entry(name: &str, objects: Vec<ObjectParameter>) -> EntrypointDeclaration {
    EntrypointDeclaration {
        name: name.to_owned(),
        type_parameters: vec![],
        objects,
    }
}

fn constructors(count: u16) -> Vec<ConstructorDeclaration> {
    (1..=count)
        .map(|local_id| ConstructorDeclaration {
            local_id,
            schema: 1,
            arguments: vec![],
        })
        .collect()
}

fn tag(origin: &PackageOrigin, id: u16) -> Vec<u8> {
    encode_scoped_type_tag(&ScopedTypeTag::new(origin.clone(), id, vec![]).unwrap()).unwrap()
}

fn data(address: u32, bytes: &[u8]) -> String {
    let escaped: String = bytes.iter().map(|byte| format!("\\{byte:02x}")).collect();
    format!("(data (i32.const {address}) \"{escaped}\")")
}

// The checked field walker follows CanonicalStruct's documented 10-byte header
// and 6-byte field header. No business value is accessed using a magic offset.
const HOST: &str = r#"
(import "sunrise" "get_object_count" (func $count (result i32)))
(import "sunrise" "get_object_data_len" (func $len (param i32) (result i32)))
(import "sunrise" "read_object_data" (func $read (param i32 i32 i32 i32) (result i32)))
(import "sunrise" "write_object_data" (func $write (param i32 i32 i32) (result i32)))
(import "sunrise" "consume_object" (func $consume (param i32) (result i32)))
(import "sunrise" "create_object" (func $create (param i32 i32 i32 i32 i32) (result i32)))
(import "sunrise" "transfer_object" (func $transfer (param i32 i32) (result i32)))
(import "sunrise" "get_args_len" (func $args_len (result i32)))
(import "sunrise" "read_args" (func $args (param i32 i32 i32) (result i32)))
(import "sunrise" "get_caller" (func $caller (param i32) (result i32)))
(import "sunrise" "get_instance" (func $instance (param i32 i32) (result i32)))
(import "sunrise" "emit_event" (func $event (param i32 i32 i32 i32) (result i32)))
(import "sunrise" "abort" (func $abort (param i32 i32)))
(import "sunrise" "call_dependency" (func $call (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
(memory (export "memory") 1 2)
(global $al (mut i32) (i32.const 0))
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
(func $slot (param $p i32) (param $n i32) (param $index i32) (result i32) (local $list i32) (local $item i32)
 (local.set $list (call $field (local.get $p) (local.get $n) (i32.const 2)))
 (local.set $item (call $field (local.get $list) (call $size (local.get $list)) (i32.add (local.get $index) (i32.const 2))))
 (call $scalar (local.get $item) (call $size (local.get $item))))
(func $prepare (param $expected i32)
 (call $require (i32.eq (call $count) (local.get $expected)))
 (call $require (i32.eq (call $caller (i32.const 256)) (i32.const 32)))
 (call $require (i32.gt_s (call $instance (i32.const 32768) (i32.const 8192)) (i32.const 0)))
 (global.set $al (call $args_len))
 (call $require (i32.le_u (global.get $al) (i32.const 4096)))
 (call $require (i32.eq (call $args (i32.const 0) (i32.const 8192) (global.get $al)) (global.get $al))))
(func $object (param $h i32) (result i32) (local $n i32)
 (local.set $n (call $len (local.get $h)))
 (call $require (i32.le_u (local.get $n) (i32.const 4096)))
 (call $require (i32.eq (call $read (local.get $h) (i32.const 0) (i32.const 12288) (local.get $n)) (local.get $n)))
 (local.get $n))
"#;

pub fn warehouse(origin: &PackageOrigin, policy_origin: &PackageOrigin) -> InventoryPackage {
    let abi: CallAbi = CallAbi {
        objects: PackageAbi {
            origin: origin.clone(),
            constructors: constructors(4),
            entrypoints: vec![
                entry(
                    "fulfil",
                    vec![
                        param(origin, 1, ObjectMode::Read),
                        param(origin, 3, ObjectMode::Consume),
                        param(policy_origin, 1, ObjectMode::Read),
                    ],
                ),
                entry("init", vec![]),
                entry(
                    "reserve",
                    vec![
                        param(origin, 1, ObjectMode::Read),
                        param(origin, 2, ObjectMode::Write),
                    ],
                ),
                entry("transfer", vec![param(origin, 4, ObjectMode::Write)]),
            ],
        },
        arguments: vec![
            tuple_layout(0),
            tuple_layout(3),
            tuple_layout(2),
            ValueLayout::Bytes {
                min_len: 32,
                max_len: 32,
            },
        ],
        bodies: vec![
            tuple_layout(0),
            tuple_layout(2),
            tuple_layout(3),
            tuple_layout(3),
        ],
    };
    let tags: Vec<Vec<u8>> = (1..=4).map(|id| tag(origin, id)).collect();
    let stock: Vec<u8> = tuple_arguments(&[0, 0]);
    let reservation: Vec<u8> = tuple_arguments(&[0, 0, 0]);
    let cap: Vec<u8> = tuple_arguments(&[]);
    let scalar: Vec<u8> = scalar_argument(0);
    let types: Vec<u8> = encode_scoped_type_arguments(origin.chain_id(), &[]).unwrap();
    let mut segments: String = tags
        .iter()
        .enumerate()
        .map(|(i, bytes)| data(1024 * (i as u32 + 1), bytes))
        .collect();
    for (address, bytes) in [
        (640, types.as_slice()),
        (700, b"configure"),
        (720, b"approve"),
        (16384, stock.as_slice()),
        (17408, reservation.as_slice()),
        (18432, cap.as_slice()),
        (19456, scalar.as_slice()),
    ] {
        segments.push_str(&data(address, bytes));
    }
    let wat: String = format!(
        r#"(module {HOST} {segments}
 (func (export "init") (local $q i64)
  (call $prepare (i32.const 0))
  (i64.store (call $slot (i32.const 16384) (i32.const {stock_len}) (i32.const 0)) (i64.load (call $slot (i32.const 8192) (global.get $al) (i32.const 0))))
  (i64.store (call $slot (i32.const 16384) (i32.const {stock_len}) (i32.const 1)) (i64.load (call $slot (i32.const 8192) (global.get $al) (i32.const 1))))
  (drop (call $create (i32.const 1024) (i32.const {cap_tag}) (i32.const 256) (i32.const 18432) (i32.const {cap_len})))
  (drop (call $create (i32.const 2048) (i32.const {stock_tag}) (i32.const 256) (i32.const 16384) (i32.const {stock_len})))
  (i64.store (call $scalar (i32.const 19456) (i32.const {scalar_len})) (i64.load (call $slot (i32.const 8192) (global.get $al) (i32.const 2))))
  (call $zero (call $call (i32.const 0) (i32.const 700) (i32.const 9) (i32.const 640) (i32.const {types_len}) (i32.const 512) (i32.const 0) (i32.const 19456) (i32.const {scalar_len}))))
 (func (export "reserve") (local $n i32) (local $available i64) (local $quantity i64)
  (call $prepare (i32.const 2)) (local.set $n (call $object (i32.const 1)))
  (local.set $quantity (i64.load (call $slot (i32.const 8192) (global.get $al) (i32.const 1))))
  (local.set $available (i64.load (call $slot (i32.const 12288) (local.get $n) (i32.const 1))))
  (call $require (i64.gt_u (local.get $quantity) (i64.const 0)))
  (call $require (i64.le_u (local.get $quantity) (local.get $available)))
  (i64.store (call $slot (i32.const 12288) (local.get $n) (i32.const 1)) (i64.sub (local.get $available) (local.get $quantity)))
  (call $zero (call $write (i32.const 1) (i32.const 12288) (local.get $n)))
  (i64.store (call $slot (i32.const 17408) (i32.const {reservation_len}) (i32.const 0)) (i64.load (call $slot (i32.const 8192) (global.get $al) (i32.const 0))))
  (i64.store (call $slot (i32.const 17408) (i32.const {reservation_len}) (i32.const 1)) (i64.load (call $slot (i32.const 12288) (local.get $n) (i32.const 0))))
  (i64.store (call $slot (i32.const 17408) (i32.const {reservation_len}) (i32.const 2)) (local.get $quantity))
  (drop (call $create (i32.const 3072) (i32.const {reservation_tag}) (i32.const 256) (i32.const 17408) (i32.const {reservation_len})))
  (call $zero (call $event (i32.const 3072) (i32.const {reservation_tag}) (i32.const 17408) (i32.const {reservation_len}))))
 (func (export "fulfil") (local $n i32)
  (call $prepare (i32.const 3)) (local.set $n (call $object (i32.const 1)))
  (i64.store (call $scalar (i32.const 19456) (i32.const {scalar_len})) (i64.load (call $slot (i32.const 12288) (local.get $n) (i32.const 2))))
  (call $zero (call $consume (i32.const 1)))
  (i32.store (i32.const 512) (i32.const 2))
  (call $zero (call $call (i32.const 0) (i32.const 720) (i32.const 7) (i32.const 640) (i32.const {types_len}) (i32.const 512) (i32.const 1) (i32.const 19456) (i32.const {scalar_len})))
  (drop (call $create (i32.const 4096) (i32.const {shipment_tag}) (i32.const 256) (i32.const 12288) (local.get $n)))
  (call $zero (call $event (i32.const 4096) (i32.const {shipment_tag}) (i32.const 12288) (local.get $n))))
 (func (export "transfer") (local $recipient i32)
  (call $prepare (i32.const 1))
  (local.set $recipient (call $field (i32.const 8192) (global.get $al) (i32.const 2)))
  (call $require (i32.eq (call $size (local.get $recipient)) (i32.const 32)))
  (call $zero (call $transfer (i32.const 0) (local.get $recipient)))))"#,
        stock_len = stock.len(),
        cap_tag = tags[0].len(),
        stock_tag = tags[1].len(),
        reservation_tag = tags[2].len(),
        shipment_tag = tags[3].len(),
        cap_len = cap.len(),
        reservation_len = reservation.len(),
        scalar_len = scalar.len(),
        types_len = types.len()
    );
    let wasm: Vec<u8> = wat::parse_str(&wat).unwrap();
    InventoryPackage {
        wat,
        wasm,
        abi,
        initializer: Some("init".to_owned()),
        transferable_constructors: vec![4],
    }
}

pub fn dispatch_policy(origin: &PackageOrigin) -> InventoryPackage {
    let abi: CallAbi = CallAbi {
        objects: PackageAbi {
            origin: origin.clone(),
            constructors: constructors(1),
            entrypoints: vec![
                entry("approve", vec![param(origin, 1, ObjectMode::Read)]),
                entry("configure", vec![]),
            ],
        },
        arguments: vec![ValueLayout::U64, ValueLayout::U64],
        bodies: vec![ValueLayout::U64],
    };
    let tag: Vec<u8> = tag(origin, 1);
    let segment: String = data(1024, &tag);
    let wat: String = format!(
        r#"(module {HOST} {segment}
 (func (export "configure") (local $q i64)
  (call $prepare (i32.const 0))
  (local.set $q (i64.load (call $scalar (i32.const 8192) (global.get $al))))
  (call $require (i64.gt_u (local.get $q) (i64.const 0)))
  (drop (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 256) (i32.const 8192) (global.get $al))))
 (func (export "approve") (local $n i32) (local $q i64)
  (call $prepare (i32.const 1)) (local.set $n (call $object (i32.const 0)))
  (local.set $q (i64.load (call $scalar (i32.const 8192) (global.get $al))))
  (call $require (i64.gt_u (local.get $q) (i64.const 0)))
  (call $require (i64.le_u (local.get $q) (i64.load (call $scalar (i32.const 12288) (local.get $n)))))))"#,
        tag_len = tag.len()
    );
    let wasm: Vec<u8> = wat::parse_str(&wat).unwrap();
    InventoryPackage {
        wat,
        wasm,
        abi,
        initializer: None,
        transferable_constructors: vec![],
    }
}
