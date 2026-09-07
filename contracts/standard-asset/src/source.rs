//! The bounded WAT source of the public Standard Asset package.
//!
//! The guest is a profile-four module. It never trusts a caller-supplied
//! type, origin, or amount: it derives its own package origin from the
//! canonical instance record, derives every created object's nominal tag
//! from a tag the host already validated for a handle the frame holds, and
//! performs all amount arithmetic with checked unsigned 64-bit operations.
//! Every canonical frame it walks is length-bounded before any field read.
//!
//! Memory map (single fixed 64 KiB page, no growth):
//!
//! | address | bytes | contents                                    |
//! |---------|-------|---------------------------------------------|
//! |    1024 |    32 | `u64` value-frame template (value at +24)   |
//! |    1280 |    42 | `Definition` empty-tuple body               |
//! |    1536 |    32 | caller address                              |
//! |    1600 |    32 | fresh `Definition` ObjectId (asset `A`)     |
//! |    4096 |  4096 | canonical call arguments                    |
//! |    8192 |  2048 | canonical instance record                   |
//! |   12288 |  1024 | object body read buffer                     |
//! |   16384 |  1024 | `get_object_type` output                    |
//! |   20480 |  1024 | constructed nominal tag                     |
//! |   24576 |    32 | constructed `u64` body                      |

use abi::call_values::{CallValue, encode_call_value};

use crate::StandardAssetError;
use crate::types::{coin_body_layout, definition_body_layout};

fn segment(address: u32, bytes: &[u8]) -> String {
    let escaped: String = bytes.iter().map(|byte| format!("\\{byte:02x}")).collect();
    format!("(data (i32.const {address}) \"{escaped}\")")
}

/// Returns the exact WAT source of the package.
///
/// The source embeds only origin-independent canonical constants, so the
/// same bytes are published for every publisher and instance.
pub fn contract_wat() -> Result<String, StandardAssetError> {
    let template: Vec<u8> = encode_call_value(&coin_body_layout(), &CallValue::U64(0))?;
    if template.len() != 32 || template[24..] != [0u8; 8] {
        return Err(StandardAssetError::Invalid(
            "unexpected canonical u64 value framing",
        ));
    }
    let definition: Vec<u8> = encode_call_value(
        &definition_body_layout(),
        &CallValue::Tuple(Vec::<CallValue>::new()),
    )?;
    if definition.len() > 256 {
        return Err(StandardAssetError::Invalid("definition body too large"));
    }
    let definition_len: usize = definition.len();
    let data: String = [segment(1024, &template), segment(1280, &definition)].concat();
    Ok(format!(
        r#"(module
(import "sunrise" "get_object_count" (func $object_count (result i32)))
(import "sunrise" "get_args_len" (func $args_len (result i32)))
(import "sunrise" "read_args" (func $read_args (param i32 i32 i32) (result i32)))
(import "sunrise" "read_object_data" (func $read_body (param i32 i32 i32 i32) (result i32)))
(import "sunrise" "write_object_data" (func $write_body (param i32 i32 i32) (result i32)))
(import "sunrise" "create_object" (func $create (param i32 i32 i32 i32 i32) (result i32)))
(import "sunrise" "consume_object" (func $consume (param i32) (result i32)))
(import "sunrise" "transfer_object" (func $move_owner (param i32 i32) (result i32)))
(import "sunrise" "get_caller" (func $caller (param i32) (result i32)))
(import "sunrise" "get_instance" (func $instance (param i32 i32) (result i32)))
(import "sunrise" "get_object_id" (func $object_id (param i32 i32) (result i32)))
(import "sunrise" "get_object_type" (func $object_type (param i32 i32 i32) (result i32)))
(import "sunrise" "return_object" (func $return_object (param i32 i32) (result i32)))
(import "sunrise" "abort" (func $abort (param i32 i32)))
(memory (export "memory") 1 1)
(global $al (mut i32) (i32.const 0))
{data}

;; ---------------------------------------------------------------- guards
(func $require (param $ok i32)
 (if (i32.eqz (local.get $ok)) (then (call $abort (i32.const 0) (i32.const 0)) unreachable)))
(func $zero (param $status i32) (call $require (i32.eqz (local.get $status))))

;; ------------------------------------------------- canonical frame walker
;; Length of the field whose payload starts at $p.
(func $size (param $p i32) (result i32)
 (i32.load (i32.sub (local.get $p) (i32.const 4))))
;; Locates one field of a bounded canonical frame, checking magic, type,
;; version one, and every framed length against the enclosing region.
(func $find (param $p i32) (param $n i32) (param $ty i32) (param $id i32) (result i32)
 (local $end i32) (local $at i32) (local $left i32) (local $len i32)
 (call $require (i32.ge_u (local.get $n) (i32.const 10)))
 (local.set $end (i32.add (local.get $p) (local.get $n)))
 (call $require (i32.gt_u (local.get $end) (local.get $p)))
 (call $require (i32.le_u (local.get $end) (i32.const 65536)))
 (call $require (i32.eq (i32.load (local.get $p)) (i32.const 1163021907)))
 (call $require (i32.eq (i32.load16_u offset=4 (local.get $p)) (local.get $ty)))
 (call $require (i32.eq (i32.load16_u offset=6 (local.get $p)) (i32.const 1)))
 (local.set $left (i32.load16_u offset=8 (local.get $p)))
 (local.set $at (i32.add (local.get $p) (i32.const 10)))
 (block $missing (loop $fields
  (br_if $missing (i32.eqz (local.get $left)))
  (call $require (i32.ge_u (i32.sub (local.get $end) (local.get $at)) (i32.const 6)))
  (local.set $len (i32.load offset=2 (local.get $at)))
  (call $require (i32.le_u (local.get $len)
    (i32.sub (i32.sub (local.get $end) (local.get $at)) (i32.const 6))))
  (if (i32.eq (i32.load16_u (local.get $at)) (local.get $id))
   (then (return (i32.add (local.get $at) (i32.const 6)))))
  (local.set $at (i32.add (i32.add (local.get $at) (i32.const 6)) (local.get $len)))
  (local.set $left (i32.sub (local.get $left) (i32.const 1)))
  (br $fields)))
 (call $require (i32.const 0))
 (i32.const 0))
(func $u16_field (param $p i32) (param $n i32) (param $ty i32) (param $id i32) (result i32)
 (local $v i32)
 (local.set $v (call $find (local.get $p) (local.get $n) (local.get $ty) (local.get $id)))
 (call $require (i32.eq (call $size (local.get $v)) (i32.const 2)))
 (i32.load16_u (local.get $v)))
(func $equal (param $a i32) (param $b i32) (param $len i32) (result i32)
 (local $i i32)
 (block $done (loop $next
  (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
  (if (i32.ne (i32.load8_u (i32.add (local.get $a) (local.get $i)))
              (i32.load8_u (i32.add (local.get $b) (local.get $i))))
   (then (return (i32.const 0))))
  (local.set $i (i32.add (local.get $i) (i32.const 1)))
  (br $next)))
 (i32.const 1))

;; ------------------------------------------------------ canonical values
(func $u64_at (param $p i32) (param $n i32) (result i64)
 (local $v i32)
 (call $require (i32.eq (call $u16_field (local.get $p) (local.get $n)
   (i32.const 21507) (i32.const 1)) (i32.const 2)))
 (local.set $v (call $find (local.get $p) (local.get $n) (i32.const 21507) (i32.const 2)))
 (call $require (i32.eq (call $size (local.get $v)) (i32.const 8)))
 (i64.load (local.get $v)))
(func $u64 (param $p i32) (result i64)
 (call $u64_at (local.get $p) (call $size (local.get $p))))
(func $bytes (param $p i32) (param $len i32) (result i32)
 (local $n i32) (local $v i32)
 (local.set $n (call $size (local.get $p)))
 (call $require (i32.eq (call $u16_field (local.get $p) (local.get $n)
   (i32.const 21507) (i32.const 1)) (i32.const 4)))
 (local.set $v (call $find (local.get $p) (local.get $n) (i32.const 21507) (i32.const 2)))
 (call $require (i32.eq (call $size (local.get $v)) (local.get $len)))
 (local.get $v))
(func $tuple (param $p i32) (param $n i32) (param $items i32) (result i32)
 (local $v i32)
 (call $require (i32.eq (call $u16_field (local.get $p) (local.get $n)
   (i32.const 21507) (i32.const 1)) (i32.const 6)))
 (local.set $v (call $find (local.get $p) (local.get $n) (i32.const 21507) (i32.const 2)))
 (call $require (i32.eq (call $u16_field (local.get $v) (call $size (local.get $v))
   (i32.const 21508) (i32.const 1)) (local.get $items)))
 (local.get $v))
(func $item (param $list i32) (param $index i32) (result i32)
 (call $find (local.get $list) (call $size (local.get $list)) (i32.const 21508)
  (i32.add (local.get $index) (i32.const 2))))

;; --------------------------------------------------------- host wrappers
(func $arguments (param $objects i32) (param $items i32) (result i32)
 (call $require (i32.eq (call $object_count) (local.get $objects)))
 (global.set $al (call $args_len))
 (call $require (i32.le_u (global.get $al) (i32.const 4096)))
 (call $require (i32.eq (call $read_args (i32.const 0) (i32.const 4096) (global.get $al))
   (global.get $al)))
 (call $tuple (i32.const 4096) (global.get $al) (local.get $items)))
(func $u64_body (param $dst i32) (param $value i64)
 (memory.copy (local.get $dst) (i32.const 1024) (i32.const 32))
 (i64.store offset=24 (local.get $dst) (local.get $value)))
(func $amount_of (param $handle i32) (result i64)
 (local $n i32)
 (local.set $n (call $read_body (local.get $handle) (i32.const 0)
   (i32.const 12288) (i32.const 1024)))
 (call $u64_at (i32.const 12288) (local.get $n)))
(func $set_amount (param $handle i32) (param $value i64)
 (call $u64_body (i32.const 24576) (local.get $value))
 (call $zero (call $write_body (local.get $handle) (i32.const 24576) (i32.const 32))))
(func $reservation_of (param $handle i32) (result i32)
 (local $n i32)
 (local.set $n (call $read_body (local.get $handle) (i32.const 0)
   (i32.const 12288) (i32.const 1024)))
 (call $tuple (i32.const 12288) (local.get $n) (i32.const 5)))
;; Validates one caller-attested field as the exact 56-byte canonical
;; self-describing Digest32 frame produced by `canonical_encoding::
;; encode_digest32` and accepted by `canonical_encoding::decode_digest32`:
;; magic "SNRE", type 0x0103, version 1, field count 2, field 1 (id 1,
;; length 2) holding a known hash algorithm id (1..3), then field 2 (id 2,
;; length 32) holding the digest bytes, at fixed offsets with no slack for
;; unknown algorithm ids, extra/reordered fields, or mismatched lengths.
(func $digest (param $p i32) (result i32)
 (local $v i32) (local $alg i32)
 (local.set $v (call $bytes (local.get $p) (i32.const 56)))
 (call $require (i32.eq (i32.load (local.get $v)) (i32.const 1163021907)))
 (call $require (i32.eq (i32.load16_u offset=4 (local.get $v)) (i32.const 259)))
 (call $require (i32.eq (i32.load16_u offset=6 (local.get $v)) (i32.const 1)))
 (call $require (i32.eq (i32.load16_u offset=8 (local.get $v)) (i32.const 2)))
 (call $require (i32.eq (i32.load16_u offset=10 (local.get $v)) (i32.const 1)))
 (call $require (i32.eq (i32.load offset=12 (local.get $v)) (i32.const 2)))
 (local.set $alg (i32.load16_u offset=16 (local.get $v)))
 (call $require (i32.ge_u (local.get $alg) (i32.const 1)))
 (call $require (i32.le_u (local.get $alg) (i32.const 3)))
 (call $require (i32.eq (i32.load16_u offset=18 (local.get $v)) (i32.const 2)))
 (call $require (i32.eq (i32.load offset=20 (local.get $v)) (i32.const 32)))
 (local.get $v))

;; ------------------------------------------------------- nominal tag work
;; Writes one opaque scoped type argument (domain one, 32-byte asset id).
(func $opaque (param $dst i32) (param $value i32)
 (i32.store (local.get $dst) (i32.const 1163021907))
 (i32.store16 offset=4 (local.get $dst) (i32.const 20994))
 (i32.store16 offset=6 (local.get $dst) (i32.const 1))
 (i32.store16 offset=8 (local.get $dst) (i32.const 3))
 (i32.store16 offset=10 (local.get $dst) (i32.const 1))
 (i32.store offset=12 (local.get $dst) (i32.const 2))
 (i32.store16 offset=16 (local.get $dst) (i32.const 2))
 (i32.store16 offset=18 (local.get $dst) (i32.const 2))
 (i32.store offset=20 (local.get $dst) (i32.const 2))
 (i32.store16 offset=24 (local.get $dst) (i32.const 1))
 (i32.store16 offset=26 (local.get $dst) (i32.const 3))
 (i32.store offset=28 (local.get $dst) (i32.const 32))
 (memory.copy (i32.add (local.get $dst) (i32.const 32)) (local.get $value) (i32.const 32)))
;; Builds one scoped type tag from an existing encoded origin.
(func $build_tag (param $dst i32) (param $op i32) (param $ol i32) (param $ctor i32)
  (param $arg i32) (result i32)
 (local $at i32)
 (call $require (i32.ge_u (local.get $ol) (i32.const 10)))
 (call $require (i32.le_u (local.get $ol) (i32.const 256)))
 (i32.store (local.get $dst) (i32.const 1163021907))
 (i32.store16 offset=4 (local.get $dst) (i32.const 20995))
 (i32.store16 offset=6 (local.get $dst) (i32.const 1))
 (i32.store16 offset=8 (local.get $dst)
   (i32.add (i32.const 3) (i32.ne (local.get $arg) (i32.const 0))))
 (i32.store16 offset=10 (local.get $dst) (i32.const 1))
 (i32.store offset=12 (local.get $dst) (local.get $ol))
 (memory.copy (i32.add (local.get $dst) (i32.const 16)) (local.get $op) (local.get $ol))
 (local.set $at (i32.add (i32.add (local.get $dst) (i32.const 16)) (local.get $ol)))
 (i32.store16 (local.get $at) (i32.const 2))
 (i32.store offset=2 (local.get $at) (i32.const 2))
 (i32.store16 offset=6 (local.get $at) (local.get $ctor))
 (local.set $at (i32.add (local.get $at) (i32.const 8)))
 (i32.store16 (local.get $at) (i32.const 3))
 (i32.store offset=2 (local.get $at) (i32.const 2))
 (i32.store16 offset=6 (local.get $at) (i32.ne (local.get $arg) (i32.const 0)))
 (local.set $at (i32.add (local.get $at) (i32.const 8)))
 (if (local.get $arg) (then
  (i32.store16 (local.get $at) (i32.const 4))
  (i32.store offset=2 (local.get $at) (i32.const 64))
  (call $opaque (i32.add (local.get $at) (i32.const 6)) (local.get $arg))
  (local.set $at (i32.add (local.get $at) (i32.const 70)))))
 (i32.sub (local.get $at) (local.get $dst)))
;; Own package origin, read from the canonical instance record.
(func $own_origin (result i32)
 (local $n i32) (local $dep i32)
 (local.set $n (call $instance (i32.const 8192) (i32.const 2048)))
 (local.set $dep (call $find (i32.const 8192) (local.get $n)
   (i32.const 25604) (i32.const 4)))
 (call $find (local.get $dep) (call $size (local.get $dep))
   (i32.const 25346) (i32.const 1)))
;; Rebuilds a sibling tag of the same asset from a handle's validated tag,
;; preserving both the defining origin and the bound opaque asset argument.
(func $retag (param $handle i32) (param $ctor i32) (result i32)
 (local $n i32) (local $op i32) (local $arg i32) (local $an i32)
 (local.set $n (call $object_type (local.get $handle) (i32.const 16384) (i32.const 1024)))
 (local.set $op (call $find (i32.const 16384) (local.get $n) (i32.const 20995) (i32.const 1)))
 (call $require (i32.eq (call $u16_field (i32.const 16384) (local.get $n)
   (i32.const 20995) (i32.const 3)) (i32.const 1)))
 (local.set $arg (call $find (i32.const 16384) (local.get $n) (i32.const 20995) (i32.const 4)))
 (local.set $an (call $size (local.get $arg)))
 (call $require (i32.eq (call $u16_field (local.get $arg) (local.get $an)
   (i32.const 20994) (i32.const 1)) (i32.const 2)))
 (call $require (i32.eq (call $u16_field (local.get $arg) (local.get $an)
   (i32.const 20994) (i32.const 2)) (i32.const 1)))
 (local.set $arg (call $find (local.get $arg) (local.get $an) (i32.const 20994) (i32.const 3)))
 (call $require (i32.eq (call $size (local.get $arg)) (i32.const 32)))
 (call $build_tag (i32.const 20480) (local.get $op) (call $size (local.get $op))
   (local.get $ctor) (local.get $arg)))

;; ------------------------------------------------------------ entrypoints
;; Creates one empty Definition and one zero-supply TreasuryCap. The asset
;; identity is the host-derived ObjectId of that Definition, never a
;; caller-chosen value, and no result slot is declared for it.
(func (export "init") (local $op i32) (local $len i32) (local $handle i32)
 (drop (call $arguments (i32.const 0) (i32.const 0)))
 (call $require (i32.eq (call $caller (i32.const 1536)) (i32.const 32)))
 (local.set $op (call $own_origin))
 (local.set $len (call $build_tag (i32.const 20480) (local.get $op)
   (call $size (local.get $op)) (i32.const 1) (i32.const 0)))
 (local.set $handle (call $create (i32.const 20480) (local.get $len)
   (i32.const 1536) (i32.const 1280) (i32.const {definition_len})))
 (call $require (i32.eq (call $object_id (local.get $handle) (i32.const 1600)) (i32.const 32)))
 (local.set $len (call $build_tag (i32.const 20480) (local.get $op)
   (call $size (local.get $op)) (i32.const 3) (i32.const 1600)))
 (call $u64_body (i32.const 24576) (i64.const 0))
 (drop (call $create (i32.const 20480) (local.get $len)
   (i32.const 1536) (i32.const 24576) (i32.const 32))))

;; TreasuryCap Write, positive amount, recipient; returns the new Coin Read.
(func (export "mint")
  (local $list i32) (local $amount i64) (local $supply i64) (local $to i32) (local $len i32)
 (local.set $list (call $arguments (i32.const 1) (i32.const 2)))
 (local.set $amount (call $u64 (call $item (local.get $list) (i32.const 0))))
 (call $require (i64.gt_u (local.get $amount) (i64.const 0)))
 (local.set $to (call $bytes (call $item (local.get $list) (i32.const 1)) (i32.const 32)))
 (local.set $supply (call $amount_of (i32.const 0)))
 (call $require (i64.gt_u (i64.add (local.get $supply) (local.get $amount)) (local.get $supply)))
 (local.set $len (call $retag (i32.const 0) (i32.const 2)))
 (call $set_amount (i32.const 0) (i64.add (local.get $supply) (local.get $amount)))
 (call $u64_body (i32.const 24576) (local.get $amount))
 (call $zero (call $return_object (i32.const 0) (call $create (i32.const 20480) (local.get $len)
   (local.get $to) (i32.const 24576) (i32.const 32)))))

;; TreasuryCap Write and Coin Consume; burns the entire Coin.
(func (export "burn") (local $amount i64) (local $supply i64)
 (drop (call $arguments (i32.const 2) (i32.const 0)))
 (local.set $amount (call $amount_of (i32.const 1)))
 (call $require (i64.gt_u (local.get $amount) (i64.const 0)))
 (local.set $supply (call $amount_of (i32.const 0)))
 (call $require (i64.ge_u (local.get $supply) (local.get $amount)))
 (call $set_amount (i32.const 0) (i64.sub (local.get $supply) (local.get $amount)))
 (call $zero (call $consume (i32.const 1))))

;; Coin Write, positive strict partial amount, recipient; returns Coin Read.
(func (export "split")
  (local $list i32) (local $amount i64) (local $held i64) (local $to i32) (local $len i32)
 (local.set $list (call $arguments (i32.const 1) (i32.const 2)))
 (local.set $amount (call $u64 (call $item (local.get $list) (i32.const 0))))
 (call $require (i64.gt_u (local.get $amount) (i64.const 0)))
 (local.set $to (call $bytes (call $item (local.get $list) (i32.const 1)) (i32.const 32)))
 (local.set $held (call $amount_of (i32.const 0)))
 (call $require (i64.lt_u (local.get $amount) (local.get $held)))
 (local.set $len (call $retag (i32.const 0) (i32.const 2)))
 (call $set_amount (i32.const 0) (i64.sub (local.get $held) (local.get $amount)))
 (call $u64_body (i32.const 24576) (local.get $amount))
 (call $zero (call $return_object (i32.const 0) (call $create (i32.const 20480) (local.get $len)
   (local.get $to) (i32.const 24576) (i32.const 32)))))

;; Destination Coin Write and source Coin Consume, with checked addition.
(func (export "merge") (local $held i64) (local $source i64)
 (drop (call $arguments (i32.const 2) (i32.const 0)))
 (local.set $held (call $amount_of (i32.const 0)))
 (local.set $source (call $amount_of (i32.const 1)))
 (call $require (i64.gt_u (local.get $source) (i64.const 0)))
 (call $require (i64.gt_u (i64.add (local.get $held) (local.get $source)) (local.get $held)))
 (call $set_amount (i32.const 0) (i64.add (local.get $held) (local.get $source)))
 (call $zero (call $consume (i32.const 1))))

;; Coin Write and recipient. Only Coin is a transferable constructor.
(func (export "transfer") (local $list i32)
 (local.set $list (call $arguments (i32.const 1) (i32.const 1)))
 (call $zero (call $move_owner (i32.const 0)
   (call $bytes (call $item (local.get $list) (i32.const 0)) (i32.const 32)))))

;; Coin Write with 0 < reserved < balance; returns one sender-owned
;; Reservation Consume whose body is exactly the signed argument tuple.
(func (export "reserve") (local $list i32) (local $reserved i64) (local $held i64) (local $len i32)
 (local.set $list (call $arguments (i32.const 1) (i32.const 5)))
 (local.set $reserved (call $u64 (call $item (local.get $list) (i32.const 0))))
 (call $require (i64.gt_u (local.get $reserved) (i64.const 0)))
 (drop (call $digest (call $item (local.get $list) (i32.const 1))))
 (drop (call $digest (call $item (local.get $list) (i32.const 2))))
 (drop (call $bytes (call $item (local.get $list) (i32.const 3)) (i32.const 32)))
 (drop (call $bytes (call $item (local.get $list) (i32.const 4)) (i32.const 32)))
 (local.set $held (call $amount_of (i32.const 0)))
 (call $require (i64.lt_u (local.get $reserved) (local.get $held)))
 (local.set $len (call $retag (i32.const 0) (i32.const 4)))
 (call $set_amount (i32.const 0) (i64.sub (local.get $held) (local.get $reserved)))
 (call $require (i32.eq (call $caller (i32.const 1536)) (i32.const 32)))
 (call $zero (call $return_object (i32.const 0) (call $create (i32.const 20480) (local.get $len)
   (i32.const 1536) (i32.const 4096) (global.get $al)))))

;; Coin Consume with reserved == balance > 0; returns the same Reservation.
(func (export "reserve_all")
  (local $list i32) (local $reserved i64) (local $held i64) (local $len i32)
 (local.set $list (call $arguments (i32.const 1) (i32.const 5)))
 (local.set $reserved (call $u64 (call $item (local.get $list) (i32.const 0))))
 (call $require (i64.gt_u (local.get $reserved) (i64.const 0)))
 (drop (call $digest (call $item (local.get $list) (i32.const 1))))
 (drop (call $digest (call $item (local.get $list) (i32.const 2))))
 (drop (call $bytes (call $item (local.get $list) (i32.const 3)) (i32.const 32)))
 (drop (call $bytes (call $item (local.get $list) (i32.const 4)) (i32.const 32)))
 (local.set $held (call $amount_of (i32.const 0)))
 (call $require (i64.eq (local.get $reserved) (local.get $held)))
 (local.set $len (call $retag (i32.const 0) (i32.const 4)))
 (call $require (i32.eq (call $caller (i32.const 1536)) (i32.const 32)))
 (call $zero (call $consume (i32.const 0)))
 (call $zero (call $return_object (i32.const 0) (call $create (i32.const 20480) (local.get $len)
   (i32.const 1536) (i32.const 4096) (global.get $al)))))

;; Reservation Consume with 0 < actual <= reserved and exactly matching
;; stored commitments. Creates the fee Coin, and the refund Coin only when
;; the checked difference is nonzero. Recipients come from the resource.
(func (export "settle")
  (local $list i32) (local $body i32) (local $actual i64) (local $reserved i64)
  (local $len i32) (local $fee i32) (local $refund i32)
 (local.set $list (call $arguments (i32.const 1) (i32.const 3)))
 (local.set $actual (call $u64 (call $item (local.get $list) (i32.const 0))))
 (call $require (i64.gt_u (local.get $actual) (i64.const 0)))
 (local.set $body (call $reservation_of (i32.const 0)))
 (local.set $reserved (call $u64 (call $item (local.get $body) (i32.const 0))))
 (call $require (i64.le_u (local.get $actual) (local.get $reserved)))
 (call $require (call $equal
   (call $digest (call $item (local.get $list) (i32.const 1)))
   (call $digest (call $item (local.get $body) (i32.const 1)))
   (i32.const 56)))
 (call $require (call $equal
   (call $digest (call $item (local.get $list) (i32.const 2)))
   (call $digest (call $item (local.get $body) (i32.const 2)))
   (i32.const 56)))
 (local.set $fee (call $bytes (call $item (local.get $body) (i32.const 3)) (i32.const 32)))
 (local.set $refund (call $bytes (call $item (local.get $body) (i32.const 4)) (i32.const 32)))
 (local.set $len (call $retag (i32.const 0) (i32.const 2)))
 (call $zero (call $consume (i32.const 0)))
 (call $u64_body (i32.const 24576) (local.get $actual))
 (call $zero (call $return_object (i32.const 0) (call $create (i32.const 20480) (local.get $len)
   (local.get $fee) (i32.const 24576) (i32.const 32))))
 (if (i64.gt_u (i64.sub (local.get $reserved) (local.get $actual)) (i64.const 0)) (then
  (call $u64_body (i32.const 24576) (i64.sub (local.get $reserved) (local.get $actual)))
  (call $zero (call $return_object (i32.const 1) (call $create (i32.const 20480) (local.get $len)
    (local.get $refund) (i32.const 24576) (i32.const 32))))))))
"#
    ))
}

/// Parses the package source into core WASM bytes.
pub fn contract_wasm() -> Result<Vec<u8>, StandardAssetError> {
    let source: String = contract_wat()?;
    wat::parse_str(&source).map_err(|error| StandardAssetError::Wat(error.to_string()))
}
